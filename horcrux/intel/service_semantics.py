"""Protocol-specific service semantics (Phase 7, Part 7).

Converts raw protocol-enumeration results into semantic ApplicationModel
facts usable by hypothesis generation. Never copies raw scanner output;
each converter emits typed facts (identities, resources, directory facts,
auth observations, mail capabilities, ...).
"""

from __future__ import annotations

import re
from typing import Any


def _words(text: str) -> list[str]:
    return re.findall(r"[A-Za-z0-9_.$-]{2,64}", text or "")


def smb_to_facts(raw: str | dict, host: str = "", port: int = 445) -> list[dict]:
    """SMB shares -> service resource objects."""
    facts: list[dict] = []
    text = raw if isinstance(raw, str) else str((raw or {}).get("stdout", raw))
    shares = set(re.findall(r"(?im)^\s*([A-Za-z0-9_$.-]+)\s+(?:Disk|IPC|Printer)", text))
    for line in (text or "").splitlines():
        if "READ" in line or "WRITE" in line:
            shares.add(line.strip()[:80])
    for share in sorted(shares)[:20]:
        facts.append({"fact_type": "service_resource",
                      "protocol": "smb", "host": host, "port": port,
                      "name": str(share),
                      "evidence": f"smb:share:{share}"})
    if re.search(r"signing\s*:\s*false", text or "", re.I):
        facts.append({"fact_type": "auth_observation", "protocol": "smb",
                      "observation": "smb_signing_not_required", "host": host})
    if re.search(r"null session|anonymous|READ", text or "", re.I):
        facts.append({"fact_type": "auth_observation", "protocol": "smb",
                      "observation": "anonymous_share_access", "host": host})
    return facts


def ldap_to_facts(raw: str | dict, host: str = "", port: int = 389) -> list[dict]:
    text = raw if isinstance(raw, str) else str((raw or {}).get("stdout", raw))
    facts: list[dict] = []
    for dn in set(re.findall(r"(?im)(?:namingContexts|defaultNamingContext):\s*([^\r\n]+)", text or "")):
        facts.append({"fact_type": "directory_fact", "protocol": "ldap",
                      "naming_context": dn.strip(), "host": host})
    if re.search(r"anonymous.*bind.*success|unauthenticated.*allowed", text or "", re.I):
        facts.append({"fact_type": "auth_observation", "protocol": "ldap",
                      "observation": "anonymous_bind_allowed", "host": host})
    for user in set(re.findall(r"(?im)^(?:dn|uid|cn|sAMAccountName):\s*([^\r\n,]+)", text or "")) :
        facts.append({"fact_type": "identity_observation", "protocol": "ldap",
                      "identity": user.strip()[:64], "host": host})
    return facts[:25]


def kerberos_to_facts(raw: str | dict, host: str = "") -> list[dict]:
    text = raw if isinstance(raw, str) else str((raw or {}).get("stdout", raw))
    facts: list[dict] = []
    for princ in set(re.findall(r"[\w.$-]+@[\w.-]+", text or "")):
        facts.append({"fact_type": "identity_observation", "protocol": "kerberos",
                      "principal": princ, "host": host})
    if re.search(r"kdc|kerberos", text or "", re.I):
        facts.append({"fact_type": "service_fact", "protocol": "kerberos",
                      "observation": "kdc_present", "host": host})
    return facts[:25]


def ssh_to_facts(banner: str = "", ciphers: str = "", host: str = "") -> list[dict]:
    facts: list[dict] = []
    m = re.search(r"OpenSSH_([\w.-]+)", banner or "")
    if m:
        facts.append({"fact_type": "technology_fact", "protocol": "ssh",
                      "product": "OpenSSH", "version": m.group(1), "host": host})
    if banner:
        facts.append({"fact_type": "auth_observation", "protocol": "ssh",
                      "observation": f"banner:{banner[:80]}", "host": host})
    if ciphers:
        weak = [c for c in _words(ciphers) if any(k in c.lower() for k in ("cbc", "3des", "rc4", "md5"))]
        facts.append({"fact_type": "auth_observation", "protocol": "ssh",
                      "observation": f"ciphers:{len(_words(ciphers))};weak:{len(weak)}",
                      "host": host})
    return facts


def ftp_to_facts(banner: str = "", anonymous: bool = False, host: str = "") -> list[dict]:
    facts: list[dict] = []
    if banner:
        facts.append({"fact_type": "technology_fact", "protocol": "ftp",
                      "banner": banner[:100], "host": host})
    facts.append({"fact_type": "auth_observation", "protocol": "ftp",
                  "observation": "anonymous_allowed" if anonymous else "anonymous_denied",
                  "host": host})
    return facts


def smtp_to_facts(banner: str = "", ehlo: str = "", open_relay: bool = False,
                  users: list[str] | None = None, host: str = "") -> list[dict]:
    facts: list[dict] = []
    if banner:
        facts.append({"fact_type": "technology_fact", "protocol": "smtp",
                      "banner": banner[:100], "host": host})
    if ehlo:
        caps = [w for w in _words(ehlo) if w.upper() in
                {"STARTTLS", "AUTH", "PIPELINING", "SIZE", "8BITMIME", "ENHANCEDSTATUSCODES"}]
        facts.append({"fact_type": "mail_capability", "protocol": "smtp",
                      "capabilities": sorted(set(caps)), "host": host})
    facts.append({"fact_type": "mail_capability", "protocol": "smtp",
                  "observation": "open_relay" if open_relay else "relay_closed",
                  "host": host})
    for u in (users or [])[:10]:
        facts.append({"fact_type": "identity_observation", "protocol": "smtp",
                      "identity": u, "host": host})
    return facts


def dns_to_facts(records: list[dict] | None = None, zone_transfer: bool = False,
                 host: str = "") -> list[dict]:
    facts: list[dict] = []
    for r in (records or [])[:25]:
        facts.append({"fact_type": "dns_record", "host": host,
                      "record": {k: r.get(k) for k in ("type", "name", "value") if k in r}})
    if zone_transfer:
        facts.append({"fact_type": "auth_observation", "protocol": "dns",
                      "observation": "axfr_allowed", "host": host})
    return facts


def snmp_to_facts(community: str = "", oids: list[str] | None = None,
                  host: str = "") -> list[dict]:
    facts: list[dict] = []
    if community:
        facts.append({"fact_type": "auth_observation", "protocol": "snmp",
                      "observation": f"community:{community}", "host": host})
    for oid in (oids or [])[:15]:
        facts.append({"fact_type": "snmp_fact", "host": host, "oid": oid})
    return facts


def database_to_facts(db_type: str = "", version: str = "",
                       unauthenticated: bool = False, host: str = "",
                       port: int = 0) -> list[dict]:
    facts: list[dict] = []
    if db_type:
        facts.append({"fact_type": "technology_fact", "protocol": "database",
                      "product": db_type, "version": version or "", "host": host,
                      "port": port})
    facts.append({"fact_type": "auth_observation", "protocol": "database",
                  "observation": "unauthenticated_access" if unauthenticated else "auth_required",
                  "host": host, "port": port})
    return facts


def remote_to_facts(service: str = "", details: str = "", host: str = "",
                    port: int = 0) -> list[dict]:
    facts = [{"fact_type": "service_fact", "protocol": service or "remote",
              "observation": (details or "remote service present")[:120],
              "host": host, "port": port}]
    if service.lower() in ("nfs",) and details:
        for share in set(re.findall(r"/[\w./-]{2,80}", details)) :
            facts.append({"fact_type": "service_resource", "protocol": "nfs",
                          "name": share, "host": host})
    return facts[:15]


PROTOCOL_CONVERTERS = {
    "smb": smb_to_facts,
    "ldap": ldap_to_facts,
    "kerberos": kerberos_to_facts,
    "ssh": ssh_to_facts,
    "ftp": ftp_to_facts,
    "smtp": smtp_to_facts,
    "dns": dns_to_facts,
    "snmp": snmp_to_facts,
    "database": database_to_facts,
    "remote": remote_to_facts,
}


def ingest_service_facts(app: Any, facts: list[dict], source: str = "service_enum") -> int:
    """Fold protocol facts into the ApplicationModel. Returns facts ingested."""
    from horcrux.intel.application_model import (
        IdentityRole,
        ObjectType,
        SemanticIdentity,
        SemanticTechnology,
    )
    count = 0
    for fact in facts or []:
        ftype = fact.get("fact_type", "")
        try:
            if ftype == "service_resource":
                obj = ObjectType(name=str(fact.get("name", "share"))[:64],
                                 endpoints=[f"{fact.get('protocol')}:{fact.get('port', '')}"],
                                 parameter_names=[],
                                 evidence_refs=[fact.get("evidence", source)])
                app.upsert_object_type(obj)
                count += 1
            elif ftype in ("identity_observation",):
                label = str(fact.get("identity", fact.get("principal", "unknown")))[:64]
                ident = SemanticIdentity(role=IdentityRole.USER, label=label,
                                         session_evidence=[f"{source}:{fact.get('protocol', '')}"])
                app.upsert_identity(ident)
                count += 1
            elif ftype == "technology_fact":
                name = str(fact.get("product", fact.get("banner", "unknown")))[:64]
                if not any(t.name.lower() == name.lower() for t in app.technologies):
                    app.technologies.append(SemanticTechnology(
                        name=name, category="SERVICE",
                        version=str(fact.get("version", "")),
                        sources=[source]))
                    count += 1
            elif ftype in ("directory_fact", "dns_record", "snmp_fact",
                           "mail_capability", "service_fact", "auth_observation"):
                # Represent as security-boundary-annotated object facts so
                # hypothesis rules can consume them.
                obj = ObjectType(name=f"{fact.get('protocol', 'service')}-fact",
                                 endpoints=[],
                                 parameter_names=[],
                                 evidence_refs=[f"{source}:{ftype}"])
                app.upsert_object_type(obj)
                count += 1
        except Exception:
            continue
    return count
