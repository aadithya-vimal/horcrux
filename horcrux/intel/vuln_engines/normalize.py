"""Normalization, deduplication, correlation and stale detection.

Deterministic. AI may suggest, never decides. Version numbers are never
invented — correlation only uses observed evidence.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any

from horcrux.intel.vuln_engines.types import (
    CorrelatedVulnerability,
    CorrelationDisposition,
    NormalizedExternalFinding,
)

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_CWE_RE = re.compile(r"\bCWE-\d+\b", re.IGNORECASE)

# vendor/product alias resolution → stable product identity
_PRODUCT_ALIASES: dict[str, str] = {
    "apache httpd": "apache http server",
    "apache http server": "apache http server",
    "httpd": "apache http server",
    "apache": "apache http server",
    "nginx": "nginx",
    "iis": "microsoft iis",
    "internet information services": "microsoft iis",
    "openssh": "openssh",
    "openssl": "openssl",
    "samba": "samba",
    "smb": "samba",
    "mysql": "mysql",
    "mariadb": "mariadb",
    "postgres": "postgresql",
    "postgresql": "postgresql",
    "mssql": "microsoft sql server",
    "microsoft sql server": "microsoft sql server",
    "tomcat": "apache tomcat",
    "apache tomcat": "apache tomcat",
    "jenkins": "jenkins",
    "wordpress": "wordpress",
    "drupal": "drupal",
    "joomla": "joomla",
    "php": "php",
    "python": "python",
    "node.js": "node.js",
    "nodejs": "node.js",
    "express": "express",
    "django": "django",
    "flask": "flask",
    "spring": "spring framework",
    "log4j": "apache log4j",
    "apache log4j": "apache log4j",
    "openssl ": "openssl",
}

_VENDOR_ALIASES: dict[str, str] = {
    "apache software foundation": "apache",
    "apache": "apache",
    "microsoft corporation": "microsoft",
    "microsoft": "microsoft",
    "oracle corporation": "oracle",
    "oracle": "oracle",
    "openssl software foundation": "openssl",
}

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def normalize_vendor(vendor: str) -> str:
    v = (vendor or "").strip().lower()
    return _VENDOR_ALIASES.get(v, v)


def normalize_product(product: str) -> str:
    p = re.sub(r"\s+", " ", (product or "").strip().lower())
    if p in _PRODUCT_ALIASES:
        return _PRODUCT_ALIASES[p]
    # prefix match for "apache httpd 2.4" style strings
    for alias, canonical in _PRODUCT_ALIASES.items():
        if p.startswith(alias + " ") or p.startswith(alias + "/"):
            return canonical
    return p


def normalize_cve(value: str) -> str:
    v = (value or "").strip().upper()
    return v if _CVE_RE.fullmatch(v) else ""


def extract_cves(*texts: str) -> list[str]:
    found: list[str] = []
    for text in texts:
        for match in _CVE_RE.findall(text or ""):
            cve = match.upper()
            if cve not in found:
                found.append(cve)
    return found


def extract_cwes(*texts: str) -> list[str]:
    found: list[str] = []
    for text in texts:
        for match in _CWE_RE.findall(text or ""):
            cwe = match.upper()
            if cwe not in found:
                found.append(cwe)
    return found


def normalize_severity(value: Any, cvss: float | None = None) -> str:
    s = str(value or "").strip().lower()
    mapping = {
        "0": "info", "none": "info", "info": "info", "informational": "info",
        "1": "low", "low": "low", "minor": "low",
        "2": "medium", "medium": "medium", "moderate": "medium",
        "3": "high", "high": "high", "important": "high", "major": "high",
        "4": "critical", "critical": "critical", "blocker": "critical",
    }
    if s in mapping:
        base = mapping[s]
    elif cvss is not None:
        try:
            score = float(cvss)
        except (TypeError, ValueError):
            return "info"
        if score >= 9.0:
            base = "critical"
        elif score >= 7.0:
            base = "high"
        elif score >= 4.0:
            base = "medium"
        elif score > 0:
            base = "low"
        else:
            base = "info"
    else:
        return "info"
    # CVSS escalates but never de-escalates an explicit critical/high
    if cvss is not None:
        try:
            score = float(cvss)
            cvss_sev = normalize_severity("", None) if False else None  # placeholder
            if score >= 9.0 and _SEVERITY_RANK[base] < 4:
                return "critical"
            if score >= 7.0 and _SEVERITY_RANK[base] < 3:
                return "high"
        except (TypeError, ValueError):
            pass
    return base


def severity_rank(severity: str) -> int:
    return _SEVERITY_RANK.get(str(severity or "").lower(), 0)


def dedup_key(asset: str, cve: str, port: int | None) -> str:
    return f"{(asset or '').lower()}|{(cve or '').upper()}|{port if port is not None else 'any'}"


def finding_identity(f: NormalizedExternalFinding) -> str:
    raw = f"{f.provider}|{f.source_finding_id}|{f.asset}|{f.port}|{','.join(sorted(f.cves))}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def deduplicate_findings(findings: list[NormalizedExternalFinding]) -> list[CorrelatedVulnerability]:
    """Same CVE + same asset (+ same port context) → ONE entity with sources[].

    Same CVE on different assets → distinct entities.
    Same asset with different CVEs → distinct entities.
    """
    grouped: dict[str, CorrelatedVulnerability] = {}
    order: list[str] = []
    for f in findings:
        cves = f.cves or ["NO-CVE"]
        for cve in cves:
            key = dedup_key(f.asset or f.hostname or "unknown", cve, f.port)
            if key not in grouped:
                grouped[key] = CorrelatedVulnerability(
                    vuln_id=f"hvuln-{hashlib.sha256(key.encode()).hexdigest()[:12]}",
                    primary_cve=cve if cve != "NO-CVE" else "",
                    cves=[] if cve == "NO-CVE" else [cve],
                    cwes=list(f.cwes),
                    asset=f.asset or f.hostname,
                    port=f.port,
                    service=f.service,
                    product=normalize_product(f.product),
                    version=f.version,
                    title=f.title,
                    severity=f.severity,
                    max_cvss=f.cvss,
                    sources=[f.provider],
                    finding_ids=[f.finding_id or f.source_finding_id],
                    description=f.description,
                    remediation=f.remediation,
                    references=list(f.references),
                )
                order.append(key)
            else:
                entity = grouped[key]
                if f.provider not in entity.sources:
                    entity.sources.append(f.provider)
                fid = f.finding_id or f.source_finding_id
                if fid and fid not in entity.finding_ids:
                    entity.finding_ids.append(fid)
                for cwe in f.cwes:
                    if cwe not in entity.cwes:
                        entity.cwes.append(cwe)
                if f.cvss is not None and (entity.max_cvss is None or f.cvss > entity.max_cvss):
                    entity.max_cvss = f.cvss
                if severity_rank(f.severity) > severity_rank(entity.severity):
                    entity.severity = f.severity
                for ref in f.references:
                    if ref not in entity.references:
                        entity.references.append(ref)
    return [grouped[k] for k in order]


def _native_product_strings(state: Any) -> list[tuple[str, str, str]]:
    """Return (product_norm, version, service) tuples from workspace state."""
    out: list[tuple[str, str, str]] = []
    try:
        for s in getattr(state, "software", []) or []:
            out.append((normalize_product(getattr(s, "product", "")),
                        str(getattr(s, "version", "") or ""), str(getattr(s, "service", "") or "")))
        for svc in getattr(state, "services", []) or []:
            prod = getattr(svc, "product", "") or getattr(svc, "service", "")
            if prod:
                out.append((normalize_product(str(prod)), str(getattr(svc, "version", "") or ""),
                            str(getattr(svc, "service", "") or "")))
    except Exception:
        pass
    return out


def correlate_finding_with_state(
    finding: NormalizedExternalFinding,
    state: Any,
    stale_days: int = 30,
) -> NormalizedExternalFinding:
    """Correlate ONE external observation with native HORCRUX evidence.

    Never invents versions. Scanner output stays UNVERIFIED unless native
    evidence corroborates (service/version match) or contradicts it.
    """
    updated = finding.model_copy(deep=True)
    reasons: list[str] = []

    # staleness first — a stale result must not become current truth
    if is_stale(updated, stale_days=stale_days):
        updated.stale = True
        updated.disposition = CorrelationDisposition.STALE.value
        updated.disposition_reason = "scanner result older than freshness window or predates current evidence"
        return updated

    native = _native_product_strings(state)
    fprod = normalize_product(updated.product)
    matched_service = False
    version_match: bool | None = None  # None = no version evidence either way
    port_match = False

    try:
        services = getattr(state, "services", []) or []
        for svc in services:
            try:
                sport = int(getattr(svc, "port", -1))
            except (TypeError, ValueError):
                sport = -1
            if updated.port is not None and sport == int(updated.port):
                port_match = True
                sprod = normalize_product(str(getattr(svc, "product", "") or getattr(svc, "service", "") or ""))
                if fprod and sprod and (fprod == sprod or fprod in sprod or sprod in fprod):
                    matched_service = True
                sver = str(getattr(svc, "version", "") or "").strip()
                if updated.version and sver:
                    version_match = (updated.version.strip() == sver)
                break
    except Exception:
        pass

    if not matched_service and fprod:
        for nprod, nver, _svc in native:
            if nprod and (fprod == nprod or fprod in nprod or nprod in fprod):
                matched_service = True
                if updated.version and nver:
                    version_match = (updated.version.strip() == nver.strip())
                break

    # HTTP reachability hint (affected functionality reachable)
    http_hint = False
    try:
        app = state.get_application_model() if hasattr(state, "get_application_model") else None
        eps = getattr(app, "endpoints", []) if app is not None else []
        if updated.port in (80, 443, 8000, 8080, 8443, 3000, 5000) and eps:
            http_hint = True
    except Exception:
        pass

    if version_match is False:
        updated.disposition = CorrelationDisposition.CONTRADICTED.value
        updated.disposition_reason = (
            "scanner-reported product version differs from HORCRUX-observed version (version mismatch conflict); "
            "requires investigation, not confirmation")
        reasons.append("version-mismatch")
    elif matched_service and (port_match or http_hint or version_match):
        updated.disposition = CorrelationDisposition.CORROBORATED.value
        updated.disposition_reason = "native service/version evidence corroborates scanner observation"
    elif matched_service:
        updated.disposition = CorrelationDisposition.APPLICABLE.value
        updated.disposition_reason = "product observed natively; version-level corroboration pending"
    elif fprod and not native:
        updated.disposition = CorrelationDisposition.UNVERIFIED.value
        updated.disposition_reason = "no native product evidence to corroborate or refute"
    elif fprod:
        updated.disposition = CorrelationDisposition.LIKELY_APPLICABLE.value
        updated.disposition_reason = "product not contradicted by native inventory"
    else:
        updated.disposition = CorrelationDisposition.UNVERIFIED.value
        updated.disposition_reason = "insufficient product context for correlation"
    _ = reasons
    return updated


def is_stale(finding: NormalizedExternalFinding, stale_days: int = 30,
             now: datetime | None = None) -> bool:
    ref = finding.scan_timestamp or finding.last_seen
    if ref is None:
        return False
    try:
        stamp = ref if ref.tzinfo else ref.replace(tzinfo=timezone.utc)
        current = now or datetime.now(timezone.utc)
        return (current - stamp).days > stale_days
    except Exception:
        return False


def apply_dispositions_to_entities(
    entities: list[CorrelatedVulnerability],
    findings: list[NormalizedExternalFinding],
) -> list[CorrelatedVulnerability]:
    """Propagate strongest finding disposition onto each deduplicated entity."""
    by_provider_fid = {(f.provider, f.finding_id or f.source_finding_id): f for f in findings}
    strength = {
        CorrelationDisposition.CONTRADICTED.value: 5,
        CorrelationDisposition.CORROBORATED.value: 4,
        CorrelationDisposition.STALE.value: 3,
        CorrelationDisposition.APPLICABLE.value: 2,
        CorrelationDisposition.LIKELY_APPLICABLE.value: 1,
        CorrelationDisposition.UNVERIFIED.value: 0,
    }
    for entity in entities:
        best = CorrelationDisposition.UNVERIFIED.value
        best_reason = ""
        corroborated = False
        stale_all = True
        for (prov, fid), f in by_provider_fid.items():
            if prov in entity.sources and fid in entity.finding_ids:
                if strength.get(f.disposition, 0) >= strength.get(best, 0):
                    best = f.disposition
                    best_reason = f.disposition_reason
                if f.disposition == CorrelationDisposition.CORROBORATED.value:
                    corroborated = True
                if not f.stale:
                    stale_all = False
        if len(set(entity.sources)) >= 2 and best != CorrelationDisposition.CONTRADICTED.value:
            best = CorrelationDisposition.CORROBORATED.value
            best_reason = f"corroborated across {len(set(entity.sources))} external providers ({', '.join(sorted(set(entity.sources)))})"
            corroborated = True
        entity.disposition = best
        entity.disposition_reason = best_reason
        entity.corroborated_by_native = corroborated
        entity.stale = stale_all and bool(entity.finding_ids)
    return entities
