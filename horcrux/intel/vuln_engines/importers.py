"""Imported-result support — Nessus XML + generic JSON.

Imported data is IMPORTED_RESULT with source/timestamp/artifact/provenance.
It is NEVER labeled as a live HORCRUX-executed scan.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from horcrux.intel.vuln_engines.normalize import (
    extract_cves,
    extract_cwes,
    normalize_severity,
)
from horcrux.intel.vuln_engines.types import DeploymentType, NormalizedExternalFinding

SEVERITY_INT_MAP = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}


def import_nessus_xml(path: str | Path) -> list[NormalizedExternalFinding]:
    """Parse .nessus (Nessus XML v2) exports into normalized observations."""
    xml_path = Path(path)
    root = ET.parse(str(xml_path)).getroot()
    now = datetime.now(timezone.utc)
    findings: list[NormalizedExternalFinding] = []
    for host in root.iter("ReportHost"):
        host_ip = host.get("name", "")
        props = {p.get("name", ""): (p.text or "") for p in host.iter("tag")}
        hostname = props.get("host-fqdn", props.get("hostname", ""))
        for item in host.iter("ReportItem"):
            plugin_id = item.get("pluginID", "")
            plugin_name = item.get("pluginName", "nessus finding")
            port = item.get("port", "0")
            try:
                port_i = int(port) if port not in ("0", "") else None
            except ValueError:
                port_i = None
            sev_raw = item.get("severity", "0")
            try:
                sev = SEVERITY_INT_MAP.get(int(sev_raw), "info")
            except ValueError:
                sev = "info"
            cves = [c.text.strip().upper() for c in item.iter("cve") if c.text]
            for extra in extract_cves(" ".join(c.text or "" for c in item.iter("description"))):
                if extra not in cves:
                    cves.append(extra)
            cvss_raw = "".join(c.text or "" for c in item.iter("cvss3_base_score")) or "".join(
                c.text or "" for c in item.iter("cvss_base_score"))
            try:
                cvss = float(cvss_raw) if cvss_raw.strip() else None
            except ValueError:
                cvss = None
            sev = normalize_severity(sev, cvss)
            desc = " ".join(c.text or "" for c in item.iter("description"))[:2000]
            sol = " ".join(c.text or "" for c in item.iter("solution"))[:1000]
            cwes = extract_cwes(desc)
            findings.append(NormalizedExternalFinding(
                finding_id=f"imported-tenable-{plugin_id}-{host_ip}-{port_i or 'na'}",
                provider="tenable", source_product="Tenable Nessus (imported)",
                source_finding_id=plugin_id, asset=host_ip, hostname=hostname,
                port=port_i, service=item.get("svc_name", ""), protocol=item.get("protocol", "tcp"),
                cves=cves, cwes=cwes, severity=sev, cvss=cvss,
                title=plugin_name, description=desc,
                evidence=[f"imported nessus plugin {plugin_id}: {plugin_name}"],
                first_seen=now, last_seen=now, scan_timestamp=now,
                scanner_state="imported", remediation=sol,
                deployment_type=DeploymentType.IMPORTED_RESULT.value, imported=True,
                provenance=f"imported .nessus artifact {xml_path.name}",
                source_artifacts=[str(xml_path)],
                raw={"pluginID": plugin_id, "pluginName": plugin_name, "host": host_ip}))
    return findings


def import_generic_json(path: str | Path, provider: str = "generic") -> list[NormalizedExternalFinding]:
    """Import provider-exported JSON lists (documented shapes only)."""
    json_path = Path(path)
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    items = payload if isinstance(payload, list) else payload.get("findings", payload.get("vulnerabilities", []))
    now = datetime.now(timezone.utc)
    findings: list[NormalizedExternalFinding] = []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        cves = [str(c).upper() for c in (item.get("cves", []) or [])]
        cves += extract_cves(str(item.get("title", "")), str(item.get("description", "")))
        findings.append(NormalizedExternalFinding(
            finding_id=f"imported-{provider}-{item.get('id', len(findings))}",
            provider=provider, source_product=f"{provider} (imported)",
            source_finding_id=str(item.get("id", "")),
            asset=str(item.get("asset", item.get("host", ""))),
            hostname=str(item.get("hostname", "")),
            port=item.get("port"), service=str(item.get("service", "")),
            product=str(item.get("product", "")), version=str(item.get("version", "")),
            cves=cves, severity=normalize_severity(item.get("severity", "info")),
            title=str(item.get("title", "imported finding")),
            description=str(item.get("description", "")),
            evidence=[f"imported {provider} finding {item.get('id', '?')}"],
            first_seen=now, last_seen=now, scan_timestamp=now,
            deployment_type=DeploymentType.IMPORTED_RESULT.value, imported=True,
            provenance=f"imported JSON artifact {json_path.name}",
            source_artifacts=[str(json_path)], raw=dict(item)))
    return findings


def import_results(path: str | Path, provider: str = "auto") -> list[NormalizedExternalFinding]:
    p = Path(path)
    if p.suffix.lower() in (".nessus", ".xml") or provider in ("tenable", "nessus"):
        try:
            return import_nessus_xml(p)
        except ET.ParseError:
            pass
    return import_generic_json(p, provider="tenable" if provider == "auto" else provider)


def summarize_import(findings: list[NormalizedExternalFinding]) -> dict[str, Any]:
    providers: dict[str, int] = {}
    for f in findings:
        providers[f.provider] = providers.get(f.provider, 0) + 1
    return {"total": len(findings), "by_provider": providers, "imported": True,
            "provenance": sorted({f.provenance for f in findings})}
