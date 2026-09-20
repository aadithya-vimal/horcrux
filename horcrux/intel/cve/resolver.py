"""CVE & Component Intelligence Resolver for HORCRUX.

Performs component name normalization, CPE 2.3 URI synthesis,
and offline/cached vulnerability matching for reliable versioned software.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from horcrux.intel.cve.knowledge_base import (
    KNOWN_VULNERABILITIES,
    ComponentVulnerability,
)
from horcrux.models import Finding, FindingStatus, Severity, ValidationState


# Common product normalization mappings: raw_product_substr -> (vendor, canonical_product)
PRODUCT_ALIASES: dict[str, tuple[str, str]] = {
    "proftpd": ("proftpd", "proftpd"),
    "apache": ("apache", "apache"),
    "httpd": ("apache", "apache"),
    "openssh": ("openbsd", "openssh"),
    "openssl": ("openssl", "openssl"),
    "spring": ("vmware", "spring_framework"),
    "log4j": ("apache", "log4j"),
    "jenkins": ("jenkins", "jenkins"),
    "ejs": ("ejs", "ejs"),
    "node-serialize": ("nodejs", "node-serialize"),
    "nginx": ("nginx", "nginx"),
    "mysql": ("oracle", "mysql"),
    "postgresql": ("postgresql", "postgresql"),
    "sqlite": ("sqlite", "sqlite"),
    "express": ("expressjs", "express"),
    "angular": ("google", "angular"),
    "jsonwebtoken": ("auth0", "jsonwebtoken"),
}


def normalize_component(product_raw: str) -> tuple[str, str]:
    """Normalize raw banner/product name to (vendor, canonical_product)."""
    p_lower = product_raw.lower().strip()
    for alias, (vendor, canonical) in PRODUCT_ALIASES.items():
        if alias in p_lower:
            return vendor, canonical
    # Fallback to sanitized raw string
    clean = re.sub(r"[^a-z0-9_-]", "_", p_lower)
    return clean, clean


def synthesize_cpe(vendor: str, product: str, version: str = "*", part: str = "a") -> str:
    """Synthesize a valid CPE 2.3 URI string."""
    v_clean = vendor.strip().lower() or "*"
    p_clean = product.strip().lower() or "*"
    ver_clean = version.strip().lower() if version else "*"
    # Sanitize characters not allowed in basic CPE 2.3 formatted string
    v_clean = re.sub(r"[^a-z0-9._-]", "_", v_clean)
    p_clean = re.sub(r"[^a-z0-9._-]", "_", p_clean)
    ver_clean = re.sub(r"[^a-z0-9._-]", "_", ver_clean)
    return f"cpe:2.3:{part}:{v_clean}:{p_clean}:{ver_clean}:*:*:*:*:*:*:*"


def match_vulnerabilities(product: str, version: str, service: str = "") -> list[ComponentVulnerability]:
    """Find known component vulnerabilities matching product and version."""
    if not product or not version:
        return []

    vendor, canon_product = normalize_component(product)
    matches: list[ComponentVulnerability] = []

    for entry in KNOWN_VULNERABILITIES:
        # Check product match (canonical or vendor)
        if entry.product == canon_product or entry.vendor == vendor or entry.product in product.lower():
            if entry.matches_version(version):
                matches.append(entry)

    return matches


def correlate_software_vulnerabilities(workspace_or_state: Any) -> list[Finding]:
    """Inspect software and services in state and generate canonical vulnerability findings.

    Accepts either a Workspace or a WorkspaceState.
    """
    is_ws = hasattr(workspace_or_state, "load")
    state = workspace_or_state.load() if is_ws else workspace_or_state

    findings: list[Finding] = []
    seen_keys: set[str] = set()

    # 1. Inspect software entries
    software_list = getattr(state, "software", []) or []
    for sw in software_list:
        prod = getattr(sw, "product", "")
        ver = getattr(sw, "version", "")
        svc = getattr(sw, "service", "")
        conf = getattr(sw, "confidence", 0.5)

        if not prod or not ver or conf < 0.6:
            continue

        matched = match_vulnerabilities(prod, ver, svc)
        for vuln in matched:
            key = f"{vuln.cve}:{state.target}:{prod}:{ver}"
            if key in seen_keys:
                continue
            seen_keys.add(key)

            vendor, canon_prod = normalize_component(prod)
            cpe_uri = synthesize_cpe(vendor, canon_prod, ver)

            sev_enum = getattr(Severity, vuln.severity.lower(), Severity.high)
            fid = f"vuln-{vuln.cve.lower()}-{canon_prod}"

            finding = Finding(
                id=fid,
                title=vuln.title,
                category="component-vulnerability",
                severity=sev_enum,
                confidence=min(0.95, max(0.70, conf)),
                status=FindingStatus.suspected,
                validation_state=ValidationState.confirmed if conf >= 0.85 else ValidationState.likely,
                target=state.target,
                affected_asset=f"{state.target}:{svc}" if svc else state.target,
                source_tool="cve_resolver",
                source_tools=["cve_resolver"],
                source_providers=["cve_kb", "authoritative_offline_kb"],
                cves=vuln.cves,
                cwes=vuln.cwes,
                cvss=vuln.cvss,
                cvss_vector=vuln.cvss_vector,
                cpe=cpe_uri,
                affected_component=vuln.product,
                affected_version=ver,
                affected_service=svc,
                access_context="unauthenticated",
                exploitability_state=vuln.exploitability,
                exploit_intelligence_refs=vuln.exploit_refs,
                correlation_status="CORROBORATED",
                evidence=[
                    f"Component: {prod} version {ver}",
                    f"CPE: {cpe_uri}",
                    f"Vulnerability: {vuln.cve} (CVSS {vuln.cvss})",
                    f"Observed service: {svc or 'detected-software'}",
                ],
                artifacts=[],
                reproduction=[
                    f"Verify component version: {prod} {ver}",
                    f"NVD Reference: https://nvd.nist.gov/vuln/detail/{vuln.cve}",
                ] + ([f"Exploit-DB: {ref}" for ref in vuln.exploit_refs]),
                why_it_matters=vuln.description,
                recommended_next_action=vuln.remediation or f"Upgrade {vuln.product} to a patched release.",
                next_action=vuln.remediation or f"Upgrade {vuln.product} to a patched release.",
            )
            findings.append(finding)
            if is_ws:
                workspace_or_state.upsert_finding(finding)
            else:
                existing_ids = {f.id for f in getattr(state, "findings", [])}
                if finding.id not in existing_ids:
                    state.findings.append(finding)

    # 2. Inspect services with product & version
    services_list = getattr(state, "services", []) or []
    for s in services_list:
        prod = getattr(s, "product", "")
        ver = getattr(s, "version", "")
        port = getattr(s, "port", None)
        proto = getattr(s, "protocol", "tcp")
        svc_name = getattr(s, "service", "")

        if not prod or not ver:
            continue

        matched = match_vulnerabilities(prod, ver, svc_name)
        for vuln in matched:
            key = f"{vuln.cve}:{state.target}:{port}:{ver}"
            if key in seen_keys:
                continue
            seen_keys.add(key)

            vendor, canon_prod = normalize_component(prod)
            cpe_uri = synthesize_cpe(vendor, canon_prod, ver)
            sev_enum = getattr(Severity, vuln.severity.lower(), Severity.high)
            fid = f"vuln-{vuln.cve.lower()}-port{port or 'svc'}"

            finding = Finding(
                id=fid,
                title=vuln.title,
                category="component-vulnerability",
                severity=sev_enum,
                confidence=0.92,
                status=FindingStatus.suspected,
                validation_state=ValidationState.confirmed,
                target=state.target,
                affected_asset=f"{state.target}:{port}/{proto}" if port else state.target,
                protocol=proto,
                port=port,
                source_tool="cve_resolver",
                source_tools=["cve_resolver"],
                source_providers=["cve_kb", "authoritative_offline_kb"],
                cves=vuln.cves,
                cwes=vuln.cwes,
                cvss=vuln.cvss,
                cvss_vector=vuln.cvss_vector,
                cpe=cpe_uri,
                affected_component=vuln.product,
                affected_version=ver,
                affected_service=svc_name,
                access_context="unauthenticated",
                exploitability_state=vuln.exploitability,
                exploit_intelligence_refs=vuln.exploit_refs,
                correlation_status="CORROBORATED",
                evidence=[
                    f"Service banner: {prod} {ver} running on port {port}/{proto}",
                    f"CPE: {cpe_uri}",
                    f"Vulnerability: {vuln.cve} (CVSS {vuln.cvss})",
                ],
                reproduction=[
                    f"Probe service banner: nc -nv {state.target} {port}",
                    f"NVD Reference: https://nvd.nist.gov/vuln/detail/{vuln.cve}",
                ] + ([f"Exploit-DB: {ref}" for ref in vuln.exploit_refs]),
                why_it_matters=vuln.description,
                recommended_next_action=vuln.remediation or f"Upgrade {vuln.product} to a patched release.",
                next_action=vuln.remediation or f"Upgrade {vuln.product} to a patched release.",
            )
            findings.append(finding)
            if is_ws:
                workspace_or_state.upsert_finding(finding)
            else:
                existing_ids = {f.id for f in getattr(state, "findings", [])}
                if finding.id not in existing_ids:
                    state.findings.append(finding)

    return findings
