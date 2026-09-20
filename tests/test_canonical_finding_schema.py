"""Test canonical vulnerability finding schema and scan profile configurations."""

from __future__ import annotations

from horcrux.models import Finding, FindingStatus, PROFILES, Severity, ValidationState, get_profile


def test_finding_canonical_fields_default_initialization():
    f = Finding(
        id="test-finding-1",
        title="SQL Injection in login endpoint",
        category="injection-sqli",
        severity=Severity.critical,
        confidence=0.95,
        status=FindingStatus.verified,
        validation_state=ValidationState.confirmed,
        target="example.local",
        affected_asset="/api/v1/login",
        source_tool="sqli_probe",
    )

    assert f.source_tool == "sqli_probe"
    assert f.source_tools == ["sqli_probe"]
    assert f.source_providers == []
    assert f.cves == []
    assert f.cwes == []
    assert f.cvss is None
    assert f.cvss_vector == ""
    assert f.cpe == ""
    assert f.affected_component == ""
    assert f.affected_version == ""
    assert f.access_context == ""
    assert f.exploitability_state == "MANUAL_REVIEW"
    assert f.correlation_status == "NATIVE"


def test_finding_canonical_fields_explicit_population():
    f = Finding(
        id="cve-2021-41773-apache",
        title="Apache HTTP Server 2.4.49 Path Traversal and RCE",
        category="component-vulnerability",
        severity=Severity.critical,
        confidence=0.98,
        status=FindingStatus.verified,
        validation_state=ValidationState.confirmed,
        target="web.example.local",
        affected_asset="web.example.local:80/tcp",
        protocol="tcp",
        port=80,
        source_tool="cve_resolver",
        source_tools=["cve_resolver", "vuln:tenable"],
        source_providers=["cve_kb", "tenable"],
        cves=["CVE-2021-41773", "CVE-2021-42013"],
        cwes=["CWE-22"],
        cvss=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cpe="cpe:2.3:a:apache:apache:2.4.49:*:*:*:*:*:*:*",
        affected_component="apache",
        affected_version="2.4.49",
        affected_service="http",
        access_context="unauthenticated",
        exploitability_state="HIGH (REMOTE)",
        exploit_intelligence_refs=["EDB-ID:50383"],
        correlation_status="CORROBORATED",
        evidence=["Component: Apache version 2.4.49"],
    )

    dumped = f.model_dump()
    assert dumped["cves"] == ["CVE-2021-41773", "CVE-2021-42013"]
    assert dumped["cwes"] == ["CWE-22"]
    assert dumped["cvss"] == 9.8
    assert dumped["cpe"] == "cpe:2.3:a:apache:apache:2.4.49:*:*:*:*:*:*:*"
    assert dumped["source_providers"] == ["cve_kb", "tenable"]
    assert dumped["exploit_intelligence_refs"] == ["EDB-ID:50383"]

    # Deserialization check
    reconstructed = Finding.model_validate(dumped)
    assert reconstructed.id == f.id
    assert reconstructed.cvss == 9.8
    assert reconstructed.source_providers == ["cve_kb", "tenable"]


def test_scan_profiles_cve_correlation():
    assert get_profile("deep").cve_correlation is True
    assert get_profile("web").cve_correlation is True
    assert get_profile("service").cve_correlation is True
    assert get_profile("intel").cve_correlation is True
    assert get_profile("full").cve_correlation is True
    # quick remains minimal
    assert get_profile("quick").cve_correlation is False
