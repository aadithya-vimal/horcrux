"""CVE Acceptance Test and False Positive Version Rejection (Sections 6 and 7)."""

from __future__ import annotations

from horcrux.intel.cve.resolver import correlate_software_vulnerabilities
from horcrux.models import Software, ValidationState, WorkspaceState


def test_section_6_cve_deterministic_acceptance():
    """Section 6: Proves component evidence -> CVE resolution -> affected-version match -> canonical Finding."""
    state = WorkspaceState(target="127.0.0.1")
    state.software = [
        Software(
            product="ProFTPD",
            version="1.3.5",
            service="ftp",
            confidence=0.95,
            evidence=["ProFTPD 1.3.5 banner on port 21"],
        )
    ]

    correlate_software_vulnerabilities(state)

    cve_findings = [f for f in state.findings if "CVE-2015-3306" in f.cves]
    assert len(cve_findings) == 1, "Expected exactly 1 canonical finding for CVE-2015-3306"

    f = cve_findings[0]
    assert f.cves == ["CVE-2015-3306"]
    assert "CWE-284" in f.cwes
    assert f.cvss == 9.8
    assert f.affected_component.lower() == "proftpd"
    assert f.affected_version == "1.3.5"
    assert "cpe:2.3:a:proftpd:proftpd:1.3.5" in f.cpe
    assert f.validation_state == ValidationState.confirmed
    assert len(f.evidence) >= 1
    assert "cve_resolver" in f.source_tools
    assert "authoritative_offline_kb" in f.source_providers


def test_section_7_cve_false_positive_rejection():
    """Section 7: Product matches, but version is outside vulnerable range -> NO CVE finding."""
    state = WorkspaceState(target="127.0.0.1")
    # ProFTPD 1.3.6 is patched against CVE-2015-3306 (which affects <= 1.3.5)
    state.software = [
        Software(
            product="ProFTPD",
            version="1.3.6",
            service="ftp",
            confidence=0.95,
            evidence=["ProFTPD 1.3.6 banner on port 21"],
        )
    ]

    correlate_software_vulnerabilities(state)

    # Must NOT produce CVE-2015-3306 finding
    cve_findings = [f for f in state.findings if "CVE-2015-3306" in f.cves]
    assert len(cve_findings) == 0, "Patched version 1.3.6 must NOT match CVE-2015-3306"
