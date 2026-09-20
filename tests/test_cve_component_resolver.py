"""Test CVE & Component Intelligence Resolver."""

from __future__ import annotations

import tempfile
import pathlib

from horcrux.core.storage import Workspace
from horcrux.intel.cve.resolver import (
    correlate_software_vulnerabilities,
    match_vulnerabilities,
    normalize_component,
    synthesize_cpe,
)
from horcrux.models import Service, Software, WorkspaceState


def test_normalize_component():
    vendor, product = normalize_component("Apache httpd 2.4.49")
    assert vendor == "apache"
    assert product == "apache"

    vendor, product = normalize_component("ProFTPD")
    assert vendor == "proftpd"
    assert product == "proftpd"

    vendor, product = normalize_component("OpenSSH_7.4p1")
    assert vendor == "openbsd"
    assert product == "openssh"


def test_synthesize_cpe():
    cpe = synthesize_cpe("proftpd", "proftpd", "1.3.5")
    assert cpe == "cpe:2.3:a:proftpd:proftpd:1.3.5:*:*:*:*:*:*:*"

    cpe_os = synthesize_cpe("linux", "linux_kernel", "5.10", part="o")
    assert cpe_os == "cpe:2.3:o:linux:linux_kernel:5.10:*:*:*:*:*:*:*"


def test_match_vulnerabilities():
    matches = match_vulnerabilities("proftpd", "1.3.5")
    assert len(matches) >= 1
    assert any(m.cve == "CVE-2015-3306" for m in matches)

    apache_matches = match_vulnerabilities("apache", "2.4.49")
    assert len(apache_matches) >= 1
    assert any("CVE-2021-41773" in m.cves for m in apache_matches)

    # Clean non-vulnerable version should not match
    no_matches = match_vulnerabilities("proftpd", "1.3.8")
    assert len(no_matches) == 0


def test_correlate_software_vulnerabilities_end_to_end():
    with tempfile.TemporaryDirectory() as tmpdir:
        ws = Workspace("cve-test", base=tmpdir)
        state = ws.load()
        state.target = "target.corp"
        state.software = [
            Software(product="ProFTPD", version="1.3.5", service="ftp", source="nmap", confidence=0.95),
            Software(product="Apache", version="2.4.49", service="http", source="banner", confidence=0.90),
        ]
        state.services = [
            Service(host="target.corp", port=21, protocol="tcp", service="ftp", product="ProFTPD", version="1.3.5"),
        ]
        ws.save(state)

        findings = correlate_software_vulnerabilities(ws)
        assert len(findings) >= 2

        proftpd_findings = [f for f in findings if "CVE-2015-3306" in f.cves]
        assert len(proftpd_findings) >= 1
        pf = proftpd_findings[0]
        assert pf.category == "component-vulnerability"
        assert pf.severity.value == "critical"
        assert pf.cpe == "cpe:2.3:a:proftpd:proftpd:1.3.5:*:*:*:*:*:*:*"
        assert "EDB-ID:36742" in pf.exploit_intelligence_refs
        assert pf.source_tool == "cve_resolver"
        assert "cve_kb" in pf.source_providers
        assert pf.affected_component == "proftpd"
        assert pf.affected_version == "1.3.5"
