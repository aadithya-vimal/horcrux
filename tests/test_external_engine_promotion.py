"""Test external vulnerability engine finding promotion into canonical findings."""

from __future__ import annotations

import tempfile

from horcrux.core.storage import Workspace
from horcrux.intel.vuln_engines.orchestrator import correlate_and_store
from horcrux.intel.vuln_engines.types import NormalizedExternalFinding
from horcrux.models import Service, Software, ValidationState


def test_correlate_and_store_promotes_canonical_findings():
    with tempfile.TemporaryDirectory() as tmpdir:
        ws = Workspace("ext-promote", base=tmpdir)
        state = ws.load()
        state.target = "192.168.1.50"
        state.services = [
            Service(host="192.168.1.50", port=80, protocol="tcp", service="http", product="Apache httpd", version="2.4.49")
        ]
        state.software = [
            Software(product="Apache httpd", version="2.4.49", service="http", source="nmap", confidence=0.9)
        ]
        ws.save(state)

        external_findings = [
            NormalizedExternalFinding(
                finding_id="tenable-apache-1",
                provider="tenable",
                source_product="Tenable One",
                source_finding_id="100",
                asset="192.168.1.50",
                port=80,
                service="http",
                product="Apache httpd",
                version="2.4.49",
                cves=["CVE-2021-41773"],
                severity="critical",
                cvss=9.8,
                title="Apache Path Traversal CVE-2021-41773",
                description="Path traversal flaw in Apache 2.4.49",
                remediation="Upgrade Apache to 2.4.51",
            ),
            NormalizedExternalFinding(
                finding_id="qualys-apache-1",
                provider="qualys",
                source_product="Qualys VMDR",
                source_finding_id="200",
                asset="192.168.1.50",
                port=80,
                service="http",
                product="Apache httpd",
                version="2.4.49",
                cves=["CVE-2021-41773"],
                severity="critical",
                cvss=9.8,
                title="Apache Path Traversal CVE-2021-41773",
                description="Path traversal flaw in Apache 2.4.49",
                remediation="Upgrade Apache to 2.4.51",
            ),
        ]

        correlated = correlate_and_store(ws, state, external_findings)
        assert len(correlated) == 1

        fresh = ws.load()
        # Ensure findings were promoted to fresh.findings!
        assert len(fresh.findings) >= 1

        cve_findings = [f for f in fresh.findings if "CVE-2021-41773" in f.cves]
        assert len(cve_findings) == 1

        f = cve_findings[0]
        assert f.category == "external-vulnerability"
        assert f.severity.value == "critical"
        assert f.cvss == 9.8
        assert "tenable" in f.source_providers
        assert "qualys" in f.source_providers
        assert f.correlation_status == "CORROBORATED"
        assert f.validation_state == ValidationState.confirmed
        assert "apache" in f.affected_component.lower()
        assert f.port == 80
