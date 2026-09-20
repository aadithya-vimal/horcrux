"""External Engine Acceptance and Conflict Resolution (Sections 9 and 10)."""

from __future__ import annotations

from pathlib import Path
from horcrux.core.storage import Workspace
from horcrux.intel.vuln_engines.orchestrator import correlate_and_store
from horcrux.intel.vuln_engines.types import (
    CorrelationDisposition,
    NormalizedExternalFinding,
)
from horcrux.models import Severity, Software, ValidationState, WorkspaceState


def test_section_9_external_engine_multi_provider_deduplication(tmp_path: Path):
    """Section 9: Tenable, Qualys, and Rapid7 reporting the same flaw produces ONE canonical Finding with multiple sources."""
    ws = Workspace("127.0.0.1")
    ws.root = tmp_path
    for d in (ws.root, ws.root/"raw", ws.root/"reports"):
        d.mkdir(parents=True, exist_ok=True)

    state = WorkspaceState(target="127.0.0.1")
    ws.save(state)

    # Three external findings for the exact same Apache vulnerability
    f_tenable = NormalizedExternalFinding(
        engine_id="tenable",
        provider_name="Tenable One",
        native_id="TEN-12345",
        cve="CVE-2021-41773",
        cwe="CWE-22",
        title="Apache HTTP Server Path Traversal",
        severity=Severity.critical.value,
        cvss_score=9.8,
        asset="127.0.0.1",
        port=80,
        protocol="tcp",
        affected_component="Apache",
        affected_version="2.4.49",
        raw_evidence="Tenable path traversal detected",
    )
    f_qualys = NormalizedExternalFinding(
        engine_id="qualys",
        provider_name="Qualys VMDR",
        native_id="QUAL-67890",
        cve="CVE-2021-41773",
        cwe="CWE-22",
        title="Apache 2.4.49 Path Traversal and RCE",
        severity=Severity.critical.value,
        cvss_score=9.8,
        asset="127.0.0.1",
        port=80,
        protocol="tcp",
        affected_component="Apache",
        affected_version="2.4.49",
        raw_evidence="Qualys signature 67890 triggered",
    )
    f_rapid7 = NormalizedExternalFinding(
        engine_id="rapid7",
        provider_name="Rapid7 InsightVM",
        native_id="R7-11223",
        cve="CVE-2021-41773",
        cwe="CWE-22",
        title="Apache Path Traversal Vulnerability",
        severity=Severity.critical.value,
        cvss_score=9.8,
        asset="127.0.0.1",
        port=80,
        protocol="tcp",
        affected_component="Apache",
        affected_version="2.4.49",
        raw_evidence="Rapid7 assessment check matched",
    )

    correlated = correlate_and_store(
        ws,
        state,
        [f_tenable, f_qualys, f_rapid7],
    )

    # Correlated list must have 1 vulnerability corroborated by all 3
    assert len(correlated) == 1
    assert correlated[0].cve == "CVE-2021-41773"
    assert len(correlated[0].sources) == 3
    assert correlated[0].disposition == CorrelationDisposition.CORROBORATED.value

    # Must create exactly ONE canonical Finding in state.findings, NOT three
    saved = ws.load()
    cve_findings = [f for f in saved.findings if "CVE-2021-41773" in f.cves]
    assert len(cve_findings) == 1, "Expected single deduplicated canonical finding"
    assert set(cve_findings[0].source_providers) == {"tenable", "qualys", "rapid7"}


def test_section_10_external_engine_conflict_resolution(tmp_path: Path):
    """Section 10: Scanner claims Apache vulnerable version, but native evidence says patched version -> NOT CONFIRMED."""
    ws = Workspace("127.0.0.1")
    ws.root = tmp_path
    for d in (ws.root, ws.root/"raw", ws.root/"reports"):
        d.mkdir(parents=True, exist_ok=True)

    state = WorkspaceState(target="127.0.0.1")
    # Native evidence verified Apache is 2.4.52 (patched against CVE-2021-41773)
    state.software = [
        Software(
            product="Apache",
            version="2.4.52",
            service="http",
            confidence=0.95,
            evidence=["HTTP Server header: Apache/2.4.52 (Unix)"],
        )
    ]
    ws.save(state)

    # External scanner reports old Apache 2.4.49
    f_scanner = NormalizedExternalFinding(
        engine_id="tenable",
        provider_name="Tenable One",
        native_id="TEN-12345",
        cve="CVE-2021-41773",
        title="Apache HTTP Server Path Traversal",
        severity=Severity.critical.value,
        cvss_score=9.8,
        asset="127.0.0.1",
        port=80,
        protocol="tcp",
        affected_component="Apache",
        affected_version="2.4.49",
        raw_evidence="Plugin matched banner",
    )

    correlated = correlate_and_store(
        ws,
        state,
        [f_scanner],
    )

    assert len(correlated) == 1
    # Must be marked CONTRADICTED or NOT_APPLICABLE because native evidence conflicts
    assert correlated[0].disposition in (CorrelationDisposition.CONTRADICTED.value, CorrelationDisposition.NOT_APPLICABLE.value)
    assert "version mismatch" in correlated[0].notes.lower() or "conflict" in correlated[0].notes.lower()

    # Conflicted scanner report must NEVER be promoted to confirmed finding in state.findings
    saved = ws.load()
    confirmed_findings = [f for f in saved.findings if "CVE-2021-41773" in f.cves and f.validation_state == ValidationState.confirmed]
    assert len(confirmed_findings) == 0, "Conflicted external finding must never be promoted to confirmed"
