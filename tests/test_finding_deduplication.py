"""Tests for canonical finding deduplication across tools (Phases H and I)."""

from horcrux.intel.vulnerability_adjudicator import (
    record_or_merge_canonical_finding,
    canonicalize_state_findings,
)
from horcrux.models import Finding, FindingStatus, Severity, ValidationState, WorkspaceState


def test_record_or_merge_canonical_finding():
    state = WorkspaceState(target="testapp.local")

    f1 = Finding(
        id="find-1",
        title="SQL Injection in search query parameter",
        category="injection-sqli",
        severity=Severity.critical,
        confidence=0.9,
        affected_asset="/rest/products/search",
        target="testapp.local",
        cwes=["CWE-89"],
        source_tool="http_probe",
        evidence=["Observed SQLite syntax error"],
    )
    record_or_merge_canonical_finding(state, f1)
    assert len(state.findings) == 1
    assert state.findings[0].id == f1.id
    assert "http_probe" in state.findings[0].source_tools

    f2 = Finding(
        id="find-2",
        title="Confirmed SQL Injection in search",
        category="injection-sqli",
        severity=Severity.critical,
        confidence=0.95,
        affected_asset="/rest/products/search",
        target="testapp.local",
        cwes=["CWE-89"],
        source_tool="validator",
        evidence=["Observed boolean blind differential response"],
    )
    fid = record_or_merge_canonical_finding(state, f2)
    assert fid == f1.id
    assert len(state.findings) == 1
    assert state.findings[0].id == f1.id
    assert "http_probe" in state.findings[0].source_tools
    assert "validator" in state.findings[0].source_tools
    assert len(state.findings[0].evidence) == 2


def test_canonicalize_state_findings_dedupes_existing():
    state = WorkspaceState(target="testapp.local")
    f1 = Finding(
        id="find-1",
        title="IDOR in Basket",
        category="authorization",
        severity=Severity.high,
        confidence=0.85,
        affected_asset="/api/BasketItems/1",
        target="testapp.local",
        source_tool="authz_compare",
    )
    f2 = Finding(
        id="find-2",
        title="Broken Object Level Auth on Basket",
        category="authorization",
        severity=Severity.high,
        confidence=0.9,
        affected_asset="/api/BasketItems/1",
        target="testapp.local",
        source_tool="nuclei",
    )
    state.findings.extend([f1, f2])
    assert len(state.findings) == 2

    canonicalize_state_findings(state)
    assert len(state.findings) == 1
    assert "authz_compare" in state.findings[0].source_tools
    assert "nuclei" in state.findings[0].source_tools
