"""Comprehensive test suite for the HORCRUX Live Acceptance Gate, Provenance Separation,
Zero-Finding Success, True Disk Persistence, CVE vs Non-CVE Flaws, and Nuclei Adjudication.
"""
from __future__ import annotations

import json
import pytest
from horcrux.core.acceptance import (
    evaluate_live_acceptance,
    evaluate_vulnerability_adjudication_acceptance,
    derive_target_provenance,
    verify_workspace_persistence,
    verify_model_roundtrip,
    AcceptanceResult,
)
from horcrux.core.storage import Workspace
from horcrux.models import (
    WorkspaceState, Finding, Severity, ValidationState, FindingStatus,
    Service, Software, LiveExecutionRecord
)
from horcrux.intel.application_model import ApplicationModel, SemanticEndpoint
from horcrux.intel.investigations import Investigation, InvestigationState
from horcrux.intel.cve.resolver import correlate_software_vulnerabilities
from horcrux.core.intel import run_nuclei


def test_synthetic_fixture_strictly_blocked():
    """Synthetic fixtures must NEVER satisfy the live acceptance gate."""
    state = WorkspaceState(target="127.0.0.1")
    state.target_provenance = "SYNTHETIC_TEST_TARGET"
    state.assessment_run_id = "run-123"
    state.services = [Service(host="127.0.0.1", port=3000, protocol="tcp", service="http", state="open")]

    state.findings = [
        Finding(
            id="authz-1",
            title="IDOR",
            category="authorization",
            severity=Severity.high,
            confidence=0.9,
            target="127.0.0.1",
            validation_state=ValidationState.confirmed,
            evidence=["User A accessed User B object"],
            source_tools=["authz_compare"],
        )
    ]

    result = evaluate_live_acceptance(state)
    assert result.gate == "BLOCKED"
    assert "SYNTHETIC_TEST_TARGET" in result.reason
    assert "integration tests only" in result.reason.lower()


def test_unknown_provenance_strictly_blocked():
    """Unknown provenance must default to BLOCKED, not PASSED."""
    state = WorkspaceState(target="127.0.0.1")
    state.target_provenance = "UNKNOWN"

    result = evaluate_live_acceptance(state)
    assert result.gate == "BLOCKED"
    assert "UNKNOWN" in result.reason or "unestablished provenance" in result.reason


def test_zero_finding_live_acceptance_passes(tmp_path):
    """Section 1 & 11: A real target with ZERO confirmed findings must PASS live acceptance
    if execution, discovery, investigations, and persistence operated correctly.
    The security verdict must be 'NO CONFIRMED FINDINGS' (never 'CLEAN' or 'SECURE').
    """
    state = WorkspaceState(target="127.0.0.1:8080")
    state.target_provenance = "REAL_LOCAL_TARGET"
    state.live_execution_observed = True
    state.provenance_source = "live_socket_connect"
    state.assessment_run_id = "run-zero-findings"
    state.record_live_execution(
        capability_id="socket_connect",
        target="127.0.0.1:8080",
        host="127.0.0.1",
        port=8080,
        protocol="tcp",
        success=True,
    )
    state.services = [
        Service(host="127.0.0.1", port=8080, protocol="tcp", service="http", state="open", product="Nginx")
    ]

    app = ApplicationModel(base_url="http://127.0.0.1:8080")
    app.endpoints = [
        SemanticEndpoint(path="/health", method="GET", classification="standard")
    ]
    state.set_application_model(app)

    inv = Investigation(
        id="inv-health-check",
        objective="Verify web endpoint health",
        state=InvestigationState.COMPLETE,
    )
    state.set_investigations([inv])

    # Zero findings!
    state.findings = []

    result = evaluate_live_acceptance(state)
    assert result.gate == "PASSED", f"Expected PASSED but got {result.gate}: {result.reason}"
    assert result.findings_confirmed == 0
    assert result.findings_confirmed_no_cve == 0
    assert result.findings_confirmed_with_cve == 0
    assert result.security_verdict == "NO CONFIRMED FINDINGS"
    assert "CLEAN" not in result.security_verdict
    assert "SECURE" not in result.security_verdict


def test_acceptance_gate_logic_with_simulated_real_provenance():
    """Gate logic unit test: proves that the evaluation function validates all invariants
    when confirmed findings exist.
    NOTE: This is a unit test of the evaluator rules; it does NOT prove production live execution.
    """
    state = WorkspaceState(target="192.168.1.50")
    state.target_provenance = "REAL_REMOTE_TARGET"
    state.live_execution_observed = True
    state.provenance_source = "live_network_probe"
    state.assessment_run_id = "run-live-456"
    state.record_live_execution(
        capability_id="http_probe",
        target="192.168.1.50:80",
        host="192.168.1.50",
        port=80,
        protocol="http",
        success=True,
    )
    state.services = [
        Service(host="192.168.1.50", port=80, protocol="tcp", service="http", state="open", product="Apache")
    ]

    app = ApplicationModel(base_url="http://192.168.1.50")
    app.endpoints = [
        SemanticEndpoint(path="/api/user/1", method="GET", classification="object_resource")
    ]
    state.set_application_model(app)

    inv = Investigation(
        id="inv-live-1",
        objective="Verify object authorization",
        state=InvestigationState.SUPPORTED,
    )
    state.set_investigations([inv])

    f = Finding(
        id="finding-live-1",
        title="BOLA on /api/user/1",
        category="authorization",
        severity=Severity.high,
        confidence=0.9,
        target="192.168.1.50",
        validation_state=ValidationState.confirmed,
        evidence=["Unauthorized object data returned with status 200 via curl http://192.168.1.50/api/user/1"],
        cves=[],
        cwes=["CWE-639"],
        investigation_id="inv-live-1",
        source_tools=["authz_compare"],
        reproduction=["curl -s -i http://192.168.1.50/api/user/1"],
    )
    state.findings = [f]

    result = evaluate_live_acceptance(state)
    assert result.gate == "PASSED"
    assert result.findings_confirmed == 1
    assert result.findings_confirmed_no_cve == 1
    assert result.investigations_ready_at_close == 0
    assert result.persistence_verified is True


def test_investigation_execution_count_semantics():
    """Section 1: BLOCKED and UNAVAILABLE must NOT be counted as executed."""
    state = WorkspaceState(target="192.168.1.50")
    state.target_provenance = "REAL_REMOTE_TARGET"
    state.live_execution_observed = True
    state.assessment_run_id = "run-inv-test"
    state.record_live_execution(capability_id="socket", target="192.168.1.50", success=True)
    state.services = [Service(host="192.168.1.50", port=80, protocol="tcp", service="http", state="open")]

    inv_done = Investigation(id="inv-1", objective="Test SQLi", state=InvestigationState.COMPLETE)
    inv_supp = Investigation(id="inv-2", objective="Test IDOR", state=InvestigationState.SUPPORTED)
    inv_blocked = Investigation(id="inv-3", objective="SMB scan", state=InvestigationState.BLOCKED)
    inv_unavail = Investigation(id="inv-4", objective="Nuclei scan", state=InvestigationState.UNAVAILABLE)
    inv_not_app = Investigation(id="inv-5", objective="S3 check", state=InvestigationState.SCOPE_BLOCKED)

    state.set_investigations([inv_done, inv_supp, inv_blocked, inv_unavail, inv_not_app])

    result = evaluate_live_acceptance(state)
    assert result.investigations_executed == 2
    assert result.investigations_blocked == 3
    assert result.investigations_scheduled == 5


def test_per_finding_evidence_chain_enforcement():
    """Section 2: EVERY confirmed finding must have an evidence chain; failure on any finding fails gate."""
    state = WorkspaceState(target="192.168.1.50")
    state.target_provenance = "REAL_REMOTE_TARGET"
    state.live_execution_observed = True
    state.assessment_run_id = "run-chain-test"
    state.record_live_execution(capability_id="socket", target="192.168.1.50", success=True)
    state.services = [Service(host="192.168.1.50", port=80, protocol="tcp", service="http", state="open")]

    inv = Investigation(id="inv-1", objective="Check auth", state=InvestigationState.SUPPORTED)
    state.set_investigations([inv])

    f_valid = Finding(
        id="f-good",
        title="Valid IDOR",
        category="authorization",
        severity=Severity.high,
        confidence=0.9,
        target="192.168.1.50",
        validation_state=ValidationState.confirmed,
        evidence=["Observed HTTP 200 via curl"],
        source_tools=["authz_compare"],
        investigation_id="inv-1",
        reproduction=["curl http://192.168.1.50/api/1"],
    )

    f_no_ev = Finding(
        id="f-no-ev",
        title="No Evidence Finding",
        category="authorization",
        severity=Severity.high,
        confidence=0.9,
        target="192.168.1.50",
        validation_state=ValidationState.confirmed,
        evidence=[],
        evidence_refs=[],
        source_tools=["authz_compare"],
        investigation_id="inv-1",
    )

    state.findings = [f_valid, f_no_ev]
    result = evaluate_live_acceptance(state)
    assert result.gate == "FAILED"
    assert any("f-no-ev has no evidence" in err for err in result.per_finding_failures)


def test_provenance_requires_live_execution_records():
    """Section 4 & 5: Provenance must not pass without genuine LiveExecutionRecord entries."""
    state = WorkspaceState(target="192.168.1.50")
    state.target_provenance = "REAL_REMOTE_TARGET"
    # live_execution_observed set to True, but zero live_execution_records!
    state.live_execution_observed = True
    state.live_execution_records = []
    state.assessment_run_id = "run-fake"
    state.services = [Service(host="192.168.1.50", port=80, protocol="tcp", service="http", state="open")]

    result = evaluate_live_acceptance(state)
    assert result.gate == "FAILED"
    assert any("live_execution_records_present" in c["name"] and not c["passed"] for c in result.checks)


def test_untested_high_value_discovery_fails():
    """Section 7: High-value discoveries (e.g. GraphQL, Admin) that disappear cause gate failure."""
    state = WorkspaceState(target="192.168.1.50")
    state.target_provenance = "REAL_REMOTE_TARGET"
    state.live_execution_observed = True
    state.assessment_run_id = "run-disc-test"
    state.record_live_execution(capability_id="socket", target="192.168.1.50", success=True)
    state.services = [Service(host="192.168.1.50", port=80, protocol="tcp", service="http", state="open")]

    app = ApplicationModel(base_url="http://192.168.1.50")
    app.endpoints = [
        SemanticEndpoint(path="/graphql", method="POST"),
        SemanticEndpoint(path="/admin/dashboard", method="GET"),
    ]
    state.set_application_model(app)

    inv = Investigation(id="inv-other", objective="Check robots.txt", state=InvestigationState.COMPLETE)
    state.set_investigations([inv])

    f = Finding(
        id="f-robots",
        title="robots.txt",
        category="web",
        severity=Severity.info,
        confidence=0.8,
        target="192.168.1.50",
        validation_state=ValidationState.confirmed,
        evidence=["robots.txt content"],
        source_tools=["http_probe"],
        investigation_id="inv-other",
        reproduction=["curl http://192.168.1.50/robots.txt"],
    )
    state.findings = [f]

    result = evaluate_live_acceptance(state)
    assert result.gate == "FAILED"
    assert any("no_silently_untested_high_value_discoveries" in c["name"] and not c["passed"] for c in result.checks)
    assert len(result.untested_high_value_discoveries) >= 1


def test_real_target_fails_when_ready_investigations_remain():
    """Assessment must NOT pass if READY investigations remain unfinalized."""
    state = WorkspaceState(target="192.168.1.50")
    state.target_provenance = "REAL_LOCAL_TARGET"
    state.live_execution_observed = True
    state.assessment_run_id = "run-live-789"
    state.record_live_execution(capability_id="socket", target="192.168.1.50", success=True)
    state.services = [Service(host="127.0.0.1", port=80, protocol="tcp", service="http", state="open")]

    app = ApplicationModel(base_url="http://192.168.1.50")
    app.endpoints = [SemanticEndpoint(path="/login", method="POST")]
    state.set_application_model(app)

    inv = Investigation(
        id="inv-ready-leftover",
        objective="Check login bypass",
        state=InvestigationState.READY,
    )
    state.set_investigations([inv])

    result = evaluate_live_acceptance(state)
    assert result.gate == "FAILED"
    assert any("loop_invariant_READY_zero" in c["name"] and not c["passed"] for c in result.checks)


def test_persistence_roundtrip_true_disk(tmp_path):
    """Section 3: True workspace disk roundtrip (save -> new Workspace -> load -> validate)."""
    import os
    os.environ["HORCRUX_WORKSPACES_ROOT"] = str(tmp_path)

    ws = Workspace("test-persistence-target", base=str(tmp_path))
    state = ws.load()
    state.target = "test-persistence-target"
    state.target_provenance = "REAL_LOCAL_TARGET"
    state.live_execution_observed = True
    state.assessment_run_id = "persist-test-run"
    state.record_live_execution(capability_id="socket", target="test-persistence-target", success=True)
    state.services = [Service(host="127.0.0.1", port=8080, protocol="tcp", service="http", state="open")]

    f = Finding(
        id="f-persist-1",
        title="IDOR vulnerability",
        category="authorization",
        severity=Severity.high,
        confidence=0.9,
        target="test-persistence-target",
        validation_state=ValidationState.confirmed,
        evidence=["Evidence string 1", "Evidence string 2"],
        cves=[],
        cwes=["CWE-639"],
        source_tools=["authz_compare"],
        reproduction=["curl -i http://test-persistence-target/rest/user/1"],
    )
    state.findings = [f]

    # Verify true disk persistence
    ok, errors = verify_workspace_persistence(state, workspace=ws)
    assert ok is True, f"Persistence verification failed: {errors}"
    assert len(errors) == 0


def test_vulnerability_adjudication_acceptance_suite():
    """Section 2: Vulnerability Adjudication Acceptance on synthetic fixtures requires confirmed findings."""
    state = WorkspaceState(target="fixture.local")
    state.target_provenance = "SYNTHETIC_TEST_TARGET"

    # With zero findings, vulnerability adjudication acceptance fails
    state.findings = []
    res_fail = evaluate_vulnerability_adjudication_acceptance(state)
    assert res_fail.gate == "FAILED"

    # With confirmed findings, vulnerability adjudication acceptance passes
    f = Finding(
        id="f-cve-1",
        title="Apache Log4j RCE",
        category="component-vulnerability",
        severity=Severity.critical,
        confidence=0.95,
        target="fixture.local",
        validation_state=ValidationState.confirmed,
        cves=["CVE-2021-44228"],
        evidence=["Vulnerable log4j banner detected"],
    )
    f2 = Finding(
        id="f-idor-1",
        title="IDOR on User",
        category="authorization",
        severity=Severity.high,
        confidence=0.9,
        target="fixture.local",
        validation_state=ValidationState.confirmed,
        cves=[],
        evidence=["Cross-identity access succeeded"],
    )
    state.findings = [f, f2]
    res_pass = evaluate_vulnerability_adjudication_acceptance(state)
    assert res_pass.gate == "PASSED"
    assert res_pass.findings_confirmed == 2
    assert res_pass.findings_confirmed_with_cve == 1
    assert res_pass.findings_confirmed_no_cve == 1
