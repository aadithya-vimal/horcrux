"""Tests that tool failures do NOT result in a false "clean" or "no vulnerability" verdict."""
from __future__ import annotations

import pytest
from horcrux.models import WorkspaceState
from horcrux.intel.coverage import PropertyStatus, CoverageStatus
from horcrux.intel.investigations import Investigation, InvestigationState
from horcrux.core.acceptance import evaluate_live_acceptance


def test_capability_failure_does_not_claim_clean_verdict():
    """When capabilities fail or are unavailable, assessment does NOT claim clean/no vulnerability."""
    state = WorkspaceState(target="192.168.1.100")
    state.target_provenance = "REAL_REMOTE_TARGET"
    state.assessment_run_id = "run-fail-test"
    
    # Tool failure marks investigation as UNAVAILABLE or BLOCKED with explicit reason
    inv = Investigation(
        id="inv-tool-fail",
        objective="Validate web findings with targeted Nuclei templates",
        state=InvestigationState.UNAVAILABLE,
        block_reason="nuclei binary not installed on operator machine",
    )
    state.set_investigations([inv])
    
    # State has NO findings, but an unavailable tool means coverage is LIMITED / INCOMPLETE
    assert len(state.findings) == 0
    
    # The coverage model must not claim clean/no issue evidence
    assert PropertyStatus.UNKNOWN != PropertyStatus.NO_ISSUE_EVIDENCE
    assert CoverageStatus.BLOCKED != CoverageStatus.REVIEWED
    
    # evaluate_live_acceptance must NOT pass if zero findings and tool failure blocked verification
    result = evaluate_live_acceptance(state)
    assert any("investigations_executed" in c["name"] and not c["passed"] for c in result.checks)
    assert "CLEAN" not in result.security_verdict
    assert "SECURE" not in result.security_verdict
