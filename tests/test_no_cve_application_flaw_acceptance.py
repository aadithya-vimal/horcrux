"""No-CVE Application Vulnerability Acceptance Test (Section 8)."""

from __future__ import annotations

from horcrux.agents.executor import _assess_hypothesis_outcome
from horcrux.intel.hypotheses import Hypothesis, HypothesisClass, HypothesisStatus
from horcrux.intel.investigations import Investigation, InvestigationState
from horcrux.models import ValidationState, WorkspaceState


class MockCapabilityResult:
    def __init__(self, capability_id: str, data: dict):
        self.capability_id = capability_id
        self.data = data
        self.structured_data = data
        self.evidence = []
        self.ingested_count = 1


def test_section_8_no_cve_application_flaw_acceptance():
    """Section 8: Proves an application vulnerability produces a canonical Finding with cves = []."""
    state = WorkspaceState(target="127.0.0.1")
    inv = Investigation(
        id="inv-idor-test",
        objective="Determine whether user profiles are authorization-bound",
        candidate_tools=["authz_compare"],
    )
    hyp = Hypothesis(
        id="hyp-idor-test",
        hypothesis_class=HypothesisClass.IDOR_BOLA,
        title="Potential IDOR on user resource",
    )
    state.set_hypotheses([hyp])

    # Simulated differential access result (user A accesses user B's object)
    result = MockCapabilityResult(
        capability_id="authz_compare",
        data={
            "potential_gap": True,
            "affected_asset": "/rest/user/1",
            "identity_a": "user-a",
            "identity_b": "user-b",
            "status_code": 200,
            "object_accessed": True,
            "cross_identity": True,
        },
    )

    outcome = _assess_hypothesis_outcome(state, inv, result, 1)
    assert outcome["state"] == InvestigationState.SUPPORTED

    # Verify canonical Finding
    assert len(state.findings) == 1
    f = state.findings[0]
    assert f.cves == [], "Application flaws MUST have cves = [] (Invariant Section 8)"
    assert f.category == "authorization"
    assert f.severity.value in ("high", "medium")
    assert f.confidence >= 0.8
    assert f.validation_state == ValidationState.confirmed
    assert len(f.evidence) >= 1
    assert len(f.reproduction) >= 1
    assert f.why_it_matters != ""
    assert f.recommended_next_action != ""
    assert f.affected_asset == "/rest/user/1"
