from __future__ import annotations

from horcrux.core.actions import compute_next_actions
from horcrux.models import (
    Credential,
    ExploitCandidate,
    Finding,
    FindingStatus,
    Service,
    Severity,
    Software,
    SubsystemState,
    ValidationState,
    WorkspaceState,
)


def test_next_action_unrun_web_enumeration():
    state = WorkspaceState(
        target="10.0.0.5",
        services=[Service(host="10.0.0.5", port=80, protocol="tcp", service="http")],
    )
    actions = compute_next_actions(state)
    action_ids = [a.id for a in actions]

    assert "web_discovery" in action_ids
    web_act = next(a for a in actions if a.id == "web_discovery")
    assert web_act.score >= 90


def test_next_action_unrun_smb_enumeration():
    state = WorkspaceState(
        target="10.0.0.5",
        services=[Service(host="10.0.0.5", port=445, protocol="tcp", service="microsoft-ds")],
    )
    actions = compute_next_actions(state)
    action_ids = [a.id for a in actions]

    assert "smb_enum" in action_ids


def test_next_action_versionless_software_does_not_trigger_cve_correlation():
    # BUG 4 FIX VERIFICATION: Versionless software must not trigger CVE correlation
    state = WorkspaceState(
        target="10.0.0.5",
        services=[Service(host="10.0.0.5", port=80, protocol="tcp", service="http")],
        software=[Software(product="Apache", version="", service="80/tcp", source="nmap", confidence=0.70)],
    )
    actions = compute_next_actions(state)
    action_ids = [a.id for a in actions]

    assert "cve_intel" not in action_ids


def test_next_action_no_repeat_on_zero_cve_candidates():
    # BUG 5 FIX VERIFICATION: When CVE intelligence completed with 0 candidates, do NOT repeat recommendation
    state = WorkspaceState(
        target="10.0.0.5",
        services=[Service(host="10.0.0.5", port=80, protocol="tcp", service="http")],
        software=[Software(product="Apache", version="2.4.41", service="80/tcp", source="nmap", confidence=0.95)],
    )
    state.set_subsystem_state("cve_intelligence", SubsystemState.COMPLETE_NO_CANDIDATES)

    actions = compute_next_actions(state)
    action_ids = [a.id for a in actions]

    assert "cve_intel" not in action_ids
    assert "review_config" in action_ids


def test_next_action_with_candidates_recommends_review():
    state = WorkspaceState(
        target="10.0.0.5",
        services=[Service(host="10.0.0.5", port=80, protocol="tcp", service="http")],
        software=[Software(product="Apache", version="2.4.49", service="80/tcp", source="nmap", confidence=0.95)],
        exploits=[
            ExploitCandidate(
                title="Apache 2.4.49 - Path Traversal & Remote Code Execution",
                product="Apache",
                version="2.4.49",
                cve="CVE-2021-41773",
                source="exploits/multiple/webapps/50383.sh",
                relevance="CONFIRMED VERSION MATCH",
                exploitability="HIGH (REMOTE)",
                confidence=0.95,
            )
        ],
    )
    state.set_subsystem_state("cve_intelligence", SubsystemState.COMPLETE_WITH_CANDIDATES)

    actions = compute_next_actions(state)
    action_ids = [a.id for a in actions]

    assert "review_exploit" in action_ids
    top_act = actions[0]
    assert top_act.id == "review_exploit"
    assert "CVE-2021-41773" in top_act.title


def test_next_action_confirmed_finding_prioritization():
    state = WorkspaceState(
        target="10.0.0.5",
        services=[
            Service(host="10.0.0.5", port=445, protocol="tcp", service="microsoft-ds"),
            Service(host="10.0.0.5", port=80, protocol="tcp", service="http"),
        ],
        findings=[
            Finding(
                id="smb-anon-access-445",
                title="Anonymous SMB Share Access Allowed",
                category="smb",
                severity=Severity.high,
                confidence=0.98,
                status=FindingStatus.verified,
                validation_state=ValidationState.confirmed,
                target="10.0.0.5",
                evidence=["Null session enumerated shares."],
            )
        ],
    )
    actions = compute_next_actions(state)
    top_action = actions[0]

    assert top_action.id == "smb_inspect_shares"
    assert top_action.score >= 95
