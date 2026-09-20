"""Assessment lifecycle management."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from horcrux.intel.attack_paths import attack_paths_to_dict, build_attack_paths
from horcrux.intel.coverage import assessment_completeness, calculate_coverage
from horcrux.intel.hypotheses import update_hypotheses_from_state
from horcrux.intel.ingestion import ingest_workspace_state
from horcrux.intel.investigations import (
    choose_highest_value_task,
    generate_investigations,
    merge_investigations,
    rank_investigations,
)
from horcrux.intel.reasoning import ReasoningCheckpoint, run_reasoning_checkpoint
from horcrux.models import AssessmentPhase, ExploitHandoff, ValidationState

if TYPE_CHECKING:
    from horcrux.models import WorkspaceState


def reassess(state: WorkspaceState, ai_manager=None) -> WorkspaceState:
    """Full reassessment cycle: ingest → hypothesize → investigate queue → coverage."""
    state.assessment_phase = AssessmentPhase.APPLICATION_MODELING.value

    ingest_workspace_state(state)
    app = state.get_application_model()

    try:
        from horcrux.intel.cve import correlate_software_vulnerabilities
        correlate_software_vulnerabilities(state)
    except Exception:
        pass

    state.assessment_phase = AssessmentPhase.HYPOTHESIS_GENERATION.value
    hypotheses = update_hypotheses_from_state(state)
    state.set_hypotheses(hypotheses)

    coverage = state.get_security_coverage()
    coverage.ensure_domains()
    coverage_gaps = {d: coverage.get(d).value for d in coverage.domains}
    candidates = generate_investigations(app, hypotheses, coverage_gaps)
    existing = state.get_investigations()
    merged = merge_investigations(existing, candidates)
    # Continuous replenishment pruning: retire matrix work whose test no
    # longer derives from the current attack surface (explicit NOT_APPLICABLE,
    # never silent deletion).
    try:
        from horcrux.intel.investigations import prune_stale_matrix_investigations
        from horcrux.intel.test_matrix import derive_applicable_tests
        applicable_ids = {tc.ensure_id() for tc in derive_applicable_tests(app, state)}
        merged = prune_stale_matrix_investigations(merged, applicable_ids)
    except Exception:
        pass
    # Dependency graph: score prerequisites, park impossible work as BLOCKED.
    try:
        from horcrux.intel.dependencies import apply_dependencies
        merged = apply_dependencies(state, merged)
    except Exception:
        pass
    state.set_investigations(rank_investigations(merged))

    coverage = calculate_coverage(app, hypotheses, state.get_investigations(), coverage)
    state.set_security_coverage(coverage)

    state.attack_paths = attack_paths_to_dict(build_attack_paths(state))

    run_reasoning_checkpoint(state, ReasoningCheckpoint.AFTER_HYPOTHESIS_CREATION, ai_manager)
    # Reassessment history for state-delta analysis ("what changed").
    try:
        from horcrux.intel.events import snapshot_counts
        hist = (state.scheduler_state or {}).get("history", [])
        hist.append(snapshot_counts(state))
        state.scheduler_state = {**(state.scheduler_state or {}), "history": hist[-5:]}
    except Exception:
        pass
    return state


def recover_interrupted(state: WorkspaceState) -> dict[str, Any]:
    """Resume-safe recovery after interruption (Part 23).

    - RUNNING investigations (interrupted mid-execution) return to READY.
    - Verifies stored model/hypothesis/investigation consistency.
    - Never discards completed evidence; never blindly reruns expensive work
      (terminal states are preserved).
    """
    from typing import Any as _Any
    from horcrux.intel.investigations import InvestigationState
    report: dict[str, _Any] = {"recovered": [], "warnings": []}
    try:
        app = state.get_application_model()
    except Exception as exc:
        report["warnings"].append(f"application model unreadable: {exc}")
        return report
    invs = state.get_investigations()
    for inv in invs:
        if inv.state == InvestigationState.RUNNING:
            inv.state = InvestigationState.READY
            inv.result_summary = "recovered: interrupted mid-execution; rescheduled"
            report["recovered"].append(inv.id)
    # Consistency: hypothesis asset refs pointing at vanished endpoints.
    try:
        ep_ids = {e.id for e in app.endpoints}
        for h in state.get_hypotheses():
            stale = [r for r in h.asset_refs if r.startswith(("ep", "endpoint")) and r not in ep_ids]
            if stale:
                report["warnings"].append(f"hypothesis {h.id[:8]} refs {len(stale)} stale asset(s)")
    except Exception as exc:
        report["warnings"].append(f"consistency check skipped: {exc}")
    state.set_investigations(invs)
    return report


def assessment_has_actionable_work(state: WorkspaceState) -> bool:
    """Check if assessment should continue."""
    if state.operator_focus.stopped:
        return False
    if state.operator_focus.paused:
        return False

    # Bootstrap: recon data exists but application model not yet built
    app = state.get_application_model()
    if (state.services or state.discovered_paths) and not app.endpoints:
        return True

    completeness = assessment_completeness(state)
    verdict = completeness.get("verdict", "INCOMPLETE")
    # Only stop when verdict is COMPLETE (not just "sufficient")
    if (verdict == "COMPLETE" and completeness.get("sufficient", False)
            and not completeness["open_hypotheses"]
            and not completeness["pending_high_investigations"]):
        return False

    investigations = state.get_investigations()
    actionable = [
        i for i in investigations
        if i.state.value in {"READY", "PENDING"}
        and i.id not in state.operator_focus.skip_investigation_ids
    ]
    if actionable:
        return True

    # Continue if high-value surfaces exist but authorization never investigated
    if (
        completeness["high_value_surfaces"] >= 3
        and not completeness["authorization_investigated"]
    ):
        return True

    open_hyps = [
        h for h in state.get_hypotheses()
        if h.status.value in {"OPEN", "INVESTIGATING"} and h.confidence >= 0.6
    ]
    return len(open_hyps) > 0


def prepare_exploit_handoffs(state: WorkspaceState) -> list[ExploitHandoff]:
    """Create exploitation handoffs for validated findings — operator approval required."""
    handoffs: list[ExploitHandoff] = []
    for finding in state.findings:
        if finding.validation_state not in {ValidationState.confirmed, ValidationState.likely}:
            continue
        if finding.severity.value in {"info"}:
            continue
        handoff = ExploitHandoff(
            id=f"handoff-{finding.id}",
            finding_id=finding.id,
            target=finding.target or state.target,
            vulnerability=finding.title,
            affected_asset=finding.affected_asset or finding.target,
            affected_component=finding.category,
            evidence=finding.evidence,
            prerequisites=["Operator authorization", "Scoped target access",
                           *(finding.reproduction[:1] or [])],
            reproduction_plan=finding.reproduction,
            expected_result=finding.title,
            impact=finding.why_it_matters,
            confidence=finding.confidence,
            recommended_operator_action=finding.recommended_next_action or
            "Manually validate within authorized scope before any exploitation.",
            relevant_capabilities=["http_probe", "authz_compare", "endpoint_validate"],
            relevant_tools=["http_probe", "authz_compare", "endpoint_validate"],
            risks=["Service disruption", "Account lockout", "Legal/scope violation if mis-scoped"],
            operator_approval_required=True,
            # New Phase 9 fields
            identity_required=_infer_identity_required(finding, state),
            session_required=finding.severity.value in ("high", "critical"),
            attack_path_id=_find_attack_path_for_finding(finding, state),
            finding_validation_state=finding.validation_state.value if hasattr(finding.validation_state, 'value') else str(finding.validation_state),
            what_was_tested=list(finding.evidence[:3]),
            what_could_not_be_tested=_blocked_investigations_for_finding(finding, state),
            why_not_tested=["Operator approval required for active exploitation"],
        )
        handoffs.append(handoff)
    state.exploit_handoffs = handoffs
    return handoffs


def _infer_identity_required(finding: Any, state: Any) -> str:
    try:
        app = state.get_application_model()
        if finding.severity.value in ("high", "critical") and app.identities:
            auth_identities = [i for i in app.identities if i.role.value != "anonymous"]
            return auth_identities[0].label if auth_identities else ""
    except Exception:
        pass
    return ""


def _find_attack_path_for_finding(finding: Any, state: Any) -> str:
    try:
        for ap in (state.attack_paths or []):
            if isinstance(ap, dict):
                nodes = ap.get("nodes", [])
                if any(finding.id in str(n) or finding.title[:20].lower() in str(n).lower() for n in nodes):
                    return ap.get("id", "")
    except Exception:
        pass
    return ""


def _blocked_investigations_for_finding(finding: Any, state: Any) -> list[str]:
    try:
        blocked = []
        for inv in state.get_investigations():
            if inv.state.value in ("BLOCKED", "SCOPE_BLOCKED", "UNAVAILABLE") and \
                    any(r in inv.evidence_refs for r in finding.evidence[:3]):
                blocked.append(inv.objective[:80])
        return blocked[:3]
    except Exception:
        return []
