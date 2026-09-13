"""Assessment lifecycle management."""

from __future__ import annotations

from typing import TYPE_CHECKING

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

    state.assessment_phase = AssessmentPhase.HYPOTHESIS_GENERATION.value
    hypotheses = update_hypotheses_from_state(state)
    state.set_hypotheses(hypotheses)

    coverage = state.get_security_coverage()
    coverage.ensure_domains()
    coverage_gaps = {d: coverage.get(d).value for d in coverage.domains}
    candidates = generate_investigations(app, hypotheses, coverage_gaps)
    existing = state.get_investigations()
    merged = merge_investigations(existing, candidates)
    state.set_investigations(rank_investigations(merged))

    coverage = calculate_coverage(app, hypotheses, state.get_investigations(), coverage)
    state.set_security_coverage(coverage)

    state.attack_paths = attack_paths_to_dict(build_attack_paths(state))

    run_reasoning_checkpoint(state, ReasoningCheckpoint.AFTER_HYPOTHESIS_CREATION, ai_manager)
    return state


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
    if completeness["sufficient"]:
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
            affected_asset=finding.affected_asset or finding.target,
            evidence=finding.evidence,
            prerequisites=["Operator authorization", "Scoped target access"],
            reproduction_plan=finding.reproduction,
            expected_result=finding.title,
            impact=finding.why_it_matters,
            confidence=finding.confidence,
            operator_approval_required=True,
        )
        handoffs.append(handoff)
    state.exploit_handoffs = handoffs
    return handoffs
