"""Assessment coordinator — bridges scan pipeline and agent loop."""

from __future__ import annotations

from horcrux.agents.root import RootVAPTOrchestrator
from horcrux.core.actions import compute_investigation_actions
from horcrux.core.storage import Workspace
from horcrux.intel.reasoning import ReasoningCheckpoint, run_reasoning_checkpoint
from horcrux.models import AssessmentPhase


def on_recon_complete(workspace: Workspace, ai_manager=None) -> None:
    """Called after initial reconnaissance to bootstrap application model."""
    root = RootVAPTOrchestrator(workspace, ai_manager=ai_manager)
    state = root.ingest_and_reassess()

    run_reasoning_checkpoint(state, ReasoningCheckpoint.AFTER_NETWORK_DISCOVERY, ai_manager)
    run_reasoning_checkpoint(state, ReasoningCheckpoint.AFTER_APP_STRUCTURE, ai_manager)

    if state.get_application_model().authentication:
        run_reasoning_checkpoint(state, ReasoningCheckpoint.AFTER_AUTH_DISCOVERY, ai_manager)
    if state.get_application_model().endpoints:
        run_reasoning_checkpoint(state, ReasoningCheckpoint.AFTER_API_DISCOVERY, ai_manager)

    workspace.save(state)
    _sync_actions(workspace)


def run_full_assessment(
    workspace: Workspace,
    ai_manager=None,
    max_iterations: int = 250,
    max_workers: int = 1,
    observer=None,
    time_limit: int | None = None,
    request_limit: int | None = None,
) -> None:
    """Run complete agentic assessment loop."""
    state = workspace.load()
    state.assessment_phase = AssessmentPhase.RECONNAISSANCE.value
    workspace.save(state)

    root = RootVAPTOrchestrator(workspace, ai_manager=ai_manager,
                               max_iterations=max_iterations,
                               max_workers=max_workers,
                               observer=observer,
                               time_limit=time_limit,
                               request_limit=request_limit)
    root.run_assessment_loop()
    _sync_actions(workspace)



def _sync_actions(workspace: Workspace) -> None:
    state = workspace.load()
    actions = compute_investigation_actions(state)
    workspace.set_actions(actions)
