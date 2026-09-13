"""Root VAPT orchestrator — coordinates assessment intelligence loop."""

from __future__ import annotations

from typing import TYPE_CHECKING

from horcrux.agents.lifecycle import (
    assessment_has_actionable_work,
    prepare_exploit_handoffs,
    reassess,
)
from horcrux.agents.specialists import SpecialistExecutor, update_agent_states
from horcrux.intel.investigations import choose_highest_value_task, rank_investigations
from horcrux.intel.reasoning import ReasoningCheckpoint, run_reasoning_checkpoint
from horcrux.models import AssessmentPhase

if TYPE_CHECKING:
    from horcrux.core.storage import Workspace
    from horcrux.models import WorkspaceState


class RootVAPTOrchestrator:
    """
    Root agent responsible for:
    - Understanding state
    - Selecting specialists
    - Selecting investigations
    - Coordinating tools
    - Updating application model
    - Evaluating coverage
    - Deciding when to reassess
    - Producing final synthesis
    """

    def __init__(
        self,
        workspace: Workspace,
        ai_manager=None,
        max_iterations: int = 20,
        mock_mode: bool = False,
    ):
        self.workspace = workspace
        self.ai_manager = ai_manager
        self.max_iterations = max_iterations
        self.mock_mode = mock_mode
        self.executor = SpecialistExecutor()

    def run_assessment_loop(self) -> WorkspaceState:
        """Execute the investigation loop until completeness or limits."""
        state = self.workspace.load()
        state.assessment_phase = AssessmentPhase.RECONNAISSANCE.value
        self.workspace.save(state)

        iteration = 0
        while iteration < self.max_iterations:
            state = self.workspace.load()
            if not assessment_has_actionable_work(state):
                break

            state = reassess(state, self.ai_manager)
            self.workspace.save(state)

            investigations = rank_investigations(state.get_investigations())

            # Operator steering: prioritize focused investigation
            next_task = self._choose_task(state, investigations)
            if not next_task:
                break

            state.assessment_phase = AssessmentPhase.INVESTIGATION.value
            update_agent_states(state, next_task.specialist)
            self.workspace.save(state)

            self.executor.execute_investigation(state, next_task)
            invs = state.get_investigations()
            for idx, inv in enumerate(invs):
                if inv.id == next_task.id:
                    invs[idx] = next_task
                    break
            state.set_investigations(invs)
            self.workspace.save(state)

            run_reasoning_checkpoint(
                state,
                ReasoningCheckpoint.AFTER_INVESTIGATION,
                self.ai_manager,
            )
            self.workspace.save(state)

            reassess(state, self.ai_manager)
            self.workspace.save(self.workspace.load())

            iteration += 1

        return self.finalize()

    def ingest_and_reassess(self) -> WorkspaceState:
        """Single reassessment pass after reconnaissance (no investigation execution)."""
        state = self.workspace.load()
        state = reassess(state, self.ai_manager)
        update_agent_states(state)
        self.workspace.save(state)
        return state

    def _choose_task(self, state: WorkspaceState, investigations: list):
        focus_id = state.operator_focus.prioritize_investigation_id
        if focus_id:
            for inv in investigations:
                if inv.id == focus_id and inv.state.value in {"READY", "PENDING"}:
                    return inv
        ranked = [i for i in investigations if i.id not in state.operator_focus.skip_investigation_ids]
        return choose_highest_value_task(ranked)

    def finalize(self) -> WorkspaceState:
        """Final synthesis with exploit handoffs."""
        state = self.workspace.load()
        state.assessment_phase = AssessmentPhase.SYNTHESIS.value

        run_reasoning_checkpoint(
            state,
            ReasoningCheckpoint.BEFORE_FINAL_SYNTHESIS,
            self.ai_manager,
        )

        prepare_exploit_handoffs(state)
        state.attack_paths = state.attack_paths or []
        from horcrux.intel.attack_paths import attack_paths_to_dict, build_attack_paths
        state.attack_paths = attack_paths_to_dict(build_attack_paths(state))

        from horcrux.intel.coverage import assessment_completeness
        completeness = assessment_completeness(state)
        if completeness["sufficient"]:
            state.assessment_phase = AssessmentPhase.COMPLETE.value
        else:
            state.assessment_phase = AssessmentPhase.INVESTIGATION.value

        update_agent_states(state)
        self.workspace.save(state)
        return state
