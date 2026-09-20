"""Root VAPT orchestrator — continuous coverage-driven assessment loop."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from horcrux.agents.lifecycle import (
    assessment_has_actionable_work,
    prepare_exploit_handoffs,
    reassess,
)
from horcrux.agents.specialists import SpecialistExecutor, update_agent_states
from horcrux.core.runner import CommandRunner
from horcrux.intel.investigations import rank_investigations
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
    - Coordinating tools (via central CapabilityRegistry -> CommandRunner)
    - Updating application model
    - Evaluating coverage
    - Deciding when to reassess
    - Producing final synthesis

    Loop (per iteration):
      1 load/initialize workspace
      2 ingest current evidence
      3 update ApplicationModel
      4 calculate coverage
      5 generate/update hypotheses
      6 deduplicate hypotheses
      7 generate/update investigations
      8 rank investigations
      9 apply OperatorFocus
      10 select highest-value executable investigation
      11 execute capability
      12 normalize evidence
      13 ingest evidence
      14 update model
      15 reassess hypotheses
      16 update findings
      17 update attack paths
      18 recalculate coverage
      19 reasoning checkpoint when appropriate
      20 repeat until completion criteria are met

    Completion depends on coverage + investigation exhaustion + unresolved
    high-value hypotheses + execution failures — NEVER on
    ``findings == 0`` or ``scanners exhausted``.
    """

    def __init__(
        self,
        workspace: Workspace,
        ai_manager=None,
        max_iterations: int = 250,
        mock_mode: bool = False,
        max_workers: int = 1,
        observer=None,
        time_limit: int | None = None,
        request_limit: int | None = None,
    ):
        self.workspace = workspace
        self.ai_manager = ai_manager
        self.max_iterations = max_iterations
        self.mock_mode = mock_mode
        self.max_workers = max(1, int(max_workers))
        self.observer = observer
        self.time_limit = time_limit
        self.request_limit = request_limit
        try:
            runner = CommandRunner(workspace)
        except Exception:
            runner = None
        self.executor = SpecialistExecutor(workspace=workspace, runner=runner,
                                           observer=observer)
        self.runner = runner
        self.last_batch_size = 0

    def _emit(self, event: str, payload: dict | None = None) -> None:
        if self.observer is None:
            return
        try:
            self.observer(event, payload or {})
        except Exception:
            pass

    def run_assessment_loop(self) -> WorkspaceState:
        """Execute the continuous investigation loop."""
        import secrets as _secrets
        from horcrux.intel.events import log_event
        # 1. load/initialize workspace
        state = self.workspace.load()
        # Resume-safe recovery: requeue interrupted RUNNING work (Part 23).
        try:
            from horcrux.agents.lifecycle import recover_interrupted
            recovery = recover_interrupted(state)
        except Exception:
            recovery = {"recovered": [], "warnings": []}
        if not state.assessment_run_id:
            state.assessment_run_id = _secrets.token_hex(6)
        state.assessment_phase = AssessmentPhase.RECONNAISSANCE.value
        state.scheduler_state = {"max_workers": self.max_workers,
                                 "mode": "parallel" if self.max_workers > 1 else "sequential",
                                 "recovered": recovery.get("recovered", [])}
        self.workspace.save(state)
        log_event(self.workspace, state, "ASSESSMENT_STARTED",
                  {"run_id": state.assessment_run_id, "recovered": recovery.get("recovered", []),
                   "max_workers": self.max_workers})
        self.executor.bind_context(workspace=self.workspace, runner=self.runner,
                                   state=state, observer=self.observer)
        self._emit("phase", {"name": "RECON"})

        import time
        loop_start = time.monotonic()
        requests_executed = 0
        iteration = 0
        while iteration < self.max_iterations:
            # 1. load
            state = self.workspace.load()
            # Operator stop/pause gates.
            if state.operator_focus.stopped or state.operator_focus.paused:
                break
            # Operator limits (Phase A / Part 2)
            if self.time_limit is not None and (time.monotonic() - loop_start) >= self.time_limit:
                self._record_stop_reason(state, f"Operator time limit reached ({self.time_limit}s)")
                state.assessment_phase = "LIMITED"
                self.workspace.save(state)
                break
            if self.request_limit is not None and requests_executed >= self.request_limit:
                self._record_stop_reason(state, f"Operator request limit reached ({self.request_limit})")
                state.assessment_phase = "LIMITED"
                self.workspace.save(state)
                break
            # Completion gate: coverage + exhaustion + hypotheses + failures.
            if not assessment_has_actionable_work(state):
                break

            # 2-8. ingest -> model -> hypotheses -> investigations -> rank
            # (reassess performs 2-7 + coverage + attack paths internally)
            self._emit("phase", {"name": "MODEL"})
            state = reassess(state, self.ai_manager)
            self._emit("phase", {"name": "HYPOTHESIZE"})
            self.executor.bind_context(workspace=self.workspace,
                                       runner=self.runner, state=state,
                                       observer=self.observer)
            # Contradiction detection -> resolution investigations (Part 21).
            try:
                from horcrux.intel.contradictions import (detect_contradictions,
                                                          propose_resolutions)
                contras = detect_contradictions(state)
                if contras:
                    propose_resolutions(state, contras)
            except Exception:
                pass
            self.workspace.save(state)

            # 9. apply OperatorFocus (skip + prioritize + area boost)
            investigations = rank_investigations(state.get_investigations())
            batch = self._choose_batch(state, investigations)
            # 10. select highest-value executable investigation(s)
            if not batch:
                # No executable work remains — record why and stop.
                self._record_stop_reason(state, "no high-value executable investigation remains")
                self.workspace.save(state)
                break
            self.last_batch_size = len(batch)
            state.scheduler_state = {"max_workers": self.max_workers,
                                     "mode": "parallel" if self.max_workers > 1 else "sequential",
                                     "last_batch": len(batch)}
            next_task = batch[0]

            # 11-16. execute capability -> evidence -> model -> hypotheses -> findings
            state.assessment_phase = AssessmentPhase.INVESTIGATION.value
            update_agent_states(state, next_task.specialist)
            self._emit("agents", {"agents": [(a.agent_id, a.status)
                                             for a in state.agent_states]})
            self.workspace.save(state)

            self._execute_batch(state, batch)
            requests_executed += len(batch)
            self.workspace.save(state)
            self._emit("phase", {"name": "REASSESS"})

            # 17-18. attack paths + coverage recalculated inside reassess
            # 19. reasoning checkpoint when appropriate (every 2nd iteration
            # or when a hypothesis was supported/refuted)
            states_done = {i.state.value for i in batch}
            if iteration % 2 == 1 or states_done & {"SUPPORTED", "REFUTED"}:
                run_reasoning_checkpoint(
                    state,
                    ReasoningCheckpoint.AFTER_INVESTIGATION,
                    self.ai_manager,
                )
                try:
                    log_event(self.workspace, state, "AI_REASONING_COMPLETED",
                              {"checkpoint": "after_investigation"})
                except Exception:
                    pass
                self.workspace.save(state)

            # 15/18. reassess hypotheses + coverage after new evidence
            reassess(state, self.ai_manager)
            self.workspace.save(self.workspace.load())

            iteration += 1

        final = self.finalize()
        try:
            log_event(self.workspace, final, "ASSESSMENT_COMPLETED",
                      {"phase": final.assessment_phase})
        except Exception:
            pass
        return final

    def _record_stop_reason(self, state: WorkspaceState, reason: str) -> None:
        try:
            self.workspace.write("raw/assessment-stop-reason.txt", reason + "\n")
        except Exception:
            pass

    def ingest_and_reassess(self) -> WorkspaceState:
        """Single reassessment pass after reconnaissance (no investigation execution)."""
        state = self.workspace.load()
        state = reassess(state, self.ai_manager)
        update_agent_states(state)
        self.workspace.save(state)
        return state

    def _choose_batch(self, state: WorkspaceState, investigations: list) -> list:
        """Dependency-aware batch: focus-ranked, prerequisite-gated (P16/P34)."""
        try:
            from horcrux.intel.dependencies import select_parallel_batch
            from horcrux.agents.focus import scheduler_rank
            ranked = scheduler_rank(state, investigations)
            if not ranked:
                single = self._choose_task(state, investigations)
                return [single] if single else []
            return select_parallel_batch(ranked, max_workers=self.max_workers)
        except Exception:
            single = self._choose_task(state, investigations)
            return [single] if single else []

    def _execute_batch(self, state: WorkspaceState, batch: list) -> None:
        """Execute a batch: capabilities concurrently, ingestion serially."""
        from horcrux.intel.events import log_event
        if len(batch) <= 1:
            inv = batch[0]
            try:
                log_event(self.workspace, state, "INVESTIGATION_STARTED",
                          {"investigation": inv.id, "objective": inv.objective[:80]})
            except Exception:
                pass
            self.executor.execute_investigation(state, inv)
            self._persist_investigation(state, inv)
            try:
                log_event(self.workspace, state, "INVESTIGATION_COMPLETED",
                          {"investigation": inv.id, "state": inv.state.value})
            except Exception:
                pass
            return
        # Parallel capability phase (threads), serial apply phase (rank order).
        from concurrent.futures import ThreadPoolExecutor
        from horcrux.agents.executor import (apply_capability_result,
                                             run_capability_for_investigation)
        self.executor.tools.bind_context(workspace=self.workspace,
                                         runner=self.runner, state=state)
        registry = self.executor.tools.capabilities
        runs: dict[str, Any] = {}

        def _run(inv) -> tuple:
            try:
                self._emit("investigation_start",
                           {"id": inv.id, "objective": inv.objective})
                return (inv.id, run_capability_for_investigation(
                    state, inv, registry, observer=self.observer))
            except Exception as exc:
                return (inv.id, {"ok": False, "outcome": "tool_failed",
                                 "capability": None, "request_id": "",
                                 "summary": f"batch execution crashed: {exc}"})

        with ThreadPoolExecutor(max_workers=len(batch)) as pool:
            for inv_id, run in pool.map(_run, batch):
                runs[inv_id] = run
        for inv in batch:
            try:
                apply_capability_result(state, inv, runs.get(inv.id, {"ok": False}),
                                        workspace=self.workspace,
                                        observer=self.observer)
            except Exception as exc:
                from horcrux.intel.investigations import InvestigationState
                inv.state = InvestigationState.FAILED
                inv.result_summary = f"apply crashed: {exc}"[:200]
            self._persist_investigation(state, inv)

    def _persist_investigation(self, state: WorkspaceState, inv) -> None:
        invs = state.get_investigations()
        for idx, existing in enumerate(invs):
            if existing.id == inv.id:
                invs[idx] = inv
                break
        state.set_investigations(invs)

    def _choose_task(self, state: WorkspaceState, investigations: list):
        """Scheduler: skip-list, explicit prioritize, then focus-weighted rank."""
        try:
            from horcrux.agents.focus import scheduler_rank
            ranked = scheduler_rank(state, investigations)
            if ranked:
                return ranked[0]
        except Exception:
            pass
        focus_id = state.operator_focus.prioritize_investigation_id
        if focus_id:
            for inv in investigations:
                if inv.id == focus_id and inv.state.value in {"READY", "PENDING"}:
                    return inv
        ranked = [i for i in investigations if i.id not in state.operator_focus.skip_investigation_ids]
        from horcrux.intel.investigations import choose_highest_value_task
        return choose_highest_value_task(ranked)

    def completion_report(self, state: WorkspaceState) -> dict:
        """Structured completion accounting (coverage, hypotheses, failures)."""
        from horcrux.intel.coverage import assessment_completeness
        completeness = assessment_completeness(state)
        invs = state.get_investigations()
        blocked = [i for i in invs if i.state.value in
                   {"BLOCKED", "SCOPE_BLOCKED", "UNAVAILABLE", "FAILED"}]
        return {
            "sufficient": completeness["sufficient"],
            "verdict": completeness.get("verdict", "INCOMPLETE"),
            "blocking_reasons": completeness.get("blocking_reasons", []),
            "coverage": completeness["coverage_percentages"],
            "property_summary": completeness.get("property_summary", {}),
            "open_hypotheses": completeness["open_hypotheses"],
            "pending_high": completeness["pending_high_investigations"],
            "blocked_investigations": [(i.id, i.state.value) for i in blocked],
            "operator_paused": state.operator_focus.paused,
            "operator_stopped": state.operator_focus.stopped,
        }

    def finalize(self) -> WorkspaceState:
        """Final synthesis with exploit handoffs."""
        state = self.workspace.load()
        state.assessment_phase = AssessmentPhase.SYNTHESIS.value
        self._emit("phase", {"name": "SYNTHESIZE"})

        run_reasoning_checkpoint(
            state,
            ReasoningCheckpoint.BEFORE_FINAL_SYNTHESIS,
            self.ai_manager,
        )

        prepare_exploit_handoffs(state)
        self._emit("phase", {"name": "HANDOFF"})
        state.attack_paths = state.attack_paths or []
        from horcrux.intel.attack_paths import attack_paths_to_dict, build_attack_paths
        state.attack_paths = attack_paths_to_dict(build_attack_paths(state))

        from horcrux.intel.coverage import assessment_completeness
        completeness = assessment_completeness(state)
        verdict = completeness.get("verdict", "INCOMPLETE")
        if verdict == "COMPLETE" and completeness.get("sufficient", False):
            state.assessment_phase = AssessmentPhase.COMPLETE.value
        elif verdict in ("LIMITED", "BLOCKED"):
            state.assessment_phase = "LIMITED"
        else:
            state.assessment_phase = AssessmentPhase.INVESTIGATION.value

        # Deduplicate and canonicalize findings across tools (Phase H/I)
        try:
            from horcrux.intel.vulnerability_adjudicator import canonicalize_state_findings
            canonicalize_state_findings(state)
        except Exception:
            pass

        # Clean up any remaining READY / PENDING / RUNNING work at completion with explicit requirement states
        from horcrux.intel.investigations import InvestigationState
        from horcrux.intel.dependencies import evaluate_prerequisites
        invs = state.get_investigations()
        for inv in invs:
            if inv.state in (InvestigationState.READY, InvestigationState.PENDING, InvestigationState.RUNNING):
                schedulable, blocked = evaluate_prerequisites(state, inv)
                blocked_str = "; ".join(blocked[:3]) if blocked else "prerequisite unsatisfied or execution budget reached"
                b_lower = blocked_str.lower()
                inv.result_summary = f"Blocked: {blocked_str}"
                if any(k in b_lower for k in ("two", "second", "cross-context", "identity context")):
                    inv.state = InvestigationState.REQUIRES_SECOND_IDENTITY
                elif any(k in b_lower for k in ("auth", "session", "user access context", "admin access context", "authenticated")):
                    inv.state = InvestigationState.REQUIRES_AUTH
                elif any(k in b_lower for k in ("tool", "binary", "missing tool")):
                    inv.state = InvestigationState.REQUIRES_TOOL
                elif any(k in b_lower for k in ("operator", "approval")):
                    inv.state = InvestigationState.REQUIRES_OPERATOR
                else:
                    inv.state = InvestigationState.BLOCKED
        state.set_investigations(invs)

        update_agent_states(state)
        self.workspace.save(state)
        return state
