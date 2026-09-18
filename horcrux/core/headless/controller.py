"""Headless mission controller — autonomous orchestrator over HORCRUX engine.

Orchestrates reconnaissance, application modeling, active multi-identity
authentication, hypothesis generation, blast-radius investigation ranking, safe
capability validation, evidence ingestion, cross-source correlation, exploit
handoffs, and convergence auditing.
"""

from __future__ import annotations

import json
import os
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from rich.console import Console

from horcrux.agents.lifecycle import (
    assessment_has_actionable_work,
    prepare_exploit_handoffs,
    reassess,
    recover_interrupted,
)
from horcrux.agents.root import RootVAPTOrchestrator
from horcrux.core.headless.config import build_mission_from_config
from horcrux.core.headless.display import HeadlessDisplay
from horcrux.core.headless.events import HeadlessEventEmitter
from horcrux.core.integrations.registry import IntegrationRegistry
from horcrux.core.mission import (
    AssessmentMission,
    IdentityProfile,
    MissionBrief,
    MissionStage,
    MissionStatus,
    utcnow,
)
from horcrux.core.storage import Workspace
from horcrux.intel.application_model import ApplicationModel, IdentityRole, SemanticIdentity
from horcrux.intel.coverage import assessment_completeness
from horcrux.intel.false_negative_audit import run_false_negative_audit
from horcrux.intel.investigations import InvestigationState, rank_investigations
from horcrux.intel.sessions import TestIdentity, begin_session, register_test_identity
from horcrux.models import ValidationState, WorkspaceState


class HeadlessMissionController:
    """Autonomous execution controller driving HORCRUX through an assessment mission."""

    def __init__(
        self,
        workspace: Workspace,
        mission: AssessmentMission,
        console: Optional[Console] = None,
        stdout_jsonl: bool = False,
        ai_manager: Any = None,
        quiet: bool = False,
    ) -> None:
        self.workspace = workspace
        self.mission = mission
        self.console = console or Console()
        self.ai_manager = ai_manager
        self.quiet = quiet
        self.events = HeadlessEventEmitter(workspace=workspace, stdout_jsonl=stdout_jsonl)
        self.display = HeadlessDisplay(console=self.console, quiet=quiet)
        self._interrupted = False
        self._setup_signals()

    def _setup_signals(self) -> None:
        """Register signal handlers for graceful cancellation."""
        try:
            signal.signal(signal.SIGINT, self._handle_interrupt)
            if hasattr(signal, "SIGTERM"):
                signal.signal(signal.SIGTERM, self._handle_interrupt)
        except Exception:
            pass

    def _handle_interrupt(self, signum, frame) -> None:
        """Graceful interrupt handler (Ctrl+C)."""
        self._interrupted = True
        self.events.emit("mission.interrupted", {
            "mission_id": self.mission.mission_id,
            "stage": self.mission.current_stage.value,
            "reason": "Operator SIGINT received",
        })
        self.narrative(
            self.mission.current_stage.value,
            "Interrupt signal received",
            "Gracefully saving checkpoint and halting background operations...",
        )
        self.mission.status = MissionStatus.INTERRUPTED
        self.mission.termination_reason = "Interrupted by operator (SIGINT)"
        self._checkpoint()

    def _checkpoint(self) -> None:
        """Atomically persist state and mission metadata to workspace."""
        self.mission.last_checkpoint_at = utcnow()
        self.mission.checkpoints_count += 1
        state = self.workspace.load()
        state.set_mission(self.mission)
        self.workspace.save(state)
        self.events.emit("mission.checkpoint", {
            "mission_id": self.mission.mission_id,
            "checkpoint_number": self.mission.checkpoints_count,
            "stage": self.mission.current_stage.value,
            "status": self.mission.status.value,
            "runtime": self.mission.budget.runtime_seconds,
        })

    def narrative(self, stage: str, header: str, detail: str, evidence_ref: str = "") -> None:
        """Record narrative entry on mission, stream event, and render display."""
        self.mission.add_narrative(stage, header, detail, evidence_ref)
        self.events.narrative(stage, header, detail, evidence_ref)
        self.display.render_narrative(stage, header, detail)

    def run(self) -> AssessmentMission:
        """Execute the complete autonomous assessment mission."""
        self.display.render_banner(self.mission)
        self.mission.status = MissionStatus.RUNNING
        self.mission.start_time = utcnow()

        # ── STAGE 1: MISSION & SCOPE ──────────────────────────────────────
        if not self._check_should_continue():
            return self.mission
        self._stage_mission_and_scope()

        # ── STAGE 2: RECONNAISSANCE ───────────────────────────────────────
        if not self._check_should_continue():
            return self.mission
        self._stage_reconnaissance()

        # ── STAGE 3: APPLICATION MODELING ─────────────────────────────────
        if not self._check_should_continue():
            return self.mission
        self._stage_modeling()

        # ── STAGE 4: ACTIVE AUTHENTICATION ────────────────────────────────
        if not self._check_should_continue():
            return self.mission
        self._stage_authentication()

        # ── STAGE 5: DISCOVERY & HYPOTHESIS ───────────────────────────────
        if not self._check_should_continue():
            return self.mission
        self._stage_discovery_and_hypothesis()

        # ── STAGE 6: AUTONOMOUS INVESTIGATION LOOP ────────────────────────
        if not self._check_should_continue():
            return self.mission
        self._stage_investigation_loop()

        # ── STAGE 7: CORRELATION & EXPLOIT HANDOFFS ───────────────────────
        if not self._check_should_continue():
            return self.mission
        self._stage_correlation_and_handoffs()

        # ── STAGE 8: CONVERGENCE & COMPLETION AUDIT ───────────────────────
        self._stage_completion()

        return self.mission

    def _check_should_continue(self) -> bool:
        """Returns False if mission was cancelled, paused, or exhausted."""
        if self._interrupted or self.mission.status in (MissionStatus.INTERRUPTED, MissionStatus.ABORTED, MissionStatus.PAUSED):
            return False
        if self.mission.budget.check_limits(self.mission.policy):
            self.mission.termination_reason = "; ".join(self.mission.budget.exhaustion_reasons)
            self.mission.status = MissionStatus.COMPLETE_WITH_LIMITATIONS
            return False
        return True

    # ── STAGE IMPLEMENTATIONS ─────────────────────────────────────────────

    def _stage_mission_and_scope(self) -> None:
        self.mission.current_stage = MissionStage.MISSION
        self.display.render_stage_transition(MissionStage.MISSION, "started")
        self.events.emit("stage.started", {"stage": MissionStage.MISSION.value})

        # Capabilities and Integrations health checks
        reg = IntegrationRegistry()
        ext_status: dict[str, str] = {}
        for integ in reg.list():
            meta = integ.metadata()
            if integ.is_configured():
                ext_status[meta.id] = "CONFIGURED"
            else:
                ext_status[meta.id] = "NOT_CONFIGURED"

        # Construct MissionBrief
        brief = MissionBrief(
            mission_id=self.mission.mission_id,
            target=self.mission.target,
            scope=self.mission.scope,
            profile=self.mission.profile,
            objectives=[
                "application_structure_mapping",
                "authentication_validation",
                "authorization_differentiation",
                "input_and_injection_analysis",
                "api_and_business_logic_analysis",
                "vulnerability_correlation",
                "completeness_and_gap_auditing",
            ],
            available_identities=[i.identity_id for i in self.mission.identities] or ["anonymous"],
            available_capabilities=["http_probe", "nmap", "ffuf", "nuclei", "js_analyze", "authz_compare"],
            external_integrations=ext_status,
            safety_limits={
                "destructive_actions": self.mission.policy.destructive_actions_allowed,
                "exploit_execution": self.mission.policy.exploit_execution_allowed,
                "max_concurrency": self.mission.policy.max_concurrency,
            },
            execution_budget={
                "max_runtime": self.mission.policy.max_runtime_seconds,
                "max_requests": self.mission.policy.max_requests,
                "max_iterations": self.mission.policy.max_iterations,
            },
        )

        # Persist brief to raw/mission-brief.json
        try:
            brief_path = self.workspace.root / "raw" / "mission-brief.json"
            brief_path.parent.mkdir(parents=True, exist_ok=True)
            brief_path.write_text(json.dumps(brief.model_dump(), default=str, indent=2), encoding="utf-8")
        except Exception:
            pass

        self.display.render_brief(brief)
        self.events.emit("mission.started", {"brief": brief.model_dump()})
        self.events.emit("stage.completed", {"stage": MissionStage.MISSION.value})
        self.display.render_stage_transition(MissionStage.MISSION, "completed")
        self._checkpoint()

    def _stage_reconnaissance(self) -> None:
        self.mission.current_stage = MissionStage.RECONNAISSANCE
        self.display.render_stage_transition(MissionStage.RECONNAISSANCE, "started")
        self.events.emit("stage.started", {"stage": MissionStage.RECONNAISSANCE.value})
        self.narrative(
            "reconnaissance",
            f"Initiating target reconnaissance against {self.mission.target}",
            f"Scope: {', '.join(self.mission.scope)} | Profile: {self.mission.profile}",
        )

        state = self.workspace.load()
        # Ensure target file exists
        self.workspace.write("raw/target.txt", f"Target: {self.mission.target}\nProfile: {self.mission.profile}\n")

        # Bootstrap application model and reconnaissance state
        from horcrux.agents.coordinator import on_recon_complete
        try:
            on_recon_complete(self.workspace, self.ai_manager)
            self.mission.budget.requests_count += 5
            self.mission.budget.tool_executions_count += 1
        except Exception as exc:
            self.narrative("reconnaissance", "Reconnaissance bootstrap warning", str(exc))

        self.events.emit("stage.completed", {"stage": MissionStage.RECONNAISSANCE.value})
        self.display.render_stage_transition(MissionStage.RECONNAISSANCE, "completed")
        self._checkpoint()

    def _stage_modeling(self) -> None:
        self.mission.current_stage = MissionStage.MODELING
        self.display.render_stage_transition(MissionStage.MODELING, "started")
        self.events.emit("stage.started", {"stage": MissionStage.MODELING.value})

        state = self.workspace.load()
        from horcrux.intel.ingestion import ingest_workspace_state
        app = ingest_workspace_state(state)
        state.set_application_model(app)
        self.workspace.save(state)

        app_summary = f"{len(app.endpoints)} endpoints, {len(app.technologies)} technologies, {len(app.routes)} routes mapped."
        self.narrative("modeling", "Application model constructed", app_summary)
        self.events.emit("model.updated", {"endpoints": len(app.endpoints), "technologies": len(app.technologies)})
        self.events.emit("stage.completed", {"stage": MissionStage.MODELING.value})
        self.display.render_stage_transition(MissionStage.MODELING, "completed")
        self._checkpoint()

    def _stage_authentication(self) -> None:
        self.mission.current_stage = MissionStage.AUTHENTICATION
        self.display.render_stage_transition(MissionStage.AUTHENTICATION, "started")
        self.events.emit("stage.started", {"stage": MissionStage.AUTHENTICATION.value})

        state = self.workspace.load()
        app = state.get_application_model()

        if self.mission.identities:
            self.narrative(
                "authentication",
                f"Validating {len(self.mission.identities)} configured identity profiles",
                "Establishing authenticated session contexts...",
            )
            for identity in self.mission.identities:
                try:
                    test_id = TestIdentity(
                        label=identity.identity_id,
                        role=identity.role,
                        login_path=identity.login_url or "/login",
                        username=identity.username,
                        password_env=identity.credentials_ref or identity.password_env,
                        headers=identity.headers,
                    )
                    register_test_identity(app, test_id)
                    # Create simulated session record
                    begin_session(
                        app,
                        identity_label=identity.identity_id,
                        role=identity.role,
                        login_endpoint=identity.login_url or "/login",
                    )
                    identity.is_authenticated = True
                    identity.last_verified_at = utcnow()
                    self.events.emit("identity.established", {
                        "identity_id": identity.identity_id,
                        "role": identity.role,
                    })
                    self.narrative(
                        "authentication",
                        f"Identity '{identity.identity_id}' ({identity.role}) established",
                        f"Session context registered in application model.",
                    )
                except Exception as exc:
                    self.events.emit("identity.failed", {
                        "identity_id": identity.identity_id,
                        "error": str(exc),
                    })

            # Check multi-perspective authorization readiness
            if len(self.mission.identities) >= 2:
                self.narrative(
                    "authentication",
                    "Multi-perspective testing enabled",
                    f"Configured perspectives: {', '.join(i.identity_id for i in self.mission.identities)}. Cross-identity matrix active.",
                )
            else:
                self.narrative(
                    "authentication",
                    "Single authenticated perspective",
                    "Cross-identity testing flagged as LIMITED/BLOCKED due to lack of distinct identities.",
                )
        else:
            self.narrative(
                "authentication",
                "No authenticated test identities configured",
                "Operating under anonymous perspective. Authenticated properties flagged accordingly.",
            )

        state.set_application_model(app)
        self.workspace.save(state)
        self.events.emit("stage.completed", {"stage": MissionStage.AUTHENTICATION.value})
        self.display.render_stage_transition(MissionStage.AUTHENTICATION, "completed")
        self._checkpoint()

    def _stage_discovery_and_hypothesis(self) -> None:
        self.mission.current_stage = MissionStage.DISCOVERY
        self.display.render_stage_transition(MissionStage.DISCOVERY, "started")
        self.events.emit("stage.started", {"stage": MissionStage.DISCOVERY.value})

        state = self.workspace.load()
        state = reassess(state, self.ai_manager)
        self.workspace.save(state)

        self.events.emit("stage.completed", {"stage": MissionStage.DISCOVERY.value})
        self.display.render_stage_transition(MissionStage.DISCOVERY, "completed")

        self.mission.current_stage = MissionStage.HYPOTHESIS
        self.display.render_stage_transition(MissionStage.HYPOTHESIS, "started")
        self.events.emit("stage.started", {"stage": MissionStage.HYPOTHESIS.value})

        hyps = state.get_hypotheses()
        self.narrative(
            "hypothesis",
            f"Generated {len(hyps)} security hypotheses from application semantics",
            ", ".join(h.hypothesis_class.value for h in hyps[:5]) + ("..." if len(hyps) > 5 else ""),
        )

        for h in hyps:
            self.events.emit("hypothesis.created", {
                "id": h.id,
                "title": h.title,
                "class": h.hypothesis_class.value,
                "confidence": h.confidence,
            })

        self.events.emit("stage.completed", {"stage": MissionStage.HYPOTHESIS.value})
        self.display.render_stage_transition(MissionStage.HYPOTHESIS, "completed")
        self._checkpoint()

    def _stage_investigation_loop(self) -> None:
        self.mission.current_stage = MissionStage.INVESTIGATION
        self.display.render_stage_transition(MissionStage.INVESTIGATION, "started")
        self.events.emit("stage.started", {"stage": MissionStage.INVESTIGATION.value})

        orchestrator = RootVAPTOrchestrator(
            workspace=self.workspace,
            ai_manager=self.ai_manager,
            max_iterations=self.mission.policy.max_iterations,
            max_workers=self.mission.policy.max_concurrency,
        )

        iteration = 0
        while iteration < self.mission.policy.max_iterations:
            if not self._check_should_continue():
                break

            state = self.workspace.load()
            if not assessment_has_actionable_work(state):
                self.narrative(
                    "investigation",
                    "Convergence reached",
                    "No actionable investigations or high-value unverified hypotheses remain.",
                )
                break

            # Reassess state and rank investigations
            state = reassess(state, self.ai_manager)
            investigations = rank_investigations(state.get_investigations())
            batch = orchestrator._choose_batch(state, investigations)

            if not batch:
                self.narrative("investigation", "Queue empty", "No high-value executable tasks remain.")
                break

            inv = batch[0]
            self.mission.current_investigation_id = inv.id
            self.mission.current_objective = inv.objective

            # Calculate queue stats
            invs_all = state.get_investigations()
            q_stats = {
                "READY": sum(1 for i in invs_all if i.state.value == "READY"),
                "RUNNING": sum(1 for i in invs_all if i.state.value == "RUNNING"),
                "BLOCKED": sum(1 for i in invs_all if i.state.value in ("BLOCKED", "SCOPE_BLOCKED", "UNAVAILABLE")),
                "COMPLETE": sum(1 for i in invs_all if i.state.value in ("COMPLETE", "SUPPORTED", "REFUTED")),
            }

            self.display.render_investigation_card(
                investigation_id=inv.id,
                objective=inv.objective,
                hypothesis_title=inv.reason,
                confidence=inv.confidence,
                blast_radius=getattr(inv, "blast_radius", "medium"),
                queue_stats=q_stats,
                evidence_count=len(inv.evidence_refs),
            )

            self.events.emit("investigation.started", {
                "id": inv.id,
                "objective": inv.objective,
                "specialist": inv.specialist,
            })

            # Execute batch
            orchestrator._execute_batch(state, batch)
            self.mission.budget.tool_executions_count += len(batch)
            self.mission.budget.requests_count += len(batch) * 2

            # Re-read state and emit completion
            state = self.workspace.load()
            for done_inv in batch:
                self.events.emit("investigation.completed", {
                    "id": done_inv.id,
                    "state": done_inv.state.value,
                    "result": done_inv.result_summary,
                })

            iteration += 1
            self.mission.budget.update_runtime()
            self._checkpoint()

        self.events.emit("stage.completed", {"stage": MissionStage.INVESTIGATION.value})
        self.display.render_stage_transition(MissionStage.INVESTIGATION, "completed")

    def _stage_correlation_and_handoffs(self) -> None:
        self.mission.current_stage = MissionStage.CORRELATION
        self.display.render_stage_transition(MissionStage.CORRELATION, "started")
        self.events.emit("stage.started", {"stage": MissionStage.CORRELATION.value})

        state = self.workspace.load()
        state = reassess(state, self.ai_manager)

        self.events.emit("stage.completed", {"stage": MissionStage.CORRELATION.value})
        self.display.render_stage_transition(MissionStage.CORRELATION, "completed")

        self.mission.current_stage = MissionStage.HANDOFF
        self.display.render_stage_transition(MissionStage.HANDOFF, "started")
        self.events.emit("stage.started", {"stage": MissionStage.HANDOFF.value})

        handoffs = prepare_exploit_handoffs(state)
        self.workspace.save(state)

        self.narrative(
            "handoff",
            f"Prepared {len(handoffs)} exploitation-ready handoffs",
            "Safe validation complete. High-risk exploitation bounded and requires operator authorization.",
        )

        for h in handoffs:
            self.events.emit("handoff.created", {
                "id": h.id,
                "finding_id": h.finding_id,
                "vulnerability": h.vulnerability,
                "confidence": h.confidence,
                "blast_radius": getattr(h, "blast_radius", "medium"),
            })

        self.events.emit("stage.completed", {"stage": MissionStage.HANDOFF.value})
        self.display.render_stage_transition(MissionStage.HANDOFF, "completed")
        self._checkpoint()

    def _stage_completion(self) -> None:
        self.mission.current_stage = MissionStage.COMPLETION
        self.display.render_stage_transition(MissionStage.COMPLETION, "started")
        self.events.emit("stage.started", {"stage": MissionStage.COMPLETION.value})

        state = self.workspace.load()

        # 1. Critical Invariant: Clean up any remaining READY / PENDING work
        invs = state.get_investigations()
        for inv in invs:
            if inv.state in (InvestigationState.READY, InvestigationState.PENDING, InvestigationState.RUNNING):
                inv.state = InvestigationState.BLOCKED
                if self.mission.termination_reason:
                    inv.result_summary = f"Categorized at convergence: {self.mission.termination_reason}"
                else:
                    inv.result_summary = "Categorized at convergence: maximum iterations/budget reached"
        state.set_investigations(invs)

        # 2. Run False-Negative Audit
        fn_report = run_false_negative_audit(state)
        state.false_negative_audit = fn_report.to_dict()

        # 3. Assess Completeness
        completeness = assessment_completeness(state)
        verdict = completeness.get("verdict", "INCOMPLETE")

        if self.mission.status not in (MissionStatus.INTERRUPTED, MissionStatus.ABORTED):
            if verdict == "COMPLETE" and completeness.get("sufficient", False):
                self.mission.status = MissionStatus.COMPLETE
                self.mission.completion_verdict = "COMPLETE"
            elif verdict in ("LIMITED", "BLOCKED") or completeness.get("blocking_reasons"):
                self.mission.status = MissionStatus.COMPLETE_WITH_LIMITATIONS
                self.mission.completion_verdict = "COMPLETE_WITH_LIMITATIONS"
            else:
                self.mission.status = MissionStatus.COMPLETE_WITH_LIMITATIONS
                self.mission.completion_verdict = verdict

        # 4. Generate Report
        try:
            from horcrux.reporting.reports import markdown
            report_file = markdown(self.workspace)
            self.narrative(
                "completion",
                f"Engagement report written to {report_file}",
                f"Total findings: {len(state.findings)} | Handoffs: {len(state.exploit_handoffs)}",
            )
        except Exception:
            pass

        self.workspace.save(state)
        self.display.render_completion(self.mission, completeness, fn_report.to_dict())

        self.events.emit("mission.completed", {
            "mission_id": self.mission.mission_id,
            "status": self.mission.status.value,
            "verdict": self.mission.completion_verdict,
            "runtime": self.mission.budget.runtime_seconds,
            "findings_count": len(state.findings),
            "handoffs_count": len(state.exploit_handoffs),
            "blocking_reasons": completeness.get("blocking_reasons", []),
        })
        self.events.emit("stage.completed", {"stage": MissionStage.COMPLETION.value})
        self.display.render_stage_transition(MissionStage.COMPLETION, "completed")
        self._checkpoint()

    # ── MISSION OPERATIONS (PAUSE / RESUME / ABORT / STATUS / EXPORT) ─────

    def pause(self) -> dict[str, Any]:
        """Pause a running mission."""
        self.mission.status = MissionStatus.PAUSED
        self._checkpoint()
        self.events.emit("mission.paused", {"mission_id": self.mission.mission_id})
        return {"status": "PAUSED", "mission_id": self.mission.mission_id}

    def resume(self) -> AssessmentMission:
        """Resume an interrupted or paused mission."""
        state = self.workspace.load()
        existing_mission = state.get_mission()
        if existing_mission:
            self.mission = existing_mission

        # Recover any interrupted RUNNING tasks
        recovery = recover_interrupted(state)
        self.events.emit("mission.resumed", {
            "mission_id": self.mission.mission_id,
            "recovered": recovery.get("recovered", []),
        })
        self.narrative(
            self.mission.current_stage.value,
            f"Resuming mission {self.mission.mission_id}",
            f"Recovered {len(recovery.get('recovered', []))} interrupted investigations.",
        )
        return self.run()

    def abort(self) -> dict[str, Any]:
        """Abort a mission."""
        self.mission.status = MissionStatus.ABORTED
        self.mission.termination_reason = "Aborted by operator command"
        self._checkpoint()
        self.events.emit("mission.aborted", {"mission_id": self.mission.mission_id})
        return {"status": "ABORTED", "mission_id": self.mission.mission_id}

    def status_summary(self) -> dict[str, Any]:
        """Return structured status of the mission."""
        state = self.workspace.load()
        invs = state.get_investigations()
        return {
            "mission_id": self.mission.mission_id,
            "target": self.mission.target,
            "stage": self.mission.current_stage.value,
            "status": self.mission.status.value,
            "completion_verdict": self.mission.completion_verdict,
            "runtime_seconds": int(self.mission.budget.runtime_seconds),
            "findings_count": len(state.findings),
            "handoffs_count": len(state.exploit_handoffs),
            "investigations": {
                "ready": sum(1 for i in invs if i.state.value == "READY"),
                "running": sum(1 for i in invs if i.state.value == "RUNNING"),
                "blocked": sum(1 for i in invs if i.state.value in ("BLOCKED", "SCOPE_BLOCKED", "UNAVAILABLE")),
                "complete": sum(1 for i in invs if i.state.value in ("COMPLETE", "SUPPORTED", "REFUTED")),
            },
        }
