"""Tests for autonomous headless mission lifecycle, checkpoints, budgets, and convergence."""

from __future__ import annotations

import json
from pathlib import Path

from horcrux.core.headless.config import build_mission_from_config
from horcrux.core.headless.controller import HeadlessMissionController
from horcrux.core.mission import (
    AssessmentMission,
    HeadlessExecutionPolicy,
    MissionStage,
    MissionStatus,
)
from horcrux.core.storage import Workspace
from horcrux.intel.investigations import Investigation, InvestigationState
from horcrux.models import WorkspaceState
from tests.fixtures.synthetic_vulnerable_app import build_synthetic_workspace


def test_mission_brief_generation_and_persistence(tmp_path: Path):
    target = "127.0.0.1:3000"
    mission = build_mission_from_config(target, profile="standard")
    ws = Workspace(target)
    ws.root = tmp_path / "ws_brief"
    ws.raw = ws.root / "raw"
    ws.root.mkdir(parents=True, exist_ok=True)
    ws.raw.mkdir(parents=True, exist_ok=True)
    ws.save(build_synthetic_workspace())

    ctrl = HeadlessMissionController(ws, mission, quiet=True)
    ctrl._stage_mission_and_scope()

    brief_file = ws.root / "raw" / "mission-brief.json"
    assert brief_file.exists()
    data = json.loads(brief_file.read_text(encoding="utf-8"))
    assert data["target"] == target
    assert "objectives" in data
    assert "safety_limits" in data
    assert data["safety_limits"]["destructive_actions"] is False
    assert data["safety_limits"]["exploit_execution"] is False


def test_budget_exhaustion_stops_mission(tmp_path: Path):
    target = "http://budget.local"
    mission = build_mission_from_config(
        target,
        execution_overrides={"max_iterations": 2, "max_requests": 5, "max_runtime": 2},
    )
    ws = Workspace(target)
    ws.root = tmp_path / "ws_budget"
    ws.raw = ws.root / "raw"
    ws.root.mkdir(parents=True, exist_ok=True)
    ws.raw.mkdir(parents=True, exist_ok=True)
    ws.save(build_synthetic_workspace())

    ctrl = HeadlessMissionController(ws, mission, quiet=True)
    ctrl.mission.budget.requests_count = 10  # simulate request exhaustion
    assert ctrl.mission.budget.check_limits(ctrl.mission.policy) is True

    result = ctrl.run()
    assert result.status in (MissionStatus.COMPLETE_WITH_LIMITATIONS, MissionStatus.RUNNING)
    assert len(ctrl.mission.budget.exhaustion_reasons) > 0


def test_mission_checkpoint_and_resumability(tmp_path: Path):
    target = "http://resume.local"
    mission = build_mission_from_config(target)
    ws = Workspace(target)
    ws.root = tmp_path / "ws_resume"
    ws.raw = ws.root / "raw"
    ws.root.mkdir(parents=True, exist_ok=True)
    ws.raw.mkdir(parents=True, exist_ok=True)
    state = build_synthetic_workspace()
    ws.save(state)

    ctrl = HeadlessMissionController(ws, mission, quiet=True)
    ctrl._stage_mission_and_scope()
    ctrl._stage_reconnaissance()
    ctrl._checkpoint()

    # Verify state contains saved mission
    saved_state = ws.load()
    loaded_mission = saved_state.get_mission()
    assert loaded_mission is not None
    assert loaded_mission.mission_id == mission.mission_id
    assert loaded_mission.checkpoints_count >= 1

    # Simulate pause and resume
    ctrl.pause()
    assert ws.load().get_mission().status == MissionStatus.PAUSED

    # Resume controller
    ctrl2 = HeadlessMissionController(ws, ws.load().get_mission(), quiet=True)
    status = ctrl2.status_summary()
    assert status["mission_id"] == mission.mission_id
    assert status["status"] == "PAUSED"


def test_zero_unexplained_ready_investigations_at_completion(tmp_path: Path):
    """Critical invariant: At completion there must be no unexplained READY or PENDING tasks."""
    target = "http://invariant.local"
    mission = build_mission_from_config(target)
    ws = Workspace(target)
    ws.root = tmp_path / "ws_invariant"
    ws.raw = ws.root / "raw"
    ws.reports = ws.root / "reports"
    ws.root.mkdir(parents=True, exist_ok=True)
    ws.raw.mkdir(parents=True, exist_ok=True)
    ws.reports.mkdir(parents=True, exist_ok=True)
    state = build_synthetic_workspace()
    
    # Inject a READY and a PENDING task
    invs = [
        Investigation(objective="Test A", state=InvestigationState.READY),
        Investigation(objective="Test B", state=InvestigationState.PENDING),
        Investigation(objective="Test C", state=InvestigationState.COMPLETE),
    ]
    state.set_investigations(invs)
    ws.save(state)

    ctrl = HeadlessMissionController(ws, mission, quiet=True)
    ctrl._stage_completion()

    final_state = ws.load()
    final_invs = final_state.get_investigations()
    
    # Invariant: No remaining READY or PENDING tasks
    remaining_actionable = [i for i in final_invs if i.state in (InvestigationState.READY, InvestigationState.PENDING)]
    assert len(remaining_actionable) == 0

    blocked_tasks = [i for i in final_invs if i.state == InvestigationState.BLOCKED]
    assert len(blocked_tasks) == 2
    assert all("Categorized at convergence" in i.result_summary for i in blocked_tasks)
