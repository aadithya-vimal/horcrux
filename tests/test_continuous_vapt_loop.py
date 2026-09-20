"""Tests for continuous autonomous VAPT loop and operator constraints (Phases A and J)."""

import time
from horcrux.agents.root import RootVAPTOrchestrator
from horcrux.core.storage import Workspace
from horcrux.intel.investigations import Investigation, InvestigationState
from horcrux.models import WorkspaceState


def test_root_orchestrator_honors_time_limit(tmp_path):
    ws = Workspace("test-time-limit.local")
    ws.root = tmp_path
    (tmp_path / "raw").mkdir(parents=True, exist_ok=True)
    state = WorkspaceState(target="test-time-limit.local")
    ws.save(state)

    root = RootVAPTOrchestrator(ws, max_iterations=50, time_limit=1)
    t0 = time.time()
    res = root.run_assessment_loop()
    duration = time.time() - t0
    assert duration < 5


def test_root_orchestrator_does_not_mass_block_ready_tasks(tmp_path):
    ws = Workspace("test-continuous.local")
    ws.root = tmp_path
    (tmp_path / "raw").mkdir(parents=True, exist_ok=True)
    state = WorkspaceState(target="test-continuous.local")
    inv1 = Investigation(id="inv-1", objective="test 1", state=InvestigationState.READY)
    inv2 = Investigation(id="inv-2", objective="test 2", state=InvestigationState.READY)
    state.set_investigations([inv1, inv2])
    ws.save(state)

    root = RootVAPTOrchestrator(ws, max_iterations=2)
    res = root.run_assessment_loop()

    for inv in res.get_investigations():
        assert "iteration budget reached" not in getattr(inv, "failure_reason", "")
