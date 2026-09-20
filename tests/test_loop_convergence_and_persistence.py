"""Investigation Loop Convergence, Feedback, and Persistence (Sections 12, 13, 14, 15, 16)."""

from __future__ import annotations

from pathlib import Path
from horcrux.agents.root import RootVAPTOrchestrator
from horcrux.core.storage import Workspace
from horcrux.intel.ask_engine import answer_deterministically
from horcrux.intel.hypotheses import HypothesisClass
from horcrux.intel.investigations import InvestigationState
from horcrux.models import ValidationState
from tests.fixtures.juice_shop_like import build_juice_shop_fixture


def test_section_13_investigation_loop_convergence_and_feedback(tmp_path: Path):
    """Sections 13 and 14: Loop converges to READY=0, RUNNING=0; model updates drive scheduling."""
    ws = Workspace("juice-shop.local")
    ws.root = tmp_path
    ws.raw = tmp_path / "raw"
    ws.responses = tmp_path / "responses"
    ws.headers = tmp_path / "headers"
    ws.reports = tmp_path / "reports"
    for d in (ws.root, ws.raw, ws.responses, ws.headers, ws.reports):
        d.mkdir(parents=True, exist_ok=True)

    state = build_juice_shop_fixture()
    ws.save(state)

    orchestrator = RootVAPTOrchestrator(ws, max_iterations=6)
    final_state = orchestrator.run_assessment_loop()

    # Section 13: Loop convergence invariant
    invs = final_state.get_investigations()
    ready_count = sum(1 for i in invs if i.state == InvestigationState.READY)
    running_count = sum(1 for i in invs if i.state == InvestigationState.RUNNING)
    assert ready_count == 0, f"READY investigations remaining: {ready_count}"
    assert running_count == 0, f"RUNNING investigations remaining: {running_count}"

    # Section 14: Application-Model feedback produced findings
    assert len(final_state.findings) >= 1

    # Section 15: Persistence — reload from disk
    reloaded_ws = Workspace("juice-shop.local")
    reloaded_ws.root = tmp_path
    reloaded_state = reloaded_ws.load()
    assert len(reloaded_state.findings) == len(final_state.findings)
    assert len(reloaded_state.findings) >= 1

    # Section 16: Ask Acceptance from persisted structured state
    q1 = answer_deterministically(reloaded_state, "What vulnerabilities did you actually confirm?")
    assert len(q1) > 0

    q2 = answer_deterministically(reloaded_state, "Which confirmed findings have no CVE?")
    assert len(q2) > 0
