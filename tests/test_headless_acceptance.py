"""Acceptance test for autonomous headless VAPT operator against Juice-Shop-like fixture (Section 57).

Validates autonomous end-to-end flow:
discover -> build model -> generate hypotheses -> execute investigations automatically ->
evidence increases -> model changes -> queue is regenerated -> continue until convergence ->
final report & completeness audit.
"""

from __future__ import annotations

from pathlib import Path

from horcrux.core.headless.config import build_mission_from_config
from horcrux.core.headless.controller import HeadlessMissionController
from horcrux.core.mission import MissionStatus
from horcrux.core.storage import Workspace
from tests.fixtures.juice_shop_like import build_juice_shop_fixture


def test_juice_shop_headless_acceptance_flow(tmp_path: Path):
    target = "juice-shop.local"
    ws = Workspace(target)
    ws.root = tmp_path / "ws_juiceshop_headless"
    ws.raw = ws.root / "raw"
    ws.responses = ws.root / "responses"
    ws.headers = ws.root / "headers"
    ws.reports = ws.root / "reports"
    for d in (ws.root, ws.raw, ws.responses, ws.headers, ws.reports):
        d.mkdir(parents=True, exist_ok=True)

    state = build_juice_shop_fixture()
    ws.save(state)

    mission = build_mission_from_config(
        target,
        profile="deep",
        execution_overrides={"max_iterations": 4, "max_runtime": 60, "narrative": True},
    )

    controller = HeadlessMissionController(
        workspace=ws,
        mission=mission,
        quiet=True,
    )

    final_mission = controller.run()

    # 1. Verification of mission completion status
    assert final_mission.status in (MissionStatus.COMPLETE, MissionStatus.COMPLETE_WITH_LIMITATIONS)
    assert final_mission.checkpoints_count >= 3

    # 2. Verification of Application Model growth
    final_state = ws.load()
    app = final_state.get_application_model()
    assert len(app.endpoints) >= 20
    assert len(app.object_types) >= 3

    # 3. Verification of Hypotheses and Investigations
    hyps = final_state.get_hypotheses()
    assert len(hyps) >= 5
    invs = final_state.get_investigations()
    assert len(invs) >= 5

    # 4. Critical Invariant: No unexplained READY or PENDING tasks left at completion
    actionable_remaining = [i for i in invs if i.state.value in ("READY", "PENDING")]
    assert len(actionable_remaining) == 0

    # 5. Exploit Handoffs and Safety Boundary
    assert isinstance(final_state.exploit_handoffs, list)
    for h in final_state.exploit_handoffs:
        assert h.operator_approval_required is True

    # 6. False-Negative Audit & Completeness Verdict
    assert "total_gaps" in final_state.false_negative_audit
    assert final_mission.completion_verdict in ("COMPLETE_WITH_LIMITATIONS", "LIMITED", "INCOMPLETE")

    # 7. Narrative Timeline populated
    assert len(final_mission.narrative_timeline) >= 4
    stages_logged = {entry["stage"] for entry in final_mission.narrative_timeline}
    assert "reconnaissance" in stages_logged or "modeling" in stages_logged or "investigation" in stages_logged

    # 8. Report generated
    report_file = ws.reports / "report.md"
    assert report_file.exists()
    report_text = report_file.read_text(encoding="utf-8")
    assert "Autonomous Headless Mission ID" in report_text or "Headless Mission ID" in report_text
