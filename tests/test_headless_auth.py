"""Tests for headless access contexts, no-friction authentication, and authorization testing.

Verifies:
- Assessment starts immediately without authentication
- Assessment continues without stalling when no contexts are supplied
- Missing contexts result in immediate BLOCKED decisions with explicit MISSING_ACCESS_CONTEXT reasons
- Unrelated / public investigations continue executing
- Pre-established access contexts (anonymous, user, admin) are consumed
- Differential authorization testing works with supplied contexts
- Invalid/expired contexts do not stall or loop
- No automatic login attempts or credential prompting occur
"""

from __future__ import annotations

import json
from pathlib import Path

from horcrux.core.headless.config import build_mission_from_config
from horcrux.core.headless.controller import HeadlessMissionController
from horcrux.core.mission import AccessContextStatus, MissionStage, MissionStatus
from horcrux.core.storage import Workspace
from horcrux.intel.investigations import Investigation, InvestigationState
from tests.fixtures.synthetic_vulnerable_app import build_synthetic_workspace


def test_headless_scan_without_authentication_does_not_block(tmp_path: Path):
    """Section 36: Scan without any supplied access contexts proceeds immediately to convergence."""
    target = "http://no-auth.local"
    ws = Workspace(target)
    ws.root = tmp_path / "ws_no_auth"
    ws.raw = ws.root / "raw"
    ws.reports = ws.root / "reports"
    for d in (ws.root, ws.raw, ws.reports):
        d.mkdir(parents=True, exist_ok=True)

    state = build_synthetic_workspace()
    # Add an authorization investigation that requires two contexts
    authz_inv = Investigation(
        objective="Cross-user IDOR access validation",
        reason="Check for horizontal privilege escalation across tenant accounts",
        prerequisites=["two_identities"],
        specialist="AuthorizationAgent",
        candidate_tools=["identity_switch", "http_probe"],
        state=InvestigationState.READY,
    )
    authz_inv.ensure_id()
    invs = state.get_investigations()
    invs.append(authz_inv)
    state.set_investigations(invs)
    ws.save(state)

    # Mission configured with NO access contexts
    mission = build_mission_from_config(
        target,
        config_data={"access_contexts": []},
        execution_overrides={"max_iterations": 3, "max_runtime": 30},
    )

    ctrl = HeadlessMissionController(ws, mission, quiet=True)
    final_mission = ctrl.run()

    # 1. Mission converged without waiting or blocking
    assert final_mission.status in (MissionStatus.COMPLETE, MissionStatus.COMPLETE_WITH_LIMITATIONS)

    final_state = ws.load()
    final_invs = final_state.get_investigations()

    # 2. Auth-dependent investigation is immediately BLOCKED with explicit reason
    target_inv = next(i for i in final_invs if i.id == authz_inv.id)
    assert target_inv.state in (
        InvestigationState.BLOCKED,
        InvestigationState.UNAVAILABLE,
        InvestigationState.REQUIRES_SECOND_IDENTITY,
    )
    assert "MISSING_ACCESS_CONTEXT" in target_inv.result_summary

    # 3. Public/unrelated investigations continued and finished
    completed_or_progressed = [
        i for i in final_invs
        if i.state in (InvestigationState.COMPLETE, InvestigationState.SUPPORTED, InvestigationState.REFUTED, InvestigationState.BLOCKED)
    ]
    assert len(completed_or_progressed) >= 2

    # 4. Zero unexplained READY or PENDING tasks left
    unexplained = [i for i in final_invs if i.state.value in ("READY", "PENDING")]
    assert len(unexplained) == 0


def test_supplied_contexts_enable_authorization_testing(tmp_path: Path):
    """Section 37: Pre-established access contexts enable cross-context testing without logins."""
    target = "http://supplied-auth.local"
    ws = Workspace(target)
    ws.root = tmp_path / "ws_supplied"
    ws.raw = ws.root / "raw"
    ws.reports = ws.root / "reports"
    for d in (ws.root, ws.raw, ws.reports):
        d.mkdir(parents=True, exist_ok=True)

    state = build_synthetic_workspace()
    ws.save(state)

    secret_token = "TOP_SECRET_SESSION_TOKEN_XYZ_99"
    cfg = {
        "access_contexts": [
            {"id": "anonymous", "role": "anonymous"},
            {
                "id": "tenant_user",
                "role": "user",
                "headers": {"Authorization": f"Bearer {secret_token}"},
                "cookies": {"session": "user_cookie_abc"},
            },
            {
                "id": "tenant_admin",
                "role": "admin",
                "headers": {"Authorization": "Bearer ADMIN_SECRET_123"},
                "cookies": {"session": "admin_cookie_def"},
            },
        ]
    }

    mission = build_mission_from_config(
        target,
        config_data=cfg,
        execution_overrides={"max_iterations": 2, "max_runtime": 30},
    )
    assert len(mission.get_all_contexts()) == 3

    ctrl = HeadlessMissionController(ws, mission, quiet=True)
    final_mission = ctrl.run()

    assert final_mission.status in (MissionStatus.COMPLETE, MissionStatus.COMPLETE_WITH_LIMITATIONS)

    # Verify contexts are registered in application model
    loaded_state = ws.load()
    app = loaded_state.get_application_model()
    assert len(app.identities) >= 3
    ident_labels = {i.label for i in app.identities}
    assert "tenant_user" in ident_labels
    assert "tenant_admin" in ident_labels

    # Verify secrets NEVER leak into events.jsonl
    events_file = ws.raw / "events.jsonl"
    if events_file.exists():
        events_text = events_file.read_text(encoding="utf-8")
        assert secret_token not in events_text
        assert "ADMIN_SECRET_123" not in events_text


def test_expired_context_does_not_block_mission(tmp_path: Path):
    """Section 38: Expired/invalid context is marked UNAVAILABLE and public testing continues."""
    target = "http://expired-context.local"
    ws = Workspace(target)
    ws.root = tmp_path / "ws_expired"
    ws.raw = ws.root / "raw"
    ws.reports = ws.root / "reports"
    for d in (ws.root, ws.raw, ws.reports):
        d.mkdir(parents=True, exist_ok=True)

    state = build_synthetic_workspace()
    ws.save(state)

    cfg = {
        "access_contexts": [
            {"id": "anon", "role": "anonymous"},
            {
                "id": "stale_admin",
                "role": "admin",
                "metadata": {"force_invalid": True},
            },
        ]
    }

    mission = build_mission_from_config(
        target,
        config_data=cfg,
        execution_overrides={"max_iterations": 2, "max_runtime": 30},
    )

    ctrl = HeadlessMissionController(ws, mission, quiet=True)
    final_mission = ctrl.run()

    # Mission continues and completes
    assert final_mission.status in (MissionStatus.COMPLETE, MissionStatus.COMPLETE_WITH_LIMITATIONS)

    # Check that stale_admin is marked UNAVAILABLE
    admin_ctx = final_mission.get_context("stale_admin")
    assert admin_ctx is not None
    assert admin_ctx.status == AccessContextStatus.UNAVAILABLE


def test_no_auth_loop(tmp_path: Path):
    """Section 39: An invalid context must never trigger loops, repeated login attempts, or timeouts."""
    target = "http://no-loop.local"
    ws = Workspace(target)
    ws.root = tmp_path / "ws_no_loop"
    ws.raw = ws.root / "raw"
    ws.reports = ws.root / "reports"
    for d in (ws.root, ws.raw, ws.reports):
        d.mkdir(parents=True, exist_ok=True)

    state = build_synthetic_workspace()
    ws.save(state)

    cfg = {
        "access_contexts": [
            {"id": "bad_ctx", "role": "admin", "metadata": {"expired": True}},
        ]
    }

    mission = build_mission_from_config(
        target,
        config_data=cfg,
        execution_overrides={"max_iterations": 2, "max_runtime": 10},
    )

    ctrl = HeadlessMissionController(ws, mission, quiet=True)
    import time
    start = time.time()
    final_mission = ctrl.run()
    duration = time.time() - start

    # Execution should finish fast with zero retry loops (well under 5 seconds)
    assert duration < 5.0
    assert final_mission.status in (MissionStatus.COMPLETE, MissionStatus.COMPLETE_WITH_LIMITATIONS)
    # Check that there are no repeated validation events
    events_file = ws.raw / "events.jsonl"
    if events_file.exists():
        lines = [json.loads(l) for l in events_file.read_text(encoding="utf-8").splitlines() if l.strip()]
        reg_events = [e for e in lines if e.get("event") == "context.registered" and e.get("data", {}).get("context_id") == "bad_ctx"]
        assert len(reg_events) <= 1
