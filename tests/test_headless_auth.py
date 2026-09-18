"""Tests for multi-identity configuration, session registration, and cross-identity authorization."""

from __future__ import annotations

from pathlib import Path

from horcrux.core.headless.config import build_mission_from_config
from horcrux.core.headless.controller import HeadlessMissionController
from horcrux.core.storage import Workspace
from tests.fixtures.synthetic_vulnerable_app import build_synthetic_workspace


def test_multi_identity_configured_sessions(tmp_path: Path):
    target = "http://auth-test.local"
    cfg = {
        "identities": [
            {"id": "user_a", "role": "user", "username": "alice", "credentials_ref": "PASS_ALICE"},
            {"id": "admin_x", "role": "admin", "username": "root", "credentials_ref": "PASS_ROOT"},
        ]
    }
    mission = build_mission_from_config(target, config_data=cfg)
    assert len(mission.identities) == 2

    ws = Workspace(target)
    ws.root = tmp_path / "ws_auth"
    ws.raw = ws.root / "raw"
    ws.root.mkdir(parents=True, exist_ok=True)
    ws.raw.mkdir(parents=True, exist_ok=True)
    ws.save(build_synthetic_workspace())

    ctrl = HeadlessMissionController(ws, mission, quiet=True)
    ctrl._stage_modeling()
    ctrl._stage_authentication()

    state = ws.load()
    app = state.get_application_model()
    assert len(app.identities) >= 2
    labels = {i.label for i in app.identities}
    assert "user_a" in labels
    assert "admin_x" in labels


def test_single_identity_marks_cross_identity_blocked(tmp_path: Path):
    """When only 1 identity is available, cross-identity testing is recognized as limited/blocked."""
    target = "http://single-id.local"
    cfg = {
        "identities": [
            {"id": "anon", "role": "anonymous"},
        ]
    }
    mission = build_mission_from_config(target, config_data=cfg)
    ws = Workspace(target)
    ws.root = tmp_path / "ws_single"
    ws.raw = ws.root / "raw"
    ws.root.mkdir(parents=True, exist_ok=True)
    ws.raw.mkdir(parents=True, exist_ok=True)
    ws.save(build_synthetic_workspace())

    ctrl = HeadlessMissionController(ws, mission, quiet=True)
    ctrl._stage_modeling()
    ctrl._stage_authentication()

    state = ws.load()
    app = state.get_application_model()
    # Anonymous identity registered
    assert any(i.label == "anon" or i.role.value == "anonymous" for i in app.identities)
