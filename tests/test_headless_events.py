"""Tests for headless JSONL event stream and secret redaction."""

from __future__ import annotations

import json
from pathlib import Path

from horcrux.core.headless.events import HEADLESS_EVENT_TYPES, HeadlessEventEmitter
from horcrux.core.storage import Workspace


def test_headless_events_stream_and_format(tmp_path: Path):
    ws = Workspace("test_event_target")
    ws.root = tmp_path / "ws_events"
    ws.raw = ws.root / "raw"
    ws.root.mkdir(parents=True, exist_ok=True)
    ws.raw.mkdir(parents=True, exist_ok=True)

    captured_events: list[dict] = []
    emitter = HeadlessEventEmitter(
        workspace=ws,
        observer=lambda ev: captured_events.append(ev),
    )

    emitter.emit("mission.started", {"target": "10.0.0.1"})
    emitter.emit("stage.started", {"stage": "RECONNAISSANCE"})
    emitter.narrative("reconnaissance", "Target probed", "Web server running nginx 1.18")
    emitter.emit("stage.completed", {"stage": "RECONNAISSANCE"})

    assert len(captured_events) == 4
    assert captured_events[0]["event"] == "mission.started"
    assert captured_events[1]["event"] == "stage.started"
    assert captured_events[2]["event"] == "narrative.entry"
    assert captured_events[3]["event"] == "stage.completed"

    # Verify persisted JSONL file
    log_file = ws.root / "raw" / "events.jsonl"
    assert log_file.exists()
    lines = [json.loads(line) for line in log_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) == 4
    for line in lines:
        assert "timestamp" in line
        assert "event" in line
        assert "data" in line


def test_headless_events_redaction(tmp_path: Path):
    ws = Workspace("redact_target")
    ws.root = tmp_path / "ws_redact"
    ws.raw = ws.root / "raw"
    ws.root.mkdir(parents=True, exist_ok=True)
    ws.raw.mkdir(parents=True, exist_ok=True)

    emitter = HeadlessEventEmitter(workspace=ws)
    emitter.emit("identity.established", {
        "user": "admin",
        "api_key": "gsk_1234567890abcdef1234567890abcdef1234567890abcdef",
    })

    log_file = ws.root / "raw" / "events.jsonl"
    content = log_file.read_text(encoding="utf-8")
    assert "gsk_1234567890abcdef1234567890abcdef1234567890abcdef" not in content
    assert "••••" in content or "REDACTED" in content or "gsk_••••" in content
