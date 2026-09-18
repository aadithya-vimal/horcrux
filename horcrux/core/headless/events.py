"""Structured JSONL event stream for headless autonomous operations.

Emits typed, redacted events to workspace/raw/events.jsonl, stdout, and live sinks.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from horcrux.core.sanitizer import redact_secrets

HEADLESS_EVENT_TYPES = {
    "mission.started",
    "mission.checkpoint",
    "mission.paused",
    "mission.resumed",
    "mission.interrupted",
    "mission.aborted",
    "mission.completed",
    "stage.started",
    "stage.completed",
    "capability.started",
    "capability.completed",
    "capability.failed",
    "discovery.added",
    "model.updated",
    "identity.established",
    "identity.failed",
    "identity.switched",
    "hypothesis.created",
    "hypothesis.updated",
    "hypothesis.evaluated",
    "investigation.created",
    "investigation.started",
    "investigation.completed",
    "investigation.blocked",
    "evidence.added",
    "finding.created",
    "attack_path.updated",
    "handoff.created",
    "integration.used",
    "integration.unavailable",
    "narrative.entry",
}


def _redact_payload(data: Any) -> Any:
    if isinstance(data, str):
        return redact_secrets(data)
    if isinstance(data, dict):
        return {k: _redact_payload(v) for k, v in data.items()}
    if isinstance(data, list):
        return [_redact_payload(v) for v in data]
    return data


class HeadlessEventEmitter:
    """Manages publishing and logging of typed events during headless assessments."""

    def __init__(
        self,
        workspace: Any = None,
        stdout_jsonl: bool = False,
        observer: Optional[Callable[[dict[str, Any]], None]] = None,
    ) -> None:
        self.workspace = workspace
        self.stdout_jsonl = stdout_jsonl
        self.observer = observer
        self._history: list[dict[str, Any]] = []

    def emit(self, event_type: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        """Record and stream a single structured event."""
        payload_data = _redact_payload(payload or {})
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event_type,
            "data": payload_data,
        }

        self._history.append(event)
        if len(self._history) > 1000:
            self._history = self._history[-1000:]

        if self.workspace is not None:
            try:
                events_file = self.workspace.root / "raw" / "events.jsonl"
                events_file.parent.mkdir(parents=True, exist_ok=True)
                with open(events_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(event, default=str) + "\n")
            except Exception:
                pass

        if self.stdout_jsonl:
            try:
                sys.stdout.write(json.dumps(event, default=str) + "\n")
                sys.stdout.flush()
            except Exception:
                pass

        if self.observer is not None:
            try:
                self.observer(event)
            except Exception:
                pass

        return event

    def narrative(self, stage: str, header: str, detail: str, evidence_ref: str = "") -> dict[str, Any]:
        """Convenience method for researcher narrative entries."""
        return self.emit("narrative.entry", {
            "stage": stage,
            "header": header,
            "detail": detail,
            "evidence_ref": evidence_ref,
        })
