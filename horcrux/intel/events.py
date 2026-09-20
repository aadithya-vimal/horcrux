"""Structured event log + evidence provenance graph (Parts 22, 35).

Major assessment transitions are logged as structured events persisted to
``raw/events.jsonl`` inside the workspace. All entries pass through secret
redaction. The provenance index answers finding -> evidence -> observation ->
tool execution, and attack path -> findings/evidence.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any


EVENT_TYPES = (
    "ASSESSMENT_STARTED",
    "MODEL_UPDATED",
    "HYPOTHESIS_CREATED",
    "INVESTIGATION_CREATED",
    "INVESTIGATION_STARTED",
    "INVESTIGATION_COMPLETED",
    "EVIDENCE_INGESTED",
    "FINDING_UPDATED",
    "ATTACK_PATH_UPDATED",
    "AI_REASONING_COMPLETED",
    "CAPABILITY_FAILED",
    "SCOPE_BLOCKED",
    "OPERATOR_PAUSED",
    "OPERATOR_RESUMED",
    "HANDOFF_CREATED",
    "ASSESSMENT_COMPLETED",
)


def _redact(obj: Any) -> Any:
    try:
        from horcrux.core.sanitizer import redact_secrets
    except Exception:
        return obj
    if isinstance(obj, str):
        return redact_secrets(obj)
    if isinstance(obj, dict):
        return {k: _redact(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_redact(v) for v in obj]
    return obj


def log_event(workspace: Any, state: Any, event_type: str,
              detail: dict[str, Any] | None = None) -> dict[str, Any]:
    """Append a redacted structured event; never raises."""
    entry = {"ts": datetime.now(timezone.utc).isoformat(),
             "event": event_type if event_type in EVENT_TYPES else "UNKNOWN",
             "target": getattr(state, "target", "") if state is not None else "",
             "phase": getattr(state, "assessment_phase", "") if state is not None else "",
             "detail": _redact(detail or {})}
    if workspace is not None:
        try:
            path = workspace.root / "raw" / "events.jsonl"
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, default=str) + "\n")
        except Exception:
            pass
    return entry


def read_events(workspace: Any, limit: int = 50,
                event_filter: str = "") -> list[dict[str, Any]]:
    """Read recent events (newest last)."""
    try:
        path = workspace.root / "raw" / "events.jsonl"
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return []
    out: list[dict[str, Any]] = []
    for line in lines[-abs(limit * 4):]:
        try:
            rec = json.loads(line)
        except Exception:
            continue
        if event_filter and rec.get("event") != event_filter:
            continue
        out.append(rec)
    return out[-limit:]


def state_delta(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """Summarize what changed between two lightweight state snapshots."""
    delta: dict[str, Any] = {}
    for key in ("endpoints", "hypotheses", "investigations", "findings",
                "coverage", "attack_paths", "phase"):
        b, a = before.get(key), after.get(key)
        if isinstance(b, (int, float)) and isinstance(a, (int, float)) and a != b:
            delta[key] = {"before": b, "after": a}
        elif b != a and key in ("phase",):
            delta[key] = {"before": b, "after": a}
    return delta


def snapshot_counts(state: Any) -> dict[str, Any]:
    """Cheap snapshot for delta analysis ('what changed since reassessment')."""
    try:
        app = state.get_application_model()
        n_endpoints = len(app.endpoints)
    except Exception:
        n_endpoints = 0
    try:
        n_hyps = len(state.get_hypotheses())
        n_invs = len(state.get_investigations())
    except Exception:
        n_hyps = n_invs = 0
    return {"endpoints": n_endpoints, "hypotheses": n_hyps,
            "investigations": n_invs, "findings": len(getattr(state, "findings", []) or []),
            "attack_paths": len(getattr(state, "attack_paths", []) or []),
            "phase": getattr(state, "assessment_phase", "")}


def finding_lineage(state: Any, finding_id: str) -> dict[str, Any]:
    """Trace finding -> evidence -> observation -> tool execution."""
    lineage: dict[str, Any] = {"finding": finding_id, "evidence": [],
                               "observations": [], "executions": []}
    finding = next((f for f in getattr(state, "findings", []) if f.id == finding_id), None)
    if finding is None:
        return lineage
    lineage["evidence"] = list(finding.evidence or [])
    lineage["title"] = finding.title
    lineage["validation_state"] = finding.validation_state.value
    # Observations: match evidence refs against endpoint evidence_refs.
    try:
        app = state.get_application_model()
        for ep in app.endpoints:
            shared = set(ep.evidence_refs or []) & set(finding.evidence or [])
            if shared:
                lineage["observations"].append(
                    {"endpoint": ep.path, "sources": ep.sources,
                     "shared_refs": sorted(shared)[:5]})
    except Exception:
        pass
    return lineage


def attack_path_lineage(state: Any, path_id: str) -> dict[str, Any]:
    """Trace attack path -> hypothesis/investigations/evidence + finding (if promoted)."""
    for p in getattr(state, "attack_paths", []) or []:
        if p.get("id") == path_id or p.get("name", "").startswith(path_id):
            return {"path": p.get("name"), "status": p.get("status", "HYPOTHESIS"),
                    "finding_ids": p.get("finding_ids", []),
                    "hypothesis_id": p.get("hypothesis_id", ""),
                    "investigation_ids": p.get("investigation_ids", []),
                    "nodes": [{"type": n.get("node_type"), "label": n.get("label"),
                               "status": n.get("status", ""),
                               "hypothesis_id": n.get("hypothesis_id", ""),
                               "investigation_ids": n.get("investigation_ids", []),
                               "finding_id": n.get("finding_id", "")}
                              for n in p.get("nodes", [])],
                    "edges": [{"type": e.get("edge_type"), "evidence": e.get("evidence", []),
                               "security_evidence": e.get("security_evidence", False),
                               "inference": e.get("inference", False)}
                              for e in p.get("edges", [])],
                    "assumptions": p.get("assumptions", []),
                    "rank_why": p.get("rank_why", "")}
    return {"path": path_id, "status": "HYPOTHESIS", "finding_ids": [],
            "hypothesis_id": "", "investigation_ids": [], "nodes": [], "edges": []}
