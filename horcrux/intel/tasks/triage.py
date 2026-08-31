from __future__ import annotations

import json
from typing import Any
from horcrux.models import ExploitCandidate, WorkspaceState
from horcrux.intel.ai.base import HORCRUX_EVIDENCE_POLICY


def build_compact_state(state: WorkspaceState) -> dict[str, Any]:
    """Builds a token-efficient structured summary of the workspace state."""
    return {
        "target": state.target,
        "services": [
            {
                "port": s.port,
                "protocol": s.protocol,
                "service": s.service,
                "product": s.product,
                "version": s.version,
            }
            for s in state.services
        ],
        "software": [
            {
                "product": s.product,
                "version": s.version,
                "confidence": round(s.confidence, 2),
            }
            for s in state.software
        ],
        "technologies": state.technologies[:12],
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value,
                "state": f.validation_state.value,
            }
            for f in state.findings[:10]
        ],
        "audited_checks": [
            {"asset": a.asset, "check": a.check_name, "status": a.status.value}
            for a in state.audit[:8]
        ],
    }


def execute_exploit_triage(
    ai_manager,
    state: WorkspaceState,
    candidates: list[ExploitCandidate],
) -> list[ExploitCandidate]:
    """
    Evaluates candidate exploits against host evidence using structured AI reasoning.
    Falls back to deterministic relevance ratings if AI is unavailable.
    """
    if not candidates:
        return candidates

    compact_state = build_compact_state(state)
    candidates_subset = candidates[:10]
    payload = {
        "target_context": compact_state,
        "candidates": [
            {
                "title": c.title,
                "product": c.product,
                "version": c.version,
                "cve": c.cve,
                "source": c.source,
                "exploitability": c.exploitability,
            }
            for c in candidates_subset
        ],
    }

    prompt = f"""Evaluate the applicability of these exploit candidates against the discovered host environment.
Input:
{json.dumps(payload, indent=2)}

Return a JSON list of evaluations for each candidate in order:
[
  {{
    "decision": "HIGHLY_RELEVANT" | "POTENTIAL" | "REJECTED",
    "confidence": 0.0 to 1.0,
    "attack_type": "remote" | "local" | "dos",
    "reasoning": "exact technical match or contradiction explanation",
    "missing_prerequisites": ["string"],
    "recommended_verification": "safe non-destructive command or check"
  }}
]
"""

    resp = ai_manager.call_task("exploit_triage", prompt, payload=payload, max_tokens=1024)
    if not resp or not resp.structured or not isinstance(resp.structured, list):
        return candidates

    evaluations = resp.structured
    for idx, cand in enumerate(candidates_subset):
        if idx < len(evaluations) and isinstance(evaluations[idx], dict):
            ev = evaluations[idx]
            decision = ev.get("decision", "POTENTIAL")
            if decision == "HIGHLY_RELEVANT":
                cand.relevance = "CONFIRMED VERSION MATCH"
            elif decision == "REJECTED":
                cand.relevance = "IRRELEVANT / WRONG PLATFORM"
            else:
                cand.relevance = "HIGH-CONFIDENCE CANDIDATE"

            cand.confidence = min(1.0, max(0.1, float(ev.get("confidence", cand.confidence))))
            cand.relevance_reasoning = ev.get("reasoning", cand.relevance_reasoning)
            if ev.get("attack_type"):
                cand.exploitability = f"{ev['attack_type'].upper()}"

    return candidates
