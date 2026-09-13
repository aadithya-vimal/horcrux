from __future__ import annotations

import json
from horcrux.models import Action, WorkspaceState
from horcrux.intel.tasks.triage import build_compact_state


def execute_action_reasoning(
    ai_manager,
    state: WorkspaceState,
    candidate_actions: list[Action],
) -> list[Action]:
    """
    Ranks and augments locally synthesized candidate actions using AI contextual reasoning.
    Falls back to deterministic candidate order if AI is unavailable.
    """
    if not candidate_actions:
        return candidate_actions

    compact_state = build_compact_state(state)
    payload = {
        "target": compact_state["target"],
        "services": compact_state["services"],
        "findings": compact_state["findings"],
        "candidate_actions": [
            {
                "id": a.id,
                "title": a.title,
                "current_score": a.score,
                "reason": a.reason,
            }
            for a in candidate_actions[:8]
        ],
    }

    prompt = f"""You are an offensive security operator assistant.
Given the current engagement state and candidate actions, adjust priority scores (0 to 100) and provide concise tactical rationale.
Evidence input:
{json.dumps(payload, indent=2)}

Return a JSON list of prioritized actions:
[
  {{
    "id": "matching candidate id",
    "adjusted_score": 0 to 100,
    "refined_reason": "tactical justification based strictly on observed state"
  }}
]
"""

    resp = ai_manager.call_task("action_reasoning", prompt, payload=payload, max_tokens=512)
    if not resp or not resp.structured or not isinstance(resp.structured, list):
        return candidate_actions

    adjustments = {item["id"]: item for item in resp.structured if isinstance(item, dict) and "id" in item}
    for action in candidate_actions:
        if action.id in adjustments:
            adj = adjustments[action.id]
            if "adjusted_score" in adj:
                try:
                    action.score = float(adj["adjusted_score"])
                except (ValueError, TypeError):
                    pass
            if "refined_reason" in adj and adj["refined_reason"]:
                action.reason = str(adj["refined_reason"]).strip()

    candidate_actions.sort(key=lambda a: a.score, reverse=True)
    return candidate_actions
