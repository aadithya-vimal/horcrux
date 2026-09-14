"""Operator focus controls (Phase 7, Part 9).

Commands: focus <area> | pause | resume | skip <ref> | prioritize <ref>
All changes affect the investigation scheduler and are visible via status.
"""

from __future__ import annotations

from typing import Any

FOCUS_AREAS = ("web", "api", "auth", "authz", "business_logic", "business-logic",
               "network", "all")

_AREA_TO_SPECIALISTS = {
    "web": ("WebAgent", "ClientSideAgent"),
    "api": ("APIAgent",),
    "auth": ("AuthenticationAgent",),
    "authz": ("AuthorizationAgent",),
    "business_logic": ("BusinessLogicAgent",),
    "business-logic": ("BusinessLogicAgent",),
    "network": ("NetworkAgent", "ReconAgent"),
    "all": (),
}


def normalize_area(raw: str) -> str:
    area = (raw or "").strip().lower()
    if area in ("business-logic", "business logic", "logic"):
        return "business_logic"
    if area in ("authz", "authorization", "authorisation"):
        return "authz"
    if area in ("auth", "authentication"):
        return "auth"
    return area or "all"


def apply_focus(state: Any, area: str) -> dict[str, Any]:
    area = normalize_area(area)
    if area not in FOCUS_AREAS and area != "business_logic":
        return {"applied": False, "detail": f"Unknown focus area '{area}'. Use: focus web|api|auth|authz|business-logic|network|all"}
    state.operator_focus.focus_type = "area"
    state.operator_focus.focus_id = area
    state.operator_focus.focus_area = area
    boost = _boost_focused(state, area)
    return {"applied": True, "area": area,
            "detail": f"Focus set to '{area}'; boosted {boost} investigation(s)."}


def _boost_focused(state: Any, area: str) -> int:
    if area == "all":
        return 0
    specialists = _AREA_TO_SPECIALISTS.get(area, ())
    n = 0
    try:
        from horcrux.intel.investigations import InvestigationState
        invs = state.get_investigations()
        for inv in invs:
            if inv.specialist in specialists and inv.state in (
                    InvestigationState.READY, InvestigationState.PENDING):
                inv.score.coverage_gap = min(1.0, inv.score.coverage_gap + 0.2)
                inv.score.expected_information_gain = min(
                    1.0, inv.score.expected_information_gain + 0.1)
                inv.priority = inv.score.total
                n += 1
        state.set_investigations(sorted(invs, key=lambda i: -i.priority))
    except Exception:
        pass
    return n


def pause(state: Any) -> dict[str, Any]:
    state.operator_focus.paused = True
    return {"applied": True, "detail": "Paused: no new work scheduled; running subprocess cleanup allowed."}


def resume(state: Any) -> dict[str, Any]:
    state.operator_focus.paused = False
    state.operator_focus.stopped = False
    return {"applied": True, "detail": "Resumed scheduling."}


def skip(state: Any, ref: str) -> dict[str, Any]:
    from horcrux.intel.ask_engine import validate_and_apply_action, AskAction, AskActionType
    return validate_and_apply_action(
        state, AskAction(action=AskActionType.SKIP_INVESTIGATION,
                         args={"investigation_ref": ref}))


def prioritize(state: Any, ref: str) -> dict[str, Any]:
    from horcrux.intel.ask_engine import validate_and_apply_action, AskAction, AskActionType
    return validate_and_apply_action(
        state, AskAction(action=AskActionType.REPRIORITIZE_INVESTIGATION,
                         args={"investigation_ref": ref}))


def scheduler_rank(state: Any, investigations: list) -> list:
    """Apply OperatorFocus to a ranked list (skip + prioritize + focus boost)."""
    from horcrux.intel.investigations import InvestigationState
    focus = getattr(state, "operator_focus", None)
    skip_ids = set(getattr(focus, "skip_investigation_ids", []) or [])
    ranked = [i for i in investigations if i.id not in skip_ids]
    # Focus boost already applied at set-time; re-apply cheaply for fresh candidates.
    area = getattr(focus, "focus_id", "") or getattr(focus, "focus_area", "all")
    if area and area != "all":
        specialists = _AREA_TO_SPECIALISTS.get(area, ())
        for inv in ranked:
            if inv.specialist in specialists:
                inv.priority = min(1.0, inv.priority + 0.02)
        ranked.sort(key=lambda i: -i.priority)
    prio = getattr(focus, "prioritize_investigation_id", "")
    if prio:
        ranked.sort(key=lambda i: (0 if i.id == prio else 1, -i.priority))
    return [i for i in ranked if i.state in (InvestigationState.READY, InvestigationState.PENDING)]
