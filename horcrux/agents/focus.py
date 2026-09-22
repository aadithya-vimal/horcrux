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
    """Apply OperatorFocus to a ranked list (skip + prioritize + focus boost).

    Security reservation: critical property families (auth bypass, authz,
    injection, sensitive exposure, API security, session) always sort
    ahead of recon expansion, so passive discovery can never starve
    executable security tests. Every READY test still returns (ordered,
    never dropped), so no property is permanently sacrificed.
    """
    from horcrux.intel.investigations import InvestigationState
    focus = getattr(state, "operator_focus", None)
    skip_ids = set(getattr(focus, "skip_investigation_ids", []) or [])
    ranked = [i for i in investigations if i.id not in skip_ids]
    tiers: dict[int, int] = {}
    for inv in ranked:
        obs = " ".join(str(o) for o in (getattr(inv, "observations", []) or [])).lower()
        fams = [o.split(":", 1)[1] for o in (getattr(inv, "observations", []) or [])
                if str(o).startswith("matrix_family:")]
        if fams:
            tier = 3
            for fam in fams:
                tier = min(tier, _RESERVATION_TIER.get(str(fam), 3))
        else:
            # Hypothesis-driven (non-matrix) security work is primary, not
            # recon expansion: only pure discovery objectives sort last.
            tier = 1
            _obj = str(getattr(inv, "objective", "") or "").lower()
            if any(k in _obj for k in ("fuzzing", "wordlist", "banner", "hidden routes",
                                       "content discovery", "enumerate")):
                tier = 3
            else:
                for vc in (getattr(inv, "vulnerability_classes", []) or []):
                    tier = min(tier, _RESERVATION_TIER.get(str(vc), tier))
        if "registration" in obs or "bypass" in obs:
            tier = min(tier, 0)
        inv.priority = min(1.0, float(getattr(inv, "priority", 0.5)) + (3 - tier) * 0.03)
        tiers[id(inv)] = tier
    ranked.sort(key=lambda i: (tiers.get(id(i), 3), -float(getattr(i, "priority", 0))))
    # Focus boost already applied at set-time; re-apply cheaply for fresh candidates.
    area = getattr(focus, "focus_id", "") or getattr(focus, "focus_area", "all")
    if area and area != "all":
        specialists = _AREA_TO_SPECIALISTS.get(area, ())
        for inv in ranked:
            if inv.specialist in specialists:
                inv.priority = min(1.0, inv.priority + 0.02)
        ranked.sort(key=lambda i: (tiers.get(id(i), 3), -i.priority))
    prio = getattr(focus, "prioritize_investigation_id", "")
    if prio:
        ranked.sort(key=lambda i: (0 if i.id == prio else 1, tiers.get(id(i), 3), -i.priority))
    # Analyzed hypotheses win ties over blind sweeps within a tier.
    ranked.sort(key=lambda i: (tiers.get(id(i), 3),
                               0 if getattr(i, "hypothesis_id", "") else 1,
                               -float(getattr(i, "priority", 0))))
    return [i for i in ranked if i.state in (InvestigationState.READY, InvestigationState.PENDING)]


# Critical-first reservation tiers (lower runs first; recon last).
# Tier 0 is reserved for authentication-bypass/registration flow work only;
# broad auth/API sweeps sit with the other security work so hypothesis
# analyzed tests are not crowded out of small budgets.
_RESERVATION_TIER = {
    "auth_enforcement": 1,
    "api_security": 1,
    "authentication": 1,
    "bola_idor": 1,
    "idor_bola": 1,
    "authz_horizontal": 1,
    "authz_vertical": 1,
    "authorization": 1,
    "object_level_authorization": 1,
    "function_level_authorization": 1,
    "param_sqli": 1,
    "param_cmdi": 1,
    "param_traversal": 1,
    "param_ssrf": 1,
    "param_xss": 1,
    "injection": 1,
    "ssrf": 1,
    "file_upload": 1,
    "file_handling": 1,
    "graphql_authz": 1,
    "business_logic": 2,
    "input_validation": 2,
    "client_side_security": 2,
    "config_exposure": 1,
    "configuration": 1,
    "information_disclosure": 2,
    "graphql_introspection": 2,
    "workflow_state": 2,
    "workflow_tampering": 2,
    "service_exploit_intel": 3,
    "infrastructure": 3,
    "web_discovery": 3,
}
