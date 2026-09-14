"""Investigation dependency graph + dependency-aware scheduling (Parts 16, 34).

Investigations declare prerequisites; the scheduler never schedules
impossible work and exposes blocked prerequisites in status. Independent
investigations may run concurrently (bounded workers); anything touching
shared mutable sessions, unresolved prerequisites, or destructive
implications stays serial.
"""

from __future__ import annotations

from typing import Any


def _has_two_identities(state: Any) -> tuple[bool, str]:
    try:
        labels = {i.label for i in state.get_application_model().identities}
        labels.discard("anonymous")
        if len(labels) >= 2:
            return True, ""
        return False, "requires two distinct non-anonymous identities"
    except Exception:
        return False, "identity state unavailable"


def _has_authenticated_session(state: Any) -> tuple[bool, str]:
    try:
        app = state.get_application_model()
        if app.sessions or any(i.role.value != "anonymous" for i in app.identities):
            return True, ""
        return False, "requires an authenticated session"
    except Exception:
        return False, "session state unavailable"


def _has_authenticated_api(state: Any) -> tuple[bool, str]:
    try:
        app = state.get_application_model()
        if app.authentication or any("login" in e.path.lower() for e in app.endpoints):
            return True, ""
        return False, "requires a discovered authentication surface"
    except Exception:
        return False, "auth state unavailable"


def _has_web_target(state: Any) -> tuple[bool, str]:
    try:
        if state.get_application_model().web_targets:
            return True, ""
        return False, "requires a web target"
    except Exception:
        return False, "web state unavailable"


def _has_workflow(state: Any) -> tuple[bool, str]:
    try:
        app = state.get_application_model()
        if app.workflows or getattr(app, "workflow_transitions", []):
            return True, ""
        return False, "requires workflow discovery first"
    except Exception:
        return False, "workflow state unavailable"


def _has_graphql(state: Any) -> tuple[bool, str]:
    try:
        app = state.get_application_model()
        if any("graphql" in e.path.lower() for e in app.endpoints) or \
                getattr(app, "graphql_operations", []):
            return True, ""
        return False, "requires a GraphQL surface"
    except Exception:
        return False, "graphql state unavailable"


def _has_upload(state: Any) -> tuple[bool, str]:
    try:
        app = state.get_application_model()
        if any("upload" in e.path.lower() for e in app.endpoints) or \
                any("upload" in f.action.lower() for f in app.forms):
            return True, ""
        return False, "requires a file-upload surface"
    except Exception:
        return False, "upload state unavailable"


def _has_objects(state: Any) -> tuple[bool, str]:
    try:
        if any(e.has_object_reference for e in state.get_application_model().endpoints):
            return True, ""
        return False, "requires object-bearing endpoints"
    except Exception:
        return False, "endpoint state unavailable"


PREREQUISITE_CHECKS = {
    "two_identities": _has_two_identities,
    "authenticated_session": _has_authenticated_session,
    "authenticated_api": _has_authenticated_api,
    "web_target": _has_web_target,
    "workflow_discovered": _has_workflow,
    "graphql_present": _has_graphql,
    "upload_surface": _has_upload,
    "object_endpoints": _has_objects,
    # Legacy aliases used by older templates/adapters.
    "web target": _has_web_target,
    "authentication_surface": _has_authenticated_api,
    "discovered_path": _has_objects,
}


def evaluate_prerequisites(state: Any, investigation: Any) -> tuple[bool, list[str]]:
    """Return (schedulable, [blocked reasons]). Unknown prereqs are ignored."""
    blocked: list[str] = []
    for prereq in investigation.prerequisites or []:
        check = PREREQUISITE_CHECKS.get(str(prereq).lower())
        if check is None:
            continue
        try:
            ok, reason = check(state)
        except Exception:
            ok, reason = False, f"prerequisite check failed: {prereq}"
        if not ok:
            blocked.append(reason or str(prereq))
    return (not blocked, blocked)


def apply_dependencies(state: Any, investigations: list) -> list:
    """Score prerequisites and mark impossible investigations BLOCKED (Part 16).

    BLOCKED here means 'waiting on prerequisites' — the investigation is
    refreshed on the next reassessment, so it unblocks automatically when
    evidence arrives.
    """
    from horcrux.intel.investigations import InvestigationState
    for inv in investigations:
        parked_blocked = (inv.state == InvestigationState.BLOCKED
                          and inv.result_summary.startswith("blocked prerequisite:"))
        if inv.state not in (InvestigationState.READY, InvestigationState.PENDING) \
                and not parked_blocked:
            continue
        schedulable, blocked = evaluate_prerequisites(state, inv)
        inv.score.prerequisites_satisfied = 1.0 if schedulable else 0.0
        inv.priority = inv.score.total
        if not blocked:
            if parked_blocked:
                inv.state = InvestigationState.READY
                inv.result_summary = ""
        else:
            inv.state = InvestigationState.BLOCKED
            inv.result_summary = "blocked prerequisite: " + "; ".join(blocked[:3])
    return investigations


# ---------------------------------------------------------------------------
# Dependency-aware parallel batching (Part 34)
# ---------------------------------------------------------------------------

SESSION_MUTATING_CAPABILITIES = {"identity_switch", "browser_automate"}


def select_parallel_batch(ranked: list, max_workers: int = 1) -> list:
    """Select a batch of investigations safe to execute concurrently.

    Rules: prerequisites satisfied (READY/PENDING only), disjoint endpoints
    (via hypothesis asset overlap heuristic), no session-mutating tools, no
    HIGH/FORBIDDEN safety implications (capability-level check happens at
    execution). Defaults to a single-item batch (sequential).
    """
    from horcrux.intel.investigations import InvestigationState
    actionable = [i for i in ranked
                  if i.state in (InvestigationState.READY, InvestigationState.PENDING)]
    if max_workers <= 1 or not actionable:
        return actionable[:1]
    batch: list = [actionable[0]]
    used_tools: set[str] = set(actionable[0].candidate_tools or [])
    used_hyps: set[str] = {actionable[0].hypothesis_id} if actionable[0].hypothesis_id else set()
    for inv in actionable[1:]:
        if len(batch) >= max_workers:
            break
        tools = set(inv.candidate_tools or [])
        if tools & SESSION_MUTATING_CAPABILITIES or used_tools & SESSION_MUTATING_CAPABILITIES:
            continue
        if inv.hypothesis_id and inv.hypothesis_id in used_hyps:
            continue  # same hypothesis -> shared mutable reasoning context
        batch.append(inv)
        used_tools |= tools
        if inv.hypothesis_id:
            used_hyps.add(inv.hypothesis_id)
    return batch
