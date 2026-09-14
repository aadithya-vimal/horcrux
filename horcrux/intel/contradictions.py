"""Contradiction engine (Phase 8, Part 21).

Systematically detects conflicting observations (status codes, auth
contexts, object visibility, workflow state), represents each contradiction
explicitly instead of silently picking one explanation, and spawns
resolution investigations for high-impact cases.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class Contradiction(BaseModel):
    id: str = ""
    kind: str = ""  # status_conflict, auth_conflict, visibility_conflict, workflow_conflict
    subject: str = ""
    observation_a: str = ""
    observation_b: str = ""
    possible_explanations: list[str] = Field(default_factory=list)
    impact: str = "medium"  # low, medium, high
    resolution_investigation_id: str = ""
    resolved: bool = False

    def ensure_id(self) -> str:
        if not self.id:
            from horcrux.intel.application_model import fingerprint
            self.id = fingerprint("contradiction", self.kind, self.subject)
        return self.id


EXPLANATIONS = {
    "status_conflict": ["session changed between observations",
                        "object created/deleted between observations",
                        "inconsistent authorization across identities",
                        "caching or CDN variance",
                        "different tenant/context",
                        "transient application state"],
    "auth_conflict": ["endpoint reachable anonymously but marked auth-required",
                      "role evaluated inconsistently",
                      "session fixation or replacement"],
    "visibility_conflict": ["object visible to one identity but not another",
                            "tenant isolation boundary",
                            "soft-delete vs hard-delete semantics"],
    "workflow_conflict": ["step reachable without prerequisite",
                          "state machine enforced client-side only",
                          "replay or double-submit accepted"],
}


def detect_contradictions(state: Any) -> list[Contradiction]:
    """Scan model state for conflicting observations."""
    from horcrux.intel.application_model import fingerprint
    found: list[Contradiction] = []
    try:
        app = state.get_application_model()
    except Exception:
        return found
    # Auth conflict: endpoint observed with anonymous AND requires-auth marker.
    for e in getattr(app, "endpoints", []):
        idents = set(e.observed_identities or [])
        if "anonymous" in idents and e.authentication == "required":
            found.append(Contradiction(
                kind="auth_conflict", subject=e.path,
                observation_a=f"{e.path} observed anonymously",
                observation_b=f"{e.path} marked authentication=required",
                possible_explanations=EXPLANATIONS["auth_conflict"],
                impact="high" if e.has_object_reference or "admin" in e.path.lower() else "medium"))
    # Status conflict: comparison evidence with divergent codes for same endpoint+identity.
    seen: dict[str, set] = {}
    for lc in getattr(app, "object_lifecycles", []):
        for note in lc.authorization_notes:
            if note.startswith("cross-identity-divergence"):
                found.append(Contradiction(
                    kind="visibility_conflict", subject=lc.object_type,
                    observation_a=f"{lc.object_type} objects differ across identities",
                    observation_b=note,
                    possible_explanations=EXPLANATIONS["visibility_conflict"],
                    impact="high"))
    # Workflow conflict: transition to a state whose precondition step is absent.
    for t in getattr(app, "workflow_transitions", []):
        if t.from_state != "START":
            steps = {s.name for wf in app.workflows for s in wf.steps}
            states = {x.from_state for x in getattr(app, "workflow_transitions", [])}
            states |= {x.to_state for x in getattr(app, "workflow_transitions", [])}
            if t.from_state not in steps and t.from_state not in states:
                found.append(Contradiction(
                    kind="workflow_conflict", subject=t.trigger or t.endpoint,
                    observation_a=f"transition from '{t.from_state}' observed",
                    observation_b="precondition state never observed",
                    possible_explanations=EXPLANATIONS["workflow_conflict"],
                    impact="medium"))
    for c in found:
        c.ensure_id()
    # Deduplicate.
    unique: dict[str, Contradiction] = {}
    for c in found:
        unique[c.id] = c
    return list(unique.values())


def propose_resolutions(state: Any, contradictions: list[Contradiction]) -> list[Any]:
    """Create resolution investigations for high-impact contradictions."""
    from horcrux.intel.investigations import (Investigation, InvestigationScore,
                                              InvestigationState)
    created: list[Any] = []
    existing = state.get_investigations()
    for c in contradictions:
        if c.impact != "high" or c.resolved:
            continue
        objective = f"Resolve conflicting observations on {c.subject}"
        inv = Investigation(
            objective=objective,
            reason=f"Contradiction ({c.kind}): {c.observation_a} vs {c.observation_b}",
            evidence_refs=[c.observation_a, c.observation_b],
            vulnerability_classes=["authorization"] if "auth" in c.kind or "visibility" in c.kind else ["business_logic"],
            required_capabilities=["http"],
            candidate_tools=["identity_compare", "authz_compare", "http_probe"],
            expected_information_gain="high",
            specialist="AuthorizationAgent" if "auth" in c.kind or "visibility" in c.kind else "BusinessLogicAgent",
            state=InvestigationState.READY,
            score=InvestigationScore(evidence_relevance=0.8,
                                     expected_information_gain=0.9,
                                     impact_potential=0.85, coverage_gap=0.8))
        inv.priority = inv.score.total
        inv.ensure_id()
        if not any(i.id == inv.id for i in existing):
            existing.append(inv)
            created.append(inv)
            c.resolution_investigation_id = inv.id
    if created:
        state.set_investigations(existing)
    return created
