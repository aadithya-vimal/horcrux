"""Investigation model and queue — targeted security investigations."""

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

from horcrux.intel.application_model import ApplicationModel, fingerprint
from horcrux.intel.hypotheses import Hypothesis, HypothesisClass, HypothesisStatus

if TYPE_CHECKING:
    from horcrux.models import WorkspaceState


class InvestigationState(str, Enum):
    PENDING = "PENDING"
    READY = "READY"
    RUNNING = "RUNNING"
    BLOCKED = "BLOCKED"
    SUPPORTED = "SUPPORTED"
    REFUTED = "REFUTED"
    COMPLETE = "COMPLETE"


class InvestigationScore(BaseModel):
    evidence_relevance: float = 0.5
    expected_information_gain: float = 0.5
    impact_potential: float = 0.5
    coverage_gap: float = 0.5
    prerequisites_satisfied: float = 1.0
    execution_cost: float = 0.3
    redundancy_penalty: float = 0.0

    @property
    def total(self) -> float:
        return (
            self.evidence_relevance * 0.2
            + self.expected_information_gain * 0.25
            + self.impact_potential * 0.2
            + self.coverage_gap * 0.15
            + self.prerequisites_satisfied * 0.1
            - self.execution_cost * 0.05
            - self.redundancy_penalty * 0.05
        )


class Investigation(BaseModel):
    id: str = ""
    objective: str = ""
    reason: str = ""
    evidence_refs: list[str] = Field(default_factory=list)
    vulnerability_classes: list[str] = Field(default_factory=list)
    required_capabilities: list[str] = Field(default_factory=list)
    candidate_tools: list[str] = Field(default_factory=list)
    prerequisites: list[str] = Field(default_factory=list)
    expected_information_gain: str = "medium"  # low, medium, high
    priority: float = 0.5
    state: InvestigationState = InvestigationState.PENDING
    hypothesis_id: str = ""
    specialist: str = ""
    score: InvestigationScore = Field(default_factory=InvestigationScore)
    result_summary: str = ""

    def ensure_id(self) -> str:
        if not self.id:
            self.id = fingerprint("inv", self.objective[:80], self.hypothesis_id)
        return self.id


HYPOTHESIS_TO_INVESTIGATIONS: dict[HypothesisClass, list[dict[str, Any]]] = {
    HypothesisClass.IDOR_BOLA: [
        {
            "objective": "Determine whether object IDs are authorization-bound",
            "capabilities": ["http", "proxy"],
            "tools": ["http_probe", "identity_switch"],
            "gain": "high",
            "specialist": "AuthorizationAgent",
            "impact": 0.9,
        },
        {
            "objective": "Map object ownership relationships across endpoints",
            "capabilities": ["http", "browser"],
            "tools": ["http_probe", "browser_navigate"],
            "gain": "high",
            "specialist": "AuthorizationAgent",
            "impact": 0.85,
        },
    ],
    HypothesisClass.PRIVILEGE_ESCALATION: [
        {
            "objective": "Test privileged endpoints as anonymous and authenticated user",
            "capabilities": ["http"],
            "tools": ["http_probe", "identity_switch"],
            "gain": "high",
            "specialist": "AuthorizationAgent",
            "impact": 0.9,
        },
    ],
    HypothesisClass.AUTHENTICATION: [
        {
            "objective": "Map authentication workflow and session lifecycle",
            "capabilities": ["http", "browser"],
            "tools": ["http_probe", "browser_navigate"],
            "gain": "high",
            "specialist": "AuthenticationAgent",
            "impact": 0.8,
        },
        {
            "objective": "Test authentication bypass and weak credential handling",
            "capabilities": ["http"],
            "tools": ["http_probe"],
            "gain": "medium",
            "specialist": "AuthenticationAgent",
            "impact": 0.75,
        },
    ],
    HypothesisClass.SESSION: [
        {
            "objective": "Analyze JWT/session token structure and validation",
            "capabilities": ["http"],
            "tools": ["http_probe", "jwt_analyze"],
            "gain": "high",
            "specialist": "AuthenticationAgent",
            "impact": 0.85,
        },
    ],
    HypothesisClass.SSRF: [
        {
            "objective": "Test server-side URL fetch behavior on URL parameters",
            "capabilities": ["http"],
            "tools": ["http_probe"],
            "gain": "high",
            "specialist": "WebAgent",
            "impact": 0.85,
        },
    ],
    HypothesisClass.INJECTION: [
        {
            "objective": "Test input validation on search and filter parameters",
            "capabilities": ["http"],
            "tools": ["http_probe", "param_fuzz"],
            "gain": "medium",
            "specialist": "WebAgent",
            "impact": 0.7,
        },
    ],
    HypothesisClass.GRAPHQL: [
        {
            "objective": "Test GraphQL introspection and authorization boundaries",
            "capabilities": ["http"],
            "tools": ["http_probe", "graphql_probe"],
            "gain": "high",
            "specialist": "APIAgent",
            "impact": 0.85,
        },
    ],
    HypothesisClass.FILE_UPLOAD: [
        {
            "objective": "Test file upload validation and storage constraints",
            "capabilities": ["http"],
            "tools": ["http_probe"],
            "gain": "high",
            "specialist": "WebAgent",
            "impact": 0.8,
        },
    ],
    HypothesisClass.BUSINESS_LOGIC: [
        {
            "objective": "Test workflow state skipping and inconsistent authorization",
            "capabilities": ["http", "browser"],
            "tools": ["http_probe", "browser_navigate"],
            "gain": "high",
            "specialist": "BusinessLogicAgent",
            "impact": 0.9,
        },
    ],
    HypothesisClass.INFORMATION_DISCLOSURE: [
        {
            "objective": "Review exposed endpoints for sensitive data leakage",
            "capabilities": ["http"],
            "tools": ["http_probe", "validator"],
            "gain": "medium",
            "specialist": "WebAgent",
            "impact": 0.6,
        },
    ],
}


def generate_investigations(
    app: ApplicationModel,
    hypotheses: list[Hypothesis],
    coverage_gaps: dict[str, str] | None = None,
) -> list[Investigation]:
    """Generate candidate investigations from hypotheses and application state."""
    coverage_gaps = coverage_gaps or {}
    investigations: list[Investigation] = []
    seen_objectives: set[str] = set()

    for hyp in hypotheses:
        if hyp.status in {HypothesisStatus.REFUTED, HypothesisStatus.CONFIRMED}:
            continue
        templates = HYPOTHESIS_TO_INVESTIGATIONS.get(hyp.hypothesis_class, [])
        for tmpl in templates:
            obj_key = tmpl["objective"].lower()
            if obj_key in seen_objectives:
                continue
            seen_objectives.add(obj_key)

            gap_key = _coverage_key_for_class(hyp.hypothesis_class)
            gap_score = 1.0 if coverage_gaps.get(gap_key, "NOT_REVIEWED") == "NOT_REVIEWED" else 0.4

            inv = Investigation(
                objective=tmpl["objective"],
                reason=f"Hypothesis: {hyp.title}",
                evidence_refs=hyp.evidence_refs[:8],
                vulnerability_classes=[hyp.hypothesis_class.value],
                required_capabilities=tmpl["capabilities"],
                candidate_tools=tmpl["tools"],
                expected_information_gain=tmpl["gain"],
                hypothesis_id=hyp.id,
                specialist=tmpl["specialist"],
                state=InvestigationState.READY,
                score=InvestigationScore(
                    evidence_relevance=min(1.0, 0.4 + len(hyp.evidence_refs) * 0.05),
                    expected_information_gain=0.9 if tmpl["gain"] == "high" else 0.6,
                    impact_potential=tmpl.get("impact", 0.7),
                    coverage_gap=gap_score,
                    prerequisites_satisfied=1.0,
                    execution_cost=0.2 if "browser" not in tmpl["capabilities"] else 0.5,
                ),
            )
            inv.priority = inv.score.total
            inv.ensure_id()
            investigations.append(inv)

    # Baseline investigations when app has structure but no hypotheses yet
    if app.endpoints and not investigations:
        investigations.append(
            Investigation(
                objective="Map API structure and authentication requirements",
                reason="Endpoints discovered but no targeted investigations generated yet",
                evidence_refs=[e.id for e in app.endpoints[:5]],
                vulnerability_classes=["api_security"],
                required_capabilities=["http"],
                candidate_tools=["http_probe"],
                expected_information_gain="high",
                specialist="APIAgent",
                state=InvestigationState.READY,
                score=InvestigationScore(
                    evidence_relevance=0.7,
                    expected_information_gain=0.85,
                    coverage_gap=0.9,
                ),
            )
        )

    if app.endpoints and not any(i.specialist == "WebAgent" for i in investigations):
        investigations.append(
            Investigation(
                objective="Complete functional application structure discovery",
                reason="Web endpoints exist; ensure routes, forms, and JS APIs are mapped",
                evidence_refs=[e.id for e in app.endpoints[:5]],
                vulnerability_classes=["information_disclosure"],
                required_capabilities=["http", "javascript"],
                candidate_tools=["js_analyzer", "http_probe"],
                expected_information_gain="high",
                specialist="WebAgent",
                state=InvestigationState.READY,
                score=InvestigationScore(
                    evidence_relevance=0.6,
                    expected_information_gain=0.8,
                    coverage_gap=0.85,
                ),
            )
        )

    return investigations


def _coverage_key_for_class(hyp_class: HypothesisClass) -> str:
    mapping = {
        HypothesisClass.IDOR_BOLA: "object_level_authorization",
        HypothesisClass.PRIVILEGE_ESCALATION: "function_level_authorization",
        HypothesisClass.AUTHENTICATION: "authentication",
        HypothesisClass.SESSION: "session_security",
        HypothesisClass.INJECTION: "injection",
        HypothesisClass.SSRF: "ssrf",
        HypothesisClass.FILE_UPLOAD: "file_handling",
        HypothesisClass.GRAPHQL: "api_security",
        HypothesisClass.BUSINESS_LOGIC: "business_logic",
        HypothesisClass.INFORMATION_DISCLOSURE: "information_disclosure",
    }
    return mapping.get(hyp_class, "input_validation")


def rank_investigations(investigations: list[Investigation]) -> list[Investigation]:
    """Rank investigations by information gain score."""
    for inv in investigations:
        inv.priority = inv.score.total
    return sorted(investigations, key=lambda i: -i.priority)


def merge_investigations(
    existing: list[Investigation],
    candidates: list[Investigation],
) -> list[Investigation]:
    """Deduplicate and preserve state of in-progress investigations."""
    lookup = {i.id: i for i in existing}
    merged: list[Investigation] = []
    for cand in candidates:
        if cand.id in lookup:
            old = lookup[cand.id]
            if old.state in {
                InvestigationState.RUNNING,
                InvestigationState.COMPLETE,
                InvestigationState.SUPPORTED,
                InvestigationState.REFUTED,
            }:
                merged.append(old)
            else:
                cand.state = old.state
                merged.append(cand)
        else:
            merged.append(cand)
    done_ids = {i.id for i in merged}
    for old in existing:
        if old.id not in done_ids and old.state in {
            InvestigationState.RUNNING,
            InvestigationState.COMPLETE,
        }:
            merged.append(old)
    return merged


def choose_highest_value_task(ranked: list[Investigation]) -> Investigation | None:
    """Select the highest-value actionable investigation."""
    for inv in ranked:
        if inv.state in {InvestigationState.READY, InvestigationState.PENDING}:
            return inv
    return None
