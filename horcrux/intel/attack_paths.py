"""Attack path engine — builds paths from correlated evidence."""

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

from horcrux.intel.application_model import fingerprint

if TYPE_CHECKING:
    from horcrux.intel.hypotheses import Hypothesis
    from horcrux.models import Finding, WorkspaceState


class AttackNodeType(str, Enum):
    ASSET = "asset"
    SERVICE = "service"
    ENDPOINT = "endpoint"
    IDENTITY = "identity"
    ROLE = "role"
    OBJECT = "object"
    HYPOTHESIS = "hypothesis"
    FINDING = "finding"


class AttackEdgeType(str, Enum):
    EXPOSES = "exposes"
    AUTHENTICATES = "authenticates"
    AUTHORIZES = "authorizes"
    REFERENCES = "references"
    ENABLES = "enables"
    ESCALATES = "escalates"
    DEPENDS_ON = "depends_on"
    REACHES = "reaches"


class AttackNode(BaseModel):
    id: str
    node_type: AttackNodeType
    label: str
    ref_id: str = ""


class AttackEdge(BaseModel):
    source_id: str
    target_id: str
    edge_type: AttackEdgeType
    evidence: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.5, ge=0, le=1)
    validation_state: str = "unverified"


class AttackPath(BaseModel):
    id: str = ""
    name: str = ""
    nodes: list[AttackNode] = Field(default_factory=list)
    edges: list[AttackEdge] = Field(default_factory=list)
    probability: str = "MEDIUM"
    prerequisites: str = ""
    steps: list[str] = Field(default_factory=list)
    validation_state: str = "hypothetical"

    def ensure_id(self) -> str:
        if not self.id:
            self.id = fingerprint("attackpath", self.name)
        return self.id


def build_attack_paths(state: WorkspaceState) -> list[AttackPath]:
    """Build attack paths deterministically from application model and hypotheses."""
    app = state.get_application_model()
    hypotheses = state.get_hypotheses()
    findings = state.findings
    paths: list[AttackPath] = []

    # IDOR path
    idor_hyps = [h for h in hypotheses if h.hypothesis_class.value == "idor_bola" and h.status.value != "REFUTED"]
    object_eps = [e for e in app.endpoints if e.has_object_reference]
    if idor_hyps and object_eps:
        ep = object_eps[0]
        path = AttackPath(
            name=f"Object reference access via {ep.path}",
            probability="MEDIUM" if idor_hyps[0].status.value == "OPEN" else "HIGH",
            prerequisites="Authenticated user context with object ID",
            steps=[
                f"1. Authenticate as user (endpoint: {app.authentication[0].login_endpoint if app.authentication else 'login'})",
                f"2. Access object endpoint {ep.path} with controlled ID",
                "3. Attempt cross-user object access to validate authorization binding",
            ],
            nodes=[
                AttackNode(id="identity:user", node_type=AttackNodeType.IDENTITY, label="Authenticated User"),
                AttackNode(id=ep.id, node_type=AttackNodeType.ENDPOINT, label=ep.path, ref_id=ep.id),
                AttackNode(id=idor_hyps[0].id, node_type=AttackNodeType.HYPOTHESIS, label=idor_hyps[0].title),
            ],
            edges=[
                AttackEdge(
                    source_id="identity:user",
                    target_id=ep.id,
                    edge_type=AttackEdgeType.AUTHENTICATES,
                    evidence=ep.evidence_refs[:3],
                    confidence=0.6,
                ),
                AttackEdge(
                    source_id=ep.id,
                    target_id=idor_hyps[0].id,
                    edge_type=AttackEdgeType.REFERENCES,
                    evidence=idor_hyps[0].evidence_refs[:3],
                    confidence=idor_hyps[0].confidence,
                ),
            ],
        )
        path.ensure_id()
        paths.append(path)

    # Privileged endpoint path
    admin_eps = [e for e in app.endpoints if "admin" in e.path.lower()]
    priv_hyps = [h for h in hypotheses if h.hypothesis_class.value == "privilege_escalation"]
    if admin_eps:
        ep = admin_eps[0]
        hyp = priv_hyps[0] if priv_hyps else None
        path = AttackPath(
            name=f"Privileged function access via {ep.path}",
            probability="MEDIUM",
            prerequisites="Network access to web service",
            steps=[
                f"1. Request {ep.path} as anonymous user",
                "2. Request same endpoint as authenticated low-privilege user",
                "3. Compare responses for authorization enforcement gaps",
            ],
            nodes=[
                AttackNode(id="identity:anonymous", node_type=AttackNodeType.IDENTITY, label="Anonymous"),
                AttackNode(id=ep.id, node_type=AttackNodeType.ENDPOINT, label=ep.path),
            ],
            edges=[
                AttackEdge(
                    source_id="identity:anonymous",
                    target_id=ep.id,
                    edge_type=AttackEdgeType.EXPOSES,
                    evidence=ep.evidence_refs[:3],
                    confidence=0.55,
                ),
            ],
        )
        if hyp:
            path.nodes.append(AttackNode(id=hyp.id, node_type=AttackNodeType.HYPOTHESIS, label=hyp.title))
            path.edges.append(
                AttackEdge(
                    source_id=ep.id,
                    target_id=hyp.id,
                    edge_type=AttackEdgeType.ENABLES,
                    confidence=hyp.confidence,
                )
            )
        path.ensure_id()
        paths.append(path)

    # Confirmed finding paths
    for finding in findings:
        if finding.validation_state.value in {"confirmed", "likely"}:
            path = AttackPath(
                name=f"Confirmed: {finding.title[:60]}",
                probability="HIGH",
                prerequisites=finding.reproduction[0] if finding.reproduction else "See evidence",
                steps=finding.reproduction or [finding.title],
                validation_state="confirmed",
                nodes=[
                    AttackNode(id=finding.id, node_type=AttackNodeType.FINDING, label=finding.title, ref_id=finding.id),
                ],
            )
            path.ensure_id()
            paths.append(path)

    return paths


def attack_paths_to_dict(paths: list[AttackPath]) -> list[dict[str, Any]]:
    return [p.model_dump() for p in paths]
