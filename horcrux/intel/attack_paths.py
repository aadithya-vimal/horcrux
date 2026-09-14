"""Attack path engine — evidence-backed graphs, not flat lists (Phase 8, P13/P14)."""

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
    # --- Phase 8 graph nodes ---
    VULNERABILITY = "vulnerability"
    WORKFLOW_STATE = "workflow_state"
    PRIVILEGE = "privilege"
    CAPABILITY = "capability"
    TRUST_BOUNDARY = "trust_boundary"


class AttackEdgeType(str, Enum):
    EXPOSES = "exposes"
    AUTHENTICATES = "authenticates"
    AUTHORIZES = "authorizes"
    REFERENCES = "references"
    ENABLES = "enables"
    ESCALATES = "escalates"
    DEPENDS_ON = "depends_on"
    REACHES = "reaches"
    # --- Phase 8 graph edges ---
    PRODUCES = "produces"
    GRANTS = "grants"
    ACCESSES = "accesses"
    TRANSITIONS_TO = "transitions_to"


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
    # --- Phase 8: inference must be explicit when evidence is absent ---
    inference: bool = False
    rationale: str = ""


class AttackPath(BaseModel):
    id: str = ""
    name: str = ""
    nodes: list[AttackNode] = Field(default_factory=list)
    edges: list[AttackEdge] = Field(default_factory=list)
    probability: str = "MEDIUM"
    prerequisites: str = ""
    steps: list[str] = Field(default_factory=list)
    validation_state: str = "hypothetical"
    # --- Phase 8 ranking support ---
    confidence: float = Field(default=0.5, ge=0, le=1)
    uncertain_edges: int = 0
    assumptions: list[str] = Field(default_factory=list)
    rank_score: float = 0.0
    rank_why: str = ""

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
            hyp_ev = list(hyp.evidence_refs[:3])
            path.edges.append(
                AttackEdge(
                    source_id=ep.id,
                    target_id=hyp.id,
                    edge_type=AttackEdgeType.ENABLES,
                    evidence=hyp_ev,
                    confidence=hyp.confidence,
                    inference=not hyp_ev,
                    rationale="" if hyp_ev else "privilege link inferred; needs validation",
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

    # Workflow-state path: identity -> workflow states -> privileged transition.
    wf_transitions = getattr(app, "workflow_transitions", [])
    state_changing = [t for t in wf_transitions if t.state_changing]
    if state_changing:
        tr = state_changing[0]
        wpath = AttackPath(
            name=f"Workflow abuse via {tr.endpoint or tr.workflow}",
            probability="MEDIUM",
            prerequisites=f"Reach workflow state '{tr.from_state}'",
            steps=[
                f"1. Reach state '{tr.from_state}' in {tr.workflow}",
                f"2. Trigger transition '{tr.trigger}'",
                f"3. Verify postconditions for '{tr.to_state}'",
            ],
            nodes=[
                AttackNode(id="identity:user", node_type=AttackNodeType.IDENTITY, label="Authenticated User"),
                AttackNode(id=f"wfstate:{tr.from_state}", node_type=AttackNodeType.WORKFLOW_STATE, label=tr.from_state),
                AttackNode(id=f"wfstate:{tr.to_state}", node_type=AttackNodeType.WORKFLOW_STATE, label=tr.to_state),
                AttackNode(id=tr.id, node_type=AttackNodeType.CAPABILITY, label=tr.trigger or tr.endpoint, ref_id=tr.id),
            ],
            edges=[
                AttackEdge(source_id="identity:user", target_id=f"wfstate:{tr.from_state}",
                           edge_type=AttackEdgeType.REACHES, evidence=tr.evidence_refs[:3], confidence=0.6),
                AttackEdge(source_id=f"wfstate:{tr.from_state}", target_id=f"wfstate:{tr.to_state}",
                           edge_type=AttackEdgeType.TRANSITIONS_TO, evidence=tr.evidence_refs[:3],
                           confidence=0.55, inference=not bool(tr.evidence_refs),
                           rationale="" if tr.evidence_refs else "transition inferred from endpoint naming"),
            ],
        )
        wpath.ensure_id()
        paths.append(wpath)

    # Multi-step chain: object lifecycle read -> mutation -> privilege.
    lifecycles = getattr(app, "object_lifecycles", [])
    for lc in lifecycles[:3]:
        if lc.read_endpoints and (lc.mutation_endpoints or lc.delete_endpoints):
            target_ep = (lc.mutation_endpoints or lc.delete_endpoints)[0]
            chain = AttackPath(
                name=f"Object lifecycle abuse: {lc.object_type}",
                probability="MEDIUM",
                prerequisites="Authenticated identity with object reference",
                steps=[
                    f"1. Read {lc.object_type} via {lc.read_endpoints[0]}",
                    f"2. Mutate via {target_ep}",
                    "3. Verify cross-identity effect and privilege impact",
                ],
                nodes=[
                    AttackNode(id="identity:user", node_type=AttackNodeType.IDENTITY, label="Authenticated User"),
                    AttackNode(id=f"object:{lc.object_type}", node_type=AttackNodeType.OBJECT, label=lc.object_type, ref_id=lc.id),
                    AttackNode(id=f"ep:{target_ep}", node_type=AttackNodeType.ENDPOINT, label=target_ep),
                    AttackNode(id="boundary:authz", node_type=AttackNodeType.TRUST_BOUNDARY, label="Authorization boundary"),
                ],
                edges=[
                    AttackEdge(source_id="identity:user", target_id=f"object:{lc.object_type}",
                               edge_type=AttackEdgeType.ACCESSES, evidence=lc.evidence_refs[:3], confidence=0.65),
                    AttackEdge(source_id=f"object:{lc.object_type}", target_id=f"ep:{target_ep}",
                               edge_type=AttackEdgeType.PRODUCES, evidence=lc.evidence_refs[:3], confidence=0.55,
                               inference=True, rationale="mutation effect requires validation"),
                ],
            )
            chain.ensure_id()
            paths.append(chain)

    # GraphQL operation path.
    gql_ops = getattr(app, "graphql_operations", [])
    if gql_ops:
        op = gql_ops[0]
        gpath = AttackPath(
            name=f"GraphQL abuse via {op.kind} {op.name}",
            probability="MEDIUM",
            prerequisites="GraphQL endpoint reachable",
            steps=[
                f"1. Introspect schema at {op.endpoint}",
                f"2. Exercise {op.kind} {op.name} across identities",
                "3. Compare field-level authorization",
            ],
            nodes=[
                AttackNode(id=f"ep:{op.endpoint}", node_type=AttackNodeType.ENDPOINT, label=op.endpoint),
                AttackNode(id=op.id, node_type=AttackNodeType.CAPABILITY, label=f"{op.kind} {op.name}", ref_id=op.id),
                AttackNode(id="boundary:authz", node_type=AttackNodeType.TRUST_BOUNDARY, label="Authorization boundary"),
            ],
            edges=[
                AttackEdge(source_id=f"ep:{op.endpoint}", target_id=op.id,
                           edge_type=AttackEdgeType.EXPOSES, evidence=op.evidence_refs[:3], confidence=0.6),
                AttackEdge(source_id=op.id, target_id="boundary:authz",
                           edge_type=AttackEdgeType.ENABLES, evidence=[], confidence=0.4,
                           inference=True, rationale="field authorization not yet validated"),
            ],
        )
        gpath.ensure_id()
        paths.append(gpath)

    _finalize_paths(paths)
    return rank_attack_paths(paths)


def _finalize_paths(paths: list[AttackPath]) -> None:
    """Mark uncertainty explicitly; unsupported paths never look confirmed."""
    for p in paths:
        uncertain = sum(1 for e in p.edges if e.inference or not e.evidence)
        p.uncertain_edges = uncertain
        if p.validation_state != "confirmed" and uncertain >= 2:
            p.probability = "LOW"
        ev_confs = [e.confidence for e in p.edges] or [0.5]
        p.confidence = round(sum(ev_confs) / len(ev_confs), 3)
        if p.validation_state != "confirmed":
            p.assumptions = [e.rationale for e in p.edges if e.inference and e.rationale][:4]


def rank_attack_paths(paths: list[AttackPath]) -> list[AttackPath]:
    """Prioritize by evidence strength, impact, exploitability, prerequisites,
    uncertain edges, coverage relevance, and investigation cost (Part 14)."""
    for p in paths:
        score = 0.0
        why: list[str] = []
        # Evidence strength: mean edge confidence weighted by evidenced ratio.
        ev_edges = [e for e in p.edges if e.evidence and not e.inference]
        ratio = (len(ev_edges) / len(p.edges)) if p.edges else 1.0
        score += p.confidence * 0.3
        why.append(f"evidence {p.confidence:.2f}x{ratio:.0%}")
        # Impact: confirmed findings / privilege nodes score highest.
        kinds = {n.node_type for n in p.nodes}
        if any(n.node_type == AttackNodeType.FINDING for n in p.nodes) \
                and p.validation_state == "confirmed":
            score += 0.3
            why.append("confirmed finding")
        elif AttackNodeType.PRIVILEGE in kinds or "admin" in p.name.lower():
            score += 0.2
            why.append("privilege impact")
        elif AttackNodeType.OBJECT in kinds or AttackNodeType.WORKFLOW_STATE in kinds:
            score += 0.15
            why.append("object/workflow impact")
        # Exploitability: fewer prerequisites is better.
        prereq_count = len([s for s in p.prerequisites.split(",") if s.strip()]) if p.prerequisites else 1
        score += max(0.0, 0.1 - 0.02 * prereq_count)
        # Uncertain edges penalized: 3+ unsupported assumptions rank below evidence.
        score -= min(0.3, 0.1 * p.uncertain_edges)
        if p.uncertain_edges >= 3:
            why.append(f"{p.uncertain_edges} unsupported assumptions")
        # Investigation cost: shorter paths are cheaper to validate.
        score -= min(0.1, 0.01 * len(p.nodes))
        p.rank_score = round(score, 3)
        p.rank_why = "; ".join(why) or "baseline"
    return sorted(paths, key=lambda p: -p.rank_score)


def attack_paths_to_dict(paths: list[AttackPath]) -> list[dict[str, Any]]:
    return [p.model_dump() for p in paths]
