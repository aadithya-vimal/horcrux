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
    # Traceability: every node links back to hypothesis / investigation /
    # evidence / finding records. Empty finding_id means NOT confirmed.
    status: str = ""
    hypothesis_id: str = ""
    investigation_ids: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    finding_id: str = ""


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
    # Security evidence ONLY when derived from validator/adjudication
    # output (SUPPORTED investigation/hypothesis or confirmed finding).
    # Discovery observations (endpoint/route refs) are never security
    # evidence, even when present.
    security_evidence: bool = False


# Canonical path status vocabulary. HYPOTHESIS means "worth testing, not
# validated". CONFIRMED requires a canonical finding_id.
PATH_STATUS_HYPOTHESIS = "HYPOTHESIS"
PATH_STATUS_SUPPORTED = "SUPPORTED"
PATH_STATUS_REFUTED = "REFUTED"
PATH_STATUS_INSUFFICIENT = "INSUFFICIENT_EVIDENCE"
PATH_STATUS_BLOCKED = "BLOCKED"
PATH_STATUS_CONFIRMED = "CONFIRMED"

# Investigation terminals that mean "blocked, not validated".
_BLOCKED_TERMINALS = frozenset({
    "BLOCKED", "SCOPE_BLOCKED", "UNAVAILABLE", "APPROVAL_REQUIRED",
    "REQUIRES_AUTH", "REQUIRES_SECOND_IDENTITY", "REQUIRES_TOOL",
    "REQUIRES_OPERATOR", "NOT_APPLICABLE", "OUT_OF_SCOPE", "FAILED",
})


class AttackPath(BaseModel):
    id: str = ""
    name: str = ""
    nodes: list[AttackNode] = Field(default_factory=list)
    edges: list[AttackEdge] = Field(default_factory=list)
    probability: str = "MEDIUM"
    prerequisites: str = ""
    steps: list[str] = Field(default_factory=list)
    validation_state: str = "hypothetical"
    # Canonical adjudication status. CONFIRMED requires finding_ids.
    status: str = PATH_STATUS_HYPOTHESIS
    finding_ids: list[str] = Field(default_factory=list)
    hypothesis_id: str = ""
    investigation_ids: list[str] = Field(default_factory=list)
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


def _norm_asset(path: str) -> str:
    p = (path or "").strip().lower()
    if "://" in p:
        try:
            from urllib.parse import urlparse as _urlparse
            p = _urlparse(p).path or "/"
        except Exception:
            p = "/"
    if not p.startswith("/"):
        p = "/" + p
    return p or "/"


def _validation_ledger(state: WorkspaceState) -> dict[str, Any]:
    """Authoritative adjudication facts for graph labeling.

    - finding_by_asset: normalized asset -> finding id (CONFIRMED only).
    - inv_terminals_by_asset: normalized asset -> [(inv id, terminal)].
    - hyp_status: hypothesis id -> status string.
    """
    finding_by_asset: dict[str, str] = {}
    for f in (state.findings or []):
        try:
            vs = f.validation_state.value
        except Exception:
            vs = str(f.validation_state)
        if vs not in ("CONFIRMED", "confirmed"):
            continue
        finding_by_asset[_norm_asset(f.affected_asset or f.target or "")] = f.id
    try:
        app = state.get_application_model()
        ep_path_by_id = {e.id: e.path for e in app.endpoints}
    except Exception:
        ep_path_by_id = {}
    invs_by_asset: dict[str, list[tuple[str, str]]] = {}
    try:
        investigations = state.get_investigations()
    except Exception:
        investigations = []
    for inv in investigations:
        terminal = inv.state.value if hasattr(inv.state, "value") else str(inv.state)
        assets: set[str] = set()
        for obs in getattr(inv, "observations", []) or []:
            if str(obs).startswith("matrix_asset:"):
                val = str(obs).split(":", 1)[1]
                if val:
                    assets.add(_norm_asset(val))
        hyp_id = getattr(inv, "hypothesis_id", "") or ""
        if hyp_id:
            assets.add(f"hyp:{hyp_id}")
        for asset in assets:
            invs_by_asset.setdefault(asset, []).append((inv.id, terminal))
        # Hypothesis asset refs (endpoint ids) also bind the investigation.
        try:
            for h in state.get_hypotheses():
                if h.id == hyp_id and getattr(h, "asset_refs", None):
                    for ref in h.asset_refs:
                        if ref in ep_path_by_id:
                            invs_by_asset.setdefault(
                                _norm_asset(ep_path_by_id[ref]), []).append((inv.id, terminal))
        except Exception:
            pass
    hyp_status: dict[str, str] = {}
    try:
        for h in state.get_hypotheses():
            hyp_status[h.id] = h.status.value if hasattr(h.status, "value") else str(h.status)
    except Exception:
        pass
    return {"findings": finding_by_asset, "invs": invs_by_asset, "hyps": hyp_status}


def _resolve_status(hyp_status: str, inv_terminals: list[str],
                    finding_id: str) -> str:
    """Strongest adjudication fact wins; CONFIRMED needs a finding."""
    if finding_id:
        return PATH_STATUS_CONFIRMED
    terms = set(inv_terminals or [])
    if "SUPPORTED" in terms:
        return PATH_STATUS_SUPPORTED
    if "REFUTED" in terms:
        return PATH_STATUS_REFUTED
    if "INSUFFICIENT_EVIDENCE" in terms:
        return PATH_STATUS_INSUFFICIENT
    if terms & set(_BLOCKED_TERMINALS):
        return PATH_STATUS_BLOCKED
    if (hyp_status or "") == "SUPPORTED":
        return PATH_STATUS_SUPPORTED
    if (hyp_status or "") == "REFUTED":
        return PATH_STATUS_REFUTED
    return PATH_STATUS_HYPOTHESIS


def build_attack_paths(state: WorkspaceState) -> list[AttackPath]:
    """Build attack paths deterministically from application model and hypotheses.

    Status semantics: HYPOTHESIS (worth testing) vs SUPPORTED / REFUTED /
    INSUFFICIENT_EVIDENCE / BLOCKED (adjudicated) vs CONFIRMED (canonical
    finding linked). Discovery observations are never security evidence.
    """
    app = state.get_application_model()
    hypotheses = state.get_hypotheses()
    findings = state.findings
    ledger = _validation_ledger(state)
    paths: list[AttackPath] = []

    def _asset_context(asset_path: str, hyp_id: str = "") -> dict[str, Any]:
        norm = _norm_asset(asset_path)
        invs = list(ledger["invs"].get(norm, []))
        if hyp_id:
            invs += [t for t in ledger["invs"].get(f"hyp:{hyp_id}", []) if t not in invs]
        finding_id = ledger["findings"].get(norm, "")
        status = _resolve_status(ledger["hyps"].get(hyp_id, ""),
                                 [t for _, t in invs], finding_id)
        return {"finding_id": finding_id, "status": status,
                "inv_ids": [i for i, _ in invs], "hyp_status": ledger["hyps"].get(hyp_id, "")}

    # IDOR path (historical paths kept: REFUTED stays visible as rejected,
    # never as confirmed).
    idor_hyps = [h for h in hypotheses if h.hypothesis_class.value == "idor_bola"]
    object_eps = [e for e in app.endpoints if e.has_object_reference]
    if idor_hyps and object_eps:
        ep = object_eps[0]
        hyp = idor_hyps[0]
        actx = _asset_context(ep.path, hyp.id)
        sec = actx["status"] in (PATH_STATUS_SUPPORTED, PATH_STATUS_CONFIRMED)
        path = AttackPath(
            name=f"Object reference access via {ep.path}",
            probability="HIGH" if actx["status"] == PATH_STATUS_CONFIRMED else "MEDIUM",
            prerequisites="Authenticated user context with object ID",
            status=actx["status"],
            finding_ids=[actx["finding_id"]] if actx["finding_id"] else [],
            hypothesis_id=hyp.id,
            investigation_ids=actx["inv_ids"],
            steps=[
                f"1. Authenticate as user (endpoint: {app.authentication[0].login_endpoint if app.authentication else 'login'})",
                f"2. Access object endpoint {ep.path} with controlled ID",
                "3. Attempt cross-user object access to validate authorization binding",
            ],
            nodes=[
                AttackNode(id="identity:user", node_type=AttackNodeType.IDENTITY, label="Authenticated User"),
                AttackNode(id=ep.id, node_type=AttackNodeType.ENDPOINT, label=ep.path, ref_id=ep.id,
                           status=actx["status"], investigation_ids=actx["inv_ids"],
                           finding_id=actx["finding_id"]),
                AttackNode(id=hyp.id, node_type=AttackNodeType.HYPOTHESIS, label=hyp.title,
                           status=actx["hyp_status"] or PATH_STATUS_HYPOTHESIS,
                           hypothesis_id=hyp.id, investigation_ids=actx["inv_ids"],
                           finding_id=actx["finding_id"]),
            ],
            edges=[
                AttackEdge(
                    source_id="identity:user",
                    target_id=ep.id,
                    edge_type=AttackEdgeType.AUTHENTICATES,
                    evidence=ep.evidence_refs[:3],
                    confidence=0.6,
                    security_evidence=False,
                ),
                AttackEdge(
                    source_id=ep.id,
                    target_id=hyp.id,
                    edge_type=AttackEdgeType.REFERENCES,
                    evidence=hyp.evidence_refs[:3],
                    confidence=hyp.confidence,
                    security_evidence=sec and bool(hyp.evidence_refs),
                    inference=not hyp.evidence_refs,
                    rationale="" if hyp.evidence_refs else "hypothesis not yet validated",
                ),
            ],
        )
        path.ensure_id()
        paths.append(path)

    # Privileged endpoint path. Without validation this is a HYPOTHESIS:
    # endpoint observation is not authorization evidence.
    admin_eps = [e for e in app.endpoints if "admin" in e.path.lower()]
    priv_hyps = [h for h in hypotheses if h.hypothesis_class.value == "privilege_escalation"]
    if admin_eps:
        ep = admin_eps[0]
        hyp = priv_hyps[0] if priv_hyps else None
        actx = _asset_context(ep.path, hyp.id if hyp else "")
        sec = actx["status"] in (PATH_STATUS_SUPPORTED, PATH_STATUS_CONFIRMED)
        path = AttackPath(
            name=f"Privileged function access via {ep.path}",
            probability="HIGH" if actx["status"] == PATH_STATUS_CONFIRMED else "MEDIUM",
            prerequisites="Network access to web service",
            status=actx["status"],
            finding_ids=[actx["finding_id"]] if actx["finding_id"] else [],
            hypothesis_id=hyp.id if hyp else "",
            investigation_ids=actx["inv_ids"],
            steps=[
                f"1. Request {ep.path} as anonymous user",
                "2. Request same endpoint as authenticated low-privilege user",
                "3. Compare responses for authorization enforcement gaps",
            ],
            nodes=[
                AttackNode(id="identity:anonymous", node_type=AttackNodeType.IDENTITY, label="Anonymous"),
                AttackNode(id=ep.id, node_type=AttackNodeType.ENDPOINT, label=ep.path,
                           status=actx["status"], investigation_ids=actx["inv_ids"],
                           finding_id=actx["finding_id"]),
            ],
            edges=[
                AttackEdge(
                    source_id="identity:anonymous",
                    target_id=ep.id,
                    edge_type=AttackEdgeType.EXPOSES,
                    evidence=ep.evidence_refs[:3],
                    confidence=0.55,
                    security_evidence=False,
                ),
            ],
        )
        if hyp:
            hyp_ev = list(hyp.evidence_refs[:3])
            path.nodes.append(AttackNode(id=hyp.id, node_type=AttackNodeType.HYPOTHESIS, label=hyp.title,
                                         status=actx["hyp_status"] or PATH_STATUS_HYPOTHESIS,
                                         hypothesis_id=hyp.id, investigation_ids=actx["inv_ids"],
                                         finding_id=actx["finding_id"]))
            path.edges.append(
                AttackEdge(
                    source_id=ep.id,
                    target_id=hyp.id,
                    edge_type=AttackEdgeType.ENABLES,
                    evidence=hyp_ev,
                    confidence=hyp.confidence,
                    security_evidence=sec and bool(hyp_ev),
                    inference=not hyp_ev,
                    rationale="" if hyp_ev else "privilege link inferred; needs validation",
                )
            )
        path.ensure_id()
        paths.append(path)

    # Confirmed finding paths
    for finding in findings:
        try:
            fvs = finding.validation_state.value
        except Exception:
            fvs = str(finding.validation_state)
        if str(fvs).lower() in {"confirmed", "likely"}:
            path = AttackPath(
                name=f"Confirmed: {finding.title[:60]}",
                probability="HIGH",
                prerequisites=finding.reproduction[0] if finding.reproduction else "See evidence",
                steps=finding.reproduction or [finding.title],
                validation_state="confirmed",
                status=PATH_STATUS_CONFIRMED,
                finding_ids=[finding.id],
                hypothesis_id=finding.hypothesis_id,
                investigation_ids=[finding.investigation_id] if finding.investigation_id else [],
                nodes=[
                    AttackNode(id=finding.id, node_type=AttackNodeType.FINDING, label=finding.title, ref_id=finding.id,
                               status=PATH_STATUS_CONFIRMED, hypothesis_id=finding.hypothesis_id,
                               investigation_ids=[finding.investigation_id] if finding.investigation_id else [],
                               finding_id=finding.id),
                ],
                edges=[],
            )
            path.ensure_id()
            paths.append(path)

    # Workflow-state path: identity -> workflow states -> privileged transition.
    wf_transitions = getattr(app, "workflow_transitions", [])
    state_changing = [t for t in wf_transitions if t.state_changing]
    if state_changing:
        tr = state_changing[0]
        wactx = _asset_context(tr.endpoint or "", "")
        wpath = AttackPath(
            name=f"Workflow abuse via {tr.endpoint or tr.workflow}",
            probability="HIGH" if wactx["status"] == PATH_STATUS_CONFIRMED else "MEDIUM",
            prerequisites=f"Reach workflow state '{tr.from_state}'",
            status=wactx["status"],
            finding_ids=[wactx["finding_id"]] if wactx["finding_id"] else [],
            investigation_ids=wactx["inv_ids"],
            steps=[
                f"1. Reach state '{tr.from_state}' in {tr.workflow}",
                f"2. Trigger transition '{tr.trigger}'",
                f"3. Verify postconditions for '{tr.to_state}'",
            ],
            nodes=[
                AttackNode(id="identity:user", node_type=AttackNodeType.IDENTITY, label="Authenticated User"),
                AttackNode(id=f"wfstate:{tr.from_state}", node_type=AttackNodeType.WORKFLOW_STATE, label=tr.from_state,
                           status=wactx["status"], investigation_ids=wactx["inv_ids"],
                           finding_id=wactx["finding_id"]),
                AttackNode(id=f"wfstate:{tr.to_state}", node_type=AttackNodeType.WORKFLOW_STATE, label=tr.to_state,
                           status=wactx["status"], investigation_ids=wactx["inv_ids"],
                           finding_id=wactx["finding_id"]),
                AttackNode(id=tr.id, node_type=AttackNodeType.CAPABILITY, label=tr.trigger or tr.endpoint, ref_id=tr.id,
                           status=wactx["status"], investigation_ids=wactx["inv_ids"]),
            ],
            edges=[
                AttackEdge(source_id="identity:user", target_id=f"wfstate:{tr.from_state}",
                           edge_type=AttackEdgeType.REACHES, evidence=tr.evidence_refs[:3], confidence=0.6,
                           security_evidence=False),
                AttackEdge(source_id=f"wfstate:{tr.from_state}", target_id=f"wfstate:{tr.to_state}",
                           edge_type=AttackEdgeType.TRANSITIONS_TO, evidence=tr.evidence_refs[:3],
                           confidence=0.55, inference=not bool(tr.evidence_refs),
                           security_evidence=False,
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
            lactx = _asset_context(target_ep, "")
            chain = AttackPath(
                name=f"Object lifecycle abuse: {lc.object_type}",
                probability="HIGH" if lactx["status"] == PATH_STATUS_CONFIRMED else "MEDIUM",
                prerequisites="Authenticated identity with object reference",
                status=lactx["status"],
                finding_ids=[lactx["finding_id"]] if lactx["finding_id"] else [],
                investigation_ids=lactx["inv_ids"],
                steps=[
                    f"1. Read {lc.object_type} via {lc.read_endpoints[0]}",
                    f"2. Mutate via {target_ep}",
                    "3. Verify cross-identity effect and privilege impact",
                ],
                nodes=[
                    AttackNode(id="identity:user", node_type=AttackNodeType.IDENTITY, label="Authenticated User"),
                    AttackNode(id=f"object:{lc.object_type}", node_type=AttackNodeType.OBJECT, label=lc.object_type, ref_id=lc.id,
                               status=lactx["status"], investigation_ids=lactx["inv_ids"],
                               finding_id=lactx["finding_id"]),
                    AttackNode(id=f"ep:{target_ep}", node_type=AttackNodeType.ENDPOINT, label=target_ep,
                               status=lactx["status"], investigation_ids=lactx["inv_ids"],
                               finding_id=lactx["finding_id"]),
                    AttackNode(id="boundary:authz", node_type=AttackNodeType.TRUST_BOUNDARY, label="Authorization boundary"),
                ],
                edges=[
                    AttackEdge(source_id="identity:user", target_id=f"object:{lc.object_type}",
                               edge_type=AttackEdgeType.ACCESSES, evidence=lc.evidence_refs[:3], confidence=0.65,
                               security_evidence=False),
                    AttackEdge(source_id=f"object:{lc.object_type}", target_id=f"ep:{target_ep}",
                               edge_type=AttackEdgeType.PRODUCES, evidence=lc.evidence_refs[:3], confidence=0.55,
                               security_evidence=False,
                               inference=True, rationale="mutation effect requires validation"),
                ],
            )
            chain.ensure_id()
            paths.append(chain)

    # GraphQL operation path.
    gql_ops = getattr(app, "graphql_operations", [])
    if gql_ops:
        op = gql_ops[0]
        gactx = _asset_context(op.endpoint, "")
        gpath = AttackPath(
            name=f"GraphQL abuse via {op.kind} {op.name}",
            probability="HIGH" if gactx["status"] == PATH_STATUS_CONFIRMED else "MEDIUM",
            prerequisites="GraphQL endpoint reachable",
            status=gactx["status"],
            finding_ids=[gactx["finding_id"]] if gactx["finding_id"] else [],
            investigation_ids=gactx["inv_ids"],
            steps=[
                f"1. Introspect schema at {op.endpoint}",
                f"2. Exercise {op.kind} {op.name} across identities",
                "3. Compare field-level authorization",
            ],
            nodes=[
                AttackNode(id=f"ep:{op.endpoint}", node_type=AttackNodeType.ENDPOINT, label=op.endpoint,
                           status=gactx["status"], investigation_ids=gactx["inv_ids"],
                           finding_id=gactx["finding_id"]),
                AttackNode(id=op.id, node_type=AttackNodeType.CAPABILITY, label=f"{op.kind} {op.name}", ref_id=op.id,
                           status=gactx["status"], investigation_ids=gactx["inv_ids"]),
                AttackNode(id="boundary:authz", node_type=AttackNodeType.TRUST_BOUNDARY, label="Authorization boundary"),
            ],
            edges=[
                AttackEdge(source_id=f"ep:{op.endpoint}", target_id=op.id,
                           edge_type=AttackEdgeType.EXPOSES, evidence=op.evidence_refs[:3], confidence=0.6,
                           security_evidence=False),
                AttackEdge(source_id=op.id, target_id="boundary:authz",
                           edge_type=AttackEdgeType.ENABLES, evidence=[], confidence=0.4,
                           security_evidence=False,
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
        # Evidence strength: mean edge confidence weighted by the share of
        # edges carrying validator/adjudication evidence (discovery
        # observations alone do not count).
        ev_edges = [e for e in p.edges if e.security_evidence]
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
