"""Hypothesis engine — converts application semantics into security hypotheses."""

from __future__ import annotations

import re
from enum import Enum
from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

from horcrux.intel.application_model import ApplicationModel, fingerprint

if TYPE_CHECKING:
    from horcrux.models import WorkspaceState


class HypothesisStatus(str, Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    SUPPORTED = "SUPPORTED"
    REFUTED = "REFUTED"
    CONFIRMED = "CONFIRMED"
    BLOCKED = "BLOCKED"


class HypothesisClass(str, Enum):
    IDOR_BOLA = "idor_bola"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    AUTHENTICATION = "authentication"
    SESSION = "session"
    INJECTION = "injection"
    SSRF = "ssrf"
    FILE_UPLOAD = "file_upload"
    GRAPHQL = "graphql"
    BUSINESS_LOGIC = "business_logic"
    INFORMATION_DISCLOSURE = "information_disclosure"
    CONFIGURATION = "configuration"
    API_SECURITY = "api_security"
    CLIENT_SIDE = "client_side"


class Hypothesis(BaseModel):
    id: str = ""
    hypothesis_class: HypothesisClass = HypothesisClass.INFORMATION_DISCLOSURE
    title: str = ""
    asset_refs: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.5, ge=0, le=1)
    assumptions: list[str] = Field(default_factory=list)
    validation_requirements: list[str] = Field(default_factory=list)
    next_investigations: list[str] = Field(default_factory=list)
    status: HypothesisStatus = HypothesisStatus.OPEN
    rule_id: str = ""

    def ensure_id(self) -> str:
        if not self.id:
            self.id = fingerprint("hyp", self.hypothesis_class.value, self.title[:60])
        return self.id


# Extensible rule registry
HYPOTHESIS_RULES: list[dict] = []


def _register_rule(rule_id: str, fn) -> None:
    HYPOTHESIS_RULES.append({"id": rule_id, "fn": fn})


def _object_ref_rule(app: ApplicationModel) -> list[Hypothesis]:
    results: list[Hypothesis] = []
    object_endpoints = [e for e in app.endpoints if e.has_object_reference]
    if not object_endpoints:
        return results
    asset_refs = [e.id for e in object_endpoints[:8]]
    evidence_refs: list[str] = []
    for e in object_endpoints:
        evidence_refs.extend(e.evidence_refs)
    results.append(
        Hypothesis(
            hypothesis_class=HypothesisClass.IDOR_BOLA,
            title="Potential object-level authorization weakness (IDOR/BOLA)",
            asset_refs=asset_refs,
            evidence_refs=list(set(evidence_refs))[:12],
            confidence=min(0.85, 0.5 + 0.05 * len(object_endpoints)),
            assumptions=["Object identifiers are user-controllable", "Access control may not bind objects to identity"],
            validation_requirements=[
                "Determine whether object access is bound to authenticated user identity",
                "Test cross-user object access with distinct identities",
            ],
            rule_id="object_reference",
        )
    )
    return results


def _privileged_endpoint_rule(app: ApplicationModel) -> list[Hypothesis]:
    privileged_patterns = re.compile(
        r"(admin|management|privileged|/roles|/system|/delete|/internal)",
        re.I,
    )
    privileged = [e for e in app.endpoints if privileged_patterns.search(e.path)]
    if not privileged:
        return []
    return [
        Hypothesis(
            hypothesis_class=HypothesisClass.PRIVILEGE_ESCALATION,
            title="Potential privileged endpoint exposure or authorization bypass",
            asset_refs=[e.id for e in privileged[:8]],
            evidence_refs=list({r for e in privileged for r in e.evidence_refs})[:12],
            confidence=0.65,
            assumptions=["Privileged routes may be accessible without proper role enforcement"],
            validation_requirements=[
                "Test privileged endpoints as anonymous and low-privilege identities",
                "Verify role-based access control enforcement",
            ],
            rule_id="privileged_endpoint",
        )
    ]


def _auth_surface_rule(app: ApplicationModel) -> list[Hypothesis]:
    if not app.authentication and not any(
        k in (e.path.lower() for e in app.endpoints)
        for k in ("login", "register", "signin", "auth", "oauth")
    ):
        return []
    auth_endpoints = [
        e for e in app.endpoints
        if any(k in e.path.lower() for k in ("login", "register", "signin", "auth", "oauth", "reset"))
    ]
    mech_types = [a.mechanism_type for a in app.authentication]
    jwt_present = any(m == "jwt" for m in mech_types) or any(
        "jwt" in e.path.lower() for e in app.endpoints
    )
    results: list[Hypothesis] = [
        Hypothesis(
            hypothesis_class=HypothesisClass.AUTHENTICATION,
            title="Authentication surface requires systematic review",
            asset_refs=[e.id for e in auth_endpoints[:6]],
            evidence_refs=list({r for a in app.authentication for r in a.evidence_refs})[:10],
            confidence=0.7,
            assumptions=["Authentication workflow may contain bypass or weak session handling"],
            validation_requirements=[
                "Map registration, login, and session lifecycle",
                "Test authentication bypass and session fixation vectors",
            ],
            rule_id="authentication_surface",
        )
    ]
    if jwt_present:
        results.append(
            Hypothesis(
                hypothesis_class=HypothesisClass.SESSION,
                title="JWT-based authentication may have token validation weaknesses",
                asset_refs=[a.id for a in app.authentication if a.mechanism_type == "jwt"],
                confidence=0.6,
                assumptions=["JWT tokens may be weakly validated or algorithm-confused"],
                validation_requirements=["Inspect JWT structure, signing, and expiration enforcement"],
                rule_id="jwt_detected",
            )
        )
    return results


def _ssrf_rule(app: ApplicationModel) -> list[Hypothesis]:
    ssrf_params = {"url", "target", "callback", "webhook", "import", "redirect", "fetch", "src"}
    matching = [
        p for p in app.parameters
        if p.name.lower() in ssrf_params or any(k in p.name.lower() for k in ssrf_params)
    ]
    if not matching:
        return []
    return [
        Hypothesis(
            hypothesis_class=HypothesisClass.SSRF,
            title="URL-fetching parameters may enable SSRF",
            asset_refs=[p.id for p in matching[:6]],
            evidence_refs=list({r for p in matching for r in p.evidence_refs})[:8],
            confidence=0.55,
            assumptions=["Application may fetch user-supplied URLs server-side"],
            validation_requirements=["Test server-side URL fetch behavior with controlled callbacks"],
            rule_id="ssrf_parameter",
        )
    ]


def _injection_rule(app: ApplicationModel) -> list[Hypothesis]:
    injection_params = {"q", "query", "search", "filter", "sort", "id", "name", "email"}
    matching = [
        p for p in app.parameters
        if p.name.lower() in injection_params or p.location in {"query", "body"}
    ]
    if len(matching) < 2:
        return []
    return [
        Hypothesis(
            hypothesis_class=HypothesisClass.INJECTION,
            title="Input parameters may be vulnerable to injection or data exposure",
            asset_refs=[p.id for p in matching[:8]],
            confidence=0.5,
            assumptions=["User input reaches backend processing without sufficient validation"],
            validation_requirements=["Test input validation on search/filter/query parameters"],
            rule_id="search_filter_params",
        )
    ]


def _graphql_rule(app: ApplicationModel) -> list[Hypothesis]:
    graphql_eps = [e for e in app.endpoints if "graphql" in e.path.lower()]
    if not graphql_eps:
        return []
    return [
        Hypothesis(
            hypothesis_class=HypothesisClass.GRAPHQL,
            title="GraphQL endpoint may expose schema or authorization weaknesses",
            asset_refs=[e.id for e in graphql_eps],
            confidence=0.65,
            assumptions=["GraphQL introspection or batching may be enabled"],
            validation_requirements=[
                "Test introspection, authorization on queries/mutations, and depth limits",
            ],
            rule_id="graphql_endpoint",
        )
    ]


def _file_upload_rule(app: ApplicationModel) -> list[Hypothesis]:
    upload_forms = [
        f for f in app.forms
        if any("file" in i.lower() for i in f.inputs) or "upload" in f.action.lower()
    ]
    upload_eps = [e for e in app.endpoints if "upload" in e.path.lower()]
    if not upload_forms and not upload_eps:
        return []
    return [
        Hypothesis(
            hypothesis_class=HypothesisClass.FILE_UPLOAD,
            title="File upload surface may allow unsafe file handling",
            asset_refs=[f.id for f in upload_forms] + [e.id for e in upload_eps],
            confidence=0.6,
            assumptions=["Uploaded files may not be validated or stored securely"],
            validation_requirements=["Test file type validation, path traversal, and execution constraints"],
            rule_id="file_upload",
        )
    ]


def _workflow_rule(app: ApplicationModel) -> list[Hypothesis]:
    if len(app.workflows) < 1 and len(app.endpoints) < 5:
        return []
    multi_step = [w for w in app.workflows if len(w.steps) >= 2]
    if not multi_step and len(app.endpoints) < 8:
        return []
    return [
        Hypothesis(
            hypothesis_class=HypothesisClass.BUSINESS_LOGIC,
            title="Multi-step workflows may contain business logic flaws",
            asset_refs=[w.id for w in multi_step] or [e.id for e in app.endpoints[:5]],
            confidence=0.55,
            assumptions=["State transitions may be skippable or authorization-inconsistent"],
            validation_requirements=[
                "Test state skipping, replay, and privilege transitions across workflow steps",
            ],
            rule_id="business_logic_workflow",
        )
    ]


# Register rules
_register_rule("object_reference", _object_ref_rule)
_register_rule("privileged_endpoint", _privileged_endpoint_rule)
_register_rule("authentication_surface", _auth_surface_rule)
_register_rule("ssrf_parameter", _ssrf_rule)
_register_rule("search_filter_params", _injection_rule)
_register_rule("graphql_endpoint", _graphql_rule)
_register_rule("file_upload", _file_upload_rule)
_register_rule("business_logic_workflow", _workflow_rule)


def _correlated_authz_rule(app: ApplicationModel) -> list[Hypothesis]:
    """Correlated: authenticated API + object IDs + identities + retrieval (P7/P15).

    Generates property hypotheses with explicit evidence requirements instead
    of asserting a vulnerability from inference.
    """
    object_eps = [e for e in app.endpoints if e.has_object_reference]
    if not object_eps:
        return []
    identities = [i for i in app.identities if i.role.value != "anonymous"]
    authed_api = any(e.authentication in ("required", "unknown")
                     for e in app.endpoints if e.path.startswith(("/api", "/rest", "/v1")))
    if not (authed_api and identities):
        return []
    retrieval = [e for e in object_eps if e.method.upper() == "GET"]
    mutations = [e for e in object_eps if e.is_mutation]
    results: list[Hypothesis] = []
    if retrieval:
        results.append(Hypothesis(
            hypothesis_class=HypothesisClass.IDOR_BOLA,
            title="Unauthorized object read may be possible across identities",
            asset_refs=[e.id for e in retrieval[:8]],
            evidence_refs=list({r for e in retrieval for r in e.evidence_refs})[:12],
            confidence=min(0.8, 0.55 + 0.05 * len(retrieval)),
            assumptions=["Same object identifier is addressable by different identities",
                         "Ownership is not verified server-side"],
            validation_requirements=[
                "Same object identifier requested from two distinct identities",
                "Comparable requests with response comparison",
                "Ownership relationship between identity and object",
            ],
            rule_id="correlated_authorization"))
    if mutations:
        results.append(Hypothesis(
            hypothesis_class=HypothesisClass.IDOR_BOLA,
            title="Unauthorized object mutation may be possible across identities",
            asset_refs=[e.id for e in mutations[:8]],
            evidence_refs=list({r for e in mutations for r in e.evidence_refs})[:12],
            confidence=0.6,
            assumptions=["Mutation endpoints bind objects by client-supplied identifier"],
            validation_requirements=[
                "Replay mutation with a second identity's object identifier",
                "Verify state change attribution server-side",
            ],
            rule_id="correlated_authorization"))
    # Vertical dimension: low-privilege identity vs privileged endpoints.
    admin_eps = [e for e in app.endpoints if "admin" in e.path.lower()]
    low_priv = [i for i in identities if i.privilege_level <= 1]
    if admin_eps and low_priv:
        results.append(Hypothesis(
            hypothesis_class=HypothesisClass.PRIVILEGE_ESCALATION,
            title="Low-privilege identity may reach privileged functions",
            asset_refs=[e.id for e in admin_eps[:8]],
            evidence_refs=list({r for e in admin_eps for r in e.evidence_refs})[:12],
            confidence=0.6,
            assumptions=["Role is enforced client-side or inconsistently server-side"],
            validation_requirements=[
                "Request privileged endpoints as anonymous and low-privilege identities",
                "Compare role-differentiated responses",
            ],
            rule_id="correlated_authorization"))
    return results


def _file_processing_rule(app: ApplicationModel) -> list[Hypothesis]:
    """Correlated: upload endpoint + stored object + downloadable resource."""
    upload = [e for e in app.endpoints if "upload" in e.path.lower()]
    if not upload:
        return []
    stored = [o for o in app.object_lifecycles
              if "file" in o.object_type.lower() or o.mutation_endpoints]
    downloadable = [e for e in app.endpoints
                    if any(k in e.path.lower() for k in ("download", "files", "static", "uploads"))]
    if not (stored or downloadable):
        return []
    return [Hypothesis(
        hypothesis_class=HypothesisClass.FILE_UPLOAD,
        title="Uploaded files may be stored unsafely and retrievable",
        asset_refs=[e.id for e in upload[:6]],
        evidence_refs=list({r for e in upload for r in e.evidence_refs})[:10],
        confidence=0.65,
        assumptions=["Server-side processing trusts uploaded content",
                     "Stored objects are served without re-validation"],
        validation_requirements=[
            "Upload constrained test file and observe storage response",
            "Attempt retrieval of the stored resource",
            "Test extension, content-type, and path handling",
        ],
        rule_id="file_processing_chain")]


def _jwt_weakness_rule(app: ApplicationModel) -> list[Hypothesis]:
    """JWT/session weakness from mechanism + session observations."""
    jwt_mechs = [a for a in app.authentication if a.mechanism_type == "jwt"]
    has_sessions = bool(app.sessions)
    token_params = [p for p in app.parameters
                    if p.name.lower() in ("token", "jwt", "access_token", "id_token")]
    if not (jwt_mechs or token_params):
        return []
    return [Hypothesis(
        hypothesis_class=HypothesisClass.SESSION,
        title="Session tokens may be weakly validated (algorithm/expiry/audience)",
        asset_refs=[a.id for a in jwt_mechs[:4]] + [p.id for p in token_params[:4]],
        evidence_refs=list({r for a in jwt_mechs for r in a.evidence_refs})[:10],
        confidence=0.6 if has_sessions else 0.5,
        assumptions=["Tokens accepted without strict alg/expiry/audience checks"],
        validation_requirements=[
            "Decode token header/payload structure (no secret needed)",
            "Test none-algorithm and expiry enforcement",
            "Observe session replacement/expiry behavior",
        ],
        rule_id="jwt_session_weakness")]


SENSITIVE_KEYWORDS = {"ssn", "password", "secret", "card", "pan", "iban",
                      "salary", "medical", "dob", "phone", "address", "email"}


def _sensitive_data_rule(app: ApplicationModel) -> list[Hypothesis]:
    """Sensitive-data exposure from parameters/paths/object fields."""
    hits = [p for p in app.parameters if p.name.lower() in SENSITIVE_KEYWORDS]
    hits += [p for p in app.parameters if p.param_class == "auth_credential"]
    paths = [e for e in app.endpoints
             if any(k in e.path.lower() for k in ("profile", "account", "invoice", "export"))]
    if not hits and not paths:
        return []
    return [Hypothesis(
        hypothesis_class=HypothesisClass.INFORMATION_DISCLOSURE,
        title="Sensitive personal/credential data may be over-exposed via APIs",
        asset_refs=[p.id for p in hits[:8]] + [e.id for e in paths[:6]],
        evidence_refs=list({r for p in hits for r in p.evidence_refs})[:10],
        confidence=0.55,
        assumptions=["Responses return full objects without field minimization"],
        validation_requirements=[
            "Inspect response fields for sensitive attributes",
            "Verify authorization on export/profile endpoints",
        ],
        rule_id="sensitive_data_exposure")]


def _workflow_state_rule(app: ApplicationModel) -> list[Hypothesis]:
    """Business-logic properties from workflow transitions (Part 8)."""
    transitions = getattr(app, "workflow_transitions", [])
    if not transitions and len(app.workflows) < 1:
        return []
    props: list[Hypothesis] = []
    state_changing = [t for t in transitions if t.state_changing]
    if len(transitions) >= 2 or state_changing:
        props.append(Hypothesis(
            hypothesis_class=HypothesisClass.BUSINESS_LOGIC,
            title="Workflow state transition may be reorderable or skippable",
            asset_refs=[t.id for t in transitions[:8]],
            evidence_refs=list({r for t in transitions for r in t.evidence_refs})[:10],
            confidence=0.55,
            assumptions=["Server does not enforce step preconditions",
                         "Client-controlled state drives transitions"],
            validation_requirements=[
                "Invoke later step without completing prerequisites",
                "Replay transitions out of order",
                "Verify server-side state machine enforcement",
            ],
            rule_id="workflow_state_properties"))
    privileged_steps = [t for t in transitions
                        if any(k in (t.endpoint or "").lower()
                               for k in ("admin", "approve", "refund", "role", "privileg"))]
    if privileged_steps:
        props.append(Hypothesis(
            hypothesis_class=HypothesisClass.BUSINESS_LOGIC,
            title="Privileged workflow transition may lack authorization",
            asset_refs=[t.id for t in privileged_steps[:6]],
            evidence_refs=list({r for t in privileged_steps for r in t.evidence_refs})[:10],
            confidence=0.6,
            assumptions=["Transition authorization differs from endpoint authorization"],
            validation_requirements=[
                "Execute privileged transition as low-privilege identity",
                "Compare transition outcomes across roles",
            ],
            rule_id="workflow_state_properties"))
    return props


def _graphql_authz_rule(app: ApplicationModel) -> list[Hypothesis]:
    """Schema-semantics GraphQL authorization hypotheses (Part 10)."""
    ops = getattr(app, "graphql_operations", [])
    if not ops:
        return []
    mutations = [o for o in ops if o.kind == "mutation"]
    results = [Hypothesis(
        hypothesis_class=HypothesisClass.GRAPHQL,
        title="GraphQL operations may lack object/field-level authorization",
        asset_refs=[o.id for o in ops[:10]],
        evidence_refs=list({r for o in ops for r in o.evidence_refs})[:10],
        confidence=0.6,
        assumptions=["Resolvers enforce authorization inconsistently across fields"],
        validation_requirements=[
            "Test introspection availability and depth limits",
            "Exercise queries/mutations across identities",
            "Compare field visibility by role",
        ],
        rule_id="graphql_authorization")]
    if mutations:
        results.append(Hypothesis(
            hypothesis_class=HypothesisClass.BUSINESS_LOGIC,
            title="GraphQL mutations may permit unsafe state changes",
            asset_refs=[o.id for o in mutations[:8]],
            evidence_refs=list({r for o in mutations for r in o.evidence_refs})[:10],
            confidence=0.55,
            assumptions=["Mutations lack server-side state validation"],
            validation_requirements=[
                "Invoke mutations with controlled inputs only",
                "Verify state effects and authorization per mutation",
            ],
            rule_id="graphql_authorization"))
    return results


_PHASE8_RULES_REGISTERED = False


def _ensure_phase8_rules() -> None:
    """Register Phase 8 correlated rules once (defined below registration site)."""
    global _PHASE8_RULES_REGISTERED
    if _PHASE8_RULES_REGISTERED:
        return
    _PHASE8_RULES_REGISTERED = True
    _register_rule("correlated_authorization", _correlated_authz_rule)
    _register_rule("file_processing_chain", _file_processing_rule)
    _register_rule("jwt_session_weakness", _jwt_weakness_rule)
    _register_rule("sensitive_data_exposure", _sensitive_data_rule)
    _register_rule("workflow_state_properties", _workflow_state_rule)
    _register_rule("graphql_authorization", _graphql_authz_rule)


def generate_hypotheses(app: ApplicationModel) -> list[Hypothesis]:
    """Run all registered rules against the application model."""
    _ensure_phase8_rules()
    seen: dict[str, Hypothesis] = {}
    for rule in HYPOTHESIS_RULES:
        for hyp in rule["fn"](app):
            hyp.ensure_id()
            if hyp.rule_id:
                hyp.rule_id = rule["id"]
            if hyp.id not in seen:
                seen[hyp.id] = hyp
    return list(seen.values())


def update_hypotheses_from_state(state: WorkspaceState) -> list[Hypothesis]:
    """Merge new hypotheses with existing, preserving status of known ones."""
    app = state.get_application_model()
    if not app.target:
        app.target = state.target
    new_hyps = generate_hypotheses(app)
    existing_list = state.get_hypotheses()
    existing = {h.id: h for h in existing_list}
    merged: list[Hypothesis] = []
    for hyp in new_hyps:
        if hyp.id in existing:
            old = existing[hyp.id]
            if old.status not in {HypothesisStatus.REFUTED, HypothesisStatus.CONFIRMED}:
                hyp.status = old.status
            merged.append(hyp)
        else:
            merged.append(hyp)
    # Keep refuted/confirmed that are no longer generated
    new_ids = {h.id for h in merged}
    for old_id, old in existing.items():
        if old_id not in new_ids and old.status in {
            HypothesisStatus.REFUTED,
            HypothesisStatus.CONFIRMED,
            HypothesisStatus.INVESTIGATING,
        }:
            merged.append(old)
    state.set_application_model(app)
    return merged
