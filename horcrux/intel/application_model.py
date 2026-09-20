"""Semantic application model — structured state for agentic VAPT reasoning."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def fingerprint(*parts: str) -> str:
    normalized = "|".join(p.strip().lower() for p in parts if p)
    return hashlib.sha256(normalized.encode()).hexdigest()[:16]


class IdentityRole(str, Enum):
    ANONYMOUS = "anonymous"
    USER = "user"
    PRIVILEGED = "privileged"
    ADMIN = "admin"


class EvidenceSource(str, Enum):
    NMAP = "nmap"
    HTTP = "http"
    JAVASCRIPT = "javascript"
    HTML = "html"
    BROWSER = "browser"
    PROXY = "proxy"
    FINGERPRINT = "fingerprint"
    FUZZER = "fuzzer"
    VALIDATOR = "validator"
    SERVICE_ENUM = "service_enum"
    OPERATOR = "operator"
    INFERENCE = "inference"


class ApplicationProfile(BaseModel):
    """High-level application characterization."""

    app_type: str = "unknown"  # SPA, API, TRADITIONAL_WEB_APP, STATIC_SITE, HYBRID
    framework: str = ""
    runtime: str = ""
    confidence: float = Field(default=0.5, ge=0, le=1)
    evidence_refs: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)


class SemanticService(BaseModel):
    """Network service mapped into application semantics."""

    id: str = ""
    host: str = ""
    port: int = 0
    protocol: str = "tcp"
    service_name: str = ""
    product: str = ""
    version: str = ""
    is_web: bool = False
    evidence_refs: list[str] = Field(default_factory=list)

    def ensure_id(self) -> str:
        if not self.id:
            self.id = fingerprint("service", self.host, str(self.port), self.protocol)
        return self.id


class SemanticWebTarget(BaseModel):
    """Web-facing target within the application model."""

    id: str = ""
    scheme: str = "http"
    host: str = ""
    port: int = 80
    base_url: str = ""
    application_type: str = "unknown"
    evidence_refs: list[str] = Field(default_factory=list)

    def ensure_id(self) -> str:
        if not self.id:
            self.id = fingerprint("web", self.scheme, self.host, str(self.port))
        return self.id


class SemanticTechnology(BaseModel):
    name: str
    category: str = "unknown"
    version: str = ""
    confidence: float = Field(default=0.8, ge=0, le=1)
    evidence_refs: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)


class SemanticPage(BaseModel):
    id: str = ""
    url: str = ""
    path: str = ""
    title: str = ""
    status_code: int = 0
    evidence_refs: list[str] = Field(default_factory=list)

    def ensure_id(self) -> str:
        if not self.id:
            self.id = fingerprint("page", self.url or self.path)
        return self.id


class SemanticRoute(BaseModel):
    id: str = ""
    path: str = ""
    source: str = "unknown"
    evidence_refs: list[str] = Field(default_factory=list)

    def ensure_id(self) -> str:
        if not self.id:
            self.id = fingerprint("route", self.path, self.source)
        return self.id


class SemanticEndpoint(BaseModel):
    id: str = ""
    method: str = "GET"
    path: str = ""
    authentication: str = "unknown"  # none, required, unknown
    object_type: str = ""
    parameters: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    observed_identities: list[str] = Field(default_factory=list)
    # --- Phase 8 behavior semantics ---
    is_mutation: bool = False  # POST/PUT/PATCH/DELETE or state-changing keyword
    api_version: str = ""
    response_hints: list[str] = Field(default_factory=list)  # json, html, redirect...

    def ensure_id(self) -> str:
        if not self.id:
            self.id = fingerprint("endpoint", self.method, self.path)
        return self.id

    @property
    def normalized_path(self) -> str:
        """Path with scheme/host stripped so ID heuristics never match IPs."""
        p = (self.path or "").strip()
        if p.startswith(("http://", "https://")):
            try:
                from urllib.parse import urlparse as _urlparse
                p = _urlparse(p).path or "/"
            except Exception:
                pass
        if not p.startswith("/"):
            p = "/" + p
        return p or "/"

    @property
    def has_object_collection(self) -> bool:
        """Collection-level object typing (e.g. /api/Products) without an
        instance identifier. Never an authorization boundary by itself."""
        return bool(self.object_type)

    @property
    def has_object_reference(self) -> bool:
        """Instance-level object reference only (e.g. /api/Products/1,
        /api/Users/{id}, /rest/basket/:id, UUID segments).

        Collections (bare /api/Products) are NOT object references — a
        publicly readable catalog is not evidence of an authorization
        boundary failure. IP octets in absolute URLs must never match.
        """
        p = self.normalized_path
        if "{" in p and "}" in p:
            return True
        if "/:" in p:
            return True
        if re.search(r"/\d+(?=/|$|\?|#)", p):
            return True
        if re.search(r"/[0-9a-fA-F-]{36}(?=/|$|\?|#)", p):
            return True
        if re.search(r"/[0-9a-fA-F]{16,32}(?=/|$|\?|#)", p):
            return True
        return False


class SemanticParameter(BaseModel):
    id: str = ""
    name: str = ""
    location: str = "query"
    endpoint: str = ""
    source: str = "unknown"
    evidence_refs: list[str] = Field(default_factory=list)
    # --- Phase 8 parameter class (object_id, pagination, filter, url_fetch...) ---
    param_class: str = ""

    def ensure_id(self) -> str:
        if not self.id:
            self.id = fingerprint("param", self.name, self.location, self.endpoint)
        return self.id


class SemanticForm(BaseModel):
    id: str = ""
    action: str = ""
    method: str = "POST"
    inputs: list[str] = Field(default_factory=list)
    page_url: str = ""
    evidence_refs: list[str] = Field(default_factory=list)

    def ensure_id(self) -> str:
        if not self.id:
            self.id = fingerprint("form", self.action, self.method, self.page_url)
        return self.id


class AuthenticationMechanism(BaseModel):
    id: str = ""
    mechanism_type: str = "unknown"  # session, jwt, oauth, basic, api_key
    login_endpoint: str = ""
    register_endpoint: str = ""
    reset_endpoint: str = ""
    evidence_refs: list[str] = Field(default_factory=list)

    def ensure_id(self) -> str:
        if not self.id:
            self.id = fingerprint("auth", self.mechanism_type, self.login_endpoint)
        return self.id


class SemanticIdentity(BaseModel):
    id: str = ""
    role: IdentityRole = IdentityRole.ANONYMOUS
    label: str = ""
    session_evidence: list[str] = Field(default_factory=list)
    observed_endpoints: list[str] = Field(default_factory=list)
    # --- Phase 8 session/identity semantics (Part 3) ---
    privilege_level: int = 0  # 0 anonymous, 1 user, 2 privileged, 3 admin
    session_ids: list[str] = Field(default_factory=list)
    token_hashes: list[str] = Field(default_factory=list)  # correlation handles only
    observed_objects: list[str] = Field(default_factory=list)  # "Type:id" pairs
    auth_mechanism: str = ""

    def ensure_id(self) -> str:
        if not self.id:
            self.id = fingerprint("identity", self.role.value, self.label)
        return self.id


class SessionRecord(BaseModel):
    """A single observed session. Raw secrets are NEVER stored — only hashes."""

    id: str = ""
    identity_label: str = "anonymous"
    role: IdentityRole = IdentityRole.ANONYMOUS
    cookie_hashes: list[str] = Field(default_factory=list)
    token_hashes: list[str] = Field(default_factory=list)
    login_endpoint: str = ""
    logout_observed: bool = False
    expired_observed: bool = False
    replaced_by: str = ""
    evidence_refs: list[str] = Field(default_factory=list)
    provenance: list[str] = Field(default_factory=list)

    def ensure_id(self) -> str:
        if not self.id:
            self.id = fingerprint("session", self.identity_label, self.login_endpoint,
                                  ",".join(sorted(self.cookie_hashes))[:48])
        return self.id


class ObjectLifecycle(BaseModel):
    """Semantic lifecycle of one application object instance/type (Part 6)."""

    id: str = ""
    object_type: str = ""
    identifier: str = ""  # concrete id or pattern, e.g. "123" or "{id}"
    identifier_pattern: str = ""
    creator_identity: str = ""
    owner_identity: str = ""
    read_endpoints: list[str] = Field(default_factory=list)
    mutation_endpoints: list[str] = Field(default_factory=list)
    delete_endpoints: list[str] = Field(default_factory=list)
    observed_identities: list[str] = Field(default_factory=list)
    relationships: list[str] = Field(default_factory=list)
    workflow_names: list[str] = Field(default_factory=list)
    authorization_notes: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    provenance: list[str] = Field(default_factory=list)

    def ensure_id(self) -> str:
        if not self.id:
            self.id = fingerprint("objlife", self.object_type, self.identifier or self.identifier_pattern)
        return self.id


class WorkflowTransition(BaseModel):
    """One state transition within a workflow (Part 5)."""

    id: str = ""
    workflow: str = ""
    from_state: str = ""
    to_state: str = ""
    trigger: str = ""  # e.g. "POST /rest/basket/1/checkout"
    endpoint: str = ""
    method: str = ""
    identity: str = "anonymous"
    preconditions: list[str] = Field(default_factory=list)
    postconditions: list[str] = Field(default_factory=list)
    state_changing: bool = False
    evidence_refs: list[str] = Field(default_factory=list)
    provenance: list[str] = Field(default_factory=list)

    def ensure_id(self) -> str:
        if not self.id:
            self.id = fingerprint("wftrans", self.workflow, self.from_state,
                                  self.to_state, self.trigger[:60])
        return self.id


class GraphQLOperation(BaseModel):
    """A GraphQL query/mutation observed in schema/JS/traffic (Part 10)."""

    id: str = ""
    kind: str = "query"  # query | mutation | subscription
    name: str = ""
    object_types: list[str] = Field(default_factory=list)
    fields: list[str] = Field(default_factory=list)
    endpoint: str = "/graphql"
    authorization_noted: bool = False
    evidence_refs: list[str] = Field(default_factory=list)
    provenance: list[str] = Field(default_factory=list)

    def ensure_id(self) -> str:
        if not self.id:
            self.id = fingerprint("gqlop", self.kind, self.name)
        return self.id


class APIOperation(BaseModel):
    """Semantic API operation beyond static endpoint inventory (Part 9)."""

    id: str = ""
    method: str = "GET"
    path: str = ""
    version: str = ""
    parameter_classes: list[str] = Field(default_factory=list)  # object_id, pagination, filter...
    supports_methods: list[str] = Field(default_factory=list)  # observed alternates
    is_mutation: bool = False
    is_bulk: bool = False
    object_type: str = ""
    evidence_refs: list[str] = Field(default_factory=list)
    provenance: list[str] = Field(default_factory=list)

    def ensure_id(self) -> str:
        if not self.id:
            self.id = fingerprint("apiop", self.method, self.path)
        return self.id


class ObjectType(BaseModel):
    id: str = ""
    name: str = ""
    endpoints: list[str] = Field(default_factory=list)
    parameter_names: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)

    def ensure_id(self) -> str:
        if not self.id:
            self.id = fingerprint("object", self.name)
        return self.id


class ObjectReference(BaseModel):
    id: str = ""
    object_type: str = ""
    endpoint_id: str = ""
    parameter: str = ""
    evidence_refs: list[str] = Field(default_factory=list)

    def ensure_id(self) -> str:
        if not self.id:
            self.id = fingerprint("objref", self.object_type, self.endpoint_id, self.parameter)
        return self.id


class WorkflowStep(BaseModel):
    id: str = ""
    name: str = ""
    method: str = ""
    path: str = ""
    identity: str = "anonymous"
    inputs: list[str] = Field(default_factory=list)
    state_transition: str = ""
    request_refs: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)

    def ensure_id(self) -> str:
        if not self.id:
            self.id = fingerprint("wfstep", self.name, self.method, self.path)
        return self.id


class Workflow(BaseModel):
    id: str = ""
    name: str = ""
    steps: list[WorkflowStep] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)

    def ensure_id(self) -> str:
        if not self.id:
            self.id = fingerprint("workflow", self.name)
        return self.id


class SecurityBoundary(BaseModel):
    id: str = ""
    boundary_type: str = ""  # authentication, authorization, network, data
    description: str = ""
    protected_assets: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)

    def ensure_id(self) -> str:
        if not self.id:
            self.id = fingerprint("boundary", self.boundary_type, self.description[:40])
        return self.id


class ServiceFact(BaseModel):
    """Protocol-specific semantic fact (SMB share, LDAP context, principal...)."""

    id: str = ""
    protocol: str = ""
    fact_type: str = ""
    name: str = ""
    details: dict[str, Any] = Field(default_factory=dict)
    evidence_refs: list[str] = Field(default_factory=list)
    provenance: list[str] = Field(default_factory=list)

    def ensure_id(self) -> str:
        if not self.id:
            self.id = fingerprint("svcfact", self.protocol, self.fact_type, self.name[:60])
        return self.id


def track_provenance(existing: list[str], source: str, ref: str = "") -> list[str]:
    """Append ``source[:ref]`` provenance without duplicates."""
    entry = f"{source}:{ref}" if ref else source
    if entry not in existing:
        existing.append(entry)
    return existing


class ApplicationModel(BaseModel):
    """Living semantic model of the target application."""

    target: str = ""
    profile: ApplicationProfile = Field(default_factory=ApplicationProfile)
    services: list[SemanticService] = Field(default_factory=list)
    web_targets: list[SemanticWebTarget] = Field(default_factory=list)
    technologies: list[SemanticTechnology] = Field(default_factory=list)
    pages: list[SemanticPage] = Field(default_factory=list)
    routes: list[SemanticRoute] = Field(default_factory=list)
    endpoints: list[SemanticEndpoint] = Field(default_factory=list)
    parameters: list[SemanticParameter] = Field(default_factory=list)
    forms: list[SemanticForm] = Field(default_factory=list)
    authentication: list[AuthenticationMechanism] = Field(default_factory=list)
    identities: list[SemanticIdentity] = Field(default_factory=list)
    object_types: list[ObjectType] = Field(default_factory=list)
    object_references: list[ObjectReference] = Field(default_factory=list)
    workflows: list[Workflow] = Field(default_factory=list)
    workflow_transitions: list[WorkflowTransition] = Field(default_factory=list)
    object_lifecycles: list[ObjectLifecycle] = Field(default_factory=list)
    api_operations: list[APIOperation] = Field(default_factory=list)
    graphql_operations: list[GraphQLOperation] = Field(default_factory=list)
    sessions: list[SessionRecord] = Field(default_factory=list)
    security_boundaries: list[SecurityBoundary] = Field(default_factory=list)
    service_facts: list[ServiceFact] = Field(default_factory=list)
    authorization_matrix: dict[str, Any] = Field(default_factory=dict)
    app_classification_signals: dict[str, float] = Field(default_factory=dict)
    sensitive_data_observations: list[dict[str, Any]] = Field(default_factory=list)
    discovery_sources: list[str] = Field(default_factory=list)
    updated_at: datetime = Field(default_factory=utcnow)

    def upsert_endpoint(self, endpoint: SemanticEndpoint) -> SemanticEndpoint:
        endpoint.ensure_id()
        for idx, existing in enumerate(self.endpoints):
            if existing.id == endpoint.id:
                merged = _merge_endpoint(existing, endpoint)
                self.endpoints[idx] = merged
                return merged
        self.endpoints.append(endpoint)
        return endpoint

    def upsert_route(self, route: SemanticRoute) -> SemanticRoute:
        route.ensure_id()
        for idx, existing in enumerate(self.routes):
            if existing.id == route.id:
                if route.source and route.source != existing.source:
                    existing.source = f"{existing.source},{route.source}"
                existing.evidence_refs = list(set(existing.evidence_refs + route.evidence_refs))
                return existing
        self.routes.append(route)
        return route

    def upsert_object_type(self, obj: ObjectType) -> ObjectType:
        obj.ensure_id()
        for idx, existing in enumerate(self.object_types):
            if existing.name.lower() == obj.name.lower():
                existing.endpoints = list(set(existing.endpoints + obj.endpoints))
                existing.parameter_names = list(set(existing.parameter_names + obj.parameter_names))
                existing.evidence_refs = list(set(existing.evidence_refs + obj.evidence_refs))
                return existing
        self.object_types.append(obj)
        return obj

    def upsert_identity(self, identity: SemanticIdentity) -> SemanticIdentity:
        identity.ensure_id()
        for idx, existing in enumerate(self.identities):
            if existing.role == identity.role and existing.label == identity.label:
                existing.observed_endpoints = list(
                    set(existing.observed_endpoints + identity.observed_endpoints)
                )
                existing.session_evidence = list(
                    set(existing.session_evidence + identity.session_evidence)
                )
                existing.session_ids = list(set(existing.session_ids + identity.session_ids))
                existing.token_hashes = list(set(existing.token_hashes + identity.token_hashes))
                existing.observed_objects = list(
                    set(existing.observed_objects + identity.observed_objects))
                if identity.privilege_level > existing.privilege_level:
                    existing.privilege_level = identity.privilege_level
                if identity.auth_mechanism and not existing.auth_mechanism:
                    existing.auth_mechanism = identity.auth_mechanism
                return existing
        self.identities.append(identity)
        return identity

    def upsert_session(self, session: SessionRecord) -> SessionRecord:
        session.ensure_id()
        for existing in self.sessions:
            if existing.id == session.id:
                existing.cookie_hashes = list(set(existing.cookie_hashes + session.cookie_hashes))
                existing.token_hashes = list(set(existing.token_hashes + session.token_hashes))
                existing.evidence_refs = list(set(existing.evidence_refs + session.evidence_refs))
                existing.provenance = list(set(existing.provenance + session.provenance))
                if session.logout_observed:
                    existing.logout_observed = True
                if session.expired_observed:
                    existing.expired_observed = True
                if session.replaced_by:
                    existing.replaced_by = session.replaced_by
                return existing
        self.sessions.append(session)
        return session

    def upsert_object_lifecycle(self, obj: ObjectLifecycle) -> ObjectLifecycle:
        obj.ensure_id()
        for existing in self.object_lifecycles:
            if existing.id == obj.id:
                for attr in ("read_endpoints", "mutation_endpoints", "delete_endpoints",
                             "observed_identities", "relationships", "workflow_names",
                             "authorization_notes", "evidence_refs", "provenance"):
                    setattr(existing, attr,
                            list(set(getattr(existing, attr) + getattr(obj, attr))))
                if obj.owner_identity and not existing.owner_identity:
                    existing.owner_identity = obj.owner_identity
                if obj.creator_identity and not existing.creator_identity:
                    existing.creator_identity = obj.creator_identity
                return existing
        self.object_lifecycles.append(obj)
        return obj

    def upsert_transition(self, tr: WorkflowTransition) -> WorkflowTransition:
        tr.ensure_id()
        for existing in self.workflow_transitions:
            if existing.id == tr.id:
                existing.evidence_refs = list(set(existing.evidence_refs + tr.evidence_refs))
                existing.provenance = list(set(existing.provenance + tr.provenance))
                return existing
        self.workflow_transitions.append(tr)
        return tr

    def upsert_api_operation(self, op: APIOperation) -> APIOperation:
        op.ensure_id()
        for existing in self.api_operations:
            if existing.id == op.id:
                existing.parameter_classes = list(
                    set(existing.parameter_classes + op.parameter_classes))
                existing.supports_methods = list(
                    set(existing.supports_methods + op.supports_methods))
                existing.evidence_refs = list(set(existing.evidence_refs + op.evidence_refs))
                existing.provenance = list(set(existing.provenance + op.provenance))
                return existing
        self.api_operations.append(op)
        return op

    def upsert_graphql_operation(self, op: GraphQLOperation) -> GraphQLOperation:
        op.ensure_id()
        for existing in self.graphql_operations:
            if existing.id == op.id:
                existing.fields = list(set(existing.fields + op.fields))
                existing.object_types = list(set(existing.object_types + op.object_types))
                existing.evidence_refs = list(set(existing.evidence_refs + op.evidence_refs))
                existing.provenance = list(set(existing.provenance + op.provenance))
                return existing
        self.graphql_operations.append(op)
        return op

    def upsert_service_fact(self, fact: ServiceFact) -> ServiceFact:
        fact.ensure_id()
        for existing in self.service_facts:
            if existing.id == fact.id:
                existing.evidence_refs = list(set(existing.evidence_refs + fact.evidence_refs))
                existing.provenance = list(set(existing.provenance + fact.provenance))
                existing.details.update(fact.details)
                return existing
        self.service_facts.append(fact)
        return fact

    def upsert_technology(self, tech: SemanticTechnology) -> SemanticTechnology:
        for existing in self.technologies:
            if existing.name.lower() == tech.name.lower():
                existing.evidence_refs = list(set(existing.evidence_refs + tech.evidence_refs))
                existing.sources = list(set(existing.sources + tech.sources))
                if tech.version and not existing.version:
                    existing.version = tech.version
                return existing
        self.technologies.append(tech)
        return tech

    def summary(self) -> dict[str, Any]:
        """Compact summary for AI reasoning checkpoints."""
        object_endpoints = [e for e in self.endpoints if e.has_object_reference]
        admin_endpoints = [
            e for e in self.endpoints
            if any(k in e.path.lower() for k in ("admin", "management", "privileged", "/roles"))
        ]
        return {
            "target": self.target,
            "application": {
                "type": self.profile.app_type,
                "framework": self.profile.framework,
                "runtime": self.profile.runtime,
                "confidence": self.profile.confidence,
            },
            "services": len(self.services),
            "web_targets": len(self.web_targets),
            "technologies": [t.name for t in self.technologies[:10]],
            "endpoints": len(self.endpoints),
            "object_bearing_endpoints": len(object_endpoints),
            "admin_endpoints": len(admin_endpoints),
            "routes": len(self.routes),
            "parameters": len(self.parameters),
            "authentication_surfaces": len(self.authentication),
            "identities": [i.role.value for i in self.identities],
            "identity_labels": [i.label for i in self.identities],
            "sessions": len(self.sessions),
            "object_types": [o.name for o in self.object_types],
            "object_lifecycles": len(self.object_lifecycles),
            "workflows": [w.name for w in self.workflows],
            "workflow_transitions": len(self.workflow_transitions),
            "api_operations": len(self.api_operations),
            "graphql_operations": len(self.graphql_operations),
        }


def _merge_endpoint(existing: SemanticEndpoint, new: SemanticEndpoint) -> SemanticEndpoint:
    existing.parameters = list(set(existing.parameters + new.parameters))
    existing.sources = list(set(existing.sources + new.sources))
    existing.evidence_refs = list(set(existing.evidence_refs + new.evidence_refs))
    existing.observed_identities = list(set(existing.observed_identities + new.observed_identities))
    existing.response_hints = list(set(existing.response_hints + new.response_hints))
    if new.object_type and not existing.object_type:
        existing.object_type = new.object_type
    if new.authentication != "unknown" and existing.authentication == "unknown":
        existing.authentication = new.authentication
    if new.is_mutation:
        existing.is_mutation = True
    if new.api_version and not existing.api_version:
        existing.api_version = new.api_version
    return existing
