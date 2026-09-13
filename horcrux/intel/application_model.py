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

    def ensure_id(self) -> str:
        if not self.id:
            self.id = fingerprint("endpoint", self.method, self.path)
        return self.id

    @property
    def has_object_reference(self) -> bool:
        return bool(self.object_type) or "{" in self.path or re.search(r"/\d+", self.path)


class SemanticParameter(BaseModel):
    id: str = ""
    name: str = ""
    location: str = "query"
    endpoint: str = ""
    source: str = "unknown"
    evidence_refs: list[str] = Field(default_factory=list)

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

    def ensure_id(self) -> str:
        if not self.id:
            self.id = fingerprint("identity", self.role.value, self.label)
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
    security_boundaries: list[SecurityBoundary] = Field(default_factory=list)
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
                return existing
        self.identities.append(identity)
        return identity

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
            "object_types": [o.name for o in self.object_types],
            "workflows": [w.name for w in self.workflows],
        }


def _merge_endpoint(existing: SemanticEndpoint, new: SemanticEndpoint) -> SemanticEndpoint:
    existing.parameters = list(set(existing.parameters + new.parameters))
    existing.sources = list(set(existing.sources + new.sources))
    existing.evidence_refs = list(set(existing.evidence_refs + new.evidence_refs))
    existing.observed_identities = list(set(existing.observed_identities + new.observed_identities))
    if new.object_type and not existing.object_type:
        existing.object_type = new.object_type
    if new.authentication != "unknown" and existing.authentication == "unknown":
        existing.authentication = new.authentication
    return existing
