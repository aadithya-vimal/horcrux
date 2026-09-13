"""Evidence ingestion — maps reconnaissance output into ApplicationModel."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from horcrux.intel.application_model import (
    ApplicationModel,
    ApplicationProfile,
    AuthenticationMechanism,
    EvidenceSource,
    IdentityRole,
    SemanticEndpoint,
    SemanticForm,
    SemanticIdentity,
    SemanticPage,
    SemanticParameter,
    SemanticRoute,
    SemanticService,
    SemanticTechnology,
    SemanticWebTarget,
    ObjectType,
    ObjectReference,
    Workflow,
    WorkflowStep,
    fingerprint,
)
from horcrux.models import WebApplicationType

if TYPE_CHECKING:
    from horcrux.models import WorkspaceState

OBJECT_ID_PATTERNS = [
    re.compile(r"/(\w+)/\{(\w+)\}", re.I),
    re.compile(r"/(\w+)/:(\w+)", re.I),
    re.compile(r"/rest/(\w+)/\{(\w+)\}", re.I),
]

PRIVILEGED_PATH_KEYWORDS = {"admin", "management", "privileged", "roles", "system", "internal"}
AUTH_PATH_KEYWORDS = {"login", "register", "signin", "signup", "auth", "oauth", "reset", "logout"}
JWT_KEYWORDS = {"jwt", "bearer", "authorization"}


def ingest_workspace_state(state: WorkspaceState) -> ApplicationModel:
    """Full ingestion pass from WorkspaceState into ApplicationModel."""
    app = state.get_application_model()
    app.target = state.target

    _ingest_services(state, app)
    _ingest_web_targets(state, app)
    _ingest_technologies(state, app)
    _ingest_discovered_paths(state, app)
    _ingest_parameters(state, app)
    _ingest_authentication_surfaces(state, app)
    _ingest_identities(state, app)
    _infer_object_types(app)
    _infer_workflows(app)

    from datetime import datetime, timezone
    app.updated_at = datetime.now(timezone.utc)
    state.set_application_model(app)
    return app


def _ingest_services(state: WorkspaceState, app: ApplicationModel) -> None:
    existing = {(s.host, s.port): s for s in app.services}
    for svc in state.services:
        key = (svc.host or state.target, svc.port)
        is_web = svc.port in {80, 443, 8080, 8443, 3000, 8000} or svc.service.lower() in {"http", "https"}
        if key in existing:
            continue
        sem = SemanticService(
            host=svc.host or state.target,
            port=svc.port,
            protocol=svc.protocol,
            service_name=svc.service,
            product=svc.product,
            version=svc.version,
            is_web=is_web,
            evidence_refs=[f"nmap:{svc.port}/{svc.protocol}"],
        )
        sem.ensure_id()
        app.services.append(sem)
        if is_web:
            scheme = "https" if svc.port in {443, 8443} else "http"
            wt = SemanticWebTarget(
                scheme=scheme,
                host=sem.host,
                port=svc.port,
                base_url=f"{scheme}://{sem.host}:{svc.port}",
                evidence_refs=[sem.id],
            )
            wt.ensure_id()
            if not any(w.port == wt.port for w in app.web_targets):
                app.web_targets.append(wt)


def _ingest_web_targets(state: WorkspaceState, app: ApplicationModel) -> None:
    for wt in state.web_targets:
        sem_wt = next((w for w in app.web_targets if w.port == wt.port), None)
        if not sem_wt:
            sem_wt = SemanticWebTarget(
                scheme=wt.scheme,
                host=wt.host,
                port=wt.port,
                base_url=wt.base_url,
            )
            sem_wt.ensure_id()
            app.web_targets.append(sem_wt)

        app_type = wt.application_type.value if isinstance(wt.application_type, WebApplicationType) else str(wt.application_type)
        if app_type != "UNKNOWN":
            app.profile.app_type = app_type
            app.profile.confidence = max(app.profile.confidence, 0.85)
            app.profile.evidence_refs.append(f"web_target:{wt.port}")

        for tech in wt.technologies:
            _add_technology(app, tech.name, tech.category.value if hasattr(tech.category, "value") else str(tech.category), tech.version, EvidenceSource.FINGERPRINT.value)


def _ingest_technologies(state: WorkspaceState, app: ApplicationModel) -> None:
    for tech in state.normalized_technologies:
        cat = tech.category.value if hasattr(tech.category, "value") else str(tech.category)
        _add_technology(app, tech.name, cat, tech.version, EvidenceSource.FINGERPRINT.value)
        if cat == "FRAMEWORK" and not app.profile.framework:
            app.profile.framework = tech.name
        if cat == "RUNTIME" and not app.profile.runtime:
            app.profile.runtime = tech.name


def _add_technology(app: ApplicationModel, name: str, category: str, version: str, source: str) -> None:
    name_lower = name.lower()
    if any(t.name.lower() == name_lower for t in app.technologies):
        return
    tech = SemanticTechnology(name=name, category=category, version=version, sources=[source])
    app.technologies.append(tech)
    if "angular" in name_lower:
        app.profile.framework = "Angular"
        app.profile.app_type = app.profile.app_type if app.profile.app_type != "unknown" else "SPA"
    elif "react" in name_lower or "vue" in name_lower:
        app.profile.framework = name
        app.profile.app_type = app.profile.app_type if app.profile.app_type != "unknown" else "SPA"
    elif "express" in name_lower or "node" in name_lower:
        app.profile.runtime = "Node.js"


def _ingest_discovered_paths(state: WorkspaceState, app: ApplicationModel) -> None:
    for path in state.discovered_paths:
        route = SemanticRoute(
            path=path.path,
            source=path.source or EvidenceSource.FUZZER.value,
            evidence_refs=[path.url],
        )
        app.upsert_route(route)

        page = SemanticPage(
            url=path.url,
            path=path.path,
            status_code=path.status,
            evidence_refs=[path.url],
        )
        page.ensure_id()
        if not any(p.url == page.url for p in app.pages):
            app.pages.append(page)

        method = "GET"
        endpoint = SemanticEndpoint(
            method=method,
            path=path.path,
            sources=[path.source or EvidenceSource.FUZZER.value],
            evidence_refs=[path.url],
        )
        _enrich_endpoint_from_path(endpoint, path.path)
        app.upsert_endpoint(endpoint)


def _ingest_parameters(state: WorkspaceState, app: ApplicationModel) -> None:
    for param in state.parameters:
        sem = SemanticParameter(
            name=param.name,
            location=param.location,
            endpoint=param.endpoint,
            source=param.source,
            evidence_refs=[f"param:{param.name}@{param.endpoint}"],
        )
        sem.ensure_id()
        if not any(p.id == sem.id for p in app.parameters):
            app.parameters.append(sem)

        if param.endpoint:
            ep = SemanticEndpoint(
                method="GET",
                path=param.endpoint,
                parameters=[param.name],
                sources=[param.source],
            )
            app.upsert_endpoint(ep)


def _ingest_authentication_surfaces(state: WorkspaceState, app: ApplicationModel) -> None:
    for ep in app.endpoints:
        path_lower = ep.path.lower()
        if any(k in path_lower for k in AUTH_PATH_KEYWORDS):
            mech = AuthenticationMechanism(
                mechanism_type=_infer_auth_type(path_lower, state),
                login_endpoint=ep.path if "login" in path_lower or "signin" in path_lower else "",
                register_endpoint=ep.path if "register" in path_lower or "signup" in path_lower else "",
                reset_endpoint=ep.path if "reset" in path_lower else "",
                evidence_refs=ep.evidence_refs,
            )
            mech.ensure_id()
            if not any(a.login_endpoint == mech.login_endpoint and a.register_endpoint == mech.register_endpoint for a in app.authentication):
                app.authentication.append(mech)
            ep.authentication = "required" if "login" not in path_lower else "unknown"


def _infer_auth_type(path: str, state: WorkspaceState) -> str:
    if "oauth" in path:
        return "oauth"
    if any("jwt" in t.lower() for t in state.technologies):
        return "jwt"
    if any("jwt" in f.title.lower() for f in state.findings):
        return "jwt"
    return "session"


def _ingest_identities(state: WorkspaceState, app: ApplicationModel) -> None:
    app.upsert_identity(SemanticIdentity(role=IdentityRole.ANONYMOUS, label="anonymous"))
    if state.credentials:
        app.upsert_identity(SemanticIdentity(role=IdentityRole.USER, label="authenticated_user"))
    for ep in app.endpoints:
        if "admin" in ep.path.lower():
            ep.observed_identities.append(IdentityRole.ADMIN.value)
        elif ep.authentication == "required":
            ep.observed_identities.append(IdentityRole.USER.value)
        else:
            ep.observed_identities.append(IdentityRole.ANONYMOUS.value)


def _enrich_endpoint_from_path(endpoint: SemanticEndpoint, path: str) -> None:
    path_lower = path.lower()
    for pattern in OBJECT_ID_PATTERNS:
        m = pattern.search(path)
        if m:
            obj_name = m.group(1).rstrip("s").capitalize()
            endpoint.object_type = obj_name
            param = m.group(2)
            if param not in endpoint.parameters:
                endpoint.parameters.append(param)
            break
    if any(k in path_lower for k in PRIVILEGED_PATH_KEYWORDS):
        endpoint.authentication = "required"
    if any(k in path_lower for k in AUTH_PATH_KEYWORDS):
        endpoint.authentication = "unknown"


def _infer_object_types(app: ApplicationModel) -> None:
    for ep in app.endpoints:
        if ep.object_type:
            obj = ObjectType(
                name=ep.object_type,
                endpoints=[ep.id],
                parameter_names=ep.parameters,
                evidence_refs=ep.evidence_refs,
            )
            app.upsert_object_type(obj)
            ref = ObjectReference(
                object_type=ep.object_type,
                endpoint_id=ep.id,
                parameter=ep.parameters[0] if ep.parameters else "",
                evidence_refs=ep.evidence_refs,
            )
            ref.ensure_id()
            if not any(r.id == ref.id for r in app.object_references):
                app.object_references.append(ref)


def _infer_workflows(app: ApplicationModel) -> None:
    auth_eps = [e for e in app.endpoints if any(k in e.path.lower() for k in AUTH_PATH_KEYWORDS)]
    if not auth_eps:
        return
    steps: list[WorkflowStep] = []
    for ep in sorted(auth_eps, key=lambda e: e.path):
        step_name = ep.path.split("/")[-1] or ep.path
        steps.append(
            WorkflowStep(
                name=step_name,
                method=ep.method,
                path=ep.path,
                identity="anonymous",
                evidence_refs=ep.evidence_refs,
            )
        )
    if len(steps) >= 2:
        wf = Workflow(name="Authentication Flow", steps=steps)
        wf.ensure_id()
        if not any(w.name == wf.name for w in app.workflows):
            app.workflows.append(wf)


def ingest_javascript_routes(
    app: ApplicationModel,
    routes: list[str],
    parameters: list,
    source: str = "javascript",
) -> None:
    """Ingest JS-analyzed routes into application model."""
    for route in routes:
        path = route if route.startswith("/") else f"/{route}"
        sem_route = SemanticRoute(path=path, source=source, evidence_refs=[f"js:{path}"])
        app.upsert_route(sem_route)
        ep = SemanticEndpoint(method="GET", path=path, sources=[source], evidence_refs=[f"js:{path}"])
        _enrich_endpoint_from_path(ep, path)
        app.upsert_endpoint(ep)

    for param in parameters:
        name = param.name if hasattr(param, "name") else str(param)
        endpoint = param.endpoint if hasattr(param, "endpoint") else ""
        sem = SemanticParameter(
            name=name,
            location=getattr(param, "location", "query"),
            endpoint=endpoint,
            source=source,
            evidence_refs=[f"js:param:{name}"],
        )
        sem.ensure_id()
        if not any(p.id == sem.id for p in app.parameters):
            app.parameters.append(sem)


def ingest_http_request(
    app: ApplicationModel,
    method: str,
    path: str,
    identity: str = "anonymous",
    parameters: list[str] | None = None,
    source: str = "proxy",
) -> SemanticEndpoint:
    """Ingest proxy/browser HTTP observation."""
    ep = SemanticEndpoint(
        method=method.upper(),
        path=path,
        parameters=parameters or [],
        sources=[source],
        evidence_refs=[f"{source}:{method}:{path}"],
        observed_identities=[identity],
    )
    _enrich_endpoint_from_path(ep, path)
    result = app.upsert_endpoint(ep)

    if any(k in path.lower() for k in ("login", "register")):
        step = WorkflowStep(
            name=path.split("/")[-1],
            method=method.upper(),
            path=path,
            identity=identity,
            state_transition="authenticated" if "login" in path.lower() else "registered",
            evidence_refs=[f"{source}:{method}:{path}"],
        )
        step.ensure_id()
        wf_name = "Authentication Flow"
        existing = next((w for w in app.workflows if w.name == wf_name), None)
        if existing:
            if not any(s.path == step.path for s in existing.steps):
                existing.steps.append(step)
        else:
            wf = Workflow(name=wf_name, steps=[step])
            wf.ensure_id()
            app.workflows.append(wf)

    return result
