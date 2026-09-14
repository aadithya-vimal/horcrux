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
    # --- Phase 8 behavior model ---
    ingest_object_lifecycles(app)
    ingest_workflow_transitions(app)
    ingest_api_operations(app)

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
            param_class=classify_parameter(param.name, param.location, param.endpoint),
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


MUTATION_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
STATE_CHANGING_KEYWORDS = {"checkout", "payment", "order", "transfer", "delete",
                           "update", "create", "register", "reset", "invite",
                           "approve", "upload", "purchase", "refund", "cancel"}
VERSION_PATTERN = re.compile(r"^/(v\d+|api/v\d+)/", re.I)


def classify_parameter(name: str, location: str = "", endpoint: str = "") -> str:
    """Parameter class for API reasoning (Part 9)."""
    n = (name or "").lower()
    if n in {"id"} or n.endswith("id") or n.endswith("_id"):
        return "object_id"
    if n in {"page", "limit", "offset", "per_page", "cursor"}:
        return "pagination"
    if n in {"filter", "sort", "order", "q", "query", "search", "fields"}:
        return "filtering"
    if n in {"url", "target", "callback", "webhook", "import", "redirect",
             "fetch", "src", "next", "return_url"}:
        return "url_fetch"
    if n in {"file", "upload", "avatar", "attachment", "document"}:
        return "file"
    if n in {"email", "password", "token", "code", "otp"}:
        return "auth_credential"
    if location == "path":
        return "object_id"
    return "general"


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
    # --- Phase 8 behavior semantics ---
    if endpoint.method.upper() in MUTATION_METHODS or \
            any(k in path_lower for k in STATE_CHANGING_KEYWORDS):
        endpoint.is_mutation = True
    vm = VERSION_PATTERN.match(path)
    if vm:
        endpoint.api_version = vm.group(1).lower()


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


# ---------------------------------------------------------------------------
# Phase 7: full evidence-source coverage. Every function is idempotent
# (stable IDs + dedup) and records provenance via sources/evidence_refs.
# ---------------------------------------------------------------------------

def ingest_crawler_paths(app: ApplicationModel, paths: list, source: str = "crawler") -> int:
    """Web crawler/discovery output -> routes + endpoints + pages."""
    count = 0
    for p in paths or []:
        path = p.path if hasattr(p, "path") else str(p.get("path", "/") if isinstance(p, dict) else p)
        url = p.url if hasattr(p, "url") else (p.get("url", "") if isinstance(p, dict) else "")
        status = int(getattr(p, "status", p.get("status", 0) if isinstance(p, dict) else 0) or 0)
        route = SemanticRoute(path=path, source=source, evidence_refs=[url or f"{source}:{path}"])
        app.upsert_route(route)
        ep = SemanticEndpoint(method="GET", path=path, sources=[source],
                              evidence_refs=[url or f"{source}:{path}"])
        _enrich_endpoint_from_path(ep, path)
        app.upsert_endpoint(ep)
        count += 1
    _infer_object_types(app)
    return count


def ingest_api_discovery(app: ApplicationModel, endpoints: list,
                         source: str = "api_discovery") -> int:
    """API discovery (OpenAPI/Swagger/GraphQL schema) -> endpoints + params."""
    count = 0
    for e in endpoints or []:
        if isinstance(e, dict):
            path, method = e.get("path", "/"), e.get("method", "GET")
            params = e.get("parameters", [])
        else:
            path, method, params = getattr(e, "path", "/"), getattr(e, "method", "GET"), []
        ep = SemanticEndpoint(method=str(method).upper(), path=str(path),
                              parameters=list(params or []), sources=[source],
                              evidence_refs=[f"{source}:{method}:{path}"])
        _enrich_endpoint_from_path(ep, str(path))
        app.upsert_endpoint(ep)
        for pname in (params or []):
            sem = SemanticParameter(name=str(pname), location="query",
                                    endpoint=str(path), source=source,
                                    evidence_refs=[f"{source}:param:{pname}"])
            sem.ensure_id()
            if not any(p.id == sem.id for p in app.parameters):
                app.parameters.append(sem)
        count += 1
    _infer_object_types(app)
    return count


def ingest_auth_observation(app: ApplicationModel, mechanism_type: str,
                            login_endpoint: str = "", evidence: str = "",
                            source: str = "auth_probe") -> AuthenticationMechanism:
    mech = AuthenticationMechanism(mechanism_type=mechanism_type or "unknown",
                                   login_endpoint=login_endpoint or "",
                                   evidence_refs=[evidence or f"{source}:{login_endpoint}"])
    mech.ensure_id()
    if not any(a.id == mech.id for a in app.authentication):
        app.authentication.append(mech)
    app.upsert_identity(SemanticIdentity(
        role=IdentityRole.USER if login_endpoint else IdentityRole.ANONYMOUS,
        label="authenticated_user" if login_endpoint else "anonymous",
        session_evidence=[evidence or source]))
    return mech


def ingest_identity_observation(app: ApplicationModel, role: str, label: str,
                                evidence: str = "", endpoints: list[str] | None = None) -> None:
    try:
        r = IdentityRole(role)
    except ValueError:
        r = IdentityRole.USER
    app.upsert_identity(SemanticIdentity(role=r, label=label,
                                         session_evidence=[evidence or "identity"],
                                         observed_endpoints=list(endpoints or [])))


def ingest_technology_fingerprint(app: ApplicationModel, technologies: list,
                                  source: str = "fingerprint") -> int:
    count = 0
    for t in technologies or []:
        name = t.name if hasattr(t, "name") else str(t.get("name", t) if isinstance(t, dict) else t)
        category = ""
        version = ""
        if hasattr(t, "category"):
            category = t.category.value if hasattr(t.category, "value") else str(t.category)
            version = getattr(t, "version", "")
        elif isinstance(t, dict):
            category, version = t.get("category", ""), t.get("version", "")
        if not name:
            continue
        _add_technology(app, str(name), str(category or "unknown"), str(version or ""), source)
        count += 1
    return count


def ingest_nuclei_findings(app: ApplicationModel, findings: list,
                           source: str = "nuclei") -> int:
    """Nuclei findings -> technologies/endpoints/boundaries (never raw dump)."""
    count = 0
    for f in findings or []:
        title = f.title if hasattr(f, "title") else str(f.get("title", "") if isinstance(f, dict) else f)
        asset = f.affected_asset if hasattr(f, "affected_asset") else (f.get("asset", "") if isinstance(f, dict) else "")
        path = asset.split("://")[-1].split("/", 1)[-1] if "://" in asset else asset
        path = "/" + path.lstrip("/") if path else "/"
        ep = SemanticEndpoint(method="GET", path=path[:128], sources=[source],
                              evidence_refs=[f"{source}:{title[:60]}"])
        _enrich_endpoint_from_path(ep, ep.path)
        app.upsert_endpoint(ep)
        count += 1
    return count


def ingest_fuzz_paths(app: ApplicationModel, paths: list, source: str = "fuzzer") -> int:
    return ingest_crawler_paths(app, paths, source=source)


def ingest_endpoint_validation(app: ApplicationModel, path: str, validation_state: str,
                               confidence: float = 0.8, evidence: str = "",
                               source: str = "validator") -> None:
    ep = SemanticEndpoint(method="GET", path=path, sources=[source],
                          evidence_refs=[evidence or f"{source}:{path}:{validation_state}"])
    _enrich_endpoint_from_path(ep, path)
    merged = app.upsert_endpoint(ep)
    merged.evidence_refs = list(set(merged.evidence_refs + [f"{source}:{validation_state}"]))


def ingest_service_enumeration(app: ApplicationModel, protocol: str,
                               raw: Any, host: str = "", port: int = 0,
                               source: str = "service_enum") -> int:
    """Protocol enumeration -> semantic service facts + model updates."""
    from horcrux.intel.service_semantics import PROTOCOL_CONVERTERS, ingest_service_facts
    conv = PROTOCOL_CONVERTERS.get((protocol or "").lower())
    if conv is None:
        return 0
    try:
        import inspect
        kwargs: dict[str, Any] = {"host": host}
        sig = inspect.signature(conv)
        if "port" in sig.parameters:
            kwargs["port"] = port
        if "raw" in sig.parameters:
            facts = conv(raw, **kwargs)
        else:
            facts = conv(str(raw), **kwargs)
    except Exception:
        facts = []
    n = ingest_service_facts(app, facts, source=f"{source}:{protocol}")
    # Also persist structured ServiceFacts with provenance.
    try:
        from horcrux.intel.application_model import ServiceFact
        for fact in facts or []:
            app.upsert_service_fact(ServiceFact(
                protocol=str(fact.get("protocol", protocol)),
                fact_type=str(fact.get("fact_type", "")),
                name=str(fact.get("name", fact.get("observation", fact.get("naming_context", ""))))[:80],
                details={k: v for k, v in fact.items() if k not in ("fact_type",)},
                evidence_refs=[fact.get("evidence", source)],
                provenance=[source, protocol]))
    except Exception:
        pass
    return n


def ingest_capability_evidence(app: ApplicationModel, capability_id: str,
                               evidence: list[dict]) -> int:
    """Normalize capability evidence items into the ApplicationModel."""
    count = 0
    for item in evidence or []:
        etype = item.get("evidence_type", "")
        data = item.get("data", {}) or {}
        source = item.get("source", capability_id)
        try:
            if etype == "endpoint_observation":
                ingest_http_request(app, method=data.get("method", "GET"),
                                    path=data.get("path", "/"),
                                    identity=data.get("identity", "anonymous"),
                                    parameters=data.get("parameters"),
                                    source=source)
                count += 1
            elif etype == "route_discovery":
                ingest_crawler_paths(app, [data.get("path", "/")], source=source)
                count += 1
            elif etype in ("parameter_observation",):
                pname = data.get("parameter", data.get("name", ""))
                if pname:
                    sem = SemanticParameter(name=str(pname), location="query",
                                            endpoint=str(data.get("endpoint", "")),
                                            source=source,
                                            evidence_refs=[f"{source}:param:{pname}"])
                    sem.ensure_id()
                    if not any(p.id == sem.id for p in app.parameters):
                        app.parameters.append(sem)
                    count += 1
            elif etype in ("technology_observation",):
                ingest_technology_fingerprint(app, [data.get("name", "")], source=source)
                count += 1
            elif etype in ("identity_context", "auth_observation"):
                ingest_identity_observation(
                    app, "user" if data.get("to_identity", "user") != "anonymous" else "anonymous",
                    data.get("to_identity", data.get("identity", "observed")),
                    evidence=f"{source}", endpoints=None)
                count += 1
            elif etype in ("authorization_observation", "graphql_observation",
                           "graphql_operation", "validation_result", "nuclei_finding",
                           "browser_observation", "form_observation", "service_observation",
                           "workflow_observation", "object_observation", "comparison",
                           "console_observation"):
                # Endpoint-anchored generic evidence.
                path = data.get("path", data.get("endpoint", "/"))
                ingest_http_request(app, method="GET", path=str(path),
                                    identity="anonymous", source=source)
                count += 1
            elif etype in ("client_state_observation",):
                key = str(data.get("key", ""))
                if key:
                    sem = SemanticParameter(name=key, location="client_state",
                                            endpoint="", source=source,
                                            evidence_refs=[f"{source}:client-state:{key}"],
                                            param_class="client_state")
                    sem.ensure_id()
                    if not any(p.id == sem.id for p in app.parameters):
                        app.parameters.append(sem)
                    count += 1
            elif etype in ("smb_share", "directory_fact", "identity_observation",
                           "mail_capability", "dns_record", "snmp_fact",
                           "service_observation", "exploit_intelligence"):
                from horcrux.intel.service_semantics import ingest_service_facts
                ingest_service_facts(app, [{"fact_type": "service_fact",
                                            "protocol": source,
                                            "observation": str(data)[:120]}], source=source)
                count += 1
        except Exception:
            continue
    _infer_object_types(app)
    return count


def normalize_evidence_item(raw: Any, default_source: str = "unknown") -> dict:
    """Coerce arbitrary tool output into {evidence_type, data, source, confidence}."""
    if isinstance(raw, dict) and "evidence_type" in raw:
        return raw
    if isinstance(raw, dict):
        return {"evidence_type": "generic_observation", "data": raw,
                "source": raw.get("source", default_source), "confidence": 0.5}
    return {"evidence_type": "generic_observation", "data": {"value": str(raw)},
            "source": default_source, "confidence": 0.5}


# ---------------------------------------------------------------------------
# Phase 8: application behavior model (Parts 5, 6, 9, 10, 11)
# ---------------------------------------------------------------------------

def _normalize_api_path(path: str) -> str:
    """Collapse concrete ids to {id} so browser+JS+HTTP+fuzzer deduplicate."""
    out = re.sub(r"/\d+(?=/|$)", "/{id}", path)
    out = re.sub(r"/[0-9a-f]{8,}(?=/|$)", "/{id}", out, flags=re.I)
    return out


def ingest_object_lifecycles(app: ApplicationModel,
                             source: str = "inference") -> int:
    """Build per-object lifecycles from endpoint operations (Part 6)."""
    from horcrux.intel.application_model import ObjectLifecycle
    count = 0
    by_object: dict[str, list] = {}
    for ep in app.endpoints:
        if ep.object_type:
            by_object.setdefault(ep.object_type, []).append(ep)
    for obj_type, eps in by_object.items():
        lc = ObjectLifecycle(object_type=obj_type)
        for ep in eps:
            method = ep.method.upper()
            if method == "GET":
                if ep.path not in lc.read_endpoints:
                    lc.read_endpoints.append(ep.path)
            elif method == "DELETE":
                if ep.path not in lc.delete_endpoints:
                    lc.delete_endpoints.append(ep.path)
            else:
                if ep.path not in lc.mutation_endpoints:
                    lc.mutation_endpoints.append(ep.path)
            for ident in ep.observed_identities:
                if ident not in lc.observed_identities:
                    lc.observed_identities.append(ident)
            lc.evidence_refs.extend(ep.evidence_refs[:2])
            for src in ep.sources:
                if src not in lc.provenance:
                    lc.provenance.append(src)
        # Identifier pattern from representative path.
        rep = eps[0].path
        m = re.search(r"/(\d+)", rep)
        lc.identifier_pattern = "{id}" if m or "{" in rep else ""
        lc.identifier = m.group(1) if m else lc.identifier_pattern
        if source not in lc.provenance:
            lc.provenance.append(source)
        app.upsert_object_lifecycle(lc)
        count += 1
    return count


def ingest_workflow_transitions(app: ApplicationModel,
                                source: str = "inference") -> int:
    """Derive explicit workflow transitions incl. checkout-style flows (Part 5)."""
    from horcrux.intel.application_model import WorkflowTransition
    count = 0
    # From declared workflows: chain consecutive steps.
    for wf in app.workflows:
        steps = wf.steps
        for idx, step in enumerate(steps):
            prev = steps[idx - 1].name if idx > 0 else "START"
            tr = WorkflowTransition(
                workflow=wf.name, from_state=prev, to_state=step.name,
                trigger=f"{step.method} {step.path}", endpoint=step.path,
                method=step.method, identity=step.identity,
                preconditions=[f"reach:{prev}"] if idx > 0 else [],
                postconditions=[f"state:{step.state_transition}"] if step.state_transition else [],
                state_changing=step.method.upper() in MUTATION_METHODS,
                evidence_refs=list(step.evidence_refs),
                provenance=[source])
            app.upsert_transition(tr)
            count += 1
    # Checkout-style inference from endpoint naming (marked inference).
    flow_keywords = ["cart", "basket", "address", "payment", "checkout",
                     "order", "confirm"]
    chain = [e for e in app.endpoints
             if any(k in e.path.lower() for k in flow_keywords)]
    if len(chain) >= 2:
        ordered = sorted(chain, key=lambda e: e.path)
        prev = "START"
        name = "CheckoutWorkflow"
        for ep in ordered:
            tr = WorkflowTransition(
                workflow=name, from_state=prev, to_state=ep.path,
                trigger=f"{ep.method} {ep.path}", endpoint=ep.path,
                method=ep.method, identity=(ep.observed_identities or ["anonymous"])[0],
                preconditions=[f"reach:{prev}"] if prev != "START" else [],
                postconditions=[],
                state_changing=bool(ep.is_mutation),
                evidence_refs=list(ep.evidence_refs[:2]),
                provenance=[source])
            if not any(t.id == tr.ensure_id() for t in app.workflow_transitions):
                app.upsert_transition(tr)
                count += 1
            prev = ep.path
    return count


def ingest_api_operations(app: ApplicationModel, source: str = "inference") -> int:
    """Correlate endpoint evidence into deduplicated API operations (Part 9)."""
    from horcrux.intel.application_model import APIOperation
    count = 0
    grouped: dict[str, list] = {}
    for ep in app.endpoints:
        key = f"{ep.method.upper()} {_normalize_api_path(ep.path)}"
        grouped.setdefault(key, []).append(ep)
    for (method_path, eps) in grouped.items():
        method, norm_path = method_path.split(" ", 1)
        first = eps[0]
        param_classes = sorted({classify_parameter(p) for e in eps for p in e.parameters})
        op = APIOperation(
            method=method, path=norm_path,
            version=first.api_version,
            parameter_classes=param_classes,
            supports_methods=sorted({e.method.upper() for e in eps}),
            is_mutation=any(e.is_mutation for e in eps),
            is_bulk="bulk" in norm_path.lower() or "batch" in norm_path.lower(),
            object_type=first.object_type,
            evidence_refs=list({r for e in eps for r in e.evidence_refs[:2]}),
            provenance=sorted({s for e in eps for s in e.sources} or [source]))
        app.upsert_api_operation(op)
        count += 1
    return count


GRAPHQL_OP_PATTERN = re.compile(
    r"(query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)\s*[\(\{]", re.I)
GRAPHQL_FIELD_PATTERN = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*[\(\{:]", re.M)


def ingest_graphql_operations(app: ApplicationModel, texts: list[str] | None = None,
                              endpoint: str = "/graphql",
                              source: str = "javascript") -> int:
    """Parse GraphQL schema/JS/traffic evidence into operations (Part 10)."""
    from horcrux.intel.application_model import GraphQLOperation
    count = 0
    gql_eps = [e.path for e in app.endpoints if "graphql" in e.path.lower()]
    ep = gql_eps[0] if gql_eps else endpoint
    corpus: list[str] = list(texts or [])
    # Also harvest from JS-derived parameters that look like operation names.
    for p in app.parameters:
        if p.source in ("javascript", "graphql") and re.match(r"^[A-Z][A-Za-z0-9]+$", p.name):
            corpus.append(f"query {p.name} {{ id }}")
    for text in corpus:
        for m in GRAPHQL_OP_PATTERN.finditer(text or ""):
            kind, name = m.group(1).lower(), m.group(2)
            fields = GRAPHQL_FIELD_PATTERN.findall(text[m.end():m.end() + 800])[:20]
            obj_types = [f.capitalize() for f in fields[:5]
                         if f.lower() not in ("id", "edges", "node", "pageinfo")]
            op = GraphQLOperation(kind=kind, name=name, object_types=obj_types,
                                  fields=fields[:20], endpoint=ep,
                                  evidence_refs=[f"{source}:gql:{name}"],
                                  provenance=[source])
            app.upsert_graphql_operation(op)
            count += 1
    # Schema-presence marker when endpoint exists but no operations parsed.
    if gql_eps and not app.graphql_operations:
        op = GraphQLOperation(kind="query", name="__schema_probe",
                              endpoint=gql_eps[0],
                              evidence_refs=[f"{source}:endpoint:{gql_eps[0]}"],
                              provenance=[source])
        app.upsert_graphql_operation(op)
        count += 1
    return count


SECRET_PATTERNS = [
    (re.compile(r"(?i)\b(api[_-]?key|apikey)\b\s*[:=]\s*['\"]?([A-Za-z0-9_\-./+=]{8,})"), "api_key"),
    (re.compile(r"(?i)\b(secret|client_secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9_\-./+=]{8,})"), "secret"),
    (re.compile(r"(?i)\b(db[_-]?password|password)\b\s*[:=]\s*['\"]?([^'\"\s]{6,})"), "password"),
    (re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"), "jwt"),
]
SOURCEMAP_PATTERN = re.compile(r"//# sourceMappingURL=(\S+)", re.I)
DOM_SINK_PATTERNS = [r"\.innerHTML\s*=", r"document\.write\s*\(", r"eval\s*\(",
                     r"new\s+Function\s*\(", r"\.outerHTML\s*="]
DANGEROUS_PATTERNS = [r"localStorage\s*\.\s*setItem", r"sessionStorage",
                      r"postMessage\s*\(", r"location\.hash"]
TOKEN_PATTERNS = [r"localStorage\s*\[\s*['\"]token", r"Authorization['\"]?\s*:",
                  r"Bearer\s+[A-Za-z0-9_\-\.]+", r"\.jwt\b"]


def ingest_client_side(app: ApplicationModel, js_text: str,
                       source_name: str = "", source: str = "javascript") -> dict[str, Any]:
    """Client-side semantic extraction (Part 11).

    Produces typed evidence only — raw JS is never stored and must never be
    dumped into LLM context. Secrets are recorded as redacted observations.
    """
    from horcrux.modules.web.js_analyzer import analyze_javascript_content
    findings: dict[str, Any] = {"routes": [], "parameters": [],
                                "secrets": [], "sourcemaps": [],
                                "client_state": [], "dom_sinks": [],
                                "dangerous": [], "token_handling": []}
    try:
        parsed = analyze_javascript_content(js_text or "", source_name=source_name)
    except Exception:
        parsed = {"routes": [], "parameters": []}
    findings["routes"] = parsed.get("routes", [])
    findings["parameters"] = parsed.get("parameters", [])
    if findings["routes"]:
        ingest_javascript_routes(app, findings["routes"],
                                 findings["parameters"], source=source)
    for pat, kind in SECRET_PATTERNS:
        if pat.search(js_text or ""):
            findings["secrets"].append({"kind": kind, "redacted": True,
                                        "source_asset": source_name})
    for m in SOURCEMAP_PATTERN.finditer(js_text or ""):
        findings["sourcemaps"].append(m.group(1).rstrip(";")[:160])
    for pat in DOM_SINK_PATTERNS:
        if re.search(pat, js_text or ""):
            findings["dom_sinks"].append(pat)
    for pat in DANGEROUS_PATTERNS:
        if re.search(pat, js_text or ""):
            findings["dangerous"].append(pat)
    for pat in TOKEN_PATTERNS:
        if re.search(pat, js_text or ""):
            findings["token_handling"].append(pat)
    client_keys = set(re.findall(r"localStorage\s*(?:\[\s*['\"]([\w\-]+)|"
                                 r"\.\s*setItem\s*\(\s*['\"]([\w\-]+))", js_text or ""))
    findings["client_state"] = sorted({k for pair in client_keys for k in pair if k})[:20]
    # Persist typed observations as parameters with client_state class.
    for key in findings["client_state"]:
        sem = SemanticParameter(name=key, location="client_state",
                                endpoint=source_name, source=source,
                                evidence_refs=[f"{source}:client-state:{key}"],
                                param_class="client_state")
        sem.ensure_id()
        if not any(p.id == sem.id for p in app.parameters):
            app.parameters.append(sem)
    return findings
