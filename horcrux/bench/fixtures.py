"""Deterministic synthetic benchmark fixtures (Phase 8, Part 30).

Twenty scenarios as synthetic WorkspaceState builders — no real external
targets, ever. Each fixture targets one benchmark dimension and ships with
golden expectations (see :mod:`horcrux.bench.golden`).
"""

from __future__ import annotations

from horcrux.models import (
    Credential,
    DiscoveredPath,
    NormalizedTechnology,
    Parameter,
    Service,
    TechCategory,
    WebApplicationType,
    WebTarget,
    WorkspaceState,
)


def _base(target: str, port: int = 3000) -> WorkspaceState:
    state = WorkspaceState(target=target)
    state.services = [Service(host=target, port=port, service="http",
                              product="Node.js", version="18.x")]
    return state


def _web(state: WorkspaceState, paths: list[str], params: list[Parameter] | None = None,
         app_type: WebApplicationType = WebApplicationType.SPA,
         techs: list[NormalizedTechnology] | None = None) -> WorkspaceState:
    t = state.target
    port = state.services[0].port if state.services else 3000
    state.discovered_paths = [DiscoveredPath(url=f"http://{t}:{port}{p}", path=p,
                                             status=200, source="javascript",
                                             validated=True) for p in paths]
    state.parameters = list(params or [])
    state.normalized_technologies = techs or [
        NormalizedTechnology(name="Express", category=TechCategory.FRAMEWORK, confidence=0.9)]
    state.web_targets = [WebTarget(scheme="http", host=t, port=port,
                                   base_url=f"http://{t}:{port}",
                                   application_type=app_type,
                                   endpoints=state.discovered_paths,
                                   technologies=state.normalized_technologies,
                                   parameters=state.parameters)]
    return state


def _param(name: str, location: str, endpoint: str, source: str = "javascript") -> Parameter:
    return Parameter(name=name, location=location, source=source, endpoint=endpoint)


def fx_bola() -> WorkspaceState:
    """1. BOLA: object retrieval + two identities' objects."""
    s = _web(_base("bench-bola.local"),
             ["/rest/user/login", "/rest/users/{id}", "/rest/basket/{id}"],
             [_param("id", "path", "/rest/users/{id}"),
              _param("basketId", "path", "/rest/basket/{id}"),
              _param("email", "body", "/rest/user/login")])
    s.credentials = [Credential(username="user-a", secret="synthetic",
                                kind="test-identity", source="bench")]
    return s


def fx_broken_auth() -> WorkspaceState:
    """2. Broken authentication: login/register/reset surfaces."""
    return _web(_base("bench-auth.local"),
                ["/login", "/register", "/reset", "/api/session"],
                [_param("email", "body", "/login", "form"),
                 _param("password", "body", "/login", "form")])


def fx_bfla() -> WorkspaceState:
    """3. Broken function-level authorization: admin endpoints + user identity."""
    s = _web(_base("bench-bfla.local"),
             ["/rest/user/login", "/api/profile", "/admin", "/admin/users"],
             [_param("email", "body", "/rest/user/login")])
    s.credentials = [Credential(username="lowpriv", secret="synthetic",
                                kind="test-identity", source="bench")]
    return s


def fx_privesc() -> WorkspaceState:
    """4. Privilege escalation: role endpoint + admin surface."""
    return _web(_base("bench-privesc.local"),
                ["/login", "/api/roles", "/admin", "/internal/metrics"],
                [_param("role", "body", "/api/roles")])


def fx_business_logic() -> WorkspaceState:
    """5. Business-logic flaw: cart -> checkout workflow."""
    return _web(_base("bench-blogic.local"),
                ["/login", "/rest/basket/{id}", "/rest/basket/1/checkout",
                 "/rest/orders/{id}"],
                [_param("basketId", "path", "/rest/basket/{id}"),
                 _param("coupon", "body", "/rest/basket/1/checkout")])


def fx_ssrf() -> WorkspaceState:
    """6. SSRF: external URL parameters."""
    return _web(_base("bench-ssrf.local"),
                ["/api/feedbacks", "/api/import", "/callback"],
                [_param("url", "query", "/api/import"),
                 _param("callback", "query", "/callback"),
                 _param("q", "query", "/api/feedbacks")])


def fx_injection() -> WorkspaceState:
    """7. Injection: search/filter/sort inputs."""
    return _web(_base("bench-injection.local"),
                ["/api/products", "/api/search"],
                [_param("q", "query", "/api/search"),
                 _param("filter", "query", "/api/products"),
                 _param("sort", "query", "/api/products")])


def fx_upload() -> WorkspaceState:
    """8. Unsafe file upload."""
    return _web(_base("bench-upload.local"),
                ["/login", "/upload", "/files/{id}"],
                [_param("file", "body", "/upload", "form")])


def fx_graphql_authz() -> WorkspaceState:
    """9. GraphQL authorization issue."""
    return _web(_base("bench-graphql.local"),
                ["/login", "/graphql"],
                [_param("query", "body", "/graphql")])


def fx_jwt() -> WorkspaceState:
    """10. JWT/session weakness."""
    s = _web(_base("bench-jwt.local"),
             ["/login", "/api/profile"],
             [_param("token", "header", "/api/profile")],
             techs=[NormalizedTechnology(name="jsonwebtoken", category=TechCategory.LIBRARY,
                                         confidence=0.9)])
    s.technologies = ["jsonwebtoken"]
    return s


def fx_data_exposure() -> WorkspaceState:
    """11. Sensitive data exposure: profile/export with PII params."""
    return _web(_base("bench-exposure.local"),
                ["/login", "/api/profile", "/api/export"],
                [_param("email", "query", "/api/profile"),
                 _param("ssn", "query", "/api/export"),
                 _param("phone", "query", "/api/profile")])


def fx_workflow_state() -> WorkspaceState:
    """12. Workflow/state flaw: multi-step order flow."""
    return _web(_base("bench-workflow.local"),
                ["/cart", "/cart/address", "/cart/payment", "/cart/confirm"],
                [_param("addressId", "body", "/cart/address"),
                 _param("paymentId", "body", "/cart/payment")])


def fx_multistep_path() -> WorkspaceState:
    """13. Multi-step attack path: login + objects + admin + workflow."""
    s = _web(_base("bench-chain.local"),
             ["/rest/user/login", "/rest/users/{id}", "/rest/basket/{id}",
              "/rest/basket/1/checkout", "/rest/admin"],
             [_param("id", "path", "/rest/users/{id}"),
              _param("email", "body", "/rest/user/login")])
    s.credentials = [Credential(username="user-a", secret="synthetic",
                                kind="test-identity", source="bench")]
    return s


def fx_contradictory() -> WorkspaceState:
    """14. Contradictory evidence: admin marked required yet anonymously seen."""
    s = _web(_base("bench-contradict.local"),
             ["/admin", "/api/profile"],
             [_param("id", "query", "/api/profile")])
    return s


def fx_tool_failure() -> WorkspaceState:
    """15. Tool failure: normal surface; runner will lack binaries."""
    return _web(_base("bench-toolfail.local"),
                ["/login", "/api/items"],
                [_param("q", "query", "/api/items")])


def fx_browser_failure() -> WorkspaceState:
    """16. Browser failure: SPA shell with no JS routes (empty bundles)."""
    s = _base("bench-browserfail.local")
    return _web(s, ["/"], [], WebApplicationType.SPA)


def fx_missing_capability() -> WorkspaceState:
    """17. Missing capability: ssh-only service, no web surface."""
    s = WorkspaceState(target="bench-nocap.local")
    s.services = [Service(host=s.target, port=22, service="ssh",
                          product="OpenSSH", version="8.9")]
    return s


def fx_ai_unavailable() -> WorkspaceState:
    """18. AI unavailable: rich surface assessed without any provider."""
    return fx_bola()


def fx_provider_refusal() -> WorkspaceState:
    """19. Provider refusal: rich surface; refusal simulated at call_task."""
    return fx_multistep_path()


def fx_operator_intervention() -> WorkspaceState:
    """20. Operator intervention: rich surface with pre-seeded focus/skip."""
    s = fx_multistep_path()
    s.target = "bench-operator.local"
    for svc in s.services:
        svc.host = s.target
    return s


FIXTURES: dict[str, Any] = {
    "bola": fx_bola,
    "broken_auth": fx_broken_auth,
    "bfla": fx_bfla,
    "privesc": fx_privesc,
    "business_logic": fx_business_logic,
    "ssrf": fx_ssrf,
    "injection": fx_injection,
    "upload": fx_upload,
    "graphql_authz": fx_graphql_authz,
    "jwt": fx_jwt,
    "data_exposure": fx_data_exposure,
    "workflow_state": fx_workflow_state,
    "multistep_path": fx_multistep_path,
    "contradictory": fx_contradictory,
    "tool_failure": fx_tool_failure,
    "browser_failure": fx_browser_failure,
    "missing_capability": fx_missing_capability,
    "ai_unavailable": fx_ai_unavailable,
    "provider_refusal": fx_provider_refusal,
    "operator_intervention": fx_operator_intervention,
}
