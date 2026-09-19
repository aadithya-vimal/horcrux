"""Central security test-definition registry and applicability matrix.

Provides deterministic derivation of applicable security test cases from the
discovered ApplicationModel and WorkspaceState (Phases B and C).
"""

from __future__ import annotations

__test__ = False

import re
from enum import Enum
from typing import Any, TYPE_CHECKING
from urllib.parse import urlparse
from pydantic import BaseModel, Field

from horcrux.intel.application_model import ApplicationModel, fingerprint
from horcrux.intel.investigations import (
    Investigation,
    InvestigationScore,
    InvestigationState,
)
from horcrux.intel.parameters import (
    ParameterSemanticRole,
    classify_parameter,
    is_static_asset_endpoint,
)

if TYPE_CHECKING:
    from horcrux.models import WorkspaceState


class TestFamily(str, Enum):
    __test__ = False
    BOLA_IDOR = "bola_idor"
    AUTHZ_HORIZONTAL = "authz_horizontal"
    AUTHZ_VERTICAL = "authz_vertical"
    AUTH_ENFORCEMENT = "auth_enforcement"
    API_SECURITY = "api_security"
    PARAM_SQLI = "param_sqli"
    PARAM_CMDI = "param_cmdi"
    PARAM_TRAVERSAL = "param_traversal"
    PARAM_SSRF = "param_ssrf"
    PARAM_XSS = "param_xss"
    FILE_UPLOAD = "file_upload"
    GRAPHQL_INTROSPECTION = "graphql_introspection"
    GRAPHQL_AUTHZ = "graphql_authz"
    WORKFLOW_STATE = "workflow_state"
    WORKFLOW_TAMPERING = "workflow_tampering"
    CONFIG_EXPOSURE = "config_exposure"
    SERVICE_EXPLOIT_INTEL = "service_exploit_intel"


class SecurityTestCase(BaseModel):
    """A concrete security test bound to a specific application asset."""

    __test__ = False


    id: str = ""
    family: TestFamily
    name: str
    asset_id: str
    asset_type: str  # endpoint, parameter, object, workflow, service
    target_path: str = ""
    target_method: str = "GET"
    target_parameter: str = ""
    specialist: str = "WebAgent"
    candidate_tools: list[str] = Field(default_factory=list)
    required_capabilities: list[str] = Field(default_factory=list)
    prerequisites: list[str] = Field(default_factory=list)
    vulnerability_classes: list[str] = Field(default_factory=list)
    priority: float = 0.5
    state: str = "PENDING"
    result_summary: str = ""
    evidence_refs: list[str] = Field(default_factory=list)
    # --- Explicit executable-test contract (no silent skipping) ---
    applicability: str = ""
    execution_input: dict[str, Any] = Field(default_factory=dict)
    evidence_requirements: list[str] = Field(default_factory=list)
    adjudication_rule: str = ""
    terminal_states: list[str] = Field(default_factory=list)

    def ensure_id(self) -> str:
        if not self.id:
            self.id = fingerprint(
                "tc",
                self.family.value,
                self.asset_type,
                self.target_method,
                self.target_path,
                self.target_parameter,
            )
        return self.id


# Instance-identifier match on a NORMALIZED path only (never on scheme/host,
# so 127.0.0.1 octets can never read as "/1"). Collections such as
# GET /api/Products are not instance references.
_INSTANCE_ID_RE = re.compile(r"/\d+(?=/|$|\?|#)")
_UUID_RE = re.compile(r"/[0-9a-fA-F-]{36}(?=/|$|\?|#)")
_HEXKEY_RE = re.compile(r"/[0-9a-fA-F]{16,32}(?=/|$|\?|#)")


def normalize_matrix_path(p: str) -> str:
    """Strip scheme/host, enforce leading slash. Never returns an absolute URL."""
    if not p:
        return "/"
    if p.startswith(("http://", "https://")):
        p = urlparse(p).path or "/"
    # Guard against doubly-prefixed garbage ("http://h/http://h/x").
    if "http://" in p or "https://" in p:
        p = "/" + p.split("://")[-1].split("/", 1)[-1] if "/" in p.split("://")[-1] else "/"
    if not p.startswith("/"):
        p = "/" + p
    return p or "/"


def path_has_instance_id(path: str) -> bool:
    """True only for instance-level references: /1, /{id}, /:id, UUID/hex."""
    p = normalize_matrix_path(path)
    if "{" in p and "}" in p:
        return True
    if "/:" in p:
        return True
    return bool(
        _INSTANCE_ID_RE.search(p) or _UUID_RE.search(p) or _HEXKEY_RE.search(p)
    )


def derive_applicable_tests(
    app: ApplicationModel,
    state: Any | None = None,
) -> list[SecurityTestCase]:
    """Derive all applicable security test cases from the current application model."""
    test_cases: list[SecurityTestCase] = []
    seen_ids: set[str] = set()

    def _normalize_path(p: str) -> str:
        return normalize_matrix_path(p)

    def _add(tc: SecurityTestCase) -> None:
        _contract_for(tc)
        tc.ensure_id()
        if tc.id not in seen_ids:
            seen_ids.add(tc.id)
            test_cases.append(tc)

    def _contract_for(tc: SecurityTestCase) -> None:
        contracts: dict[str, tuple[str, list[str], str]] = {
            TestFamily.BOLA_IDOR.value: (
                "endpoint carries an instance-level object reference (/1, {id}, :id, UUID)",
                ["authorization_observation: anonymous vs authenticated status + cross-identity object access"],
                "gap on private tenant entity -> SUPPORTED; public catalog/collection -> REFUTED; needs 2nd identity -> REQUIRES_SECOND_IDENTITY",
            ),
            TestFamily.AUTHZ_HORIZONTAL.value: (
                "instance-level endpoint + two supplied access contexts",
                ["comparison: identity A vs identity B on shared object"],
                "divergent private access -> SUPPORTED; enforced -> REFUTED; missing 2nd context -> REQUIRES_SECOND_IDENTITY",
            ),
            TestFamily.AUTHZ_VERTICAL.value: (
                "administrative/privileged endpoint present",
                ["http_probe/authz_compare: anonymous vs user vs admin status"],
                "anonymous/user reaches admin surface -> SUPPORTED; 401/403 -> REFUTED",
            ),
            TestFamily.AUTH_ENFORCEMENT.value: (
                "endpoint requires authentication or is state-changing",
                ["http_probe: unauthenticated status code"],
                "200 with protected content -> SUPPORTED; 401/403 -> REFUTED",
            ),
            TestFamily.API_SECURITY.value: (
                "REST/API endpoint present",
                ["api_probe: excessive-data / mass-assignment / method-tampering semantics"],
                "sensitive fields or accepted privileged field -> SUPPORTED; clean -> REFUTED",
            ),
            TestFamily.PARAM_SQLI.value: (
                "semantic input parameter (search/object/user/sort/query/body)",
                ["param_fuzz differential: baseline vs quote/time payloads + DB error signatures"],
                "DB/framework error or time differential -> SUPPORTED; sanitized -> REFUTED",
            ),
            TestFamily.PARAM_CMDI.value: (
                "semantic input parameter reachable via query/body",
                ["param_fuzz differential: command-separator payloads + output reflection"],
                "command output reflected -> SUPPORTED; neutral -> REFUTED/INSUFFICIENT",
            ),
            TestFamily.PARAM_TRAVERSAL.value: (
                "file-path or search parameter",
                ["param_fuzz differential: traversal payloads + file-read evidence"],
                "file content disclosed -> SUPPORTED; neutral -> REFUTED",
            ),
            TestFamily.PARAM_SSRF.value: (
                "redirect/target URL parameter (semantic sink candidate)",
                ["http_probe/param_fuzz: controlled value + observable fetch behavior"],
                "internal response/DNS interaction leaked -> SUPPORTED; neutral -> REFUTED",
            ),
            TestFamily.PARAM_XSS.value: (
                "text-bearing input parameter (search/feedback/message/query)",
                ["param_fuzz: reflected-context probe + unescaped reflection check"],
                "unescaped reflection -> SUPPORTED; escaped/neutral -> REFUTED",
            ),
            TestFamily.FILE_UPLOAD.value: (
                "file-upload surface (upload endpoint or upload form)",
                ["http_probe: extension/content-type/filename handling + storage exposure"],
                "executable content stored and reachable -> SUPPORTED; rejected -> REFUTED",
            ),
            TestFamily.GRAPHQL_INTROSPECTION.value: (
                "GraphQL endpoint present",
                ["graphql_probe: introspection query + schema types"],
                "full schema disclosed -> SUPPORTED; disabled -> REFUTED",
            ),
            TestFamily.GRAPHQL_AUTHZ.value: (
                "GraphQL endpoint with object/field operations",
                ["graphql_probe + authz_compare: per-field authorization comparison"],
                "unauthorized field/object access -> SUPPORTED; enforced -> REFUTED",
            ),
            TestFamily.WORKFLOW_STATE.value: (
                "multi-step workflow discovered",
                ["http_probe sequence: skipped/reordered steps + state validation"],
                "step bypass accepted -> SUPPORTED; enforced -> REFUTED",
            ),
            TestFamily.WORKFLOW_TAMPERING.value: (
                "workflow with tamperable values (price/quantity/ids)",
                ["http_probe: altered trusted values + server acceptance"],
                "tampered value accepted -> SUPPORTED; rejected -> REFUTED",
            ),
            TestFamily.CONFIG_EXPOSURE.value: (
                "sensitive path disclosed (robots/sitemap/backup/config)",
                ["http_probe/endpoint_validate: targeted probe + verified content (listing/keys/git)"],
                "sensitive artifact verified -> SUPPORTED; absent/catchall -> REFUTED",
            ),
            TestFamily.SERVICE_EXPLOIT_INTEL.value: (
                "non-web network service present",
                ["protocol enumeration + versioned software evidence"],
                "versioned product + intel match -> SUPPORTED-candidate; otherwise COMPLETE/REQUIRES_TOOL",
            ),
        }
        app_text, ev_req, adj = contracts.get(
            tc.family.value,
            ("attack surface element present", ["capability evidence"], "adjudicator rule"),
        )
        tc.applicability = app_text
        tc.execution_input = {
            "target_path": tc.target_path,
            "target_method": tc.target_method,
            "target_parameter": tc.target_parameter,
            "candidate_tools": list(tc.candidate_tools),
            "required_capabilities": list(tc.required_capabilities),
            "prerequisites": list(tc.prerequisites),
        }
        tc.evidence_requirements = list(ev_req)
        tc.adjudication_rule = adj
        tc.terminal_states = [
            "EXECUTED_SUCCESS", "EXECUTED_FAILURE", "EXECUTED_NO_ISSUE",
            "REQUIRES_AUTH", "REQUIRES_SECOND_IDENTITY", "REQUIRES_TOOL",
            "BLOCKED", "OUT_OF_SCOPE", "NOT_APPLICABLE",
        ]

    def _contract(
        tc: SecurityTestCase,
        applicability: str,
        evidence_requirements: list[str],
        adjudication_rule: str,
    ) -> SecurityTestCase:
        tc.applicability = applicability
        tc.execution_input = {
            "target_path": tc.target_path,
            "target_method": tc.target_method,
            "target_parameter": tc.target_parameter,
            "candidate_tools": list(tc.candidate_tools),
            "required_capabilities": list(tc.required_capabilities),
            "prerequisites": list(tc.prerequisites),
        }
        tc.evidence_requirements = list(evidence_requirements)
        tc.adjudication_rule = adjudication_rule
        tc.terminal_states = [
            "EXECUTED_SUCCESS", "EXECUTED_FAILURE", "EXECUTED_NO_ISSUE",
            "REQUIRES_AUTH", "REQUIRES_SECOND_IDENTITY", "REQUIRES_TOOL",
            "BLOCKED", "OUT_OF_SCOPE", "NOT_APPLICABLE",
        ]
        return tc

    # 1. Endpoint & Object Resource Tests
    for ep in app.endpoints:
        path = _normalize_path(ep.path)
        if is_static_asset_endpoint(path):
            continue

        method = ep.method.upper()
        # Instance-level reference only: collections (GET /api/Products)
        # are NOT authorization boundaries. Never match IP octets.
        has_obj = bool(getattr(ep, "has_object_reference", False)) or path_has_instance_id(path)
        is_admin = "admin" in path.lower() or "management" in path.lower() or "internal" in path.lower()
        is_graphql = "graphql" in path.lower()

        # BOLA / IDOR on instance-level object references only.
        # Collections (GET /api/Products) are NOT boundaries. A bound
        # object-id parameter (e.g. /rest/track-order?orderId=) is a
        # demonstrable reference candidate and also derives one test.
        bound_obj_params = []
        try:
            for _p in app.parameters:
                _pep = _normalize_path(_p.endpoint or "")
                if _pep != path:
                    continue
                if is_static_asset_endpoint(_pep):
                    continue
                _role = classify_parameter(_p.name, _pep)
                if _role in (ParameterSemanticRole.OBJECT_ID, ParameterSemanticRole.USER_ID):
                    bound_obj_params.append(_p.name)
        except Exception:
            bound_obj_params = []
        has_param_obj_ref = bool(bound_obj_params)

        # BOLA / IDOR on object-bearing endpoints
        if has_obj or has_param_obj_ref:
            bola_suffix = "" if has_obj else f" via object parameter(s) {', '.join(bound_obj_params[:2])}"
            _add(
                SecurityTestCase(
                    family=TestFamily.BOLA_IDOR,
                    name=f"BOLA / IDOR authorization boundary check on {method} {path}{bola_suffix}",
                    asset_id=ep.id,
                    asset_type="endpoint",
                    target_path=path,
                    target_method=method,
                    specialist="AuthorizationAgent",
                    candidate_tools=["authz_compare", "http_probe"],
                    required_capabilities=["http", "proxy"],
                    prerequisites=["web_target"],
                    vulnerability_classes=["object_level_authorization"],
                    priority=0.82,
                    evidence_refs=[ep.id],
                )
            )
            _add(
                SecurityTestCase(
                    family=TestFamily.AUTHZ_HORIZONTAL,
                    name=f"Horizontal authorization comparison on {method} {path}",
                    asset_id=ep.id,
                    asset_type="endpoint",
                    target_path=path,
                    target_method=method,
                    specialist="AuthorizationAgent",
                    candidate_tools=["authz_compare"],
                    required_capabilities=["http", "proxy"],
                    prerequisites=["two_identities"],
                    vulnerability_classes=["authorization"],
                    priority=0.80,
                    evidence_refs=[ep.id],
                )
            )

        # Admin / Privileged Endpoints
        if is_admin:
            _add(
                SecurityTestCase(
                    family=TestFamily.AUTHZ_VERTICAL,
                    name=f"Privilege boundary enforcement on administrative endpoint {method} {path}",
                    asset_id=ep.id,
                    asset_type="endpoint",
                    target_path=path,
                    target_method=method,
                    specialist="AuthorizationAgent",
                    candidate_tools=["authz_compare", "http_probe"],
                    required_capabilities=["http"],
                    prerequisites=["web_target"],
                    vulnerability_classes=["function_level_authorization"],
                    priority=0.85,
                    evidence_refs=[ep.id],
                )
            )

        # Authentication Enforcement on Protected or State-Changing Endpoints
        if ep.authentication == "required" or ep.is_mutation or is_admin:
            _add(
                SecurityTestCase(
                    family=TestFamily.AUTH_ENFORCEMENT,
                    name=f"Test unauthenticated and anonymous access to {method} {path}",
                    asset_id=ep.id,
                    asset_type="endpoint",
                    target_path=path,
                    target_method=method,
                    specialist="AuthenticationAgent",
                    candidate_tools=["auth_probe", "http_probe"],
                    required_capabilities=["http"],
                    prerequisites=["web_target"],
                    vulnerability_classes=["authentication"],
                    priority=0.78,
                    evidence_refs=[ep.id],
                )
            )

        # GraphQL Tests
        if is_graphql:
            _add(
                SecurityTestCase(
                    family=TestFamily.GRAPHQL_INTROSPECTION,
                    name=f"GraphQL introspection and schema validation on {path}",
                    asset_id=ep.id,
                    asset_type="endpoint",
                    target_path=path,
                    target_method="POST",
                    specialist="WebAgent",
                    candidate_tools=["graphql_probe"],
                    required_capabilities=["http"],
                    prerequisites=["web_target"],
                    vulnerability_classes=["api_security"],
                    priority=0.76,
                    evidence_refs=[ep.id],
                )
            )

        # API security semantics on actual REST/API endpoints.
        pl = path.lower()
        if pl.startswith(("/api/", "/rest/", "/v1/", "/v2/", "/v3/")) and not is_graphql:
            _add(
                SecurityTestCase(
                    family=TestFamily.API_SECURITY,
                    name=f"API security semantics (excessive data / mass assignment / method tampering) on {method} {path}",
                    asset_id=ep.id,
                    asset_type="endpoint",
                    target_path=path,
                    target_method=method,
                    specialist="WebAgent",
                    candidate_tools=["api_probe", "http_probe"],
                    required_capabilities=["http"],
                    prerequisites=["web_target"],
                    vulnerability_classes=["api_security"],
                    priority=0.74,
                    evidence_refs=[ep.id],
                )
            )

        # Sensitive Directory / Information Exposure Tests
        if path in ("/ftp", "/ftp/", "/robots.txt", "/sitemap.xml") or path.endswith((".env", ".git", ".bak", ".kdbx")):
            _add(
                SecurityTestCase(
                    family=TestFamily.CONFIG_EXPOSURE,
                    name=f"Inspect sensitive directory or configuration exposure at {path}",
                    asset_id=ep.id,
                    asset_type="endpoint",
                    target_path=path,
                    target_method="GET",
                    specialist="WebAgent",
                    candidate_tools=["http_probe", "endpoint_validate"],
                    required_capabilities=["http"],
                    prerequisites=["web_target"],
                    vulnerability_classes=["information_disclosure"],
                    priority=0.86,
                    evidence_refs=[ep.id],
                )
            )

    # 2. Parameterized Input Tests (semantic only — never spray static assets)
    for param in app.parameters:
        p_name = (param.name or "").strip()
        if not p_name:
            continue
        if (param.location or "") == "client_state":
            continue
        endpoint_path = _normalize_path(param.endpoint or "/")
        if is_static_asset_endpoint(endpoint_path):
            continue
        # Static JS bundle pseudo-endpoints must never become server targets.
        if endpoint_path.endswith((".js", ".css")) or "/main.js" in endpoint_path or "/polyfills.js" in endpoint_path:
            continue

        role = classify_parameter(p_name, endpoint_path)
        is_input = role in (
            ParameterSemanticRole.SEARCH_QUERY,
            ParameterSemanticRole.OBJECT_ID,
            ParameterSemanticRole.USER_ID,
            ParameterSemanticRole.SORT_ORDER,
            ParameterSemanticRole.BUSINESS_LOGIC,
            ParameterSemanticRole.GENERIC_INPUT,
        ) or param.location in ("query", "body")

        # Injection probes for semantic query/search/filter/object parameters
        if role in (ParameterSemanticRole.SEARCH_QUERY, ParameterSemanticRole.OBJECT_ID, ParameterSemanticRole.USER_ID, ParameterSemanticRole.SORT_ORDER) or param.location in ("body",):
            _add(
                SecurityTestCase(
                    family=TestFamily.PARAM_SQLI,
                    name=f"Test SQL/NoSQL injection semantics on parameter '{p_name}' at {endpoint_path}",
                    asset_id=param.id,
                    asset_type="parameter",
                    target_path=endpoint_path,
                    target_parameter=p_name,
                    specialist="WebAgent",
                    candidate_tools=["sqli_probe", "param_fuzz"],
                    required_capabilities=["http"],
                    prerequisites=["web_target"],
                    vulnerability_classes=["injection"],
                    priority=0.75,
                    evidence_refs=[param.id],
                )
            )

        # Command-injection probes on the same semantic input surface
        if is_input:
            _add(
                SecurityTestCase(
                    family=TestFamily.PARAM_CMDI,
                    name=f"Test OS command injection semantics on parameter '{p_name}' at {endpoint_path}",
                    asset_id=param.id,
                    asset_type="parameter",
                    target_path=endpoint_path,
                    target_parameter=p_name,
                    specialist="WebAgent",
                    candidate_tools=["cmdi_probe", "param_fuzz"],
                    required_capabilities=["http"],
                    prerequisites=["web_target"],
                    vulnerability_classes=["injection"],
                    priority=0.73,
                    evidence_refs=[param.id],
                )
            )

        # Cross-site scripting probes on text-bearing parameters
        if role in (ParameterSemanticRole.SEARCH_QUERY, ParameterSemanticRole.GENERIC_INPUT) or p_name.lower() in ("q", "query", "search", "keyword", "term", "filter", "message", "feedback", "comment", "name", "email"):
            _add(
                SecurityTestCase(
                    family=TestFamily.PARAM_XSS,
                    name=f"Test reflected XSS context on parameter '{p_name}' at {endpoint_path}",
                    asset_id=param.id,
                    asset_type="parameter",
                    target_path=endpoint_path,
                    target_parameter=p_name,
                    specialist="WebAgent",
                    candidate_tools=["xss_probe", "param_fuzz"],
                    required_capabilities=["http"],
                    prerequisites=["web_target"],
                    vulnerability_classes=["xss"],
                    priority=0.72,
                    evidence_refs=[param.id],
                )
            )

        # SSRF probes
        if role in (ParameterSemanticRole.TARGET_URL, ParameterSemanticRole.REDIRECT_URL):
            _add(
                SecurityTestCase(
                    family=TestFamily.PARAM_SSRF,
                    name=f"Validate server-side request behavior (SSRF) on parameter '{p_name}' at {endpoint_path}",
                    asset_id=param.id,
                    asset_type="parameter",
                    target_path=endpoint_path,
                    target_parameter=p_name,
                    specialist="WebAgent",
                    candidate_tools=["ssrf_probe", "param_fuzz"],
                    required_capabilities=["http"],
                    prerequisites=["web_target"],
                    vulnerability_classes=["ssrf"],
                    priority=0.81,
                    evidence_refs=[param.id],
                )
            )

        # Path Traversal probes
        if role in (ParameterSemanticRole.FILE_PATH, ParameterSemanticRole.SEARCH_QUERY):
            _add(
                SecurityTestCase(
                    family=TestFamily.PARAM_TRAVERSAL,
                    name=f"Test path traversal and file disclosure on parameter '{p_name}' at {endpoint_path}",
                    asset_id=param.id,
                    asset_type="parameter",
                    target_path=endpoint_path,
                    target_parameter=p_name,
                    specialist="WebAgent",
                    candidate_tools=["traversal_probe", "param_fuzz"],
                    required_capabilities=["http"],
                    prerequisites=["web_target"],
                    vulnerability_classes=["file_handling"],
                    priority=0.74,
                    evidence_refs=[param.id],
                )
            )

    # Discovered Search Endpoints with implied query parameters
    for ep in app.endpoints:
        ep_path = _normalize_path(ep.path)
        if is_static_asset_endpoint(ep_path):
            continue
        if any(k in ep_path.lower() for k in ("search", "find", "query", "filter")):
            _add(
                SecurityTestCase(
                    family=TestFamily.PARAM_SQLI,
                    name=f"Test SQL/NoSQL injection semantics on parameter 'q' at {ep_path}",
                    asset_id=f"param-{fingerprint(ep_path, 'q')}",
                    asset_type="parameter",
                    target_path=ep_path,
                    target_parameter="q",
                    specialist="WebAgent",
                    candidate_tools=["sqli_probe", "param_fuzz"],
                    required_capabilities=["http"],
                    prerequisites=["web_target"],
                    vulnerability_classes=["injection"],
                    priority=0.88,
                    evidence_refs=[ep.id],
                )
            )
            _add(
                SecurityTestCase(
                    family=TestFamily.PARAM_XSS,
                    name=f"Test reflected XSS context on parameter 'q' at {ep_path}",
                    asset_id=f"param-{fingerprint(ep_path, 'q-xss')}",
                    asset_type="parameter",
                    target_path=ep_path,
                    target_parameter="q",
                    specialist="WebAgent",
                    candidate_tools=["xss_probe", "param_fuzz"],
                    required_capabilities=["http"],
                    prerequisites=["web_target"],
                    vulnerability_classes=["xss"],
                    priority=0.84,
                    evidence_refs=[ep.id],
                )
            )

    # GraphQL authorization boundary tests (generic: any GraphQL surface)
    for ep in app.endpoints:
        ep_path = _normalize_path(ep.path)
        if is_static_asset_endpoint(ep_path):
            continue
        if "graphql" in ep_path.lower():
            _add(
                SecurityTestCase(
                    family=TestFamily.GRAPHQL_AUTHZ,
                    name=f"GraphQL object/field authorization boundary check on {ep_path}",
                    asset_id=ep.id,
                    asset_type="endpoint",
                    target_path=ep_path,
                    target_method="POST",
                    specialist="WebAgent",
                    candidate_tools=["graphql_probe", "http_probe"],
                    required_capabilities=["http"],
                    prerequisites=["web_target"],
                    vulnerability_classes=["api_security"],
                    priority=0.79,
                    evidence_refs=[ep.id],
                )
            )

    # File-upload tests (generic: upload endpoint or upload form action)
    _upload_eps = [e for e in app.endpoints if "upload" in _normalize_path(e.path).lower()]
    _upload_forms = [f for f in getattr(app, "forms", []) if "upload" in (getattr(f, "action", "") or "").lower()]
    if _upload_eps or _upload_forms:
        anchor = _normalize_path(_upload_eps[0].path) if _upload_eps else (getattr(_upload_forms[0], "action", "") or "/upload")
        anchor_id = _upload_eps[0].id if _upload_eps else fingerprint("form", anchor)
        _add(
            SecurityTestCase(
                family=TestFamily.FILE_UPLOAD,
                name=f"Test file upload validation and storage exposure at {anchor}",
                asset_id=anchor_id,
                asset_type="endpoint",
                target_path=anchor,
                target_method="POST",
                specialist="WebAgent",
                candidate_tools=["upload_probe", "http_probe"],
                required_capabilities=["http"],
                prerequisites=["web_target"],
                vulnerability_classes=["file_handling"],
                priority=0.80,
                evidence_refs=[anchor_id],
            )
        )

    # 3. Workflows & Business Logic
    for wf in getattr(app, "workflows", []):
        wf_name = getattr(wf, "name", "Workflow")
        wf_id = getattr(wf, "id", fingerprint("wf", wf_name))
        _add(
            SecurityTestCase(
                family=TestFamily.WORKFLOW_STATE,
                name=f"Test workflow state skipping and sequence validation on {wf_name}",
                asset_id=wf_id,
                asset_type="workflow",
                target_path=getattr(wf, "initial_endpoint", "/") or "/",
                specialist="BusinessLogicAgent",
                candidate_tools=["workflow_probe", "http_probe"],
                required_capabilities=["http"],
                prerequisites=["web_target"],
                vulnerability_classes=["business_logic"],
                priority=0.77,
                evidence_refs=[wf_id],
            )
        )
        _add(
            SecurityTestCase(
                family=TestFamily.WORKFLOW_TAMPERING,
                name=f"Test parameter and quantity/price tampering on {wf_name}",
                asset_id=wf_id,
                asset_type="workflow",
                target_path=getattr(wf, "initial_endpoint", "/") or "/",
                specialist="BusinessLogicAgent",
                candidate_tools=["workflow_probe", "http_probe"],
                required_capabilities=["http"],
                prerequisites=["web_target"],
                vulnerability_classes=["business_logic"],
                priority=0.76,
                evidence_refs=[wf_id],
            )
        )

    # 4. Infrastructure & Network Services
    for svc in getattr(app, "services", []):
        if not svc.is_web:
            svc_id = svc.id or svc.ensure_id()
            _add(
                SecurityTestCase(
                    family=TestFamily.SERVICE_EXPLOIT_INTEL,
                    name=f"Enumerate protocol and correlate intelligence for service {svc.service_name or svc.service} on port {svc.port}",
                    asset_id=svc_id,
                    asset_type="service",
                    specialist="NetworkAgent",
                    candidate_tools=["smb_enum", "nmap_discovery"],
                    required_capabilities=["service"],
                    prerequisites=[],
                    vulnerability_classes=["infrastructure"],
                    priority=0.65,
                    evidence_refs=[svc_id],
                )
            )

    # Sort deterministically by priority descending
    test_cases.sort(key=lambda x: x.priority, reverse=True)
    return test_cases


def test_case_to_investigation(tc: SecurityTestCase) -> Investigation:
    """Convert a SecurityTestCase into an Investigation model instance."""
    inv = Investigation(
        id=f"inv-{tc.id}",
        objective=tc.name,
        reason=f"Deterministic test matrix requirement for {tc.family.value} on {tc.target_path or tc.asset_id}",
        evidence_refs=list(tc.evidence_refs),
        vulnerability_classes=list(tc.vulnerability_classes),
        required_capabilities=list(tc.required_capabilities),
        candidate_tools=list(tc.candidate_tools),
        prerequisites=list(tc.prerequisites),
        expected_information_gain="high" if tc.priority >= 0.75 else "medium",
        priority=tc.priority,
        specialist=tc.specialist,
        state=InvestigationState.READY,
        score=InvestigationScore(
            evidence_relevance=0.7,
            expected_information_gain=tc.priority,
            impact_potential=tc.priority,
            coverage_gap=0.6,
            prerequisites_satisfied=1.0,
            execution_cost=0.3,
        ),
    )
    inv.observations = [
        f"matrix_tc_id:{tc.id}",
        f"matrix_family:{tc.family.value}",
        f"matrix_asset:{tc.target_path}",
        f"matrix_param:{tc.target_parameter}",
        f"matrix_method:{tc.target_method}",
    ]
    return inv


def compute_security_test_coverage(state: Any) -> dict[str, Any]:
    """Compute security test coverage statistics derived directly from ApplicationModel."""
    app = state.get_application_model()
    applicable_tests = derive_applicable_tests(app, state)
    investigations = state.get_investigations()

    inv_by_tc_id: dict[str, Any] = {}
    inv_by_family_asset: dict[tuple[str, str, str], Any] = {}
    for inv in investigations:
        tc_id = ""
        family = ""
        asset = ""
        param = ""
        for obs in getattr(inv, "observations", []):
            if obs.startswith("matrix_tc_id:"):
                tc_id = obs.split(":", 1)[1]
            elif obs.startswith("matrix_family:"):
                family = obs.split(":", 1)[1]
            elif obs.startswith("matrix_asset:"):
                asset = obs.split(":", 1)[1]
            elif obs.startswith("matrix_param:"):
                param = obs.split(":", 1)[1]
        if tc_id:
            inv_by_tc_id[tc_id] = inv
        if family and asset:
            inv_by_family_asset[(family, asset, param)] = inv

    domains_map = {
        TestFamily.BOLA_IDOR: "BOLA / IDOR",
        TestFamily.AUTHZ_HORIZONTAL: "Horizontal Authorization",
        TestFamily.AUTHZ_VERTICAL: "Vertical Authorization / Privileges",
        TestFamily.AUTH_ENFORCEMENT: "Authentication Enforcement",
        TestFamily.API_SECURITY: "API Security Semantics",
        TestFamily.PARAM_SQLI: "SQL Injection",
        TestFamily.PARAM_CMDI: "Command Injection",
        TestFamily.PARAM_TRAVERSAL: "Path Traversal / LFI",
        TestFamily.PARAM_SSRF: "Server-Side Request Forgery",
        TestFamily.PARAM_XSS: "Cross-Site Scripting",
        TestFamily.FILE_UPLOAD: "File Upload Handling",
        TestFamily.GRAPHQL_INTROSPECTION: "GraphQL Introspection",
        TestFamily.GRAPHQL_AUTHZ: "GraphQL Authorization",
        TestFamily.WORKFLOW_STATE: "Workflow State Flaws",
        TestFamily.WORKFLOW_TAMPERING: "Workflow Tampering",
        TestFamily.CONFIG_EXPOSURE: "Configuration & Secrets Exposure",
        TestFamily.SERVICE_EXPLOIT_INTEL: "Service Exploitation Intelligence",
    }

    family_stats: dict[str, dict[str, Any]] = {}
    for fam, name in domains_map.items():
        family_stats[fam.value] = {
            "family": fam.value,
            "name": name,
            "applicable": 0,
            "executable": 0,
            "executed": 0,
            "supported": 0,
            "refuted": 0,
            "blocked": 0,
            "unavailable": 0,
            "pending": 0,
            "confirmed_findings": 0,
        }

    total_applicable = len(applicable_tests)
    total_executable = 0
    total_executed = 0
    total_supported = 0
    total_refuted = 0
    total_blocked = 0
    total_insufficient = 0
    total_failed = 0
    total_pending = 0
    test_details: list[dict[str, Any]] = []

    # Terminal-state buckets. Every applicable test lands in exactly one.
    # No silent skipping: INSUFFICIENT/FAILED are terminal attempt outcomes,
    # never "pending"; READY/PENDING/RUNNING/missing are explicit NOT TESTED.
    _EXECUTED_OK = {"SUPPORTED", "REFUTED", "COMPLETE"}
    _INSUFFICIENT = {"INSUFFICIENT_EVIDENCE"}
    _FAILED = {"FAILED"}
    _BLOCKED = {
        "BLOCKED", "SCOPE_BLOCKED", "NOT_APPLICABLE", "OUT_OF_SCOPE",
        "UNAVAILABLE", "REQUIRES_AUTH", "REQUIRES_SECOND_IDENTITY",
        "REQUIRES_TOOL", "REQUIRES_OPERATOR",
    }
    _NOT_TESTED = {"READY", "PENDING", "RUNNING"}

    def _prereq_satisfied(tc: SecurityTestCase) -> tuple[bool, str]:
        try:
            from horcrux.intel.test_matrix import test_case_to_investigation as _t2i
            from horcrux.intel.dependencies import evaluate_prerequisites as _eval
            probe = _t2i(tc)
            schedulable, blocked = _eval(state, probe)
            if schedulable:
                return True, ""
            return False, "; ".join(blocked[:2])
        except Exception:
            return True, ""

    for tc in applicable_tests:
        fam_key = tc.family.value
        stats = family_stats.setdefault(fam_key, {
            "family": fam_key,
            "name": fam_key,
            "applicable": 0,
            "executable": 0,
            "executed": 0,
            "supported": 0,
            "refuted": 0,
            "blocked": 0,
            "unavailable": 0,
            "pending": 0,
            "insufficient": 0,
            "failed": 0,
            "confirmed_findings": 0,
        })
        for k in ("insufficient", "failed"):
            stats.setdefault(k, 0)
        stats["applicable"] += 1

        inv = inv_by_tc_id.get(tc.id) or inv_by_family_asset.get((tc.family.value, tc.target_path, tc.target_parameter))
        # No fuzzy name fallback: substring matching misattributes terminals
        # across tests sharing a family/parameter (e.g. "/" vs "/rest/admin").
        # Unmatched tests are explicitly NOT_TESTED with a reason.

        satisfiable, block_reason = _prereq_satisfied(tc)
        if satisfiable:
            stats["executable"] += 1
            total_executable += 1

        if inv is not None:
            st_val = inv.state.value if hasattr(inv.state, "value") else str(inv.state)
            detail = {
                "id": tc.id, "family": fam_key,
                "target": tc.target_path, "parameter": tc.target_parameter,
                "terminal": "", "reason": getattr(inv, "result_summary", "") or "",
            }
            if st_val in _EXECUTED_OK:
                stats["executed"] += 1
                total_executed += 1
                if st_val == "SUPPORTED":
                    stats["supported"] += 1
                    total_supported += 1
                    detail["terminal"] = "EXECUTED_SUCCESS"
                else:
                    stats["refuted"] += 1
                    total_refuted += 1
                    detail["terminal"] = "EXECUTED_NO_ISSUE"
            elif st_val in _INSUFFICIENT:
                stats["insufficient"] += 1
                total_insufficient += 1
                detail["terminal"] = "EXECUTED_INSUFFICIENT"
            elif st_val in _FAILED:
                stats["failed"] += 1
                total_failed += 1
                detail["terminal"] = "EXECUTED_FAILURE"
            elif st_val in _BLOCKED:
                stats["blocked"] += 1
                if st_val == "UNAVAILABLE":
                    stats["unavailable"] += 1
                total_blocked += 1
                detail["terminal"] = st_val
            else:
                # READY/PENDING/RUNNING or unknown -> explicitly NOT TESTED.
                stats["pending"] += 1
                total_pending += 1
                detail["terminal"] = "NOT_TESTED"
            test_details.append(detail)
        else:
            stats["pending"] += 1
            total_pending += 1
            test_details.append({
                "id": tc.id, "family": fam_key,
                "target": tc.target_path, "parameter": tc.target_parameter,
                "terminal": "NOT_TESTED",
                "reason": block_reason or "no investigation scheduled yet",
            })

    findings = getattr(state, "findings", []) or []
    for f in findings:
        cat = (f.category or "").lower()
        title = (f.title or "").lower()
        cwes = [c.upper() for c in getattr(f, "cwes", [])]
        fam_matched = None
        if "sql" in cat or "sql" in title or "CWE-89" in cwes:
            fam_matched = TestFamily.PARAM_SQLI.value
        elif "command" in cat or "command" in title or "CWE-78" in cwes:
            fam_matched = TestFamily.PARAM_CMDI.value
        elif "xss" in cat or "cross-site" in title or "CWE-79" in cwes:
            fam_matched = TestFamily.PARAM_XSS.value
        elif "upload" in cat or "upload" in title:
            fam_matched = TestFamily.FILE_UPLOAD.value
        elif "ssrf" in cat or "ssrf" in title or "CWE-918" in cwes:
            fam_matched = TestFamily.PARAM_SSRF.value
        elif "traversal" in cat or "cwe-22" in [c.lower() for c in cwes]:
            fam_matched = TestFamily.PARAM_TRAVERSAL.value
        elif "idor" in cat or "bola" in cat or "cwe-639" in [c.lower() for c in cwes]:
            fam_matched = TestFamily.BOLA_IDOR.value
        elif "admin" in title or "cwe-284" in [c.lower() for c in cwes]:
            fam_matched = TestFamily.AUTHZ_VERTICAL.value
        elif "exposure" in cat or "disclosure" in cat or "directory listing" in title or "cwe-548" in [c.lower() for c in cwes] or "cwe-200" in [c.lower() for c in cwes]:
            fam_matched = TestFamily.CONFIG_EXPOSURE.value
        elif "graphql" in cat or "graphql" in title:
            fam_matched = TestFamily.GRAPHQL_INTROSPECTION.value
        elif "api-security" in cat or "api security" in title:
            fam_matched = TestFamily.API_SECURITY.value
        elif "smb" in title or "service" in cat:
            fam_matched = TestFamily.SERVICE_EXPLOIT_INTEL.value
        if fam_matched and fam_matched in family_stats:
            family_stats[fam_matched]["confirmed_findings"] = family_stats[fam_matched].get("confirmed_findings", 0) + 1

    surface_elements = {
        "endpoints": len(app.endpoints),
        "parameters": len(app.parameters),
        "objects": len(getattr(app, "object_types", [])) or len(getattr(app, "object_lifecycles", [])),
        "workflows": len(app.workflows),
        "services": len(getattr(app, "services", [])) or len(getattr(state, "services", [])),
    }

    completeness_pct = (total_executed / total_applicable * 100.0) if total_applicable > 0 else 0.0

    return {
        "surface_elements": surface_elements,
        "total_applicable": total_applicable,
        "total_executable": total_executable,
        "total_executed": total_executed,
        "total_supported": total_supported,
        "total_refuted": total_refuted,
        "total_blocked": total_blocked,
        "total_insufficient": total_insufficient,
        "total_failed": total_failed,
        "total_pending": total_pending,
        "total_not_tested": total_pending,
        "completeness_percentage": completeness_pct,
        "family_breakdown": list(family_stats.values()),
        "test_details": test_details,
    }

