from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlparse
import httpx

from horcrux.models import (
    DiscoveredPath,
    EvidenceClassification,
    Parameter,
    RawObservation,
    ValidationState,
)


# Route regex patterns from compiled JS bundles and HTML
_API_ROUTE_PATTERN = re.compile(
    r"""["'`](/(?:api|v[0-9]|rest|auth|admin|user|users|account|data|internal|graphql|metrics|health)[a-zA-Z0-9_\-/\.]*?)["'`]""",
    re.I,
)
_GENERIC_RELATIVE_ROUTE = re.compile(
    r"""["'`](/[a-zA-Z0-9_\-]+(?:/[a-zA-Z0-9_\-]+)*)[\?\"'`]"""
)
_GRAPHQL_WS_PATTERN = re.compile(
    r"""["'`](wss?://[^\s"'`]+|/graphql|/subscriptions|/ws)[\?\"'`]""",
    re.I,
)
_JS_PARAM_PATTERN = re.compile(
    r"""(?:params|searchParams|query|body|data)\s*[:=.]\s*(?:append\s*\(\s*["']([a-zA-Z0-9_\-]+)["']|\{\s*["']?([a-zA-Z0-9_\-]+)["']?\s*:)""",
    re.I,
)
_HTML_INPUT_PATTERN = re.compile(
    r"""<input[^>]+name=["']([a-zA-Z0-9_\-]+)["'][^>]*>""",
    re.I,
)
_HTML_FORM_PATTERN = re.compile(
    r"""<form[^>]+(?:action=["']([^"']*)["'])?[^>]*>([\s\S]*?)</form>""",
    re.I,
)


def extract_script_sources(html: str, base_url: str) -> list[str]:
    """Extracts unique absolute JavaScript asset URLs from HTML."""
    script_urls: list[str] = []
    matches = re.findall(r"""<script[^>]+src=["']([^"']+)["']""", html, re.I)
    for m in matches:
        if m.startswith("//"):
            parsed = urlparse(base_url)
            u = f"{parsed.scheme}:{m}"
        elif m.startswith("http"):
            u = m
        else:
            u = urljoin(base_url.rstrip("/") + "/", m.lstrip("/"))
        if u not in script_urls:
            script_urls.append(u)
    return script_urls


def extract_form_parameters(html: str, base_url: str) -> list[Parameter]:
    """Extracts parameters from HTML forms."""
    params: list[Parameter] = []
    seen: set[tuple[str, str]] = set()

    for form_match in _HTML_FORM_PATTERN.finditer(html):
        action = form_match.group(1) or "/"
        endpoint = urljoin(base_url.rstrip("/") + "/", action.lstrip("/"))
        form_body = form_match.group(2)
        inputs = _HTML_INPUT_PATTERN.findall(form_body)
        for input_name in inputs:
            key = (input_name.lower(), endpoint)
            if key not in seen:
                seen.add(key)
                params.append(
                    Parameter(
                        name=input_name,
                        location="body" if "post" in form_match.group(0).lower() else "query",
                        source="html_form",
                        endpoint=endpoint,
                        confidence=0.95,
                    )
                )

    return params


def analyze_javascript_and_routes(
    client: httpx.Client,
    base_url: str,
    root_html: str,
    max_scripts: int = 8,
) -> tuple[list[DiscoveredPath], list[Parameter], list[RawObservation]]:
    """
    Analyzes JavaScript bundles and HTML to extract candidate endpoints and parameters.
    Returns:
      (discovered_candidate_paths, discovered_parameters, raw_observations)
    """
    candidate_paths: list[DiscoveredPath] = []
    parameters: list[Parameter] = []
    observations: list[RawObservation] = []

    seen_paths: set[str] = set()
    seen_params: set[str] = set()

    # 1. Form parameters from root HTML
    form_params = extract_form_parameters(root_html, base_url)
    parameters.extend(form_params)

    # 2. Extract script sources
    script_urls = extract_script_sources(root_html, base_url)
    observations.append(
        RawObservation(
            source_tool="js_analyzer",
            target=base_url,
            observation_type="script_inventory",
            data={"script_count": len(script_urls), "scripts": script_urls},
        )
    )

    # 3. Download & inspect script contents
    for s_url in script_urls[:max_scripts]:
        # Only inspect scripts on the same origin/host
        if urlparse(s_url).netloc and urlparse(s_url).netloc != urlparse(base_url).netloc:
            continue

        try:
            resp = client.get(s_url, timeout=6.0)
            if resp.status_code != 200 or not resp.text:
                continue

            js_text = resp.text

            # Check for source map reference
            map_match = re.search(r"//# sourceMappingURL=(\S+)", js_text)
            if map_match:
                map_url = urljoin(s_url, map_match.group(1))
                observations.append(
                    RawObservation(
                        source_tool="js_analyzer",
                        target=base_url,
                        observation_type="sourcemap_reference",
                        data={"sourcemap_url": map_url, "source_script": s_url},
                    )
                )

            # Extract API and relative routes
            routes = _API_ROUTE_PATTERN.findall(js_text)
            for r in routes:
                clean_r = "/" + r.lstrip("/")
                # Filter out file extensions like .js, .png, .css unless API
                if any(clean_r.endswith(ext) for ext in (".js", ".css", ".png", ".jpg", ".svg", ".woff")):
                    continue
                if clean_r not in seen_paths:
                    seen_paths.add(clean_r)
                    full_u = urljoin(base_url.rstrip("/") + "/", clean_r.lstrip("/"))
                    candidate_paths.append(
                        DiscoveredPath(
                            url=full_u,
                            path=clean_r,
                            status=0,
                            source="js_analysis",
                            confidence=0.85,
                            validated=False,
                            validation_state=ValidationState.potential,
                            evidence_classification=EvidenceClassification.CANDIDATE,
                            discovery_state="DISCOVERED_FROM_SOURCE",
                        )
                    )
                    observations.append(
                        RawObservation(
                            source_tool="js_analyzer",
                            target=base_url,
                            observation_type="js_endpoint",
                            data={"path": clean_r, "source_asset": s_url},
                        )
                    )

            # Endpoint-bound parameters from request construction literals.
            # Same-literal co-occurrence is endpoint-specific evidence;
            # bare tokens stay anchored to the bundle (never owned).
            for b in extract_endpoint_param_bindings(js_text):
                parameters.append(
                    Parameter(
                        name=b["name"],
                        location="query",
                        source="javascript",
                        endpoint=b["endpoint"],
                        confidence=0.85,
                    )
                )

            # Extract Parameters from JS
            param_matches = _JS_PARAM_PATTERN.finditer(js_text)
            for p_match in param_matches:
                p_name = p_match.group(1) or p_match.group(2)
                if p_name and len(p_name) > 1 and p_name.lower() not in seen_params:
                    # Ignore common JS language identifiers
                    if p_name in {"then", "catch", "length", "type", "data", "headers", "method"}:
                        continue
                    seen_params.add(p_name.lower())
                    parameters.append(
                        Parameter(
                            name=p_name,
                            location="query",
                            source="javascript",
                            endpoint=s_url,
                            confidence=0.75,
                        )
                    )

        except Exception:
            continue

    return candidate_paths, parameters, observations


def analyze_javascript_content(js_text: str, source_name: str = "") -> dict[str, Any]:
    """Analyzes raw JavaScript content string to extract candidate routes and parameters.

    Beyond URLs: methods, request-body schemas, auth headers, token
    handling, object identifiers, GraphQL operations, upload/admin
    routes, feature flags, client-side authorization assumptions and
    dangerous sinks — each as structured evidence (never a verdict).
    """
    routes: list[str] = []
    parameters: list[dict[str, Any]] = []
    seen_routes: set[str] = set()
    seen_params: set[str] = set()

    for r in _API_ROUTE_PATTERN.findall(js_text):
        clean_r = "/" + r.lstrip("/")
        if any(clean_r.endswith(ext) for ext in (".js", ".css", ".png", ".jpg", ".svg", ".woff")):
            continue
        if clean_r not in seen_routes:
            seen_routes.add(clean_r)
            routes.append(clean_r)

    for p_match in _JS_PARAM_PATTERN.finditer(js_text):
        p_name = p_match.group(1) or p_match.group(2)
        if p_name and len(p_name) > 1 and p_name.lower() not in seen_params:
            if p_name in {"then", "catch", "length", "type", "data", "headers", "method"}:
                continue
            seen_params.add(p_name.lower())
            parameters.append({"name": p_name, "source": source_name})

    # Extract keys inside JSON.stringify({ ... })
    for js_json in re.finditer(r"JSON\.stringify\s*\(\s*\{([\s\S]*?)\}\s*\)", js_text):
        keys = re.findall(r"""["']?([a-zA-Z0-9_\-]+)["']?\s*:""", js_json.group(1))
        for k in keys:
            if k and len(k) > 1 and k.lower() not in seen_params:
                if k in {"then", "catch", "length", "type", "data", "headers", "method"}:
                    continue
                seen_params.add(k.lower())
                parameters.append({"name": k, "source": source_name})

    # Extract keys inside params: { ... } or data: { ... }
    for js_obj in re.finditer(r"""(?:params|data|body)\s*:\s*\{([\s\S]*?)\}""", js_text):
        keys = re.findall(r"""["']?([a-zA-Z0-9_\-]+)["']?\s*:""", js_obj.group(1))
        for k in keys:
            if k and len(k) > 1 and k.lower() not in seen_params:
                if k in {"then", "catch", "length", "type", "data", "headers", "method"}:
                    continue
                seen_params.add(k.lower())
                parameters.append({"name": k, "source": source_name})

    # Extract query params in URL strings e.g. ?fields=profile,settings
    for q_match in re.finditer(r"""[?&]([a-zA-Z0-9_\-]+)=(?:[^&"'`\s]+)""", js_text):
        q_name = q_match.group(1)
        if q_name and len(q_name) > 1 and q_name.lower() not in seen_params:
            if q_name not in {"version", "v"}:
                seen_params.add(q_name.lower())
                parameters.append({"name": q_name, "source": source_name})

    # ── Structured client intelligence (evidence, never verdicts) ──
    _method_hits: list[str] = []
    for m in re.finditer(
        r"""method\s*:\s*["'](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)["']""",
        js_text, re.I):
        _method_hits.append(m.group(1).upper())
    methods = sorted(set(_method_hits))
    auth_headers = sorted(set(re.findall(
        r"""["'](Authorization|X-Auth-Token|X-API-Key|Bearer)["']""", js_text)))
    token_flows = sorted(set(re.findall(
        r"""(localStorage\s*\[\s*['"]token|sessionStorage[\s\S]{0,40}token|Bearer\s+\$\{|set\s+Authorization)""",
        js_text)))[:10]
    object_ids = sorted(set(re.findall(
        r"""/(?:users|orders|baskets|products|accounts|invoices|wallets|memories)/\$\{?[a-zA-Z0-9_]+|[?&](?:id|userId|orderId|basketId)=\$\{?[a-zA-Z0-9_]+""",
        js_text)))[:20]
    upload_routes = sorted({"/" + r.lstrip("/") for r in re.findall(
        r"""["'`](/(?:upload|files|avatar|document|attachment)[a-zA-Z0-9_\-/]*)["'`]""", js_text, re.I)})
    admin_routes = sorted({"/" + r.lstrip("/") for r in re.findall(
        r"""["'`](/(?:admin|management|internal|roles|metrics)[a-zA-Z0-9_\-/]*)["'`]""", js_text, re.I)})
    feature_flags = sorted(set(re.findall(r"""(?:featureFlag|isEnabled|flags\.)([A-Za-z0-9_]+)""", js_text)))[:20]
    client_authz = sorted(set(re.findall(
        r"""(?:if\s*\(\s*(?:user|role|isAdmin|canAccess)[^)]{0,80}\)|role\s*===?\s*["']admin["'])""",
        js_text)))[:10]
    sinks = sorted({s for pat in (r"\.innerHTML\s*=", r"document\.write\s*\(",
                                  r"eval\s*\(", r"new\s+Function\s*\(") for s in re.findall(pat, js_text)})[:10]
    graphql_ops = sorted(set(re.findall(
        r"""(?:query|mutation)\s+([A-Za-z_][A-Za-z0-9_]*)""", js_text)))[:20]

    return {"routes": routes, "parameters": parameters,
            "methods": methods, "auth_headers": auth_headers,
            "token_flows": token_flows, "object_ids": object_ids,
            "upload_routes": upload_routes, "admin_routes": admin_routes,
            "feature_flags": feature_flags,
            "client_authz_assumptions": client_authz,
            "dangerous_sinks": sinks, "graphql_operations": graphql_ops}


_BOUND_QUERY_RE = re.compile(
    r"""["'`](?:\$\{[^}]*\})?(/(?:api|rest|v\d+/)[^"'`\s]*?)\?([^"'`\s]+)["'`]""")


def extract_endpoint_param_bindings(js_text: str) -> list[dict[str, str]]:
    """Endpoint-specific parameter evidence from client request construction.

    Template literals such as `/rest/products/search?q=${e}` bind parameter
    `q` to that exact endpoint (JS_REQUEST_CONSTRUCTION provenance). Only
    same-literal co-occurrence counts — never global token promotion.
    """
    out: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for m in _BOUND_QUERY_RE.finditer(js_text or ""):
        ep, qs = "/" + m.group(1).lstrip("/"), m.group(2)
        for part in re.split(r"[&;]", qs):
            name = re.split(r"[=}$]", part, maxsplit=1)[0].strip().strip("${}")
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.\-]{0,63}", name or ""):
                continue
            key = (ep, name)
            if key not in seen:
                seen.add(key)
                out.append({"endpoint": ep, "name": name})
    return out


def extract_html_inputs(html: str, endpoint: str = "") -> list[dict[str, str]]:
    """Extracts form input parameters as a list of dicts with name and endpoint."""
    params = extract_form_parameters(html, endpoint or "http://target.local")
    return [{"name": p.name, "endpoint": p.endpoint, "location": p.location} for p in params]


_SOURCE_RES = (
    re.compile(r"queryParams\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)"),
    re.compile(r"queryParams\s*:\s*\{[^}]*?([A-Za-z_][A-Za-z0-9_]*)", re.S),
    re.compile(r"queryParamMap\s*\.\s*get\s*\(\s*['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]\s*\)"),
    re.compile(r"location\s*\.\s*(?:search|hash)"),
    re.compile(r"""\.get\(['"]([A-Za-z_][A-Za-z0-9_]*)['"]\)"""),
)

_SINK_RES = (
    ("bypassSecurityTrustHtml", re.compile(r"bypassSecurityTrustHtml\s*\(([\s\S]{1,400}?)\)")),
    ("innerHTML", re.compile(r"\.innerHTML\s*=\s*([^\n;]{1,300})")),
    ("document.write", re.compile(r"document\.write\s*\(([^)]{1,300})\)")),
)


def detect_dom_xss_flows(js_text: str, param: str = "") -> list[dict[str, str]]:
    """Pair attacker-influenced sources (URL query params) with dangerous
    sinks (sanitizer bypass / innerHTML / document.write).

    A flow confirms only when the SAME parameter name read from the URL
    appears in the sink expression. Unpaired sinks or sourceless sinks
    are never findings.
    """
    text = js_text or ""
    if not text:
        return []
    names: set[str] = set()
    for rx in _SOURCE_RES:
        for m in rx.finditer(text):
            try:
                name = m.group(1)
            except IndexError:
                name = ""
            if name and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", name):
                names.add(name)
    # Scope-local pairing: minified bundles reuse single-letter vars
    # across functions, so aliases are resolved per sink within a bounded
    # backward window (same-function heuristic), never bundle-global.
    flows: list[dict[str, str]] = []
    for kind, rx in _SINK_RES:
        for m in rx.finditer(text):
            expr = m.group(1)
            window = text[max(0, m.start() - 2000):m.start()]
            hit = ""
            for name in names:
                if param and name != param:
                    continue
                if not re.search(rf"queryParams\s*\.\s*{re.escape(name)}\b", window) \
                        and not re.search(rf"queryParamMap\s*\.\s*get\s*\(\s*['\"]{re.escape(name)}['\"]", window):
                    continue
                if re.search(rf"\b{re.escape(name)}\b", expr):
                    hit = name
                    break
                # Single-hop alias inside the window: var assigned from the
                # URL read, then used in the sink expression.
                for am in re.finditer(
                        r"(?:(?:let|var|const)\s+)?(?:this\.)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^;]{1,200})",
                        window):
                    var, rhs = am.group(1), am.group(2)
                    if re.search(rf"queryParams\s*\.\s*{re.escape(name)}\b", rhs) \
                            and re.search(rf"\b{re.escape(var)}\b", expr):
                        hit = f"{name} via {var}"
                        break
                if hit:
                    break
            if hit:
                flows.append({"source": f"url-query:{hit}",
                              "sink_kind": kind,
                              "excerpt": expr[:200]})
    return flows[:5]


extract_script_urls = extract_script_sources
