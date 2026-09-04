from __future__ import annotations

import re
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
    """Analyzes raw JavaScript content string to extract candidate routes and parameters."""
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

    return {"routes": routes, "parameters": parameters}


def extract_html_inputs(html: str, endpoint: str = "") -> list[dict[str, str]]:
    """Extracts form input parameters as a list of dicts with name and endpoint."""
    params = extract_form_parameters(html, endpoint or "http://target.local")
    return [{"name": p.name, "endpoint": p.endpoint, "location": p.location} for p in params]


extract_script_urls = extract_script_sources
