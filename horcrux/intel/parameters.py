"""Semantic parameter classification for targeted security testing.

Classifies parameters into semantic security roles (e.g. object IDs, search queries,
redirect targets, file paths, business quantities) to drive tailored test payloads
instead of blind payload spraying.
"""

from __future__ import annotations

import re
from enum import Enum


class ParameterSemanticRole(str, Enum):
    OBJECT_ID = "object_id"
    USER_ID = "user_id"
    REDIRECT_URL = "redirect_url"
    TARGET_URL = "target_url"
    SEARCH_QUERY = "search_query"
    FILE_PATH = "file_path"
    BUSINESS_LOGIC = "business_logic"
    PRIVILEGE_ROLE = "privilege_role"
    AUTH_TOKEN = "auth_token"
    SORT_ORDER = "sort_order"
    GENERIC_INPUT = "generic_input"


class ParameterProvenance(str, Enum):
    OBSERVED_REQUEST = "OBSERVED_REQUEST"
    HTML_FORM = "HTML_FORM"
    JS_REQUEST_CONSTRUCTION = "JS_REQUEST_CONSTRUCTION"
    OPENAPI = "OPENAPI"
    GRAPHQL_SCHEMA = "GRAPHQL_SCHEMA"
    BROWSER_NETWORK = "BROWSER_NETWORK"
    OPERATOR = "OPERATOR"
    UNKNOWN = "UNKNOWN"


PARAMETER_LOCATIONS = frozenset({"query", "path", "header", "body", "json", "form", "multipart"})

_OWNING_SOURCES = frozenset({
    "url", "proxy", "http", "browser", "browser_network",
    "html_form", "form", "html", "openapi", "swagger", "api_discovery",
    "graphql", "operator", "observed_request", "fixture",
})


def is_owned_in_model(app_params: object, name: str, endpoint_path: str) -> bool:
    """True only when the application model carries endpoint-specific
    evidence for (name, endpoint) from a non-probe source.

    Probe/fuzz observations corroborate but never create ownership:
    a parameter sprayed by param_fuzz onto an endpoint does not become
    owned by that endpoint.
    """
    want = _norm_path(endpoint_path or "")
    if not want or not (name or "").strip() or is_static_asset_endpoint(want):
        return False
    try:
        items = list(app_params or [])
    except TypeError:
        return False
    for p in items:
        if str(getattr(p, "name", "") or "").lower() != str(name).lower():
            continue
        if str(getattr(p, "location", "") or "").lower() == "client_state":
            continue
        mine = _norm_path(str(getattr(p, "endpoint", "") or ""))
        if not mine or mine != want or is_static_asset_endpoint(mine):
            continue
        prov = str(getattr(p, "provenance", "") or "").upper()
        if prov and prov != "UNKNOWN":
            return True
        if str(getattr(p, "source", "") or "").lower() in _OWNING_SOURCES:
            return True
    return False


_SOURCE_TO_PROVENANCE: dict[str, ParameterProvenance] = {
    "url": ParameterProvenance.OBSERVED_REQUEST,
    "proxy": ParameterProvenance.OBSERVED_REQUEST,
    "http": ParameterProvenance.OBSERVED_REQUEST,
    "browser": ParameterProvenance.BROWSER_NETWORK,
    "browser_network": ParameterProvenance.BROWSER_NETWORK,
    "html_form": ParameterProvenance.HTML_FORM,
    "form": ParameterProvenance.HTML_FORM,
    "html": ParameterProvenance.HTML_FORM,
    "javascript": ParameterProvenance.JS_REQUEST_CONSTRUCTION,
    "js": ParameterProvenance.JS_REQUEST_CONSTRUCTION,
    "js_analysis": ParameterProvenance.JS_REQUEST_CONSTRUCTION,
    "openapi": ParameterProvenance.OPENAPI,
    "swagger": ParameterProvenance.OPENAPI,
    "api_discovery": ParameterProvenance.OPENAPI,
    "graphql": ParameterProvenance.GRAPHQL_SCHEMA,
    "operator": ParameterProvenance.OPERATOR,
}


def provenance_for_source(source: str, explicit: str = "") -> str:
    """Resolve explicit provenance, else map legacy source strings.

    An explicit UNKNOWN carries no information and falls through to the
    source mapping (otherwise records explicitly marked UNKNOWN could
    never be upgraded by their source channel).
    """
    if explicit and explicit != ParameterProvenance.UNKNOWN.value \
            and explicit in {p.value for p in ParameterProvenance}:
        return explicit
    return _SOURCE_TO_PROVENANCE.get((source or "").lower(), ParameterProvenance.UNKNOWN).value


def _norm_path(p: str) -> str:
    ep = (p or "").strip().split("?")[0].split("#")[0]
    if "://" in ep:
        try:
            from urllib.parse import urlparse as _urlparse
            ep = _urlparse(ep).path or "/"
        except Exception:
            ep = "/"
    if ep and not ep.startswith("/"):
        ep = "/" + ep
    return ep or ""


def has_endpoint_specific_provenance(param: object, endpoint_path: str) -> bool:
    """A parameter may ONLY generate parameter security tests when it has
    endpoint-specific provenance: its recorded endpoint equals the target
    endpoint, it is not client_state/static-asset bound, and its provenance
    is endpoint-evidence (never a global promotion)."""
    name = str(getattr(param, "name", "") or "").strip()
    if not name:
        return False
    if str(getattr(param, "location", "") or "").lower() == "client_state":
        return False
    mine = _norm_path(str(getattr(param, "endpoint", "") or ""))
    want = _norm_path(endpoint_path or "")
    if not mine or not want or mine != want:
        return False
    if is_static_asset_endpoint(mine):
        return False
    prov = str(getattr(param, "provenance", "") or "").upper() or "UNKNOWN"
    if prov in {p.value for p in ParameterProvenance if p != ParameterProvenance.UNKNOWN}:
        # JS_REQUEST_CONSTRUCTION bound to a JS bundle URL is not ownership:
        # the bundle is not the server endpoint.
        if prov == ParameterProvenance.JS_REQUEST_CONSTRUCTION.value and mine != want:
            return False
        return True
    # Legacy fallback: exact endpoint match is endpoint-specific evidence
    # (never a cross-endpoint promotion). JS bundle sources and empty
    # sources without any evidence are excluded.
    src = str(getattr(param, "source", "") or "").lower()
    if src in ("javascript", "js", "js_analysis"):
        # JS tokens anchored to a bundle URL are not server ownership.
        return False
    if mine != want:
        return False
    ev = list(getattr(param, "evidence_refs", []) or [])
    if src or ev or getattr(param, "endpoint", ""):
        return True
    return False


_OBJECT_ID_PATTERNS = re.compile(r"^(id|uuid|uid|guid|basket_?id|product_?id|order_?id|item_?id|entity_?id)$", re.IGNORECASE)
_USER_ID_PATTERNS = re.compile(r"^(user_?id|account_?id|owner_?id|creator_?id|profile_?id|client_?id)$", re.IGNORECASE)
_REDIRECT_PATTERNS = re.compile(r"^(redirect|redirect_?url|return|return_?url|next|forward|dest|destination|goto)$", re.IGNORECASE)
_TARGET_URL_PATTERNS = re.compile(r"^(url|target|host|callback|webhook|fetch|proxy|endpoint|feed)$", re.IGNORECASE)
_SEARCH_PATTERNS = re.compile(r"^(q|query|search|keyword|term|filter|find|lookup)$", re.IGNORECASE)
_FILE_PATH_PATTERNS = re.compile(r"^(file|path|filename|filepath|folder|dir|directory|doc|document|template|include)$", re.IGNORECASE)
_BUSINESS_LOGIC_PATTERNS = re.compile(r"^(quantity|qty|price|amount|total|discount|coupon|points|credits|balance|rate)$", re.IGNORECASE)
_PRIVILEGE_ROLE_PATTERNS = re.compile(r"^(role|role_?id|admin|is_?admin|privilege|group|permission|tier)$", re.IGNORECASE)
_AUTH_TOKEN_PATTERNS = re.compile(r"^(token|access_?token|auth|authorization|jwt|session|session_?id|code|apikey|api_?key)$", re.IGNORECASE)
_SORT_PATTERNS = re.compile(r"^(sort|order|order_?by|sort_?by|direction|dir|column)$", re.IGNORECASE)


def classify_parameter(name: str, endpoint: str = "") -> ParameterSemanticRole:
    """Classify a parameter into its primary security role based on name and endpoint context."""
    n = (name or "").strip()
    if not n:
        return ParameterSemanticRole.GENERIC_INPUT

    if _OBJECT_ID_PATTERNS.match(n):
        return ParameterSemanticRole.OBJECT_ID
    if _USER_ID_PATTERNS.match(n):
        return ParameterSemanticRole.USER_ID
    if _REDIRECT_PATTERNS.match(n):
        return ParameterSemanticRole.REDIRECT_URL
    if _TARGET_URL_PATTERNS.match(n):
        return ParameterSemanticRole.TARGET_URL
    if _SEARCH_PATTERNS.match(n):
        return ParameterSemanticRole.SEARCH_QUERY
    if _FILE_PATH_PATTERNS.match(n):
        return ParameterSemanticRole.FILE_PATH
    if _BUSINESS_LOGIC_PATTERNS.match(n):
        return ParameterSemanticRole.BUSINESS_LOGIC
    if _PRIVILEGE_ROLE_PATTERNS.match(n):
        return ParameterSemanticRole.PRIVILEGE_ROLE
    if _AUTH_TOKEN_PATTERNS.match(n):
        return ParameterSemanticRole.AUTH_TOKEN
    if _SORT_PATTERNS.match(n):
        return ParameterSemanticRole.SORT_ORDER

    # Secondary contextual checks
    n_lower = n.lower()
    if "search" in endpoint.lower() and n_lower in ("q", "s", "query", "term"):
        return ParameterSemanticRole.SEARCH_QUERY
    if "redirect" in endpoint.lower() or "callback" in endpoint.lower():
        return ParameterSemanticRole.REDIRECT_URL

    return ParameterSemanticRole.GENERIC_INPUT


def is_static_asset_endpoint(path: str) -> bool:
    """Check if an endpoint path points to a client-side bundle or static asset."""
    p = (path or "").lower().split("?")[0]
    return p.endswith((".js", ".css", ".png", ".jpg", ".jpeg", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map"))


def normalize_param_endpoint(endpoint: str) -> str:
    """Strip scheme/host/query so bundle URLs compare as server paths."""
    ep = (endpoint or "").strip().split("?")[0].split("#")[0]
    if "://" in ep:
        try:
            from urllib.parse import urlparse as _urlparse
            ep = _urlparse(ep).path or "/"
        except Exception:
            ep = "/"
    if ep and not ep.startswith("/"):
        ep = "/" + ep
    return ep or ""


def is_server_bound_parameter(param: object, known_paths: set[str]) -> bool:
    """True only when a parameter is bound to an actual server-side request.

    A JS-extracted token (e.g. ``isPeriodic`` from ``polyfills.js``) is not
    executable security-test input: it must name a server location, that
    location must not be a static asset, and the location must exist in the
    discovered/model route set. ``known_paths`` must already be normalized.
    """
    name = str(getattr(param, "name", "") or "").strip()
    if not name or not re.match(r"^[A-Za-z_][A-Za-z0-9_.\-]{0,63}$", name):
        return False
    if str(getattr(param, "location", "") or "").lower() == "client_state":
        return False
    ep = normalize_param_endpoint(str(getattr(param, "endpoint", "") or ""))
    if not ep or is_static_asset_endpoint(ep):
        return False
    return ep in (known_paths or set())
