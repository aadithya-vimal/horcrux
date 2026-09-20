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
