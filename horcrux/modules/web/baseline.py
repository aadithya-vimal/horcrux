from __future__ import annotations

import secrets
from urllib.parse import urljoin
import httpx

from horcrux.models import (
    BaselineClassification,
    ResponseFingerprint,
    WebApplicationType,
)
from horcrux.modules.web.fingerprint_engine import (
    fingerprint_response,
    same_response_family,
)


def probe_url(client: httpx.Client, url: str) -> ResponseFingerprint | None:
    """Safely issues an HTTP GET and fingerprints the response."""
    try:
        resp = client.get(url, follow_redirects=False)
        redirect_chain = [str(resp.url)]
        if resp.is_redirect and "location" in resp.headers:
            redirect_chain.append(resp.headers["location"])
        return fingerprint_response(
            status_code=resp.status_code,
            text=resp.text,
            headers=dict(resp.headers),
            url=str(resp.url),
            redirect_chain=redirect_chain,
        )
    except Exception:
        return None


def detect_baseline(
    client: httpx.Client,
    base_url: str,
) -> tuple[BaselineClassification, list[ResponseFingerprint], WebApplicationType]:
    """
    Establishes multi-probe HTTP baseline behavior and classifies web application type.

    Probes:
      1. Random alphanumeric route (e.g. /_horcrux_rnd_<token>)
      2. Random path with .html extension (e.g. /_horcrux_<token>.html)
      3. Random nested path (e.g. /_horcrux_dir/<token>)
      4. Root path (/) for app shell / SPA comparison

    Returns:
      (BaselineClassification, list[ResponseFingerprint], WebApplicationType)
    """
    token1 = f"_horcrux_probe_{secrets.token_hex(6)}"
    token2 = f"_horcrux_probe_{secrets.token_hex(6)}.html"
    token3 = f"_horcrux_sub_{secrets.token_hex(4)}/{secrets.token_hex(4)}"

    probes = [token1, token2, token3]
    probe_fps: list[ResponseFingerprint] = []

    for p in probes:
        target_url = urljoin(base_url.rstrip("/") + "/", p)
        fp = probe_url(client, target_url)
        if fp:
            probe_fps.append(fp)

    # Also inspect root URL
    root_fp = probe_url(client, base_url.rstrip("/") + "/")

    if not probe_fps:
        return BaselineClassification.UNKNOWN, [], WebApplicationType.UNKNOWN

    statuses = [fp.status_code for fp in probe_fps]

    # Check 1: Normal 404 (All probes return 404)
    if all(s == 404 for s in statuses):
        # Determine web app type from root
        app_type = WebApplicationType.STATIC_SITE
        if root_fp:
            if root_fp.is_spa_fallback or "api" in root_fp.content_type:
                app_type = WebApplicationType.API if "json" in root_fp.content_type else WebApplicationType.SPA
            elif root_fp.is_html and ("form" in root_fp.structural_signature or "input" in root_fp.structural_signature):
                app_type = WebApplicationType.TRADITIONAL_WEB_APP
        return BaselineClassification.NORMAL_404, probe_fps, app_type

    # Check 2: Redirect Catch-All (All probes return 301/302/307/308)
    if all(s in {301, 302, 307, 308} for s in statuses):
        return BaselineClassification.REDIRECT_CATCH_ALL, probe_fps, WebApplicationType.TRADITIONAL_WEB_APP

    # Check 3: SPA Fallback (All probes return 200 with HTML identical/near-identical to root or each other)
    if all(s == 200 for s in statuses):
        # Compare probes to root and each other
        all_match_each_other = all(
            same_response_family(probe_fps[0], fp, threshold=0.88) for fp in probe_fps
        )
        matches_root = root_fp is not None and same_response_family(root_fp, probe_fps[0], threshold=0.88)
        has_spa_markers = (root_fp and root_fp.is_spa_fallback) or any(fp.is_spa_fallback for fp in probe_fps)

        if (matches_root or all_match_each_other) and has_spa_markers:
            return BaselineClassification.SPA_FALLBACK, probe_fps, WebApplicationType.SPA

        # Check for Soft 404 (200 with error page text)
        error_keywords = ("not found", "does not exist", "error 404", "page not found", "cannot find", "nothing here")
        has_soft404_text = any(
            any(kw in fp.title.lower() for kw in error_keywords) for fp in probe_fps
        )
        if has_soft404_text or all_match_each_other:
            return BaselineClassification.SOFT_404, probe_fps, WebApplicationType.TRADITIONAL_WEB_APP

    # Check 4: Generic Error Template (e.g. 500 or 400 with identical error template)
    if all(s in {500, 502, 503, 400, 403} for s in statuses):
        return BaselineClassification.GENERIC_ERROR_TEMPLATE, probe_fps, WebApplicationType.UNKNOWN

    # Default fallback
    app_type = WebApplicationType.UNKNOWN
    if root_fp:
        if root_fp.is_json or "api" in root_fp.content_type:
            app_type = WebApplicationType.API
        elif root_fp.is_spa_fallback:
            app_type = WebApplicationType.SPA
        elif root_fp.is_html:
            app_type = WebApplicationType.TRADITIONAL_WEB_APP

    return BaselineClassification.UNKNOWN, probe_fps, app_type
