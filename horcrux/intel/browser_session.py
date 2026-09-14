"""Browser / HTTP session evidence layer (Phase 7 Part 8, Phase 8 Part 2).

Pluggable adapter boundary. All browser/session evidence converges into the
SAME semantic ApplicationModel via ``ingest_http_request`` and related
ingestion — there is deliberately no separate browser data model.

Provenance tracked per observation: browser, http, javascript, crawler,
scanner, operator, inference.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse


def _infer_params_from_url(path: str) -> list[str]:
    params: list[str] = []
    if "?" in path:
        qs = path.split("?", 1)[1]
        for pair in qs.split("&"):
            name = pair.split("=", 1)[0].strip()
            if name and name not in params:
                params.append(name)
    return params


def record_browser_navigation(ctx: dict[str, Any]) -> dict[str, Any]:
    """Record a (possibly stubbed) browser navigation into the ApplicationModel.

    ``ctx`` keys: url, actions (list), network_requests (list of dicts),
    cookies (list), forms (list), application_model (ApplicationModel),
    identity (str). Returns summary dict with ``evidence`` list.
    """
    from horcrux.intel.ingestion import ingest_http_request

    url: str = ctx.get("url", "")
    actions: list = ctx.get("actions", []) or []
    network_requests: list = ctx.get("network_requests", []) or []
    cookies: list = ctx.get("cookies", []) or []
    forms: list = ctx.get("forms", []) or []
    identity: str = ctx.get("identity", "anonymous")
    app = ctx.get("application_model")

    parsed = urlparse(url or "http://target.local/")
    evidence: list[dict] = []

    def _record(method: str, path: str, params: list[str] | None = None,
                source: str = "browser"):
        evidence.append({"evidence_type": "endpoint_observation",
                         "data": {"method": method, "path": path,
                                  "identity": identity},
                         "source": source, "confidence": 0.85})
        if app is not None:
            try:
                ingest_http_request(app, method=method, path=path,
                                    identity=identity,
                                    parameters=params or _infer_params_from_url(path),
                                    source=source)
            except Exception:
                pass

    if url:
        _record("GET", parsed.path or "/")
    for req in network_requests:
        if isinstance(req, dict):
            _record(req.get("method", "GET"), req.get("path", "/"),
                    req.get("parameters"), source="browser")
        elif isinstance(req, str):
            _record("GET", req)
    # UI actions that imply navigation / API calls.
    for act in actions:
        if isinstance(act, dict):
            kind = str(act.get("type", act.get("action", ""))).lower()
            if kind in ("navigate", "goto") and act.get("url"):
                _record("GET", urlparse(act["url"]).path or "/")
            elif kind in ("submit", "form") and act.get("path"):
                _record(act.get("method", "POST"), act["path"],
                        act.get("inputs"), source="browser")
            elif kind in ("click", "api") and act.get("path"):
                _record(act.get("method", "GET"), act["path"], source="browser")
    # Forms -> model forms + params.
    if app is not None and forms:
        from horcrux.intel.application_model import SemanticForm
        for f in forms:
            if not isinstance(f, dict):
                continue
            try:
                sem = SemanticForm(action=f.get("action", parsed.path or "/"),
                                   method=f.get("method", "POST"),
                                   inputs=f.get("inputs", []),
                                   page_url=url,
                                   evidence_refs=[f"browser:{url}"])
                sem.ensure_id()
                if not any(x.id == sem.id for x in app.forms):
                    app.forms.append(sem)
                evidence.append({"evidence_type": "form_observation",
                                 "data": {"action": sem.action}, "source": "browser",
                                 "confidence": 0.9})
            except Exception:
                continue
    # Cookies/session -> identity session evidence.
    if app is not None and cookies:
        try:
            from horcrux.intel.application_model import IdentityRole, SemanticIdentity
            role = IdentityRole.USER if identity != "anonymous" else IdentityRole.ANONYMOUS
            ident = SemanticIdentity(role=role, label=identity,
                                     session_evidence=[f"browser-cookie:{c}" if isinstance(c, str)
                                                       else f"browser-cookie:{c.get('name', 'session')}"
                                                       for c in cookies[:5]])
            app.upsert_identity(ident)
            evidence.append({"evidence_type": "identity_context",
                             "data": {"identity": identity,
                                      "cookies": len(cookies)},
                             "source": "browser", "confidence": 0.8})
        except Exception:
            pass
    return {"url": url, "identity": identity,
            "requests_recorded": len(evidence),
            "forms": len(forms), "cookies": len(cookies),
            "actions": len(actions), "evidence": evidence,
            "stub": True}


class BrowserAdapter:
    """Pluggable adapter interface. Override ``navigate`` for a real runtime."""

    name = "stub"

    def is_available(self) -> bool:
        return True

    def navigate(self, ctx: dict[str, Any]) -> dict[str, Any]:
        return record_browser_navigation(ctx)


class StubBrowserAdapter(BrowserAdapter):
    """Default stub — always available, no external runtime required."""


def record_browser_session(obs: Any, app: Any = None,
                           identity: str = "anonymous") -> dict[str, Any]:
    """Converge a :class:`BrowserObservation` into the ApplicationModel.

    Mapping (Part 2):
    - browser request -> HTTP evidence -> ``ingest_http_request()``
    - DOM-discovered route -> route evidence -> ApplicationModel
    - JS-loaded API -> API evidence -> ApplicationModel
    - cookie/session observation -> session evidence (hashed) -> identity
    - form/workflow action -> workflow evidence -> ApplicationModel

    Every observation carries ``browser`` provenance. Returns a summary with
    per-item evidence records.
    """
    from urllib.parse import urlparse

    from horcrux.intel.ingestion import (
        ingest_crawler_paths,
        ingest_http_request,
    )

    url = getattr(obs, "url", "") or ""
    ident = getattr(obs, "identity", "") or identity
    provenance = getattr(obs, "provenance", "browser") or "browser"
    evidence: list[dict] = []
    parsed = urlparse(url or "http://target.local/")
    base_path = parsed.path or "/"

    def _ev(etype: str, data: dict, confidence: float = 0.85) -> None:
        evidence.append({"evidence_type": etype, "data": data,
                         "source": "browser", "confidence": confidence,
                         "provenance": provenance})

    if app is not None and url:
        try:
            ingest_http_request(app, method="GET", path=base_path,
                                identity=ident, source="browser")
            _ev("endpoint_observation",
                {"method": "GET", "path": base_path, "identity": ident})
        except Exception:
            pass

    # Network/API calls -> HTTP evidence (dedupe via ingestion stable IDs).
    for req in (getattr(obs, "requests", []) or []) + (getattr(obs, "api_calls", []) or []):
        if not isinstance(req, dict):
            continue
        raw_url = req.get("url", "")
        try:
            rpath = urlparse(raw_url).path or "/"
        except Exception:
            rpath = "/"
        if not rpath:
            continue
        method = str(req.get("method", "GET")).upper()
        params = req.get("parameters") or _infer_params_from_url(raw_url)
        if app is not None:
            try:
                ingest_http_request(app, method=method, path=rpath,
                                    identity=ident, parameters=params,
                                    source="browser")
            except Exception:
                pass
        _ev("endpoint_observation",
            {"method": method, "path": rpath, "identity": ident,
             "api": req in (getattr(obs, "api_calls", []) or [])})

    # DOM routes + JS-loaded APIs -> route evidence.
    dom_routes = [r for r in (getattr(obs, "dom_routes", []) or [])
                  if isinstance(r, str) and r.startswith("/")]
    if app is not None and dom_routes:
        try:
            ingest_crawler_paths(app, dom_routes, source="browser")
        except Exception:
            pass
        for r in dom_routes[:30]:
            _ev("route_discovery", {"path": r})

    # Forms -> model forms.
    if app is not None and getattr(obs, "forms", []):
        from horcrux.intel.application_model import SemanticForm
        for f in obs.forms:
            if not isinstance(f, dict):
                continue
            try:
                sem = SemanticForm(action=f.get("action", base_path),
                                   method=f.get("method", "POST"),
                                   inputs=f.get("inputs", []),
                                   page_url=url,
                                   evidence_refs=[f"browser:{url}"])
                sem.ensure_id()
                if not any(x.id == sem.id for x in app.forms):
                    app.forms.append(sem)
                _ev("form_observation", {"action": sem.action}, 0.9)
            except Exception:
                continue

    # Cookies/session -> hashed session evidence on the identity.
    cookies = getattr(obs, "cookies", []) or []
    if app is not None and cookies:
        try:
            from horcrux.intel.application_model import IdentityRole, SemanticIdentity
            from horcrux.intel.browser import hash_secret
            role = IdentityRole.USER if ident != "anonymous" else IdentityRole.ANONYMOUS
            hashed = []
            for c in cookies[:8]:
                name = c.get("name", "session") if isinstance(c, dict) else str(c)
                raw = c.get("value", "") if isinstance(c, dict) else ""
                hashed.append(f"browser-cookie:{name}={hash_secret(raw) if raw else 'empty'}")
            app.upsert_identity(SemanticIdentity(role=role, label=ident,
                                                 session_evidence=hashed))
            _ev("identity_context",
                {"identity": ident, "cookies": len(cookies)}, 0.8)
        except Exception:
            pass

    # Storage keys -> client-side state observations (names only, no values).
    for key in (getattr(obs, "storage_keys", []) or [])[:20]:
        _ev("client_state_observation", {"key": str(key)}, 0.6)

    for msg in (getattr(obs, "console_messages", []) or [])[:10]:
        _ev("console_observation", {"message": str(msg)[:160]}, 0.5)

    return {"url": url, "identity": ident, "provenance": provenance,
            "evidence": evidence, "requests": len(getattr(obs, "requests", []) or []),
            "dom_routes": len(dom_routes),
            "forms": len(getattr(obs, "forms", []) or []),
            "cookies": len(cookies)}
