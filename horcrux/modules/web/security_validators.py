"""Generic evidence-driven security validators (no hardcoded app knowledge).

Each validator follows: baseline -> mutation -> comparison -> evidence ->
adjudication-ready verdict. All operate on an injectable ``request_fn`` so
they work live (httpx), against fixtures, and in unit tests without network.

Verdict vocabulary (per validator): NO_EFFECT, ERROR_SIGNAL,
BEHAVIORAL_DIFFERENTIAL, STRONG_*_EVIDENCE, BLOCKED, plus
INSUFFICIENT_EVIDENCE when the baseline itself is unusable.
"""

from __future__ import annotations

import hashlib
import html
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import quote, urlencode

# ---------------------------------------------------------------------------
# Structured evidence
# ---------------------------------------------------------------------------

_SECRET_RE = re.compile(
    r"(?i)(api[_-]?key|secret|passwd|password|token|authorization\s*:|cookie\s*:)\s*[:=]\s*\S+"
)


def redact(text: str) -> str:
    def _sub(m: re.Match) -> str:
        return "[REDACTED]"
    return _SECRET_RE.sub(_sub, str(text or ""))


def build_evidence(
    capability: str,
    test_id: str,
    target: str,
    request: dict[str, Any],
    response_meta: dict[str, Any],
    excerpt: str,
    payload: str = "",
    baseline: dict[str, Any] | None = None,
    mutated: dict[str, Any] | None = None,
    auth_context: str = "anonymous",
    stage: str = "OBSERVED",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "capability": capability,
        "test_id": test_id,
        "target": target,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "stage": stage,  # OBSERVED|SUPPORTED|CONFIRMED|REFUTED|INSUFFICIENT_EVIDENCE
        "request": {k: redact(v) if isinstance(v, str) else v for k, v in request.items()},
        "response_meta": response_meta,
        "response_excerpt": redact(excerpt)[:2000],
        "payload": redact(payload)[:1000],
        "baseline_comparison": baseline or {},
        "mutated_comparison": mutated or {},
        "authentication_context": auth_context,
        **(extra or {}),
    }


@dataclass
class ValidatorResult:
    verdict: str
    confidence: float
    evidence: list[dict[str, Any]] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    stage: str = "OBSERVED"


RequestFn = Callable[..., dict[str, Any]]
# request_fn(method, url, query=None, body=None, headers=None, cookies=None,
#            raw_body=None, content_type=None) -> {status, headers, text, elapsed_ms}


def httpx_request_fn(method: str, url: str, query: dict | None = None,
                     body: dict | None = None, headers: dict | None = None,
                     cookies: dict | None = None, raw_body: Any = None,
                     content_type: str | None = None) -> dict[str, Any]:
    import httpx
    t0 = time.monotonic()
    try:
        with httpx.Client(verify=False, timeout=10.0, follow_redirects=False) as c:
            kw: dict[str, Any] = {}
            if headers:
                kw["headers"] = headers
            if cookies:
                kw["cookies"] = cookies
            if raw_body is not None:
                kw["content"] = raw_body
                if content_type:
                    kw.setdefault("headers", {}).update({"Content-Type": content_type})
            elif body is not None:
                kw["json"] = body
            resp = c.request(method, url, params=query, **kw)
            return {"status": resp.status_code, "headers": dict(resp.headers),
                    "text": resp.text[:8000], "elapsed_ms": (time.monotonic() - t0) * 1000.0}
    except Exception as exc:
        return {"status": 0, "headers": {}, "text": f"request failed: {exc}",
                "elapsed_ms": (time.monotonic() - t0) * 1000.0, "error": str(exc)}


def _fingerprint(text: str) -> dict[str, Any]:
    t = text or ""
    title = ""
    m = re.search(r"<title[^>]*>(.*?)</title>", t, re.I | re.S)
    if m:
        title = re.sub(r"\s+", " ", m.group(1)).strip()[:120]
    return {"length": len(t),
            "hash": hashlib.sha256(t.encode("utf-8", errors="replace")).hexdigest()[:16],
            "title": title}


_DB_ERROR_RE = re.compile(
    r"(sqlite3?|sequelize|syntax error|unterminated|near \"|near '|'.*not terminate|"
    r"mysql|you have an error in your sql|psql|pg_query|ora-\d+|sqlserver|odbc|"
    r"sqlite_exception|database error|sql syntax)", re.I)


def _blocked(resp: dict) -> bool:
    if resp.get("status") in (403, 406, 418, 429):
        t = (resp.get("text") or "").lower()
        return any(k in t for k in ("blocked", "forbidden", "waf", "mod_security", "denied", "captcha")) \
            or resp.get("status") in (403, 406)
    return False


# ---------------------------------------------------------------------------
# 1. SQL injection — differential
# ---------------------------------------------------------------------------

def validate_sqli(request_fn: RequestFn, method: str, url: str, param: str,
                  location: str = "query", capability: str = "sqli_probe",
                  test_id: str = "sqli", auth_context: str = "anonymous",
                  base_value: str = "test123") -> ValidatorResult:
    """Baseline -> harmless syntax -> boolean differential -> error inputs."""
    def _send(value: str) -> dict:
        if location == "body":
            return request_fn(method if method != "GET" else "POST", url, body={param: value})
        if location == "path":
            return request_fn(method, url.replace("{id}", quote(value, safe="")) + ("" if "{id}" in url else f"/{quote(value, safe='')}"))
        return request_fn(method, url, query={param: value})

    ev: list[dict] = []
    try:
        base = _send(base_value)
    except Exception as exc:
        return ValidatorResult("INSUFFICIENT_EVIDENCE", 0.2, stage="INSUFFICIENT_EVIDENCE",
                               details={"error": str(exc)})
    if base.get("status") == 0:
        return ValidatorResult("INSUFFICIENT_EVIDENCE", 0.2, stage="INSUFFICIENT_EVIDENCE",
                               details={"error": base.get("error", "no baseline")})
    base_fp = _fingerprint(base.get("text", ""))

    def _ev(tag: str, req_v: str, resp: dict, stage: str, extra: dict | None = None) -> dict:
        fp = _fingerprint(resp.get("text", ""))
        return build_evidence(capability, test_id, url,
                              {"method": method, "url": url, "param": param, "value": req_v},
                              {"status": resp.get("status"), "elapsed_ms": round(resp.get("elapsed_ms", 0), 1)},
                              resp.get("text", "")[:1500], payload=req_v,
                              baseline={"status": base.get("status"), **base_fp},
                              mutated={"status": resp.get("status"), **fp},
                              auth_context=auth_context, stage=stage, extra=extra)

    ev.append(_ev("baseline", base_value, base, "OBSERVED"))
    # 2. harmless syntax mutations (should be NO_EFFECT on healthy endpoint)
    harmless = _send(base_value + "'")
    if _blocked(harmless):
        ev.append(_ev("harmless-quote", base_value + "'", harmless, "OBSERVED", {"signal": "BLOCKED"}))
        return ValidatorResult("BLOCKED", 0.6, ev, {"signal": "waf/blocked"}, "OBSERVED")
    h_fp = _fingerprint(harmless.get("text", ""))
    h_err = _DB_ERROR_RE.search(harmless.get("text", "") or "")
    # 3. boolean differential: true vs false conditions
    r_true = _send(f"{base_value}' AND '1'='1")
    r_false = _send(f"{base_value}' AND '1'='2")
    t_fp, f_fp = _fingerprint(r_true.get("text", "")), _fingerprint(r_false.get("text", ""))
    ev.append(_ev("bool-true", f"{base_value}' AND '1'='1", r_true, "OBSERVED"))
    ev.append(_ev("bool-false", f"{base_value}' AND '1'='2", r_false, "OBSERVED"))

    bool_differential = (
        r_true.get("status") != r_false.get("status")
        or (t_fp["hash"] != f_fp["hash"]
            and abs(t_fp["length"] - f_fp["length"]) > 20
            and _fingerprint(base.get("text", ""))["hash"] in (t_fp["hash"], f_fp["hash"])
            or (t_fp["hash"] != f_fp["hash"] and r_true.get("status", 0) < 500 and r_false.get("status", 0) < 500
                and abs(t_fp["length"] - f_fp["length"]) > 50)))
    # 4. error-oriented inputs (require DB/framework signature, not generic 500)
    err_probe = _send(base_value + '"\\;--')
    err_sig = _DB_ERROR_RE.search(err_probe.get("text", "") or "")
    ev.append(_ev("error-probe", base_value + '"\\;--', err_probe, "OBSERVED"))

    signals = []
    if h_err:
        signals.append(f"db-error:{h_err.group(0)[:40]}")
    if err_sig:
        signals.append(f"db-error:{err_sig.group(0)[:40]}")

    # Adjudication: single generic error string is never enough.
    if bool_differential and signals:
        return ValidatorResult("STRONG_SQLI_EVIDENCE", 0.92, ev,
                               {"signals": signals, "boolean_differential": True}, "CONFIRMED")
    if bool_differential:
        return ValidatorResult("BEHAVIORAL_DIFFERENTIAL", 0.75, ev,
                               {"boolean_differential": True}, "SUPPORTED")
    if len(signals) >= 2 or (h_err and err_sig and h_err.group(0).lower() == err_sig.group(0).lower()):
        return ValidatorResult("STRONG_SQLI_EVIDENCE", 0.88, ev, {"signals": signals}, "CONFIRMED")
    if signals:
        return ValidatorResult("ERROR_SIGNAL", 0.55, ev, {"signals": signals}, "OBSERVED")
    # harmless quote changed nothing and booleans identical -> NO_EFFECT
    if h_fp["hash"] == base_fp["hash"] and t_fp["hash"] == f_fp["hash"]:
        return ValidatorResult("NO_EFFECT", 0.7, ev, {}, "REFUTED")
    return ValidatorResult("NO_EFFECT", 0.5, ev, {}, "OBSERVED")


# ---------------------------------------------------------------------------
# 2. XSS — context-aware
# ---------------------------------------------------------------------------

_XSS_TOKEN = "hxss{TOKEN}t"
_HTML_CTX = re.compile(r"<[^>]*({T})[^>]*>|<!--.*?({T}).*?-->|<script[^>]*>.*?({T}).*?</script>|"
                       r"on\w+\s*=\s*[\"'][^\"']*({T})", re.I | re.S)


def _xss_context(body: str, token: str) -> str:
    b = body or ""
    if token not in b:
        return "not-reflected"
    idx = b.find(token)
    window = b[max(0, idx - 400):idx + 400]
    low = window.lower()
    if "<script" in low and token.lower() in low:
        return "script-context"
    if re.search(r"on\w+\s*=", low):
        m = re.search(r"<[^>]+>", window)
        if m and token in m.group(0):
            return "event-handler-attribute"
    m = re.search(r"<([a-z0-9]+)[^>]*>", window, re.I)
    if m and token in m.group(0):
        return "tag-attribute"
    if "<!--" in window and "-->" in window:
        return "comment-context"
    if re.search(r"<(div|p|span|h\d|td|li|body)[^>]*>", low):
        return "html-body"
    return "reflected-unknown-context"


def validate_xss_reflected(request_fn: RequestFn, method: str, url: str, param: str,
                           location: str = "query", capability: str = "xss_probe",
                           test_id: str = "xss", auth_context: str = "anonymous") -> ValidatorResult:
    import secrets as _s
    token = f"hxss{_s.token_hex(3)}t"
    payload = f"\"><svg onload=alert('{token}')>"
    if location == "body":
        resp = request_fn(method if method != "GET" else "POST", url, body={param: payload})
    else:
        resp = request_fn(method, url, query={param: payload})
    body = resp.get("text", "") or ""
    fp = _fingerprint(body)
    req = {"method": method, "url": url, "param": param, "value": payload}
    meta = {"status": resp.get("status")}
    # naive "payload appears" is NOT a finding: require unescaped executable context
    if token not in body and payload not in body and html.escape(payload) in body:
        ev = [build_evidence(capability, test_id, url, req, meta, body[:1500], payload,
                             auth_context=auth_context, stage="REFUTED",
                             extra={"context": "properly-escaped"})]
        return ValidatorResult("NO_EFFECT", 0.8, ev, {"context": "escaped"}, "REFUTED")
    if token not in body and payload not in body:
        ev = [build_evidence(capability, test_id, url, req, meta, body[:1500], payload,
                             auth_context=auth_context, stage="REFUTED",
                             extra={"context": "not-reflected"})]
        return ValidatorResult("NO_EFFECT", 0.75, ev, {"context": "not-reflected"}, "REFUTED")
    ctx = _xss_context(body, token if token in body else payload)
    # escaped reflection (e.g. &lt;svg) is not executable
    if html.escape("<svg") in body and "<svg" not in body[max(0, body.find(token) - 200):body.find(token) + 200] if token in body else True:
        if "&lt;" in body:
            ev = [build_evidence(capability, test_id, url, req, meta, body[:1500], payload,
                                 auth_context=auth_context, stage="REFUTED",
                                 extra={"context": "html-escaped"})]
            return ValidatorResult("NO_EFFECT", 0.8, ev, {"context": "html-escaped"}, "REFUTED")
    executable = ctx in ("script-context", "event-handler-attribute", "tag-attribute", "html-body")
    stage = "SUPPORTED" if executable else "OBSERVED"
    verdict = "STRONG_XSS_EVIDENCE" if executable else "ERROR_SIGNAL"
    ev = [build_evidence(capability, test_id, url, req, meta, body[:1500], payload,
                         auth_context=auth_context, stage=stage,
                         extra={"context": ctx, "sink": ctx})]
    return ValidatorResult(verdict, 0.85 if executable else 0.45, ev,
                           {"context": ctx, "unescaped": executable}, stage)


def validate_xss_stored(submit_fn: RequestFn, retrieve_fn: RequestFn,
                        submit: dict, retrieve: dict, param: str,
                        capability: str = "xss_probe",
                        test_id: str = "xss-stored") -> ValidatorResult:
    """Demonstrate input -> persistence -> later retrieval -> browser sink."""
    import secrets as _s
    token = f"sxss{_s.token_hex(3)}t"
    payload = f"<svg onload=alert('{token}')>"
    sub_resp = submit_fn(payload=payload, token=token)
    ret_resp = retrieve_fn()
    body = (ret_resp.get("text", "") or "")
    if token not in body:
        ev = [build_evidence(capability, test_id, str(retrieve.get("url", "")), submit, sub_resp,
                             str(sub_resp.get("text", ""))[:800], payload,
                             stage="REFUTED", extra={"flow": "no-persistence"})]
        return ValidatorResult("NO_EFFECT", 0.7, ev, {"flow": "not-persisted"}, "REFUTED")
    ctx = _xss_context(body, token)
    executable = ctx in ("script-context", "event-handler-attribute", "tag-attribute", "html-body")
    ev = [build_evidence(capability, test_id, str(retrieve.get("url", "")), submit, ret_resp,
                         body[:1500], payload, stage="SUPPORTED" if executable else "OBSERVED",
                         extra={"flow": "input->persist->retrieve->sink", "context": ctx})]
    if executable:
        return ValidatorResult("STRONG_XSS_EVIDENCE", 0.9, ev,
                               {"flow": "stored", "context": ctx}, "CONFIRMED")
    return ValidatorResult("ERROR_SIGNAL", 0.5, ev, {"flow": "stored-unconfirmed-sink"}, "OBSERVED")


def validate_xss_dom(page_html: str, sink_observations: dict,
                     token: str, capability: str = "xss_probe",
                     test_id: str = "xss-dom") -> ValidatorResult:
    """Correlate source token to a DOM sink (innerHTML/eval/location) + dialog/nav."""
    sinks = sink_observations.get("sinks", [])
    hit = [s for s in sinks if token in str(s.get("source", "")) or s.get("triggered")]
    dialog = bool(sink_observations.get("dialog") or sink_observations.get("navigation"))
    ev = [build_evidence(capability, test_id, sink_observations.get("url", ""), {"token": token},
                         {"sinks": len(sinks)}, page_html[:1500], token, stage="OBSERVED",
                         extra={"sinks": sinks[:5], "dialog": dialog})]
    if hit and dialog:
        return ValidatorResult("STRONG_XSS_EVIDENCE", 0.9, ev, {"sink": hit[0]}, "CONFIRMED")
    if hit:
        return ValidatorResult("BEHAVIORAL_DIFFERENTIAL", 0.65, ev, {"sink": hit[0]}, "SUPPORTED")
    return ValidatorResult("NO_EFFECT", 0.6, ev, {}, "REFUTED")


# ---------------------------------------------------------------------------
# 3. Path traversal
# ---------------------------------------------------------------------------

_PASSWD_RE = re.compile(r"root:x:0:0:[^\n]*\n[^\n]*:[^\n]*:\d+:\d+", re.M)
_WININI_RE = re.compile(r"\[fonts\]|\[extensions\]|for 16-bit app", re.I)
_TRAVERSAL_PAYLOADS = ["../../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd",
                       "....//....//etc/passwd", "..\\..\\..\\windows\\win.ini"]


def validate_traversal(request_fn: RequestFn, method: str, url: str, param: str,
                       location: str = "query", capability: str = "traversal_probe",
                       test_id: str = "traversal", auth_context: str = "anonymous",
                       base_value: str = "test.txt") -> ValidatorResult:
    base = request_fn(method, url, query={param: base_value} if location != "body" else None,
                      body={param: base_value} if location == "body" else None)
    if base.get("status") == 0:
        return ValidatorResult("INSUFFICIENT_EVIDENCE", 0.2, stage="INSUFFICIENT_EVIDENCE",
                               details={"error": "no baseline"})
    base_fp = _fingerprint(base.get("text", ""))
    ev = [build_evidence(capability, test_id, url, {"param": param, "value": base_value},
                         {"status": base.get("status")}, base.get("text", "")[:800],
                         base_value, auth_context=auth_context, stage="OBSERVED")]
    for p in _TRAVERSAL_PAYLOADS:
        if location == "body":
            resp = request_fn(method if method != "GET" else "POST", url, body={param: p})
        else:
            resp = request_fn(method, url, query={param: p})
        body = resp.get("text", "") or ""
        if resp.get("status") in (403, 406, 429) and len(body) < 2000:
            continue  # blocked variant, not evidence
        m = _PASSWD_RE.search(body) or _WININI_RE.search(body)
        fp = _fingerprint(body)
        if m and resp.get("status") == 200 and fp["hash"] != base_fp["hash"]:
            ev.append(build_evidence(capability, test_id, url, {"param": param, "value": p},
                                     {"status": resp.get("status")}, body[:1500], p,
                                     baseline={"status": base.get("status"), **base_fp},
                                     mutated={"status": resp.get("status"), **fp},
                                     auth_context=auth_context, stage="CONFIRMED",
                                     extra={"matched": m.group(0)[:120]}))
            return ValidatorResult("STRONG_TRAVERSAL_EVIDENCE", 0.93, ev,
                                   {"payload": p, "match": m.group(0)[:120]}, "CONFIRMED")
        ev.append(build_evidence(capability, test_id, url, {"param": param, "value": p},
                                 {"status": resp.get("status")}, body[:600], p,
                                 auth_context=auth_context, stage="OBSERVED"))
    # generic 4xx/5xx is never traversal evidence
    return ValidatorResult("NO_EFFECT", 0.7, ev, {}, "REFUTED")


# ---------------------------------------------------------------------------
# 4. File upload
# ---------------------------------------------------------------------------

def validate_upload(upload_fn: RequestFn, access_fn: RequestFn | None,
                    field: str = "file", filename: str = "probe.html",
                    content: bytes = b"<html>horcrux-probe</html>",
                    content_type: str = "text/html", capability: str = "upload_probe",
                    test_id: str = "upload") -> ValidatorResult:
    up = upload_fn(field=field, filename=filename, content=content, content_type=content_type)
    body = (up.get("text", "") or "")
    status = up.get("status", 0)
    loc = ""
    try:
        import json as _j
        loc = (_j.loads(body).get("location") or _j.loads(body).get("url") or "") if body.strip().startswith("{") else ""
    except Exception:
        m = re.search(r"(?:location|url|path)[\"']?\s*[:=]\s*[\"']([^\"']+)[\"']", body, re.I)
        loc = m.group(1) if m else ""
    if status in (400, 415, 422) or "reject" in body.lower() or "not allowed" in body.lower():
        ev = [build_evidence(capability, test_id, "", {"filename": filename}, up, body[:800],
                             filename, stage="REFUTED", extra={"handling": "rejected"})]
        return ValidatorResult("NO_EFFECT", 0.8, ev, {"handling": "rejected"}, "REFUTED")
    if status == 0 or status >= 500:
        return ValidatorResult("INSUFFICIENT_EVIDENCE", 0.3,
                               [build_evidence(capability, test_id, "", {"filename": filename}, up,
                                               body[:800], filename, stage="INSUFFICIENT_EVIDENCE")],
                               {}, "INSUFFICIENT_EVIDENCE")
    ev = [build_evidence(capability, test_id, "", {"filename": filename}, up, body[:1000],
                         filename, stage="OBSERVED", extra={"stored_location": loc})]
    # verify artifact is actually reachable / executable
    if loc and access_fn is not None:
        acc = access_fn(loc)
        acc_body = acc.get("text", "") or ""
        if acc.get("status") == 200 and ("horcrux-probe" in acc_body or "probe" in acc_body.lower()):
            ev.append(build_evidence(capability, test_id, loc, {"fetch": loc}, acc,
                                     acc_body[:800], filename, stage="CONFIRMED",
                                     extra={"artifact_reachable": True}))
            return ValidatorResult("STRONG_UPLOAD_EVIDENCE", 0.9, ev,
                                   {"location": loc, "executable": content_type in ("text/html",)},
                                   "CONFIRMED")
        ev.append(build_evidence(capability, test_id, loc, {"fetch": loc}, acc,
                                 acc_body[:600], filename, stage="OBSERVED"))
    # traversal-ish filename normalization check (generic, non-destructive)
    trav = upload_fn(field=field, filename="../../probe.html", content=b"probe",
                     content_type="text/plain")
    if trav.get("status") == 200 and (".." in (trav.get("text", "") or "") or "probe" in (trav.get("text", "") or "").lower()):
        ev.append(build_evidence(capability, test_id, "", {"filename": "../../probe.html"}, trav,
                                 trav.get("text", "")[:600], "../../probe.html", stage="SUPPORTED"))
        return ValidatorResult("BEHAVIORAL_DIFFERENTIAL", 0.65, ev, {"path_handling": "weak"}, "SUPPORTED")
    if status in (200, 201) and loc:
        return ValidatorResult("BEHAVIORAL_DIFFERENTIAL", 0.6, ev, {"stored": True}, "SUPPORTED")
    return ValidatorResult("NO_EFFECT", 0.5, ev, {}, "OBSERVED")


# ---------------------------------------------------------------------------
# 5. SSRF — controlled loopback validation
# ---------------------------------------------------------------------------

def validate_ssrf(request_fn: RequestFn, method: str, url: str, param: str,
                  location: str = "query", control_token: str = "horcrux-ssrf",
                  capability: str = "ssrf_probe", test_id: str = "ssrf",
                  auth_context: str = "anonymous") -> ValidatorResult:
    """Use caller-controlled destination; require server-side fetch evidence."""
    sentinel_url = f"http://127.0.0.1:9/{control_token}"
    if location == "body":
        resp = request_fn(method if method != "GET" else "POST", url, body={param: sentinel_url})
    else:
        resp = request_fn(method, url, query={param: sentinel_url})
    body = resp.get("text", "") or ""
    status = resp.get("status", 0)
    headers = {k.lower(): v for k, v in (resp.get("headers") or {}).items()}
    req = {"method": method, "url": url, "param": param, "value": sentinel_url}
    # open-redirect vs server-fetch: 3xx Location echoing the value is redirect, not SSRF
    if status in (301, 302, 303, 307, 308) and control_token in str(headers.get("location", "")):
        ev = [build_evidence(capability, test_id, url, req, {"status": status}, body[:600],
                             sentinel_url, auth_context=auth_context, stage="OBSERVED",
                             extra={"classification": "open-redirect-not-ssrf"})]
        return ValidatorResult("NO_EFFECT", 0.75, ev, {"classification": "open-redirect"}, "REFUTED")
    # Fetch evidence must be server-side fetch semantics, never a mere echo of
    # the supplied URL (error pages routinely echo the request URL, including
    # the token and 127.0.0.1). Strip the echo, then require network-error text.
    scrubbed = body.replace(sentinel_url, "").replace(control_token, "")
    scrubbed = scrubbed.replace("127.0.0.1", "").replace("localhost", "")
    fetch_markers = ["connection refused", "econnrefused", "enotfound",
                     "getaddrinfo", "enoent", "dial tcp", "socket hang up",
                     "fetch failed", "failed to fetch", "error fetching",
                     "unable to fetch", "etimedout", "timed out"]
    hit = next((m for m in fetch_markers if m in scrubbed.lower()), "")
    elapsed = resp.get("elapsed_ms", 0)
    if hit and status in (200, 500):
        ev = [build_evidence(capability, test_id, url, req, {"status": status}, body[:1200],
                             sentinel_url, auth_context=auth_context, stage="CONFIRMED",
                             extra={"fetch_evidence": hit})]
        return ValidatorResult("STRONG_SSRF_EVIDENCE", 0.88, ev, {"fetch_evidence": hit}, "CONFIRMED")
    if control_token in body:
        ev = [build_evidence(capability, test_id, url, req, {"status": status}, body[:1000],
                             sentinel_url, auth_context=auth_context, stage="SUPPORTED",
                             extra={"fetch_evidence": "token-reflected-by-server"})]
        return ValidatorResult("BEHAVIORAL_DIFFERENTIAL", 0.6, ev, {}, "SUPPORTED")
    _ = elapsed
    ev = [build_evidence(capability, test_id, url, req, {"status": status}, body[:600],
                         sentinel_url, auth_context=auth_context, stage="REFUTED",
                         extra={"classification": "no-server-fetch"})]
    return ValidatorResult("NO_EFFECT", 0.65, ev, {"classification": "no-fetch"}, "REFUTED")


# ---------------------------------------------------------------------------
# 6/7. Authentication + differential authorization
# ---------------------------------------------------------------------------

def validate_auth_enforcement(anon_fn: Callable[[], dict], auth_fn: Callable[[], dict] | None,
                              url: str, capability: str = "auth_probe",
                              test_id: str = "auth") -> ValidatorResult:
    anon = anon_fn()
    a_status = anon.get("status", 0)
    if a_status in (401, 403):
        ev = [build_evidence(capability, test_id, url, {"identity": "anonymous"}, anon,
                             anon.get("text", "")[:500], "", stage="REFUTED",
                             extra={"enforced": True})]
        return ValidatorResult("NO_EFFECT", 0.9, ev, {"enforced": True}, "REFUTED")
    if a_status == 0:
        return ValidatorResult("INSUFFICIENT_EVIDENCE", 0.3,
                               [build_evidence(capability, test_id, url, {}, anon, "",
                                               "", stage="INSUFFICIENT_EVIDENCE")],
                               {}, "INSUFFICIENT_EVIDENCE")
    if auth_fn is None:
        ev = [build_evidence(capability, test_id, url, {"identity": "anonymous"}, anon,
                             anon.get("text", "")[:800], "", stage="OBSERVED",
                             extra={"requires_auth_context": True})]
        return ValidatorResult("REQUIRES_AUTH", 0.5, ev, {"anonymous_status": a_status},
                               "INSUFFICIENT_EVIDENCE")
    authed = auth_fn()
    if a_status == 200 and authed.get("status") == 200:
        # same content anonymously -> missing enforcement (only if body is non-trivial)
        if len(anon.get("text", "")) > 50:
            ev = [build_evidence(capability, test_id, url, {"identity": "anonymous"}, anon,
                                 anon.get("text", "")[:800], "", stage="SUPPORTED",
                                 extra={"anonymous_status": a_status})]
            return ValidatorResult("STRONG_AUTHZ_EVIDENCE", 0.8, ev,
                                   {"anonymous_status": a_status}, "SUPPORTED")
    ev = [build_evidence(capability, test_id, url, {"identity": "anonymous"}, anon,
                         anon.get("text", "")[:500], "", stage="OBSERVED")]
    return ValidatorResult("NO_EFFECT", 0.5, ev, {}, "OBSERVED")


def _ownership_fields(body: str) -> dict:
    out: dict[str, str] = {}
    for k in ("userid", "user_id", "ownerid", "owner_id", "email", "username"):
        m = re.search(rf'"{k}"\s*:\s*"?([^",}}]+)"?', body, re.I)
        if m:
            out[k] = m.group(1)[:80]
    return out


def validate_authz_differential(fetch_a: Callable[[str], dict], fetch_b: Callable[[str], dict],
                                object_url_a: str, object_url_b_cross: str,
                                identity_a: str = "user-a", identity_b: str = "user-b",
                                capability: str = "authz_compare",
                                test_id: str = "authz") -> ValidatorResult:
    """A->objA baseline, then B->objA cross-boundary attempt. Generic; never
    treats collection endpoints or bare numeric IDs as a boundary."""
    base = fetch_a(object_url_a)
    cross = fetch_b(object_url_b_cross)
    ev = [build_evidence(capability, test_id, object_url_a, {"identity": identity_a}, base,
                         base.get("text", "")[:800], "", auth_context=identity_a, stage="OBSERVED"),
          build_evidence(capability, test_id, object_url_b_cross, {"identity": identity_b}, cross,
                         cross.get("text", "")[:800], "", auth_context=identity_b, stage="OBSERVED")]
    if base.get("status") == 0 or cross.get("status") == 0:
        return ValidatorResult("INSUFFICIENT_EVIDENCE", 0.3, ev, {}, "INSUFFICIENT_EVIDENCE")
    if cross.get("status") in (401, 403):
        return ValidatorResult("NO_EFFECT", 0.9, ev, {"enforced": True}, "REFUTED")
    if cross.get("status") == 200:
        b_body, c_body = base.get("text", "") or "", cross.get("text", "") or ""
        b_own, c_own = _ownership_fields(b_body), _ownership_fields(c_body)
        # observable security impact: cross-identity response carries the
        # victim object's private fields
        if b_body and c_body and _fingerprint(b_body)["hash"] == _fingerprint(c_body)["hash"] and len(c_body) > 30:
            for e in ev:
                e["stage"] = "CONFIRMED"
            return ValidatorResult("STRONG_AUTHZ_EVIDENCE", 0.9, ev,
                                   {"boundary": object_url_b_cross, "impact": "identical private object disclosed cross-identity",
                                    "ownership": c_own}, "CONFIRMED")
        if c_own and len(c_body) > 30:
            for e in ev:
                e["stage"] = "SUPPORTED"
            return ValidatorResult("BEHAVIORAL_DIFFERENTIAL", 0.7, ev,
                                   {"boundary": object_url_b_cross, "ownership": c_own}, "SUPPORTED")
    return ValidatorResult("NO_EFFECT", 0.55, ev, {}, "OBSERVED")


# ---------------------------------------------------------------------------
# 8. API security (generic request/response semantics)
# ---------------------------------------------------------------------------

def validate_api_surface(request_fn: RequestFn, method: str, url: str,
                         capability: str = "api_probe", test_id: str = "api") -> ValidatorResult:
    base = request_fn("GET", url)
    body = base.get("text", "") or ""
    ev = [build_evidence(capability, test_id, url, {"method": "GET"}, base, body[:1200],
                         "", stage="OBSERVED")]
    details: dict[str, Any] = {}
    # excessive data exposure: sensitive keys in a list/object response
    sens = re.findall(r'"(password|ssn|credit_?card|secret|private_?key|salary)"\s*:', body, re.I)
    if sens and base.get("status") == 200:
        details["excessive_data"] = sorted(set(s.lower() for s in sens))
    # method tampering: try unexpected verb on same URL
    tampered = request_fn("PUT" if method == "GET" else "GET", url)
    if tampered.get("status") == 200 and len(tampered.get("text", "")) > 50:
        details["method_tampering"] = {"status": tampered.get("status")}
        ev.append(build_evidence(capability, test_id, url, {"method": "PUT-tamper"}, tampered,
                                 tampered.get("text", "")[:600], "", stage="SUPPORTED"))
    # mass-assignment probe: non-destructive privileged-field guess
    guess = request_fn("POST", url, body={"role": "admin", "isAdmin": True, "probe_only": True})
    gbody = guess.get("text", "") or ""
    if guess.get("status") in (200, 201) and re.search(r'"role"\s*:\s*"admin"|isAdmin"?\s*:\s*true', gbody, re.I):
        details["mass_assignment"] = True
        ev.append(build_evidence(capability, test_id, url, {"method": "POST-mass-assign"}, guess,
                                 gbody[:600], "role=admin", stage="SUPPORTED"))
    if details.get("excessive_data") or details.get("mass_assignment"):
        return ValidatorResult("STRONG_API_EVIDENCE", 0.85, ev, details, "SUPPORTED")
    if details.get("method_tampering"):
        return ValidatorResult("BEHAVIORAL_DIFFERENTIAL", 0.6, ev, details, "SUPPORTED")
    return ValidatorResult("NO_EFFECT", 0.6, ev, details, "REFUTED")


# ---------------------------------------------------------------------------
# 9. GraphQL (no generic "exposed" finding)
# ---------------------------------------------------------------------------

_INTROSPECTION_Q = {"query": "{__schema{queryType{name}types{name}}}"}


def validate_graphql(request_fn: RequestFn, url: str, capability: str = "graphql_probe",
                     test_id: str = "graphql") -> ValidatorResult:
    probe = request_fn("POST", url, body=dict(_INTROSPECTION_Q))
    body = probe.get("text", "") or ""
    try:
        import json as _j
        data = _j.loads(body) if body.strip().startswith("{") else {}
    except Exception:
        data = {}
    types = (((data.get("data") or {}).get("__schema") or {}).get("types") or [])
    ev = [build_evidence(capability, test_id, url, {"query": "introspection"}, probe,
                         body[:1200], "{__schema}", stage="OBSERVED",
                         extra={"types_count": len(types)})]
    if not types:
        return ValidatorResult("NO_EFFECT", 0.75, ev, {"introspection": False}, "REFUTED")
    # introspection alone is configuration info; authorization requires a
    # second probe showing per-field/object access divergence — record authz
    # boundary as needing follow-up, do not confirm from introspection alone.
    names = [t.get("name") for t in types if isinstance(t, dict)][:12]
    priv = [n for n in names if n and any(k in n.lower() for k in ("user", "admin", "account", "order", "payment"))]
    details = {"introspection": True, "types_count": len(types), "root_fields": names,
               "privileged_fields": priv, "needs_field_authz_probe": True}
    return ValidatorResult("BEHAVIORAL_DIFFERENTIAL", 0.7, ev, details, "SUPPORTED")


# ---------------------------------------------------------------------------
# 10. Business logic / workflows (generic state machine)
# ---------------------------------------------------------------------------

def validate_workflow(steps: list[dict], run_step: Callable[[dict, dict], dict],
                      tamperings: list[dict] | None = None,
                      capability: str = "workflow_probe",
                      test_id: str = "workflow") -> ValidatorResult:
    """steps: [{name, request}]; run_step(step, ctx)->resp. Tests omission,
    reorder, replay, value tamper generically."""
    ev: list[dict] = []
    ctx: dict[str, Any] = {}
    baseline_ok = True
    for s in steps:
        r = run_step(s, ctx)
        ev.append(build_evidence(capability, test_id, str(s.get("request", {}).get("url", "")),
                                 s.get("request", {}), r, str(r.get("text", ""))[:600],
                                 "", stage="OBSERVED", extra={"step": s.get("name")}))
        if r.get("status", 0) not in (200, 201, 302):
            baseline_ok = False
        ctx[s.get("name", "step")] = r
    if not baseline_ok:
        return ValidatorResult("INSUFFICIENT_EVIDENCE", 0.3, ev, {}, "INSUFFICIENT_EVIDENCE")
    # omission: skip middle step, attempt final directly
    if len(steps) >= 2:
        skip = run_step({"name": "omit-middle", "request": steps[-1].get("request", {})}, {})
        ev.append(build_evidence(capability, test_id, "omit-middle", steps[-1].get("request", {}),
                                 skip, str(skip.get("text", ""))[:600], "", stage="OBSERVED",
                                 extra={"tamper": "step-omission"}))
        if skip.get("status") in (200, 201):
            return ValidatorResult("STRONG_WORKFLOW_EVIDENCE", 0.85, ev,
                                   {"accepted": "step-omission"}, "CONFIRMED")
    for t in tamperings or []:
        r = run_step({"name": "tamper", "request": t.get("request", {})}, dict(ctx))
        ev.append(build_evidence(capability, test_id, "tamper", t.get("request", {}), r,
                                 str(r.get("text", ""))[:600], str(t.get("request", ""))[:300],
                                 stage="OBSERVED", extra={"tamper": t.get("kind", "value")}))
        if r.get("status") in (200, 201) and t.get("expect_reflect"):
            if t["expect_reflect"].lower() in str(r.get("text", "")).lower():
                return ValidatorResult("STRONG_WORKFLOW_EVIDENCE", 0.85, ev,
                                       {"accepted": t.get("kind")}, "CONFIRMED")
    return ValidatorResult("NO_EFFECT", 0.65, ev, {}, "REFUTED")


# ---------------------------------------------------------------------------
# 11. Information disclosure — recon stays recon until artifact validated
# ---------------------------------------------------------------------------

def validate_info_artifact(url: str, resp: dict, kind: str,
                           capability: str = "info_probe",
                           test_id: str = "info") -> ValidatorResult:
    body = resp.get("text", "") or ""
    ev = [build_evidence(capability, test_id, url, {"kind": kind}, resp, body[:1000], "",
                         stage="OBSERVED")]
    if kind == "robots":
        if re.search(r"(?im)^\s*(user-agent|disallow)\s*:", body) and resp.get("status") == 200:
            dis = re.findall(r"(?im)^\s*disallow\s*:\s*(\S+)", body)
            # robots itself is recon; only validated artifact access is a finding.
            return ValidatorResult("BEHAVIORAL_DIFFERENTIAL", 0.6, ev,
                                   {"disallowed": dis[:8], "needs_artifact_probe": True}, "SUPPORTED")
        return ValidatorResult("NO_EFFECT", 0.7, ev, {}, "REFUTED")
    if kind == "headers":
        # banners alone are never vulnerabilities
        return ValidatorResult("NO_EFFECT", 0.8, ev, {"note": "banner-is-recon-only"}, "REFUTED")
    return ValidatorResult("NO_EFFECT", 0.5, ev, {}, "OBSERVED")
