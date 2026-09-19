"""Focused validator regression tests — synthetic fixtures only, no third-party targets."""

from horcrux.modules.web import security_validators as sv


def _resp(status=200, text="", elapsed_ms=5.0, headers=None):
    return {"status": status, "headers": headers or {}, "text": text, "elapsed_ms": elapsed_ms}


def test_sqli_behavioral_differential():
    base = "results: apple apple apple apple apple apple"
    calls = {}

    def req(method, url, query=None, body=None, **kw):
        v = (query or {}).get("q", "") if query else (body or {}).get("q", "")
        calls[v] = True
        if v == "test123":
            return _resp(200, base)
        if v == "test123'":
            return _resp(200, base)  # harmless quote: no effect
        if v == "test123' AND '1'='1":
            return _resp(200, base)
        if v == "test123' AND '1'='2":
            return _resp(200, "no results found")
        if "OR" in v or "--" in v or "\\" in v:
            return _resp(200, "sqlite error: near \"test\": syntax error")
        return _resp(200, base)

    res = sv.validate_sqli(req, "GET", "http://t.local/search", "q")
    assert res.verdict == "STRONG_SQLI_EVIDENCE", res.verdict
    assert res.stage == "CONFIRMED"


def test_sqli_single_generic_error_not_confirmed():
    def req(method, url, query=None, body=None, **kw):
        v = (query or {}).get("q", "")
        if v == "test123":
            return _resp(200, "ok results page with content here")
        return _resp(500, "internal server error")
    res = sv.validate_sqli(req, "GET", "http://t.local/search", "q")
    assert res.verdict in ("NO_EFFECT", "ERROR_SIGNAL", "BEHAVIORAL_DIFFERENTIAL"), res.verdict
    assert res.verdict != "STRONG_SQLI_EVIDENCE"


def test_xss_context_validation_escaped_is_not_finding():
    def req(method, url, query=None, body=None, **kw):
        v = (query or {}).get("q", "")
        import html as _h
        return _resp(200, f"<p>{_h.escape(v)}</p>")
    res = sv.validate_xss_reflected(req, "GET", "http://t.local/search", "q")
    assert res.verdict == "NO_EFFECT", res.verdict


def test_xss_context_validation_executable_sink():
    def req(method, url, query=None, body=None, **kw):
        v = (query or {}).get("q", "")
        return _resp(200, f"<div>results for {v}</div>")
    res = sv.validate_xss_reflected(req, "GET", "http://t.local/search", "q")
    assert res.verdict == "STRONG_XSS_EVIDENCE", res.verdict
    assert res.details.get("unescaped") is True


def test_stored_xss_flow():
    store = {}

    def submit(payload, token):
        store["v"] = payload
        return {"status": 200, "text": "saved", "headers": {}}

    def retrieve():
        return _resp(200, f"<div>comment: {store.get('v', '')}</div>")

    res = sv.validate_xss_stored(submit, retrieve, {"url": "http://t.local/c"}, {"url": "http://t.local/c"}, "comment")
    assert res.verdict == "STRONG_XSS_EVIDENCE", res.verdict


def test_xss_dom_sink_correlation():
    res = sv.validate_xss_dom("<div>hi</div>",
                              {"url": "http://t.local/", "sinks": [{"source": "tok123", "sink": "innerHTML", "triggered": False}]},
                              "tok123")
    assert res.verdict == "BEHAVIORAL_DIFFERENTIAL"
    res2 = sv.validate_xss_dom("<div>hi</div>",
                               {"url": "http://t.local/", "sinks": [{"source": "tok123", "sink": "innerHTML", "triggered": True}], "dialog": "alert"},
                               "tok123")
    assert res2.verdict == "STRONG_XSS_EVIDENCE"


def test_traversal_evidence_required():
    def req(method, url, query=None, body=None, **kw):
        v = (query or {}).get("file", "")
        if "passwd" in v:
            return _resp(200, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/bin/sh\n")
        if v == "test.txt":
            return _resp(200, "hello file")
        return _resp(404, "not found")
    res = sv.validate_traversal(req, "GET", "http://t.local/dl", "file")
    assert res.verdict == "STRONG_TRAVERSAL_EVIDENCE", res.verdict


def test_traversal_generic_4xx_not_finding():
    def req(method, url, query=None, body=None, **kw):
        v = (query or {}).get("file", "")
        if v == "test.txt":
            return _resp(200, "hello")
        return _resp(403, "forbidden")
    res = sv.validate_traversal(req, "GET", "http://t.local/dl", "file")
    assert res.verdict == "NO_EFFECT"


def test_upload_validation_rejected():
    def up(field, filename, content, content_type):
        return _resp(400, "extension not allowed")
    res = sv.validate_upload(up, None)
    assert res.verdict == "NO_EFFECT"


def test_upload_stored_and_reachable():
    stored = {}

    def up(field, filename, content, content_type):
        stored["loc"] = "/uploads/probe.html"
        return _resp(201, '{"location": "/uploads/probe.html"}')

    def acc(loc):
        return _resp(200, "horcrux-probe marker here")
    res = sv.validate_upload(up, acc)
    assert res.verdict == "STRONG_UPLOAD_EVIDENCE", res.verdict


def test_ssrf_open_redirect_is_not_ssrf():
    tok = "horcrux-ssrf"

    def req(method, url, query=None, body=None, **kw):
        return _resp(302, "redirect", headers={"Location": f"http://127.0.0.1:9/{tok}"})
    res = sv.validate_ssrf(req, "GET", "http://t.local/go", "url")
    assert res.verdict == "NO_EFFECT"
    assert res.details.get("classification") == "open-redirect"


def test_ssrf_server_fetch_evidence():
    tok = "horcrux-ssrf"

    def req(method, url, query=None, body=None, **kw):
        return _resp(500, f"failed to fetch {tok}: connection refused 127.0.0.1")
    res = sv.validate_ssrf(req, "GET", "http://t.local/fetch", "url")
    assert res.verdict == "STRONG_SSRF_EVIDENCE", res.verdict


def test_auth_enforcement_and_requires_auth():
    anon = lambda: _resp(401, "unauthorized")
    res = sv.validate_auth_enforcement(anon, None, "http://t.local/admin")
    assert res.verdict == "NO_EFFECT"  # enforced
    anon2 = lambda: _resp(200, "secret dashboard content with data here 12345")
    res2 = sv.validate_auth_enforcement(anon2, None, "http://t.local/admin")
    assert res2.verdict == "REQUIRES_AUTH"


def test_horizontal_authorization_differential():
    victim = '{"id": 2, "UserId": 2, "email": "victim@t.local"}'

    def fa(u):
        return _resp(200, '{"id": 1, "UserId": 1, "email": "a@t.local"}')

    def fb(u):
        return _resp(200, victim)
    res = sv.validate_authz_differential(fa, fb, "/api/users/1", "/api/users/2")
    assert res.verdict in ("STRONG_AUTHZ_EVIDENCE", "BEHAVIORAL_DIFFERENTIAL"), res.verdict

    def fb_denied(u):
        return _resp(403, "forbidden")
    res2 = sv.validate_authz_differential(fa, fb_denied, "/api/users/1", "/api/users/2")
    assert res2.verdict == "NO_EFFECT"


def test_api_object_exposure_and_mass_assignment():
    def req(method, url, query=None, body=None, **kw):
        if method == "GET":
            return _resp(200, '{"id": 1, "email": "a@t.local", "password": "hash123"}')
        if method == "POST":
            return _resp(201, '{"id": 9, "role": "admin"}')
        return _resp(404, "no")
    res = sv.validate_api_surface(req, "GET", "http://t.local/api/users")
    assert res.verdict == "STRONG_API_EVIDENCE"
    assert "excessive_data" in res.details or "mass_assignment" in res.details


def test_graphql_introspection_needs_field_authz():
    def req(method, url, query=None, body=None, **kw):
        import json as _j
        return _resp(200, _j.dumps({"data": {"__schema": {"types": [{"name": "User"}, {"name": "Query"}]}}}))
    res = sv.validate_graphql(req, "http://t.local/graphql")
    assert res.verdict == "BEHAVIORAL_DIFFERENTIAL"
    assert res.details.get("needs_field_authz_probe") is True


def test_workflow_tampering_and_omission():
    def run(step, ctx):
        name = step.get("name")
        if name == "omit-middle":
            return _resp(200, "order placed")  # omission accepted -> flaw
        return _resp(200, "ok step")
    res = sv.validate_workflow([{"name": "s1", "request": {}}, {"name": "s2", "request": {}}], run)
    assert res.verdict == "STRONG_WORKFLOW_EVIDENCE"


def test_evidence_schema_and_redaction():
    e = sv.build_evidence("sqli_probe", "t1", "http://t.local", {"method": "GET"},
                          {"status": 200}, "body text here", payload="q='",
                          auth_context="anonymous")
    for k in ("request", "response_meta", "response_excerpt", "payload",
              "baseline_comparison", "authentication_context", "target", "timestamp",
              "capability", "test_id"):
        assert k in e, k
    e2 = sv.build_evidence("c", "t", "u", {"h": "api_key= SECRET123456"}, {"status": 200}, "x", payload="p")
    assert "SECRET123456" not in str(e2)


def test_adjudication_and_dedup():
    from horcrux.intel.vulnerability_adjudicator import (
        adjudicate_capability_outcome, record_or_merge_canonical_finding)
    from horcrux.intel.investigations import Investigation, InvestigationState
    from horcrux.models import Finding, Severity, WorkspaceState

    state = WorkspaceState(target="t.local")
    inv = Investigation(id="inv-test-001", objective="sqli test",
                        candidate_tools=["sqli_probe"], required_capabilities=["http"])

    class R:
        capability_id = "sqli_probe"
        data = {"verdict": "STRONG_SQLI_EVIDENCE", "endpoint": "/search",
                "parameter": "q", "sql_errors": "sqlite syntax error"}
        evidence = []
        ingested_count = 1

    out = adjudicate_capability_outcome(R(), inv, None, state)
    assert out["state"] == InvestigationState.SUPPORTED, out
    assert len(state.findings) == 1
    f = state.findings[0]
    assert f.validation_details.get("what") and f.validation_details.get("how_verified")

    # single error string must not promote
    class R2:
        capability_id = "sqli_probe"
        data = {"verdict": "ERROR_SIGNAL", "endpoint": "/search", "parameter": "q"}
        evidence = [{"x": 1}]
        ingested_count = 1
    state2 = WorkspaceState(target="t.local")
    out2 = adjudicate_capability_outcome(R2(), inv, None, state2)
    assert out2["state"] != InvestigationState.SUPPORTED
    assert len(state2.findings) == 0

    # dedup: same asset+category merges
    n0 = len(state.findings)
    dup = Finding(id="dup-1", title="SQL Injection Vulnerability on parameter 'q'",
                  category="injection-sqli", severity=Severity.critical, confidence=0.9,
                  target="t.local", affected_asset="/search")
    record_or_merge_canonical_finding(state, dup)
    assert len(state.findings) == n0
