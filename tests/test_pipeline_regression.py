"""Pipeline regression tests: discovery -> matrix -> execution -> validator
-> evidence ingestion -> adjudication, on a local synthetic fixture.

Covers the demo regression class: discovery must not crash on candidate
paths, validator evidence must not pollute the model, and strict content
evidence is required for exposure findings.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import pytest

SPA_HTML = ("<!doctype html><html><head><title>App</title></head><body>"
            "<app-root></app-root><script src=\"/app.js\"></script></body></html>")
APP_JS = "const routes = ['/api/widgets', '/api/widgets/{id}'];\nfetch('/api/widgets');\n"
ECHO_TMPL = ("<html><head><title>Error: Unexpected path: {u}</title></head>"
             "<body><h1>App (Express ^4.22.1)</h1><h2><em>500</em> Error</h2></body></html>")


class _Handler(BaseHTTPRequestHandler):
    def _send(self, status, body, ctype="application/json", headers=None):
        raw = body.encode() if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        get1 = lambda k: (q.get(k) or [""])[0]
        if u.path == "/":
            self._send(200, SPA_HTML, "text/html")
        elif u.path == "/app.js":
            self._send(200, APP_JS, "application/javascript")
        elif u.path == "/robots.txt":
            self._send(200, "User-agent: *\nDisallow: /private\n", "text/plain")
        elif u.path == "/private":
            self._send(200, "secret area", "text/plain")
        elif u.path == "/api/widgets":
            self._send(200, json.dumps({"id": 1, "owner": "a@t.local", "password": "hash-x"}))
        elif u.path == "/api/widgets/1":
            self._send(200, json.dumps({"id": 1, "UserId": 1, "email": "a@t.local"}))
        elif u.path == "/api/widgets/2":
            self._send(200, json.dumps({"id": 2, "UserId": 2, "email": "b@t.local"}))
        elif u.path == "/api/admin":
            self._send(401, "unauthorized", "text/plain")
        elif u.path == "/api/me":
            self._send(200, "dashboard user profile data with content padding 1234567890", "text/html")
        elif u.path == "/.env":
            self._send(200, SPA_HTML, "text/html")
        elif u.path == "/.git/HEAD":
            self._send(200, SPA_HTML, "text/html")
        elif u.path == "/echo500":
            self._send(500, ECHO_TMPL.format(u=self.path), "text/html")
        else:
            self._send(404, "Cannot GET " + u.path, "text/html")

    def do_POST(self):
        u = urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            data = json.loads(raw or b"{}")
        except Exception:
            data = {}
        if u.path == "/api/widgets":
            body = {"id": 9}
            body.update(data)
            self._send(201, json.dumps(body))
        else:
            self._send(404, "no", "text/plain")

    def do_PUT(self):
        u = urlparse(self.path)
        if u.path == "/api/widgets":
            self._send(200, json.dumps({"id": 1, "owner": "a@t.local",
                                        "note": "updated via unexpected method tamper accepted here"}))
        else:
            self._send(404, "no", "text/plain")

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield port
    srv.shutdown()


class _StubRunner:
    def which(self, binary):
        return None


def _model(port, endpoints, params, workflows=None):
    from horcrux.intel.application_model import (
        ApplicationModel, SemanticEndpoint, SemanticParameter,
        SemanticWebTarget, Workflow, WorkflowStep)
    from horcrux.models import WorkspaceState
    state = WorkspaceState(target="127.0.0.1")
    state.execution_mode = "LOCAL"
    eps = []
    for method, path, auth in endpoints:
        ep = SemanticEndpoint(method=method, path=path, sources=["fixture"],
                              evidence_refs=[f"fixture:{path}"])
        if auth:
            ep.authentication = "required"
        try:
            ep.ensure_id()
        except Exception:
            pass
        eps.append(ep)
    plist = []
    for name, loc, ep in params:
        p = SemanticParameter(name=name, location=loc, endpoint=ep,
                              source="fixture", evidence_refs=[f"fixture:{name}"])
        try:
            p.ensure_id()
        except Exception:
            pass
        plist.append(p)
    wt = SemanticWebTarget(scheme="http", host="127.0.0.1", port=port,
                           base_url=f"http://127.0.0.1:{port}")
    try:
        wt.ensure_id()
    except Exception:
        pass
    app = ApplicationModel(target="127.0.0.1")
    app.endpoints = eps
    app.parameters = plist
    app.web_targets = [wt]
    if workflows:
        app.workflows = [Workflow(name=n, steps=[
            WorkflowStep(name=s, method="GET", path=s, identity="anonymous",
                         evidence_refs=["fixture"]) for s in steps])
            for n, steps in workflows]
    state.set_application_model(app)
    return state


def _run_family(state, family, param=""):
    from horcrux.agents import executor as ex
    from horcrux.agents.tools.capabilities import CapabilityRegistry
    from horcrux.intel.test_matrix import derive_applicable_tests, test_case_to_investigation
    app = state.get_application_model()
    tests = [t for t in derive_applicable_tests(app, state) if t.family.value == family]
    if param:
        tests = [t for t in tests if t.target_parameter == param]
    assert tests, f"no applicable test for {family} {param!r}"
    inv = test_case_to_investigation(tests[0])
    state.set_investigations([inv])
    reg = CapabilityRegistry(workspace=None, runner=None, state=state, live_local=True)
    out = ex.execute_investigation_pipeline(state, inv, reg)
    return out, inv


def test_discovery_does_not_crash_and_harvests_robots(server, tmp_path):
    """Regression: known_targets/robots.txt candidates must be valid
    DiscoveredPath records; validation pipeline must complete."""
    from horcrux.core.storage import Workspace
    from horcrux.modules.web.discovery import run as web_discovery
    ws = Workspace("127.0.0.1", base=str(tmp_path))
    findings, audits, paths = web_discovery(ws, _StubRunner(), "127.0.0.1", server,
                                            strategy="quickhits")
    by_path = {p.path for p in paths}
    assert "/robots.txt" in by_path
    assert "/private" in by_path  # robots Disallow harvested as candidate
    assert "/api/widgets" in by_path  # JS bundle route
    for p in paths:
        assert p.url and p.path  # pydantic-validated records


def test_excessive_data_end_to_end(server):
    state = _model(server, [("GET", "/api/widgets", False)], [])
    out, inv = _run_family(state, "api_security")
    assert inv.state.value == "SUPPORTED", inv.result_summary
    assert any("CWE-200" in f.cwes for f in state.findings)


def test_mass_assignment_end_to_end(server):
    from horcrux.modules.web import security_validators as sv
    base = f"http://127.0.0.1:{server}"
    res = sv.validate_api_surface(sv.httpx_request_fn, "GET", base + "/api/widgets")
    assert res.verdict == "STRONG_API_EVIDENCE"
    assert res.details.get("mass_assignment") is True


def test_method_tampering_observed_not_inflated(server):
    from horcrux.modules.web import security_validators as sv
    from horcrux.intel.vulnerability_adjudicator import adjudicate_capability_outcome
    from horcrux.intel.investigations import Investigation, InvestigationState
    from horcrux.models import WorkspaceState
    base = f"http://127.0.0.1:{server}"

    def req(method, url, query=None, body=None, **kw):
        # tamper-only surface: no excessive fields, no mass assignment
        if method == "GET":
            return {"status": 200, "headers": {}, "text": '{"id": 1}', "elapsed_ms": 2.0}
        if method == "PUT":
            return {"status": 200, "headers": {},
                    "text": '{"id": 1, "note": "unexpected method accepted with a long body here"}',
                    "elapsed_ms": 2.0}
        return {"status": 404, "headers": {}, "text": "no", "elapsed_ms": 1.0}

    res = sv.validate_api_surface(req, "GET", base + "/api/widgets")
    assert res.verdict == "BEHAVIORAL_DIFFERENTIAL"

    class R:
        capability_id = "api_probe"
        data = {"verdict": res.verdict, "endpoint": "/api/widgets",
                "details": dict(res.details)}
        evidence = []
        ingested_count = 1

    st = WorkspaceState(target="127.0.0.1")
    inv = Investigation(id="inv-tamper-1", objective="method tamper",
                        candidate_tools=["api_probe"], required_capabilities=["http"])
    out = adjudicate_capability_outcome(R(), inv, None, st)
    assert out["state"] != InvestigationState.SUPPORTED  # differential alone never inflates
    assert len(st.findings) == 0


def test_ssrf_error_echo_never_confirms(server):
    from horcrux.modules.web import security_validators as sv
    base = f"http://127.0.0.1:{server}"
    res = sv.validate_ssrf(sv.httpx_request_fn, "GET", base + "/echo500", "url")
    assert res.verdict != "STRONG_SSRF_EVIDENCE", res.details


def test_env_spa_fallback_never_confirms(server):
    from horcrux.agents.tools.capabilities import CapabilityRegistry
    from horcrux.intel.vulnerability_adjudicator import adjudicate_capability_outcome
    from horcrux.intel.investigations import Investigation, InvestigationState
    from horcrux.models import WorkspaceState
    st = WorkspaceState(target="127.0.0.1")
    st.execution_mode = "LOCAL"
    reg = CapabilityRegistry(workspace=None, runner=None, state=st, live_local=True)
    out = reg.execute("http_probe", {"target": "127.0.0.1", "port": server,
                                     "scheme": "http", "path": "/.env", "method": "GET"})
    assert out.success
    assert not out.structured_data.get("env_keys")

    class R:
        capability_id = "http_probe"
        data = dict(out.structured_data)
        evidence = []
        ingested_count = 1

    inv = Investigation(id="inv-env-1", objective="env check",
                        candidate_tools=["http_probe"], required_capabilities=["http"])
    res = adjudicate_capability_outcome(R(), inv, None, st)
    assert res["state"] != InvestigationState.SUPPORTED
    assert not [f for f in st.findings if "CWE-552" in f.cwes]


def test_git_spa_fallback_never_confirms(server):
    from horcrux.agents.tools.capabilities import CapabilityRegistry
    from horcrux.intel.vulnerability_adjudicator import adjudicate_capability_outcome
    from horcrux.intel.investigations import Investigation, InvestigationState
    from horcrux.models import WorkspaceState
    st = WorkspaceState(target="127.0.0.1")
    st.execution_mode = "LOCAL"
    reg = CapabilityRegistry(workspace=None, runner=None, state=st, live_local=True)
    out = reg.execute("http_probe", {"target": "127.0.0.1", "port": server,
                                     "scheme": "http", "path": "/.git/HEAD", "method": "GET"})
    assert out.success
    assert not out.structured_data.get("git_head")

    class R:
        capability_id = "http_probe"
        data = dict(out.structured_data)
        evidence = []
        ingested_count = 1

    inv = Investigation(id="inv-git-1", objective="git check",
                        candidate_tools=["http_probe"], required_capabilities=["http"])
    res = adjudicate_capability_outcome(R(), inv, None, st)
    assert res["state"] != InvestigationState.SUPPORTED
    assert not [f for f in st.findings if "CWE-538" in f.cwes]


def test_ingestion_rejects_pseudo_methods_and_payload_params():
    from horcrux.intel.application_model import ApplicationModel
    from horcrux.intel.ingestion import ingest_capability_evidence
    app = ApplicationModel(target="127.0.0.1")
    n = ingest_capability_evidence(app, "api_probe", [{
        "evidence_type": "validator_evidence",
        "data": {"target": "/api/widgets",
                 "request": {"method": "POST-mass-assign", "param": "role=admin"},
                 "response_meta": {"status": 201},
                 "response_excerpt": "x", "payload": "role=admin",
                 "authentication_context": "anonymous", "stage": "SUPPORTED",
                 "extra": {"discovered_params": ["not a param!"]}},
        "source": "api_probe", "confidence": 0.85}])
    assert n == 1
    assert all(e.method in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")
               for e in app.endpoints), [e.method for e in app.endpoints]
    assert all("=" not in p.name and "!" not in p.name for p in app.parameters)


def test_auth_boundary_enforced_and_requires_auth(server):
    state = _model(server, [("GET", "/api/admin", True)], [])
    _, inv = _run_family(state, "auth_enforcement")
    assert inv.state.value in ("REFUTED", "COMPLETE"), inv.result_summary
    state2 = _model(server, [("GET", "/api/me", True)], [])
    _, inv2 = _run_family(state2, "auth_enforcement")
    assert inv2.state.value == "REQUIRES_AUTH", inv2.result_summary


def test_authorization_differential_supported(server):
    state = _model(server, [("GET", "/api/widgets/1", False)],
                   [("id", "path", "/api/widgets/1")])
    _, inv = _run_family(state, "bola_idor")
    assert inv.state.value == "SUPPORTED", inv.result_summary
    assert any("CWE-639" in f.cwes for f in state.findings)
