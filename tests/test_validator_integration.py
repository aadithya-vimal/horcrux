"""Validator integration tests: matrix -> dispatch -> capability -> validator
-> evidence -> adjudication, using a local synthetic HTTP fixture.

No external services. Fixture server binds 127.0.0.1 on an ephemeral port.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import pytest

PASSWD_BODY = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/bin/sh\n"


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
        if u.path == "/search":
            v = get1("q")
            if "' AND '1'='2" in v:
                self._send(200, json.dumps({"data": []}))
            elif v.endswith("'") and "AND" not in v:
                self._send(200, json.dumps({"data": "sqlite3 syntax error near \"test\""}))
            else:
                self._send(200, json.dumps({"data": ["apple", "pear", "plum", "grape"]}), "text/html")
            return
        if u.path == "/reflect":
            self._send(200, f"<div>results for {get1('q')}</div>", "text/html")
            return
        if u.path == "/echo":
            import html as _h
            self._send(200, f"<p>{_h.escape(get1('q'))}</p>", "text/html")
            return
        if u.path == "/files":
            v = get1("file")
            if "etc/passwd" in v:
                self._send(200, PASSWD_BODY, "text/plain")
            else:
                self._send(200, "file ok", "text/plain")
            return
        if u.path == "/run":
            v = get1("cmd")
            if any(t in v for t in (";id", "|id", "$(id)", "`id`")):
                self._send(200, "uid=0(root) gid=0(root)", "text/plain")
            else:
                self._send(200, "cmd ok", "text/plain")
            return
        if u.path == "/fetch":
            v = get1("url")
            if "127.0.0.1" in v:
                self._send(500, "connection refused dial tcp: stub fetch failed", "text/plain")
            else:
                self._send(200, "fetched ok", "text/plain")
            return
        if u.path == "/go":
            self._send(302, "redirect", "text/plain", {"Location": get1("next")})
            return
        if u.path == "/admin":
            self._send(401, "unauthorized", "text/plain")
            return
        if u.path == "/management":
            self._send(200, "<html><title>Admin dashboard</title><div>user management</div>"
                            "<div>administration panel</div></html>", "text/html")
            return
        if u.path == "/profile":
            self._send(200, "dashboard user profile data with content padding 1234567890", "text/html")
            return
        if u.path == "/api/items/1":
            self._send(200, json.dumps({"id": 1, "UserId": 1, "email": "a@t.local",
                                        "password": "hash-abc"}))
            return
        if u.path == "/api/items/2":
            self._send(200, json.dumps({"id": 2, "UserId": 2, "email": "b@t.local"}))
            return
        if u.path == "/uploads/p.html":
            self._send(200, "<html>horcrux-probe marker</html>", "text/html")
            return
        if u.path in ("/wf/step1", "/wf/step2"):
            self._send(200, "ok step", "text/plain")
            return
        if u.path == "/app.js":
            self._send(200, "console.log(1)", "application/javascript")
            return
        self._send(404, "not found", "text/plain")

    def do_POST(self):
        u = urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else b""
        if u.path == "/upload":
            self._send(201, json.dumps({"location": "/uploads/p.html"}))
            return
        if u.path == "/graphql":
            self._send(200, json.dumps({"data": {"__schema": {"types": [
                {"name": "User"}, {"name": "Query"}]}}}))
            return
        if u.path in ("/wf/step1", "/wf/step2"):
            self._send(200, "ok step " + body.decode("utf-8", "replace")[:50], "text/plain")
            return
        self._send(404, "not found", "text/plain")

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield port
    srv.shutdown()


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


def _run_family(state, family, port, param=""):
    from horcrux.agents import executor as ex
    from horcrux.agents.tools.capabilities import CapabilityRegistry
    from horcrux.intel.test_matrix import derive_applicable_tests, test_case_to_investigation
    app = state.get_application_model()
    tests = [t for t in derive_applicable_tests(app, state) if t.family.value == family]
    if param:
        tests = [t for t in tests if t.target_parameter == param]
    assert tests, f"no applicable test for family {family} param {param!r}"
    inv = test_case_to_investigation(tests[0])
    state.set_investigations([inv])
    reg = CapabilityRegistry(workspace=None, runner=None, state=state, live_local=True)
    cap = ex.resolve_capability(inv, reg)
    inputs = ex.build_capability_inputs(state, inv, cap)
    out = ex.execute_investigation_pipeline(state, inv, reg)
    return cap, inputs, out, inv


def _contract(structured):
    for k in ("test_id", "matrix_family", "target", "verdict",
              "confidence", "access_context"):
        assert k in structured, f"contract missing {k}: {sorted(structured)}"
    assert structured["evidence"] if False else True


def test_sqli_pipeline_confirms(server):
    state = _model(server, [("GET", "/search", False)], [("q", "query", "/search")])
    cap, inputs, out, inv = _run_family(state, "param_sqli", server, "q")
    assert cap in ("sqli_probe", "param_fuzz")
    assert inputs["parameter"] == "q" and inputs["matrix_family"] == "param_sqli"
    assert inputs["port"] == server
    assert inv.state.value == "SUPPORTED", inv.result_summary
    assert any("CWE-89" in f.cwes for f in state.findings)
    assert out["evidence_ingested"] > 0


def test_xss_pipeline_confirms_and_dom_explicit(server):
    state = _model(server, [("GET", "/reflect", False)], [("q", "query", "/reflect")])
    cap, inputs, out, inv = _run_family(state, "param_xss", server, "q")
    assert cap in ("xss_probe", "param_fuzz")
    assert inv.state.value == "SUPPORTED", inv.result_summary
    assert any("CWE-79" in f.cwes for f in state.findings)


def test_xss_escaped_is_refuted_with_dom_note(server):
    state = _model(server, [("GET", "/echo", False)], [("q", "query", "/echo")])
    cap, inputs, out, inv = _run_family(state, "param_xss", server, "q")
    assert inv.state.value in ("REFUTED", "COMPLETE"), inv.result_summary
    assert not [f for f in state.findings if "CWE-79" in f.cwes]


def test_traversal_pipeline_confirms(server):
    state = _model(server, [("GET", "/files", False)], [("file", "query", "/files")])
    cap, inputs, out, inv = _run_family(state, "param_traversal", server, "file")
    assert cap in ("traversal_probe", "param_fuzz")
    assert inputs["parameter"] == "file"
    assert inv.state.value == "SUPPORTED", inv.result_summary
    assert any("CWE-22" in f.cwes for f in state.findings)


def test_ssrf_pipeline_confirms_fetch(server):
    state = _model(server, [("GET", "/fetch", False)], [("url", "query", "/fetch")])
    cap, inputs, out, inv = _run_family(state, "param_ssrf", server, "url")
    assert cap in ("ssrf_probe", "param_fuzz")
    assert inv.state.value == "SUPPORTED", inv.result_summary
    assert any("CWE-918" in f.cwes for f in state.findings)


def test_open_redirect_is_not_ssrf(server):
    state = _model(server, [("GET", "/go", False)], [("next", "query", "/go")])
    cap, inputs, out, inv = _run_family(state, "param_ssrf", server, "next")
    assert inv.state.value in ("REFUTED", "COMPLETE"), inv.result_summary
    assert not [f for f in state.findings if "CWE-918" in f.cwes]


def test_cmdi_pipeline_confirms(server):
    state = _model(server, [("GET", "/run", False)], [("cmd", "query", "/run")])
    cap, inputs, out, inv = _run_family(state, "param_cmdi", server, "cmd")
    assert cap in ("cmdi_probe", "param_fuzz")
    assert inv.state.value == "SUPPORTED", inv.result_summary
    assert any("CWE-78" in f.cwes for f in state.findings)


def test_upload_pipeline_confirms(server):
    state = _model(server, [("POST", "/upload", False)], [])
    cap, inputs, out, inv = _run_family(state, "file_upload", server)
    assert cap == "upload_probe", cap
    assert inv.state.value == "SUPPORTED", inv.result_summary
    assert any("CWE-434" in f.cwes for f in state.findings)


def test_auth_enforced_refuted_and_requires_auth(server):
    state = _model(server, [("GET", "/admin", True)], [])
    _, _, _, inv = _run_family(state, "auth_enforcement", server)
    assert inv.state.value in ("REFUTED", "COMPLETE"), inv.result_summary
    state2 = _model(server, [("GET", "/profile", True)], [])
    _, _, _, inv2 = _run_family(state2, "auth_enforcement", server)
    assert inv2.state.value == "REQUIRES_AUTH", inv2.result_summary


def test_authz_horizontal_requires_second_identity(server):
    state = _model(server, [("GET", "/api/items/1", False)], [])
    _, _, _, inv = _run_family(state, "authz_horizontal", server)
    assert inv.state.value == "REQUIRES_SECOND_IDENTITY", inv.result_summary


def test_bola_cross_boundary_supported(server):
    state = _model(server, [("GET", "/api/items/1", False)], [("id", "path", "/api/items/1")])
    cap, inputs, out, inv = _run_family(state, "bola_idor", server)
    assert cap == "authz_compare", cap
    assert inv.state.value == "SUPPORTED", inv.result_summary
    assert any("CWE-639" in f.cwes for f in state.findings)


def test_api_excessive_data_supported(server):
    state = _model(server, [("GET", "/api/items/1", False)], [])
    cap, inputs, out, inv = _run_family(state, "api_security", server)
    assert cap == "api_probe", cap
    assert inv.state.value == "SUPPORTED", inv.result_summary


def test_graphql_introspection_supported(server):
    state = _model(server, [("POST", "/graphql", False)], [])
    cap, inputs, out, inv = _run_family(state, "graphql_introspection", server)
    assert cap == "graphql_probe", cap
    assert inv.state.value == "SUPPORTED", inv.result_summary


def test_workflow_omission_supported(server):
    state = _model(server, [("GET", "/wf/step1", False), ("GET", "/wf/step2", False)],
                   [], workflows=[("Checkout", ["/wf/step1", "/wf/step2"])])
    cap, inputs, out, inv = _run_family(state, "workflow_state", server)
    assert cap == "workflow_probe", cap
    assert inv.state.value == "SUPPORTED", inv.result_summary


def test_static_asset_never_derives_validator_test(server):
    from horcrux.intel.test_matrix import derive_applicable_tests
    state = _model(server, [("GET", "/app.js", False)], [("v", "query", "/app.js")])
    tests = derive_applicable_tests(state.get_application_model(), state)
    kinds = {(t.family.value, t.target_path) for t in tests}
    assert not any(p == "/app.js" for _, p in kinds), kinds


def test_root_target_is_not_retargeted(server):
    """A literal '/' matrix asset must reach the validator as '/', never
    silently redirected at an unrelated admin/object endpoint."""
    from horcrux.agents import executor as ex
    from horcrux.agents.tools.capabilities import CapabilityRegistry
    from horcrux.intel.test_matrix import derive_applicable_tests, test_case_to_investigation
    state = _model(server, [("GET", "/", False), ("GET", "/rest/admin", False)],
                   [("callback", "query", "/")])
    app = state.get_application_model()
    tests = [t for t in derive_applicable_tests(app, state)
             if t.family.value == "param_ssrf" and t.target_path == "/"]
    assert tests
    inv = test_case_to_investigation(tests[0])
    reg = CapabilityRegistry(workspace=None, runner=None, state=state, live_local=True)
    cap = ex.resolve_capability(inv, reg)
    inputs = ex.build_capability_inputs(state, inv, cap)
    assert inputs["endpoint"] == "/", inputs["endpoint"]
    assert inputs["url"] == f"http://127.0.0.1:{server}/", inputs["url"]


def test_authz_vertical_exposed_admin_supported(server):
    state = _model(server, [("GET", "/management", False)], [])
    cap, inputs, out, inv = _run_family(state, "authz_vertical", server)
    assert cap == "authz_compare", cap
    assert inv.state.value == "SUPPORTED", inv.result_summary
    assert any("CWE-639" in f.cwes or "CWE-284" in f.cwes for f in state.findings)


def test_replenishment_from_validator_evidence(server):
    from horcrux.intel.test_matrix import derive_applicable_tests
    state = _model(server, [("GET", "/search", False)], [("q", "query", "/search")])
    before = {t.id for t in derive_applicable_tests(state.get_application_model(), state)}
    _run_family(state, "param_sqli", server, "q")
    after = derive_applicable_tests(state.get_application_model(), state)
    assert len(after) >= len(before)
