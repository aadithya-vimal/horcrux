"""Multi-family assessment recovery: one synthetic assessment must convert
observations from five distinct vulnerability families into five distinct
canonical findings with evidence chains. Local fixture server only.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

PASSWD = ("root:x:0:0:root:/root:/bin/bash\n"
          "daemon:x:1:1:daemon:/usr/sbin:/bin/sh\n")


class _VulnHandler(BaseHTTPRequestHandler):
    def _send(self, status, body, ctype="text/plain"):
        raw = body.encode() if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        get1 = lambda k: (q.get(k) or [""])[0]
        if u.path == "/search":
            v = get1("q")
            if "' AND '1'='2" in v:
                self._send(200, json.dumps({"data": []}), "application/json")
            elif "' AND '1'='1" in v:
                self._send(200, json.dumps({"data": ["apple", "pear", "plum", "grape"]}),
                            "application/json")
            elif (v.endswith("'") and "AND" not in v) or "\\;--" in v:
                self._send(200, json.dumps({"data": "sqlite3 syntax error near \"x\""}),
                            "application/json")
            else:
                self._send(200, json.dumps({"data": ["apple", "pear", "plum", "grape"]}),
                            "application/json")
            return
        if u.path == "/reflect":
            self._send(200, f"<div><script>var x='{get1('q')}'</script></div>", "text/html")
            return
        if u.path == "/files":
            if "etc/passwd" in get1("file"):
                self._send(200, PASSWD)
            else:
                self._send(200, "file ok")
            return
        if u.path == "/run":
            if any(t in get1("cmd") for t in (";id", "|id", "$(id)")):
                self._send(200, "uid=0(root) gid=0(root)")
            else:
                self._send(200, "cmd ok")
            return
        if u.path == "/fetch":
            if "127.0.0.1" in get1("url"):
                self._send(500, "connection refused dial tcp: stub fetch failed")
            else:
                self._send(200, "fetched ok")
            return
        if u.path == "/uploads/p.html":
            self._send(200, "<html>horcrux-probe marker</html>", "text/html")
            return
        self._send(404, "not found")

    def do_POST(self):
        if urlparse(self.path).path == "/upload":
            length = int(self.headers.get("Content-Length", 0) or 0)
            if length:
                self.rfile.read(length)
            self._send(201, json.dumps({"location": "/uploads/p.html"}), "application/json")
            return
        self._send(404, "not found")

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def vuln_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _VulnHandler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield port
    srv.shutdown()


def _assessment_state(port: int):
    from horcrux.intel.application_model import (
        ApplicationModel, SemanticEndpoint, SemanticParameter,
        SemanticWebTarget)
    from horcrux.models import WorkspaceState
    state = WorkspaceState(target="127.0.0.1")
    state.execution_mode = "LOCAL"
    eps = [SemanticEndpoint(method=m, path=p, sources=["synthetic-assessment"],
                            evidence_refs=[f"synthetic:{p}"])
           for m, p in [("GET", "/search"), ("GET", "/reflect"), ("GET", "/files"),
                        ("GET", "/run"), ("GET", "/fetch"), ("POST", "/upload")]]
    for ep in eps:
        ep.ensure_id()
    params = [SemanticParameter(name=n, location="query", endpoint=e,
                                source="operator", evidence_refs=[f"synthetic:{n}"],
                                provenance="OBSERVED_REQUEST", confidence=0.9,
                                first_seen="synthetic")
              for n, e in [("q", "/search"), ("q", "/reflect"), ("file", "/files"),
                           ("cmd", "/run"), ("url", "/fetch")]]
    for p in params:
        p.ensure_id()
    wt = SemanticWebTarget(scheme="http", host="127.0.0.1", port=port,
                           base_url=f"http://127.0.0.1:{port}")
    wt.ensure_id()
    app = ApplicationModel(target="127.0.0.1")
    app.endpoints = eps
    app.parameters = params
    app.web_targets = [wt]
    state.set_application_model(app)
    return state


@pytest.mark.parametrize("family,param,cwe", [
    ("param_sqli", "q", "CWE-89"),
    ("param_xss", "q", "CWE-79"),
    ("param_traversal", "file", "CWE-22"),
    ("param_cmdi", "cmd", "CWE-78"),
    ("param_ssrf", "url", "CWE-918"),
])
def test_single_family_confirms(vuln_server, family, param, cwe):
    from horcrux.agents import executor as ex
    from horcrux.agents.tools.capabilities import CapabilityRegistry
    from horcrux.intel.test_matrix import derive_applicable_tests, test_case_to_investigation
    ep_map = {"param_sqli": "/search", "param_xss": "/reflect",
              "param_traversal": "/files", "param_cmdi": "/run",
              "param_ssrf": "/fetch"}
    state = _assessment_state(vuln_server)
    app = state.get_application_model()
    tests = [t for t in derive_applicable_tests(app, state)
             if t.family.value == family and t.target_parameter == param
             and t.target_path == ep_map[family]]
    assert tests, f"no applicable test for {family}"
    inv = test_case_to_investigation(tests[0])
    state.set_investigations([inv])
    reg = CapabilityRegistry(workspace=None, runner=None, state=state, live_local=True)
    ex.execute_investigation_pipeline(state, inv, reg)
    assert inv.state.value == "SUPPORTED", f"{family}: {inv.result_summary}"
    assert any(cwe in f.cwes for f in state.findings), f"{family}: no {cwe} finding"


def test_one_assessment_recovers_five_distinct_families(vuln_server):
    """The core proof: one assessment, five families, five canonical
    findings with evidence — observations converted to conclusions."""
    from horcrux.agents import executor as ex
    from horcrux.agents.tools.capabilities import CapabilityRegistry
    from horcrux.intel.test_matrix import derive_applicable_tests, test_case_to_investigation
    state = _assessment_state(vuln_server)
    app = state.get_application_model()
    tests = derive_applicable_tests(app, state)
    wanted = {"param_sqli": "q", "param_xss": "q", "param_traversal": "file",
              "param_cmdi": "cmd", "param_ssrf": "url"}
    invs = []
    ep_map = {"param_sqli": "/search", "param_xss": "/reflect",
              "param_traversal": "/files", "param_cmdi": "/run",
              "param_ssrf": "/fetch"}
    for fam, param in wanted.items():
        match = [t for t in tests if t.family.value == fam and t.target_parameter == param
                 and t.target_path == ep_map[fam]]
        assert match, f"matrix missing {fam}/{param}"
        invs.append(test_case_to_investigation(match[0]))
    state.set_investigations(invs)
    reg = CapabilityRegistry(workspace=None, runner=None, state=state, live_local=True)
    for inv in invs:
        ex.execute_investigation_pipeline(state, inv, reg)
    supported = [i for i in invs if i.state.value == "SUPPORTED"]
    assert len(supported) >= 4, [(i.objective, i.state.value) for i in invs]
    cwes = {c for f in state.findings for c in f.cwes}
    assert len({"CWE-89", "CWE-79", "CWE-22", "CWE-78", "CWE-918"} & cwes) >= 4
    for f in state.findings:
        assert f.evidence, f"finding {f.id} lacks evidence chain"
        assert f.validation_state.value == "CONFIRMED"
