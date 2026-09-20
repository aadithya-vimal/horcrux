"""Regression tests for real Juice Shop misses (v20.2.0 adversarial run).

1. /ftp serve-index listing missed by over-narrow oracle markers.
2. Synthetic `q`/`id` spray onto unowned endpoints + model contamination.
3. SQLi login bypass on /rest/user/login never tested.

Synthetic/local fixtures only. No external targets.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest


def _mock_resp(status: int, text: str, ctype: str = "text/html") -> httpx.Response:
    req = httpx.Request("GET", "http://t.local/x")
    return httpx.Response(status, headers={"content-type": ctype},
                          text=text, request=req)


SERVE_INDEX_BODY = """<!DOCTYPE html><html><head><title>listing directory /ftp/</title></head>
<body><h1>ftp</h1><ul id="files" class="view-tiles">
<li><a href="coupons_2013.md.bak"><span class="name">coupons_2013.md.bak</span></a></li>
<li><a href="incident-support.kdbx"><span class="name">incident-support.kdbx</span></a></li>
</ul></body></html>"""


def _baseline():
    from horcrux.modules.web.validator import BaselineFingerprint
    return BaselineFingerprint.analyze(_mock_resp(404, "not found", "text/plain"))


# ── Miss 1: serve-index directory listing ─────────────────────────
def test_ftp_serve_index_confirms_listing():
    from horcrux.models import ValidationState
    from horcrux.modules.web.validator import validate_ftp_directory_listing
    res = validate_ftp_directory_listing(_mock_resp(200, SERVE_INDEX_BODY), _baseline())
    assert res.is_valid is True
    assert res.validation_state == ValidationState.confirmed


def test_ftp_plain_page_without_files_is_not_listing():
    from horcrux.models import ValidationState
    from horcrux.modules.web.validator import validate_ftp_directory_listing
    res = validate_ftp_directory_listing(
        _mock_resp(200, "<html><body>ftp service ready</body></html>"), _baseline())
    assert res.is_valid is False
    assert res.validation_state != ValidationState.confirmed


# ── Miss 2: synthetic spray refusal ───────────────────────────────
def _live_ctx(endpoint: str, app) -> dict:
    return {"target": "127.0.0.1:9", "endpoint": endpoint, "path": endpoint,
            "port": 9, "scheme": "http", "matrix_family": "param_sqli",
            "application_model": app, "live_local": True,
            "execution_mode": "LOCAL"}


def test_param_fuzz_refuses_unowned_spray_without_network():
    from horcrux.agents.tools.capabilities import _adapter_param_fuzz
    from horcrux.intel.application_model import ApplicationModel
    app = ApplicationModel(target="t.local")
    ctx = _live_ctx("/rest/admin", app)
    ctx["parameters"] = ["q", "id"]
    out = _adapter_param_fuzz(ctx)
    assert out.structured_data["verdict"] == "INSUFFICIENT_EVIDENCE"
    assert "unowned-parameter" in out.structured_data["reason"]
    assert out.evidence == []


def test_validator_adapter_refuses_unowned_param():
    from horcrux.agents.tools.capabilities import _run_validator_adapter
    from horcrux.intel.application_model import ApplicationModel
    app = ApplicationModel(target="t.local")
    ctx = _live_ctx("/rest/admin", app)
    ctx["parameter"] = "q"
    out = _run_validator_adapter("sqli_probe", ctx, "sqli")
    assert out.structured_data["verdict"] == "INSUFFICIENT_EVIDENCE"
    assert "unowned-parameter" in out.structured_data["reason"]
    assert out.evidence == []


def test_owned_param_still_reaches_validator():
    from horcrux.agents.tools.capabilities import _resolve_param_location
    from horcrux.intel.application_model import ApplicationModel, SemanticParameter
    app = ApplicationModel(target="t.local")
    app.parameters = [SemanticParameter(name="q", location="query",
                                        endpoint="/search", source="operator",
                                        evidence_refs=["op:q"],
                                        provenance="OBSERVED_REQUEST")]
    ctx = {"application_model": app}
    assert _resolve_param_location(ctx, "/search", "q") == "query"
    assert _resolve_param_location(ctx, "/other", "q") is None


def test_openapi_document_yields_owned_endpoints_and_params():
    from horcrux.intel.application_model import ApplicationModel
    from horcrux.intel.ingestion import ingest_openapi_document
    from horcrux.intel.parameters import is_owned_in_model
    from horcrux.intel.test_matrix import derive_applicable_tests
    app = ApplicationModel(target="t.local")
    doc = {"openapi": "3.0.0", "paths": {
        "/users/v1/{username}": {
            "get": {"parameters": [{"name": "username", "in": "path"}]}},
        "/books/v1": {
            "get": {},
            "post": {"requestBody": {"content": {"application/json": {"schema": {
                "properties": {"title": {}, "secret": {}}}}}}}}}}
    assert ingest_openapi_document(app, doc, source="openapi") == 3
    paths = {e.path for e in app.endpoints}
    assert "/users/v1/{username}" in paths and "/books/v1" in paths
    assert is_owned_in_model(app.parameters, "username", "/users/v1/{username}")
    assert is_owned_in_model(app.parameters, "secret", "/books/v1")
    tests = derive_applicable_tests(app, None)
    assert any(t.asset_type == "endpoint" and t.target_path == "/books/v1" for t in tests)


def test_probe_observations_never_create_ownership():
    from horcrux.intel.application_model import ApplicationModel
    from horcrux.intel.ingestion import ingest_capability_evidence
    app = ApplicationModel(target="t.local")
    n = ingest_capability_evidence(app, "param_fuzz", [{
        "evidence_type": "parameter_observation",
        "data": {"parameter": "q", "endpoint": "/rest/admin"},
        "source": "param_fuzz", "confidence": 0.6}])
    assert n == 0
    assert app.parameters == []


# ── Miss 3: login bypass ──────────────────────────────────────────
class _LoginHandler(BaseHTTPRequestHandler):
    def _send(self, status, body):
        raw = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            data = {}
        email = str(data.get("email", ""))
        if "OR 1=1" in email or email.endswith("--"):
            self._send(200, json.dumps({"authentication": {"token": "jwt-admin-token",
                                                           "umail": "admin@juice-sh.op"}}))
        else:
            self._send(401, json.dumps({"error": "Invalid email or password"}))

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def login_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _LoginHandler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield port
    srv.shutdown()


def test_auth_bypass_sqli_confirms_token_oracle(login_server):
    from horcrux.modules.web import security_validators as sv
    base = f"http://127.0.0.1:{login_server}/rest/user/login"

    def _login(fields: dict) -> dict:
        with httpx.Client(verify=False, timeout=5.0) as c:
            r = c.post(base, json=fields)
            return {"status": r.status_code, "headers": dict(r.headers),
                    "text": r.text[:8000], "elapsed_ms": 1.0}

    res = sv.validate_auth_bypass_sqli(_login, base)
    assert res.verdict == "STRONG_AUTH_BYPASS_EVIDENCE"
    assert res.details["auth_bypass"] is True
    assert res.details["token_issued"] is True


def test_auth_bypass_rejects_hardened_login():
    from horcrux.modules.web import security_validators as sv

    def _login(fields: dict) -> dict:
        return {"status": 401, "headers": {}, "text": '{"error":"nope"}',
                "elapsed_ms": 1.0}

    res = sv.validate_auth_bypass_sqli(_login, "http://t.local/login")
    assert res.verdict == "NO_EFFECT"
