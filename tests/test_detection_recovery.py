"""Detection-recovery tests: new execution paths with vulnerable and
hardened twins. Local HTTP fixtures only; no external targets.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest


def _resp(status: int, text: str, headers: dict | None = None) -> dict:
    return {"status": status, "headers": dict(headers or {}), "text": text,
            "elapsed_ms": 5.0}


# ── registration JWT (vuln + hardened twin) ─────────────────────────
class _RegHandler(BaseHTTPRequestHandler):
    MODE = "vuln"

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
        if self.path == "/api/Users":
            if self.MODE == "hardened":
                self._send(403, '{"error":"registration disabled"}')
            else:
                self._send(201, json.dumps({"id": 7, "email": data.get("email")}))
            return
        if self.path == "/rest/user/login":
            if self.MODE == "hardened":
                self._send(401, '{"error":"nope"}')
            else:
                self._send(200, json.dumps({"authentication": {
                    "token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.c2ln",
                    "umail": data.get("email", "")}}))
            return
        self._send(404, "{}")

    def do_GET(self):
        auth = self.headers.get("Authorization", "")
        if self.path == "/rest/user/whoami" and auth.startswith("Bearer eyJ"):
            self._send(200, '{"user": {"id": 7}}')
        else:
            self._send(401, '{"error":"auth required"}')

    def log_message(self, *a):
        pass


@pytest.fixture(params=["vuln", "hardened"])
def reg_server(request):
    _RegHandler.MODE = request.param
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _RegHandler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield port, request.param
    srv.shutdown()


def test_registration_jwt_flow(reg_server):
    from horcrux.modules.web import security_validators as sv
    port, mode = reg_server
    base = f"http://127.0.0.1:{port}"

    def _req(method, url, query=None, body=None, headers_=None, **kw):
        with httpx.Client(verify=False, timeout=5.0) as c:
            r = c.request(method, url, params=query, json=body,
                          headers=headers_ or {})
            return {"status": r.status_code, "headers": dict(r.headers),
                    "text": r.text[:8000], "elapsed_ms": 1.0}

    res = sv.validate_registration_jwt_flow(
        _req, base, ["/api/Users"], ["/rest/user/login"],
        verify_paths=["/rest/user/whoami"])
    if mode == "vuln":
        assert res.verdict == "STRONG_REGISTRATION_JWT", res.details
        assert res.details["verified_at"] == "/rest/user/whoami"
        assert "eyJ" not in str(res.evidence)  # secrets never stored
    else:
        assert res.verdict in ("NO_EFFECT", "INSUFFICIENT_EVIDENCE"), res.verdict


# ── controls: headers/CORS/rate-limit (vuln + hardened twin) ───────
class _CtlHandler(BaseHTTPRequestHandler):
    MODE = "vuln"
    HITS = 0

    def _send(self, status, body, extra=None):
        raw = body.encode()
        self.send_response(status)
        origin = self.headers.get("Origin", "")
        if self.MODE == "vuln":
            self.send_header("Access-Control-Allow-Origin", origin or "*")
            self.send_header("Access-Control-Allow-Credentials", "true")
        else:
            self.send_header("Access-Control-Allow-Origin", "https://shop.example")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        self._send(200, "<html><body>app</body></html>")

    def do_OPTIONS(self):
        self.send_response(204)
        origin = self.headers.get("Origin", "")
        if self.MODE == "vuln":
            self.send_header("Access-Control-Allow-Origin", origin or "*")
            self.send_header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE")
        else:
            self.send_header("Access-Control-Allow-Origin", "https://shop.example")
        self.end_headers()

    def do_POST(self):
        if self.MODE == "vuln":
            length = int(self.headers.get("Content-Length", 0) or 0)
            self.rfile.read(length)
            self._send(200, '{"ok": true}')
        else:
            self._send(429, '{"error": "too many"}', {"Retry-After": "60"})

    def log_message(self, *a):
        pass


@pytest.fixture(params=["vuln", "hardened"])
def ctl_server(request):
    _CtlHandler.MODE = request.param
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _CtlHandler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield port, request.param
    srv.shutdown()


def test_controls_validator(ctl_server):
    from horcrux.modules.web import security_validators as sv
    port, mode = ctl_server
    base = f"http://127.0.0.1:{port}"

    def _req(method, url, query=None, body=None, headers_=None, **kw):
        with httpx.Client(verify=False, timeout=5.0) as c:
            r = c.request(method, url, params=query, json=body,
                          headers=headers_ or {})
            return {"status": r.status_code, "headers": dict(r.headers),
                    "text": r.text[:8000], "elapsed_ms": 1.0}

    res = sv.validate_security_controls(_req, base, ["/", "/login"])
    if mode == "vuln":
        assert res.verdict == "STRONG_CONTROLS_EVIDENCE", res.details
        assert "csp_missing" in res.details
        assert "cors_reflection" in res.details
        assert "rate_limit_absent" in res.details
    else:
        assert "cors_reflection" not in res.details
        assert "rate_limit_absent" not in res.details


# ── file artifacts (synthetic, no network) ─────────────────────────
def _freq(method, url, query=None, body=None, headers=None, **kw):
    if url.endswith("/ftp"):
        return _resp(200, '<title>listing directory /ftp/</title><ul id="files">'
                          '<li><a href="store.kdbx">x</a></li></ul>')
    if url.endswith("store.kdbx"):
        return {"status": 200, "headers": {"content-type": "application/octet-stream"},
                "text": bytes([0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5]).decode("latin-1"),
                "elapsed_ms": 1.0}
    return _resp(404, "no")


def test_file_probe_identifies_keepass_by_magic():
    from horcrux.modules.web import security_validators as sv
    res = sv.validate_file_artifact(_freq, "http://t.local", "/ftp")
    assert res.verdict == "STRONG_FILE_EVIDENCE", res.details
    kinds = [a["kind"] for a in res.details["artifacts"]]
    assert "keepass-kdbx" in kinds


def test_file_probe_adapter_sees_links_past_truncation():
    """Serve-index entries buried under >8000 chars of CSS must still be
    enumerated (Juice Shop /ftp regression)."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from horcrux.agents.tools.capabilities import _adapter_file_probe

    pad = "<style>" + ("x" * 9000) + "</style>"

    class _H(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.endswith("store.kdbx"):
                raw = bytes([0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5]) + b"\x00" * 64
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.end_headers()
                self.wfile.write(raw)
                return
            body = ("<html><head><title>listing directory /ftp/</title>" + pad +
                    '</head><body><ul id="files">'
                    '<li><a href="store.kdbx">s</a></li></ul></body></html>')
            raw = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        out = _adapter_file_probe({"target": "127.0.0.1", "endpoint": "/ftp",
                                   "port": port, "scheme": "http",
                                   "live_local": True, "matrix_family": "config_exposure"})
        assert out.structured_data["verdict"] == "STRONG_FILE_EVIDENCE", \
            out.structured_data
    finally:
        srv.shutdown()


def test_file_probe_rejects_plain_page():
    from horcrux.modules.web import security_validators as sv

    def _plain(method, url, query=None, body=None, headers=None, **kw):
        if url.endswith("/files"):
            return _resp(200, "<html><body>file area</body></html>")
        return _resp(404, "no")

    res = sv.validate_file_artifact(_plain, "http://t.local", "/files")
    assert res.verdict in ("NO_EFFECT", "INSUFFICIENT_EVIDENCE")


def test_xor_recovery_needs_english():
    from horcrux.modules.web.security_validators import _xor_recover
    txt, key = _xor_recover(bytes(b ^ 0x42 for b in b"the secret password is hunter2 " * 8))
    assert key == 0x42 and "secret" in txt
    txt2, key2 = _xor_recover(bytes(range(256)) * 4)
    assert txt2 == "" and key2 == -1


# ── provisioning (synthetic request_fn) ────────────────────────────
def test_provisioning_creates_two_isolated_actors():
    from horcrux.intel.provisioning import IdentityVault, provision_test_identities
    from horcrux.models import WorkspaceState
    from horcrux.intel.application_model import ApplicationModel, SemanticEndpoint
    st = WorkspaceState(target="127.0.0.1")
    app = ApplicationModel(target="127.0.0.1")
    for p in ("/api/Users", "/rest/user/login", "/rest/user/whoami"):
        ep = SemanticEndpoint(method="GET", path=p, sources=["t"], evidence_refs=["t"])
        ep.ensure_id()
        app.endpoints.append(ep)
    st.set_application_model(app)

    def _req(method, url, query=None, body=None, headers=None, **kw):
        who = ""
        if isinstance(body, dict):
            who = str(body.get("email", "") or body.get("username", ""))
        tok = "TOKEN-" + who
        if url.endswith("/api/Users") and method == "POST":
            return _resp(201, '{"id": 9}')
        if url.endswith("/rest/user/login"):
            return _resp(200, '{"authentication": {"token": "%s"}}' % tok)
        if url.endswith("/rest/user/whoami") and (headers or {}).get("Authorization", "").startswith("Bearer TOKEN-"):
            return _resp(200, '{"user": {"id": 9}}')
        return _resp(401, "{}")

    out = provision_test_identities(st, _req, "http://127.0.0.1:9")
    assert len(out["provisioned"]) == 2, out
    a = IdentityVault.get("127.0.0.1", "horcrux-a")
    b = IdentityVault.get("127.0.0.1", "horcrux-b")
    assert a.headers != b.headers  # isolation
    assert len(st.get_application_model().identities) >= 2  # A + B (anon added by ingestion)
    IdentityVault.clear("127.0.0.1")


def test_provisioning_refuses_out_of_scope():
    from horcrux.intel.provisioning import provision_test_identities
    from horcrux.models import WorkspaceState
    st = WorkspaceState(target="example.com")
    out = provision_test_identities(st, lambda *a, **k: _resp(200, "{}"), "http://example.com")
    assert out["provisioned"] == [] and out["reason"]


def test_token_extraction_covers_auth_token_field():
    from horcrux.intel.provisioning import _extract_token
    assert _extract_token({"auth_token": "A" * 40}) == "A" * 40
    assert _extract_token({"authentication": {"token": "B" * 40}}) == "B" * 40
    assert _extract_token({"message": "ok"}) == ""


def test_pinned_port_scope_parsing():
    from horcrux.core.orchestrator import _pinned_port
    assert _pinned_port("127.0.0.1:3000") == 3000
    assert _pinned_port("127.0.0.1") is None
    assert _pinned_port("example.com:http") is None
    assert _pinned_port("") is None


def test_registration_candidates_ranked_real_first():
    from horcrux.intel.provisioning import discover_auth_surfaces, provision_test_identities
    from horcrux.intel.application_model import ApplicationModel, SemanticEndpoint
    from horcrux.models import WorkspaceState
    from horcrux.intel.provisioning import IdentityVault
    st = WorkspaceState(target="127.0.0.1")
    app = ApplicationModel(target="127.0.0.1")
    for p in ("/users/v1", "/users/v1/_debug", "/users/v1/login",
              "/users/v1/register"):
        ep = SemanticEndpoint(method="GET", path=p, sources=["t"],
                              evidence_refs=["t"])
        ep.ensure_id()
        app.endpoints.append(ep)
    st.set_application_model(app)

    def _req(method, url, query=None, body=None, headers=None, **kw):
        if url.endswith("/users/v1/register") and method == "POST":
            return {"status": 200, "headers": {}, "text": '{"id": 3}',
                    "elapsed_ms": 1.0}
        if url.endswith("/users/v1/login"):
            who = (body or {}).get("username", "")
            return {"status": 200, "headers": {},
                    "text": '{"auth_token": "TOK-%s-1234567890abcdef"}' % who,
                    "elapsed_ms": 1.0}
        if url.endswith("/me"):
            return {"status": 200, "headers": {},
                    "text": '{"username": "u"}', "elapsed_ms": 1.0}
        return {"status": 404, "headers": {}, "text": "no",
                "elapsed_ms": 1.0}

    out = provision_test_identities(st, _req, "http://127.0.0.1:9")
    assert out["provisioned"] == ["horcrux-a", "horcrux-b"], out
    IdentityVault.clear("127.0.0.1")


def test_instance_discovery_framework_agnostic_and_jwt_sub():
    from horcrux.intel.application_model import ApplicationModel, SemanticEndpoint
    from horcrux.intel.provisioning import (ActorContext, IdentityVault,
                                            _jwt_sub,
                                            discover_object_instances)
    from horcrux.models import WorkspaceState
    assert _jwt_sub("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJwcm9iZSJ9.c2ln") == "probe"
    st = WorkspaceState(target="127.0.0.1")
    app = ApplicationModel(target="127.0.0.1")
    for p in ("/users/v1", "/books/v1"):
        ep = SemanticEndpoint(method="GET", path=p, sources=["t"],
                              evidence_refs=["t"])
        ep.ensure_id()
        app.endpoints.append(ep)
    st.set_application_model(app)
    IdentityVault.put("127.0.0.1", ActorContext(
        label="horcrux-a", email="a@horcrux.test", username="aa",
        headers={"Authorization": "Bearer T"}, user_id="",
        verified=True))

    def _req(method, url, query=None, body=None, headers=None, **kw):
        if url.endswith("/users/v1"):
            return {"status": 200, "headers": {},
                    "text": '{"users": [{"username": "aa", "email": "a@horcrux.test"}]}',
                    "elapsed_ms": 1.0}
        return {"status": 404, "headers": {}, "text": "no",
                "elapsed_ms": 1.0}

    out = discover_object_instances(st, _req, "http://127.0.0.1:9")
    assert out["owned"] >= 1, out
    assert any(i.get("owner_identity_id") == "horcrux-a"
               for i in st.object_instances)
    IdentityVault.clear("127.0.0.1")


# ── scheduler reservation ──────────────────────────────────────────
def test_scheduler_prefers_critical_over_recon():
    from horcrux.agents.focus import scheduler_rank
    from horcrux.intel.investigations import Investigation, InvestigationState
    from horcrux.models import WorkspaceState

    def _inv(obj, fam):
        inv = Investigation(id="", objective=obj, candidate_tools=["http_probe"],
                            required_capabilities=["http"], specialist="WebAgent",
                            state=InvestigationState.READY,
                            observations=[f"matrix_family:{fam}"])
        inv.ensure_id()
        return inv

    invs = [_inv("wordlist fuzzing round 7", "service_exploit_intel"),
            _inv("SQLi on owned param", "param_sqli"),
            _inv("registration JWT issuance", "api_security")]
    ranked = scheduler_rank(WorkspaceState(target="t"), invs)
    fams = [next(o.split(":")[1] for o in i.observations if o.startswith("matrix_family:"))
            for i in ranked]
    assert fams[0] in ("api_security", "param_sqli")
    assert fams[-1] == "service_exploit_intel"
    assert len(ranked) == 3  # ordered, never dropped


def test_instance_id_findings_deduplicate():
    from horcrux.engine.promote import dedup_key

    def _mk(ep):
        from horcrux.engine.promote import CanonicalFinding
        return CanonicalFinding(
            property_id="AUTHZ_BOLA_IDOR", title="IDOR", target="t",
            asset=ep, endpoint=ep, source_identity="a",
            target_identity="b", evidence_chain=["x"],
            request_evidence=["r"], response_evidence=["s"],
            reproduction=["curl"]).finalize()

    assert _mk("/api/Users/1").dedup_key == _mk("/api/Users/2").dedup_key
    assert _mk("/api/Users/1").dedup_key != _mk("/api/Orders/1").dedup_key


def test_instance_variant_requests_fold_into_pattern_endpoint():
    from horcrux.intel.application_model import ApplicationModel
    from horcrux.intel.ingestion import ingest_http_request
    app = ApplicationModel(target="t")
    ingest_http_request(app, "GET", "/api/Users/8", source="seed")
    assert len(app.endpoints) == 1
    ingest_http_request(app, "GET", "/api/Users/9", source="probe")
    assert len(app.endpoints) == 1
    assert "probe:GET:/api/Users/9" in app.endpoints[0].evidence_refs


def test_provenance_upgrades_on_stronger_evidence():
    from horcrux.intel.application_model import ApplicationModel
    from horcrux.intel.ingestion import ingest_workspace_state
    from horcrux.models import Parameter, WorkspaceState
    st = WorkspaceState(target="t.local")
    st.parameters = [
        Parameter(name="q", location="query", endpoint="/s",
                  source="x", provenance="UNKNOWN"),
        Parameter(name="q", location="query", endpoint="/s",
                  source="javascript", provenance="UNKNOWN"),
    ]
    # Simulate: same pair re-observed with endpoint-specific provenance.
    st.parameters.append(Parameter(name="q", location="query", endpoint="/s",
                                   source="operator", provenance="OBSERVED_REQUEST"))
    app = ingest_workspace_state(st)
    owned = [p for p in app.parameters if p.name == "q"]
    assert len(owned) == 1  # one canonical record per (name, location, endpoint)
    assert owned[0].provenance != "UNKNOWN"  # upgraded by stronger evidence


# ── triage ─────────────────────────────────────────────────────────
def test_triage_classifies_each_layer():
    from horcrux.engine.triage import triage_miss
    from horcrux.intel.application_model import ApplicationModel
    from horcrux.models import WorkspaceState
    st = WorkspaceState(target="t")
    st.set_application_model(ApplicationModel(target="t"))
    assert triage_miss("/nope", st)["stage"] == "NOT_DISCOVERED"


def test_unauth_mutation_requires_creation_evidence():
    from horcrux.agents.tools.capabilities import _validate_auth_generic

    def _ok_create(method, url, query=None, body=None, headers_=None,
                   cookies_=None, **kw):
        if method == "GET":
            return {"status": 401, "headers": {}, "text": "login",
                    "elapsed_ms": 1.0}
        return {"status": 201, "headers": {},
                "text": '{"id": 9, "email": "x"}', "elapsed_ms": 1.0}

    def _ok_error(method, url, query=None, body=None, headers_=None,
                  cookies_=None, **kw):
        if method == "GET":
            return {"status": 401, "headers": {}, "text": "login",
                    "elapsed_ms": 1.0}
        return {"status": 200, "headers": {},
                "text": "LLM error: prompt must not be empty", "elapsed_ms": 1.0}

    ctx: dict = {}
    r1 = _validate_auth_generic(_ok_create, "GET", "http://t/api/Users",
                                "auth_probe", "t1", ctx)
    assert r1.verdict == "STRONG_UNAUTH_MUTATION", r1.verdict
    r2 = _validate_auth_generic(_ok_error, "GET", "http://t/rest/chat",
                                "auth_probe", "t2", ctx)
    assert r2.verdict != "STRONG_UNAUTH_MUTATION", r2.verdict


def _adj_fixture(cap_id, data):
    from horcrux.intel.investigations import Investigation, InvestigationState
    from horcrux.intel.vulnerability_adjudicator import adjudicate_capability_outcome
    from horcrux.models import WorkspaceState

    class _R:
        capability_id = cap_id
        evidence = [{"stage": "SUPPORTED"}]

    _R.data = dict(data)
    st = WorkspaceState(target="t.local")
    inv = Investigation(id=f"inv-{cap_id}", objective=f"{cap_id} check",
                        candidate_tools=[cap_id],
                        required_capabilities=["http"], specialist="WebAgent",
                        state=InvestigationState.READY)
    out = adjudicate_capability_outcome(_R(), inv, None, st)
    return out, st


def test_controls_strong_reaches_finding():
    out, st = _adj_fixture("controls_probe", {
        "verdict": "STRONG_CONTROLS_EVIDENCE", "endpoint": "/",
        "csp_missing": ["/"], "cors_wildcard": {"cors_wildcard": True}})
    from horcrux.intel.investigations import InvestigationState
    assert out["state"] == InvestigationState.SUPPORTED, out
    assert len(st.findings) >= 2  # CSP + CORS recorded separately


def test_file_strong_reaches_finding():
    out, st = _adj_fixture("file_probe", {
        "verdict": "STRONG_FILE_EVIDENCE", "endpoint": "/ftp",
        "artifacts": [{"path": "/ftp/s.kdbx", "kind": "keepass-kdbx",
                       "size": 3000}]})
    from horcrux.intel.investigations import InvestigationState
    assert out["state"] == InvestigationState.SUPPORTED, out
    assert any("KeePass" in f.title or "keepass" in f.title.lower()
               for f in st.findings)


def test_registration_strong_reaches_finding():
    out, st = _adj_fixture("registration_probe", {
        "verdict": "STRONG_REGISTRATION_JWT", "endpoint": "/api/Users",
        "registration": "/api/Users", "jwt_issued": True,
        "verified_at": "/rest/user/whoami"})
    from horcrux.intel.investigations import InvestigationState
    assert out["state"] == InvestigationState.SUPPORTED, out
    assert any("JWT" in f.title for f in st.findings)


# ── IDOR differential promotion ────────────────────────────────────
def test_idor_differential_with_ownership_promotes():
    from horcrux.intel.investigations import Investigation, InvestigationState
    from horcrux.intel.vulnerability_adjudicator import adjudicate_capability_outcome
    from horcrux.models import WorkspaceState

    class _R:
        capability_id = "authz_compare"
        data = {"verdict": "BEHAVIORAL_DIFFERENTIAL",
                "endpoint": "/api/Users/9", "affected_asset": "/api/Users/1",
                "ownership": {"email": "admin@juice-sh.op"},
                "boundary": "/api/Users/1"}
        evidence = [{"stage": "SUPPORTED"}]

    st = WorkspaceState(target="t.local")
    inv = Investigation(id="inv-idor", objective="BOLA check",
                        candidate_tools=["authz_compare"],
                        required_capabilities=["http"], specialist="WebAgent",
                        state=InvestigationState.READY)
    out = adjudicate_capability_outcome(_R(), inv, None, st)
    assert out["state"] == InvestigationState.SUPPORTED, out
    assert any("639" in c for f in st.findings for c in f.cwes)


def test_idor_differential_without_ownership_stays_neutral():
    from horcrux.intel.investigations import Investigation, InvestigationState
    from horcrux.intel.vulnerability_adjudicator import adjudicate_capability_outcome
    from horcrux.models import WorkspaceState

    class _R:
        capability_id = "authz_compare"
        data = {"verdict": "BEHAVIORAL_DIFFERENTIAL", "endpoint": "/api/x"}
        evidence = [{"stage": "OBSERVED"}]

    st = WorkspaceState(target="t.local")
    inv = Investigation(id="inv-idor2", objective="BOLA check",
                        candidate_tools=["authz_compare"],
                        required_capabilities=["http"], specialist="WebAgent",
                        state=InvestigationState.READY)
    out = adjudicate_capability_outcome(_R(), inv, None, st)
    assert out["state"] == InvestigationState.COMPLETE
    assert st.findings == []


# ── instance seeding ───────────────────────────────────────────────
def test_instance_seeding_binds_owner_from_actor_id():
    from horcrux.intel.application_model import ApplicationModel, SemanticEndpoint
    from horcrux.intel.provisioning import IdentityVault, discover_object_instances
    from horcrux.models import WorkspaceState
    from horcrux.intel.provisioning import ActorContext
    st = WorkspaceState(target="127.0.0.1")
    app = ApplicationModel(target="127.0.0.1")
    ep = SemanticEndpoint(method="GET", path="/api/Users", sources=["t"],
                          evidence_refs=["t"])
    ep.ensure_id()
    app.endpoints.append(ep)
    st.set_application_model(app)
    IdentityVault.put("127.0.0.1", ActorContext(
        label="horcrux-a", email="a@horcrux.test", username="aa",
        headers={"Authorization": "Bearer T"}, user_id="9", verified=True))

    def _req(method, url, query=None, body=None, headers=None, **kw):
        if url.endswith("/api/Users/9"):
            return {"status": 200, "headers": {},
                    "text": '{"id": 9, "email": "a@horcrux.test"}',
                    "elapsed_ms": 1.0}
        if url.endswith("/api/Users"):
            return {"status": 200, "headers": {},
                    "text": '[{"id": 9, "email": "a@horcrux.test"}]',
                    "elapsed_ms": 1.0}
        return {"status": 404, "headers": {}, "text": "no", "elapsed_ms": 1.0}

    out = discover_object_instances(st, _req, "http://127.0.0.1:9")
    assert out["owned"] >= 1, out
    owned = [i for i in st.object_instances if i.get("owner_identity_id") == "horcrux-a"]
    assert owned and owned[0]["object_id"] == "9"
    IdentityVault.clear("127.0.0.1")


# ── registration matrix routing ────────────────────────────────────
def test_registration_matrix_test_routes_to_probe():
    from horcrux.intel.application_model import ApplicationModel, SemanticEndpoint
    from horcrux.intel.test_matrix import derive_applicable_tests
    app = ApplicationModel(target="t")
    ep = SemanticEndpoint(method="POST", path="/api/Users", sources=["t"],
                          evidence_refs=["t"])
    ep.ensure_id()
    app.endpoints.append(ep)
    tests = [t for t in derive_applicable_tests(app, None)
             if "registration jwt" in t.name.lower()]
    assert tests
    assert tests[0].candidate_tools[0] == "registration_probe"
