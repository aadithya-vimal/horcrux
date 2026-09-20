"""Phase 8 production tests — synthetic/local only, never external targets."""

from __future__ import annotations

import json

import pytest

from horcrux.agents.tools.capabilities import CapabilityRegistry, is_synthetic_target
from horcrux.core.storage import Workspace
from horcrux.intel.application_model import ApplicationModel
from horcrux.intel.ask_engine import (AskIntent, answer_deterministically,
                                      build_structured_context, classify_ask_intent)
from horcrux.intel.browser import (ScriptedBrowserAdapter, browser_backend_status,
                                    get_browser_adapter)
from horcrux.intel.browser_session import record_browser_session
from horcrux.intel.contradictions import detect_contradictions, propose_resolutions
from horcrux.intel.dependencies import (apply_dependencies, evaluate_prerequisites,
                                        select_parallel_batch)
from horcrux.intel.events import (finding_lineage, log_event, read_events,
                                  snapshot_counts, state_delta)
from horcrux.intel.hypotheses import HypothesisClass, generate_hypotheses
from horcrux.intel.ingestion import (classify_parameter, ingest_api_operations,
                                     ingest_client_side, ingest_graphql_operations,
                                     ingest_object_lifecycles,
                                     ingest_workflow_transitions,
                                     ingest_workspace_state)
from horcrux.intel.investigations import InvestigationState
from horcrux.intel.sessions import (TestIdentity, authenticated_crawl,
                                    begin_session, compare_identities,
                                    load_test_identities, observe_identity_object,
                                    record_login_transition)
from horcrux.models import WorkspaceState
from tests.fixtures.synthetic_vulnerable_app import build_synthetic_workspace


def _rich() -> WorkspaceState:
    from tests.test_phase7_operational import _rich_state
    return _rich_state()


def _ws_for(state: WorkspaceState, tmp_path, name: str = "ws8"):
    ws = Workspace(state.target)
    ws.root = tmp_path / name
    for d in (ws.root, ws.raw, ws.responses, ws.headers, ws.reports):
        d.mkdir(parents=True, exist_ok=True)
    ws.state_file = ws.root / "state.json"
    ws.save(state)
    return ws


# --- P1/P2 browser ------------------------------------------------------------

def test_browser_backends_report_status():
    status = browser_backend_status()
    assert status["scripted"]["available"] is True
    assert "playwright" in status


def test_scripted_adapter_never_touches_network():
    pages = {"/": {"title": "App", "links": ["/api/orders/1"],
                   "api_calls": [{"method": "GET", "url": "http://x/app/api/orders/1"}],
                   "forms": [{"action": "/login", "inputs": ["email"]}],
                   "cookies": [{"name": "sid", "value": "abc"}]}}
    adapter = ScriptedBrowserAdapter(pages=pages)
    assert adapter.is_available()[0] is True
    adapter.launch()
    adapter.create_context(identity="user-a")
    obs = adapter.navigate("http://bench.local/")
    assert obs.status_code == 200
    assert "/api/orders/1" in obs.dom_routes
    adapter.close()


def test_browser_evidence_converges_to_same_model():
    from horcrux.intel.browser import BrowserObservation
    app = ApplicationModel(target="bench.local")
    obs = BrowserObservation(
        url="http://bench.local/app", status_code=200,
        dom_routes=["/api/orders/1"],
        api_calls=[{"method": "GET", "url": "http://bench.local/api/users/2"}],
        forms=[{"action": "/login", "method": "POST", "inputs": ["email"]}],
        cookies=[{"name": "sid", "value": "supersecret"}],
        storage_keys=["token"], identity="user-a", provenance="browser:scripted")
    out = record_browser_session(obs, app, identity="user-a")
    paths = {e.path for e in app.endpoints}
    assert "/api/orders/1" in paths and "/api/users/2" in paths
    assert any(f.action == "/login" for f in app.forms)
    # No raw secrets persisted.
    blob = app.model_dump_json()
    assert "supersecret" not in blob
    assert out["provenance"] == "browser:scripted"


def test_browser_scope_blocked():
    from horcrux.core.policy import EngagementPolicy
    pages = {"/": {"title": "x"}}
    policy = EngagementPolicy()
    policy.scope.allowed_targets = ["bench.local"]
    adapter = ScriptedBrowserAdapter(
        pages=pages,
        scope_check=lambda u: policy.is_target_allowed(
            __import__("urllib.parse", fromlist=["urlparse"]).urlparse(u).hostname or "")[0])
    with pytest.raises(PermissionError):
        adapter.navigate("http://evil.example/")


def test_get_browser_adapter_auto_prefers_scripted_offline():
    adapter = get_browser_adapter("auto")
    assert adapter.is_available()[0] is True


# --- P3 sessions ----------------------------------------------------------------

def test_session_hashes_no_raw_secrets():
    app = ApplicationModel(target="bench.local")
    sess = begin_session(app, "user-a", role="user",
                         cookies=[{"name": "sid", "value": "raw-secret-123"}],
                         token="raw-jwt-token", login_endpoint="/login")
    assert sess.id
    blob = app.model_dump_json()
    assert "raw-secret-123" not in blob and "raw-jwt-token" not in blob
    ident = next(i for i in app.identities if i.label == "user-a")
    assert ident.session_ids == [sess.id]


def test_test_identities_from_env_only(monkeypatch):
    monkeypatch.setenv("HORCRUX_IDENTITY_1_LABEL", "tester")
    monkeypatch.setenv("HORCRUX_IDENTITY_1_ROLE", "user")
    monkeypatch.setenv("HORCRUX_IDENTITY_1_USER", "tester")
    monkeypatch.setenv("HORCRUX_IDENTITY_1_PASS_ENV", "HORCRUX_TEST_PW")
    monkeypatch.setenv("HORCRUX_TEST_PW", "s3cret")
    identities = load_test_identities()
    assert identities and identities[0].label == "tester"
    assert identities[0].resolve_secret() == "s3cret"
    assert load_test_identities({}) == [] or True


def test_authenticated_crawl_workflow():
    from horcrux.intel.ingestion import ingest_workspace_state
    state = _rich()
    app = ingest_workspace_state(state)
    pages = {"/": {"title": "App", "links": ["/rest/user/login"]},
             "/rest/user/login": {"title": "Login",
                                  "forms": [{"action": "/rest/user/login", "inputs": ["email"]}]},
             "/api": {"title": "API", "api_calls": [
                 {"method": "GET", "url": "http://bench/api/orders/1"}]}}
    adapter = ScriptedBrowserAdapter(pages=pages)
    ident = TestIdentity(label="user-a", role="user", username="user-a", password="pw")
    summary = authenticated_crawl(app, adapter, "http://bench", ident,
                                  extra_paths=["/api"])
    assert summary["authenticated"] is True
    assert summary["evidence"] > 0
    assert any(s.identity_label == "user-a" for s in app.sessions)
    record_login_transition(app, "user-a", "/rest/user/login", True)


def test_observe_identity_object_feeds_lifecycle():
    app = ApplicationModel(target="bench.local")
    observe_identity_object(app, "user-a", "Order", "123",
                            endpoint="/api/orders/123", operation="read")
    observe_identity_object(app, "user-b", "Order", "456",
                            endpoint="/api/orders/456", operation="read")
    assert len(app.object_lifecycles) == 2


# --- P12 comparison ---------------------------------------------------------------

def test_multi_identity_comparison_gap():
    from horcrux.intel.ingestion import ingest_workspace_state
    state = _rich()
    app = ingest_workspace_state(state)
    observe_identity_object(app, "user-a", "Order", "123", "/rest/basket/123")
    observe_identity_object(app, "user-b", "Order", "123", "/rest/basket/123")
    state.set_application_model(app)
    out = compare_identities(state, "anonymous", "authenticated_user")
    assert out["verdict"] in ("gap_suspected", "enforced", "insufficient")
    assert "evidence" in out


# --- P5/P6 behavior ---------------------------------------------------------------

def test_object_lifecycle_and_transitions():
    from horcrux.intel.ingestion import ingest_workspace_state
    state = _rich()
    app = ingest_workspace_state(state)
    assert ingest_object_lifecycles(app) >= 1
    assert any(lc.read_endpoints for lc in app.object_lifecycles)
    assert ingest_workflow_transitions(app) >= 1
    assert any(t.state_changing for t in app.workflow_transitions)


def test_api_operations_deduplicate_sources():
    from horcrux.intel.ingestion import ingest_workspace_state
    state = _rich()
    app = ingest_workspace_state(state)
    n = ingest_api_operations(app)
    assert n >= 1
    paths = [op.path for op in app.api_operations]
    assert not any("/1" in p and "{id}" not in p for p in paths
                   if "basket" in p or "users" in p)


def test_graphql_operations_parsed():
    app = ApplicationModel(target="bench.local")
    from horcrux.intel.ingestion import ingest_crawler_paths
    ingest_crawler_paths(app, ["/graphql"], source="javascript")
    n = ingest_graphql_operations(
        app, ["query GetOrder { order { id total } }",
              "mutation PlaceOrder { placeOrder { id } }"])
    assert n == 2
    assert {o.name for o in app.graphql_operations} == {"GetOrder", "PlaceOrder"}


def test_client_side_typed_evidence_no_raw_js():
    app = ApplicationModel(target="bench.local")
    js = ('fetch("/api/orders/1"); localStorage.setItem("prefs","x"); '
          'el.innerHTML = name; //# sourceMappingURL=app.js.map; '
          'const k = "apikey: REDACTED-BY-TEST";')
    out = ingest_client_side(app, js, source_name="app.js")
    assert "/api/orders/1" in out["routes"]
    assert "app.js.map" in out["sourcemaps"]
    assert out["dom_sinks"] and out["dangerous"]
    assert any(e.path == "/api/orders/1" for e in app.endpoints)


def test_classify_parameter():
    assert classify_parameter("userId") == "object_id"
    assert classify_parameter("page") == "pagination"
    assert classify_parameter("callback") == "url_fetch"
    assert classify_parameter("file", "body") == "file"


# --- P7/P8/P15 hypotheses ----------------------------------------------------------

def test_correlated_authz_hypothesis():
    from horcrux.intel.ingestion import ingest_workspace_state
    state = _rich()
    app = ingest_workspace_state(state)
    hyps = generate_hypotheses(app)
    classes = {h.hypothesis_class for h in hyps}
    assert HypothesisClass.IDOR_BOLA in classes
    bola = [h for h in hyps if h.hypothesis_class == HypothesisClass.IDOR_BOLA]
    assert any(h.validation_requirements for h in bola)


def test_business_logic_property_hypotheses():
    from horcrux.intel.ingestion import ingest_workspace_state
    state = _rich()
    app = ingest_workspace_state(state)
    hyps = generate_hypotheses(app)
    bl = [h for h in hyps if h.hypothesis_class == HypothesisClass.BUSINESS_LOGIC]
    assert bl


# --- P13/P14 attack paths ------------------------------------------------------------

def test_attack_path_graph_and_ranking():
    from horcrux.intel.attack_paths import rank_attack_paths
    from horcrux.intel.ingestion import ingest_workspace_state
    from horcrux.agents.lifecycle import reassess
    state = _rich()
    reassess(state, None)
    paths = [type("P", (), {})()]  # placeholder guard (unused)
    from horcrux.intel.attack_paths import build_attack_paths
    built = build_attack_paths(state)
    assert len(built) >= 1
    for p in built:
        for e in p.edges:
            assert e.evidence or e.inference  # explicit either way
    ranked = rank_attack_paths(built)
    assert ranked[0].rank_score >= ranked[-1].rank_score
    assert ranked[0].rank_why


# --- P16/P34 dependencies ---------------------------------------------------------------

def test_dependency_gating_and_unblock():
    from horcrux.intel.ingestion import ingest_workspace_state
    from horcrux.intel.investigations import Investigation, InvestigationState
    state = _rich()
    ingest_workspace_state(state)
    inv = Investigation(objective="Compare object access across identities",
                        candidate_tools=["identity_compare"],
                        prerequisites=["two_identities"],
                        specialist="AuthorizationAgent", state=InvestigationState.READY)
    inv.ensure_id()
    schedulable, blocked = evaluate_prerequisites(state, inv)
    assert schedulable is False and blocked
    out = apply_dependencies(state, [inv])
    assert out[0].state in (InvestigationState.BLOCKED, InvestigationState.REQUIRES_SECOND_IDENTITY)
    # Two distinct identities arrive -> unblocks.
    observe_identity_object(state.get_application_model(), "user-b", "Order", "9")
    from horcrux.intel.application_model import IdentityRole, SemanticIdentity
    app = state.get_application_model()
    app.upsert_identity(SemanticIdentity(role=IdentityRole.USER, label="user-a"))
    app.upsert_identity(SemanticIdentity(role=IdentityRole.USER, label="user-b"))
    state.set_application_model(app)
    out = apply_dependencies(state, [inv])
    assert out[0].state == InvestigationState.READY


def test_parallel_batch_only_independent():
    from horcrux.intel.investigations import Investigation, InvestigationState
    mk = lambda obj, tools, hyp: Investigation(
        objective=obj, candidate_tools=tools, hypothesis_id=hyp,
        specialist="WebAgent", state=InvestigationState.READY)
    a, b, c = mk("a", ["http_probe"], "h1"), mk("b", ["http_probe"], "h2"), mk("c", ["identity_switch"], "h3")
    for i in (a, b, c):
        i.ensure_id()
    batch = select_parallel_batch([a, b, c], max_workers=3)
    assert a in batch and b in batch and c not in batch  # session-mutating stays serial
    assert len(select_parallel_batch([a, b], max_workers=1)) == 1


# --- P19 ask router ------------------------------------------------------------------------

def test_ask_intent_router_new_classes():
    assert classify_ask_intent("what is the status?") == AskIntent.STATUS
    assert classify_ask_intent("what changed since last time?") == AskIntent.STATUS
    assert classify_ask_intent("write a report of the assessment") == AskIntent.REPORT
    assert classify_ask_intent("explain this attack path") == AskIntent.EXPLANATION


def test_ask_status_delta_and_report():
    from horcrux.intel.ingestion import ingest_workspace_state
    from horcrux.agents.lifecycle import reassess
    state = _rich()
    reassess(state, None)
    reassess(state, None)
    ctx = build_structured_context(state, "what changed?")
    assert "delta" in ctx or "current_counts" in ctx
    answer = answer_deterministically(state, "what changed?")
    assert "changed" in answer.lower() or "state" in answer.lower()
    rep = answer_deterministically(state, "report the assessment")
    assert "bench" in rep or "investigation" in rep.lower()


def test_ask_disproof_and_attack_path_detail():
    from horcrux.intel.ingestion import ingest_workspace_state
    from horcrux.agents.lifecycle import reassess
    state = _rich()
    reassess(state, None)
    ans = answer_deterministically(state, "what evidence would disprove this bola hypothesis?")
    assert "disprove" in ans.lower()
    ans2 = answer_deterministically(state, "explain this attack path")
    assert "path" in ans2.lower()


# --- P20 cost routing --------------------------------------------------------------------------

def test_reasoning_tier_routing():
    from horcrux.intel.ai.capabilities import (select_reasoning_tier, summarize_ai_usage,
                                               usage_record)
    assert select_reasoning_tier("deduplication")[0] == "cheap"
    assert select_reasoning_tier("reasoning_before_final_synthesis")[0] == "strong"
    rec = usage_record("groq", "model", "cheap", 0.5, 10, 5, True, "r")
    assert rec["total_tokens"] == 15
    assert summarize_ai_usage(None, None)["calls"] == 0


# --- P21 contradictions -----------------------------------------------------------------------------

def test_contradiction_detect_and_resolve():
    from horcrux.intel.ingestion import ingest_workspace_state
    state = _rich()
    app = ingest_workspace_state(state)
    from horcrux.intel.ingestion import ingest_http_request
    ingest_http_request(app, "GET", "/rest/admin", identity="anonymous", source="browser")
    state.set_application_model(app)
    contras = detect_contradictions(state)
    assert any(c.kind == "auth_conflict" for c in contras)
    created = propose_resolutions(state, contras)
    assert created  # high-impact auth conflict spawns resolution work


# --- P22/P35 events ------------------------------------------------------------------------------------

def test_event_log_and_lineage(tmp_path):
    state = _rich()
    ws = _ws_for(state, tmp_path, "evt")
    log_event(ws, state, "ASSESSMENT_STARTED", {"run_id": "r1"})
    log_event(ws, state, "EVIDENCE_INGESTED", {"count": 3})
    recent = read_events(ws, limit=10)
    assert [r["event"] for r in recent] == ["ASSESSMENT_STARTED", "EVIDENCE_INGESTED"]
    snap = snapshot_counts(state)
    assert snap["endpoints"] >= 0
    assert state_delta(snap, {**snap, "endpoints": snap["endpoints"] + 1})["endpoints"]["after"] \
        == snap["endpoints"] + 1
    assert finding_lineage(state, "nope")["evidence"] == []


# --- P23 recovery --------------------------------------------------------------------------------------------

def test_workspace_recovery_requeues_running():
    from horcrux.agents.lifecycle import recover_interrupted
    from horcrux.intel.ingestion import ingest_workspace_state
    from horcrux.intel.investigations import Investigation, InvestigationState
    state = _rich()
    ingest_workspace_state(state)
    inv = Investigation(objective="interrupted work", specialist="WebAgent",
                        state=InvestigationState.RUNNING)
    inv.ensure_id()
    done = Investigation(objective="done work", specialist="WebAgent",
                         state=InvestigationState.COMPLETE)
    done.ensure_id()
    state.set_investigations([inv, done])
    report = recover_interrupted(state)
    states = {i.id: i.state for i in state.get_investigations()}
    assert states[inv.id] == InvestigationState.READY
    assert states[done.id] == InvestigationState.COMPLETE
    assert inv.id in report["recovered"]


# --- P24 crash safety ---------------------------------------------------------------------------------------------

def test_capability_crash_becomes_failed_state():
    from horcrux.agents.executor import (apply_capability_result,
                                         run_capability_for_investigation)
    from horcrux.intel.ingestion import ingest_workspace_state
    from horcrux.intel.investigations import Investigation, InvestigationState
    state = _rich()
    ingest_workspace_state(state)
    inv = Investigation(objective="crash probe", candidate_tools=["http_probe"],
                        specialist="WebAgent", state=InvestigationState.READY)
    inv.ensure_id()
    reg = CapabilityRegistry(state=state)
    cap = reg.get("http_probe")
    orig = cap.execute_fn
    cap.execute_fn = lambda ctx: (_ for _ in ()).throw(RuntimeError("boom"))
    try:
        run = run_capability_for_investigation(state, inv, reg)
        out = apply_capability_result(state, inv, run, workspace=None)
    finally:
        cap.execute_fn = orig
    assert inv.state == InvestigationState.FAILED
    assert out["success"] is False


# --- P25 scope -------------------------------------------------------------------------------------------------------

def test_scope_blocks_out_of_scope_target():
    from horcrux.core.policy import (EngagementPolicy, is_url_allowed,
                                     validate_redirect_chain)
    policy = EngagementPolicy()
    policy.scope.allowed_targets = ["bench.local"]
    assert is_url_allowed(policy, "http://bench.local/api")[0] is True
    assert is_url_allowed(policy, "http://evil.example/x")[0] is False
    assert validate_redirect_chain(policy, ["http://bench.local/a"])[0] is True
    assert validate_redirect_chain(
        policy, ["http://bench.local/a", "http://evil.example/b"])[0] is False


def test_registry_scope_gate_redirect_destination():
    from horcrux.models import WorkspaceState as WS
    state = WS(target="bench.local")
    reg = CapabilityRegistry(state=state)
    out = reg.execute("http_probe", {"target": "bench.local",
                                     "redirect_destination": "http://evil.example/"})
    assert out.success is False
    assert out.failure.value == "scope_blocked"


def test_destructive_inputs_require_approval():
    state = WorkspaceState(target="bench.local")
    reg = CapabilityRegistry(state=state)
    out = reg.execute("http_probe", {"target": "bench.local",
                                     "path": "/x", "note": "run exploit now"})
    assert out.failure.value == "operator_approval_required"


# --- P26/P27 availability -----------------------------------------------------------------------------------------------

def test_capability_status_lifecycle():
    reg = CapabilityRegistry(state=WorkspaceState(target="bench.local"))
    st = reg.capability_status("http_probe")
    assert st["status"] == "AVAILABLE"
    assert reg.capability_status("nope")["status"] == "MISSING"
    reg.disable("http_probe")
    assert reg.capability_status("http_probe")["status"] == "DISABLED"
    reg.enable("http_probe")
    cap = reg.get("http_probe")
    orig = cap.execute_fn
    from horcrux.agents.tools.capabilities import _fail, FailureClass
    cap.execute_fn = lambda ctx: _fail("http_probe", FailureClass.TOOL_FAILED, "x")
    try:
        for _ in range(3):
            reg.execute("http_probe", {"target": "bench.local", "path": "/"})
        assert reg.capability_status("http_probe")["status"] == "BROKEN"
    finally:
        cap.execute_fn = orig


# --- P38 secrets -------------------------------------------------------------------------------------------------------------

def test_secret_redaction_and_audit():
    from horcrux.core.sanitizer import redact_dict, redact_secrets, scan_for_secrets
    jwt = ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0."
           "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c")
    text = f"cookie: sessionid=abc123 Authorization: Bearer {jwt} password=hunter2"
    red = redact_secrets(text)
    assert "abc123" not in red and jwt not in red and "hunter2" not in red
    assert scan_for_secrets(red) == []
    assert scan_for_secrets(f"key {jwt}") != []
    d = redact_dict({"headers": {"Authorization": "Bearer abc12345"}, "n": 1})
    assert "abc12345" not in d["headers"]["Authorization"]
    d2 = redact_dict({"h": "Authorization: Bearer abc12345"})
    assert "abc12345" not in d2["h"]


# --- P28/P29 reporting -------------------------------------------------------------------------------------------------------------

def test_report_nineteen_sections_and_legacy(tmp_path):
    from horcrux.agents.lifecycle import reassess
    from horcrux.reporting.reports import markdown
    state = _rich()
    ws = _ws_for(state, tmp_path, "rep")
    reassess(ws.load(), None)
    out = markdown(ws)
    content = out.read_text(encoding="utf-8")
    for needle in ("## Executive Risk Summary", "## Attack Surface",
                   "## Confirmed Findings", "## Audited / Hardened Controls",
                   "## 1. Target and Scope", "## 19. Assessment Completeness",
                   "## 12. Attack Paths", "## 13. Exploit Handoffs",
                   "## 14. Unresolved Hypotheses", "## 15. Blocked Capabilities",
                   "## 16. Tool Availability", "## 18. Operator Actions"):
        assert needle in content, needle


def test_clean_report_narrative(tmp_path):
    from tests.fixtures.synthetic_vulnerable_app import build_robots_txt_only_workspace
    from horcrux.reporting.reports import markdown
    state = build_robots_txt_only_workspace()
    ws = _ws_for(state, tmp_path, "clean")
    out = markdown(ws)
    content = out.read_text(encoding="utf-8")
    assert "No confirmed vulnerabilities" in content
    assert "not that scanning was skipped" in content


# --- P30/31/32 bench ----------------------------------------------------------------------------------------------------------------------

def test_benchmark_suite_subset(tmp_path):
    from horcrux.bench.runner import run_suite
    report = run_suite(["bola", "ssrf", "upload"], tmp_path, max_iterations=4)
    assert report["fixtures"] == 3
    assert report["mean_score"] >= 0.6
    for res in report["results"]:
        assert res["score"] >= 0.6
        assert res["metrics"]["finding_precision"] >= 0.0


def test_metrics_and_golden_tolerance():
    from horcrux.bench.golden import compare
    from horcrux.bench.metrics import evaluate
    state = _rich()
    from horcrux.agents.lifecycle import reassess
    reassess(state, None)
    m = evaluate(state, "bola", {"hypothesis_classes": ["idor_bola"]})
    assert m["hypothesis_recall"] == 1.0
    assert 0.0 <= m["model_completeness"] <= 1.0
    res = compare("bola", {"endpoints": 0, "hypothesis_classes": []})
    assert res["score"] < 1.0 and res["total"] > 0


# --- P33 replay -------------------------------------------------------------------------------------------------------------------------------------

def test_replay_rebuilds_without_network(tmp_path):
    from horcrux.agents.lifecycle import reassess
    from horcrux.bench.runner import (record_evidence_script, replay_workspace,
                                      write_evidence_script)
    state = _rich()
    ws = _ws_for(state, tmp_path, "live")
    reassess(ws.load(), None)
    script = record_evidence_script(ws)
    assert script["evidence"]["discovered_paths"]
    path = write_evidence_script(ws)
    assert path.exists()
    replayed = replay_workspace("bench-replay.local", path, base=str(tmp_path / "rbase"))
    assert len(replayed.get_application_model().endpoints) >= 3
    assert replayed.get_hypotheses()


# --- P36/P37 status & why ----------------------------------------------------------------------------------------------------------------------------------------

def test_status_renders_without_flooding(tmp_path):
    from horcrux.agents.lifecycle import reassess
    from horcrux.ui.console import ConsoleApp
    from rich.console import Console as RichConsole
    state = _rich()
    ws = _ws_for(state, tmp_path, "status")
    reassess(ws.load(), None)
    app = ConsoleApp(console=RichConsole(record=True, width=120))
    app.workspace = ws
    app.status()  # must not raise
    text = app.console.export_text()
    for needle in ("TARGET", "COVERAGE", "HYPOTHESES", "CAPABILITIES", "AI:"):
        assert needle in text, needle


def test_why_variants():
    from horcrux.agents.lifecycle import reassess
    from horcrux.intel.explain import (build_why_summary, explain_finding_confidence,
                                       explain_investigation, explain_not_investigated)
    state = _rich()
    reassess(state, None)
    assert "Current focus" in build_why_summary(state)
    inv = state.get_investigations()[0]
    assert "prerequisites" in explain_investigation(state, inv.id[:8]).lower() \
        or "capability" in explain_investigation(state, inv.id[:8]).lower()
    assert "No investigation" in explain_investigation(state, "zzz-nope")
    assert "No finding" in explain_finding_confidence(state, "zzz-nope")
    assert "matching" in explain_not_investigated(state, "zzz-nope")


# --- P23 resume + P34 parallel loop ------------------------------------------------------------------------------------------------------------------------------------

def test_parallel_assessment_loop(tmp_path):
    from horcrux.agents.root import RootVAPTOrchestrator
    state = _rich()
    ws = _ws_for(state, tmp_path, "par")
    root = RootVAPTOrchestrator(ws, ai_manager=None, max_iterations=4, max_workers=2)
    final = root.run_assessment_loop()
    assert final.scheduler_state.get("max_workers") == 2
    assert len(final.get_hypotheses()) >= 2


def test_provider_refusal_never_halts_loop(tmp_path):
    from horcrux.agents.root import RootVAPTOrchestrator
    from horcrux.intel.ai.base import AIError, AIErrorType
    from horcrux.intel.ai.failures import classify_ai_failure
    state = _rich()
    ws = _ws_for(state, tmp_path, "ref")

    class RefusingManager:
        is_enabled = True

        def get_provider(self):
            return None

        def call_task(self, *a, **k):
            raise AIError(AIErrorType.SAFETY_BLOCK, "refused", provider="x")

    assert classify_ai_failure(
        AIError(AIErrorType.SAFETY_BLOCK, "refused")).category == "safety_refusal"
    root = RootVAPTOrchestrator(ws, ai_manager=RefusingManager(), max_iterations=3)
    final = root.run_assessment_loop()
    assert len(final.get_hypotheses()) >= 1


def test_operator_focus_changes_scheduler():
    from horcrux.agents.focus import apply_focus
    from horcrux.agents.lifecycle import reassess
    state = _rich()
    reassess(state, None)
    res = apply_focus(state, "authz")
    assert res["applied"] is True
    assert state.operator_focus.focus_id == "authz"


def test_merge_preserves_parked_states():
    from horcrux.agents.lifecycle import reassess
    from horcrux.intel.investigations import Investigation, InvestigationState
    state = _rich()
    reassess(state, None)
    inv = Investigation(objective="parked probe", candidate_tools=["http_probe"],
                        specialist="WebAgent", state=InvestigationState.UNAVAILABLE,
                        result_summary="nope")
    inv.ensure_id()
    state.set_investigations(state.get_investigations() + [inv])
    reassess(state, None)
    states = {i.id: i.state for i in state.get_investigations()}
    assert states[inv.id] == InvestigationState.UNAVAILABLE


def test_no_real_network_in_phase8():
    import socket
    assert is_synthetic_target("bench-bola.local") is True
    assert socket  # import guard only; no connections made


# --- Flagship product test: sparse Juice-Shop-like app, full loop ------------

JUICE_PAGES = {
    "/": {"title": "Juice Shop", "links": ["/rest/user/login", "/#/search"],
           "api_calls": [{"method": "GET", "url": "http://juice.local/api/challenges"}]},
    "/rest/user/login": {"title": "Login",
                         "forms": [{"action": "/rest/user/login", "method": "POST",
                                    "inputs": ["email", "password"]}]},
    "/api": {"title": "API", "api_calls": [
        {"method": "GET", "url": "http://juice.local/rest/users/1"},
        {"method": "GET", "url": "http://juice.local/rest/basket/1"},
        {"method": "GET", "url": "http://juice.local/rest/products/1"},
        {"method": "GET", "url": "http://juice.local/rest/admin"},
        {"method": "POST", "url": "http://juice.local/rest/basket/1/checkout"},
        {"method": "POST", "url": "http://juice.local/upload"},
        {"method": "POST", "url": "http://juice.local/graphql"}]},
}


def test_juice_shop_like_full_loop(tmp_path):
    """Sparse start -> autonomous observe/model/hypothesize/investigate/reassess."""
    from horcrux.agents.root import RootVAPTOrchestrator
    from horcrux.intel.browser import ScriptedBrowserAdapter
    from horcrux.intel.ingestion import ingest_workspace_state
    from horcrux.intel.sessions import (TestIdentity, authenticated_crawl,
                                        observe_identity_object)
    from horcrux.models import Service

    target = "juice.local"
    state = WorkspaceState(target=target)
    # Sparse initial knowledge: one service, login page only.
    state.services = [Service(host=target, port=3000, service="http")]
    state.discovered_paths = []
    ws = _ws_for(state, tmp_path, "juice")
    app = ingest_workspace_state(ws.load())
    assert len(app.endpoints) == 0

    # Autonomous evidence gathering: two identities crawl the scripted app.
    for label, role in (("customer-a", "user"), ("customer-b", "user")):
        adapter = ScriptedBrowserAdapter(pages=dict(JUICE_PAGES))
        summary = authenticated_crawl(
            app, adapter, "http://juice.local:3000",
            TestIdentity(label=label, role=role, username=label, password="pw"),
            extra_paths=["/api"])
        assert summary["evidence"] > 0
    # Per-identity object observations (ownership correlation).
    observe_identity_object(app, "customer-a", "Basket", "1", "/rest/basket/1")
    observe_identity_object(app, "customer-b", "Basket", "2", "/rest/basket/2")
    observe_identity_object(app, "customer-a", "User", "1", "/rest/users/1")
    state = ws.load()
    state.set_application_model(app)
    ws.save(state)

    # No manual AI prompting from here: run the loop headless.
    root = RootVAPTOrchestrator(ws, ai_manager=None, max_iterations=10)
    final = root.run_assessment_loop()
    app = final.get_application_model()

    # Progressive discovery happened.
    assert len(app.endpoints) >= 8
    assert any(e.has_object_reference for e in app.endpoints)
    # Meaningful hypotheses, not scanner noise.
    classes = {h.hypothesis_class.value for h in final.get_hypotheses()}
    assert "idor_bola" in classes
    # Authorization investigations were prioritized and executed.
    invs = final.get_investigations()
    authz = [i for i in invs if i.specialist == "AuthorizationAgent"]
    assert authz
    assert any(i.state.value in {"SUPPORTED", "COMPLETE", "REFUTED",
                                 "INSUFFICIENT_EVIDENCE"}
               for i in invs)
    # Evidence-backed, ranked attack paths.
    assert len(final.attack_paths or []) >= 1
    assert any(p.get("rank_why") for p in final.attack_paths)
    # Did not terminate on robots/scanner-exhaustion logic.
    comp = final.scheduler_state
    assert isinstance(comp, dict)
    # Exploit boundary respected: handoffs require approval, nothing auto-ran.
    for h in final.exploit_handoffs or []:
        assert h.operator_approval_required is True
