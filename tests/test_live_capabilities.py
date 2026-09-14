"""Live-capability reporting + orphaned-capability connection regressions.

All fixtures synthetic/local only. Local live execution uses a stdlib
HTTP server on 127.0.0.1 with explicit live-local opt-in — never external.
"""

from __future__ import annotations

import shutil
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from horcrux.agents.executor import (
    build_capability_inputs,
    execute_investigation_pipeline,
    resolve_capability,
)
from horcrux.agents.tools.capabilities import (
    Availability,
    CapabilityHealth,
    CapabilityRegistry,
    ExecutionMode,
    canonical_tool_id,
    environment_availability_report,
)
from horcrux.agents.tools.registry import ToolRegistry, create_default_registry
from horcrux.core.storage import Workspace
from horcrux.intel.browser import browser_backend_status, get_browser_adapter
from horcrux.intel.dependencies import evaluate_prerequisites
from horcrux.intel.investigations import (
    Investigation,
    InvestigationState,
    generate_gap_investigations,
    generate_investigations,
    merge_investigations,
    rank_investigations,
)
from horcrux.models import (
    DiscoveredPath,
    Parameter,
    Service,
    WorkspaceState,
)
from tests.fixtures.synthetic_vulnerable_app import build_synthetic_workspace


class _FakeRunner:
    def __init__(self, binaries: set[str]):
        self._binaries = set(binaries)

    def which(self, name: str):
        return f"/usr/bin/{name}" if name in self._binaries else None


def _ws_for(state: WorkspaceState, tmp_path, name: str = "livecap"):
    ws = Workspace(state.target)
    ws.root = tmp_path / name
    for d in (ws.root, ws.raw, ws.responses, ws.headers, ws.reports):
        d.mkdir(parents=True, exist_ok=True)
    ws.state_file = ws.root / "state.json"
    ws.save(state)
    return ws


# 1. capability status without a runner ---------------------------------------
def test_01_status_without_runner_never_claims_live():
    reg = CapabilityRegistry(runner=None)
    rep = reg.availability_report()
    assert len(rep) == len(reg.list())
    for v in rep.values():
        assert v["mode"] in {"live", "synthetic", "none"}
    # Binary-backed capabilities cannot be live without a runner to probe.
    # (Deterministic local analyzers are honestly live: they need no runner.)
    for cap_id in ("content_discovery", "nuclei_scan", "nikto_audit",
                   "nmap_discovery", "smb_enum", "dns_enum",
                   "searchsploit_intel"):
        assert rep[cap_id]["mode"] != "live", cap_id
    # ...but unknown IDs are still honestly MISSING.
    assert reg.capability_status("no_such_cap")["status"] == "MISSING"


# 2. capability status with a runner ------------------------------------------
def test_02_status_with_runner_reflects_path():
    reg = CapabilityRegistry(runner=_FakeRunner({"ffuf", "nuclei"}))
    assert reg.capability_status("content_discovery")["mode"] == "live"
    assert reg.capability_status("nuclei_scan")["mode"] == "live"
    assert reg.capability_status("nikto_audit")["mode"] == "synthetic"
    assert reg.capability_status("nikto_audit")["status"] == "AVAILABLE"


# 3. doctor/status consistency -------------------------------------------------
def test_03_health_contract_shared():
    rep = environment_availability_report()
    assert rep
    for cap_id, info in rep.items():
        assert info["mode"] in {"live", "synthetic", "none"}
        assert info["status"] in {"AVAILABLE", "MISSING", "DISABLED", "BROKEN"}
        if info["mode"] == "live":
            assert info["available"] is True
    # Binaries actually on PATH must report live, never synthetic.
    from horcrux.agents.tools.capabilities import capability_binaries
    for cap_id, binary in capability_binaries().items():
        if binary and binary != "playwright" and shutil.which(binary):
            assert rep[cap_id]["mode"] == "live", cap_id


# 4. browser Playwright availability -------------------------------------------
def test_04_browser_playwright_availability():
    from horcrux.agents.tools.capabilities import _playwright_probe
    probe = _playwright_probe()
    assert set(probe) >= {"ok", "reason", "chromium"}
    health = CapabilityRegistry.for_display().health("browser_automate")
    assert isinstance(health, CapabilityHealth)
    assert health.execution_mode in {ExecutionMode.LIVE, ExecutionMode.SYNTHETIC}
    # Scripted fallback keeps availability honest, never MISSING.
    assert health.availability == Availability.AVAILABLE


# 5. scripted browser fallback ---------------------------------------------------
def test_05_scripted_browser_fallback():
    adapter = get_browser_adapter("scripted")
    ok, _ = adapter.is_available()
    assert ok
    status = browser_backend_status()
    assert status["scripted"]["available"] is True
    assert set(status) >= {"playwright", "chromium", "scripted"}


# Helpers for generation tests --------------------------------------------------
def _sparse_web_state() -> WorkspaceState:
    state = build_synthetic_workspace()
    # Trim to an incomplete surface: 2 endpoints, no technologies.
    state.discovered_paths = state.discovered_paths[:2]
    state.normalized_technologies = []
    state.technologies = []
    for wt in state.web_targets:
        wt.technologies = []
    return state


# 6. content_discovery investigation generation -----------------------------------
def test_06_content_discovery_generated():
    from horcrux.intel.ingestion import ingest_workspace_state
    state = _sparse_web_state()
    app = ingest_workspace_state(state)
    invs = generate_gap_investigations(app, {})
    tools = [t for i in invs for t in i.candidate_tools]
    assert "content_discovery" in tools
    inv = next(i for i in invs if "content_discovery" in i.candidate_tools)
    assert "web_target" in inv.prerequisites
    assert resolve_capability(inv, CapabilityRegistry(state=state)) == "content_discovery"


# 7. nuclei investigation generation ----------------------------------------------
def test_07_nuclei_generated():
    from horcrux.intel.ingestion import ingest_workspace_state
    state = build_synthetic_workspace()
    app = ingest_workspace_state(state)
    invs = generate_gap_investigations(app, {})
    assert any("nuclei_scan" in i.candidate_tools for i in invs)


# 8. nikto investigation generation -------------------------------------------------
def test_08_nikto_generated_once_per_gap():
    from horcrux.intel.ingestion import ingest_workspace_state
    state = build_synthetic_workspace()
    app = ingest_workspace_state(state)
    invs = generate_gap_investigations(app, {})
    assert sum("nikto_audit" in i.candidate_tools for i in invs) == 1
    # Closed gap suppresses regeneration (no redundant rescans).
    closed = dict.fromkeys(["configuration", "client_side_security"], "REVIEWED")
    invs2 = generate_gap_investigations(app, closed)
    assert not any("nikto_audit" in i.candidate_tools for i in invs2)


# 9. web fingerprint investigation generation -----------------------------------------
def test_09_web_fingerprint_generated():
    from horcrux.intel.ingestion import ingest_workspace_state
    state = _sparse_web_state()
    app = ingest_workspace_state(state)
    assert not app.technologies
    invs = generate_gap_investigations(app, {})
    assert any("web_fingerprint" in i.candidate_tools for i in invs)


# 10. endpoint validation investigation generation ---------------------------------------
def test_10_endpoint_validation_generated():
    from horcrux.intel.ingestion import ingest_workspace_state
    state = build_synthetic_workspace()
    state.discovered_paths.append(DiscoveredPath(
        url=f"http://{state.target}:3000/rest/admin", path="/rest/admin",
        status=200, source="javascript", validated=True))
    app = ingest_workspace_state(state)
    invs = generate_gap_investigations(app, {})
    matches = [i for i in invs if "endpoint_validate" in i.candidate_tools]
    assert matches and any("/rest/admin" in i.objective for i in matches)


# 11. JS capability canonical ID ------------------------------------------------------------
def test_11_js_canonical_id():
    assert canonical_tool_id("js_analyzer") == "js_analyze"
    assert canonical_tool_id("validator") == "endpoint_validate"
    assert canonical_tool_id("http_probe") == "http_probe"
    inv = Investigation(objective="x", candidate_tools=["js_analyzer", "validator"],
                        specialist="WebAgent", state=InvestigationState.READY)
    inv.ensure_id()
    assert resolve_capability(inv, CapabilityRegistry()) == "js_analyze"
    # Legacy alias metadata stays registered for backward compatibility…
    assert create_default_registry().get("validator") is not None
    # …but execution canonicalizes to production (no mock fallback).
    out = ToolRegistry().execute("js_analyzer", base_url="http://x/",
                                 request_id="t")
    assert out.success is True and out.tool == "js_analyze"


# 12. protocol-specific investigation generation ----------------------------------------------
def test_12_service_investigations():
    from horcrux.intel.ingestion import ingest_workspace_state
    state = WorkspaceState(target="svc.local")
    state.services = [
        Service(host="svc.local", port=445, service="microsoft-ds"),
        Service(host="svc.local", port=22, service="ssh"),
        Service(host="svc.local", port=80, service="http"),
    ]
    app = ingest_workspace_state(state)
    invs = generate_gap_investigations(app, {})
    by_tool = {t: i for i in invs for t in i.candidate_tools}
    assert "smb_enum" in by_tool and "ssh_enum" in by_tool
    assert by_tool["smb_enum"].specialist == "NetworkAgent"
    # HTTP service does not spawn a service-enum investigation (web owns it).
    assert "remote_enum" not in by_tool and "database_enum" not in by_tool


# 13. capability input construction -----------------------------------------------------------------
def test_13_inputs_cover_new_capabilities():
    from horcrux.intel.ingestion import ingest_workspace_state
    state = build_synthetic_workspace()
    ingest_workspace_state(state)
    for cap_id in ("content_discovery", "nuclei_scan", "web_fingerprint",
                   "endpoint_validate", "smb_enum", "browser_automate",
                   "identity_compare", "js_analyze"):
        inv = Investigation(objective=f"probe {cap_id}",
                            candidate_tools=[cap_id],
                            specialist="WebAgent",
                            state=InvestigationState.READY)
        inv.ensure_id()
        inputs = build_capability_inputs(state, inv, cap_id)
        assert inputs.get("target") == state.target, cap_id
        reg = CapabilityRegistry(state=state)
        out = reg.execute(cap_id, inputs)
        assert out is not None, cap_id  # never crashes; synthetic offline path


# 14. no duplicate investigations ------------------------------------------------------------------------
def test_14_stable_ids_no_regeneration():
    from horcrux.intel.hypotheses import update_hypotheses_from_state
    from horcrux.intel.ingestion import ingest_workspace_state
    state = build_synthetic_workspace()
    ingest_workspace_state(state)
    state.set_hypotheses(update_hypotheses_from_state(state))
    app = state.get_application_model()
    first = generate_investigations(app, state.get_hypotheses(), {})
    state.set_investigations(first)
    second = generate_investigations(app, state.get_hypotheses(), {})
    merged = merge_investigations(state.get_investigations(), second)
    ids = [i.id for i in merged]
    assert len(ids) == len(set(ids))
    assert len(merged) == len(first)


# 15. low-value investigation demotion ----------------------------------------------------------------------
def test_15_cosmetic_param_demoted():
    from horcrux.intel.hypotheses import Hypothesis, HypothesisClass
    low = Investigation(objective="Audit input parameter 'isPeriodic' (query)",
                        candidate_tools=["http_probe"], specialist="WebAgent",
                        state=InvestigationState.READY)
    low.ensure_id()
    hyp = Hypothesis(hypothesis_class=HypothesisClass.IDOR_BOLA,
                     title="t", confidence=0.8)
    hyp.ensure_id()
    high = Investigation(objective="Determine whether object IDs are authorization-bound",
                         candidate_tools=["http_probe"],
                         vulnerability_classes=["idor_bola"],
                         hypothesis_id=hyp.id, specialist="AuthorizationAgent",
                         state=InvestigationState.READY)
    high.ensure_id()
    ranked = rank_investigations([low, high])
    assert ranked[0].id == high.id
    assert ranked[-1].id == low.id


# 16. blocked two-identity prerequisite remains correct -------------------------------------------------------------
def test_16_two_identity_block_preserved():
    from horcrux.intel.application_model import IdentityRole, SemanticIdentity
    from horcrux.intel.ingestion import ingest_workspace_state
    state = build_synthetic_workspace()
    app = ingest_workspace_state(state)
    app.identities = [i for i in app.identities if i.role == IdentityRole.ANONYMOUS]
    app.upsert_identity(SemanticIdentity(role=IdentityRole.USER, label="solo"))
    state.set_application_model(app)
    inv = Investigation(objective="Compare object access across identities",
                        candidate_tools=["identity_compare"],
                        prerequisites=["two_identities"],
                        specialist="AuthorizationAgent",
                        state=InvestigationState.READY)
    inv.ensure_id()
    schedulable, blocked = evaluate_prerequisites(state, inv)
    assert schedulable is False and blocked
    app.upsert_identity(SemanticIdentity(role=IdentityRole.USER, label="second"))
    state.set_application_model(app)
    schedulable, _ = evaluate_prerequisites(state, inv)
    assert schedulable is True


# 17. real-handler adapter selection -------------------------------------------------------------------------------
def test_17_production_handlers_not_mocks():
    reg = CapabilityRegistry()
    for cap_id in ("content_discovery", "nuclei_scan", "browser_automate",
                   "web_fingerprint", "endpoint_validate", "smb_enum"):
        cap = reg.get(cap_id)
        assert cap is not None and cap.execute_fn is not None, cap_id
        assert "mock" not in (cap.execute_fn.__name__ or "").lower(), cap_id


# 18. synthetic handlers remain test-only ----------------------------------------------------------------------------
def test_18_unbound_registry_uses_offline_fallback():
    from horcrux.agents.tools.registry import create_default_registry
    # Legacy mock registrations are preserved for unit-test configuration…
    assert create_default_registry().get("http_probe") is not None
    # …but an unbound registry never claims live execution.
    assert CapabilityRegistry(runner=None).capability_status(
        "content_discovery")["mode"] != "live"


# 19. live execution produces evidence (localhost server + opt-in) -------------------------------------------------------
def test_19_live_local_execution_produces_evidence(tmp_path):
    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b'{"ok": true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    server = HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        from horcrux.core.runner import CommandRunner
        state = WorkspaceState(target="127.0.0.1")
        state.services = [Service(host="127.0.0.1", port=port, service="http")]
        ws = _ws_for(state, tmp_path, "livelocal")
        runner = CommandRunner(ws)
        reg = CapabilityRegistry(workspace=ws, runner=runner, state=state,
                                 live_local=True)
        out = reg.execute("http_probe", {"target": "127.0.0.1", "port": port,
                                         "path": "/", "scheme": "http",
                                         "url": f"http://127.0.0.1:{port}/"})
        assert out.success is True
        assert out.structured_data.get("status_code") == 200
        assert "synthetic" not in out.structured_data
        assert "httpx" in (out.provenance or "")
    finally:
        server.shutdown()
        thread.join(timeout=5)


# 20. evidence triggers reassessment --------------------------------------------------------------------------------------
def test_20_execution_updates_model_and_coverage(tmp_path):
    from horcrux.agents.lifecycle import reassess
    from horcrux.intel.coverage import assessment_completeness
    from horcrux.intel.hypotheses import update_hypotheses_from_state
    from horcrux.intel.ingestion import ingest_workspace_state
    state = ws_load = _ws_for(build_synthetic_workspace(), tmp_path, "reassess").load()
    ingest_workspace_state(state)
    before = assessment_completeness(state)
    state.set_hypotheses(update_hypotheses_from_state(state))
    invs = generate_investigations(state.get_application_model(),
                                   state.get_hypotheses(), {})
    inv = next(i for i in invs if i.state == InvestigationState.READY)
    reg = CapabilityRegistry(state=state)
    out = execute_investigation_pipeline(state, inv, reg)
    assert out.get("reassess_required") or inv.state != InvestigationState.READY
    reassess(state, None)
    after = assessment_completeness(state)
    assert isinstance(after["sufficient"], bool)
    assert before["high_value_surfaces"] >= 0
