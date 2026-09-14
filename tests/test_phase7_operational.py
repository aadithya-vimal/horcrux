"""Phase 7 operational tests — synthetic/local fixtures only, no real network."""

from __future__ import annotations

import pytest

from horcrux.agents.executor import (
    build_capability_inputs,
    execute_investigation_pipeline,
    resolve_capability,
    validate_prerequisites,
)
from horcrux.agents.focus import apply_focus, pause, prioritize, resume, skip
from horcrux.agents.roles import activate_roles
from horcrux.agents.root import RootVAPTOrchestrator
from horcrux.agents.tools.capabilities import CapabilityRegistry, is_synthetic_target
from horcrux.core.storage import Workspace
from horcrux.intel.ai.failures import classify_ai_failure
from horcrux.intel.application_model import ApplicationModel
from horcrux.intel.ask_engine import (
    answer_deterministically,
    build_structured_context,
    classify_ask_intent,
    plan_ask_actions,
    validate_and_apply_action,
    AskAction,
    AskActionType,
    AskIntent,
)
from horcrux.intel.browser_session import record_browser_navigation
from horcrux.intel.coverage import CoverageStatus, assessment_completeness
from horcrux.intel.explain import build_why_summary
from horcrux.intel.hypotheses import HypothesisClass, generate_hypotheses
from horcrux.intel.ingestion import (
    ingest_capability_evidence,
    ingest_http_request,
    ingest_service_enumeration,
    ingest_workspace_state,
)
from horcrux.intel.investigations import InvestigationState, generate_investigations
from horcrux.intel.reasoning import ReasoningResult, validate_reasoning_output
from horcrux.intel.service_semantics import (
    ingest_service_facts,
    ldap_to_facts,
    smb_to_facts,
)
from horcrux.models import (
    DiscoveredPath,
    NormalizedTechnology,
    Parameter,
    Service,
    TechCategory,
    WebApplicationType,
    WebTarget,
    WorkspaceState,
)
from tests.fixtures.synthetic_vulnerable_app import build_synthetic_workspace


def _rich_state() -> WorkspaceState:
    """SPA + APIs + object IDs + privileged + workflows + upload + GraphQL + services."""
    state = build_synthetic_workspace()
    t = state.target
    # File upload + GraphQL + workflow surfaces.
    state.discovered_paths.extend([
        DiscoveredPath(url=f"http://{t}:3000/upload", path="/upload",
                       status=200, source="javascript", validated=True),
        DiscoveredPath(url=f"http://{t}:3000/graphql", path="/graphql",
                       status=200, source="javascript", validated=True),
        DiscoveredPath(url=f"http://{t}:3000/rest/basket/1/checkout",
                       path="/rest/basket/1/checkout", status=200,
                       source="javascript", validated=True),
    ])
    state.parameters.extend([
        Parameter(name="file", location="body", source="form", endpoint="/upload"),
        Parameter(name="query", location="body", source="javascript", endpoint="/graphql"),
        Parameter(name="url", location="query", source="url", endpoint="/api/feedbacks"),
    ])
    state.services.extend([
        Service(host=t, port=445, service="smb", product="Samba", version="4.15"),
        Service(host=t, port=22, service="ssh", product="OpenSSH", version="8.9"),
    ])
    return state


def _ws_for(state: WorkspaceState, tmp_path, name: str = "ws"):
    ws = Workspace(state.target)
    ws.root = tmp_path / name
    ws.raw = ws.root / "raw"
    ws.responses = ws.root / "responses"
    ws.headers = ws.root / "headers"
    ws.reports = ws.root / "reports"
    ws.state_file = ws.root / "state.json"
    for d in (ws.root, ws.raw, ws.responses, ws.headers, ws.reports):
        d.mkdir(parents=True, exist_ok=True)
    ws.save(state)
    return ws


# 1-8: rich semantic surfaces -------------------------------------------------

def test_01_spa_multiple_apis_in_model():
    app = ingest_workspace_state(_rich_state())
    assert app.profile.app_type == "SPA"
    assert len(app.endpoints) >= 8


def test_02_identities_anonymous_and_authenticated():
    state = _rich_state()
    state.credentials = []
    app = ingest_workspace_state(state)
    roles = {i.role.value for i in app.identities}
    assert "anonymous" in roles


def test_03_object_ids_drive_bola_hypothesis():
    app = ingest_workspace_state(_rich_state())
    hyps = generate_hypotheses(app)
    assert any(h.hypothesis_class == HypothesisClass.IDOR_BOLA for h in hyps)


def test_04_privileged_endpoints_drive_escalation_hypothesis():
    app = ingest_workspace_state(_rich_state())
    hyps = generate_hypotheses(app)
    assert any(h.hypothesis_class == HypothesisClass.PRIVILEGE_ESCALATION for h in hyps)


def test_05_workflows_present():
    app = ingest_workspace_state(_rich_state())
    assert len(app.workflows) >= 1  # authentication flow


def test_06_file_upload_surface():
    app = ingest_workspace_state(_rich_state())
    # Upload form evidence via browser session layer converges into same model.
    record_browser_navigation({"url": f"http://{app.target}/upload",
                               "forms": [{"action": "/upload", "method": "POST",
                                          "inputs": ["file"]}],
                               "application_model": app})
    hyps = generate_hypotheses(app)
    assert any(h.hypothesis_class == HypothesisClass.FILE_UPLOAD for h in hyps)


def test_07_graphql_surface():
    app = ingest_workspace_state(_rich_state())
    hyps = generate_hypotheses(app)
    assert any(h.hypothesis_class == HypothesisClass.GRAPHQL for h in hyps)


def test_08_service_enumeration_semantics():
    state = _rich_state()
    app = ingest_workspace_state(state)
    n = ingest_service_enumeration(app, "smb", "Sharename Disk READ IPC$ Disk", host=state.target, port=445)
    assert n >= 1
    facts = smb_to_facts("Sharename Disk READ\n signing:False", host=state.target)
    assert any(f["fact_type"] == "service_resource" for f in facts)
    ldap_facts = ldap_to_facts("defaultNamingContext: DC=corp,DC=local", host=state.target)
    assert any(f["fact_type"] == "directory_fact" for f in ldap_facts)
    assert ingest_service_facts(app, facts) >= 1


# 9: contradictory evidence ----------------------------------------------------

def test_09_contradictory_evidence_recorded():
    state = _rich_state()
    app = ingest_workspace_state(state)
    ingest_http_request(app, "GET", "/rest/basket/1", identity="anonymous", source="proxy")
    ingest_http_request(app, "GET", "/rest/basket/1", identity="user", source="proxy")
    from horcrux.intel.reasoning import _deterministic_structured
    from horcrux.intel.reasoning import ReasoningCheckpoint
    state.set_application_model(app)
    structured = _deterministic_structured(state, ReasoningCheckpoint.AFTER_INVESTIGATION)
    assert isinstance(structured, ReasoningResult)
    assert any("anonymous" in c for c in structured.contradictions)


# 10-11: tool failure / missing capability -------------------------------------

def test_10_tool_failure_marks_failed_not_complete(tmp_path):
    state = _rich_state()
    ingest_workspace_state(state)
    from horcrux.intel.hypotheses import update_hypotheses_from_state
    state.set_hypotheses(update_hypotheses_from_state(state))
    invs = generate_investigations(state.get_application_model(), state.get_hypotheses())
    inv = next(i for i in invs if i.candidate_tools)
    reg = CapabilityRegistry(state=state)  # no workspace/runner: offline synthesis
    # Force a failing adapter.
    cap = reg.get(inv.candidate_tools[0])
    assert cap is not None
    orig = cap.execute_fn
    cap.execute_fn = lambda ctx: __import__("horcrux.agents.tools.capabilities", fromlist=["_fail"]). _fail(
        cap.capability_id,
        __import__("horcrux.agents.tools.capabilities", fromlist=["FailureClass"]).FailureClass.TOOL_FAILED,
        "boom")
    try:
        out = execute_investigation_pipeline(state, inv, reg)
    finally:
        cap.execute_fn = orig
    assert inv.state == InvestigationState.FAILED
    assert out["success"] is False


def test_11_missing_capability_marks_unavailable():
    state = _rich_state()
    ingest_workspace_state(state)
    from horcrux.intel.investigations import Investigation
    inv = Investigation(objective="Impossible probe", candidate_tools=["no_such_cap"],
                        specialist="WebAgent", state=InvestigationState.READY)
    inv.ensure_id()
    reg = CapabilityRegistry(state=state)
    out = execute_investigation_pipeline(state, inv, reg)
    assert inv.state == InvestigationState.UNAVAILABLE
    assert out["outcome"] == "capability_unavailable"


# 12-13: AI unavailable / refusal ----------------------------------------------

def test_12_ai_unavailable_loop_continues(tmp_path):
    state = _rich_state()
    ws = _ws_for(state, tmp_path, "ai_off")
    root = RootVAPTOrchestrator(ws, ai_manager=None, max_iterations=4)
    final = root.run_assessment_loop()
    assert len(final.get_hypotheses()) >= 2
    assert len(final.get_investigations()) >= 1


def test_13_ai_refusal_classified_no_retry_no_crash():
    err = Exception("Content blocked by safety filter: disallowed")
    failure = classify_ai_failure(err)
    assert failure.category == "safety_refusal"
    assert failure.retryable is False
    assert "evidence" in failure.reframed_task.lower()
    # Malformed output is also classified, never raised.
    validated = validate_reasoning_output({"observations": ["a"], "confidence": 0.6})
    assert isinstance(validated, ReasoningResult)


# 14-16: ask actions + operator controls ----------------------------------------

def test_14_ask_triggers_investigation(tmp_path):
    state = _rich_state()
    ingest_workspace_state(state)
    from horcrux.intel.hypotheses import update_hypotheses_from_state
    state.set_hypotheses(update_hypotheses_from_state(state))
    before = len(state.get_investigations())
    actions = plan_ask_actions(state, "Investigate authorization on the order APIs.")
    assert actions and actions[0].action == AskActionType.CREATE_INVESTIGATION
    res = validate_and_apply_action(state, actions[0])
    assert res["applied"] is True
    assert len(state.get_investigations()) >= before


def test_15_operator_pause_resume():
    state = _rich_state()
    assert pause(state)["applied"] is True
    assert state.operator_focus.paused is True
    from horcrux.agents.lifecycle import assessment_has_actionable_work
    ingest_workspace_state(state)
    assert assessment_has_actionable_work(state) is False
    assert resume(state)["applied"] is True
    assert state.operator_focus.paused is False


def test_16_investigation_prioritization_and_skip():
    state = _rich_state()
    ingest_workspace_state(state)
    from horcrux.intel.hypotheses import update_hypotheses_from_state
    state.set_hypotheses(update_hypotheses_from_state(state))
    from horcrux.intel.coverage import calculate_coverage
    app = state.get_application_model()
    cov = calculate_coverage(app, state.get_hypotheses(), [], state.get_security_coverage())
    from horcrux.intel.investigations import rank_investigations
    invs = rank_investigations(generate_investigations(app, state.get_hypotheses()))
    state.set_investigations(invs)
    target = invs[0]
    assert prioritize(state, target.id[:8])["applied"] is True
    assert state.operator_focus.prioritize_investigation_id == target.id
    assert skip(state, target.id[:8])["applied"] is True
    assert target.id in state.operator_focus.skip_investigation_ids


# Cross-cutting pipeline assertions ---------------------------------------------

def test_capability_registry_binds_existing_modules():
    reg = CapabilityRegistry()
    ids = {c.capability_id for c in reg.list()}
    for expected in ("http_probe", "js_analyze", "content_discovery",
                     "endpoint_validate", "nuclei_scan", "nikto_audit",
                     "graphql_probe", "smb_enum", "ldap_enum", "ssh_enum",
                     "searchsploit_intel", "browser_navigate", "web_fingerprint"):
        assert expected in ids
    cap = reg.get("http_probe")
    assert cap.provenance and cap.timeout > 0 and cap.safety.value in {
        "safe", "low", "medium", "high", "forbidden"}
    assert cap.required_inputs and cap.produced_evidence_types


def test_investigation_pipeline_end_to_end(tmp_path):
    state = _rich_state()
    ingest_workspace_state(state)
    from horcrux.intel.hypotheses import update_hypotheses_from_state
    state.set_hypotheses(update_hypotheses_from_state(state))
    app = state.get_application_model()
    invs = generate_investigations(app, state.get_hypotheses())
    inv = next(i for i in invs if "object IDs" in i.objective)
    reg = CapabilityRegistry(state=state)
    assert resolve_capability(inv, reg) is not None
    ok, _ = validate_prerequisites(state, inv)
    assert ok is True
    inputs = build_capability_inputs(state, inv, "authz_compare")
    assert inputs["target"] == state.target and inputs["path"]
    out = execute_investigation_pipeline(state, inv, reg)
    assert inv.state in (InvestigationState.SUPPORTED, InvestigationState.COMPLETE,
                         InvestigationState.REFUTED, InvestigationState.INSUFFICIENT_EVIDENCE)
    assert inv.state != InvestigationState.RUNNING
    assert out.get("reassess_required") is True


def test_evidence_ingestion_updates_model_and_coverage():
    state = _rich_state()
    app = ingest_workspace_state(state)
    before = len(app.endpoints)
    n = ingest_capability_evidence(app, "http_probe", [
        {"evidence_type": "endpoint_observation",
         "data": {"method": "GET", "path": "/api/orders/1", "identity": "user"},
         "source": "http_probe", "confidence": 0.9}])
    assert n >= 1
    assert len(app.endpoints) >= before
    ep = next(e for e in app.endpoints if e.path == "/api/orders/1")
    assert "http_probe" in ep.sources  # provenance retained


def test_ask_reasons_from_workspace_state():
    state = _rich_state()
    ingest_workspace_state(state)
    from horcrux.intel.hypotheses import update_hypotheses_from_state
    state.set_hypotheses(update_hypotheses_from_state(state))
    assert classify_ask_intent("What have you not tested yet?") == AskIntent.COVERAGE_GAP
    ctx = build_structured_context(state, "What have you not tested yet?")
    assert "coverage" in ctx and "investigations" in ctx
    answer = answer_deterministically(state, "What have you not tested yet?")
    assert "coverage" in answer.lower() or "tested" in answer.lower()
    # Structured actions only, validated by orchestrator.
    acts = plan_ask_actions(state, "Stop.")
    assert acts[0].action == AskActionType.PAUSE_ASSESSMENT
    assert validate_and_apply_action(state, acts[0])["applied"] is True


def test_reasoning_result_schema_validation():
    r = validate_reasoning_output({
        "observations": ["17 object routes"], "unknowns": ["cross-user access"],
        "hypotheses": [], "evidence_requests": [],
        "recommended_investigations": [{"objective": "compare access"}],
        "deprioritized_investigations": [], "confidence": 0.7,
        "rationale": "gap", "coverage_gaps": ["authorization"],
        "contradictions": [], "assumptions": ["ids controllable"]})
    assert r.confidence == 0.7 and r.coverage_gaps == ["authorization"]
    with pytest.raises(Exception):
        validate_reasoning_output({"confidence": 9.0})


def test_roles_activate_from_evidence_not_randomly():
    state = _rich_state()
    ingest_workspace_state(state)
    roles = activate_roles(state)
    ids = {r.role_id for r in roles}
    assert "AuthorizationAnalyst" in ids  # object IDs present
    assert "APIAnalyst" in ids  # /api + /graphql present
    assert "AuthenticationAnalyst" in ids  # login surfaces present


def test_low_value_findings_do_not_dominate():
    state = _rich_state()
    ingest_workspace_state(state)
    from horcrux.intel.hypotheses import update_hypotheses_from_state
    state.set_hypotheses(update_hypotheses_from_state(state))
    from horcrux.intel.investigations import Investigation, rank_investigations
    low = Investigation(objective="Check robots.txt exists", candidate_tools=["http_probe"],
                        specialist="WebAgent", state=InvestigationState.READY)
    low.ensure_id()
    high = Investigation(objective="Determine whether object IDs are authorization-bound",
                         candidate_tools=["http_probe"], vulnerability_classes=["idor_bola"],
                         specialist="AuthorizationAgent", state=InvestigationState.READY)
    high.ensure_id()
    ranked = rank_investigations([low, high])
    assert ranked[0].id == high.id


def test_completion_not_findings_zero(tmp_path):
    from tests.fixtures.synthetic_vulnerable_app import build_robots_txt_only_workspace
    state = build_robots_txt_only_workspace()
    ws = _ws_for(state, tmp_path, "robots")
    root = RootVAPTOrchestrator(ws, ai_manager=None, max_iterations=3)
    final = root.run_assessment_loop()
    comp = assessment_completeness(final)
    assert comp["sufficient"] is False  # robots-only never sufficient
    report = root.completion_report(final)
    assert "coverage" in report and "blocked_investigations" in report


def test_browser_evidence_converges_to_same_model():
    app = ApplicationModel(target="synthetic.local")
    out = record_browser_navigation({
        "url": "http://synthetic.local/app",
        "network_requests": [{"method": "GET", "path": "/api/orders/1"}],
        "cookies": ["session=abc"], "identity": "user",
        "application_model": app})
    assert out["requests_recorded"] >= 1
    assert any(e.path == "/api/orders/1" for e in app.endpoints)
    assert any(i.label == "user" for i in app.identities)


def test_why_summary_explains_state():
    state = _rich_state()
    ingest_workspace_state(state)
    text = build_why_summary(state)
    assert "Current focus" in text and "Next investigation" in text and "Reason" in text


def test_exploit_handoff_boundary(tmp_path):
    state = _rich_state()
    ws = _ws_for(state, tmp_path, "handoff")
    root = RootVAPTOrchestrator(ws, ai_manager=None, max_iterations=4)
    final = root.run_assessment_loop()
    for h in final.exploit_handoffs:
        assert h.operator_approval_required is True
        assert h.recommended_operator_action
        assert h.why_manual_approval_required


def test_focus_affects_scheduler():
    state = _rich_state()
    ingest_workspace_state(state)
    from horcrux.intel.hypotheses import update_hypotheses_from_state
    state.set_hypotheses(update_hypotheses_from_state(state))
    from horcrux.intel.investigations import rank_investigations
    state.set_investigations(rank_investigations(
        generate_investigations(state.get_application_model(), state.get_hypotheses())))
    res = apply_focus(state, "authz")
    assert res["applied"] is True
    assert state.operator_focus.focus_id == "authz"


def test_synthetic_targets_never_hit_network():
    assert is_synthetic_target("synthetic-vuln-app.local") is True
    assert is_synthetic_target("10.10.10.5") is False
    reg = CapabilityRegistry(state=WorkspaceState(target="synthetic-vuln-app.local"))
    out = reg.execute("http_probe", {"target": "synthetic-vuln-app.local",
                                     "path": "/rest/basket/1"})
    assert out.success is True
    assert out.structured_data.get("synthetic") is True
