"""Tests for agentic VAPT engine — evidence → model → hypothesis → investigation → finding."""

from __future__ import annotations

from horcrux.agents.coordinator import on_recon_complete, run_full_assessment
from horcrux.agents.root import RootVAPTOrchestrator
from horcrux.core.actions import compute_investigation_actions
from horcrux.core.storage import Workspace
from horcrux.intel.application_model import ApplicationModel
from horcrux.intel.coverage import assessment_completeness, CoverageStatus
from horcrux.intel.hypotheses import HypothesisClass, generate_hypotheses
from horcrux.intel.ingestion import ingest_workspace_state
from horcrux.intel.investigations import generate_investigations, rank_investigations
from horcrux.intel.reasoning import build_semantic_context
from horcrux.models import AssessmentPhase
from tests.fixtures.synthetic_vulnerable_app import (
    build_robots_txt_only_workspace,
    build_synthetic_workspace,
)


def test_ingestion_builds_application_model():
    state = build_synthetic_workspace()
    app = ingest_workspace_state(state)

    assert app.profile.app_type == "SPA" or app.profile.framework == "Angular"
    assert len(app.endpoints) >= 8
    assert len(app.authentication) >= 1
    assert any(e.path.endswith("/rest/admin") or "admin" in e.path for e in app.endpoints)
    assert any(o.name in {"User", "Basket", "Product"} for o in app.object_types)


def test_hypothesis_generation_from_semantics():
    state = build_synthetic_workspace()
    app = ingest_workspace_state(state)
    hypotheses = generate_hypotheses(app)

    classes = {h.hypothesis_class for h in hypotheses}
    assert HypothesisClass.IDOR_BOLA in classes
    assert HypothesisClass.PRIVILEGE_ESCALATION in classes
    assert HypothesisClass.AUTHENTICATION in classes


def test_investigations_generated_from_hypotheses():
    state = build_synthetic_workspace()
    app = ingest_workspace_state(state)
    hypotheses = generate_hypotheses(app)
    investigations = generate_investigations(app, hypotheses)

    assert len(investigations) >= 3
    specialists = {i.specialist for i in investigations}
    assert "AuthorizationAgent" in specialists
    assert "AuthenticationAgent" in specialists

    ranked = rank_investigations(investigations)
    assert ranked[0].priority >= ranked[-1].priority


def test_semantic_context_not_raw_scanner_output():
    state = build_synthetic_workspace()
    ingest_workspace_state(state)
    state.set_hypotheses(generate_hypotheses(state.get_application_model()))

    context = build_semantic_context(state)
    assert "APPLICATION" in context or "application" in context.lower()
    assert "4721" not in context  # no raw ffuf dump
    assert len(context) < 15000


def test_full_pipeline_synthetic_fixture(tmp_path):
    state = build_synthetic_workspace()
    ws = Workspace(state.target)
    ws.root = tmp_path / "workspace"
    ws.raw = ws.root / "raw"
    ws.responses = ws.root / "responses"
    ws.headers = ws.root / "headers"
    ws.reports = ws.root / "reports"
    ws.state_file = ws.root / "state.json"
    for d in (ws.root, ws.raw, ws.responses, ws.headers, ws.reports):
        d.mkdir(parents=True, exist_ok=True)
    ws.save(state)

    on_recon_complete(ws)
    run_full_assessment(ws, max_iterations=5)

    final = ws.load()
    app = final.get_application_model()
    hypotheses = final.get_hypotheses()
    investigations = final.get_investigations()

    assert len(app.endpoints) >= 5
    assert len(hypotheses) >= 2
    assert len(investigations) >= 2

    # Must not finish with only robots.txt-level understanding
    authz_inv = [i for i in investigations if i.specialist == "AuthorizationAgent"]
    assert len(authz_inv) >= 1

    actions = compute_investigation_actions(final)
    assert len(actions) >= 1
    assert not all("robots" in a.title.lower() for a in actions)


def test_robots_txt_only_not_sufficiently_complete():
    state = build_robots_txt_only_workspace()
    ingest_workspace_state(state)
    app = state.get_application_model()
    assert len(app.endpoints) <= 2

    completeness = assessment_completeness(state)
    assert not completeness["sufficient"]


def test_rich_app_not_clean_without_authorization_review():
    state = build_synthetic_workspace()
    ingest_workspace_state(state)
    from horcrux.intel.hypotheses import update_hypotheses_from_state
    state.set_hypotheses(update_hypotheses_from_state(state))

    completeness = assessment_completeness(state)
    assert completeness["high_value_surfaces"] >= 3
    assert not completeness["authorization_investigated"]


def test_assessment_loop_produces_findings_or_supported_hypotheses(tmp_path):
    state = build_synthetic_workspace()
    ws = Workspace(state.target)
    ws.root = tmp_path / "ws2"
    ws.state_file = ws.root / "state.json"
    ws.root.mkdir(parents=True)
    (ws.root / "raw").mkdir()
    ws.save(state)

    root = RootVAPTOrchestrator(ws, max_iterations=8)
    final = root.run_assessment_loop()

    assert final.get_assessment_phase() in {
        AssessmentPhase.COMPLETE,
        AssessmentPhase.INVESTIGATION,
        AssessmentPhase.SYNTHESIS,
    }
    assert len(final.get_hypotheses()) >= 2

    completed = [i for i in final.get_investigations() if i.state.value in {"COMPLETE", "SUPPORTED"}]
    assert len(completed) >= 1 or len(final.findings) >= 1


def test_web_pipeline_output_reaches_application_model():
    """Verify JS routes feed ApplicationModel (regression for pipeline integration)."""
    state = build_synthetic_workspace()
    app = ingest_workspace_state(state)

    js_endpoints = [e for e in app.endpoints if "javascript" in e.sources or "/rest/" in e.path]
    assert len(js_endpoints) >= 5

    object_eps = [e for e in app.endpoints if e.has_object_reference]
    assert len(object_eps) >= 2
