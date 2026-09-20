"""Semantic test binding + authoritative assessment state regressions.

Synthetic/local fixtures only. No real-target scans.
"""
from __future__ import annotations

import httpx

from horcrux.core.actions import (
    compute_investigation_actions,
    compute_next_actions,
    get_authoritative_assessment_state,
)
from horcrux.intel.application_model import (
    ApplicationModel,
    SemanticEndpoint,
    SemanticParameter,
)
from horcrux.intel.attack_paths import build_attack_paths, graph_node_severity
from horcrux.intel.test_matrix import (
    EndpointSecurityTest,
    ParameterSecurityTest,
    compute_security_test_coverage,
    derive_applicable_tests,
)
from horcrux.models import (
    DiscoveredPath,
    Finding,
    FindingStatus,
    Severity,
    ValidationState,
    WorkspaceState,
    canonical_finding_severity,
)
from horcrux.modules.web.validator import (
    BaselineFingerprint,
    validate_ftp_directory_listing,
    validate_robots_content,
)


def _ep(path: str) -> SemanticEndpoint:
    ep = SemanticEndpoint(method="GET", path=path, sources=["fixture"],
                          evidence_refs=[f"fixture:{path}"])
    ep.ensure_id()
    return ep


def _owned_param(name: str, endpoint: str, provenance: str = "OBSERVED_REQUEST") -> SemanticParameter:
    p = SemanticParameter(name=name, location="query", endpoint=endpoint,
                          source="operator", evidence_refs=[f"ev:{name}@{endpoint}"],
                          provenance=provenance, confidence=0.9,
                          first_seen=f"ev:{name}")
    p.ensure_id()
    return p


def _mock(status: int, text: str, ctype: str = "text/plain") -> httpx.Response:
    req = httpx.Request("GET", "http://t.local/x")
    return httpx.Response(status, headers={"content-type": ctype}, text=text, request=req)


def _baseline() -> BaselineFingerprint:
    resp = _mock(404, "not found", "text/html")
    return BaselineFingerprint.analyze(resp)


# 1. q owned by A cannot execute on B
def test_q_owned_by_a_cannot_execute_on_b():
    app = ApplicationModel(target="t.local")
    app.endpoints = [_ep("/rest/products/search"), _ep("/api/Users")]
    app.parameters = [_owned_param("q", "/rest/products/search")]
    tests = derive_applicable_tests(app, None)
    param_tests = [t for t in tests if t.asset_type == "parameter"]
    assert param_tests, "owned q must still derive tests on its own endpoint"
    for t in param_tests:
        assert t.target_path == "/rest/products/search"
        assert t.target_parameter == "q"
    assert not any(t.target_path == "/api/Users" and t.target_parameter == "q" for t in tests)


# 2. endpoint test executes without parameters
def test_endpoint_test_executes_without_parameters():
    t = EndpointSecurityTest(
        family="auth_enforcement",  # type: ignore[arg-type]
        name="auth check",
        asset_id="e1",
        asset_type="endpoint",
        target_path="/api/Users/1",
        target_method="GET",
    )
    assert t.target_parameter == ""
    assert t.asset_type == "endpoint"


# 3. /api/Users does not receive synthetic ?q=
def test_api_users_receives_no_synthetic_q():
    app = ApplicationModel(target="t.local")
    app.endpoints = [_ep("/api/Users")]
    app.parameters = []
    tests = derive_applicable_tests(app, None)
    assert not any(t.target_parameter == "q" for t in tests)


# 4. source-only JS route is not HTTP-observed
def test_source_only_js_route_not_http_observed():
    from horcrux.intel.ingestion import ingest_javascript_routes
    app = ApplicationModel(target="t.local")
    ingest_javascript_routes(app, ["/api/hidden"], [], source="javascript")
    route = next(r for r in app.routes if r.path == "/api/hidden")
    assert route.discovery_state == "DISCOVERED_FROM_SOURCE"
    cand = DiscoveredPath(url="http://t.local/api/hidden", path="/api/hidden",
                          status=0, size=0, source="js_analysis",
                          discovery_state="DISCOVERED_FROM_SOURCE")
    assert cand.is_http_evidence is False
    assert cand.discovery_state != "OBSERVED_HTTP"


# 5. robots.txt existence does not create confirmed finding
def test_robots_existence_is_recon_not_confirmed():
    resp = _mock(200, "User-agent: *\nDisallow: /admin\n", "text/plain")
    res = validate_robots_content(resp, _baseline())
    assert res.is_valid is False
    assert res.validation_state != ValidationState.confirmed


# 6. /ftp existence does not create directory-listing finding
def test_ftp_existence_without_listing_is_not_finding():
    resp = _mock(200, "<html><body>ftp service ready</body></html>", "text/html")
    res = validate_ftp_directory_listing(resp, _baseline())
    assert res.is_valid is False
    assert res.validation_state != ValidationState.confirmed


# 7. canonical severity identical in findings + graph + report
def test_canonical_severity_identical_everywhere(tmp_path):
    f = Finding(id="f1", title="X", category="injection-sqli",
                severity=Severity.high, confidence=0.9,
                status=FindingStatus.verified,
                validation_state=ValidationState.confirmed,
                target="t.local", affected_asset="http://t.local/a",
                evidence=["e"], reproduction=["curl x"])
    st = WorkspaceState(target="t.local")
    st.findings = [f]
    app = ApplicationModel(target="t.local")
    st.set_application_model(app)
    paths = build_attack_paths(st)
    fpaths = [p for p in paths if "f1" in (p.finding_ids or [])]
    assert fpaths
    by_id = {"f1": f}
    for p in fpaths:
        for n in p.nodes:
            if n.finding_id == "f1":
                assert graph_node_severity(n, by_id) == canonical_finding_severity(f) == "high"
                assert n.severity == "high"
    from horcrux.core.storage import Workspace
    from horcrux.reporting.reports import markdown
    ws = Workspace(target="t.local", base=str(tmp_path / "ws"))
    ws.save(st)
    out = markdown(ws)
    text = out.read_text(encoding="utf-8")
    assert "[HIGH]" in text


# 8. next returns exhausted state when queue is empty
def test_next_returns_exhausted_when_queue_empty():
    from horcrux.intel.hypotheses import Hypothesis, HypothesisClass, HypothesisStatus
    from horcrux.intel.investigations import Investigation, InvestigationState
    st = WorkspaceState(target="t.local")
    app = ApplicationModel(target="t.local")
    app.endpoints = [_ep("/api/widgets/1")]
    st.set_application_model(app)
    h = Hypothesis(hypothesis_class=HypothesisClass.IDOR_BOLA, title="h",
                   status=HypothesisStatus.REFUTED, asset_refs=[])
    h.ensure_id()
    st.set_hypotheses([h])
    inv = Investigation(id="", objective="check", candidate_tools=["http_probe"],
                        required_capabilities=["http"], specialist="WebAgent",
                        state=InvestigationState.REFUTED, hypothesis_id=h.id)
    inv.ensure_id()
    st.set_investigations([inv])
    auth = get_authoritative_assessment_state(st)
    assert auth["exhausted"] is True
    assert auth["queue_executable"] == 0
    acts = compute_investigation_actions(st)
    assert [a.id for a in acts] == ["queue_drained"]
    assert "exhausted" in acts[0].title.lower()
    legacy = compute_next_actions(st)
    assert [a.id for a in legacy] == ["queue_drained"]
    assert "deep_recon" not in [a.id for a in legacy]


# 9. deep profile produces a larger applicable security matrix
def test_deep_profile_expands_matrix():
    app = ApplicationModel(target="t.local")
    app.endpoints = [_ep("/api/Users/1"), _ep("/rest/products/search")]
    app.parameters = [_owned_param("q", "/rest/products/search")]
    std = derive_applicable_tests(app, None, profile="standard")
    deep = derive_applicable_tests(app, None, profile="deep")
    assert len(deep) > len(std)
    cov = compute_security_test_coverage(WorkspaceState(target="t.local"))
    assert "deep_delta" in cov


# 10. coverage excludes semantically invalid tests
def test_coverage_excludes_semantically_invalid():
    st = WorkspaceState(target="t.local")
    app = ApplicationModel(target="t.local")
    app.endpoints = [_ep("/api/Users")]
    # No owned parameters: no parameter tests may count toward coverage.
    app.parameters = []
    st.set_application_model(app)
    cov = compute_security_test_coverage(st)
    assert not any(d.get("parameter") == "q" and d.get("target") == "/api/Users"
                   for d in cov.get("test_details", []))
    assert cov["total_applicable"] == len(derive_applicable_tests(app, None))
