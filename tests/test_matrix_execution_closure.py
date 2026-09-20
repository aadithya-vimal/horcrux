"""Execution-closure regression tests: applicable vs executed gap.

Every applicable security test must reach an explicit terminal state —
EXECUTED / BLOCKED-with-reason / NOT TESTED — never a silent skip.
"""

from horcrux.intel.application_model import (
    ApplicationModel,
    SemanticEndpoint,
    SemanticParameter,
)
from horcrux.intel.investigations import (
    Investigation,
    InvestigationState,
    prune_stale_matrix_investigations,
    rank_investigations,
)
from horcrux.intel.test_matrix import (
    TestFamily,
    derive_applicable_tests,
    compute_security_test_coverage,
    normalize_matrix_path,
    path_has_instance_id,
    test_case_to_investigation as tc_to_investigation,
)
from horcrux.models import WorkspaceState


def _app_with(*endpoints, params=None):
    app = ApplicationModel()
    for path, method in endpoints:
        app.endpoints.append(SemanticEndpoint(path=path, method=method))
    for name, ep in (params or []):
        p = SemanticParameter(name=name, endpoint=ep, location="query")
        p.ensure_id()
        app.parameters.append(p)
    return app


def test_collection_does_not_derive_bola_but_instance_does():
    app = _app_with(("/api/Products", "GET"), ("/api/Products/1", "GET"))
    fams = [(t.family, t.target_path) for t in derive_applicable_tests(app)]
    bola_paths = {p for f, p in fams if f == TestFamily.BOLA_IDOR}
    assert "/api/Products/1" in bola_paths
    assert "/api/Products" not in bola_paths
    horiz_paths = {p for f, p in fams if f == TestFamily.AUTHZ_HORIZONTAL}
    assert "/api/Products/1" in horiz_paths
    assert "/api/Products" not in horiz_paths


def test_ip_octets_and_bundles_never_read_as_instance_ids():
    ep = SemanticEndpoint(path="http://127.0.0.1:3000/main.js", method="GET")
    assert ep.has_object_reference is False
    assert path_has_instance_id("http://127.0.0.1:3000/main.js") is False
    assert path_has_instance_id("/api/Products/1") is True
    assert path_has_instance_id("/api/Products") is False
    assert normalize_matrix_path("http://127.0.0.1:3000/main.js") == "/main.js"

    app = _app_with(
        ("/rest/products/search", "GET"),
        params=[("q", "/rest/products/search"), ("id", "http://127.0.0.1:3000/main.js")],
    )
    tcs = derive_applicable_tests(app)
    # No test may target a static bundle.
    assert all(t.target_path != "/main.js" for t in tcs)
    assert all("main.js" not in (t.target_parameter or "") or t.target_path != "/main.js" for t in tcs)
    # Real search endpoint still derives semantic injection + XSS coverage.
    assert any(t.family == TestFamily.PARAM_SQLI and t.target_parameter == "q" for t in tcs)
    assert any(t.family == TestFamily.PARAM_XSS and t.target_parameter == "q" for t in tcs)


def test_param_bound_object_reference_derives_bola():
    app = _app_with(("/rest/track-order", "GET"), params=[("orderId", "/rest/track-order")])
    fams = [(t.family, t.target_path) for t in derive_applicable_tests(app)]
    assert (TestFamily.BOLA_IDOR, "/rest/track-order") in fams


def test_missing_families_derive_data_driven():
    app = _app_with(
        ("/rest/products/search", "GET"),
        ("/upload", "POST"),
        ("/graphql", "POST"),
        params=[("q", "/rest/products/search")],
    )
    fams = {t.family for t in derive_applicable_tests(app)}
    assert TestFamily.PARAM_SQLI in fams
    assert TestFamily.PARAM_CMDI in fams
    assert TestFamily.PARAM_XSS in fams
    assert TestFamily.FILE_UPLOAD in fams
    assert TestFamily.GRAPHQL_INTROSPECTION in fams
    assert TestFamily.GRAPHQL_AUTHZ in fams


def test_test_case_contract_fields_populated():
    app = _app_with(("/api/Products/1", "GET"))
    tcs = derive_applicable_tests(app)
    assert tcs
    for tc in tcs:
        assert tc.id
        assert tc.applicability
        assert tc.execution_input
        assert tc.execution_input["target_path"] == tc.target_path
        assert tc.evidence_requirements
        assert tc.adjudication_rule
        assert "REQUIRES_SECOND_IDENTITY" in tc.terminal_states
        assert "NOT_APPLICABLE" in tc.terminal_states


def test_coverage_terminal_buckets_have_no_silent_pending():
    state = WorkspaceState(target="closure.local")
    app = state.get_application_model()
    app.endpoints.append(SemanticEndpoint(path="/api/Products/1", method="GET"))
    app.endpoints.append(SemanticEndpoint(path="/api/Products/2", method="GET"))
    app.endpoints.append(SemanticEndpoint(path="/rest/products/search", method="GET"))
    app.endpoints.append(SemanticEndpoint(path="/graphql", method="POST"))
    q = SemanticParameter(name="q", endpoint="/rest/products/search", location="query")
    q.ensure_id()
    app.parameters.append(q)
    state.set_application_model(app)

    tcs = derive_applicable_tests(state.get_application_model(), state)
    assert len(tcs) >= 7
    invs = []
    states_cycle = [
        InvestigationState.SUPPORTED,
        InvestigationState.REFUTED,
        InvestigationState.COMPLETE,
        InvestigationState.INSUFFICIENT_EVIDENCE,
        InvestigationState.FAILED,
        InvestigationState.REQUIRES_SECOND_IDENTITY,
        InvestigationState.BLOCKED,
    ]
    for tc, st in zip(tcs[:-1], states_cycle * 3):
        inv = tc_to_investigation(tc)
        inv.state = st
        inv.result_summary = f"test {st.value}"
        invs.append(inv)
    state.set_investigations(invs)

    cov = compute_security_test_coverage(state)
    assert cov["total_applicable"] == len(tcs)
    # Every applicable test is accounted for exactly once.
    accounted = (
        cov["total_executed"] + cov["total_blocked"]
        + cov["total_insufficient"] + cov["total_failed"] + cov["total_pending"]
    )
    assert accounted == cov["total_applicable"]
    # INSUFFICIENT / FAILED are terminal attempts, never pending.
    assert cov["total_insufficient"] >= 1
    assert cov["total_failed"] >= 1
    terminals = {d["terminal"] for d in cov["test_details"]}
    assert "NOT_TESTED" in terminals  # unmapped remainder is explicit
    assert "" not in terminals
    assert all(d["terminal"] for d in cov["test_details"])


def test_matrix_investigations_exempt_from_cosmetic_demotion():
    matrix_inv = Investigation(
        objective="Test SQL/NoSQL injection semantics on parameter 'q' at /search",
        state=InvestigationState.READY,
        observations=["matrix_tc_id:abc", "matrix_family:param_sqli"],
    )
    plain_inv = Investigation(
        objective="Test parameter behavior on /search",
        state=InvestigationState.READY,
    )
    ranked = rank_investigations([matrix_inv, plain_inv])
    by_obj = {i.objective: i.priority for i in ranked}
    assert by_obj["Test SQL/NoSQL injection semantics on parameter 'q' at /search"] >= by_obj[
        "Test parameter behavior on /search"
    ]


def test_prune_retires_stale_matrix_work_explicitly():
    stale = Investigation(
        id="inv-stale",
        objective="stale matrix test",
        state=InvestigationState.READY,
        observations=["matrix_tc_id:deadbeef"],
    )
    done = Investigation(
        id="inv-done",
        objective="finished matrix test",
        state=InvestigationState.SUPPORTED,
        observations=["matrix_tc_id:deadbeef"],
    )
    out = prune_stale_matrix_investigations([stale, done], {"live-id"})
    assert out[0].state == InvestigationState.NOT_APPLICABLE
    assert "no longer applicable" in out[0].result_summary
    # Executed evidence is never rewritten.
    assert out[1].state == InvestigationState.SUPPORTED


def test_capability_inputs_normalize_full_url_matrix_asset():
    from horcrux.agents.executor import build_capability_inputs

    state = WorkspaceState(target="closure.local")
    app = state.get_application_model()
    app.endpoints.append(SemanticEndpoint(path="/rest/products/search", method="GET"))
    state.set_application_model(app)
    inv = Investigation(
        objective="matrix test",
        state=InvestigationState.READY,
        candidate_tools=["param_fuzz"],
        observations=[
            "matrix_tc_id:x",
            "matrix_asset:http://127.0.0.1:3000/main.js",
            "matrix_param:q",
            "matrix_method:GET",
        ],
    )
    inputs = build_capability_inputs(state, inv, "param_fuzz")
    assert inputs["endpoint"] == "/main.js"
    assert "http://" not in inputs["url"].replace("http://closure.local", "")
