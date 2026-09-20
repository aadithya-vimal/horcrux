"""Tests for security test matrix and test-case derivation (Phases B and C)."""

from horcrux.intel.application_model import (
    ApplicationModel,
    SemanticEndpoint,
    SemanticParameter,
    ObjectLifecycle,
)
from horcrux.intel.test_matrix import (
    TestFamily,
    derive_applicable_tests,
    compute_security_test_coverage,
)
from horcrux.models import WorkspaceState


def test_matrix_derivation_from_rich_application():
    app = ApplicationModel()
    app.endpoints.extend([
        SemanticEndpoint(path="/api/BasketItems/1", method="GET"),
        SemanticEndpoint(path="/rest/admin/application-configuration", method="GET"),
        SemanticEndpoint(path="/rest/products/search", method="GET"),
        SemanticEndpoint(path="/api/Feedbacks", method="POST", is_mutation=True),
    ])
    app.parameters.extend([
        SemanticParameter(name="q", endpoint="/rest/products/search"),
        SemanticParameter(name="id", endpoint="/api/BasketItems/1"),
        SemanticParameter(name="url", endpoint="/rest/redirect"),
    ])
    app.object_lifecycles.append(
        ObjectLifecycle(object_type="BasketItem", identifier="1")
    )

    tests = derive_applicable_tests(app)
    assert len(tests) >= 5

    families = {t.family for t in tests}
    assert TestFamily.BOLA_IDOR in families
    assert TestFamily.AUTHZ_VERTICAL in families
    assert TestFamily.PARAM_SQLI in families or TestFamily.PARAM_XSS in families

    for t in tests:
        assert t.id
        assert t.specialist
        assert t.candidate_tools


def test_compute_security_test_coverage():
    state = WorkspaceState(target="testapp.local")
    app = state.get_application_model()
    app.endpoints.append(
        SemanticEndpoint(path="/api/Users/1", method="GET")
    )
    state.set_application_model(app)

    cov = compute_security_test_coverage(state)
    assert cov["total_applicable"] > 0
    assert "family_breakdown" in cov
    assert "surface_elements" in cov
    assert cov["surface_elements"]["endpoints"] == 1
    assert cov["total_executed"] == 0
    assert cov["total_pending"] == cov["total_applicable"]
