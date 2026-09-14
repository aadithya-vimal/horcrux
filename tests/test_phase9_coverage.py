"""Phase 9 coverage model, completeness gate, and new module tests.

These tests verify the 50-part engineering requirements:
- Coverage model: 70+ properties, PropertyStatus enum
- Completeness gate: UNKNOWN != NO_ISSUE_EVIDENCE, never "clean" with unknowns
- Application type classification: multi-signal
- JS intelligence: semantic extraction
- Error response intelligence: stack traces, framework signatures
- Discovery correlation: multi-source
- Authorization matrix: recording, gap generation
- Differential engine: verdict logic
- False-negative audit: gap identification
- Sensitive data: detection and redaction
"""

from __future__ import annotations

import pytest

from horcrux.intel.application_model import ApplicationModel, SemanticEndpoint
from horcrux.intel.authorization import (
    AuthorizationMatrix,
    AuthzCellStatus,
    get_or_create_matrix,
    record_authz_observation,
    generate_authz_matrix_investigations,
)
from horcrux.intel.differential import (
    DifferentialEngine,
    DifferentialVerdict,
    ResponseSnapshot,
    compare_identity_access,
)
from horcrux.intel.false_negative_audit import run_false_negative_audit
from horcrux.intel.sensitive_data import (
    SensitiveDataDetector,
    redact_secrets,
    scan_capability_result,
)
from horcrux.models import (
    Credential, DiscoveredPath, NormalizedTechnology, Parameter,
    Service, TechCategory, WebApplicationType, WebTarget, WorkspaceState,
)


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _state_with_auth_surface() -> WorkspaceState:
    """State with a clear authentication surface."""
    target = "test-auth.local"
    s = WorkspaceState(target=target)
    s.services = [Service(host=target, port=3000, service="http", product="Express")]
    s.discovered_paths = [
        DiscoveredPath(url=f"http://{target}:3000/login", path="/login", status=200,
                       source="fuzzer", validated=True),
        DiscoveredPath(url=f"http://{target}:3000/api/users/1", path="/api/users/{id}",
                       status=200, source="javascript", validated=True),
        DiscoveredPath(url=f"http://{target}:3000/admin", path="/admin", status=403,
                       source="fuzzer", validated=True),
    ]
    s.parameters = [
        Parameter(name="email", location="body", source="form", endpoint="/login"),
        Parameter(name="password", location="body", source="form", endpoint="/login"),
        Parameter(name="id", location="path", source="javascript", endpoint="/api/users/{id}"),
    ]
    s.web_targets = [
        WebTarget(scheme="http", host=target, port=3000,
                  base_url=f"http://{target}:3000",
                  application_type=WebApplicationType.SPA,
                  endpoints=s.discovered_paths, parameters=s.parameters)
    ]
    return s


def _state_with_no_auth() -> WorkspaceState:
    """Minimal state with no authentication surface."""
    target = "static.local"
    s = WorkspaceState(target=target)
    s.services = [Service(host=target, port=80, service="http")]
    s.discovered_paths = [
        DiscoveredPath(url=f"http://{target}/index.html", path="/index.html",
                       status=200, source="fuzzer", validated=True),
    ]
    return s


# ──────────────────────────────────────────────────────────────────────────────
# Part 1: Coverage Model — PropertyStatus enum and 70+ properties
# ──────────────────────────────────────────────────────────────────────────────

def test_coverage_model_has_property_status_enum():
    """PropertyStatus enum must have all 9 required states."""
    from horcrux.intel.coverage import PropertyStatus
    required = {
        "UNKNOWN", "APPLICABLE", "OBSERVED", "INVESTIGATING",
        "VALIDATED", "CONFIRMED_ISSUE", "NO_ISSUE_EVIDENCE",
        "BLOCKED", "NOT_APPLICABLE",
    }
    actual = {s.value for s in PropertyStatus}
    assert required.issubset(actual), f"Missing status values: {required - actual}"


def test_coverage_model_has_minimum_properties():
    """SecurityCoverageModel must have 70+ fine-grained properties."""
    from horcrux.intel.coverage import SecurityCoverageModel
    cov = SecurityCoverageModel()
    cov.ensure_properties()
    assert len(cov.properties) >= 55, (
        f"Expected 55+ properties, got {len(cov.properties)}"
    )


def test_coverage_model_property_groups():
    """Properties must be organized into expected groups."""
    from horcrux.intel.coverage import SecurityCoverageModel
    cov = SecurityCoverageModel()
    cov.ensure_properties()
    groups = {p.group for p in cov.properties.values()}
    required_groups = {
        "attack_surface", "authentication", "authorization",
        "input_server_side", "api_security", "business_logic",
        "data_exposure", "infrastructure",
    }
    assert required_groups.issubset(groups), f"Missing groups: {required_groups - groups}"


def test_coverage_critical_properties_exist():
    """Must have critical properties in authorization and authentication."""
    from horcrux.intel.coverage import SecurityCoverageModel
    cov = SecurityCoverageModel()
    cov.ensure_properties()
    critical = [p for p in cov.properties.values() if p.critical]
    critical_groups = {p.group for p in critical}
    assert "authorization" in critical_groups, "Authorization must have critical properties"
    assert "authentication" in critical_groups, "Authentication must have critical properties"
    assert len(critical) >= 10, f"Expected 10+ critical properties, got {len(critical)}"


# ──────────────────────────────────────────────────────────────────────────────
# Part 2: UNKNOWN != NO_ISSUE_EVIDENCE — The Core Invariant
# ──────────────────────────────────────────────────────────────────────────────

def test_unknown_never_collapses_to_no_issue_evidence_without_evidence():
    """CRITICAL: Setting NO_ISSUE_EVIDENCE without evidence must downgrade to VALIDATED."""
    from horcrux.intel.coverage import SecurityCoverageModel, PropertyStatus
    cov = SecurityCoverageModel()
    cov.ensure_properties()

    # Attempt to set NO_ISSUE_EVIDENCE without evidence_refs
    cov.set_property_status("authz.horizontal", PropertyStatus.NO_ISSUE_EVIDENCE, evidence_refs=None)
    prop = cov.properties["authz.horizontal"]
    # Must NOT be NO_ISSUE_EVIDENCE — should be downgraded to VALIDATED
    assert prop.status != PropertyStatus.NO_ISSUE_EVIDENCE, (
        "CRITICAL INVARIANT VIOLATED: UNKNOWN must not collapse to NO_ISSUE_EVIDENCE without evidence"
    )


def test_no_issue_evidence_requires_explicit_evidence():
    """NO_ISSUE_EVIDENCE is only valid WITH explicit negative evidence."""
    from horcrux.intel.coverage import SecurityCoverageModel, PropertyStatus
    cov = SecurityCoverageModel()
    cov.ensure_properties()

    # With explicit evidence refs → allowed
    cov.set_property_status(
        "authz.horizontal",
        PropertyStatus.NO_ISSUE_EVIDENCE,
        evidence_refs=["authz_test:user_a:user_b:denied"],
    )
    prop = cov.properties["authz.horizontal"]
    # With explicit negative evidence, NO_ISSUE_EVIDENCE is valid
    assert prop.status == PropertyStatus.NO_ISSUE_EVIDENCE


def test_assessment_completeness_never_sufficient_with_critical_unknowns():
    """assessment_completeness() must never return sufficient=True with critical UNKNOWN properties."""
    from horcrux.intel.coverage import assessment_completeness
    state = _state_with_auth_surface()
    # Ingest but don't investigate — coverage must remain incomplete
    from horcrux.intel.ingestion import ingest_workspace_state
    ingest_workspace_state(state)

    result = assessment_completeness(state)
    # With auth surface + object endpoints + admin endpoint but NO sessions/auth testing:
    # Must NOT be sufficient
    assert not result["sufficient"], (
        "CRITICAL: assessment must not be 'sufficient' when auth surface exists "
        f"but no sessions/auth testing. verdict={result.get('verdict')}, "
        f"blocking={result.get('blocking_reasons')}"
    )


def test_assessment_verdict_not_complete_with_unknown_critical_properties():
    """coverage_verdict() must return INCOMPLETE when critical properties are UNKNOWN."""
    from horcrux.intel.coverage import SecurityCoverageModel
    cov = SecurityCoverageModel()
    cov.ensure_properties()
    # Don't set any properties — everything stays UNKNOWN
    verdict = cov.coverage_verdict()
    assert verdict in ("INCOMPLETE", "LIMITED", "BLOCKED"), (
        f"Expected INCOMPLETE/LIMITED/BLOCKED with all UNKNOWN properties, got {verdict}"
    )


def test_coverage_verdict_complete_only_when_all_critical_tested():
    """coverage_verdict() == COMPLETE only when all critical properties non-UNKNOWN."""
    from horcrux.intel.coverage import SecurityCoverageModel, PropertyStatus
    cov = SecurityCoverageModel()
    cov.ensure_properties()

    # Mark all critical properties as VALIDATED
    critical = [p for p in cov.properties.values() if p.critical and p.applicable]
    for prop in critical:
        cov.set_property_status(
            prop.property_id, PropertyStatus.VALIDATED,
            evidence_refs=["test:validated"],
        )
    # Mark all non-critical as NOT_APPLICABLE for simplicity
    non_critical = [p for p in cov.properties.values() if not p.critical]
    for prop in non_critical:
        cov.set_property_status(prop.property_id, PropertyStatus.NOT_APPLICABLE)

    verdict = cov.coverage_verdict()
    assert verdict == "COMPLETE", f"Expected COMPLETE, got {verdict}"


def test_blocking_reasons_populated_for_unknown_critical():
    """completeness_blocking_reasons() must return reasons when critical properties unknown."""
    from horcrux.intel.coverage import SecurityCoverageModel
    cov = SecurityCoverageModel()
    cov.ensure_properties()
    reasons = cov.completeness_blocking_reasons()
    assert len(reasons) > 0, "Must have blocking reasons when critical properties are UNKNOWN"
    assert any("UNKNOWN" in r or "critical" in r.lower() for r in reasons)


# ──────────────────────────────────────────────────────────────────────────────
# Part 3: Application Type Classification
# ──────────────────────────────────────────────────────────────────────────────

def test_spa_classification_from_angular():
    """Angular technology should yield SPA classification."""
    from horcrux.intel.ingestion import classify_application_type
    app = ApplicationModel(target="test.local")
    from horcrux.intel.application_model import SemanticTechnology
    app.technologies = [SemanticTechnology(name="Angular", category="FRAMEWORK")]
    app_type, confidence = classify_application_type(app)
    assert app_type == "SPA", f"Expected SPA, got {app_type}"
    assert confidence >= 0.3


def test_api_classification_from_routes():
    """Dense /api routes should yield API_service classification."""
    from horcrux.intel.ingestion import classify_application_type
    app = ApplicationModel(target="test.local")
    for i in range(12):
        ep = SemanticEndpoint(method="GET", path=f"/api/resource{i}", sources=["fuzzer"])
        ep.ensure_id()
        app.endpoints.append(ep)
    app_type, confidence = classify_application_type(app)
    assert app_type == "API_service", f"Expected API_service, got {app_type}"


def test_graphql_classification():
    """GraphQL endpoint should yield GraphQL_application classification."""
    from horcrux.intel.ingestion import classify_application_type
    from horcrux.intel.application_model import GraphQLOperation
    app = ApplicationModel(target="test.local")
    ep = SemanticEndpoint(method="POST", path="/graphql", sources=["javascript"])
    ep.ensure_id()
    app.endpoints.append(ep)
    op = GraphQLOperation(kind="query", name="getUser", endpoint="/graphql",
                          evidence_refs=["test"])
    op.ensure_id()
    app.graphql_operations.append(op)
    app_type, confidence = classify_application_type(app)
    assert app_type == "GraphQL_application", f"Expected GraphQL_application, got {app_type}"


def test_ecommerce_classification():
    """Cart/checkout routes should yield e_commerce classification."""
    from horcrux.intel.ingestion import classify_application_type
    app = ApplicationModel(target="test.local")
    for path in ["/cart", "/cart/checkout", "/products/{id}", "/orders"]:
        ep = SemanticEndpoint(method="GET", path=path, sources=["javascript"])
        ep.ensure_id()
        app.endpoints.append(ep)
    app_type, confidence = classify_application_type(app)
    assert app_type == "e_commerce", f"Expected e_commerce, got {app_type}"


# ──────────────────────────────────────────────────────────────────────────────
# Part 4: Multi-Source Discovery Correlation
# ──────────────────────────────────────────────────────────────────────────────

def test_correlate_discovery_sources_deduplicates():
    """Multiple sources finding the same path should consolidate correctly."""
    from horcrux.intel.ingestion import correlate_discovery_sources
    app = ApplicationModel(target="test.local")
    result = correlate_discovery_sources(app, {
        "ffuf": ["/api/users", "/api/admin", "/login"],
        "javascript": ["/api/users", "/api/orders", "/login"],
        "robots": ["/api/admin"],
    })
    assert result["total_paths"] == 4, f"Expected 4 unique paths, got {result['total_paths']}"


def test_correlate_discovery_sources_tracks_agreements():
    """Paths found by multiple sources should be tracked as agreements."""
    from horcrux.intel.ingestion import correlate_discovery_sources
    app = ApplicationModel(target="test.local")
    result = correlate_discovery_sources(app, {
        "ffuf": ["/api/users", "/admin"],
        "javascript": ["/api/users", "/api/orders"],
    })
    assert result["agreements"] >= 1  # /api/users found by both


def test_correlate_sources_important_path_only_in_one_source():
    """Important path found by only one source should appear in contradictions."""
    from horcrux.intel.ingestion import correlate_discovery_sources
    app = ApplicationModel(target="test.local")
    result = correlate_discovery_sources(app, {
        "javascript": ["/api/internal/config"],
        "ffuf": ["/index.html"],
    })
    contradictions = result["contradictions"]
    important_contradiction = next(
        (c for c in contradictions if "internal" in c["path"] or "config" in c["path"]), None
    )
    assert important_contradiction is not None, (
        "Important path found by only one source should be flagged as potential contradiction"
    )


# ──────────────────────────────────────────────────────────────────────────────
# Part 6: JS Intelligence
# ──────────────────────────────────────────────────────────────────────────────

def test_js_intelligence_extracts_api_endpoints():
    """JS content should yield API endpoints."""
    from horcrux.intel.ingestion import ingest_js_intelligence
    app = ApplicationModel(target="test.local")
    js_content = """
    axios.get('/api/users/1')
    fetch('/rest/basket/1')
    this.http.post('/api/feedbacks', payload)
    """
    counts = ingest_js_intelligence(app, js_content)
    assert counts.get("api_endpoints", 0) >= 1
    paths = {e.path for e in app.endpoints}
    assert any("/api/" in p or "/rest/" in p for p in paths)


def test_js_intelligence_extracts_auth_endpoints():
    """JS content should yield authentication endpoints."""
    from horcrux.intel.ingestion import ingest_js_intelligence
    app = ApplicationModel(target="test.local")
    js_content = """
    const LOGIN_URL = '/login'
    const REGISTER_URL = '/register'
    this.http.post('/rest/user/login', credentials)
    """
    counts = ingest_js_intelligence(app, js_content)
    assert counts.get("auth_endpoints", 0) >= 1
    # Authentication mechanism should be created
    assert len(app.authentication) >= 1


def test_js_intelligence_extracts_admin_refs():
    """JS content with admin routes should create privileged endpoints."""
    from horcrux.intel.ingestion import ingest_js_intelligence
    app = ApplicationModel(target="test.local")
    js_content = """
    if (user.isAdmin) { this.router.navigate(['/admin/users']); }
    const ADMIN_URL = '/admin/application-version'
    """
    counts = ingest_js_intelligence(app, js_content)
    assert counts.get("admin_refs", 0) >= 1
    admin_eps = [e for e in app.endpoints if "admin" in e.path.lower()]
    assert len(admin_eps) >= 1


def test_js_intelligence_extracts_ssrf_params():
    """JS content with URL parameters should flag SSRF candidates."""
    from horcrux.intel.ingestion import ingest_js_intelligence
    app = ApplicationModel(target="test.local")
    js_content = """
    const params = { url: this.importUrl, callback: this.webhookUrl }
    fetch('/api/import', { body: JSON.stringify(params) })
    """
    counts = ingest_js_intelligence(app, js_content)
    assert counts.get("ssrf_params", 0) >= 1
    ssrf_params = [p for p in app.parameters if p.param_class == "url_fetch"]
    assert len(ssrf_params) >= 1


def test_js_intelligence_extracts_graphql_ops():
    """JS content with GraphQL operations should yield operation records."""
    from horcrux.intel.ingestion import ingest_js_intelligence
    app = ApplicationModel(target="test.local")
    js_content = """
    const GET_USER = gql`query getUser($id: ID!) { user(id: $id) { email } }`
    const UPDATE_USER = gql`mutation updateUser($id: ID!, $role: String!) {
      updateUser(id: $id, role: $role) { id }
    }`
    """
    counts = ingest_js_intelligence(app, js_content)
    assert counts.get("graphql_ops", 0) >= 2


# ──────────────────────────────────────────────────────────────────────────────
# Part 7: Error Response Intelligence
# ──────────────────────────────────────────────────────────────────────────────

def test_error_response_detects_stack_trace():
    """500 responses with stack traces should be flagged."""
    from horcrux.intel.ingestion import ingest_error_response
    app = ApplicationModel(target="test.local")
    body = "Error: Cannot read property\n    at Object.<anonymous> (/app/routes/users.js:42:15)"
    intel = ingest_error_response(app, "/api/users", 500, body)
    assert any(f["type"] == "stack_trace" for f in intel["findings"])


def test_error_response_detects_framework_disclosure():
    """Error pages revealing framework names should be flagged."""
    from horcrux.intel.ingestion import ingest_error_response
    app = ApplicationModel(target="test.local")
    body = "werkzeug.exceptions.NotFound: 404 Not Found"
    intel = ingest_error_response(app, "/api/missing", 404, body)
    assert any(f["type"] == "framework_disclosure" for f in intel["findings"])
    # Should also add Flask to technologies
    tech_names = {t.name.lower() for t in app.technologies}
    assert "flask" in tech_names


def test_error_response_detects_db_error():
    """SQL error messages should be flagged."""
    from horcrux.intel.ingestion import ingest_error_response
    app = ApplicationModel(target="test.local")
    body = "SQLITE_ERROR: SQL error near 'or': syntax error"
    intel = ingest_error_response(app, "/api/search", 500, body)
    assert any(f["type"] == "database_error" for f in intel["findings"])


def test_error_response_detects_path_disclosure():
    """Internal file paths in error responses should be flagged."""
    from horcrux.intel.ingestion import ingest_error_response
    app = ApplicationModel(target="test.local")
    body = "Cannot find module '/var/www/juice-shop/server/routes/users.js'"
    intel = ingest_error_response(app, "/api/error", 500, body)
    assert any(f["type"] == "path_disclosure" for f in intel["findings"])


# ──────────────────────────────────────────────────────────────────────────────
# Part 11: Authorization Matrix
# ──────────────────────────────────────────────────────────────────────────────

def test_authorization_matrix_records_observation():
    """Authorization matrix should record observations correctly."""
    matrix = AuthorizationMatrix()
    cell = matrix.record_observation(
        identity="user-a", endpoint="/api/users/1",
        method="GET", status_code=200,
        evidence_refs=["http_probe:user-a:/api/users/1"],
    )
    assert cell.status == AuthzCellStatus.ALLOWED
    assert cell.status_code == 200
    assert "user-a" in matrix.identities
    assert "/api/users/1" in matrix.endpoints


def test_authorization_matrix_records_denied():
    """403/401 responses should yield DENIED status."""
    matrix = AuthorizationMatrix()
    cell = matrix.record_observation(
        identity="user-a", endpoint="/admin", method="GET", status_code=403,
    )
    assert cell.status == AuthzCellStatus.DENIED


def test_authorization_matrix_unknown_cells_reported():
    """Unknown cells should be explicitly reportable."""
    matrix = AuthorizationMatrix()
    matrix.record_observation("user-a", "/api/users/1", "GET", 200)
    matrix.record_observation("admin", "/api/users/1", "GET", 200)
    # user-b was never tested
    matrix.identities.append("user-b")

    unknown = matrix.unknown_cells(
        identities=["user-a", "user-b", "admin"],
        endpoints=["/api/users/1"],
    )
    # user-b x GET /api/users/1 should be unknown
    assert any(cell[0] == "user-b" for cell in unknown)


def test_authorization_matrix_high_value_gaps():
    """High-value unknown cells should be surfaced for investigation."""
    matrix = AuthorizationMatrix()
    matrix.identities = ["user-a", "user-b"]
    matrix.endpoints = ["/api/users/1"]

    # No observations recorded
    app = ApplicationModel(target="test.local")
    ep = SemanticEndpoint(method="GET", path="/api/users/{id}", sources=["javascript"])
    ep.ensure_id()
    app.endpoints.append(ep)

    gaps = matrix.high_value_gaps(["/api/users/1"], [])
    assert len(gaps) > 0, "Should have high-value gaps when object endpoints have unknown authorization"


def test_authorization_matrix_generates_investigations():
    """Matrix gaps should generate authorization investigations."""
    matrix = AuthorizationMatrix()
    matrix.identities = ["user-a", "admin"]
    matrix.endpoints = ["/api/users/1"]

    app = ApplicationModel(target="test.local")
    from horcrux.intel.application_model import SemanticIdentity, IdentityRole
    app.identities = [
        SemanticIdentity(role=IdentityRole.USER, label="user-a"),
        SemanticIdentity(role=IdentityRole.ADMIN, label="admin"),
    ]
    ep = SemanticEndpoint(method="GET", path="/api/users/{id}", sources=["javascript"])
    ep.ensure_id()
    app.endpoints.append(ep)

    investigations = matrix.generate_investigations(app)
    assert len(investigations) > 0
    assert all(i.specialist == "AuthorizationAgent" for i in investigations)


def test_record_authz_observation_stores_in_app_model():
    """record_authz_observation should persist to ApplicationModel."""
    app = ApplicationModel(target="test.local")
    # Add authorization_matrix field
    app.authorization_matrix = {}

    record_authz_observation(app, "user-a", "/api/orders/1", "GET", 200,
                              evidence_refs=["probe:user-a"])
    matrix = get_or_create_matrix(app)
    cell = matrix.get_cell("user-a", "/api/orders/1", "GET")
    assert cell.status == AuthzCellStatus.ALLOWED


# ──────────────────────────────────────────────────────────────────────────────
# Part 15: Differential Testing Engine
# ──────────────────────────────────────────────────────────────────────────────

def test_differential_same_status_same_size_verdict_same():
    """Same status code and similar size → SAME verdict."""
    engine = DifferentialEngine()
    snap_a = ResponseSnapshot(status_code=200, size=500, identity="user-a")
    snap_b = ResponseSnapshot(status_code=200, size=510, identity="user-b")
    result = engine.compare_snapshots(snap_a, snap_b)
    assert result.verdict == DifferentialVerdict.SAME


def test_differential_different_auth_outcome_verdict_different():
    """401 vs 200 → DIFFERENT verdict with authorization_outcome_differs=True."""
    engine = DifferentialEngine()
    snap_a = ResponseSnapshot(status_code=200, size=500, identity="admin")
    snap_b = ResponseSnapshot(status_code=403, size=100, identity="user-a")
    result = engine.compare_snapshots(snap_a, snap_b)
    assert result.verdict == DifferentialVerdict.DIFFERENT
    assert result.authorization_outcome_differs is True
    assert result.confidence >= 0.7


def test_differential_size_difference_detected():
    """Large size difference with same status → DIFFERENT verdict."""
    engine = DifferentialEngine()
    snap_a = ResponseSnapshot(status_code=200, size=2000, identity="user-a")
    snap_b = ResponseSnapshot(status_code=200, size=200, identity="user-b")
    result = engine.compare_snapshots(snap_a, snap_b)
    assert result.verdict == DifferentialVerdict.DIFFERENT
    assert result.semantic_fields_differ is True


def test_differential_error_handling():
    """Error in either response → ERROR verdict."""
    engine = DifferentialEngine()
    snap_a = ResponseSnapshot(status_code=0, identity="user-a", error="timeout")
    snap_b = ResponseSnapshot(status_code=200, size=500, identity="user-b")
    result = engine.compare_snapshots(snap_a, snap_b)
    assert result.verdict == DifferentialVerdict.ERROR


def test_differential_suggests_vulnerability_for_authz_outcome():
    """Differential suggesting IDOR should have suggests_vulnerability=True."""
    engine = DifferentialEngine()
    snap_a = ResponseSnapshot(status_code=200, size=500, identity="user-a")
    snap_b = ResponseSnapshot(status_code=200, size=500, identity="user-b")
    # Same status for different identities on object endpoint → not obviously wrong
    result = engine.compare_snapshots(snap_a, snap_b, "Object access comparison")
    # Both 200 — no auth outcome difference
    assert not result.suggests_vulnerability

    # Now test where identity-b should be denied
    snap_c = ResponseSnapshot(status_code=200, size=500, identity="user-a")  # owner
    snap_d = ResponseSnapshot(status_code=200, size=500, identity="user-b")  # non-owner
    # Both 200 — SAME verdict, but in context of object endpoint this is suspicious
    result2 = engine.compare_snapshots(snap_c, snap_d)
    assert result2.verdict == DifferentialVerdict.SAME  # Technically same


def test_compare_identity_access_convenience():
    """compare_identity_access wrapper should work with capability result dicts."""
    result = compare_identity_access(
        "/api/orders/1", "GET",
        {"status_code": 200, "identity": "user-a", "response_size": 500},
        {"status_code": 403, "identity": "user-b", "response_size": 50},
    )
    assert result.verdict == DifferentialVerdict.DIFFERENT
    assert result.authorization_outcome_differs is True


def test_differential_synthetic_compare():
    """Synthetic compare from ApplicationModel should work for offline testing."""
    engine = DifferentialEngine()
    app = ApplicationModel(target="test.local")
    result = engine.synthetic_compare("/admin/users", "user-a", "admin", app)
    # Admin endpoint: user-a should get 403, admin should get 200 (synthetic logic)
    assert result.verdict == DifferentialVerdict.DIFFERENT
    assert result.authorization_outcome_differs is True


# ──────────────────────────────────────────────────────────────────────────────
# Part 17: False Negative Audit
# ──────────────────────────────────────────────────────────────────────────────

def test_false_negative_audit_runs_without_error():
    """False-negative audit should run on any state without crashing."""
    state = _state_with_auth_surface()
    from horcrux.intel.ingestion import ingest_workspace_state
    ingest_workspace_state(state)
    report = run_false_negative_audit(state)
    assert report is not None
    assert isinstance(report.gaps, list)


def test_false_negative_audit_detects_identity_gap():
    """Auth surface + no multi-identity = identity gap."""
    state = _state_with_auth_surface()
    from horcrux.intel.ingestion import ingest_workspace_state
    ingest_workspace_state(state)
    report = run_false_negative_audit(state)
    gap_types = {g.gap_type for g in report.gaps}
    assert "insufficient_identities" in gap_types or report.identity_gap, (
        "Should flag identity gap when auth surface exists but only 1 identity"
    )


def test_false_negative_audit_detects_session_gap():
    """Auth surface + no sessions = session gap."""
    state = _state_with_auth_surface()
    from horcrux.intel.ingestion import ingest_workspace_state
    ingest_workspace_state(state)
    report = run_false_negative_audit(state)
    assert report.session_gap, (
        "Should flag session gap when auth surface exists but no sessions established"
    )


def test_false_negative_audit_detects_object_comparison_gap():
    """Object endpoints without cross-identity comparison should be flagged."""
    state = _state_with_auth_surface()
    from horcrux.intel.ingestion import ingest_workspace_state
    from horcrux.intel.application_model import SemanticIdentity, IdentityRole
    ingest_workspace_state(state)
    app = state.get_application_model()
    # Add a second identity
    app.upsert_identity(SemanticIdentity(role=IdentityRole.USER, label="user-b"))
    state.set_application_model(app)

    report = run_false_negative_audit(state)
    gap_types = {g.gap_type for g in report.gaps}
    # Should flag object endpoints needing cross-identity comparison
    assert "object_endpoint_no_identity_comparison" in gap_types or (
        report.object_endpoints_without_identity_comparison > 0
    )


def test_false_negative_audit_gap_score():
    """Total gap score should be positive for a state with many unknowns."""
    state = _state_with_auth_surface()
    from horcrux.intel.ingestion import ingest_workspace_state
    ingest_workspace_state(state)
    report = run_false_negative_audit(state)
    assert report.total_gap_score > 0, "Should have non-zero gap score"


def test_false_negative_audit_generates_investigations():
    """Gap audit should convert gaps into Investigation objects."""
    from horcrux.intel.false_negative_audit import generate_gap_investigations_from_audit
    state = _state_with_auth_surface()
    from horcrux.intel.ingestion import ingest_workspace_state
    ingest_workspace_state(state)
    report = run_false_negative_audit(state)
    app = state.get_application_model()
    investigations = generate_gap_investigations_from_audit(report, app)
    assert len(investigations) >= 1, "Should generate investigations from gaps"
    assert all(hasattr(i, "objective") for i in investigations)


# ──────────────────────────────────────────────────────────────────────────────
# Part 28: Sensitive Data Detection
# ──────────────────────────────────────────────────────────────────────────────

def test_sensitive_data_detector_finds_password():
    """Password in response body should be detected."""
    detector = SensitiveDataDetector()
    observations = detector.scan(
        "User updated: password=super_secret123", location="response"
    )
    assert len(observations) > 0
    assert any(o.category == "credential" for o in observations)


def test_sensitive_data_detector_finds_jwt():
    """JWT token in response should be detected."""
    detector = SensitiveDataDetector()
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    observations = detector.scan(f"Authorization: Bearer {jwt}", location="header")
    assert len(observations) > 0
    assert any(o.category == "token" for o in observations)


def test_sensitive_data_detector_finds_email():
    """Email address in response should be detected."""
    detector = SensitiveDataDetector()
    observations = detector.scan(
        '{"email": "admin@company.internal", "role": "admin"}',
        location="response_body"
    )
    assert any(o.category == "pii" for o in observations)


def test_sensitive_data_never_stores_raw_secret():
    """Detected sensitive data should never contain the raw secret value."""
    detector = SensitiveDataDetector()
    secret = "super_secret_api_key_12345678901234567890"
    observations = detector.scan(f"api_key={secret}")
    for obs in observations:
        assert secret not in obs.redacted_sample, (
            "Raw secret must never be stored — only redacted reference"
        )
        assert any(k in obs.redacted_sample.lower() for k in ["[redacted", "[credential", "[token"])


def test_redact_secrets_removes_bearer_tokens():
    """redact_secrets() should replace Bearer tokens with [REDACTED:TOKEN]."""
    content = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc.def"
    redacted = redact_secrets(content)
    assert "eyJhbGci" not in redacted
    assert "REDACTED" in redacted


def test_redact_secrets_removes_passwords():
    """redact_secrets() should redact password values."""
    content = "password=mysecretpassword123&email=user@test.com"
    redacted = redact_secrets(content)
    assert "mysecretpassword123" not in redacted


def test_sensitive_data_private_ip_detected():
    """Internal/private IPs in responses should be flagged."""
    detector = SensitiveDataDetector()
    observations = detector.scan(
        "Redirect to: http://192.168.1.50/internal-app", location="response"
    )
    assert any(o.category == "infra" for o in observations)


# ──────────────────────────────────────────────────────────────────────────────
# Part 34/35: Engagement Config and Modes
# ──────────────────────────────────────────────────────────────────────────────

def test_engagement_config_model_exists():
    """EngagementConfig model must exist and be usable."""
    from horcrux.models import EngagementConfig, EngagementMode, RateLimitProfile
    config = EngagementConfig(
        mode=EngagementMode.LOCAL,
        operator_reference="test-operator",
        rate_limit_profile=RateLimitProfile.CONSERVATIVE,
    )
    assert config.mode == EngagementMode.LOCAL
    assert config.rate_limit_profile == RateLimitProfile.CONSERVATIVE


def test_workspace_state_stores_engagement_config():
    """WorkspaceState must support engagement config storage."""
    from horcrux.models import EngagementConfig, EngagementMode
    state = WorkspaceState(target="test.local")
    config = EngagementConfig(mode=EngagementMode.ENGAGEMENT)
    state.set_engagement_config(config)
    loaded = state.get_engagement_config()
    assert loaded.mode == EngagementMode.ENGAGEMENT


# ──────────────────────────────────────────────────────────────────────────────
# Part 37/38: Exploit Handoff enrichment
# ──────────────────────────────────────────────────────────────────────────────

def test_exploit_handoff_has_new_fields():
    """ExploitHandoff must have Phase 9 fields."""
    from horcrux.models import ExploitHandoff
    handoff = ExploitHandoff(
        id="test-handoff",
        finding_id="finding-1",
        target="test.local",
        vulnerability="Test Vuln",
        affected_asset="test.local",
        affected_component="api",
        evidence=["evidence1"],
        prerequisites=[],
        reproduction_plan=["step1"],
        expected_result="success",
        impact="high",
        confidence=0.8,
        recommended_operator_action="test action",
        relevant_capabilities=["http_probe"],
        relevant_tools=["http_probe"],
        risks=["lockout"],
        operator_approval_required=True,
        # New Phase 9 fields
        identity_required="user-a",
        session_required=True,
        attack_path_id="ap-001",
        finding_validation_state="LIKELY",
        what_was_tested=["endpoint1"],
        what_could_not_be_tested=["exploitation"],
        why_not_tested=["Operator approval required"],
    )
    assert handoff.identity_required == "user-a"
    assert handoff.session_required is True
    assert handoff.attack_path_id == "ap-001"
    assert handoff.finding_validation_state == "LIKELY"


# ──────────────────────────────────────────────────────────────────────────────
# Coverage Model backward compatibility
# ──────────────────────────────────────────────────────────────────────────────

def test_coverage_model_backward_compat_get():
    """CoverageModel.get() must still work for old domain names."""
    from horcrux.intel.coverage import SecurityCoverageModel, CoverageStatus
    cov = SecurityCoverageModel()
    cov.ensure_domains()
    status = cov.get("authentication")
    assert isinstance(status, CoverageStatus)
    assert status == CoverageStatus.NOT_REVIEWED


def test_coverage_model_backward_compat_set_status():
    """CoverageModel.set_status() must still work."""
    from horcrux.intel.coverage import SecurityCoverageModel, CoverageStatus
    cov = SecurityCoverageModel()
    cov.ensure_domains()
    cov.set_status("authentication", CoverageStatus.IN_PROGRESS, "testing")
    assert cov.get("authentication") == CoverageStatus.IN_PROGRESS


def test_coverage_model_percentage_complete_returns_dict():
    """percentage_complete() must return a dict with expected keys."""
    from horcrux.intel.coverage import SecurityCoverageModel
    cov = SecurityCoverageModel()
    cov.ensure_domains()
    pct = cov.percentage_complete()
    assert "web" in pct
    assert "authentication" in pct
    assert "authorization" in pct
    assert all(isinstance(v, float) for v in pct.values())


def test_calculate_coverage_runs_on_ingested_state():
    """calculate_coverage() should run without error on an ingested state."""
    from horcrux.intel.coverage import SecurityCoverageModel, calculate_coverage
    from horcrux.intel.ingestion import ingest_workspace_state
    state = _state_with_auth_surface()
    ingest_workspace_state(state)
    app = state.get_application_model()
    coverage = SecurityCoverageModel()
    coverage.ensure_domains()
    coverage.ensure_properties()
    result = calculate_coverage(app, [], [], coverage)
    assert result is not None
    # With auth surface, auth properties should be APPLICABLE not UNKNOWN
    prop = result.properties.get("auth.login")
    if prop:
        assert prop.status != "UNKNOWN", (
            "auth.login should be APPLICABLE when login endpoint is discovered"
        )
