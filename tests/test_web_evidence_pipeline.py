from __future__ import annotations

import httpx
from unittest.mock import MagicMock, patch

from horcrux.models import (
    BaselineClassification,
    DiscoveredPath,
    EvidenceClassification,
    NormalizedTechnology,
    Parameter,
    RawObservation,
    ResponseFamily,
    ResponseFingerprint,
    Service,
    SubsystemState,
    TechCategory,
    ValidationState,
    WebApplicationType,
    WebTarget,
    WorkspaceState,
)
from horcrux.modules.web.fingerprint_engine import (
    cluster_response_families,
    fingerprint_response,
    normalize_dynamic_content,
    same_response_family,
)
from horcrux.modules.web.baseline import detect_baseline
from horcrux.modules.web.tech_normalizer import (
    BLACKLIST_SCANNER_LABELS,
    normalize_technologies,
)
from horcrux.modules.web.js_analyzer import (
    analyze_javascript_content,
    extract_html_inputs,
    extract_script_urls,
)
from horcrux.core.actions import evaluate_next_actions
from horcrux.intel.tasks.triage import build_compact_state
from horcrux.intel.tasks.ask import build_bounded_workspace_context


def test_dynamic_content_normalization():
    # Content with dynamic UUIDs, timestamps, tokens
    content_a = """
    <html>
      <head><meta name="csrf-token" content="abc123xyz789deadbeef"></head>
      <body>
        <div>Session ID: 123e4567-e89b-12d3-a456-426614174000</div>
        <span>Rendered at: 2026-09-04T12:30:45Z</span>
        <input type="hidden" name="nonce" value="n-987654321">
      </body>
    </html>
    """
    content_b = """
    <html>
      <head><meta name="csrf-token" content="fedcba9876543210cafe"></head>
      <body>
        <div>Session ID: 987fcdeb-51a2-43d2-b789-0123456789ab</div>
        <span>Rendered at: 2026-09-04T12:35:10Z</span>
        <input type="hidden" name="nonce" value="n-123456789">
      </body>
    </html>
    """
    norm_a = normalize_dynamic_content(content_a)
    norm_b = normalize_dynamic_content(content_b)
    # After stripping UUIDs, timestamps, and tokens, structures should be identical
    assert norm_a == norm_b


def test_same_response_family_matching():
    fp_a = fingerprint_response(
        status_code=200,
        headers={"content-type": "text/html", "server": "nginx"},
        text="""<html><head><title>App</title></head><body><div id="root">App Shell</div></body></html>""",
        url="http://target.local/",
    )
    # Near identical SPA fallback with different path
    fp_b = fingerprint_response(
        status_code=200,
        headers={"content-type": "text/html", "server": "nginx"},
        text="""<html><head><title>App</title></head><body><div id="root">App Shell</div><!-- ts: 1693800000 --></body></html>""",
        url="http://target.local/some-random-route",
    )
    # Distinct 404 page
    fp_c = fingerprint_response(
        status_code=404,
        headers={"content-type": "text/html", "server": "nginx"},
        text="""<html><body><h1>404 Not Found</h1><p>Resource missing</p></body></html>""",
        url="http://target.local/missing",
    )

    assert same_response_family(fp_a, fp_b) is True
    assert same_response_family(fp_a, fp_c) is False


def test_cluster_response_families_and_suppression():
    # Simulate an SPA catch-all where 10 probes all return the same SPA shell
    fingerprints: list[ResponseFingerprint] = []
    spa_body = "<html><head><title>Single Page App</title></head><body><div id='app'></div></body></html>"
    for i in range(10):
        fp = fingerprint_response(
            status_code=200,
            headers={"content-type": "text/html"},
            text=spa_body + f"<!-- noise {i} -->",
            url=f"http://target.local/probe-{i}",
        )
        fingerprints.append(fp)

    # Add 1 distinct response (e.g. real API endpoint returning JSON)
    api_fp = fingerprint_response(
        status_code=200,
        headers={"content-type": "application/json"},
        text='{"status": "ok", "version": "1.0.0"}',
        url="http://target.local/api/health",
    )
    fingerprints.append(api_fp)

    families, path_map = cluster_response_families(fingerprints)
    # Should create 2 distinct families
    assert len(families) == 2

    # The SPA family should have 10 occurrences
    spa_family = max(families, key=lambda f: f.member_count)
    assert spa_family.member_count == 10
    assert any("/probe-" in p for p in spa_family.representative_paths)

    api_family = min(families, key=lambda f: f.member_count)
    assert api_family.member_count == 1
    assert any("/api/health" in p for p in api_family.representative_paths)


def test_probe_web_baseline_spa_fallback():
    # Mock HTTP client returning root SPA page for all random probes
    spa_html = "<html><head><title>SPA App</title></head><body><div id='root'></div></body></html>"

    def mock_handler(request: httpx.Request):
        return httpx.Response(200, text=spa_html, headers={"content-type": "text/html"}, request=request)

    transport = httpx.MockTransport(mock_handler)
    with httpx.Client(transport=transport) as client:
        baseline_class, fps, app_type = detect_baseline(client, "http://target.local:3000")

    assert baseline_class == BaselineClassification.SPA_FALLBACK
    assert app_type == WebApplicationType.SPA
    assert len(fps) > 0


def test_probe_web_baseline_normal_404():
    # Mock HTTP client returning standard 404 for missing resources
    def mock_handler(request: httpx.Request):
        if request.url.path == "/":
            return httpx.Response(200, text="Welcome Home", headers={"content-type": "text/html"}, request=request)
        return httpx.Response(404, text="404 Not Found", headers={"content-type": "text/html"}, request=request)

    transport = httpx.MockTransport(mock_handler)
    with httpx.Client(transport=transport) as client:
        baseline_class, fps, app_type = detect_baseline(client, "http://target.local:80")

    assert baseline_class == BaselineClassification.NORMAL_404
    assert app_type in (WebApplicationType.STATIC_SITE, WebApplicationType.TRADITIONAL_WEB_APP)


def test_technology_normalization_filters_whatweb_labels():
    raw_obs = [
        RawObservation(source_tool="whatweb", observation_type="whatweb_plugin", target="http://10.0.0.1:80", data={"plugin": "Country", "value": "UNITED STATES"}),
        RawObservation(source_tool="whatweb", observation_type="whatweb_plugin", target="http://10.0.0.1:80", data={"plugin": "HTML5", "value": ""}),
        RawObservation(source_tool="whatweb", observation_type="whatweb_plugin", target="http://10.0.0.1:80", data={"plugin": "IP", "value": "10.0.0.1"}),
        RawObservation(source_tool="whatweb", observation_type="whatweb_plugin", target="http://10.0.0.1:80", data={"plugin": "Script", "value": ""}),
        RawObservation(source_tool="whatweb", observation_type="whatweb_plugin", target="http://10.0.0.1:80", data={"plugin": "Title", "value": "Login"}),
        RawObservation(source_tool="whatweb", observation_type="whatweb_plugin", target="http://10.0.0.1:80", data={"plugin": "UncommonHeaders", "value": "x-foo"}),
        RawObservation(source_tool="whatweb", observation_type="whatweb_plugin", target="http://10.0.0.1:80", data={"plugin": "Apache", "version": "2.4.52", "value": "Apache/2.4.52"}),
        RawObservation(source_tool="whatweb", observation_type="whatweb_plugin", target="http://10.0.0.1:80", data={"plugin": "PHP", "version": "8.1.2", "value": "PHP/8.1.2"}),
    ]

    normalized = normalize_technologies(raw_obs)
    tech_names = [t.name.lower() for t in normalized]

    # Verify blacklisted labels are omitted
    for label in BLACKLIST_SCANNER_LABELS:
        assert label.lower() not in tech_names

    # Verify legitimate technologies are recognized with categories
    assert any("apache" in name for name in tech_names)
    assert "php" in tech_names
    apache_tech = next(t for t in normalized if "apache" in t.name.lower())
    assert apache_tech.category == TechCategory.WEBSERVER
    assert apache_tech.version == "2.4.52"


def test_javascript_analyzer_routes_and_parameters():
    js_content = """
    function fetchUserData(userId) {
        return fetch('/api/v1/users/' + userId + '?fields=profile,settings', {
            method: 'POST',
            body: JSON.stringify({ authToken: token, role: 'admin' })
        });
    }
    const apiUrl = '/rest/v2/authenticate';
    axios.get('/api/search', { params: { query: 'test', page: 1 } });
    """
    results = analyze_javascript_content(js_content, "main.js")
    routes = results["routes"]
    params = results["parameters"]

    assert "/api/v1/users" in routes or any("/api/v1/users" in r for r in routes)
    assert any("authenticate" in r for r in routes)
    assert any("query" == p["name"] for p in params)
    assert any("token" in p["name"].lower() or "role" in p["name"].lower() for p in params)


def test_html_form_input_extraction():
    html = """
    <form action="/login" method="POST">
        <input type="text" name="username" placeholder="Username" />
        <input type="password" name="password" />
        <input type="hidden" name="csrf_token" value="abc" />
        <button type="submit">Sign In</button>
    </form>
    """
    inputs = extract_html_inputs(html, "/login")
    input_names = [i["name"] for i in inputs]
    assert "username" in input_names
    assert "password" in input_names
    assert "csrf_token" in input_names


def test_actions_parameter_fuzzing_evidence_gating():
    # Case 1: Workspace with web service and endpoints, but NO discovered parameters
    state_no_params = WorkspaceState(
        target="10.0.0.1",
        services=[Service(host="10.0.0.1", port=80, protocol="tcp", service="http")],
        discovered_paths=[
            DiscoveredPath(url="http://10.0.0.1/about", path="/about", status=200, size=500, validated=True, validation_state=ValidationState.confirmed)
        ],
        web_targets=[
            WebTarget(
                host="10.0.0.1",
                port=80,
                endpoints=[DiscoveredPath(url="http://10.0.0.1/about", path="/about", status=200, size=500, validated=True)],
                parameters=[],  # NO parameters discovered
            )
        ],
    )
    state_no_params.set_subsystem_state("web_enum", SubsystemState.COMPLETE)
    actions_no_params = evaluate_next_actions(state_no_params)
    param_actions = [a for a in actions_no_params if "parameter" in a.id.lower() or "parameter" in a.title.lower()]
    assert len(param_actions) == 0, "Parameter fuzzing should NOT be recommended without parameter evidence"

    # Case 2: Workspace with discovered parameters
    state_with_params = WorkspaceState(
        target="10.0.0.1",
        services=[Service(host="10.0.0.1", port=80, protocol="tcp", service="http")],
        parameters=[Parameter(name="id", location="query", endpoints=["/api/users"])],
        web_targets=[
            WebTarget(
                host="10.0.0.1",
                port=80,
                endpoints=[DiscoveredPath(url="http://10.0.0.1/api/users", path="/api/users", status=200, size=500, validated=True)],
                parameters=[Parameter(name="id", location="query", endpoints=["/api/users"])],
            )
        ],
    )
    state_with_params.set_subsystem_state("web_enum", SubsystemState.COMPLETE)
    actions_with_params = evaluate_next_actions(state_with_params)
    param_actions_2 = [a for a in actions_with_params if "parameter" in a.id.lower() or "parameter" in a.title.lower()]
    assert len(param_actions_2) > 0, "Parameter fuzzing SHOULD be recommended when parameter evidence exists"


def test_ai_compact_state_and_bounded_context():
    state = WorkspaceState(
        target="10.0.0.5",
        services=[
            Service(host="10.0.0.5", port=80, protocol="tcp", service="http", product="nginx", version="1.24.0"),
            Service(host="10.0.0.5", port=8080, protocol="tcp", service="http", product="node.js", version="18.16.0"),
        ],
        web_targets=[
            WebTarget(
                host="10.0.0.5",
                port=80,
                application_type=WebApplicationType.SPA,
                baseline_classification=BaselineClassification.SPA_FALLBACK,
                endpoints=[
                    DiscoveredPath(url="http://10.0.0.5:80/", path="/", status=200, size=1200),
                    DiscoveredPath(url="http://10.0.0.5:80/api/login", path="/api/login", status=200, size=300),
                ],
                parameters=[Parameter(name="username", location="body"), Parameter(name="password", location="body")],
            ),
            WebTarget(
                host="10.0.0.5",
                port=8080,
                application_type=WebApplicationType.API,
                baseline_classification=BaselineClassification.NORMAL_404,
                endpoints=[
                    DiscoveredPath(url="http://10.0.0.5:8080/v1/health", path="/v1/health", status=200, size=50),
                ],
            ),
        ],
    )

    # 1. Compact state used for AI tasks
    compact = build_compact_state(state)
    assert "web_targets" in compact
    assert len(compact["web_targets"]) == 2
    assert compact["web_targets"][0]["port"] == 80
    assert compact["web_targets"][0]["app_type"] == "SPA"
    assert compact["web_targets"][0]["baseline"] == "SPA_FALLBACK"
    assert compact["web_targets"][0]["parameters"] == ["username", "password"]

    # 2. Bounded context used for operator ask
    bounded = build_bounded_workspace_context(state, "What web targets exist?")
    assert "web_targets" in bounded
    assert len(bounded["web_targets"]) == 2
    assert bounded["web_targets"][0]["port"] == 80
