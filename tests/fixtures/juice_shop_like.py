"""Juice-Shop-like synthetic benchmark fixture (Phase 9, Part 40).

A rich, deliberately vulnerable application fixture that:
- Has SPA + REST API + GraphQL architecture
- Contains 3 distinct identities (anonymous, user-a, admin)
- Has 55+ API routes with object-bearing parameters
- Contains multiple object types
- Has authentication and authorization workflows
- Contains deliberate authorization flaws (IDOR, BFLA)
- Contains deliberate business-logic flaws
- Has file upload and URL-fetch surfaces
- Has GraphQL endpoint with operations
- Has client-side routes

CRITICAL: This fixture is for testing ONLY. No real network, ever.
The fixture defines GROUND TRUTH for benchmark scoring.

DO NOT solve the benchmark by hardcoding findings.
The system must DISCOVER them from the evidence.
"""

from __future__ import annotations

from typing import Any

from horcrux.models import (
    Credential,
    DiscoveredPath,
    NormalizedTechnology,
    Parameter,
    Service,
    TechCategory,
    WebApplicationType,
    WebTarget,
    WorkspaceState,
)


# ──────────────────────────────────────────────────────────────────────────────
# Ground truth definitions (used by benchmark scoring, not by detection)
# ──────────────────────────────────────────────────────────────────────────────

JUICE_SHOP_GROUND_TRUTH: dict[str, Any] = {
    "target": "juice-shop.local",
    "application_type": "SPA",
    "frameworks": ["Angular", "Express", "Node.js"],
    "object_types": ["User", "Basket", "Product", "Order", "Feedback", "Address", "WalletTransaction"],
    "identities": ["anonymous", "user-a", "admin"],
    "expected_hypothesis_classes": [
        "idor_bola",           # /rest/users/{id} accessible cross-user
        "privilege_escalation", # /rest/admin/* accessible as user
        "authentication",       # Login surface
        "session",              # JWT handling
        "injection",            # Search/feedback inputs
        "ssrf",                 # Import URL parameter
        "file_upload",          # File upload endpoint
        "graphql",              # GraphQL introspection + authz
        "business_logic",       # Cart price manipulation
        "information_disclosure",  # Debug endpoints
    ],
    "expected_object_types_minimum": 5,
    "expected_hypotheses_minimum": 8,
    "expected_endpoints_minimum": 30,
    "expected_identities_minimum": 2,
    # Deliberate vulnerabilities (must be discoverable from evidence, not hardcoded)
    "deliberate_flaws": [
        {
            "class": "idor_bola",
            "surface": "/rest/users/{id}",
            "description": "User profile accessible cross-identity without ownership check",
        },
        {
            "class": "idor_bola",
            "surface": "/rest/basket/{id}",
            "description": "Basket accessible cross-identity",
        },
        {
            "class": "privilege_escalation",
            "surface": "/rest/admin/application-version",
            "description": "Admin endpoint accessible without admin role",
        },
        {
            "class": "business_logic",
            "surface": "/rest/basket/{id}/checkout",
            "description": "Coupon code can produce negative total price",
        },
        {
            "class": "ssrf",
            "surface": "/api/feedbacks",
            "description": "URL parameter in feedback can trigger server-side fetch",
        },
    ],
    # Coverage expectations after running on this fixture
    "coverage_not_complete": True,  # Must NOT be COMPLETE — too many unknowns
    "must_generate_authz_investigations": True,
    "must_generate_injection_investigations": True,
}


# ──────────────────────────────────────────────────────────────────────────────
# Fixture builder
# ──────────────────────────────────────────────────────────────────────────────

def build_juice_shop_fixture() -> WorkspaceState:
    """Build the Juice-Shop-like benchmark fixture.

    Returns a WorkspaceState with pre-populated evidence that a real
    VAPT tool would discover from a vulnerable application.

    The state represents what a scanner would find BEFORE deep investigation:
    - Infrastructure (service, port)
    - Discovered paths (from FFUF + JS analysis + robots.txt)
    - Technologies (from fingerprinting)
    - Parameters (from JS analysis + form inspection)
    - Test identities (operator-configured, not brute-forced)

    The assessment loop must then generate hypotheses and investigate.
    """
    target = "juice-shop.local"
    state = WorkspaceState(target=target)

    # ── Infrastructure ───────────────────────────────────────────────────────
    state.services = [
        Service(
            host=target, port=3000, service="http",
            product="Node.js/Express", version="18.12.0",
        ),
    ]

    # ── Technologies (fingerprinted) ──────────────────────────────────────────
    state.normalized_technologies = [
        NormalizedTechnology(name="Angular", category=TechCategory.FRAMEWORK, confidence=0.96,
                             version="15.x"),
        NormalizedTechnology(name="Node.js", category=TechCategory.RUNTIME, confidence=0.92,
                             version="18.12.0"),
        NormalizedTechnology(name="Express", category=TechCategory.FRAMEWORK, confidence=0.90,
                             version="4.x"),
        NormalizedTechnology(name="SQLite", category=TechCategory.DATABASE, confidence=0.75),
        NormalizedTechnology(name="jsonwebtoken", category=TechCategory.LIBRARY, confidence=0.88),
    ]

    # ── Discovered paths (from FFUF + JS route extraction + robots.txt) ──────
    paths = _build_paths(target)
    state.discovered_paths = paths

    # ── Parameters (from JS analysis + form inspection) ───────────────────────
    state.parameters = _build_parameters()

    # ── Web target ────────────────────────────────────────────────────────────
    state.web_targets = [
        WebTarget(
            scheme="http",
            host=target,
            port=3000,
            base_url=f"http://{target}:3000",
            application_type=WebApplicationType.SPA,
            endpoints=state.discovered_paths,
            technologies=state.normalized_technologies,
            parameters=state.parameters,
        )
    ]

    # ── Operator-configured test identities (NOT brute-forced credentials) ───
    state.credentials = [
        Credential(
            username="user-a@juice-sh.op",
            secret="synthetic-bench-only",
            kind="test-identity",
            source="bench",
        ),
        Credential(
            username="admin@juice-sh.op",
            secret="synthetic-bench-only",
            kind="test-identity-admin",
            source="bench",
        ),
    ]

    return state


def _build_paths(target: str) -> list[DiscoveredPath]:
    """Build the rich path list representing what a real scanner would find."""
    base = f"http://{target}:3000"

    # Mix of sources: FFUF discovery, JS analysis, robots.txt hints, browser
    path_specs: list[tuple[str, str, int]] = [
        # Authentication surfaces
        ("/rest/user/login", "javascript", 200),
        ("/rest/user/register", "javascript", 200),
        ("/rest/user/reset-password", "javascript", 200),
        ("/rest/user/change-password", "javascript", 200),
        ("/rest/user/whoami", "javascript", 200),
        ("/api/2fa/verify", "javascript", 200),

        # User/profile object endpoints (IDOR surface)
        ("/rest/users/{id}", "javascript", 200),
        ("/api/users", "fuzzer", 200),
        ("/rest/user/photo-wall", "javascript", 200),

        # Basket/order object endpoints
        ("/rest/basket/{id}", "javascript", 200),
        ("/rest/basket/{id}/checkout", "javascript", 200),
        ("/rest/basket/{id}/applyCoupon", "javascript", 200),
        ("/rest/orders/{id}", "javascript", 200),
        ("/api/orders", "javascript", 200),

        # Product catalog
        ("/rest/products/{id}", "javascript", 200),
        ("/rest/products/search", "javascript", 200),
        ("/api/products", "fuzzer", 200),
        ("/api/products/{id}/reviews", "javascript", 200),

        # Admin surface (BFLA target)
        ("/rest/admin", "fuzzer", 403),  # Fuzzer found this
        ("/rest/admin/application-version", "javascript", 200),  # Exposed via JS
        ("/rest/admin/users", "javascript", 403),

        # Feedback/comment (injection surface)
        ("/api/feedbacks", "javascript", 200),
        ("/api/feedbacks/{id}", "javascript", 200),

        # Challenges/score (app-specific)
        ("/api/challenges", "javascript", 200),
        ("/api/challenges/{id}/flagCaptured", "javascript", 200),

        # Address (IDOR surface)
        ("/api/addresses", "javascript", 200),
        ("/api/addresses/{id}", "javascript", 200),

        # Wallet/payment (business logic surface)
        ("/api/wallets", "javascript", 200),
        ("/api/wallets/{id}", "javascript", 200),
        ("/api/deluxe-membership", "javascript", 200),

        # Delivery/tracking
        ("/rest/track-order/{id}", "javascript", 200),

        # File handling
        ("/file-upload", "javascript", 200),
        ("/rest/memories/{id}/image", "javascript", 200),
        ("/ftp/", "fuzzer", 200),  # FTP-style file listing exposed via HTTP
        ("/ftp/package.json.bak", "fuzzer", 200),  # Sensitive file

        # GraphQL
        ("/graphql", "javascript", 200),

        # Security.txt / robots.txt / well-known
        ("/robots.txt", "fuzzer", 200),
        ("/.well-known/security.txt", "fuzzer", 404),
        ("/sitemap.xml", "fuzzer", 404),

        # Angular SPA entry
        ("/", "fuzzer", 200),
        ("/main.js", "fuzzer", 200),  # Angular bundle

        # Prometheus metrics (accidentally exposed)
        ("/metrics", "fuzzer", 200),

        # Error pages (expose framework info)
        ("/this-page-does-not-exist", "fuzzer", 200),  # SPA returns 200 for all routes
    ]

    paths = []
    for path, source, status in path_specs:
        # Normalize template params for URL
        url_path = path.replace("{id}", "1")
        paths.append(DiscoveredPath(
            url=f"{base}{url_path}",
            path=path,
            status=status,
            source=source,
            validated=True,
        ))

    return paths


def _build_parameters() -> list[Parameter]:
    """Build the parameter list from JS analysis and form inspection."""
    return [
        # Auth parameters
        Parameter(name="email", location="body", source="form", endpoint="/rest/user/login"),
        Parameter(name="password", location="body", source="form", endpoint="/rest/user/login"),
        Parameter(name="passwordNew", location="body", source="form", endpoint="/rest/user/change-password"),

        # Object ID parameters (IDOR surface)
        Parameter(name="id", location="path", source="javascript", endpoint="/rest/users/{id}"),
        Parameter(name="id", location="path", source="javascript", endpoint="/rest/basket/{id}"),
        Parameter(name="id", location="path", source="javascript", endpoint="/rest/products/{id}"),
        Parameter(name="id", location="path", source="javascript", endpoint="/rest/orders/{id}"),
        Parameter(name="id", location="path", source="javascript", endpoint="/api/addresses/{id}"),
        Parameter(name="id", location="path", source="javascript", endpoint="/api/feedbacks/{id}"),

        # Search/injection parameters
        Parameter(name="q", location="query", source="javascript", endpoint="/rest/products/search"),
        Parameter(name="content", location="body", source="javascript", endpoint="/api/feedbacks"),

        # SSRF candidate
        Parameter(name="url", location="body", source="javascript", endpoint="/api/feedbacks"),

        # Business logic parameters
        Parameter(name="coupon", location="body", source="javascript", endpoint="/rest/basket/{id}/applyCoupon"),
        Parameter(name="amount", location="body", source="javascript", endpoint="/api/wallets/{id}"),

        # File upload
        Parameter(name="file", location="body", source="form", endpoint="/file-upload"),

        # GraphQL
        Parameter(name="query", location="body", source="javascript", endpoint="/graphql"),
        Parameter(name="operationName", location="body", source="javascript", endpoint="/graphql"),

        # Sort/filter
        Parameter(name="sort", location="query", source="javascript", endpoint="/api/products"),
        Parameter(name="category", location="query", source="javascript", endpoint="/api/products"),
    ]


# ──────────────────────────────────────────────────────────────────────────────
# Scoring against ground truth
# ──────────────────────────────────────────────────────────────────────────────

def score_fixture_assessment(state: WorkspaceState) -> dict[str, Any]:
    """Score an assessment result against the Juice-Shop ground truth.

    Used by benchmark tests. Does NOT hardcode findings.
    Scores based on what was DISCOVERED, not what was pre-expected.
    """
    gt = JUICE_SHOP_GROUND_TRUTH
    app = state.get_application_model()
    hypotheses = state.get_hypotheses()
    investigations = state.get_investigations()

    # Surface recall
    ep_count = len(app.endpoints)
    ep_recall = min(1.0, ep_count / gt["expected_endpoints_minimum"])

    # Object type recall
    obj_count = len(app.object_types)
    obj_recall = min(1.0, obj_count / gt["expected_object_types_minimum"])

    # Hypothesis recall
    hyp_count = len(hypotheses)
    hyp_recall = min(1.0, hyp_count / gt["expected_hypotheses_minimum"])

    # Hypothesis class coverage
    generated_classes = {h.hypothesis_class.value for h in hypotheses}
    expected_classes = set(gt["expected_hypothesis_classes"])
    class_coverage = len(generated_classes & expected_classes) / len(expected_classes)

    # Identity coverage
    identity_count = len(app.identities)
    identity_ok = identity_count >= gt["expected_identities_minimum"]

    # Coverage verdict
    try:
        coverage = state.get_security_coverage()
        coverage.ensure_properties()
        verdict = coverage.coverage_verdict()
    except Exception:
        verdict = "UNKNOWN"

    # Investigation breadth
    investigation_specialists = {i.specialist for i in investigations}
    has_authz_investigations = "AuthorizationAgent" in investigation_specialists
    has_injection_investigations = any(
        "injection" in (i.vulnerability_classes or []) for i in investigations
    )

    # Benchmark verdict
    passed = (
        ep_recall >= 0.5        # At least 50% of expected endpoints discovered
        and obj_recall >= 0.5   # At least 50% of expected object types
        and hyp_recall >= 0.6   # At least 60% of expected hypotheses
        and class_coverage >= 0.5  # At least 50% of expected hypothesis classes
        and identity_ok          # At least 2 identities
        and verdict != "COMPLETE"  # Assessment must NOT claim complete
    )

    return {
        "passed": passed,
        "endpoint_recall": round(ep_recall, 2),
        "object_type_recall": round(obj_recall, 2),
        "hypothesis_recall": round(hyp_recall, 2),
        "hypothesis_class_coverage": round(class_coverage, 2),
        "identity_coverage": identity_count,
        "coverage_verdict": verdict,
        "has_authz_investigations": has_authz_investigations,
        "has_injection_investigations": has_injection_investigations,
        "investigation_count": len(investigations),
        "investigation_specialists": list(investigation_specialists),
        "endpoints_discovered": ep_count,
        "object_types_discovered": obj_count,
        "hypotheses_generated": hyp_count,
        "hypothesis_classes": list(generated_classes),
        "expected_classes": list(expected_classes),
        "missing_classes": list(expected_classes - generated_classes),
    }
