"""Phase 9 Juice Shop Benchmark Test (Part 40).

Tests the end-to-end benchmark against the rich Juice-Shop-like fixture:
- Discovers routes, objects, identities, technologies
- Runs reassessment and hypothesis generation
- Scores against ground truth
- Verifies that an uninvestigated or partially investigated state
  is NEVER falsely declared COMPLETE.
"""

from __future__ import annotations

import pytest

from horcrux.agents.lifecycle import reassess
from horcrux.bench.fixtures import FIXTURES
from horcrux.intel.coverage import assessment_completeness
from tests.fixtures.juice_shop_like import (
    JUICE_SHOP_GROUND_TRUTH,
    build_juice_shop_fixture,
    score_fixture_assessment,
)


def test_juice_shop_fixture_builds_correctly():
    """Fixture should build with expected base assets."""
    state = build_juice_shop_fixture()
    assert state.target == "juice-shop.local"
    assert len(state.discovered_paths) >= 30
    assert len(state.parameters) >= 10
    assert len(state.normalized_technologies) >= 3
    assert len(state.credentials) >= 2


def test_juice_shop_reassessment_discovers_surface():
    """Running reassess on juice shop fixture must discover deep attack surface."""
    state = build_juice_shop_fixture()
    state = reassess(state)

    app = state.get_application_model()
    # Endpoints
    assert len(app.endpoints) >= 25, f"Expected 25+ endpoints, got {len(app.endpoints)}"
    # Object types inferred
    assert len(app.object_types) >= 3, f"Expected 3+ object types, got {len(app.object_types)}"
    # Authentication mechanisms inferred
    assert len(app.authentication) >= 1, "Expected authentication mechanism"
    # Hypotheses generated
    hyps = state.get_hypotheses()
    assert len(hyps) >= 5, f"Expected 5+ hypotheses, got {len(hyps)}"
    # Hypothesis classes
    classes = {h.hypothesis_class.value for h in hyps}
    assert "idor_bola" in classes, "Expected IDOR/BOLA hypothesis"
    assert "privilege_escalation" in classes, "Expected privilege escalation hypothesis"


def test_juice_shop_benchmark_scoring():
    """Score the reassessed juice shop fixture against ground truth."""
    state = build_juice_shop_fixture()
    state = reassess(state)

    score = score_fixture_assessment(state)
    assert score["endpoint_recall"] >= 0.5
    assert score["hypothesis_recall"] >= 0.5
    assert score["hypothesis_class_coverage"] >= 0.4
    # The assessment must NOT be complete since investigations haven't finished
    assert score["coverage_verdict"] != "COMPLETE"


def test_juice_shop_assessment_never_prematurely_complete():
    """Juice shop with many untested properties must NEVER have sufficient=True."""
    state = build_juice_shop_fixture()
    state = reassess(state)

    comp = assessment_completeness(state)
    assert not comp["sufficient"], (
        "CRITICAL: Juice Shop assessment must not be sufficient without "
        "comprehensive investigation of its extensive attack surface."
    )
    assert comp["verdict"] in ("INCOMPLETE", "LIMITED", "BLOCKED")
    assert len(comp["blocking_reasons"]) > 0


def test_juice_shop_generates_diverse_investigations():
    """Reassessment of Juice Shop must generate investigations across multiple domains."""
    state = build_juice_shop_fixture()
    state = reassess(state)

    invs = state.get_investigations()
    assert len(invs) >= 5, f"Expected 5+ investigations, got {len(invs)}"
    specialists = {i.specialist for i in invs}
    # Should include AuthorizationAgent and/or WebAgent
    assert "AuthorizationAgent" in specialists or "WebAgent" in specialists
