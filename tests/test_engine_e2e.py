"""Engine end-to-end: observations -> findings with chains, AI disabled.

Proves HORCRUX converts collected observations into security conclusions
without any AI provider.
"""
from __future__ import annotations


def _obs(endpoint, parameter, body, entities, status=200, identity="anonymous"):
    from horcrux.engine.observations import observe_http
    ob = observe_http(source="native", target="t.local", endpoint=endpoint,
                      method="GET", status=status, body=body, identity=identity,
                      parameter=parameter)
    ob.extracted_entities.update(entities)
    return ob


def test_e2e_sqli_finding_with_chain_no_ai():
    import pathlib
    import re
    # Static guarantee: no engine module may import AI providers. The
    # detector path works with AI fully disabled by construction.
    engine_dir = pathlib.Path("horcrux/engine")
    assert engine_dir.is_dir()
    bad = []
    for py in sorted(engine_dir.glob("*.py")):
        src = py.read_text(encoding="utf-8")
        if re.search(r"from\s+horcrux\.intel\.ai\s+import|from\s+horcrux\.intel\.groq\s+import|import\s+anthropic|import\s+openai", src):
            bad.append(py.name)
    assert bad == [], f"engine must not import AI: {bad}"
    from horcrux.engine.assess import assess_workspace_observations
    base = _obs("/search", "q", '{"data":[]}', {"role": "baseline"})
    mut = _obs("/search", "q", 'sqlite3 syntax error near "x"',
               {"properties": ["INJECT_SQL"], "repeatable": True})
    out = assess_workspace_observations("t.local", [base, mut])
    assert len(out["findings"]) == 1
    f = out["findings"][0]
    assert f.property_id == "INJECT_SQL"
    assert f.evidence_chain and f.request_evidence and f.response_evidence
    assert f.quality_score >= 0.6
    assert out["invariants"]["INV-INJECT-001"]["status"] == "VIOLATED"


def test_e2e_source_only_clue_never_becomes_finding():
    from horcrux.engine.assess import assess_workspace_observations
    from horcrux.engine.observations import observe_source_only
    clue = observe_source_only("js_analyzer", "t.local", "/api/Users")
    out = assess_workspace_observations("t.local", [clue])
    assert out["findings"] == []


def test_e2e_ownership_required_for_bola():
    from horcrux.engine.oracles import evaluate
    # Same responses, no ownership proof -> BLOCKED, never CONFIRMED.
    r = evaluate("AUTHZ_BOLA_IDOR", {"status_owner": 200, "status_other": 200,
                                     "private_fields": True, "ownership_proven": False})
    assert r.verdict == "BLOCKED"


def test_e2e_object_identity_binding_gates_matrix():
    from horcrux.engine.objects import (IdentityContext, ObjectInstance,
                                        authorization_tests_available,
                                        collection_vs_instance, prove_ownership)
    inst = ObjectInstance(object_type="Order", object_id="2",
                          source_endpoint="/api/orders/2",
                          identifier_location="path", provenance="http")
    assert collection_vs_instance("/api/orders") == "collection"
    assert collection_vs_instance("/api/orders/2") == "instance"
    alice = IdentityContext(identity_id="alice", role="user",
                            authentication_state="user", available=True)
    bob = IdentityContext(identity_id="bob", role="user",
                          authentication_state="user", available=True)
    # No ownership -> no tests.
    assert authorization_tests_available(inst, [alice, bob]) == []
    owned = prove_ownership(inst, "alice", "order-history shows alice created #2")
    assert owned.ownership_proven
    tests = authorization_tests_available(owned, [alice, bob])
    assert len(tests) == 1 and tests[0]["actor"] == "bob"


def test_hypothesis_maps_to_concrete_work():
    from horcrux.engine.work import concrete_work_for
    w = concrete_work_for("idor_bola")
    assert "obtain second identity" in w["steps"]
    assert w["oracle"] == "bola_oracle"
    assert "AUTHZ_BOLA_IDOR" in w["properties"]


def test_completion_verdicts():
    from horcrux.core.actions import completion_verdict
    from horcrux.intel.application_model import ApplicationModel, SemanticEndpoint
    from horcrux.models import WorkspaceState
    st = WorkspaceState(target="t.local")
    app = ApplicationModel(target="t.local")
    st.set_application_model(app)
    assert completion_verdict(st)["verdict"] == "INCONCLUSIVE"
    app.endpoints = [SemanticEndpoint(method="GET", path="/api/Users/1",
                                      sources=["fixture"], evidence_refs=["e"])]
    st.set_application_model(app)
    v = completion_verdict(st)
    assert v["verdict"] in ("LIMITED", "BLOCKED")
