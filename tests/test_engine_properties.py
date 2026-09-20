"""Engine layer tests: registry, oracles, correlation, dedup, benchmark, e2e.

Synthetic fixtures only. No network. No AI.
"""
from __future__ import annotations


# ── 1. model / registry ───────────────────────────────────────────
def test_registry_contracts_complete():
    from horcrux.engine.oracles import ORACLES
    from horcrux.engine.properties import PROPERTIES
    assert len(PROPERTIES) >= 30
    for p in PROPERTIES:
        assert p.property_id and p.category and p.title
        assert p.required_evidence, p.property_id
        assert p.test_methods, p.property_id
        assert p.required_asset_types, p.property_id
        assert p.oracle, p.property_id
        assert p.oracle in ORACLES, f"{p.property_id} -> missing oracle {p.oracle}"
        assert p.confirmation_conditions, p.property_id
        assert p.refutation_conditions, p.property_id
        assert p.blocked_conditions, p.property_id
        assert p.severity in ("low", "medium", "high", "critical"), p.property_id
        assert p.remediation, p.property_id


def test_registry_covers_required_categories():
    from horcrux.engine.properties import properties_for_category
    for cat in ("authentication", "authorization", "input_validation",
                "output_client", "file_path", "ssrf", "api", "session",
                "business_logic", "configuration", "graphql", "infrastructure"):
        assert properties_for_category(cat), f"category {cat} empty"


# ── 5. evidence oracles: vulnerable/hardened/ambiguous ────────────
def test_oracle_families_tri_state():
    from horcrux.engine.benchmark import BENCHMARK_MANIFEST
    from horcrux.engine.oracles import evaluate
    for case in BENCHMARK_MANIFEST:
        v = evaluate(case.property_id, dict(case.vulnerable_evidence))
        h = evaluate(case.property_id, dict(case.hardened_evidence))
        a = evaluate(case.property_id, dict(case.ambiguous_evidence))
        assert v.verdict == "CONFIRMED", f"{case.property_id} vulnerable -> {v.verdict}"
        assert h.verdict == "REFUTED", f"{case.property_id} hardened -> {h.verdict}"
        assert a.verdict == "INSUFFICIENT", f"{case.property_id} ambiguous -> {a.verdict} (must never CONFIRM)"


def test_oracles_never_confirm_on_single_generic_error():
    from horcrux.engine.oracles import evaluate
    r = evaluate("INJECT_SQL", {"baseline_body": "ok", "mutated_body": "error 500",
                                "generic_error_only": True})
    assert r.verdict == "INSUFFICIENT"


def test_oracles_require_ownership_for_bola():
    from horcrux.engine.oracles import evaluate
    r = evaluate("AUTHZ_BOLA_IDOR", {"ownership_proven": False, "status_owner": 200,
                                     "status_other": 200, "private_fields": True})
    assert r.verdict == "BLOCKED"


# ── 6. correlation ────────────────────────────────────────────────
def test_nuclei_claim_loses_to_native_no_effect():
    from horcrux.engine.correlate import correlate
    from horcrux.engine.oracles import OracleResult
    native = OracleResult(verdict="REFUTED", confidence=0.8,
                          evidence=["neutral"], property_id="INJECT_SQL")
    out = correlate("INJECT_SQL", native,
                    [{"source": "nuclei", "claim": "possible"}])
    assert out.verdict == "REFUTED"
    assert "native" in out.sources


def test_multi_source_merge_into_one_verdict():
    from horcrux.engine.correlate import correlate
    from horcrux.engine.oracles import OracleResult
    native = OracleResult(verdict="CONFIRMED", confidence=0.85,
                          evidence=["db-error differential"], property_id="INJECT_SQL")
    out = correlate("INJECT_SQL", native,
                    [{"source": "nuclei", "claim": "confirmed"},
                     {"source": "browser", "claim": "possible"}])
    assert out.verdict == "CONFIRMED"
    assert set(out.sources) == {"native", "nuclei", "browser"}


# ── 8. deduplication + quality ────────────────────────────────────
def test_dedup_merges_same_defect_preserving_sources():
    from horcrux.engine.promote import CanonicalFinding, deduplicate
    def _mk(tool):
        return CanonicalFinding(
            property_id="INJECT_SQL", title="SQLi", severity="critical",
            confidence=0.9, target="t", asset="/search", endpoint="/search",
            method="GET", parameter="q", source_identity="anon",
            target_identity="", evidence_chain=["db-error differential"],
            request_evidence=["GET /search?q"], response_evidence=["sqlite error"],
            reproduction=["curl"], source_tools=[tool]).finalize()
    merged = deduplicate([_mk("nuclei"), _mk("native"), _mk("browser")])
    assert len(merged) == 1
    assert set(merged[0].source_tools) == {"nuclei", "native", "browser"}
    assert merged[0].quality_score >= 0.8


def test_quality_score_measures_completeness_not_severity():
    from horcrux.engine.promote import CanonicalFinding, evidence_completeness
    full = CanonicalFinding(property_id="X", title="t", target="t", asset="a",
                            endpoint="/e", parameter="p", source_identity="anon",
                            evidence_chain=["baseline ok", "payload mutation",
                                            "differential disclosed"],
                            request_evidence=["r"], response_evidence=["resp"],
                            reproduction=["curl"]).finalize()
    thin = CanonicalFinding(property_id="X", title="t").finalize()
    assert evidence_completeness(full) > evidence_completeness(thin)


# ── 9. benchmark ──────────────────────────────────────────────────
def test_benchmark_recovery_and_gap_report():
    from horcrux.engine.benchmark import gap_report_text, run_benchmark
    report = run_benchmark()
    assert report["passed"] == report["total"]
    assert report["fp"] == 0
    assert report["fn"] == 0
    text = gap_report_text(report)
    assert "TP=" in text and "FN=" in text


def test_benchmark_distinguishes_not_implemented():
    from horcrux.engine.benchmark import BenchmarkCase, run_benchmark
    report = run_benchmark([BenchmarkCase(property_id="NO_SUCH_PROPERTY")])
    assert report["not_implemented"] == 1
    assert report["results"][0]["overall"] == "NOT_IMPLEMENTED"
