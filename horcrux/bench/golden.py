"""Golden expectations + tolerant comparison (Phase 8, Part 32)."""

from __future__ import annotations

from typing import Any


# Per-fixture golden expectations. Tolerances allow legitimate reasoning variance.
GOLDEN: dict[str, dict[str, Any]] = {
    "bola": {"min_endpoints": 2, "hypothesis_classes": ["idor_bola"],
             "investigations": ["authorization-bound"],
             "min_attack_paths": 1, "attack_path": ["Object reference"],
             "coverage": {"authorization": 0.0}},
    "broken_auth": {"min_endpoints": 3, "hypothesis_classes": ["authentication"],
                    "investigations": ["authentication workflow"],
                    "coverage": {"authentication": 0.0}},
    "bfla": {"min_endpoints": 2, "hypothesis_classes": ["privilege_escalation"],
             "investigations": ["privileged endpoints"],
             "attack_path": ["Privileged function"]},
    "privesc": {"hypothesis_classes": ["privilege_escalation"]},
    "business_logic": {"hypothesis_classes": ["business_logic"],
                       "investigations": ["workflow state skipping"]},
    "ssrf": {"hypothesis_classes": ["ssrf"],
             "investigations": ["server-side URL fetch"]},
    "injection": {"hypothesis_classes": ["injection"]},
    "upload": {"hypothesis_classes": ["file_upload"]},
    "graphql_authz": {"hypothesis_classes": ["graphql"],
                      "investigations": ["GraphQL introspection"]},
    "jwt": {"hypothesis_classes": ["session"]},
    "data_exposure": {"hypothesis_classes": ["information_disclosure"]},
    "workflow_state": {"hypothesis_classes": ["business_logic"]},
    "multistep_path": {"min_endpoints": 4, "hypothesis_classes": ["idor_bola"],
                       "min_attack_paths": 2},
    "contradictory": {"expect_contradictions": True},
    "tool_failure": {"expect_no_crash": True},
    "browser_failure": {"expect_no_crash": True},
    "missing_capability": {"expect_blocked_or_unavailable": True},
    "ai_unavailable": {"hypothesis_classes": ["idor_bola"],
                       "expect_no_crash": True},
    "provider_refusal": {"expect_no_crash": True, "min_attack_paths": 1},
    "operator_intervention": {"min_endpoints": 3},
}


def compare(fixture: str, actual: dict[str, Any]) -> dict[str, Any]:
    """Compare actual benchmark output vs golden; tolerant by design."""
    gold = GOLDEN.get(fixture, {})
    checks: list[dict[str, Any]] = []

    def _check(name: str, passed: bool, detail: str = "") -> None:
        checks.append({"check": name, "passed": bool(passed), "detail": detail})

    if "min_endpoints" in gold:
        _check("endpoints", actual.get("endpoints", 0) >= gold["min_endpoints"],
               f"{actual.get('endpoints', 0)}>={gold['min_endpoints']}")
    for cls in gold.get("hypothesis_classes", []):
        _check(f"hypothesis:{cls}", cls in (actual.get("hypothesis_classes") or []),
               f"classes={actual.get('hypothesis_classes')}")
    for needle in gold.get("investigations", []):
        hay = " | ".join(actual.get("investigations") or []).lower()
        _check(f"investigation:{needle}", needle.lower() in hay, needle)
    if "min_attack_paths" in gold:
        _check("attack_paths", actual.get("attack_paths", 0) >= gold["min_attack_paths"],
               f"{actual.get('attack_paths', 0)}>={gold['min_attack_paths']}")
    for needle in gold.get("attack_path", []):
        hay = " | ".join(actual.get("attack_path_names") or []).lower()
        _check(f"attack_path:{needle}", needle.lower() in hay, needle)
    for group, minimum in gold.get("coverage", {}).items():
        got = (actual.get("coverage") or {}).get(group, 0)
        _check(f"coverage:{group}", got >= minimum, f"{got}>={minimum}")
    if gold.get("expect_contradictions"):
        _check("contradictions", (actual.get("contradictions", 0) or 0) >= 1,
               f"count={actual.get('contradictions', 0)}")
    if gold.get("expect_no_crash"):
        _check("no_crash", actual.get("crashed", False) is False, "completed without exception")
    if gold.get("expect_blocked_or_unavailable"):
        _check("blocked_or_unavailable",
               (actual.get("blocked", 0) or 0) + (actual.get("unavailable", 0) or 0) >= 1
               or actual.get("sufficient") is False,
               f"blocked={actual.get('blocked', 0)} unavailable={actual.get('unavailable', 0)}")
    passed = sum(1 for c in checks if c["passed"])
    return {"fixture": fixture, "checks": checks, "passed": passed,
            "total": len(checks), "score": round(passed / len(checks), 3) if checks else 1.0}
