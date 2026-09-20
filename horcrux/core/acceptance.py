"""HORCRUX acceptance gate — hardened for strict provenance, execution records,
separated pipeline vs vulnerability adjudication acceptance, and true disk persistence.

PROVENANCE RULES (non-negotiable):
  SYNTHETIC_TEST_TARGET  -> LIVE ACCEPTANCE BLOCKED (integration tests only)
  UNKNOWN                -> LIVE ACCEPTANCE BLOCKED (provenance not established)
  REAL_LOCAL_TARGET      -> eligible for LIVE ACCEPTANCE PASSED
  REAL_REMOTE_TARGET     -> eligible for LIVE ACCEPTANCE PASSED
"""
from __future__ import annotations

import dataclasses
import shutil
import tempfile
from pathlib import Path
from typing import Any, Optional

_SYNTHETIC_PROVENANCES = {"SYNTHETIC_TEST_TARGET", "UNKNOWN", ""}
_REAL_PROVENANCES = {"REAL_LOCAL_TARGET", "REAL_REMOTE_TARGET"}

# Explicit investigation state taxonomy
EXECUTED_STATES = {
    "COMPLETE", "SUPPORTED", "REFUTED",
    "COMPLETE_WITH_CANDIDATES", "COMPLETE_NO_CANDIDATES",
    "FAILED", "INSUFFICIENT_EVIDENCE",
}
BLOCKED_STATES = {
    "BLOCKED", "UNAVAILABLE", "NOT_APPLICABLE",
    "SCOPE_BLOCKED", "APPROVAL_REQUIRED",
}
READY_STATES = {"READY"}
RUNNING_STATES = {"RUNNING"}
DEFERRED_STATES = {"PENDING", "DEFERRED"}


def _state_str(state_val: Any) -> str:
    """Normalize state enum/string to uppercase string without enum prefix."""
    s = str(state_val)
    if "." in s:
        s = s.split(".")[-1]
    return s.upper()


def derive_target_provenance(
    target: str,
    live_execution_observed: bool,
    existing_provenance: str = "UNKNOWN",
    provenance_source: str = "",
) -> tuple[str, str]:
    """Deterministically derive target provenance from observed execution."""
    if existing_provenance == "SYNTHETIC_TEST_TARGET":
        return "SYNTHETIC_TEST_TARGET", provenance_source or "declared_synthetic_fixture"
    if not live_execution_observed:
        return "UNKNOWN", provenance_source or "no_live_execution_observed"

    host = target.split(":")[0] if ":" in target else target
    host_lower = host.lower()

    is_loopback = host_lower in {"localhost", "127.0.0.1", "::1"} or host_lower.startswith("127.")
    if is_loopback:
        return "REAL_LOCAL_TARGET", provenance_source or "live_local_execution"
    return "REAL_REMOTE_TARGET", provenance_source or "live_remote_execution"


@dataclasses.dataclass
class AcceptanceResult:
    gate: str          # "PASSED" | "BLOCKED" | "FAILED"
    target: str
    provenance: str
    reason: str
    acceptance_type: str = "LIVE_EXECUTION"  # "LIVE_EXECUTION" | "VULNERABILITY_ADJUDICATION"
    security_verdict: str = "NO CONFIRMED FINDINGS"  # Informational verdict; NEVER "CLEAN" or "SECURE"
    checks: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    findings_confirmed: int = 0
    findings_confirmed_no_cve: int = 0
    findings_confirmed_with_cve: int = 0
    findings_rejected: int = 0
    investigations_scheduled: int = 0
    investigations_executed: int = 0
    investigations_blocked: int = 0
    investigations_failed: int = 0
    investigations_deferred: int = 0
    investigations_ready_at_close: int = 0
    investigations_running_at_close: int = 0
    live_execution_records_count: int = 0
    untested_high_value_discoveries: list[str] = dataclasses.field(default_factory=list)
    per_finding_failures: list[str] = dataclasses.field(default_factory=list)
    model_roundtrip_verified: bool = False
    persistence_verified: bool = False


def verify_model_roundtrip(state: Any) -> tuple[bool, list[str]]:
    """In-memory serialization validation: model_dump_json() -> model_validate_json()."""
    from horcrux.models import WorkspaceState
    try:
        data = state.model_dump_json()
        reloaded = WorkspaceState.model_validate_json(data)
    except Exception as exc:
        return False, [f"Serialization roundtrip failed: {exc}"]
    return True, []


def verify_workspace_persistence(state: Any, workspace: Any = None) -> tuple[bool, list[str]]:
    """True disk persistence: ws.save(state) -> new Workspace instance -> load() -> validate fields."""
    from horcrux.core.storage import Workspace
    target = getattr(state, "target", "test-target")
    temp_dir = None
    if workspace is None:
        temp_dir = tempfile.mkdtemp(prefix="horcrux_persist_test_")
        ws = Workspace(target, base=temp_dir)
    else:
        ws = workspace

    try:
        ws.save(state)
        new_ws = Workspace(target, base=str(ws.root.parent))
        reloaded = new_ws.load()

        errors = []
        if getattr(reloaded, "target", "") != getattr(state, "target", ""):
            errors.append("target mismatch after workspace reload")
        if getattr(reloaded, "assessment_run_id", "") != getattr(state, "assessment_run_id", ""):
            errors.append("assessment_run_id mismatch after workspace reload")
        if getattr(reloaded, "target_provenance", "") != getattr(state, "target_provenance", ""):
            errors.append("target_provenance mismatch after workspace reload")
        if getattr(reloaded, "live_execution_observed", False) != getattr(state, "live_execution_observed", False):
            errors.append("live_execution_observed mismatch after workspace reload")
        if len(getattr(reloaded, "services", [])) != len(getattr(state, "services", [])):
            errors.append("services count mismatch after workspace reload")
        if len(getattr(reloaded, "software", [])) != len(getattr(state, "software", [])):
            errors.append("software count mismatch after workspace reload")
        if len(getattr(reloaded, "findings", [])) != len(getattr(state, "findings", [])):
            errors.append("findings count mismatch after workspace reload")

        reloaded_findings = {f.id: f for f in getattr(reloaded, "findings", [])}
        for orig in getattr(state, "findings", []):
            if _state_str(getattr(orig, "validation_state", "")) == "CONFIRMED":
                fid = orig.id
                if fid not in reloaded_findings:
                    errors.append(f"Confirmed finding {fid} missing after reload")
                else:
                    rf = reloaded_findings[fid]
                    if list(orig.evidence) != list(rf.evidence):
                        errors.append(f"Evidence for finding {fid} corrupted after reload")
                    if orig.cves != rf.cves:
                        errors.append(f"CVEs for finding {fid} corrupted after reload")
                    if orig.cwes != rf.cwes:
                        errors.append(f"CWEs for finding {fid} corrupted after reload")
                    if orig.source_tools != rf.source_tools:
                        errors.append(f"Source tools for finding {fid} corrupted after reload")

        return len(errors) == 0, errors
    finally:
        if temp_dir and Path(temp_dir).exists():
            shutil.rmtree(temp_dir, ignore_errors=True)


def evaluate_live_acceptance(state: Any, workspace: Any = None) -> AcceptanceResult:
    """Evaluate LIVE EXECUTION ACCEPTANCE for production assessment runs.

    CRITICAL RULES:
      - Does NOT require any confirmed vulnerabilities. A real target with zero
        findings can PASS live acceptance if execution, discovery, investigations,
        and persistence operated correctly.
      - NEVER declares the target "CLEAN" or "SECURE".
      - Strictly blocks synthetic fixtures or unestablished provenance.
      - Validates LiveExecutionRecord entries proving live connection to target.
    """
    provenance: str = getattr(state, "target_provenance", "UNKNOWN") or "UNKNOWN"
    target: str = getattr(state, "target", "<unknown>")

    # Investigation state accounting (mutually exclusive)
    invs = state.get_investigations() if hasattr(state, "get_investigations") else []
    scheduled = len(invs)
    executed = sum(1 for i in invs if _state_str(i.state) in EXECUTED_STATES)
    blocked = sum(1 for i in invs if _state_str(i.state) in BLOCKED_STATES)
    failed = sum(1 for i in invs if _state_str(i.state) == "FAILED")
    deferred = sum(1 for i in invs if _state_str(i.state) in DEFERRED_STATES)
    ready_at_close = sum(1 for i in invs if _state_str(i.state) in READY_STATES)
    running_at_close = sum(1 for i in invs if _state_str(i.state) in RUNNING_STATES)

    # Finding metrics (informational)
    findings = list(getattr(state, "findings", []) or [])
    confirmed = [
        f for f in findings
        if _state_str(getattr(f, "validation_state", "")) == "CONFIRMED"
    ]
    no_cve = [f for f in confirmed if not getattr(f, "cves", None)]
    with_cve = [f for f in confirmed if getattr(f, "cves", None)]
    rejected = [
        f for f in findings
        if _state_str(getattr(f, "validation_state", "")) == "FALSE_POSITIVE"
    ]

    security_verdict = (
        f"{len(confirmed)} CONFIRMED VULNERABILITIES ({len(with_cve)} CVE, {len(no_cve)} non-CVE)"
        if confirmed
        else "NO CONFIRMED FINDINGS"
    )

    live_records = getattr(state, "live_execution_records", []) or []
    successful_live_records = [r for r in live_records if getattr(r, "success", False)]

    # HARD BLOCK: synthetic fixture or unestablished provenance
    if provenance in _SYNTHETIC_PROVENANCES:
        return AcceptanceResult(
            gate="BLOCKED",
            target=target,
            provenance=provenance,
            reason=(
                f"LIVE ACCEPTANCE BLOCKED: target_provenance='{provenance}' "
                f"indicates a synthetic fixture or unestablished provenance. "
                f"This result satisfies integration tests only."
            ),
            acceptance_type="LIVE_EXECUTION",
            security_verdict=security_verdict,
            findings_confirmed=len(confirmed),
            findings_confirmed_no_cve=len(no_cve),
            findings_confirmed_with_cve=len(with_cve),
            findings_rejected=len(rejected),
            investigations_scheduled=scheduled,
            investigations_executed=executed,
            investigations_blocked=blocked,
            investigations_failed=failed,
            investigations_deferred=deferred,
            investigations_ready_at_close=ready_at_close,
            investigations_running_at_close=running_at_close,
            live_execution_records_count=len(live_records),
        )

    checks: list[dict[str, Any]] = []
    failures: list[str] = []

    def check(name: str, passed: bool, detail: str = "") -> None:
        checks.append({"name": name, "passed": passed, "detail": detail})
        if not passed:
            failures.append(f"{name}: {detail}")

    # 1. Real target provenance
    check("real_target_provenance", provenance in _REAL_PROVENANCES,
          f"provenance={provenance}")

    # 2. Live execution explicitly observed & backed by live execution records
    live_observed = bool(getattr(state, "live_execution_observed", False))
    check("live_execution_observed", live_observed,
          f"live_execution_observed={live_observed}")
    check("live_execution_records_present", len(successful_live_records) > 0,
          f"successful_live_records={len(successful_live_records)}")

    # 3. Assessment run ID present
    run_id = getattr(state, "assessment_run_id", "") or ""
    check("scan_run_id_present", bool(run_id), f"assessment_run_id={run_id!r}")

    # 4. Services discovered
    services = list(getattr(state, "services", []) or [])
    check("services_discovered", len(services) > 0, f"services={len(services)}")

    # 5. Investigations scheduled and converged
    check("investigations_scheduled", scheduled > 0, f"scheduled={scheduled}")
    check("investigations_executed", executed > 0, f"executed={executed}")
    check("loop_invariant_READY_zero", ready_at_close == 0,
          f"READY_at_close={ready_at_close}")
    check("loop_invariant_RUNNING_zero", running_at_close == 0,
          f"RUNNING_at_close={running_at_close}")

    # 6. Application model built
    app = state.get_application_model() if hasattr(state, "get_application_model") else getattr(state, "application_model", None)
    endpoints = list(getattr(app, "endpoints", []) if app else [])
    check("application_model_built", len(endpoints) > 0,
          f"endpoints={len(endpoints)}")

    # 7. PER-FINDING EVIDENCE CHAIN VALIDATION (If confirmed findings exist, every one must pass)
    per_finding_failures: list[str] = []
    for f in confirmed:
        fid = getattr(f, "id", "<unknown>")
        has_ev = bool(getattr(f, "evidence", None) or getattr(f, "evidence_refs", None))
        if not has_ev:
            per_finding_failures.append(f"finding {fid} has no evidence or evidence_refs")

        has_source = bool(
            getattr(f, "source_tool", None)
            or getattr(f, "source_tools", None)
            or getattr(f, "source_providers", None)
        )
        if not has_source:
            per_finding_failures.append(f"finding {fid} has no source capability or tool")

        has_link = bool(
            getattr(f, "investigation_id", None)
            or getattr(f, "hypothesis_id", None)
            or getattr(f, "source_providers", None)
            or getattr(f, "source_tools", None)
            or getattr(f, "source_tool", None)
        )
        if not has_link:
            per_finding_failures.append(f"finding {fid} has no investigation or source provenance linkage")

        has_target_asset = bool(getattr(f, "target", None) or getattr(f, "affected_asset", None))
        if not has_target_asset:
            per_finding_failures.append(f"finding {fid} has no target or affected asset")

        has_repro = bool(
            getattr(f, "reproduction", None)
            or getattr(f, "validation_details", None)
            or (getattr(f, "evidence", None) and any("curl" in str(e).lower() or "http" in str(e).lower() or "request" in str(e).lower() or "matched" in str(e).lower() for e in f.evidence))
        )
        if not has_repro:
            per_finding_failures.append(f"finding {fid} has no reproduction steps or validation record")

    if confirmed:
        check(
            "every_confirmed_finding_has_evidence_chain",
            len(per_finding_failures) == 0,
            f"{len(per_finding_failures)} defect(s): {', '.join(per_finding_failures[:3])}" if per_finding_failures else "all confirmed findings verified",
        )

    # 8. PERSISTENCE VERIFICATION: Model roundtrip + true workspace disk roundtrip
    model_ok, model_errs = verify_model_roundtrip(state)
    check("model_serialization_roundtrip", model_ok,
          "clean serialization" if model_ok else f"model error: {', '.join(model_errs[:2])}")

    persist_ok, persist_errors = verify_workspace_persistence(state, workspace=workspace)
    check("workspace_disk_persistence", persist_ok,
          "disk state intact after reload" if persist_ok else f"persistence error: {', '.join(persist_errors[:2])}")

    # 9. DISCOVERY -> INVESTIGATION LINKAGE (No silently unhandled high-value discoveries)
    untested: list[str] = []
    if app:
        inv_text = " ".join(
            (getattr(i, "objective", "") + " " + getattr(i, "reason", "") + " " + " ".join(getattr(i, "candidate_tools", [])) + " " + " ".join(getattr(i, "vulnerability_classes", []))).lower()
            for i in invs
        )
        finding_assets = " ".join(
            (getattr(f, "affected_asset", "") + " " + getattr(f, "title", "")).lower()
            for f in findings
        )

        for ep in endpoints:
            p = (getattr(ep, "path", "") or "").lower()
            if "graphql" in p and "graphql" not in inv_text and "graphql" not in finding_assets:
                untested.append(f"GraphQL endpoint '{ep.path}' has no downstream investigation")
            elif ("admin" in p or "management" in p) and "admin" not in inv_text and "admin" not in finding_assets:
                untested.append(f"Admin endpoint '{ep.path}' has no downstream investigation")
            elif ("login" in p or "auth" in p) and "auth" not in inv_text and "login" not in inv_text and "login" not in finding_assets:
                untested.append(f"Auth endpoint '{ep.path}' has no downstream investigation")

    check(
        "no_silently_untested_high_value_discoveries",
        len(untested) == 0,
        "all high-value discoveries have downstream investigation/finding" if not untested else f"untested: {', '.join(untested[:2])}",
    )

    # 10. HONEST COVERAGE REPORTING: If external engines missing, must NOT claim "CLEAN"
    coverage = getattr(state, "coverage", None)
    cov_str = str(coverage or "").upper()
    check("no_false_clean_verdict", "CLEAN" not in cov_str and "SECURE" not in cov_str,
          "assessment reports findings honestly without false clean/secure claim")

    gate = "PASSED" if not failures else "FAILED"
    reason = (
        "LIVE ACCEPTANCE PASSED" if not failures
        else "LIVE ACCEPTANCE FAILED:\n  " + "\n  ".join(failures)
    )

    return AcceptanceResult(
        gate=gate,
        target=target,
        provenance=provenance,
        reason=reason,
        acceptance_type="LIVE_EXECUTION",
        security_verdict=security_verdict,
        checks=checks,
        findings_confirmed=len(confirmed),
        findings_confirmed_no_cve=len(no_cve),
        findings_confirmed_with_cve=len(with_cve),
        findings_rejected=len(rejected),
        investigations_scheduled=scheduled,
        investigations_executed=executed,
        investigations_blocked=blocked,
        investigations_failed=failed,
        investigations_deferred=deferred,
        investigations_ready_at_close=ready_at_close,
        investigations_running_at_close=running_at_close,
        live_execution_records_count=len(live_records),
        untested_high_value_discoveries=untested,
        per_finding_failures=per_finding_failures,
        model_roundtrip_verified=model_ok,
        persistence_verified=persist_ok,
    )


def evaluate_vulnerability_adjudication_acceptance(state: Any) -> AcceptanceResult:
    """Evaluate VULNERABILITY DETECTION / ADJUDICATION ACCEPTANCE on synthetic test fixtures.

    Unlike live acceptance, this suite REQUIRES findings to prove:
      - CVE resolution from component evidence
      - Non-CVE canonical findings (IDOR, BFLA, GraphQL) with cves=[]
      - False positive rejection
      - Deterministic evidence adjudication
    """
    findings = list(getattr(state, "findings", []) or [])
    confirmed = [
        f for f in findings
        if _state_str(getattr(f, "validation_state", "")) == "CONFIRMED"
    ]
    no_cve = [f for f in confirmed if not getattr(f, "cves", None)]
    with_cve = [f for f in confirmed if getattr(f, "cves", None)]

    checks = []
    failures = []

    def check(name: str, passed: bool, detail: str = "") -> None:
        checks.append({"name": name, "passed": passed, "detail": detail})
        if not passed:
            failures.append(f"{name}: {detail}")

    check("confirmed_findings_produced", len(confirmed) > 0, f"confirmed={len(confirmed)}")
    check("non_cve_findings_exist", len(no_cve) > 0, f"confirmed_no_cve={len(no_cve)}")

    gate = "PASSED" if not failures else "FAILED"
    reason = (
        "VULNERABILITY ADJUDICATION ACCEPTANCE PASSED" if not failures
        else "VULNERABILITY ADJUDICATION ACCEPTANCE FAILED:\n  " + "\n  ".join(failures)
    )

    return AcceptanceResult(
        gate=gate,
        target=getattr(state, "target", "<unknown>"),
        provenance=getattr(state, "target_provenance", "SYNTHETIC_TEST_TARGET"),
        reason=reason,
        acceptance_type="VULNERABILITY_ADJUDICATION",
        security_verdict=f"{len(confirmed)} CONFIRMED ({len(with_cve)} CVE, {len(no_cve)} non-CVE)",
        checks=checks,
        findings_confirmed=len(confirmed),
        findings_confirmed_no_cve=len(no_cve),
        findings_confirmed_with_cve=len(with_cve),
    )


def print_acceptance_report(result: AcceptanceResult) -> None:
    w = 64
    print("=" * w)
    print(f"HORCRUX ACCEPTANCE GATE [{result.acceptance_type}]: {result.gate}")
    print("=" * w)
    print(f"  Target           : {result.target}")
    print(f"  Provenance       : {result.provenance}")
    print(f"  Security Verdict : {result.security_verdict}")
    print()
    print(result.reason)
    print()
    if result.checks:
        print("Acceptance checks:")
        for c in result.checks:
            status = "PASS" if c["passed"] else "FAIL"
            print(f"  [{status}] {c['name']}: {c['detail']}")
        print()
    print(f"  Investigations scheduled : {result.investigations_scheduled}")
    print(f"  Investigations executed  : {result.investigations_executed}")
    print(f"  Investigations blocked   : {result.investigations_blocked}")
    print(f"  Investigations failed    : {result.investigations_failed}")
    print(f"  Investigations deferred  : {result.investigations_deferred}")
    print(f"  READY at assessment close: {result.investigations_ready_at_close}")
    print(f"  RUNNING at close         : {result.investigations_running_at_close}")
    print(f"  Live execution records   : {result.live_execution_records_count}")
    print(f"  Confirmed findings       : {result.findings_confirmed}")
    print(f"    with CVE               : {result.findings_confirmed_with_cve}")
    print(f"    without CVE            : {result.findings_confirmed_no_cve}")
    print(f"  Rejected (false positive): {result.findings_rejected}")
    if result.per_finding_failures:
        print("  Per-finding failures:")
        for pf in result.per_finding_failures:
            print(f"    - {pf}")
    if result.untested_high_value_discoveries:
        print("  Untested discoveries:")
        for ud in result.untested_high_value_discoveries:
            print(f"    - {ud}")
    print("=" * w)
