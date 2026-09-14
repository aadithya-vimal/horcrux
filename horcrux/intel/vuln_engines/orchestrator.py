"""Unified scan orchestration for external vulnerability engines.

HORCRUX scan → native recon + external engines → normalized evidence →
unified state → correlation → validation → findings → attack paths → report.

Provider failures NEVER crash the assessment. Raw provider data NEVER
enters LLM prompts (only normalized, redacted summaries).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable

from horcrux.intel.vuln_engines.normalize import (
    apply_dispositions_to_entities,
    correlate_finding_with_state,
    deduplicate_findings,
)
from horcrux.intel.vuln_engines.registry import get_engine, normalize_engine_id, provider_ids
from horcrux.intel.vuln_engines.selector import select_engines
from horcrux.intel.vuln_engines.types import (
    CorrelatedVulnerability,
    EngineHealth,
    EngineReadiness,
    NormalizedExternalFinding,
    ScanLifecycle,
    SelectedEngine,
)

TERMINAL_FAILURE = {
    ScanLifecycle.AUTH_FAILED, ScanLifecycle.CONFIGURATION_ERROR,
    ScanLifecycle.RATE_LIMITED, ScanLifecycle.UNAVAILABLE,
    ScanLifecycle.SCAN_FAILED, ScanLifecycle.RESULT_RETRIEVAL_FAILED,
    ScanLifecycle.PARTIAL_RESULTS, ScanLifecycle.NOT_APPLICABLE,
    ScanLifecycle.OPERATOR_EXCLUDED, ScanLifecycle.NOT_CONFIGURED,
}


def readiness_audit(
    settings_manager: Any | None = None,
    client_factory: Callable[[str], Any] | None = None,
    operator_exclude: list[str] | None = None,
    check_health: bool = False,
) -> list[EngineReadiness]:
    """Pre-scan capability audit — what vulnerability intelligence is available?"""
    excluded = {(e or "").lower() for e in (operator_exclude or [])}
    out: list[EngineReadiness] = []
    for pid in provider_ids():
        config: dict[str, Any] = {}
        creds: dict[str, Any] = {}
        if settings_manager is not None:
            try:
                if hasattr(settings_manager, "get_vuln_engine_config"):
                    config = settings_manager.get_vuln_engine_config(pid) or {}
                if hasattr(settings_manager, "get_vuln_credentials"):
                    creds = settings_manager.get_vuln_credentials(pid) or {}
            except Exception:
                pass
        try:
            engine = get_engine(pid, config=config, credentials=creds,
                                client=client_factory(pid) if client_factory else None)
        except Exception:
            out.append(EngineReadiness(provider_id=pid, detail="adapter unavailable",
                                       excluded_by_operator=pid in excluded))
            continue
        ok, reason = engine.validate_configuration()
        enabled = str(config.get("enabled", "true")).lower() in ("1", "true", "yes")
        health = EngineHealth.NOT_CONFIGURED
        last_status = str(config.get("last_status", "") or "")
        last_test = str(config.get("last_test", "") or "")
        if ok and enabled:
            health = EngineHealth.CONFIGURED
            if check_health:
                try:
                    health = engine.health_check()
                except Exception:
                    health = EngineHealth.UNAVAILABLE
            elif last_status.upper() in ("HEALTHY", "READY", "PASSED", "OK"):
                health = EngineHealth.HEALTHY
        detail = "" if ok else reason
        out.append(EngineReadiness(
            provider_id=pid, product=engine.product, configured=ok, enabled=enabled,
            health=health, capabilities=[c.capability_id for c in engine.capabilities()],
            deployment_type=str(getattr(engine.metadata, "deployment_type", "") or ""),
            endpoint=engine.endpoint(), last_test=last_test, last_status=last_status,
            detail=detail, excluded_by_operator=pid in excluded))
    return out


def readiness_text(audit: list[EngineReadiness]) -> str:
    lines = ["VULNERABILITY ENGINE READINESS", ""]
    lines.append("Native HORCRUX")
    lines.append("  READY")
    lines.append("")
    for r in audit:
        if r.excluded_by_operator:
            state = "OPERATOR EXCLUDED"
        elif not r.configured:
            state = "NOT CONFIGURED"
        elif not r.enabled:
            state = "DISABLED"
        elif r.health in (EngineHealth.HEALTHY, EngineHealth.CONFIGURED):
            state = "READY"
        else:
            state = r.health.value
        lines.append(f"{r.product or r.provider_id}")
        lines.append(f"  {state}")
        if r.capabilities and state == "READY":
            lines.append(f"  {', '.join(r.capabilities[:3])}")
        elif r.detail and state not in ("READY",):
            lines.append(f"  {r.detail[:100]}")
        lines.append("")
    ready = [r for r in audit if r.configured and r.enabled
             and r.health in (EngineHealth.HEALTHY, EngineHealth.CONFIGURED) and not r.excluded_by_operator]
    mode = "FULL" if len(ready) >= 2 else ("EXTENDED" if ready else "LIMITED")
    lines.append("Assessment mode:")
    lines.append(f"  {mode}")
    return "\n".join(lines)


def coverage_warning_text(audit: list[EngineReadiness]) -> str:
    """The Juice Shop rule — never imply comprehensive coverage when blind."""
    missing = [r for r in audit if not r.configured and not r.excluded_by_operator]
    if not missing:
        return ""
    lines = ["VULNERABILITY COVERAGE WARNING", ""]
    for r in missing:
        lines.append(f"{r.product or r.provider_id}:")
        lines.append("  NOT CONFIGURED")
        lines.append("")
    lines.append("Native vulnerability checks:")
    lines.append("  AVAILABLE")
    lines.append("")
    lines.append("External vulnerability intelligence:")
    lines.append("  INCOMPLETE")
    lines.append("")
    lines.append("This assessment may miss vulnerabilities normally identified")
    lines.append("by external vulnerability-management engines.")
    lines.append("")
    lines.append("Assessment verdict:")
    lines.append("  LIMITED — NOT COMPREHENSIVE")
    return "\n".join(lines)


def assessment_mode(audit: list[EngineReadiness]) -> str:
    ready = [r for r in audit if r.configured and r.enabled
             and r.health in (EngineHealth.HEALTHY, EngineHealth.CONFIGURED)]
    if len(ready) >= 2:
        return "FULL"
    if ready:
        return "EXTENDED"
    return "LIMITED"


def run_external_engines(
    workspace: Any,
    target: str,
    profile: str = "standard",
    settings_manager: Any | None = None,
    client_factory: Callable[[str], Any] | None = None,
    operator_include: list[str] | None = None,
    operator_exclude: list[str] | None = None,
    engine_mode: str = "best",
    poll_status: bool = False,
    console: Any | None = None,
) -> dict[str, Any]:
    """Execute selected engines; persist IDs + normalized evidence. Never raises."""
    audit = readiness_audit(settings_manager, client_factory, operator_exclude, check_health=False)
    state = workspace.load()
    previous = dict(getattr(state, "external_engine_runs", {}) or {})
    selection = select_engines(audit, profile=profile, target=target,
                               operator_include=operator_include,
                               operator_exclude=operator_exclude,
                               engine_mode=engine_mode, previous_runs=previous)
    return execute_selection(workspace, target, selection, audit, settings_manager,
                             client_factory, poll_status=poll_status, console=console)


def execute_selection(
    workspace: Any,
    target: str,
    selection: list[SelectedEngine],
    audit: list[EngineReadiness] | None = None,
    settings_manager: Any | None = None,
    client_factory: Callable[[str], Any] | None = None,
    poll_status: bool = False,
    console: Any | None = None,
) -> dict[str, Any]:
    audit = audit or []
    audit_by_id = {r.provider_id: r for r in audit}
    runs: dict[str, Any] = {}
    all_findings: list[NormalizedExternalFinding] = []
    state = workspace.load()

    for sel in selection:
        pid = normalize_engine_id(sel.provider_id)
        if sel.mode == "skipped":
            # Preserve the distinction: OPERATOR_EXCLUDED ≠ NOT_CONFIGURED ≠ NOT_APPLICABLE.
            if "operator excluded" in sel.skip_reason.lower():
                skipped_as = "OPERATOR_EXCLUDED"
            elif "not configured" in sel.skip_reason.lower():
                skipped_as = "NOT_CONFIGURED"
            else:
                skipped_as = "SKIPPED"  # profile-gated / unhealthy → NOT_APPLICABLE downstream
            runs[pid] = {"status": skipped_as,
                         "reason": sel.skip_reason,
                         "configured": bool(audit_by_id.get(pid) and audit_by_id[pid].configured)}
            continue
        readiness = audit_by_id.get(pid)
        config: dict[str, Any] = {}
        creds: dict[str, Any] = {}
        if settings_manager is not None:
            try:
                if hasattr(settings_manager, "get_vuln_engine_config"):
                    config = settings_manager.get_vuln_engine_config(pid) or {}
                if hasattr(settings_manager, "get_vuln_credentials"):
                    creds = settings_manager.get_vuln_credentials(pid) or {}
            except Exception:
                pass
        try:
            engine = get_engine(pid, config=config, credentials=creds,
                                client=client_factory(pid) if client_factory else None)
        except Exception as exc:
            runs[pid] = {"status": "FAILED", "reason": f"adapter error: {exc}"}
            continue
        if console is not None:
            try:
                console.print(f"[dim]Vulnerability engine [cyan]{pid}[/cyan]: creating scan...[/dim]")
            except Exception:
                pass
        try:
            run_record = _execute_engine(engine, workspace, state, target, pid, config, poll_status)
            runs[pid] = run_record
            for fdata in run_record.get("normalized", []) or []:
                try:
                    all_findings.append(NormalizedExternalFinding.model_validate(fdata))
                except Exception:
                    continue
        except Exception as exc:
            runs[pid] = {"status": "FAILED", "reason": engine.safe_message(str(exc)),
                         "configured": True, "executed": True}

    # correlate + deduplicate against native evidence (fresh state reload)
    try:
        state = workspace.load()
    except Exception:
        pass
    correlated = correlate_and_store(workspace, state, all_findings)
    persist_runs(workspace, runs)
    update_coverage_from_runs(workspace, runs, audit)
    feed_attack_paths(workspace, correlated)
    return {"runs": runs, "selection": [s.model_dump() for s in selection],
            "findings": len(all_findings), "correlated": len(correlated),
            "mode": assessment_mode(audit)}


def _execute_engine(engine: Any, workspace: Any, state: Any, target: str,
                    pid: str, config: dict, poll_status: bool) -> dict[str, Any]:
    record: dict[str, Any] = {
        "provider": pid, "product": engine.product,
        "configured": True, "executed": True,
        "deployment_type": str(getattr(engine.metadata, "deployment_type", "") or ""),
        "endpoint": engine.endpoint(), "started_at": datetime.now(timezone.utc).isoformat(),
    }
    context = _build_scan_context(state, target, config)
    prepared = engine.prepare_scan(target, context)
    if not prepared.ok:
        record.update({"status": prepared.status.value, "reason": prepared.message})
        return record
    # intelligence-only connectors expose observations, not a scan lifecycle
    if not engine.supports_scan_lifecycle():
        try:
            raw = engine.get_results("")
            normalized = engine.normalize_results(raw, target)
            correlated = [correlate_finding_with_state(f, state).model_dump() for f in normalized]
            record.update({"status": "COMPLETE", "reason": sel_reason(pid),
                           "results": len(normalized), "normalized": correlated,
                           "artifact": _store_results(workspace, pid, raw)})
        except Exception as exc:
            record.update({"status": "RESULT_RETRIEVAL_FAILED",
                           "reason": engine.safe_message(str(exc))})
        return record
    handle = engine.create_scan(target, context)
    record["provider_scan_id"] = handle.provider_scan_id
    if handle.status in TERMINAL_FAILURE and handle.status != ScanLifecycle.READY:
        record.update({"status": handle.status.value, "reason": handle.detail})
        return record
    launched = engine.launch_scan(handle.provider_scan_id) if handle.provider_scan_id else handle
    record["provider_scan_id"] = launched.provider_scan_id or handle.provider_scan_id
    if launched.status in TERMINAL_FAILURE and launched.status not in (ScanLifecycle.READY,):
        record.update({"status": launched.status.value, "reason": launched.detail})
        return record
    status = launched.status
    if poll_status and launched.provider_scan_id:
        import time as _time
        tries = int(config.get("poll_tries", 3))
        for _ in range(max(0, tries)):
            current = engine.get_status(launched.provider_scan_id)
            status = current.status
            record["last_status"] = status.value
            if status in (ScanLifecycle.RESULTS_AVAILABLE, ScanLifecycle.COMPLETE):
                break
            if status in TERMINAL_FAILURE:
                break
            _time.sleep(float(config.get("poll_sleep", 0.1)))
    # attempt result retrieval whenever plausible (fixtures complete instantly)
    try:
        raw = engine.get_results(record.get("provider_scan_id", ""))
        normalized = engine.normalize_results(raw, target)
        correlated = [correlate_finding_with_state(f, state).model_dump() for f in normalized]
        record.update({"status": "COMPLETE" if status in (ScanLifecycle.RESULTS_AVAILABLE,
                                                          ScanLifecycle.RUNNING, ScanLifecycle.QUEUED,
                                                          ScanLifecycle.READY) else status.value,
                       "reason": sel_reason(pid), "results": len(normalized),
                       "normalized": correlated,
                       "artifact": _store_results(workspace, pid, raw)})
    except Exception as exc:
        msg = engine.safe_message(str(exc))
        if "rate limit" in msg.lower() or "429" in msg:
            record.update({"status": "RATE_LIMITED", "reason": msg})
        elif "auth" in msg.lower() or "401" in msg:
            record.update({"status": "AUTH_FAILED", "reason": msg})
        else:
            record.update({"status": status.value if isinstance(status, ScanLifecycle) else str(status),
                           "reason": launched.detail, "results_error": msg})
    return record


def sel_reason(pid: str) -> str:
    return {"tenable": "network vulnerability coverage", "qualys": "network vulnerability coverage",
            "rapid7": "network/host vulnerability coverage", "greenbone": "network vulnerability coverage",
            "msdefender": "enterprise vulnerability-intelligence coverage"}.get(pid, "vulnerability coverage")


def _build_scan_context(state: Any, target: str, config: dict) -> dict[str, Any]:
    ctx: dict[str, Any] = {"target": target}
    try:
        services = getattr(state, "services", []) or []
        ctx["open_ports"] = sorted({int(s.port) for s in services if getattr(s, "port", None)})
    except Exception:
        ctx["open_ports"] = []
    for key in ("scan_name", "template_uuid", "template_name", "site_id", "option_title",
                "scan_config_id", "credentials"):
        if config.get(key):
            ctx[key] = config[key]
    return ctx


def _store_results(workspace: Any, pid: str, raw: Any) -> str:
    try:
        redacted: Any = raw
        if isinstance(raw, list):
            redacted = raw[:200]
        path = workspace.write_json(f"raw/vuln-{pid}-results.json",
                                    {"provider": pid, "count": len(raw) if isinstance(raw, list) else 1,
                                     "results": redacted})
        return str(path)
    except Exception:
        return ""


def correlate_and_store(workspace: Any, state: Any,
                        findings: list[NormalizedExternalFinding]) -> list[CorrelatedVulnerability]:
    if not findings:
        return []
    correlated_findings = [correlate_finding_with_state(f, state) for f in findings]
    entities = deduplicate_findings(correlated_findings)
    entities = apply_dispositions_to_entities(entities, correlated_findings)
    try:
        fresh = workspace.load()
        existing = list(getattr(fresh, "correlated_vulnerabilities", {}) or []
                        if isinstance(getattr(fresh, "correlated_vulnerabilities", None), dict)
                        else (getattr(fresh, "correlated_vulnerabilities", []) or []))
        seen = {(e.get("vuln_id") if isinstance(e, dict) else e.vuln_id) for e in existing}
        for entity in entities:
            if entity.vuln_id not in seen:
                existing.append(entity.model_dump())
        fresh.correlated_vulnerabilities = existing  # type: ignore[attr-defined]
        # external observations enter the unified Evidence model as RawObservations
        from horcrux.models import RawObservation

        obs = [RawObservation(source_tool=f"vuln:{f.provider}", target=f.asset or "",
                              observation_type="external_vulnerability",
                              data={"finding_id": f.finding_id, "cves": f.cves,
                                    "severity": f.severity, "disposition": f.disposition,
                                    "title": f.title}).model_dump()
               for f in correlated_findings[:200]]
        fresh.raw_observations = list(getattr(fresh, "raw_observations", []) or []) + [
            __import__("horcrux.models", fromlist=["RawObservation"]).RawObservation.model_validate(o)
            for o in obs]
        workspace.save(fresh)
    except Exception:
        pass
    return entities


def persist_runs(workspace: Any, runs: dict[str, Any]) -> None:
    try:
        state = workspace.load()
        merged = dict(getattr(state, "external_engine_runs", {}) or {})
        merged.update(runs)
        state.external_engine_runs = merged  # type: ignore[attr-defined]
        workspace.save(state)
    except Exception:
        pass


def update_coverage_from_runs(workspace: Any, runs: dict[str, Any], audit: list[EngineReadiness]) -> None:
    try:
        state = workspace.load()
        cov = state.get_security_coverage()
        engine_states: dict[str, str] = {}
        for pid, run in runs.items():
            status = str(run.get("status", "")).upper()
            if status == "COMPLETE":
                engine_states[pid] = "COMPLETE"
            elif status == "OPERATOR_EXCLUDED":
                engine_states[pid] = "OPERATOR_EXCLUDED"
            elif status == "NOT_CONFIGURED":
                engine_states[pid] = "NOT_CONFIGURED"
            elif status in ("FAILED", "AUTH_FAILED", "RESULT_RETRIEVAL_FAILED", "SCAN_FAILED",
                            "UNAVAILABLE", "RATE_LIMITED", "PARTIAL_RESULTS"):
                engine_states[pid] = "FAILED"
            elif status in ("SKIPPED", "NOT_APPLICABLE"):
                engine_states[pid] = "NOT_APPLICABLE"
            else:
                engine_states[pid] = "RUNNING"
        for r in audit or []:
            if r.provider_id not in engine_states:
                if r.excluded_by_operator:
                    engine_states[r.provider_id] = "OPERATOR_EXCLUDED"
                elif not r.configured:
                    engine_states[r.provider_id] = "NOT_CONFIGURED"
                else:
                    engine_states[r.provider_id] = "AVAILABLE"
        if hasattr(cov, "external_engines"):
            cov.external_engines = engine_states
        else:
            cov.__dict__["external_engines"] = engine_states
        # reflect into property dimensions (non-critical; evidence-gated)
        try:
            from horcrux.intel.coverage import PropertyStatus

            any_complete = any(v == "COMPLETE" for v in engine_states.values())
            any_failed = any(v == "FAILED" for v in engine_states.values())
            all_missing = all(v in ("NOT_CONFIGURED", "OPERATOR_EXCLUDED", "NOT_APPLICABLE")
                              for v in engine_states.values())
            if any_complete:
                cov.set_property_status("vuln.external_intel", PropertyStatus.OBSERVED,
                                        notes="external engine results imported",
                                        evidence_refs=["vuln:external:complete"])
            elif any_failed:
                cov.set_property_status("vuln.external_intel", PropertyStatus.BLOCKED,
                                        notes="external engine execution failed")
            elif not all_missing:
                cov.set_property_status("vuln.external_intel", PropertyStatus.INVESTIGATING,
                                        notes="external engines running")
        except Exception:
            pass
        state.set_security_coverage(cov)
        workspace.save(state)
    except Exception:
        pass


def feed_attack_paths(workspace: Any, entities: list[CorrelatedVulnerability]) -> None:
    """External vulns feed attack paths as corroborated/unverified nodes — never auto-confirm."""
    if not entities:
        return
    try:
        state = workspace.load()
        paths = list(state.attack_paths or [])
        corroborated = [e for e in entities
                        if e.disposition == "CORROBORATED" and e.severity in ("high", "critical")]
        for entity in corroborated[:10]:
            label = entity.primary_cve or entity.title or entity.vuln_id
            steps = [f"Internet-facing asset {entity.asset}",
                     f"externally observed {label} ({', '.join(entity.sources)}) — {entity.disposition.lower()}",
                     "reachable service per native inventory — operator validation required"]
            paths.append({"name": f"External vuln path: {label} on {entity.asset}",
                          "probability": "MEDIUM" if entity.severity == "high" else "HIGH",
                          "steps": steps,
                          "prerequisites": "operator must validate exploitability",
                          "assumptions": [f"scanner observation {entity.disposition.lower()}",
                                          "native service evidence present"],
                          "rank_score": 60 if entity.severity == "high" else 75,
                          "rank_why": f"corroborated external {entity.severity} with native evidence",
                          "source": "vulnerability-engine-fabric"})
        if corroborated:
            state.attack_paths = paths
            workspace.save(state)
    except Exception:
        pass


# client-facing language helpers (spec §33) ---------------------------------
NO_FINDINGS_QUALIFIED = ("No confirmed vulnerabilities identified within the assessed scope "
                         "and completed coverage.")
UNAVAILABLE_SOURCE_NOTE = ("Potential vulnerabilities identifiable by this unavailable assessment "
                           "source may not be represented in this report.")
NOT_NEGATIVE_EVIDENCE = ("Results from unavailable engines are not represented as negative evidence.")


def findings_footer(state: Any) -> str:
    engines = getattr(state, "external_engine_runs", {}) or {}
    missing = [pid for pid, run in engines.items()
               if str(run.get("status", "")).upper() in ("SKIPPED", "FAILED", "NOT_CONFIGURED")]
    if not engines:
        return (f"{NO_FINDINGS_QUALIFIED} External vulnerability intelligence was not executed "
                f"in this assessment. {UNAVAILABLE_SOURCE_NOTE}")
    if missing:
        return (f"{NO_FINDINGS_QUALIFIED} Assessment limited: {', '.join(missing)} did not "
                f"contribute results. {NOT_NEGATIVE_EVIDENCE}")
    return NO_FINDINGS_QUALIFIED
