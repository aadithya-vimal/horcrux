"""Investigation execution pipeline (Phase 7, Part 2).

Per-investigation lifecycle:
  1. resolve capability
  2. validate prerequisites
  3. build normalized inputs from ApplicationModel
  4. execute capability (central CapabilityRegistry -> CommandRunner)
  5. capture stdout/stderr/result artifacts
  6. normalize output into Evidence objects
  7. ingest evidence
  8. update ApplicationModel
  9. update coverage
  10. update hypothesis state
  11. mark investigation state correctly
  12. trigger reassessment

An investigation is NEVER marked COMPLETE merely because a process exited.
Outcome states distinguish: execution succeeded / useful evidence /
supported / refuted / insufficient / failed / unavailable / scope-blocked /
approval-required.
"""

from __future__ import annotations

import secrets
from typing import Any

from horcrux.agents.tools.capabilities import CapabilityRegistry, FailureClass
from horcrux.intel.investigations import Investigation, InvestigationState


# Map capability failure -> investigation state.
_FAILURE_TO_STATE = {
    FailureClass.SUCCESS: InvestigationState.COMPLETE,
    FailureClass.INSUFFICIENT_EVIDENCE: InvestigationState.INSUFFICIENT_EVIDENCE,
    FailureClass.TOOL_FAILED: InvestigationState.FAILED,
    FailureClass.UNAVAILABLE: InvestigationState.UNAVAILABLE,
    FailureClass.SCOPE_BLOCKED: InvestigationState.SCOPE_BLOCKED,
    FailureClass.APPROVAL_REQUIRED: InvestigationState.APPROVAL_REQUIRED,
    FailureClass.TIMEOUT: InvestigationState.FAILED,
    FailureClass.POLICY_BLOCKED: InvestigationState.SCOPE_BLOCKED,
}


def resolve_capability(investigation: Investigation, registry: CapabilityRegistry) -> str | None:
    """Resolve the best available capability for an investigation.

    Legacy tool IDs are canonicalized explicitly (js_analyzer → js_analyze,
    validator → endpoint_validate); the family map is a last resort.
    """
    from horcrux.agents.tools.capabilities import canonical_tool_id
    for tool in investigation.candidate_tools or []:
        cap = registry.get(canonical_tool_id(tool))
        if cap is not None:
            return cap.capability_id
    # Fall back: map required capability families to concrete adapters.
    family_map = {
        "http": "http_probe", "proxy": "authz_compare", "browser": "browser_navigate",
        "javascript": "js_analyze", "validation": "endpoint_validate",
        "service": "nmap_discovery",
    }
    for fam in investigation.required_capabilities or []:
        mapped = family_map.get(str(fam).lower())
        if mapped and registry.get(mapped) is not None:
            return mapped
    return None


def validate_prerequisites(state: Any, investigation: Investigation) -> tuple[bool, str]:
    """Check prerequisites against workspace state (no execution)."""
    # Dependency-graph evaluation first (named prerequisites).
    try:
        from horcrux.intel.dependencies import evaluate_prerequisites
        schedulable, blocked = evaluate_prerequisites(state, investigation)
        if not schedulable:
            return False, "; ".join(blocked)
    except Exception:
        pass
    app = state.get_application_model()
    for prereq in investigation.prerequisites or []:
        p = prereq.lower()
        if p in ("web_target", "web target") and not app.web_targets:
            return False, f"prerequisite unsatisfied: {prereq}"
        if p in ("authentication_surface",) and not app.authentication and not any(
                "login" in e.path.lower() for e in app.endpoints):
            return False, f"prerequisite unsatisfied: {prereq}"
        if p in ("discovered_path",) and not app.endpoints:
            return False, f"prerequisite unsatisfied: {prereq}"
    # Scope gate via policy.
    try:
        policy = state.get_policy()
        ok, _reason = policy.is_target_allowed(state.target)
        if not ok:
            return False, "scope_blocked"
    except Exception:
        pass
    return True, ""


def build_capability_inputs(state: Any, investigation: Investigation,
                            capability_id: str) -> dict[str, Any]:
    """Build normalized capability inputs from the ApplicationModel."""
    app = state.get_application_model()
    inputs: dict[str, Any] = {"target": state.target}
    # Endpoint context: prefer hypothesis-linked asset, else first object/admin endpoint.
    endpoint = "/"
    if investigation.hypothesis_id:
        for h in state.get_hypotheses():
            if h.id == investigation.hypothesis_id and h.asset_refs:
                for e in app.endpoints:
                    if e.id == h.asset_refs[0]:
                        endpoint = e.path
                        break
                break
    if endpoint == "/":
        for e in app.endpoints:
            if e.has_object_reference or "admin" in e.path.lower():
                endpoint = e.path
                break
        else:
            if app.endpoints:
                endpoint = app.endpoints[0].path
    inputs["path"] = endpoint
    inputs["endpoint"] = endpoint
    if app.web_targets:
        wt = app.web_targets[0]
        inputs["port"] = wt.port
        inputs["scheme"] = wt.scheme
        inputs["base_url"] = wt.base_url
        inputs["url"] = wt.base_url.rstrip("/") + endpoint
    else:
        inputs["port"] = 80
        inputs["scheme"] = "http"
        inputs["base_url"] = f"http://{state.target}"
        inputs["url"] = f"http://{state.target}{endpoint}"
    inputs["method"] = "GET"
    inputs["identity"] = "anonymous"
    if "authorization" in (investigation.objective or "").lower():
        inputs["identity"] = "user"
    inputs["parameters"] = [p.name for p in app.parameters[:15]]
    inputs["from_identity"] = "anonymous"
    inputs["to_identity"] = "user"
    inputs["credentials_available"] = bool(getattr(state, "credentials", [])) or True
    # Capability-specific extras.
    if capability_id == "js_analyze":
        inputs["routes"] = [e.path for e in app.endpoints
                            if "javascript" in (e.sources or [])][:10]
    if capability_id == "content_discovery":
        inputs["wordlist"] = [e.path for e in app.endpoints] + \
            ["admin", "login", "api", "graphql", "upload", ".env"]
    if capability_id == "graphql_probe":
        gql = next((e.path for e in app.endpoints if "graphql" in e.path.lower()), "/graphql")
        inputs["path"] = gql
        inputs["endpoint"] = gql
    if capability_id in ("smb_enum", "ldap_enum", "kerberos_enum", "ssh_enum",
                         "ftp_enum", "smtp_enum", "dns_enum", "snmp_enum",
                         "database_enum", "remote_enum", "nmap_discovery"):
        svc = next((s for s in app.services), None)
        if svc is not None:
            inputs["port"] = svc.port
            inputs["service"] = svc.service_name or svc.service
    if capability_id == "authz_compare":
        inputs["endpoint"] = endpoint
    if capability_id == "identity_compare":
        app_idents = [i.label for i in app.identities]
        inputs["identity_a"] = "anonymous" if "anonymous" in app_idents else (app_idents[0] if app_idents else "anonymous")
        others = [l for l in app_idents if l != inputs["identity_a"]]
        inputs["identity_b"] = others[0] if others else "user"
        inputs["endpoint_filter"] = ""
    if capability_id == "browser_automate":
        inputs["script"] = [{"op": "navigate", "url": inputs["url"]}]
        inputs["identity"] = inputs.get("identity", "anonymous")
    return inputs


def _emit(observer, event: str, payload: dict | None = None) -> None:
    if observer is None:
        return
    try:
        observer(event, payload or {})
    except Exception:
        pass


def run_capability_for_investigation(state: Any, investigation: Investigation,
                                     registry: CapabilityRegistry,
                                     observer=None) -> dict[str, Any]:
    """Execute only the capability portion (steps 1-5). No ingestion/mutation.

    Safe for concurrent use: performs resolution, prerequisite validation,
    and capability execution, returning everything needed for the serial
    apply phase. Sets the investigation to RUNNING.
    """
    request_id = secrets.token_hex(8)
    investigation.state = InvestigationState.RUNNING
    _emit(observer, "investigation_step", {"step": "resolving capability"})

    capability_id = resolve_capability(investigation, registry)
    if not capability_id:
        return {"ok": False, "outcome": "capability_unavailable",
                "capability": None, "request_id": request_id,
                "terminal_state": InvestigationState.UNAVAILABLE,
                "summary": "No registered capability for investigation"}

    ok, reason = validate_prerequisites(state, investigation)
    if not ok:
        terminal = (InvestigationState.SCOPE_BLOCKED if reason == "scope_blocked"
                    else InvestigationState.BLOCKED)
        return {"ok": False, "outcome": terminal.value.lower(),
                "capability": capability_id, "request_id": request_id,
                "terminal_state": terminal, "summary": reason}

    inputs = build_capability_inputs(state, investigation, capability_id)
    _emit(observer, "investigation_step", {"step": "executing"})
    try:
        result = registry.execute(capability_id, inputs, request_id=request_id)
    except Exception as exc:  # crash-safe: subprocess failure never corrupts state
        result = None
        error = str(exc)
    else:
        error = ""
    if result is not None:
        _emit(observer, "investigation_step", {"step": "collecting evidence"})
    return {"ok": True, "capability": capability_id, "inputs": inputs,
            "result": result, "error": error, "request_id": request_id}


def apply_capability_result(state: Any, investigation: Investigation,
                            run: dict[str, Any],
                            workspace: Any = None,
                            observer=None) -> dict[str, Any]:
    """Apply a capability run: ingest -> model -> coverage -> hypothesis (6-12).

    Always runs serially in rank order, even when capabilities executed
    concurrently.
    """
    from horcrux.intel.ingestion import ingest_capability_evidence

    request_id = run.get("request_id", secrets.token_hex(8))
    capability_id = run.get("capability")

    if not run.get("ok"):
        investigation.state = run.get("terminal_state", InvestigationState.FAILED)
        investigation.result_summary = run.get("summary", "execution failed")
        _refresh_coverage(state)
        return {"success": False, "outcome": run.get("outcome", "failed"),
                "capability": capability_id, "request_id": request_id}

    result = run.get("result")
    if result is None:
        investigation.state = InvestigationState.FAILED
        investigation.result_summary = f"capability crashed: {run.get('error', '')[:160]}"
        _refresh_coverage(state)
        try:
            from horcrux.intel.events import log_event
            log_event(workspace, state, "CAPABILITY_FAILED",
                      {"investigation": investigation.id, "capability": capability_id,
                       "error": run.get("error", "")[:200]})
        except Exception:
            pass
        return {"success": False, "outcome": "tool_failed",
                "capability": capability_id, "request_id": request_id}

    if not result.success and not result.evidence:
        investigation.state = _FAILURE_TO_STATE.get(result.failure, InvestigationState.FAILED)
        investigation.result_summary = result.stderr or result.failure.value
        _refresh_coverage(state)
        return {"success": False, "outcome": result.failure.value,
                "capability": capability_id, "request_id": request_id,
                "artifacts": result.artifacts}

    app = state.get_application_model()
    _emit(observer, "investigation_step", {"step": "ingesting"})
    try:
        ingested = ingest_capability_evidence(app, capability_id, result.evidence)
    except Exception:
        ingested = 0
    state.set_application_model(app)

    _refresh_coverage(state)

    outcome = _assess_hypothesis_outcome(state, investigation, result, ingested)
    investigation.state = outcome["state"]
    investigation.result_summary = outcome["summary"]
    if outcome.get("finding_id"):
        investigation.evidence_refs = list(set(
            investigation.evidence_refs + [outcome["finding_id"]]))

    _emit(observer, "investigation_step", {"step": "reassessing"})
    _emit(observer, "investigation_done", {"state": outcome["state"].value})

    return {"success": outcome["state"] in (InvestigationState.SUPPORTED,
                                            InvestigationState.COMPLETE),
            "outcome": outcome["state"].value.lower(),
            "capability": capability_id, "request_id": request_id,
            "evidence_ingested": ingested, "artifacts": result.artifacts,
            "reassess_required": True}


def execute_investigation_pipeline(state: Any, investigation: Investigation,
                                   registry: CapabilityRegistry,
                                   workspace: Any = None,
                                   observer=None) -> dict[str, Any]:
    """Execute one investigation through the full 12-step pipeline."""
    _emit(observer, "investigation_start",
          {"id": investigation.id, "objective": investigation.objective})
    run = run_capability_for_investigation(state, investigation, registry,
                                           observer=observer)
    return apply_capability_result(state, investigation, run,
                                   workspace=workspace, observer=observer)


def _refresh_coverage(state: Any) -> None:
    try:
        from horcrux.intel.coverage import calculate_coverage
        app = state.get_application_model()
        coverage = state.get_security_coverage()
        coverage = calculate_coverage(app, state.get_hypotheses(),
                                      state.get_investigations(), coverage)
        state.set_security_coverage(coverage)
    except Exception:
        pass


def _assess_hypothesis_outcome(state: Any, investigation: Investigation,
                               result: Any, ingested: int) -> dict[str, Any]:
    from horcrux.intel.hypotheses import HypothesisStatus
    data = result.structured_data or {}
    hyps = {h.id: h for h in state.get_hypotheses()}
    hyp = hyps.get(investigation.hypothesis_id)

    def _set_hyp(status: Any) -> None:
        if hyp is not None:
            hyp.status = status
            all_h = state.get_hypotheses()
            for idx, h in enumerate(all_h):
                if h.id == hyp.id:
                    all_h[idx] = hyp
                    break
            state.set_hypotheses(all_h)

    # Authorization comparison carries direct support/refute signal.
    if result.capability_id == "authz_compare":
        if data.get("potential_gap"):
            _set_hyp(HypothesisStatus.SUPPORTED)
            fid = _record_authz_finding(state, investigation, data)
            return {"state": InvestigationState.SUPPORTED,
                    "summary": "Cross-identity comparison suggests authorization gap",
                    "finding_id": fid}
        if data.get("authorization_enforced"):
            _set_hyp(HypothesisStatus.REFUTED)
            return {"state": InvestigationState.REFUTED,
                    "summary": "Authorization enforced across tested identities"}
    # Multi-identity comparison verdict.
    if result.capability_id == "identity_compare":
        if data.get("verdict") == "gap_suspected":
            _set_hyp(HypothesisStatus.SUPPORTED)
            fid = _record_comparison_finding(state, investigation, data)
            return {"state": InvestigationState.SUPPORTED,
                    "summary": f"Identity comparison suggests access divergence "
                               f"({data.get('identity_a')} x {data.get('identity_b')})",
                    "finding_id": fid}
        if data.get("verdict") == "enforced":
            _set_hyp(HypothesisStatus.REFUTED)
            return {"state": InvestigationState.REFUTED,
                    "summary": "Identity comparison shows no access divergence"}
    # http_probe gap signal.
    if result.capability_id == "http_probe":
        if data.get("status_code") == 200 and data.get("object_bearing") \
                and data.get("identity") == "anonymous":
            _set_hyp(HypothesisStatus.SUPPORTED)
            return {"state": InvestigationState.SUPPORTED,
                    "summary": "Object endpoint anonymously reachable; authorization review required"}
    if ingested == 0 and not result.evidence:
        return {"state": InvestigationState.INSUFFICIENT_EVIDENCE,
                "summary": "Capability executed but returned no useful evidence"}
    if hyp is not None and hyp.status == HypothesisStatus.OPEN:
        hyp.status = HypothesisStatus.INVESTIGATING
        all_h = state.get_hypotheses()
        for idx, h in enumerate(all_h):
            if h.id == hyp.id:
                all_h[idx] = hyp
                break
        state.set_hypotheses(all_h)
    return {"state": InvestigationState.COMPLETE,
            "summary": f"Executed {result.capability_id}; ingested {ingested} evidence item(s)"}


def _record_comparison_finding(state: Any, investigation: Investigation, data: dict) -> str:
    from horcrux.models import Finding, FindingStatus, Severity, ValidationState
    fid = f"authz-compare-{investigation.id[:8]}-{secrets.token_hex(3)}"
    if any(f.id == fid for f in state.findings):
        return fid
    state.findings.append(Finding(
        id=fid, title="Cross-identity access divergence on shared surface",
        category="authorization", severity=Severity.medium, confidence=0.6,
        status=FindingStatus.suspected, validation_state=ValidationState.likely,
        target=state.target,
        affected_asset=str((data.get("only_b") or data.get("only_a") or ["/"])[0]),
        evidence=[f"identity_compare:{data.get('identity_a')}x{data.get('identity_b')}:{e}"
                  for e in (data.get("evidence") or [])[:4]],
        reproduction=[f"Compare {data.get('identity_a')} vs {data.get('identity_b')} "
                      "on the shared endpoints/objects",
                      "Verify ownership binding for divergent items"],
        why_it_matters="Different identities observe different access to shared resources",
        recommended_next_action="Manual validation with distinct test accounts"))
    return fid


def _record_authz_finding(state: Any, investigation: Investigation, data: dict) -> str:
    from horcrux.models import Finding, FindingStatus, Severity, ValidationState
    fid = f"authz-{investigation.id[:8]}-{secrets.token_hex(3)}"
    if any(f.id == fid for f in state.findings):
        return fid
    state.findings.append(Finding(
        id=fid, title="Potential object-level authorization weakness",
        category="authorization", severity=Severity.medium, confidence=0.65,
        status=FindingStatus.suspected, validation_state=ValidationState.likely,
        target=state.target, affected_asset=str(data.get("endpoint", "/")),
        evidence=[f"authz_compare:{data.get('endpoint')}:anon={data.get('status_anonymous')}:user={data.get('status_user')}"],
        reproduction=["Authenticate as user A",
                      f"Access {data.get('endpoint')} with user B's object ID",
                      "Compare response for unauthorized access"],
        why_it_matters="Object access may not be bound to authenticated identity",
        recommended_next_action="Manual validation with distinct user accounts"))
    return fid
