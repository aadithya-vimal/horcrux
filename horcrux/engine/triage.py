"""Automated false-negative triage: which layer failed?

NOT_DISCOVERED -> DISCOVERED_BUT_NOT_MODELED -> MODELED_BUT_NOT_APPLICABLE
-> APPLICABLE_BUT_NOT_SCHEDULED -> SCHEDULED_BUT_BLOCKED
-> EXECUTED_BUT_BAD_REQUEST -> EXECUTED_BUT_BAD_OBSERVATION
-> OBSERVATION_BUT_BAD_ORACLE -> ORACLE_BUT_BAD_ADJUDICATION
-> FINDING_DEDUPE_ERROR -> REPORTING_ERROR
"""

from __future__ import annotations

from typing import Any


def triage_miss(asset: str, state: Any,
                parameter: str = "", method: str = "") -> dict[str, Any]:
    """Classify where a known-vulnerable asset was lost in the pipeline."""
    app = state.get_application_model()
    eps = [e for e in (getattr(app, "endpoints", []) or [])
           if asset.lower() in str(getattr(e, "path", "") or "").lower()]
    if not eps:
        routes = [r for r in (getattr(app, "routes", []) or [])
                  if asset.lower() in str(getattr(r, "path", "") or "").lower()]
        if not routes:
            return {"stage": "NOT_DISCOVERED",
                    "detail": f"no endpoint or route matching {asset}"}
        return {"stage": "DISCOVERED_BUT_NOT_MODELED",
                "detail": f"route observed but no endpoint modeled for {asset}"}
    if parameter:
        owned = [p for p in (getattr(app, "parameters", []) or [])
                 if str(getattr(p, "name", "")).lower() == parameter.lower()
                 and asset.lower() in str(getattr(p, "endpoint", "") or "").lower()]
        if not owned:
            return {"stage": "MODELED_BUT_NOT_APPLICABLE",
                    "detail": f"endpoint modeled but parameter {parameter} has no endpoint-specific evidence"}
    invs = state.get_investigations()
    related = [i for i in invs
               if asset.lower() in str(getattr(i, "objective", "") or "").lower()]
    if not related:
        return {"stage": "APPLICABLE_BUT_NOT_SCHEDULED",
                "detail": f"modeled but no investigation generated for {asset}"}
    terminals = {getattr(getattr(i, "state", ""), "value", str(getattr(i, "state", ""))) for i in related}
    blocked = terminals & {"BLOCKED", "SCOPE_BLOCKED", "UNAVAILABLE", "APPROVAL_REQUIRED",
                           "REQUIRES_AUTH", "REQUIRES_SECOND_IDENTITY", "REQUIRES_TOOL",
                           "REQUIRES_OPERATOR", "NOT_APPLICABLE", "OUT_OF_SCOPE"}
    if blocked and not (terminals - blocked):
        return {"stage": "SCHEDULED_BUT_BLOCKED",
                "detail": f"blocked terminals: {sorted(blocked)}"}
    executed = terminals & {"SUPPORTED", "REFUTED", "COMPLETE", "INSUFFICIENT_EVIDENCE", "FAILED"}
    if not executed:
        return {"stage": "APPLICABLE_BUT_NOT_SCHEDULED",
                "detail": f"investigations pending: {sorted(terminals)}"}
    if terminals & {"SUPPORTED"}:
        fids = [f.id for f in (getattr(state, "findings", []) or [])]
        linked = [i for i in related
                  if getattr(i, "state", "").value == "SUPPORTED"
                  and not any(fid in (getattr(i, "evidence_refs", []) or []) for fid in fids)]
        if linked:
            return {"stage": "ORACLE_BUT_BAD_ADJUDICATION",
                    "detail": "supported investigation without canonical finding"}
        return {"stage": "REPORTING_ERROR",
                "detail": "finding exists but missing from report output"}
    if terminals & {"INSUFFICIENT_EVIDENCE"}:
        return {"stage": "EXECUTED_BUT_BAD_OBSERVATION",
                "detail": "executed but evidence insufficient for oracle"}
    if terminals & {"REFUTED", "COMPLETE"}:
        return {"stage": "OBSERVATION_BUT_BAD_ORACLE",
                "detail": "executed with observations but oracle rejected valid evidence"}
    return {"stage": "EXECUTED_BUT_BAD_REQUEST",
            "detail": f"terminals: {sorted(terminals)}"}
