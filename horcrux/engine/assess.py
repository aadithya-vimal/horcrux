"""End-to-end deterministic assessment over normalized observations.

assess_workspace_observations() is the engine proof: observations enter,
canonical findings with evidence chains come out. No AI. Works with AI
fully disabled.
"""

from __future__ import annotations

from typing import Any

from horcrux.engine.correlate import correlate
from horcrux.engine.ledger import PropertyLedger
from horcrux.engine.observations import Observation
from horcrux.engine.oracles import OracleBlocked, evaluate
from horcrux.engine.promote import CanonicalFinding, deduplicate
from horcrux.engine.properties import get_property


def adjudicate_evidence(property_id: str, evidence: dict,
                        external: list[dict] | None = None,
                        target: str = "", asset: str = "",
                        test_ids: list[str] | None = None) -> dict[str, Any]:
    """Single-property adjudication: oracle -> correlation -> stage ->
    canonical finding (only when VALIDATED/CONFIRMED)."""
    prop = get_property(property_id)
    if prop is None:
        return {"verdict": "INSUFFICIENT", "finding": None,
                "reason": f"unknown property {property_id}"}
    try:
        native = evaluate(property_id, evidence)
    except Exception as exc:
        return {"verdict": "INSUFFICIENT", "finding": None,
                "reason": f"oracle error: {exc}"}
    corr = correlate(property_id, native, external)
    if corr.verdict != "CONFIRMED":
        return {"verdict": corr.verdict, "finding": None,
                "confidence": corr.confidence,
                "evidence": corr.evidence, "sources": corr.sources}
    from horcrux.engine.properties import REGISTRY
    severity = REGISTRY[property_id].severity if property_id in REGISTRY else "medium"
    remediation = REGISTRY[property_id].remediation if property_id in REGISTRY else ""
    finding = CanonicalFinding(
        property_id=property_id,
        title=REGISTRY[property_id].title if property_id in REGISTRY else property_id,
        severity=severity, confidence=corr.confidence,
        validation_state="CONFIRMED", target=target, asset=asset or target,
        endpoint=str(evidence.get("endpoint", asset or "")),
        method=str(evidence.get("method", "GET")),
        parameter=str(evidence.get("parameter", "")),
        object=str(evidence.get("object", "")),
        object_instance=str(evidence.get("object_instance", "")),
        source_identity=str(evidence.get("source_identity", "")),
        target_identity=str(evidence.get("target_identity", "")),
        description=f"{property_id} confirmed by deterministic oracle.",
        impact=f"Violates {property_id}.",
        evidence_chain=[f"observation->{e}" for e in corr.evidence],
        request_evidence=[str(evidence.get("request_summary", evidence.get("endpoint", "")))],
        response_evidence=[str(evidence.get("response_summary", "")) or str(evidence.get("mutated_body", ""))[:200]],
        comparison_evidence=[str(evidence.get("comparison_summary", ""))] if evidence.get("comparison_summary") else [],
        ownership_evidence=[str(evidence.get("ownership_summary", ""))] if evidence.get("ownership_summary") else [],
        test_ids=list(test_ids or []),
        source_tools=["native"] + [s for s in corr.sources if s != "native"],
        source_providers=["horcrux_engine"],
        cves=list(evidence.get("cves", []) or []),
        cwes=list((prop.cwes if hasattr(prop, "cwes") else []) or []),
        reproduction=[str(evidence.get("reproduction", f"replay {asset}"))],
        remediation=remediation,
    ).finalize()
    return {"verdict": "CONFIRMED", "finding": finding,
            "confidence": corr.confidence, "sources": corr.sources}


def _evidence_for_injection(obs: list[Observation]) -> dict:
    base = next((o for o in obs if not o.parameter or "baseline" in (o.extracted_entities.get("role", "") or "")), None)
    mut = next((o for o in obs if o.response.body and o != base), None)
    base = base or (obs[0] if obs else None)
    return {
        "baseline_body": base.response.body if base else "",
        "mutated_body": mut.response.body if mut else "",
        "baseline_time_ms": float((base.extracted_entities.get("time_ms", 0)) if base else 0),
        "mutated_time_ms": float((mut.extracted_entities.get("time_ms", 0)) if mut else 0),
        "repeatable": any(bool(o.extracted_entities.get("repeatable")) for o in obs),
        "generic_error_only": all(bool(o.extracted_entities.get("generic_error_only")) for o in obs) if obs else False,
        "payload": (mut.extracted_entities.get("payload", "") if mut else ""),
        "endpoint": (mut.endpoint if mut else ""),
        "parameter": (mut.parameter if mut else ""),
        "reflected": any(bool(o.extracted_entities.get("reflected")) for o in obs),
        "unescaped": any(bool(o.extracted_entities.get("unescaped")) for o in obs),
        "context": (mut.extracted_entities.get("context", "html-body") if mut else "html-body"),
        "network_interaction": any(bool(o.extracted_entities.get("network_interaction")) for o in obs),
        "internal_response": any(bool(o.extracted_entities.get("internal_response")) for o in obs),
        "reflected_only": all(bool(o.extracted_entities.get("reflected_only")) for o in obs) if obs else False,
        "marker_hit": any(bool(o.extracted_entities.get("marker_hit")) for o in obs),
    }


def assess_workspace_observations(target: str, observations: list[Observation],
                                  identities: list[str] | None = None,
                                  external: dict[str, list[dict]] | None = None) -> dict[str, Any]:
    """Full deterministic pass. Returns findings, ledger, invariant states."""
    from horcrux.engine.invariants import INVARIANTS, evaluate_invariant
    identities = identities or ["anonymous"]
    external = external or {}
    by_prop: dict[str, list[Observation]] = {}
    untagged: list[Observation] = []
    for ob in observations:
        pids = [str(p) for p in (ob.extracted_entities.get("properties", []) or [])]
        if not pids:
            untagged.append(ob)
        for pid in pids:
            by_prop.setdefault(pid, []).append(ob)
    # Baselines travel with their endpoint: untagged observations on the
    # same endpoint join each property group as candidate baselines.
    for pid, obs in by_prop.items():
        eps = {o.endpoint for o in obs}
        for u in untagged:
            if u.endpoint in eps and u not in obs:
                obs.append(u)
    ledger = PropertyLedger()
    findings: list[CanonicalFinding] = []
    oracle_results = []
    for pid, obs in by_prop.items():
        prop = get_property(pid)
        if prop is None:
            ledger.record(pid, applicable=1)
            continue
        ledger.record(pid, applicable=1, executable=1, executed=1)
        ev = _evidence_for_injection(obs)
        ev["endpoint"] = obs[0].endpoint
        ev["parameter"] = obs[0].parameter
        try:
            from horcrux.engine.oracles import evaluate as _eval
            native = _eval(pid, ev)
        except Exception:
            continue
        oracle_results.append(native)
        corr = correlate(pid, native, external.get(pid))
        if corr.verdict == "CONFIRMED":
            out = adjudicate_evidence(pid, ev, external.get(pid), target=target,
                                      asset=obs[0].endpoint)
            if out["finding"] is not None:
                findings.append(out["finding"])
            ledger.record(pid, confirmed=1)
        elif corr.verdict == "REFUTED":
            ledger.record(pid, refuted=1)
        else:
            ledger.record(pid, insufficient=1)
    findings = deduplicate(findings)
    invariants = {iid: evaluate_invariant(iid, oracle_results).model_dump()
                  for iid in INVARIANTS}
    return {"findings": findings, "ledger": ledger,
            "invariants": invariants, "oracle_results": oracle_results}
