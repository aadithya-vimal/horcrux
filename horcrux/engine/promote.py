"""Finding promotion pipeline, canonical findings, dedup, quality score.

Stages: OBSERVED -> SUSPECTED -> SUPPORTED -> VALIDATED -> CONFIRMED
Refutation: OBSERVED -> TESTED -> REFUTED
Blocked: APPLICABLE -> BLOCKED_BY_PREREQUISITE
Insufficient: TESTED -> INSUFFICIENT_EVIDENCE

Only VALIDATED/CONFIRMED observations become canonical findings.
Dedup key: property + asset + endpoint + parameter + object + identity
boundary + affected component. All sources preserved underneath.
Quality score = evidence completeness (not severity, not politics).
"""

from __future__ import annotations

import hashlib

from pydantic import BaseModel, Field


STAGES = ("OBSERVED", "SUSPECTED", "SUPPORTED", "VALIDATED", "CONFIRMED",
          "TESTED", "REFUTED", "APPLICABLE", "BLOCKED_BY_PREREQUISITE",
          "INSUFFICIENT_EVIDENCE")


def promote_stage(current: str, oracle_verdict: str,
                  threshold_met: bool = True) -> str:
    if oracle_verdict == "CONFIRMED" and threshold_met:
        return "CONFIRMED" if current in ("SUPPORTED", "VALIDATED", "CONFIRMED") else "VALIDATED"
    if oracle_verdict == "CONFIRMED":
        return "SUPPORTED"
    if oracle_verdict == "REFUTED":
        return "REFUTED"
    if oracle_verdict == "BLOCKED":
        return "BLOCKED_BY_PREREQUISITE"
    return "INSUFFICIENT_EVIDENCE" if current in ("TESTED", "SUSPECTED", "OBSERVED") else current


class CanonicalFinding(BaseModel):
    finding_id: str = ""
    property_id: str = ""
    title: str = ""
    severity: str = "medium"
    confidence: float = 0.8
    validation_state: str = "CONFIRMED"
    target: str = ""
    asset: str = ""
    endpoint: str = ""
    method: str = "GET"
    parameter: str = ""
    object: str = ""
    object_instance: str = ""
    source_identity: str = ""
    target_identity: str = ""
    description: str = ""
    impact: str = ""
    evidence_chain: list[str] = Field(default_factory=list)
    request_evidence: list[str] = Field(default_factory=list)
    response_evidence: list[str] = Field(default_factory=list)
    comparison_evidence: list[str] = Field(default_factory=list)
    ownership_evidence: list[str] = Field(default_factory=list)
    test_ids: list[str] = Field(default_factory=list)
    source_tools: list[str] = Field(default_factory=list)
    source_providers: list[str] = Field(default_factory=list)
    cves: list[str] = Field(default_factory=list)
    cwes: list[str] = Field(default_factory=list)
    reproduction: list[str] = Field(default_factory=list)
    remediation: str = ""
    canonical_hash: str = ""
    dedup_key: str = ""
    quality_score: float = 0.0

    def finalize(self) -> "CanonicalFinding":
        out = self.model_copy(deep=True)
        out.dedup_key = dedup_key(self.property_id, self.asset, self.endpoint,
                                  self.parameter, self.object,
                                  self.source_identity, self.target_identity)
        out.canonical_hash = hashlib.sha256(
            f"{out.dedup_key}|{out.title}".encode()).hexdigest()[:16]
        if not out.finding_id:
            out.finding_id = f"engine-{out.canonical_hash[:12]}"
        out.quality_score = evidence_completeness(self)
        return out


def dedup_key(property_id: str, asset: str, endpoint: str, parameter: str,
              object: str, source_identity: str, target_identity: str) -> str:
    parts = [property_id, asset, endpoint, parameter, object,
             source_identity, target_identity]
    norm = "|".join(p.strip().lower() for p in parts)
    return hashlib.sha256(norm.encode()).hexdigest()[:16]


def deduplicate(findings: list[CanonicalFinding]) -> list[CanonicalFinding]:
    merged: dict[str, CanonicalFinding] = {}
    for f in findings:
        key = f.dedup_key or dedup_key(f.property_id, f.asset, f.endpoint,
                                       f.parameter, f.object,
                                       f.source_identity, f.target_identity)
        if key not in merged:
            merged[key] = f.model_copy(deep=True)
            merged[key].dedup_key = key
        else:
            m = merged[key]
            for s in f.source_tools:
                if s not in m.source_tools:
                    m.source_tools.append(s)
            for s in f.source_providers:
                if s not in m.source_providers:
                    m.source_providers.append(s)
            for e in f.evidence_chain:
                if e not in m.evidence_chain:
                    m.evidence_chain.append(e)
            m.confidence = max(m.confidence, f.confidence)
    return list(merged.values())


QUALITY_CHECKS = (
    "valid_target", "live_observation", "applicable_property",
    "correct_request", "correct_identity", "correct_object",
    "baseline", "mutation", "differential", "oracle", "reproducibility",
)


def evidence_completeness(f: CanonicalFinding) -> float:
    present = {
        "valid_target": bool(f.target),
        "live_observation": bool(f.response_evidence),
        "applicable_property": bool(f.property_id),
        "correct_request": bool(f.request_evidence),
        "correct_identity": bool(f.source_identity or f.target_identity),
        "correct_object": bool(f.object or f.object_instance or f.parameter or f.endpoint),
        "baseline": any("baseline" in e.lower() for e in f.evidence_chain),
        "mutation": any("mutat" in e.lower() or "payload" in e.lower() for e in f.evidence_chain),
        "differential": any("differential" in e.lower() or "disclosed" in e.lower() or "reflected" in e.lower()
                            for e in f.evidence_chain),
        "oracle": bool(f.property_id),
        "reproducibility": bool(f.reproduction),
    }
    return round(sum(1 for v in present.values() if v) / len(QUALITY_CHECKS), 3)
