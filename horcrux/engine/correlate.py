"""Multi-source evidence correlation.

External scanners are evidence sources, not autonomous truth:
- native oracle NO_EFFECT beats a scanner "possible" -> REFUTED/INSUFFICIENT
- version-matched intel on a confirmed service -> promote
- browser + HTTP agreement -> strengthen
Disagreement never arbitrarily confirms.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from horcrux.engine.oracles import OracleResult


class CorrelatedVerdict(BaseModel):
    property_id: str
    verdict: str = "INSUFFICIENT"  # CONFIRMED|REFUTED|INSUFFICIENT|BLOCKED
    confidence: float = 0.5
    evidence: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    native_verdict: str = ""
    external_claims: list[str] = Field(default_factory=list)


def correlate(property_id: str, native: OracleResult | None,
              external: list[dict] | None = None) -> CorrelatedVerdict:
    external = list(external or [])
    claims = [str(e.get("claim", "possible")) for e in external]
    sources = sorted({str(e.get("source", "external")) for e in external})
    if native is None:
        if any(c.lower() in ("confirmed", "high") for c in claims) and len(sources) >= 2:
            return CorrelatedVerdict(property_id=property_id, verdict="INSUFFICIENT",
                                     confidence=0.55,
                                     evidence=["two external claims agree but no native oracle evidence"],
                                     sources=sources, external_claims=claims)
        return CorrelatedVerdict(property_id=property_id, verdict="INSUFFICIENT",
                                 confidence=0.4,
                                 evidence=["external claim without native corroboration"],
                                 sources=sources, external_claims=claims)
    if native.verdict == "CONFIRMED":
        return CorrelatedVerdict(property_id=property_id, verdict="CONFIRMED",
                                 confidence=min(0.95, native.confidence + 0.05 * len(sources)),
                                 evidence=list(native.evidence) + [f"external:{s}" for s in sources],
                                 sources=["native"] + sources,
                                 native_verdict="CONFIRMED", external_claims=claims)
    # Native oracle ran and says NO_EFFECT: scanner "possible" must not win.
    if external and native.verdict in ("REFUTED", "INSUFFICIENT"):
        if native.verdict == "REFUTED":
            return CorrelatedVerdict(property_id=property_id, verdict="REFUTED",
                                     confidence=native.confidence,
                                     evidence=list(native.evidence) + ["external claim overruled by native oracle"],
                                     sources=["native"] + sources,
                                     native_verdict="REFUTED", external_claims=claims)
        return CorrelatedVerdict(property_id=property_id, verdict="INSUFFICIENT",
                                 confidence=0.45,
                                 evidence=list(native.evidence) + ["external claim insufficient without native effect"],
                                 sources=["native"] + sources,
                                 native_verdict="INSUFFICIENT", external_claims=claims)
    return CorrelatedVerdict(property_id=property_id, verdict=native.verdict,
                             confidence=native.confidence,
                             evidence=list(native.evidence),
                             sources=["native"], native_verdict=native.verdict,
                             external_claims=claims)
