"""Differential testing engine (Phase 9, Part 15).

Compares:
- baseline vs modified request
- identity A vs identity B
- anonymous vs authenticated
- role A vs role B

Used by authz_compare, authorization investigation, session analysis.
The engine never executes requests itself — it compares pre-collected snapshots.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class DifferentialVerdict(str, Enum):
    SAME = "SAME"                   # responses equivalent
    DIFFERENT = "DIFFERENT"         # responses differ significantly
    INCONCLUSIVE = "INCONCLUSIVE"   # cannot determine
    ERROR = "ERROR"                 # one or both requests failed


@dataclass
class RequestSpec:
    """A request to make for differential testing."""
    url: str
    method: str = "GET"
    headers: dict[str, str] = field(default_factory=dict)
    body: Any = None
    identity: str = "anonymous"
    timeout: int = 10


@dataclass
class ResponseSnapshot:
    """Snapshot of an HTTP response for comparison."""
    status_code: int = 0
    body: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    size: int = 0
    duration_ms: float = 0.0
    identity: str = ""
    error: str = ""

    def __post_init__(self) -> None:
        # Auto-calculate size from body if not provided
        if self.size == 0 and self.body:
            self.size = len(self.body.encode("utf-8", errors="replace"))


@dataclass
class DifferentialResult:
    """Result of comparing two responses."""
    baseline: ResponseSnapshot
    modified: ResponseSnapshot
    status_diff: int = 0
    size_diff: int = 0
    timing_diff_ms: float = 0.0
    semantic_fields_differ: bool = False
    authorization_outcome_differs: bool = False
    verdict: DifferentialVerdict = DifferentialVerdict.INCONCLUSIVE
    confidence: float = 0.5
    evidence: list[str] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline_status": self.baseline.status_code,
            "modified_status": self.modified.status_code,
            "baseline_size": self.baseline.size,
            "modified_size": self.modified.size,
            "status_diff": self.status_diff,
            "size_diff": self.size_diff,
            "timing_diff_ms": self.timing_diff_ms,
            "semantic_fields_differ": self.semantic_fields_differ,
            "authorization_outcome_differs": self.authorization_outcome_differs,
            "verdict": self.verdict.value,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "notes": self.notes,
        }

    @property
    def suggests_vulnerability(self) -> bool:
        """True if differential suggests a potential authorization vulnerability."""
        return (
            self.verdict == DifferentialVerdict.DIFFERENT
            and self.authorization_outcome_differs
            and self.confidence >= 0.7
        )


class DifferentialEngine:
    """Reusable differential testing engine.

    The engine compares pre-collected response snapshots.
    It does NOT execute requests itself — that is the capability's job.
    """

    def compare_snapshots(
        self,
        baseline: ResponseSnapshot,
        modified: ResponseSnapshot,
        comparison_context: str = "",
    ) -> DifferentialResult:
        """Compare two response snapshots."""
        result = DifferentialResult(baseline=baseline, modified=modified)

        if baseline.error or modified.error:
            result.verdict = DifferentialVerdict.ERROR
            result.confidence = 0.3
            result.notes = f"Error: baseline={baseline.error!r} modified={modified.error!r}"
            return result

        result.status_diff = modified.status_code - baseline.status_code
        result.size_diff = modified.size - baseline.size
        result.timing_diff_ms = abs(modified.duration_ms - baseline.duration_ms)

        # Authorization outcome comparison
        baseline_denied = baseline.status_code in (401, 403)
        modified_denied = modified.status_code in (401, 403)
        baseline_allowed = 200 <= baseline.status_code < 300
        modified_allowed = 200 <= modified.status_code < 300

        if baseline_denied != modified_denied or baseline_allowed != modified_allowed:
            result.authorization_outcome_differs = True

        # Verdict logic
        if baseline.status_code == modified.status_code:
            size_ratio = abs(result.size_diff) / max(baseline.size, 1)
            if size_ratio > 0.3 and abs(result.size_diff) > 100:
                result.verdict = DifferentialVerdict.DIFFERENT
                result.confidence = 0.6
                result.semantic_fields_differ = True
            else:
                result.verdict = DifferentialVerdict.SAME
                result.confidence = 0.85
        elif result.authorization_outcome_differs:
            result.verdict = DifferentialVerdict.DIFFERENT
            result.confidence = 0.9
        elif abs(result.status_diff) > 0:
            result.verdict = DifferentialVerdict.DIFFERENT
            result.confidence = 0.75
        else:
            result.verdict = DifferentialVerdict.INCONCLUSIVE
            result.confidence = 0.4

        # Build evidence
        if result.authorization_outcome_differs:
            result.evidence.append(
                f"Authorization outcome differs: {baseline.identity} got {baseline.status_code}, "
                f"{modified.identity} got {modified.status_code}"
            )
        if abs(result.size_diff) > 500:
            result.evidence.append(
                f"Response size differs significantly: {baseline.size} vs {modified.size} bytes"
            )
        result.notes = comparison_context

        return result

    def compare_identities(
        self,
        identity_a_snapshot: ResponseSnapshot,
        identity_b_snapshot: ResponseSnapshot,
    ) -> DifferentialResult:
        """Compare access from identity A vs identity B to the same resource."""
        return self.compare_snapshots(
            identity_a_snapshot, identity_b_snapshot,
            f"Identity comparison: {identity_a_snapshot.identity} vs {identity_b_snapshot.identity}",
        )

    def compare_auth_states(
        self,
        anonymous_snapshot: ResponseSnapshot,
        authenticated_snapshot: ResponseSnapshot,
    ) -> DifferentialResult:
        """Compare anonymous vs authenticated access."""
        return self.compare_snapshots(
            anonymous_snapshot, authenticated_snapshot,
            "Anonymous vs authenticated access comparison",
        )

    def compare_roles(
        self,
        role_a_snapshot: ResponseSnapshot,
        role_b_snapshot: ResponseSnapshot,
        endpoint: str = "",
    ) -> DifferentialResult:
        """Compare role A vs role B access."""
        return self.compare_snapshots(
            role_a_snapshot, role_b_snapshot,
            f"Role comparison: {role_a_snapshot.identity} vs {role_b_snapshot.identity}"
            + (f" @ {endpoint}" if endpoint else ""),
        )

    def synthetic_compare(
        self,
        endpoint: str,
        identity_a: str,
        identity_b: str,
        app: Any = None,
    ) -> DifferentialResult:
        """Synthetic comparison from ApplicationModel (offline/fixture mode).

        Used when actual HTTP requests cannot be made (synthetic targets, test mode).
        Derives expected outcomes from the ApplicationModel.
        """
        privileged = "admin" in endpoint.lower() or "management" in endpoint.lower()
        object_bearing = "{" in endpoint or (
            "/" in endpoint and endpoint.split("/")[-1].isdigit()
        )

        def _status_for(identity: str) -> int:
            if privileged and identity not in ("admin", "administrator"):
                return 403
            if object_bearing and identity == "anonymous":
                return 200  # IDOR scenario: object accessible without auth
            return 200

        snap_a = ResponseSnapshot(
            status_code=_status_for(identity_a),
            size=500 + (100 if _status_for(identity_a) == 200 else 0),
            identity=identity_a,
        )
        snap_b = ResponseSnapshot(
            status_code=_status_for(identity_b),
            size=500 + (100 if _status_for(identity_b) == 200 else 0),
            identity=identity_b,
        )
        return self.compare_snapshots(
            snap_a, snap_b,
            f"Synthetic: {identity_a} vs {identity_b} @ {endpoint}",
        )


# Module-level singleton
_engine = DifferentialEngine()


def get_differential_engine() -> DifferentialEngine:
    """Get the shared differential engine instance."""
    return _engine


def compare_identity_access(
    endpoint: str,
    method: str,
    identity_a_result: dict[str, Any],
    identity_b_result: dict[str, Any],
) -> DifferentialResult:
    """Convenience wrapper: compare two capability result dicts."""
    snap_a = ResponseSnapshot(
        status_code=identity_a_result.get("status_code", 0),
        size=identity_a_result.get("response_size",
                                   len(identity_a_result.get("body", ""))),
        identity=identity_a_result.get("identity", "identity_a"),
        error=identity_a_result.get("error", ""),
    )
    snap_b = ResponseSnapshot(
        status_code=identity_b_result.get("status_code", 0),
        size=identity_b_result.get("response_size",
                                   len(identity_b_result.get("body", ""))),
        identity=identity_b_result.get("identity", "identity_b"),
        error=identity_b_result.get("error", ""),
    )
    return _engine.compare_identities(snap_a, snap_b)
