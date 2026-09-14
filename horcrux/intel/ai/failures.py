"""AI failure classification (Phase 7, Part 15).

No bypasses of provider safety policies. Failures are classified; safety
refusals are reframed around evidence/properties/validation rather than
retried verbatim; the deterministic engine continues regardless.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class AIFailure(BaseModel):
    category: str = "unknown"  # authentication, rate_limit, quota, unavailable_model,
    # malformed_output, timeout, network, safety_refusal, unsupported_capability
    retryable: bool = False
    reframed_task: str = ""
    detail: str = ""


_SAFETY_MARKERS = ("safety", "blocked", "refus", "policy violation",
                   "harmful", "disallowed", "content filter")


def classify_ai_failure(exc: BaseException | Any) -> AIFailure:
    from horcrux.intel.ai.base import AIError, AIErrorType
    text = f"{type(exc).__name__}: {exc}".lower()
    if isinstance(exc, AIError):
        et = exc.error_type
        if et == AIErrorType.SAFETY_BLOCK:
            return AIFailure(category="safety_refusal", retryable=False,
                             reframed_task=_reframe(),
                             detail=exc.diagnostic or exc.message)
        mapping = {
            AIErrorType.AUTHENTICATION_FAILED: ("authentication", False),
            AIErrorType.RATE_LIMITED: ("rate_limit", True),
            AIErrorType.QUOTA_EXCEEDED: ("quota", False),
            AIErrorType.MODEL_NOT_FOUND: ("unavailable_model", False),
            AIErrorType.MODEL_UNAVAILABLE: ("unavailable_model", False),
            AIErrorType.INVALID_RESPONSE: ("malformed_output", False),
            AIErrorType.TIMEOUT: ("timeout", True),
            AIErrorType.NETWORK_ERROR: ("network", True),
            AIErrorType.PROVIDER_UNAVAILABLE: ("network", True),
            AIErrorType.UNSUPPORTED_FEATURE: ("unsupported_capability", False),
            AIErrorType.PERMISSION_DENIED: ("authentication", False),
        }
        if et in mapping:
            cat, retry = mapping[et]
            return AIFailure(category=cat, retryable=retry,
                             detail=exc.diagnostic or exc.message)
    if any(m in text for m in _SAFETY_MARKERS):
        return AIFailure(category="safety_refusal", retryable=False,
                         reframed_task=_reframe(), detail=str(exc)[:300])
    if "rate" in text and "limit" in text:
        return AIFailure(category="rate_limit", retryable=True, detail=str(exc)[:300])
    if "quota" in text:
        return AIFailure(category="quota", retryable=False, detail=str(exc)[:300])
    if "timeout" in text or "timed out" in text:
        return AIFailure(category="timeout", retryable=True, detail=str(exc)[:300])
    if "network" in text or "connection" in text:
        return AIFailure(category="network", retryable=True, detail=str(exc)[:300])
    return AIFailure(category="unknown", retryable=False, detail=str(exc)[:300])


def _reframe() -> str:
    return ("Reframe around observed evidence, security property, missing "
            "verification, hypotheses, safe validation criteria, impact "
            "assessment, and operator handoff — without exploit instructions.")


def should_retry(failure: AIFailure, attempts: int) -> bool:
    if failure.category == "safety_refusal":
        return False
    return failure.retryable and attempts < 1
