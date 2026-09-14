"""Sensitive data detection and redaction (Phase 9, Part 28).

Detects credentials, tokens, API keys, secrets, PII, internal hostnames,
and debug information in capability output and evidence.

CRITICAL: Raw secrets are NEVER stored — only references and hashes.
Redaction is applied before evidence is persisted.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any


# Patterns for sensitive data detection
_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    # Credentials
    ("credential", "password_in_content",
     re.compile(r'(?:password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\'&,;]{6,})', re.I)),
    ("credential", "secret_key",
     re.compile(r'(?:secret|api_?key|api_?secret|private_?key)\s*[=:]\s*["\']?([A-Za-z0-9_\-+/=]{16,})', re.I)),
    # Tokens
    ("token", "bearer_token",
     re.compile(r'[Bb]earer\s+([A-Za-z0-9_\-+/=.]{20,})')),
    ("token", "jwt_token",
     re.compile(r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+')),
    ("token", "aws_key",
     re.compile(r'(?:AKIA|AIPA|AGPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}')),
    ("token", "github_token",
     re.compile(r'gh[ps]_[A-Za-z0-9]{36,}')),
    ("token", "generic_api_key",
     re.compile(r'(?:api[-_]?key|apikey|x-api-key)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})', re.I)),
    # PII
    ("pii", "email_address",
     re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b')),
    ("pii", "phone_number",
     re.compile(r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b')),
    ("pii", "credit_card",
     re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b')),
    ("pii", "ssn",
     re.compile(r'\b\d{3}-\d{2}-\d{4}\b')),
    # Internal infrastructure
    ("infra", "internal_hostname",
     re.compile(r'(?:https?://)?(?:internal|corp|intranet|staging|dev|test)[-.][\w.-]+(?:\.local|\.internal|\.corp)\b', re.I)),
    ("infra", "private_ip",
     re.compile(r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b')),
    # Debug/error
    ("debug", "stack_trace_path",
     re.compile(r'(?:/home/\w+|/var/www|/usr/local|/app/|C:\\Users\\)[^\s"\'>\n]{3,60}')),
    ("debug", "connection_string",
     re.compile(r'(?:postgresql|mysql|mongodb|redis)://[^\s"\']{10,}', re.I)),
]

# Patterns to redact from stored evidence
_REDACT_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("PASSWORD", re.compile(r'(?:password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\'&,;]{6,})', re.I)),
    ("TOKEN", re.compile(r'[Bb]earer\s+([A-Za-z0-9_\-+/=.]{20,})')),
    ("JWT", re.compile(r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+')),
    ("API_KEY", re.compile(r'(?:AKIA|AIPA|AGPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}')),
    ("GH_TOKEN", re.compile(r'gh[ps]_[A-Za-z0-9]{36,}')),
]


@dataclass
class SensitiveDataObservation:
    """An observation of sensitive data in evidence."""
    category: str           # credential, token, pii, infra, debug
    pattern_id: str         # specific pattern that matched
    location: str           # where this was found (URL, response body, header)
    redacted_sample: str    # [REDACTED] or hash of the sensitive value
    confidence: float = 0.8
    evidence_ref: str = ""  # reference to the source evidence
    needs_finding: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "pattern_id": self.pattern_id,
            "location": self.location,
            "redacted_sample": self.redacted_sample,
            "confidence": self.confidence,
            "needs_finding": self.needs_finding,
        }


class SensitiveDataDetector:
    """Pattern-based sensitive data detection with automatic redaction.

    Stores references and hashes — never raw secrets.
    """

    def __init__(self, min_confidence: float = 0.7):
        self.min_confidence = min_confidence
        self._findings: list[SensitiveDataObservation] = []

    def scan(
        self,
        content: str,
        location: str = "response",
        evidence_ref: str = "",
    ) -> list[SensitiveDataObservation]:
        """Scan content for sensitive data patterns."""
        observations = []
        for category, pattern_id, pattern in _PATTERNS:
            try:
                matches = pattern.findall(content)
                if not matches:
                    continue
                for match in matches[:3]:  # cap to avoid explosion
                    raw_value = match if isinstance(match, str) else str(match)
                    # Never store the raw value — only a hash reference
                    value_hash = hashlib.sha256(raw_value.encode()).hexdigest()[:12]
                    obs = SensitiveDataObservation(
                        category=category,
                        pattern_id=pattern_id,
                        location=location,
                        redacted_sample=f"[{category.upper()}:{value_hash}]",
                        confidence=0.85 if category in ("token", "credential") else 0.75,
                        evidence_ref=evidence_ref,
                        needs_finding=category in ("credential", "token", "pii"),
                    )
                    observations.append(obs)
                    self._findings.append(obs)
            except Exception:
                continue
        return observations

    def scan_evidence_dict(
        self,
        evidence: dict[str, Any],
        evidence_ref: str = "",
    ) -> list[SensitiveDataObservation]:
        """Scan a capability evidence dict for sensitive data."""
        observations = []
        # Scan relevant fields
        for field_name in ("body", "stdout", "response_body", "content", "summary"):
            value = evidence.get(field_name, "")
            if value and isinstance(value, str):
                obs = self.scan(value, location=f"evidence:{field_name}", evidence_ref=evidence_ref)
                observations.extend(obs)
        # Scan headers
        headers = evidence.get("headers", {})
        if isinstance(headers, dict):
            for k, v in headers.items():
                if any(s in k.lower() for s in ("auth", "token", "cookie", "key")):
                    obs = self.scan(str(v), location=f"header:{k}", evidence_ref=evidence_ref)
                    observations.extend(obs)
        return observations

    def all_findings(self) -> list[SensitiveDataObservation]:
        return list(self._findings)


def redact_secrets(content: str) -> str:
    """Redact known secret patterns from a string.

    Used before storing evidence, logs, or reports.
    Replaces sensitive values with [REDACTED:<type>] tokens.
    """
    if not content or not isinstance(content, str):
        return content
    result = content
    for label, pattern in _REDACT_PATTERNS:
        try:
            result = pattern.sub(f"[REDACTED:{label}]", result)
        except Exception:
            continue
    return result


def scan_capability_result(
    result: Any,
    capability_id: str = "",
) -> list[SensitiveDataObservation]:
    """Scan a CapabilityResult for sensitive data.

    Returns observations. Does NOT modify the result in-place — caller
    must decide whether to redact.
    """
    detector = SensitiveDataDetector()
    observations = []

    if hasattr(result, "stdout"):
        observations.extend(detector.scan(
            result.stdout or "", f"{capability_id}:stdout",
            evidence_ref=f"capability:{capability_id}",
        ))
    if hasattr(result, "stderr"):
        observations.extend(detector.scan(
            result.stderr or "", f"{capability_id}:stderr",
            evidence_ref=f"capability:{capability_id}",
        ))
    if hasattr(result, "structured_data") and isinstance(result.structured_data, dict):
        observations.extend(detector.scan_evidence_dict(
            result.structured_data,
            evidence_ref=f"capability:{capability_id}",
        ))

    return observations


def ingest_sensitive_observations(
    app: Any,
    observations: list[SensitiveDataObservation],
) -> None:
    """Record sensitive data observations in the ApplicationModel."""
    if not observations:
        return
    if not hasattr(app, "sensitive_data_observations"):
        return
    for obs in observations:
        app.sensitive_data_observations.append(obs.to_dict())
    # Cap to prevent unbounded growth
    if len(app.sensitive_data_observations) > 100:
        app.sensitive_data_observations = app.sensitive_data_observations[-100:]
