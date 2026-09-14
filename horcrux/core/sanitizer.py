from __future__ import annotations

import hashlib
import re
from typing import Iterable, Optional


def mask_key(key: str) -> str:
    """Mask an API key for safe display in UI, logs, and settings screens."""
    if not key or not key.strip():
        return "NOT CONFIGURED"
    k = key.strip()
    if len(k) <= 8:
        return "••••••••"

    # Recognized provider prefix patterns
    if k.startswith("gsk_"):
        return f"gsk_••••••••{k[-4:]}"
    elif k.startswith("sk-ant-"):
        return f"sk-ant-••••••••{k[-4:]}"
    elif k.startswith("sk-"):
        return f"sk-••••••••{k[-4:]}"
    elif k.startswith("AIza"):
        return f"AIza••••••••{k[-4:]}"

    prefix = k[:3]
    suffix = k[-4:]
    return f"{prefix}••••••••{suffix}"


def fingerprint_key(key: str) -> str:
    """
    Generate an irreversible, safe fingerprint of an API key for diagnostics.
    Returns: 'SHA256: <first8>...<last4>' or 'NONE' if key is empty.
    """
    if not key or not key.strip():
        return "NONE"
    k = key.strip()
    digest = hashlib.sha256(k.encode("utf-8")).hexdigest()
    return f"SHA256: {digest[:8]}...{digest[-4:]}"


def redact_secrets(text: str, extra_secrets: Optional[Iterable[str]] = None) -> str:
    """
    Centralized sanitization function to ensure API keys and sensitive tokens
    are NEVER exposed through:
      - Rich console errors
      - Tracebacks
      - HTTP exception strings
      - URLs & query parameters
      - Logs
      - Reports
    """
    if not text:
        return ""

    sanitized = text

    # 1. Redact known query parameters in URLs: ?key=..., &key=..., &api_key=..., &token=...
    sanitized = re.sub(
        r"([?&](?:key|api[_-]?key|token|access[_-]?token|authorization)=)([^&\s\"'>\\]+)",
        r"\g<1>[REDACTED]",
        sanitized,
        flags=re.IGNORECASE,
    )

    # 2. Redact sensitive authorization / API key headers
    sanitized = re.sub(
        r"(Authorization\s*:\s*(?:Bearer|Basic)\s+)([^\s\"',\\]+)",
        r"\g<1>[REDACTED]",
        sanitized,
        flags=re.IGNORECASE,
    )
    sanitized = re.sub(
        r"(x-goog-api-key\s*:\s*)([^\s\"',\\]+)",
        r"\g<1>[REDACTED]",
        sanitized,
        flags=re.IGNORECASE,
    )
    sanitized = re.sub(
        r"(x-api-key\s*:\s*)([^\s\"',\\]+)",
        r"\g<1>[REDACTED]",
        sanitized,
        flags=re.IGNORECASE,
    )

    # 3. Redact common API key format patterns (e.g. AIza..., sk-ant-..., gsk_..., sk-...)
    sanitized = re.sub(r"\bAIza[0-9A-Za-z-_]{35}\b", "AIza••••[REDACTED]", sanitized)
    sanitized = re.sub(r"\bsk-ant-[0-9A-Za-z-_]{20,}\b", "sk-ant-••••[REDACTED]", sanitized)
    sanitized = re.sub(r"\bgsk_[0-9A-Za-z-_]{20,}\b", "gsk_••••[REDACTED]", sanitized)
    sanitized = re.sub(r"\bsk-[0-9A-Za-z-_]{20,}\b", "sk-••••[REDACTED]", sanitized)

    # 3b. Redact JWTs (header.payload.signature) — Phase 8.
    sanitized = re.sub(
        r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b",
        "[JWT-REDACTED]",
        sanitized,
    )

    # 3c. Redact cookie/session values and JSON secret fields — Phase 8.
    sanitized = re.sub(
        r"(?i)((?:cookie|sessionid|session[_-]?id|session[_-]?token|auth[_-]?token|"
        r"password|passwd|secret|set-cookie)\s*[:=]\s*)([^\s;,\"'}]+)",
        r"\g<1>[REDACTED]",
        sanitized,
    )
    # Bare bearer tokens without a header name (e.g. stored token values).
    sanitized = re.sub(
        r"(?i)\b(Bearer\s+)([A-Za-z0-9_\-\.~+/=]{6,})",
        r"\g<1>[REDACTED]",
        sanitized,
    )
    sanitized = re.sub(
        r"(?i)(\"?(?:password|secret|token|api_key|apikey|session)\"?\s*:\s*\")([^\"]+)(\")",
        r"\g<1>[REDACTED]\g<3>",
        sanitized,
    )

    # 4. Redact any explicitly passed secret strings (e.g. active configured keys)
    if extra_secrets:
        for secret in extra_secrets:
            if secret and len(secret.strip()) >= 6:
                s = secret.strip()
                masked = mask_key(s)
                sanitized = sanitized.replace(s, masked)

    return sanitized


def redact_dict(data: Any, extra_secrets: Optional[Iterable[str]] = None) -> Any:
    """Recursively redact secrets in structured data (reports, events, prompts)."""
    if isinstance(data, str):
        return redact_secrets(data, extra_secrets)
    if isinstance(data, dict):
        return {k: redact_dict(v, extra_secrets) for k, v in data.items()}
    if isinstance(data, (list, tuple)):
        return [redact_dict(v, extra_secrets) for v in data]
    return data


_SECRET_FINDINGS = [
    (re.compile(r"\bAIza[0-9A-Za-z-_]{35}\b"), "google-api-key"),
    (re.compile(r"\bsk-ant-[0-9A-Za-z-_]{20,}\b"), "anthropic-key"),
    (re.compile(r"\bgsk_[0-9A-Za-z-_]{20,}\b"), "groq-key"),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"), "jwt"),
    (re.compile(r"(?i)password\s*[:=]\s*\S+"), "password-assignment"),
]


def scan_for_secrets(text: str) -> list[dict[str, str]]:
    """Audit helper: locate unredacted secret-like patterns in text output."""
    hits: list[dict[str, str]] = []
    for pattern, kind in _SECRET_FINDINGS:
        for match in pattern.finditer(text or ""):
            if "[REDACTED]" in match.group(0) or "••••" in match.group(0):
                continue
            hits.append({"kind": kind, "sample": match.group(0)[:24] + "…"})
    return hits
