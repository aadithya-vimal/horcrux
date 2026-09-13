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

    # 4. Redact any explicitly passed secret strings (e.g. active configured keys)
    if extra_secrets:
        for secret in extra_secrets:
            if secret and len(secret.strip()) >= 6:
                s = secret.strip()
                masked = mask_key(s)
                sanitized = sanitized.replace(s, masked)

    return sanitized
