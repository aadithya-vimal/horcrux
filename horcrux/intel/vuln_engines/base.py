"""Stable provider-neutral engine contract.

Every external engine (cloud platform, local service, imported result)
implements ExternalVulnerabilityEngine. Core assessment logic must never
contain provider-specific branches — it talks only to this contract.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional

from horcrux.core.sanitizer import redact_secrets
from horcrux.intel.vuln_engines.types import (
    EngineCapability,
    EngineHealth,
    NormalizedExternalFinding,
    ProviderMetadata,
    ScanLifecycle,
)


@dataclass
class EngineResult:
    ok: bool
    status: ScanLifecycle = ScanLifecycle.COMPLETE
    message: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    rate_limited: bool = False
    auth_failed: bool = False


@dataclass
class ScanHandle:
    provider_scan_id: str = ""
    status: ScanLifecycle = ScanLifecycle.QUEUED
    detail: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


class ExternalVulnerabilityEngine(ABC):
    """Provider-neutral contract. All network I/O injectable for tests."""

    provider_id: str = "base"
    metadata: ProviderMetadata | None = None

    def __init__(
        self,
        config: dict[str, Any] | None = None,
        credentials: dict[str, Any] | None = None,
        client: Any | None = None,
    ) -> None:
        self.config = dict(config or {})
        self._credentials = dict(credentials or {})
        self._client = client  # injectable httpx.Client / mock / GMP session
        self._api_calls = 0
        self._scan_submissions = 0

    # -- identity ------------------------------------------------------
    @property
    def product(self) -> str:
        return self.metadata.product if self.metadata else self.provider_id

    def describe(self) -> dict[str, Any]:
        md = self.metadata
        return {
            "provider_id": self.provider_id,
            "product": md.product if md else self.provider_id,
            "api_version": md.api_version if md else "",
            "docs_verified": md.docs_verified if md else "",
            "deployment_type": md.deployment_type.value if md else "",
            "endpoint": self.endpoint(),
            "authentication_type": md.authentication_type if md else "",
            "capabilities": [c.capability_id for c in self.capabilities()],
            "supported_asset_types": list(md.supported_asset_types) if md else [],
            "supported_scan_types": list(md.supported_scan_types) if md else [],
            "supported_result_formats": list(md.supported_result_formats) if md else [],
            "known_limitations": list(md.known_limitations) if md else [],
        }

    def endpoint(self) -> str:
        return str(self.config.get("endpoint", "") or "")

    def is_configured(self) -> bool:
        ok, _ = self.validate_configuration()
        return ok

    # -- contract ------------------------------------------------------
    @abstractmethod
    def validate_configuration(self) -> tuple[bool, str]:
        """Check config shape WITHOUT network. Returns (ok, reason)."""

    @abstractmethod
    def authenticate(self) -> EngineResult:
        """Verify credentials against the provider (may be mocked)."""

    @abstractmethod
    def health_check(self) -> EngineHealth:
        """Return canonical health without raising."""

    @abstractmethod
    def capabilities(self) -> list[EngineCapability]:
        """Declare what this engine can do."""

    def supports_scan_lifecycle(self) -> bool:
        """False for intelligence-only connectors (no scan lifecycle exposed)."""
        return True

    def prepare_scan(self, target: str, context: dict[str, Any] | None = None) -> EngineResult:
        """Validate scope + build scan request. Deterministic, no network."""
        reason = self.check_scope(target)
        if reason:
            return EngineResult(ok=False, status=ScanLifecycle.CONFIGURATION_ERROR, message=reason)
        return EngineResult(ok=True, status=ScanLifecycle.READY, message="ready",
                            data={"target": target, "context": context or {}})

    @abstractmethod
    def create_scan(self, target: str, context: dict[str, Any] | None = None) -> ScanHandle:
        """Create/reuse a provider-side scan. Persist IDs in workspace state."""

    @abstractmethod
    def launch_scan(self, provider_scan_id: str) -> ScanHandle:
        """Launch a created scan."""

    @abstractmethod
    def get_status(self, provider_scan_id: str) -> ScanHandle:
        """Poll provider-side status, mapped to ScanLifecycle."""

    def cancel_scan(self, provider_scan_id: str) -> EngineResult:  # noqa: ARG002
        return EngineResult(ok=True, status=ScanLifecycle.COMPLETE, message="cancel not supported; ignored")

    @abstractmethod
    def get_results(self, provider_scan_id: str) -> list[dict[str, Any]]:
        """Retrieve raw provider results (redacted before logging)."""

    @abstractmethod
    def normalize_results(self, raw: list[dict[str, Any]], target: str = "") -> list[NormalizedExternalFinding]:
        """Map raw provider records to NormalizedExternalFinding."""

    def map_assets(self, raw: list[dict[str, Any]]) -> list[str]:
        assets: list[str] = []
        for item in raw:
            for key in ("asset", "host", "ip", "hostname", "address"):
                val = item.get(key)
                if val and val not in assets:
                    assets.append(str(val))
        return assets

    def map_findings(self, findings: list[NormalizedExternalFinding]) -> list[dict[str, Any]]:
        return [f.model_dump() for f in findings]

    def close_scan(self, provider_scan_id: str) -> EngineResult:  # noqa: ARG002
        return EngineResult(ok=True, status=ScanLifecycle.COMPLETE, message="closed")

    # -- shared helpers ------------------------------------------------
    def check_scope(self, target: str) -> str:
        """Deterministic scope gate. Returns '' when allowed, reason when blocked."""
        if not target or not str(target).strip():
            return "empty target"
        allowed = self.config.get("allowed_targets")
        if allowed and str(target) not in [str(a) for a in allowed]:
            return f"target {target} outside engine allowed_targets"
        return ""

    def safe_message(self, message: str) -> str:
        secrets = [v for v in self._credentials.values() if isinstance(v, str) and v]
        return redact_secrets(message or "", extra_secrets=secrets)

    def redact(self, payload: Any) -> Any:
        from horcrux.core.sanitizer import redact_dict

        secrets = [v for v in self._credentials.values() if isinstance(v, str) and v]
        return redact_dict(payload, extra_secrets=secrets)

    def track_call(self, scans: int = 0) -> None:
        self._api_calls += 1
        self._scan_submissions += scans

    @property
    def usage(self) -> dict[str, int]:
        return {"api_requests": self._api_calls, "scan_submissions": self._scan_submissions}

    def _cred(self, *names: str, default: str = "") -> str:
        for name in names:
            val = self._credentials.get(name)
            if val:
                return str(val)
        return default

    def _cfg(self, *names: str, default: Any = "") -> Any:
        for name in names:
            if name in self.config and self.config[name] not in (None, ""):
                return self.config[name]
        return default

    def client(self) -> Any:
        """Return injected client or build a default httpx client (no live calls in tests)."""
        if self._client is not None:
            return self._client
        import httpx

        return httpx.Client(timeout=float(self.config.get("timeout", 30)))

    def _fail(self, message: str, status: ScanLifecycle, *, auth: bool = False,
              rate: bool = False) -> EngineResult:
        return EngineResult(ok=False, status=status, message=self.safe_message(message),
                            auth_failed=auth, rate_limited=rate)
