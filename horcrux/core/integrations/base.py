"""Abstract base class and specialized contracts for external integrations."""

from __future__ import annotations

import os
import shutil
import time
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

from horcrux.core.integrations.models import (
    IntegrationCategory,
    IntegrationErrorType,
    IntegrationHealth,
    IntegrationHealthResult,
    IntegrationMetadata,
    IntegrationStatus,
    IntegrationTestResult,
)

if TYPE_CHECKING:
    from horcrux.core.settings import SettingsManager


class ExternalIntegration(ABC):
    """Authoritative base class for every external integration in HORCRUX.

    Integrations represent external systems, providers, APIs, or binaries
    that extend HORCRUX's capabilities (AI providers, vulnerability engines,
    security tools, browser automation).
    """

    def __init__(self, settings_manager: SettingsManager | None = None) -> None:
        self._settings_manager = settings_manager

    @property
    def settings_manager(self) -> SettingsManager:
        if self._settings_manager is None:
            from horcrux.core.settings import get_settings_manager
            self._settings_manager = get_settings_manager()
        return self._settings_manager

    @settings_manager.setter
    def settings_manager(self, manager: SettingsManager) -> None:
        self._settings_manager = manager

    @abstractmethod
    def metadata(self) -> IntegrationMetadata:
        """Return full declarative metadata for this integration."""
        raise NotImplementedError

    @property
    def id(self) -> str:
        return self.metadata().id

    @property
    def name(self) -> str:
        return self.metadata().name

    @property
    def category(self) -> IntegrationCategory:
        return self.metadata().category

    def is_configured(self) -> bool:
        """Check if all required credentials and configurations are present."""
        meta = self.metadata()
        creds = self.get_credentials()
        for field in meta.credential_fields:
            if field.required and not creds.get(field.name):
                return False
        return True

    def is_enabled(self) -> bool:
        """Check if the integration is enabled in settings."""
        cfg = self.get_config()
        return bool(cfg.get("enabled", True))

    def set_enabled(self, enabled: bool) -> None:
        """Enable or disable this integration."""
        cfg = self.get_config()
        cfg["enabled"] = bool(enabled)
        self.settings_manager.set_integration_config(self.id, cfg)

    def validate_configuration(self) -> tuple[bool, str]:
        """Validate configuration parameters without performing network requests."""
        meta = self.metadata()
        creds = self.get_credentials()

        missing_creds = [
            f.label or f.name for f in meta.credential_fields
            if f.required and not creds.get(f.name)
        ]
        if missing_creds:
            return False, f"Missing required credentials: {', '.join(missing_creds)}"

        if meta.requires_binary:
            missing_bins = [b for b in meta.binary_names if not shutil.which(b)]
            if missing_bins:
                return False, f"Required system binary not found on PATH: {', '.join(missing_bins)}"

        return True, "Configuration is valid."

    def health_check(self, quick: bool = True) -> IntegrationHealthResult:
        """Passive or cached inspection of integration health."""
        is_conf = self.is_configured()
        if not is_conf:
            return IntegrationHealthResult(
                health=IntegrationHealth.NOT_CONFIGURED,
                message=f"{self.name} credentials are not configured.",
                error_type=IntegrationErrorType.NOT_CONFIGURED,
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            )

        if not self.is_enabled():
            return IntegrationHealthResult(
                health=IntegrationHealth.DEGRADED,
                message=f"{self.name} is configured but disabled in settings.",
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            )

        val_ok, val_msg = self.validate_configuration()
        if not val_ok:
            return IntegrationHealthResult(
                health=IntegrationHealth.UNHEALTHY,
                message=val_msg,
                error_type=IntegrationErrorType.INVALID_CONFIGURATION,
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            )

        # Base default: if configured and valid, it is CONFIGURED
        return IntegrationHealthResult(
            health=IntegrationHealth.CONFIGURED,
            message=f"{self.name} is configured and ready.",
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )

    def test_connection(self) -> IntegrationTestResult:
        """Active live connection/probe test against the external integration."""
        start = time.perf_counter()
        health = self.health_check(quick=False)
        latency = round((time.perf_counter() - start) * 1000, 2)

        if health.health in (IntegrationHealth.NOT_CONFIGURED, IntegrationHealth.UNHEALTHY):
            return IntegrationTestResult(
                ok=False,
                status=health.health,
                message=health.message,
                latency_ms=latency,
                error_type=health.error_type,
            )

        return IntegrationTestResult(
            ok=True,
            status=IntegrationHealth.OPERATIONAL,
            message=f"Successfully connected to {self.name}.",
            latency_ms=latency,
        )

    def capabilities(self) -> list[str]:
        """Return the list of capabilities offered by this integration."""
        if not self.is_configured() or not self.is_enabled():
            return []
        return list(self.metadata().capabilities)

    def get_credentials(self) -> dict[str, str]:
        """Resolve credentials adhering strictly to precedence order:
        1. Runtime overrides
        2. OS Keyring / Secure storage
        3. Settings file fallback
        4. Environment variables
        """
        return self.settings_manager.get_integration_credentials(self.id, self.metadata().credential_fields)

    def get_config(self) -> dict[str, Any]:
        """Get non-secret configuration dictionary for this integration."""
        return self.settings_manager.get_integration_config(self.id)

    def configure(self, credentials: dict[str, str] | None = None, config: dict[str, Any] | None = None) -> None:
        """Persist updated credentials and configuration fields."""
        if credentials:
            self.settings_manager.set_integration_credentials(self.id, credentials)
        if config:
            current_cfg = self.get_config()
            current_cfg.update(config)
            self.settings_manager.set_integration_config(self.id, current_cfg)

    def remove(self) -> None:
        """Purge stored credentials and reset configuration for this integration."""
        self.settings_manager.remove_integration(self.id, self.metadata().credential_fields)


class AIIntegration(ExternalIntegration):
    """Specialized integration base for AI and Large Language Model providers."""

    @abstractmethod
    def available_models(self) -> list[str]:
        """List of model identifiers supported by this provider."""
        raise NotImplementedError

    @abstractmethod
    def default_model(self) -> str:
        """Default model identifier for this provider."""
        raise NotImplementedError

    def current_model(self) -> str:
        """Get currently configured model for this provider."""
        cfg = self.get_config()
        return cfg.get("model") or self.default_model()

    def set_model(self, model: str) -> None:
        """Update selected model for this provider."""
        self.configure(config={"model": model})


class VulnerabilityIntegration(ExternalIntegration):
    """Specialized integration base for external vulnerability engines."""

    @abstractmethod
    def get_engine_instance(self) -> Any:
        """Return the underlying ExternalVulnerabilityEngine instance."""
        raise NotImplementedError

    @property
    def endpoint(self) -> str:
        cfg = self.get_config()
        return cfg.get("endpoint", "")


class AutomationIntegration(ExternalIntegration):
    """Specialized integration base for browser and UI automation engines."""

    @abstractmethod
    def is_browser_available(self) -> bool:
        """Check if browser binaries (e.g. Playwright Chromium) are installed and usable."""
        raise NotImplementedError


class ToolIntegration(ExternalIntegration):
    """Specialized integration base for standalone security tools and CLI binaries."""

    @abstractmethod
    def binary_path(self) -> str | None:
        """Find executable path for the underlying binary."""
        raise NotImplementedError
