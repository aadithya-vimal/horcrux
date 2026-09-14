"""Authoritative registry for all external integrations in HORCRUX."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from horcrux.core.integrations.adapters import (
    AIProviderAdapter,
    CoreToolAdapter,
    PlaywrightAutomationAdapter,
    VulnEngineAdapter,
)
from horcrux.core.integrations.base import ExternalIntegration
from horcrux.core.integrations.models import IntegrationCategory
from horcrux.core.settings import VULN_ENGINE_IDS, normalize_provider_name, normalize_vuln_engine_id

if TYPE_CHECKING:
    from horcrux.core.settings import SettingsManager

logger = logging.getLogger("horcrux.integrations")

_REGISTRY_INSTANCE: IntegrationRegistry | None = None


class IntegrationRegistry:
    """Central registry and discovery authority for external integrations.

    Maintains the catalog of AI providers, vulnerability engines, security tools,
    and automation runtimes, indexing by canonical ID, category, and aliases.
    """

    def __init__(self, settings_manager: SettingsManager | None = None) -> None:
        self._settings_manager = settings_manager
        self._integrations: dict[str, ExternalIntegration] = {}
        self._alias_map: dict[str, str] = {}
        self._initialize_builtins()

    def _initialize_builtins(self) -> None:
        """Register the default out-of-the-box HORCRUX external integrations."""
        # 1. AI Providers
        for ai_name in ("groq", "openai", "anthropic", "google"):
            self.register(AIProviderAdapter(ai_name, self._settings_manager))

        # 2. Vulnerability Engines
        for engine_id in VULN_ENGINE_IDS:
            self.register(VulnEngineAdapter(engine_id, self._settings_manager))

        # 3. Automation Providers
        self.register(PlaywrightAutomationAdapter(self._settings_manager))

        # 4. Core Security Tools
        for tool_id in ("nmap", "nuclei", "ffuf", "whatweb"):
            self.register(CoreToolAdapter(tool_id, self._settings_manager))

    def register(self, integration: ExternalIntegration) -> None:
        """Register a new or updated external integration."""
        meta = integration.metadata()
        canonical_id = meta.id.lower()
        self._integrations[canonical_id] = integration

        # Map ID itself
        self._alias_map[canonical_id] = canonical_id

        # Map declared aliases
        for alias in meta.aliases:
            self._alias_map[alias.lower()] = canonical_id

        # Map common normalization aliases
        norm_ai = normalize_provider_name(canonical_id)
        if norm_ai:
            self._alias_map[norm_ai] = canonical_id

        norm_vuln = normalize_vuln_engine_id(canonical_id)
        if norm_vuln:
            self._alias_map[norm_vuln] = canonical_id

    def unregister(self, integration_id: str) -> bool:
        """Unregister an integration from the registry."""
        resolved = self._resolve_id(integration_id)
        if resolved and resolved in self._integrations:
            del self._integrations[resolved]
            # Clean alias map
            keys_to_remove = [k for k, v in self._alias_map.items() if v == resolved]
            for k in keys_to_remove:
                del self._alias_map[k]
            return True
        return False

    def _resolve_id(self, identifier: str) -> str | None:
        if not identifier:
            return None
        norm = identifier.strip().lower().replace("-", "_")
        if norm in self._alias_map:
            return self._alias_map[norm]
        alt = norm.replace("_", "-")
        if alt in self._alias_map:
            return self._alias_map[alt]

        norm_ai = normalize_provider_name(identifier)
        if norm_ai in self._integrations:
            return norm_ai

        norm_vuln = normalize_vuln_engine_id(identifier)
        if norm_vuln in self._integrations:
            return norm_vuln

        return None

    def get(self, identifier: str) -> ExternalIntegration | None:
        """Lookup an integration by canonical ID or alias."""
        resolved = self._resolve_id(identifier)
        if resolved:
            return self._integrations.get(resolved)
        return None

    def list(self, category: IntegrationCategory | str | None = None) -> list[ExternalIntegration]:
        """List integrations, optionally filtered by category."""
        all_items = list(self._integrations.values())
        if category is None:
            return all_items

        cat_val = category.value if isinstance(category, IntegrationCategory) else str(category).lower()
        return [item for item in all_items if item.category.value == cat_val]

    def by_category(self, category: IntegrationCategory | str) -> list[ExternalIntegration]:
        """Convenience alias for list(category)."""
        return self.list(category)

    def enabled(self, category: IntegrationCategory | str | None = None) -> list[ExternalIntegration]:
        """Return all integrations that are currently enabled in settings."""
        return [item for item in self.list(category) if item.is_enabled()]

    def configured(self, category: IntegrationCategory | str | None = None) -> list[ExternalIntegration]:
        """Return all integrations that have valid configuration and required credentials."""
        return [item for item in self.list(category) if item.is_configured()]

    def operational(self, category: IntegrationCategory | str | None = None) -> list[ExternalIntegration]:
        """Return all integrations that are enabled and configured."""
        return [item for item in self.list(category) if item.is_enabled() and item.is_configured()]

    def categories(self) -> list[IntegrationCategory]:
        """List distinct categories that contain at least one registered integration."""
        cats: set[IntegrationCategory] = {item.category for item in self._integrations.values()}
        return sorted(cats, key=lambda c: c.value)

    def all_capabilities(self) -> dict[str, list[str]]:
        """Return a mapping of integration ID to its active capabilities."""
        return {item.id: item.capabilities() for item in self._integrations.values()}


def get_integration_registry(settings_manager: SettingsManager | None = None) -> IntegrationRegistry:
    """Return the global IntegrationRegistry singleton."""
    global _REGISTRY_INSTANCE
    if _REGISTRY_INSTANCE is None:
        _REGISTRY_INSTANCE = IntegrationRegistry(settings_manager)
    elif settings_manager is not None:
        _REGISTRY_INSTANCE._settings_manager = settings_manager
    return _REGISTRY_INSTANCE


def reset_integration_registry() -> None:
    """Reset the global singleton (used in tests)."""
    global _REGISTRY_INSTANCE
    _REGISTRY_INSTANCE = None
