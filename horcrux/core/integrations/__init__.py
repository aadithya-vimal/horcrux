"""Unified Settings and External Integration Control Plane for HORCRUX."""

from __future__ import annotations

from horcrux.core.integrations.base import (
    AIIntegration,
    AutomationIntegration,
    ExternalIntegration,
    ToolIntegration,
    VulnerabilityIntegration,
)
from horcrux.core.integrations.controller import SettingsController
from horcrux.core.integrations.models import (
    ConfigField,
    CredentialField,
    IntegrationCategory,
    IntegrationErrorType,
    IntegrationHealth,
    IntegrationHealthResult,
    IntegrationMetadata,
    IntegrationStatus,
    IntegrationTestResult,
)
from horcrux.core.integrations.registry import (
    IntegrationRegistry,
    get_integration_registry,
    reset_integration_registry,
)

__all__ = [
    "ExternalIntegration",
    "AIIntegration",
    "VulnerabilityIntegration",
    "AutomationIntegration",
    "ToolIntegration",
    "IntegrationCategory",
    "IntegrationStatus",
    "IntegrationHealth",
    "IntegrationErrorType",
    "IntegrationMetadata",
    "CredentialField",
    "ConfigField",
    "IntegrationHealthResult",
    "IntegrationTestResult",
    "IntegrationRegistry",
    "get_integration_registry",
    "reset_integration_registry",
    "SettingsController",
]
