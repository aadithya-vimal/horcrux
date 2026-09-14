"""Canonical models, enums, and dataclasses for external integrations."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class IntegrationCategory(str, Enum):
    """Broad functional grouping of integrations."""
    AI = "ai"
    VULNERABILITY = "vulnerability"
    SECURITY_TOOLS = "security_tools"
    AUTOMATION = "automation"
    INTELLIGENCE = "intelligence"
    GENERAL = "general"


class IntegrationStatus(str, Enum):
    """Static configuration status of an integration."""
    CONFIGURED = "configured"
    NOT_CONFIGURED = "not_configured"
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    DISABLED = "disabled"
    BROKEN = "broken"


class IntegrationHealth(str, Enum):
    """Dynamic operational health status."""
    HEALTHY = "healthy"
    CONFIGURED = "configured"
    CONNECTIVITY_VERIFIED = "connectivity_verified"
    AUTHENTICATED = "authenticated"
    OPERATIONAL = "operational"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNAVAILABLE = "unavailable"
    NOT_CONFIGURED = "not_configured"
    UNKNOWN = "unknown"


class IntegrationErrorType(str, Enum):
    """Detailed error classification for failure attribution."""
    NOT_CONFIGURED = "not_configured"
    INVALID_CONFIGURATION = "invalid_configuration"
    AUTHENTICATION_FAILED = "authentication_failed"
    AUTHORIZATION_FAILED = "authorization_failed"
    RATE_LIMITED = "rate_limited"
    QUOTA_EXCEEDED = "quota_exceeded"
    NETWORK_UNAVAILABLE = "network_unavailable"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    API_ERROR = "api_error"
    UNSUPPORTED_TARGET = "unsupported_target"
    UNSUPPORTED_OPERATION = "unsupported_operation"
    INVALID_RESPONSE = "invalid_response"
    TIMEOUT = "timeout"
    INTERNAL_ERROR = "internal_error"


class CredentialField(BaseModel):
    """Definition of a single credential required by an integration."""
    name: str
    label: str = ""
    secret: bool = True
    required: bool = True
    env_vars: list[str] = Field(default_factory=list)
    default: str = ""
    description: str = ""


class ConfigField(BaseModel):
    """Definition of a non-secret configuration property."""
    name: str
    label: str = ""
    type: str = "string"
    default: Any = None
    choices: list[Any] = Field(default_factory=list)
    description: str = ""
    required: bool = False


class IntegrationHealthResult(BaseModel):
    """Result of a passive or lightweight health inspection."""
    health: IntegrationHealth = IntegrationHealth.UNKNOWN
    message: str = ""
    error_type: IntegrationErrorType | None = None
    latency_ms: float = 0.0
    timestamp: str = ""
    details: dict[str, Any] = Field(default_factory=dict)


class IntegrationTestResult(BaseModel):
    """Result of an active probe or live end-to-end connection test."""
    ok: bool = False
    status: IntegrationHealth = IntegrationHealth.UNKNOWN
    message: str = ""
    raw_output: str = ""
    latency_ms: float = 0.0
    error_type: IntegrationErrorType | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class IntegrationMetadata(BaseModel):
    """Full declarative metadata specification for an external integration."""
    id: str
    name: str
    category: IntegrationCategory
    provider_type: str = ""
    description: str = ""
    version: str = ""
    documentation_url: str = ""
    capabilities: list[str] = Field(default_factory=list)
    credential_fields: list[CredentialField] = Field(default_factory=list)
    config_fields: list[ConfigField] = Field(default_factory=list)
    requires_network: bool = True
    requires_binary: bool = False
    binary_names: list[str] = Field(default_factory=list)
    aliases: list[str] = Field(default_factory=list)
