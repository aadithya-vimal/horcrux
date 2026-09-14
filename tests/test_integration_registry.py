"""Tests for the authoritative IntegrationRegistry and adapters."""

from __future__ import annotations

import pytest

from horcrux.core.integrations.base import (
    AIIntegration,
    AutomationIntegration,
    ExternalIntegration,
    ToolIntegration,
    VulnerabilityIntegration,
)
from horcrux.core.integrations.models import (
    IntegrationCategory,
    IntegrationHealth,
    IntegrationMetadata,
)
from horcrux.core.integrations.registry import (
    IntegrationRegistry,
    get_integration_registry,
    reset_integration_registry,
)


class DummyCustomIntegration(ExternalIntegration):
    """Custom dummy integration for registry extensibility tests."""

    def metadata(self) -> IntegrationMetadata:
        return IntegrationMetadata(
            id="custom_scanner",
            name="Custom Cloud Scanner",
            category=IntegrationCategory.INTELLIGENCE,
            provider_type="cloud_saas",
            capabilities=["threat_intel", "ip_reputation"],
            aliases=["custom", "scanner_v1"],
        )

    def is_configured(self) -> bool:
        return True

    def validate_configuration(self) -> tuple[bool, str]:
        return True, "OK"


@pytest.fixture(autouse=True)
def clean_registry():
    reset_integration_registry()
    yield
    reset_integration_registry()


def test_registry_builtins_initialization():
    registry = IntegrationRegistry()
    items = registry.list()
    assert len(items) >= 14

    # Verify AI providers
    ai_items = registry.by_category(IntegrationCategory.AI)
    ai_ids = {item.id for item in ai_items}
    assert {"groq", "openai", "anthropic", "google"}.issubset(ai_ids)
    for ai_item in ai_items:
        assert isinstance(ai_item, AIIntegration)
        assert ai_item.category == IntegrationCategory.AI

    # Verify Vulnerability engines
    vuln_items = registry.by_category(IntegrationCategory.VULNERABILITY)
    vuln_ids = {item.id for item in vuln_items}
    assert {"tenable", "qualys", "rapid7", "greenbone", "msdefender"}.issubset(vuln_ids)
    for v_item in vuln_items:
        assert isinstance(v_item, VulnerabilityIntegration)
        assert v_item.category == IntegrationCategory.VULNERABILITY

    # Verify Automation
    auto_items = registry.by_category(IntegrationCategory.AUTOMATION)
    assert any(item.id == "playwright" for item in auto_items)
    for a_item in auto_items:
        assert isinstance(a_item, AutomationIntegration)

    # Verify Tools
    tool_items = registry.by_category(IntegrationCategory.SECURITY_TOOLS)
    tool_ids = {item.id for item in tool_items}
    assert {"nmap", "nuclei", "ffuf", "whatweb"}.issubset(tool_ids)
    for t_item in tool_items:
        assert isinstance(t_item, ToolIntegration)


def test_registry_alias_resolution():
    registry = IntegrationRegistry()

    # AI aliases
    assert registry.get("gemini") is not None
    assert registry.get("gemini").id == "google"
    assert registry.get("claude").id == "anthropic"
    assert registry.get("google-ai").id == "google"

    # Vuln aliases
    assert registry.get("nessus").id == "tenable"
    assert registry.get("tenable_vm").id == "tenable"
    assert registry.get("tenable-one").id == "tenable"
    assert registry.get("insightvm").id == "rapid7"
    assert registry.get("nexpose").id == "rapid7"
    assert registry.get("openvas").id == "greenbone"
    assert registry.get("gvm").id == "greenbone"
    assert registry.get("defender").id == "msdefender"

    # Automation aliases
    assert registry.get("browser").id == "playwright"
    assert registry.get("automation").id == "playwright"

    # Non-existent
    assert registry.get("non_existent_engine") is None


def test_registry_custom_extension():
    registry = IntegrationRegistry()
    custom = DummyCustomIntegration()
    registry.register(custom)

    assert registry.get("custom_scanner") is custom
    assert registry.get("custom") is custom
    assert registry.get("scanner_v1") is custom
    assert custom in registry.by_category(IntegrationCategory.INTELLIGENCE)

    # Unregister
    removed = registry.unregister("custom")
    assert removed is True
    assert registry.get("custom_scanner") is None
    assert registry.get("custom") is None


def test_registry_category_enumeration():
    registry = IntegrationRegistry()
    cats = registry.categories()
    cat_values = {c.value for c in cats}
    assert "ai" in cat_values
    assert "vulnerability" in cat_values
    assert "automation" in cat_values
    assert "security_tools" in cat_values


def test_registry_capabilities_enumeration():
    registry = IntegrationRegistry()
    caps = registry.all_capabilities()
    assert "groq" in caps
    assert "tenable" in caps
    assert "playwright" in caps
    assert "nmap" in caps


def test_registry_singleton_management():
    reg1 = get_integration_registry()
    reg2 = get_integration_registry()
    assert reg1 is reg2

    reset_integration_registry()
    reg3 = get_integration_registry()
    assert reg3 is not reg1
