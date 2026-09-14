"""Tests for SettingsController command routing and UI rendering."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from rich.console import Console

from horcrux.core.integrations.controller import SettingsController
from horcrux.core.integrations.registry import get_integration_registry, reset_integration_registry
from horcrux.core.settings import SettingsManager


@pytest.fixture(autouse=True)
def clean_env():
    reset_integration_registry()
    yield
    reset_integration_registry()


def test_settings_controller_overview_and_status(tmp_path: Path):
    console = Console(record=True, width=120)
    mgr = SettingsManager(config_dir=tmp_path, use_keyring=False)
    ctrl = SettingsController(console=console, settings_manager=mgr)

    # Empty args -> overview
    code = ctrl.handle_command([])
    assert code == 0
    text = console.export_text()
    assert "CONTROL PLANE" in text
    assert "Global Engine Configuration" in text
    assert "groq" in text.lower()

    # status command
    console = Console(record=True, width=120)
    ctrl.console = console
    code = ctrl.handle_command(["status"])
    assert code == 0
    status_text = console.export_text()
    assert "INTEGRATION HEALTH & DIAGNOSTICS" in status_text
    assert "tenable" in status_text.lower()
    assert "playwright" in status_text.lower()


def test_settings_controller_category_drilldown(tmp_path: Path):
    console = Console(record=True, width=120)
    mgr = SettingsManager(config_dir=tmp_path, use_keyring=False)
    ctrl = SettingsController(console=console, settings_manager=mgr)

    for cat in ("ai", "vulnerability", "automation", "tools"):
        console = Console(record=True, width=120)
        ctrl.console = console
        code = ctrl.handle_command([cat])
        assert code == 0
        text = console.export_text()
        assert cat.upper() in text


def test_settings_controller_global_toggles(tmp_path: Path):
    console = Console(record=True)
    mgr = SettingsManager(config_dir=tmp_path, use_keyring=False)
    ctrl = SettingsController(console=console, settings_manager=mgr)

    # Disable
    assert ctrl.handle_command(["disable"]) == 0
    assert mgr.settings.enabled is False

    # Enable
    assert ctrl.handle_command(["enable"]) == 0
    assert mgr.settings.enabled is True

    # Budget
    assert ctrl.handle_command(["budget", "120"]) == 0
    assert mgr.settings.call_budget == 120

    # Fallback
    assert ctrl.handle_command(["fallback", "anthropic", "openai"]) == 0
    assert mgr.settings.fallback_sequence == ["anthropic", "openai"]

    # Provider & Model
    assert ctrl.handle_command(["provider", "openai"]) == 0
    assert mgr.settings.default_provider == "openai"

    assert ctrl.handle_command(["model", "gpt-4o-mini"]) == 0
    assert mgr.get_model("openai") == "gpt-4o-mini"

    # Key
    assert ctrl.handle_command(["key", "groq", "gsk_test_api_key_456"]) == 0
    assert mgr.get_api_key("groq") == "gsk_test_api_key_456"


def test_settings_controller_provider_actions(tmp_path: Path):
    console = Console(record=True, width=120)
    mgr = SettingsManager(config_dir=tmp_path, use_keyring=False)
    ctrl = SettingsController(console=console, settings_manager=mgr)

    # Provider detail view
    code = ctrl.handle_command(["vulnerability", "tenable"])
    assert code == 0
    text = console.export_text()
    assert "Tenable" in text

    # Configure via flags
    code = ctrl.handle_command(["vulnerability", "tenable", "configure", "--endpoint", "https://cloud.tenable.test"])
    assert code == 0
    cfg = mgr.get_vuln_engine_config("tenable")
    assert cfg["endpoint"] == "https://cloud.tenable.test"

    # Disable provider
    code = ctrl.handle_command(["vulnerability", "tenable", "disable"])
    assert code == 0
    item = ctrl.registry.get("tenable")
    assert item.is_enabled() is False

    # Enable provider
    code = ctrl.handle_command(["vulnerability", "tenable", "enable"])
    assert code == 0
    assert item.is_enabled() is True

    # Remove provider
    code = ctrl.handle_command(["vulnerability", "tenable", "remove"])
    assert code == 0


def test_settings_controller_invalid_commands(tmp_path: Path):
    console = Console(record=True)
    mgr = SettingsManager(config_dir=tmp_path, use_keyring=False)
    ctrl = SettingsController(console=console, settings_manager=mgr)

    # Unknown category / command
    code = ctrl.handle_command(["unknown_command_xyz"])
    assert code == 1

    # Unknown action on provider
    code = ctrl.handle_command(["vulnerability", "tenable", "invalid_action_123"])
    assert code == 1
