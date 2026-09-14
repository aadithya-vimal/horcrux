"""Tests for integration health checking, connection probes, and error attribution."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from horcrux.core.integrations.models import (
    IntegrationErrorType,
    IntegrationHealth,
    IntegrationHealthResult,
    IntegrationTestResult,
)
from horcrux.core.integrations.registry import get_integration_registry, reset_integration_registry
from horcrux.core.settings import SettingsManager


@pytest.fixture(autouse=True)
def clean_env():
    reset_integration_registry()
    yield
    reset_integration_registry()


def test_ai_integration_health_and_test(tmp_path: Path):
    mgr = SettingsManager(config_dir=tmp_path, use_keyring=False)
    registry = get_integration_registry(mgr)

    groq = registry.get("groq")
    assert groq is not None

    # Unconfigured health check
    health = groq.health_check()
    assert health.health == IntegrationHealth.NOT_CONFIGURED
    assert health.error_type == IntegrationErrorType.NOT_CONFIGURED

    # Connection test when unconfigured
    test_res = groq.test_connection()
    assert test_res.ok is False
    assert test_res.status == IntegrationHealth.NOT_CONFIGURED

    # Configure groq
    mgr.set_api_key("groq", "gsk_valid_key_1234567890")
    health = groq.health_check()
    assert health.health == IntegrationHealth.HEALTHY

    # Mock live connection test
    mock_resp = MagicMock()
    mock_resp.content = "HORCRUX_AI_OK"
    mock_resp.model = "llama-3.3-70b-versatile"
    mock_resp.tokens_used = 12

    with patch("horcrux.intel.ai.manager.AIManager.get_provider") as mock_get_p:
        mock_provider = MagicMock()
        mock_provider.complete.return_value = mock_resp
        with patch.object(groq, "test_connection") as mock_test:
            mock_test.return_value = IntegrationTestResult(
                ok=True,
                status=IntegrationHealth.OPERATIONAL,
                message="Connection verified to Groq LLaMA Cloud (45ms).",
                latency_ms=45.0,
            )
            res = groq.test_connection()
            assert res.ok is True
            assert res.status == IntegrationHealth.OPERATIONAL
            assert res.latency_ms > 0


def test_vuln_integration_health_and_test(tmp_path: Path):
    mgr = SettingsManager(config_dir=tmp_path, use_keyring=False)
    registry = get_integration_registry(mgr)

    tenable = registry.get("tenable")
    assert tenable is not None

    # Unconfigured
    health = tenable.health_check()
    assert health.health == IntegrationHealth.NOT_CONFIGURED

    # Configure credentials
    mgr.set_vuln_credentials("tenable", {"access_key": "AK123", "secret_key": "SK123"})
    health = tenable.health_check()
    assert health.health == IntegrationHealth.CONFIGURED

    # Connection test with mocked engine
    mock_engine_res = MagicMock()
    mock_engine_res.ok = True
    mock_engine_res.message = "Connected to Tenable One API"
    mock_engine_res.details = {"status": "operational"}

    with patch.object(tenable, "get_engine_instance") as mock_get_eng:
        mock_eng = MagicMock()
        mock_eng.test_connection.return_value = mock_engine_res
        mock_get_eng.return_value = mock_eng

        test_res = tenable.test_connection()
        assert test_res.ok is True
        assert test_res.status == IntegrationHealth.OPERATIONAL
        assert "Tenable" in test_res.message


def test_tool_integration_health_and_test(tmp_path: Path):
    mgr = SettingsManager(config_dir=tmp_path, use_keyring=False)
    registry = get_integration_registry(mgr)

    nmap = registry.get("nmap")
    assert nmap is not None

    # When binary is missing
    with patch("shutil.which", return_value=None):
        health = nmap.health_check()
        assert health.health == IntegrationHealth.UNAVAILABLE
        test_res = nmap.test_connection()
        assert test_res.ok is False
        assert test_res.status == IntegrationHealth.UNAVAILABLE

    # When binary is found
    with patch("shutil.which", return_value="/usr/bin/nmap"):
        health = nmap.health_check()
        assert health.health == IntegrationHealth.HEALTHY

        mock_proc = MagicMock()
        mock_proc.stdout = "Nmap version 7.94"
        mock_proc.stderr = ""
        with patch("subprocess.run", return_value=mock_proc):
            test_res = nmap.test_connection()
            assert test_res.ok is True
            assert test_res.status == IntegrationHealth.OPERATIONAL
            assert "Nmap version 7.94" in test_res.raw_output
