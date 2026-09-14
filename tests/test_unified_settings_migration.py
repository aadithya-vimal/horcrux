"""Tests for unified settings schema v2, migration from v1, and credential precedence."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from horcrux.core.sanitizer import mask_key
from horcrux.core.settings import HorcruxSettings, SettingsManager


def test_migrate_v1_to_v2_in_memory():
    v1_raw = {
        "enabled": True,
        "default_provider": "openai",
        "call_budget": 75,
        "fallback_sequence": ["anthropic", "groq"],
        "providers": {
            "openai": {"model": "gpt-4o", "custom_endpoint": "https://api.openai.com/v1", "timeout": 45},
            "groq": {"model": "llama-3.3-70b-versatile"},
        },
        "_keys_fallback": {
            "openai": "sk-legacy-test-key-12345678",
            "groq": "gsk_legacy_groq_key_abcdef99",
        },
        "vulnerability_engines": {
            "tenable": {
                "provider_id": "tenable",
                "enabled": True,
                "endpoint": "https://custom.tenable.example.com",
            },
            "rapid7": {
                "provider_id": "rapid7",
                "enabled": False,
                "endpoint": "https://rapid7.corp:3780",
            },
        },
        "_vuln_keys_fallback": {
            "tenable": {"access_key": "AK_LEGACY_123", "secret_key": "SK_LEGACY_456"},
            "rapid7": {"username": "r7user", "password": "r7password"},
        },
    }

    migrated = SettingsManager._migrate_v1_to_v2(v1_raw)
    assert migrated["schema_version"] == 2
    assert "integrations" in migrated
    assert "_integration_credentials_fallback" in migrated

    # Check migrated integrations
    integrations = migrated["integrations"]
    assert integrations["openai"]["model"] == "gpt-4o"
    assert integrations["openai"]["custom_endpoint"] == "https://api.openai.com/v1"
    assert integrations["tenable"]["endpoint"] == "https://custom.tenable.example.com"
    assert integrations["rapid7"]["enabled"] is False

    # Check migrated credentials
    creds = migrated["_integration_credentials_fallback"]
    assert creds["openai"]["api_key"] == "sk-legacy-test-key-12345678"
    assert creds["tenable"]["access_key"] == "AK_LEGACY_123"
    assert creds["rapid7"]["username"] == "r7user"


def test_v1_disk_migration_roundtrip(tmp_path: Path):
    v1_json = {
        "enabled": True,
        "default_provider": "google",
        "providers": {
            "google": {"model": "gemini-2.5-flash"},
        },
        "_keys_fallback": {
            "google": "AIzaSyLegacyKey9876543210",
        },
        "vulnerability_engines": {
            "qualys": {
                "enabled": True,
                "endpoint": "https://qualysapi.qg2.apps.qualys.com",
            },
        },
        "_vuln_keys_fallback": {
            "qualys": {"username": "qualys_admin", "password": "secure_pw_123"},
        },
    }

    settings_file = tmp_path / "settings.json"
    settings_file.write_text(json.dumps(v1_json, indent=2), encoding="utf-8")

    # Load with SettingsManager
    mgr = SettingsManager(config_dir=tmp_path, use_keyring=False)
    assert mgr.settings.schema_version == 2
    assert mgr.settings.default_provider == "google"

    # Verify transparent legacy accessors work
    assert mgr.get_api_key("google") == "AIzaSyLegacyKey9876543210"
    qualys_creds = mgr.get_vuln_credentials("qualys")
    assert qualys_creds["username"] == "qualys_admin"
    assert qualys_creds["password"] == "secure_pw_123"

    # Verify unified accessors work
    google_creds = mgr.get_integration_credentials("google")
    assert google_creds["api_key"] == "AIzaSyLegacyKey9876543210"
    assert mgr.get_integration_config("qualys")["endpoint"] == "https://qualysapi.qg2.apps.qualys.com"

    # Verify file saved as v2
    mgr.save()
    raw_saved = json.loads(settings_file.read_text(encoding="utf-8"))
    assert raw_saved["schema_version"] == 2
    assert "integrations" in raw_saved
    assert "_integration_credentials_fallback" in raw_saved


def test_credential_precedence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    mgr = SettingsManager(config_dir=tmp_path, use_keyring=False)

    # 4. No credential
    info = mgr.get_credential_info("groq")
    assert info.source == "none"
    assert not info.is_configured

    # 3. Environment variable
    monkeypatch.setenv("GROQ_API_KEY", "gsk_env_variable_key_111")
    info = mgr.get_credential_info("groq")
    assert info.source == "environment"
    assert info.key == "gsk_env_variable_key_111"

    # 2. Persisted file credential overrides environment
    mgr.settings._integration_credentials_fallback["groq"] = {"api_key": "gsk_persisted_file_key_222"}
    mgr.settings._keys_file_fallback["groq"] = "gsk_persisted_file_key_222"
    info = mgr.get_credential_info("groq")
    assert info.source == "persisted"
    assert info.key == "gsk_persisted_file_key_222"

    # 1. Runtime override overrides persisted and environment
    mgr.set_integration_runtime_credential("groq", "api_key", "gsk_runtime_override_key_333")
    info = mgr.get_credential_info("groq")
    assert info.source == "runtime"
    assert info.key == "gsk_runtime_override_key_333"

    # Clearing runtime restores persisted
    mgr.set_integration_runtime_credential("groq", "api_key", "")
    info = mgr.get_credential_info("groq")
    assert info.source == "persisted"
    assert info.key == "gsk_persisted_file_key_222"


def test_zero_leakage_masking(tmp_path: Path):
    mgr = SettingsManager(config_dir=tmp_path, use_keyring=False)
    raw_secret = "sk-super-confidential-token-99887766"
    mgr.set_integration_credentials("openai", {"api_key": raw_secret})

    # Credential info has masked representation
    info = mgr.get_credential_info("openai")
    assert info.masked != raw_secret
    assert "7766" in info.masked
    assert "confidential" not in info.masked
    assert raw_secret[:10] not in info.masked

    # Vulnerability credentials masking
    mgr.set_integration_credentials("tenable", {"access_key": "AK12345678", "secret_key": "SK87654321"})
    masked = mgr.masked_vuln_credentials("tenable")
    assert "AK12345678" not in masked.values()
    assert "SK87654321" not in masked.values()
