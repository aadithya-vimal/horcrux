from __future__ import annotations

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

from horcrux.core.settings import SettingsManager, normalize_provider_name


def test_normalize_provider_name():
    assert normalize_provider_name("claude") == "anthropic"
    assert normalize_provider_name("CLAUDE") == "anthropic"
    assert normalize_provider_name("gemini") == "google"
    assert normalize_provider_name("GEMINI") == "google"
    assert normalize_provider_name("google-ai") == "google"
    assert normalize_provider_name("groq") == "groq"
    assert normalize_provider_name("openai") == "openai"


def test_credential_precedence_policy():
    with tempfile.TemporaryDirectory() as tmpdir:
        mgr = SettingsManager(config_dir=Path(tmpdir))

        # 1. No key configured
        info_none = mgr.get_credential_info("google")
        assert info_none.is_configured is False
        assert info_none.source == "none"
        assert info_none.fingerprint == "NONE"

        # 2. Environment fallback when no persisted key exists
        with patch.dict(os.environ, {"GOOGLE_API_KEY": "AIzaSyEnvGoogleKey1234567890"}):
            info_env = mgr.get_credential_info("google")
            assert info_env.is_configured is True
            assert info_env.source == "environment"
            assert info_env.env_var == "GOOGLE_API_KEY"
            assert info_env.key == "AIzaSyEnvGoogleKey1234567890"
            assert info_env.fingerprint.startswith("SHA256: ")

            # Also check GEMINI_API_KEY alias
            with patch.dict(os.environ, {"GOOGLE_API_KEY": "", "GEMINI_API_KEY": "AIzaSyGeminiKey9876543210"}):
                info_gemini = mgr.get_credential_info("google")
                assert info_gemini.is_configured is True
                assert info_gemini.source == "environment"
                assert info_gemini.env_var == "GEMINI_API_KEY"
                assert info_gemini.key == "AIzaSyGeminiKey9876543210"

            # 3. Persisted key MUST override environment variable
            mgr.set_api_key("google", "AIzaSyPersistedGoogleKeyAAAAA")
            info_persisted = mgr.get_credential_info("google")
            assert info_persisted.is_configured is True
            assert info_persisted.source == "persisted"
            assert info_persisted.key == "AIzaSyPersistedGoogleKeyAAAAA"
            assert "AAAA" in info_persisted.masked

            # 4. Runtime override MUST take precedence over persisted key
            mgr.set_runtime_credential("google", "AIzaSyRuntimeGoogleKeyZZZZZ")
            info_runtime = mgr.get_credential_info("google")
            assert info_runtime.is_configured is True
            assert info_runtime.source == "runtime"
            assert info_runtime.key == "AIzaSyRuntimeGoogleKeyZZZZZ"

            # Clear runtime override -> restores persisted key
            mgr.set_runtime_credential("google", "")
            assert mgr.get_credential_info("google").source == "persisted"
            assert mgr.get_credential_info("google").key == "AIzaSyPersistedGoogleKeyAAAAA"
