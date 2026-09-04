from __future__ import annotations

import tempfile
from pathlib import Path

from horcrux.core.settings import DEFAULT_MODELS, SettingsManager


def test_atomic_save_and_reload():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        mgr = SettingsManager(config_dir=tmp_path)

        mgr.set_api_key("google", "AIzaSyTestAtomicKey123")
        mgr.set_model("google", "gemini-3.6-flash")
        mgr.set_default_provider("google")

        # Verify on disk
        settings_file = tmp_path / "settings.json"
        assert settings_file.exists()
        # .tmp file should NOT be lingering
        assert not (tmp_path / "settings.json.tmp").exists()

        # Reload
        mgr2 = SettingsManager(config_dir=tmp_path)
        assert mgr2.settings.default_provider == "google"
        assert mgr2.get_api_key("google") == "AIzaSyTestAtomicKey123"
        assert mgr2.get_model("google") == "gemini-3.6-flash"


def test_safe_removal_and_default_reassignment():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        mgr = SettingsManager(config_dir=tmp_path)

        mgr.set_api_key("google", "AIzaSyKey1")
        mgr.set_api_key("groq", "gsk_Key2")
        mgr.set_default_provider("google")
        assert mgr.settings.default_provider == "google"

        # Remove default provider (google)
        mgr.remove_api_key("google")
        assert not mgr.get_credential_info("google").is_configured
        # Should automatically switch default provider to another configured provider (groq)
        assert mgr.settings.default_provider == "groq"


def test_reset_model():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        mgr = SettingsManager(config_dir=tmp_path)

        mgr.set_model("google", "my-custom-test-model")
        assert mgr.get_model("google") == "my-custom-test-model"

        def_m = mgr.reset_model("google")
        assert def_m == DEFAULT_MODELS["google"]
        assert mgr.get_model("google") == DEFAULT_MODELS["google"]
