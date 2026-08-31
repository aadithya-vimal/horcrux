import tempfile
from pathlib import Path
from horcrux.core.settings import SettingsManager, mask_key, DEFAULT_MODELS


def test_mask_key():
    assert mask_key("") == "NOT CONFIGURED"
    assert mask_key("short") == "••••••••"
    assert mask_key("gsk_1234567890abcdef9F31") == "gsk_••••••••9F31"
    assert mask_key("sk-1234567890abcdefA82D") == "sk-••••••••A82D"
    assert mask_key("sk-ant-1234567890abcdef71C9") == "sk-ant-••••••••71C9"
    assert mask_key("AIzaSyB1234567890abcdef2E91") == "AIza••••••••2E91"
    assert mask_key("my_custom_secret_key_1234") == "my_••••••••1234"


def test_settings_persistence():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        mgr = SettingsManager(config_dir=tmp_path)
        assert mgr.settings.enabled is True
        assert mgr.settings.default_provider == "groq"
        assert "groq" in mgr.settings.providers
        assert mgr.settings.providers["groq"].model == DEFAULT_MODELS["groq"]

        # Update model
        mgr.set_model("groq", "llama-3.1-8b-instant")
        assert mgr.settings.providers["groq"].model == "llama-3.1-8b-instant"

        # Update default provider
        mgr.set_default_provider("openai")
        assert mgr.settings.default_provider == "openai"

        # Disable AI
        mgr.set_enabled(False)
        assert mgr.settings.enabled is False

        # Reload from disk
        mgr2 = SettingsManager(config_dir=tmp_path)
        assert mgr2.settings.enabled is False
        assert mgr2.settings.default_provider == "openai"
        assert mgr2.settings.providers["groq"].model == "llama-3.1-8b-instant"
