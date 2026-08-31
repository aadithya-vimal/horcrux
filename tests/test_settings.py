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


def test_regional_model_selection():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        mgr = SettingsManager(config_dir=tmp_path)

        # Region-specific model selection (e.g. EU / APAC / US regional endpoints)
        mgr.set_model("google", "gemini-1.5-flash")
        assert mgr.settings.providers["google"].model == "gemini-1.5-flash"

        mgr.set_model("groq", "llama-3.1-70b-versatile")
        assert mgr.settings.providers["groq"].model == "llama-3.1-70b-versatile"

        mgr.set_model("anthropic", "claude-3-7-sonnet-latest")
        assert mgr.settings.providers["anthropic"].model == "claude-3-7-sonnet-latest"

        # Custom regional / private deployment model ID
        mgr.set_model("openai", "us-east-1.gpt-4o-custom-deployment")
        assert mgr.settings.providers["openai"].model == "us-east-1.gpt-4o-custom-deployment"

        # Verify reload
        mgr_reloaded = SettingsManager(config_dir=tmp_path)
        assert mgr_reloaded.settings.providers["google"].model == "gemini-1.5-flash"
        assert mgr_reloaded.settings.providers["openai"].model == "us-east-1.gpt-4o-custom-deployment"


def test_ai_manager_available_models():
    with tempfile.TemporaryDirectory() as tmpdir:
        from horcrux.intel.ai.manager import AIManager
        mgr = SettingsManager(config_dir=Path(tmpdir))
        ai = AIManager(mgr)

        groq_models = ai.get_available_models("groq")
        assert "llama-3.3-70b-versatile" in groq_models
        assert "llama-3.1-8b-instant" in groq_models

        google_models = ai.get_available_models("google")
        assert "gemini-1.5-flash" in google_models
        assert "gemini-2.5-flash" in google_models

