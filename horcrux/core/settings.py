from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

try:
    import keyring
except ImportError:
    keyring = None


def get_config_dir() -> Path:
    """Return platform-appropriate configuration directory for Horcrux."""
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        base = Path(appdata) if appdata else Path.home() / "AppData" / "Roaming"
        config_dir = base / "Horcrux"
    elif sys.platform == "darwin":
        config_dir = Path.home() / "Library" / "Application Support" / "horcrux"
    else:
        xdg = os.environ.get("XDG_CONFIG_HOME")
        base = Path(xdg) if xdg else Path.home() / ".config"
        config_dir = base / "horcrux"

    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir


def mask_key(key: str) -> str:
    """Mask an API key for safe display in UI, logs, and settings screens."""
    if not key or not key.strip():
        return "NOT CONFIGURED"
    k = key.strip()
    if len(k) <= 8:
        return "••••••••"

    # Recognized provider prefix patterns
    if k.startswith("gsk_"):
        return f"gsk_••••••••{k[-4:]}"
    elif k.startswith("sk-ant-"):
        return f"sk-ant-••••••••{k[-4:]}"
    elif k.startswith("sk-"):
        return f"sk-••••••••{k[-4:]}"
    elif k.startswith("AIza"):
        return f"AIza••••••••{k[-4:]}"

    prefix = k[:3]
    suffix = k[-4:]
    return f"{prefix}••••••••{suffix}"


DEFAULT_MODELS: dict[str, str] = {
    "groq": "llama-3.3-70b-versatile",
    "openai": "gpt-4o",
    "anthropic": "claude-3-5-sonnet-latest",
    "google": "gemini-1.5-flash",
}

AVAILABLE_MODELS: dict[str, list[str]] = {
    "groq": [
        "llama-3.3-70b-versatile",
        "llama-3.1-8b-instant",
        "llama-3.1-70b-versatile",
        "mixtral-8x7b-32768",
        "gemma2-9b-it",
        "deepseek-r1-distill-llama-70b",
        "qwen-2.5-32b",
    ],
    "openai": [
        "gpt-4o",
        "gpt-4o-mini",
        "gpt-4-turbo",
        "o3-mini",
        "o1-mini",
        "chatgpt-4o-latest",
    ],
    "anthropic": [
        "claude-3-5-sonnet-latest",
        "claude-3-5-haiku-latest",
        "claude-3-7-sonnet-latest",
        "claude-3-opus-latest",
        "claude-3-haiku-20240307",
    ],
    "google": [
        "gemini-1.5-flash",
        "gemini-1.5-pro",
        "gemini-2.0-flash",
        "gemini-2.5-flash",
        "gemini-3.6-flash",
        "gemini-2.5-pro",
    ],
}

ENV_KEY_NAMES: dict[str, list[str]] = {
    "groq": ["GROQ_API_KEY"],
    "openai": ["OPENAI_API_KEY"],
    "anthropic": ["ANTHROPIC_API_KEY"],
    "google": ["GEMINI_API_KEY", "GOOGLE_API_KEY", "GOOGLE_AI_API_KEY"],
}

ENV_MODEL_NAMES: dict[str, list[str]] = {
    "groq": ["GROQ_MODEL"],
    "openai": ["OPENAI_MODEL"],
    "anthropic": ["ANTHROPIC_MODEL"],
    "google": ["GOOGLE_MODEL", "GEMINI_MODEL"],
}


@dataclass
class ProviderConfig:
    name: str
    model: str
    custom_endpoint: str = ""
    timeout: int = 60
    max_tokens: int = 2048
    temperature: float = 0.2
    last_validated: Optional[str] = None
    last_status: Optional[str] = None


@dataclass
class HorcruxSettings:
    enabled: bool = True
    default_provider: str = "groq"
    call_budget: int = 50
    fallback_sequence: list[str] = field(default_factory=lambda: ["google", "openai"])
    providers: dict[str, ProviderConfig] = field(default_factory=dict)
    _keys_file_fallback: dict[str, str] = field(default_factory=dict)

    @classmethod
    def default(cls) -> "HorcruxSettings":
        providers = {
            name: ProviderConfig(
                name=name,
                model=DEFAULT_MODELS.get(name, ""),
            )
            for name in ("groq", "openai", "anthropic", "google")
        }
        return cls(
            enabled=True,
            default_provider="groq",
            call_budget=50,
            fallback_sequence=["google", "openai"],
            providers=providers,
        )


class SettingsManager:
    SERVICE_NAME = "horcrux_ai_keys"

    def __init__(self, config_dir: Path | None = None):
        self.config_dir = config_dir or get_config_dir()
        self.settings_file = self.config_dir / "settings.json"
        self.cache_file = self.config_dir / "ai_cache.json"
        self.usage_file = self.config_dir / "ai_usage.json"
        self.settings = self.load()

    def load(self) -> HorcruxSettings:
        if not self.settings_file.exists():
            default_settings = HorcruxSettings.default()
            self.save(default_settings)
            return default_settings

        try:
            raw = json.loads(self.settings_file.read_text(encoding="utf-8"))
            providers = {}
            for name, p_data in raw.get("providers", {}).items():
                providers[name] = ProviderConfig(
                    name=name,
                    model=p_data.get("model", DEFAULT_MODELS.get(name, "")),
                    custom_endpoint=p_data.get("custom_endpoint", ""),
                    timeout=p_data.get("timeout", 60),
                    max_tokens=p_data.get("max_tokens", 2048),
                    temperature=p_data.get("temperature", 0.2),
                    last_validated=p_data.get("last_validated"),
                    last_status=p_data.get("last_status"),
                )
            for name in ("groq", "openai", "anthropic", "google"):
                if name not in providers:
                    providers[name] = ProviderConfig(name=name, model=DEFAULT_MODELS.get(name, ""))

            return HorcruxSettings(
                enabled=raw.get("enabled", True),
                default_provider=raw.get("default_provider", "groq"),
                call_budget=raw.get("call_budget", 50),
                fallback_sequence=raw.get("fallback_sequence", ["google", "openai"]),
                providers=providers,
                _keys_file_fallback=raw.get("_keys_fallback", {}),
            )
        except Exception:
            return HorcruxSettings.default()


    def save(self, settings: HorcruxSettings | None = None) -> None:
        if settings is not None:
            self.settings = settings

        data = {
            "enabled": self.settings.enabled,
            "default_provider": self.settings.default_provider,
            "call_budget": self.settings.call_budget,
            "fallback_sequence": self.settings.fallback_sequence,
            "providers": {
                name: asdict(p) for name, p in self.settings.providers.items()
            },
            "_keys_fallback": self.settings._keys_file_fallback,
        }
        self.settings_file.parent.mkdir(parents=True, exist_ok=True)
        self.settings_file.write_text(json.dumps(data, indent=2), encoding="utf-8")


        if sys.platform != "win32":
            try:
                os.chmod(self.settings_file, 0o600)
            except Exception:
                pass

    def get_api_key(self, provider: str) -> str:
        provider = provider.lower()
        env_names = ENV_KEY_NAMES.get(provider, [f"{provider.upper()}_API_KEY"])
        for env_var in env_names:
            val = os.environ.get(env_var)
            if val and val.strip():
                return val.strip()

        if keyring is not None:
            try:
                stored = keyring.get_password(self.SERVICE_NAME, provider)
                if stored and stored.strip():
                    return stored.strip()
            except Exception:
                pass

        return self.settings._keys_file_fallback.get(provider, "")

    def set_api_key(self, provider: str, key: str) -> None:
        provider = provider.lower()
        key = key.strip()

        stored_in_keyring = False
        if keyring is not None:
            try:
                keyring.set_password(self.SERVICE_NAME, provider, key)
                stored_in_keyring = True
            except Exception:
                stored_in_keyring = False

        if not stored_in_keyring:
            self.settings._keys_file_fallback[provider] = key
        else:
            self.settings._keys_file_fallback.pop(provider, None)

        self.save()

    def remove_api_key(self, provider: str) -> None:
        provider = provider.lower()
        if keyring is not None:
            try:
                keyring.delete_password(self.SERVICE_NAME, provider)
            except Exception:
                pass
        self.settings._keys_file_fallback.pop(provider, None)
        self.save()

    def get_key_source(self, provider: str) -> str:
        provider = provider.lower()
        env_names = ENV_KEY_NAMES.get(provider, [f"{provider.upper()}_API_KEY"])
        for env_var in env_names:
            val = os.environ.get(env_var)
            if val and val.strip():
                return f"ENV (${env_var})"
        if keyring is not None:
            try:
                stored = keyring.get_password(self.SERVICE_NAME, provider)
                if stored and stored.strip():
                    return "KEYCHAIN"
            except Exception:
                pass
        if provider in self.settings._keys_file_fallback:
            return "FILE (PROTECTED)"
        return "NONE"

    def get_provider_status(self, provider: str) -> tuple[bool, str]:
        key = self.get_api_key(provider)
        if key:
            return True, mask_key(key)
        return False, "NOT CONFIGURED"


    def get_model(self, provider: str) -> str:
        provider = provider.lower()
        env_names = ENV_MODEL_NAMES.get(provider, [f"{provider.upper()}_MODEL"])
        for env_var in env_names:
            val = os.environ.get(env_var)
            if val and val.strip():
                return val.strip()
        if provider in self.settings.providers:
            return self.settings.providers[provider].model or DEFAULT_MODELS.get(provider, "")
        return DEFAULT_MODELS.get(provider, "")

    def set_model(self, provider: str, model: str) -> None:
        provider = provider.lower()
        if provider in self.settings.providers:
            self.settings.providers[provider].model = model.strip()
            self.save()

    def set_provider_validation(self, provider: str, valid: bool, status: str) -> None:
        import datetime
        provider = provider.lower()
        if provider in self.settings.providers:
            self.settings.providers[provider].last_validated = datetime.datetime.now(datetime.timezone.utc).isoformat()
            self.settings.providers[provider].last_status = status
            self.save()

    def set_fallback_sequence(self, sequence: list[str]) -> None:
        self.settings.fallback_sequence = [s.lower() for s in sequence if s.lower() in self.settings.providers]
        self.save()

    def set_default_provider(self, provider: str) -> None:
        provider = provider.lower()
        if provider in self.settings.providers:
            self.settings.default_provider = provider
            self.save()

    def set_enabled(self, enabled: bool) -> None:
        self.settings.enabled = enabled
        self.save()

