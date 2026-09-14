from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

from horcrux.core.sanitizer import fingerprint_key, mask_key

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


DEFAULT_MODELS: dict[str, str] = {
    "groq": "llama-3.3-70b-versatile",
    "openai": "gpt-4o",
    "anthropic": "claude-3-5-sonnet-latest",
    "google": "gemini-3.6-flash",
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
        "gemini-3.6-flash",
        "gemini-2.5-flash",
        "gemini-1.5-flash",
        "gemini-1.5-pro",
        "gemini-2.0-flash",
        "gemini-2.5-pro",
    ],
}

ENV_KEY_NAMES: dict[str, list[str]] = {
    "groq": ["GROQ_API_KEY"],
    "openai": ["OPENAI_API_KEY"],
    "anthropic": ["ANTHROPIC_API_KEY"],
    "google": ["GOOGLE_API_KEY", "GEMINI_API_KEY", "GOOGLE_AI_API_KEY"],
}

ENV_MODEL_NAMES: dict[str, list[str]] = {
    "groq": ["GROQ_MODEL"],
    "openai": ["OPENAI_MODEL"],
    "anthropic": ["ANTHROPIC_MODEL"],
    "google": ["GOOGLE_MODEL", "GEMINI_MODEL"],
}

PROVIDER_ALIASES: dict[str, str] = {
    "claude": "anthropic",
    "gemini": "google",
    "google-ai": "google",
    "google_ai": "google",
}

VULN_ENGINE_IDS: tuple[str, ...] = ("tenable", "qualys", "rapid7", "greenbone", "msdefender")

VULN_ENGINE_LABELS: dict[str, str] = {
    "tenable": "Tenable One Vulnerability Management",
    "qualys": "Qualys VMDR",
    "rapid7": "Rapid7 InsightVM",
    "greenbone": "Greenbone / OpenVAS",
    "msdefender": "Microsoft Defender Vulnerability Management",
}

VULN_ENGINE_ALIASES: dict[str, str] = {
    "nessus": "tenable",
    "tenable_vm": "tenable",
    "tenable_one": "tenable",
    "insightvm": "rapid7",
    "nexpose": "rapid7",
    "openvas": "greenbone",
    "gvm": "greenbone",
    "defender": "msdefender",
    "microsoft": "msdefender",
}

VULN_CREDENTIAL_FIELDS: dict[str, list[str]] = {
    "tenable": ["access_key", "secret_key"],
    "qualys": ["username", "password"],
    "rapid7": ["username", "password", "api_key"],
    "greenbone": ["username", "password"],
    "msdefender": ["tenant_id", "client_id", "client_secret", "bearer_token"],
}

VULN_ENV_VARS: dict[str, dict[str, list[str]]] = {
    "tenable": {
        "access_key": ["TENABLE_ACCESS_KEY", "TENABLE_ACCESS_KEY_ID"],
        "secret_key": ["TENABLE_SECRET_KEY"],
    },
    "qualys": {
        "username": ["QUALYS_USERNAME", "QUALYS_USER"],
        "password": ["QUALYS_PASSWORD", "QUALYS_PASSWD"],
    },
    "rapid7": {
        "username": ["RAPID7_USERNAME", "INSIGHTVM_USERNAME"],
        "password": ["RAPID7_PASSWORD", "INSIGHTVM_PASSWORD"],
        "api_key": ["RAPID7_API_KEY", "INSIGHTVM_API_KEY"],
    },
    "greenbone": {
        "username": ["GREENBONE_USERNAME", "GVM_USERNAME", "OPENVAS_USERNAME"],
        "password": ["GREENBONE_PASSWORD", "GVM_PASSWORD", "OPENVAS_PASSWORD"],
    },
    "msdefender": {
        "tenant_id": ["AZURE_TENANT_ID", "MSDEFENDER_TENANT_ID"],
        "client_id": ["AZURE_CLIENT_ID", "MSDEFENDER_CLIENT_ID"],
        "client_secret": ["AZURE_CLIENT_SECRET", "MSDEFENDER_CLIENT_SECRET"],
        "bearer_token": ["MSDEFENDER_TOKEN"],
    },
}

VULN_DEFAULT_ENDPOINTS: dict[str, str] = {
    "tenable": "https://cloud.tenable.com",
    "qualys": "https://qualysapi.qualys.com",
    "rapid7": "https://console:3780",
    "greenbone": "https://127.0.0.1:9390",
    "msdefender": "https://api.security.microsoft.com",
}


def normalize_vuln_engine_id(name: str) -> str:
    if not name:
        return ""
    n = name.strip().lower().replace("-", "_")
    return VULN_ENGINE_ALIASES.get(n, n)


def normalize_provider_name(name: str) -> str:
    """Normalize user-supplied provider names and aliases."""
    if not name:
        return ""
    n = name.strip().lower()
    return PROVIDER_ALIASES.get(n, n)


@dataclass
class CredentialInfo:
    """Structured information about resolved provider credentials."""
    source: str  # "runtime" | "persisted" | "environment" | "none"
    key: str
    masked: str
    fingerprint: str
    is_configured: bool
    env_var: Optional[str] = None


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
class VulnEngineConfig:
    """Configuration for one external vulnerability engine (no secrets here)."""

    provider_id: str
    enabled: bool = True
    endpoint: str = ""
    last_test: Optional[str] = None
    last_status: Optional[str] = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class HorcruxSettings:
    enabled: bool = True
    default_provider: str = "groq"
    call_budget: int = 50
    fallback_sequence: list[str] = field(default_factory=lambda: ["google", "openai"])
    providers: dict[str, ProviderConfig] = field(default_factory=dict)
    _keys_file_fallback: dict[str, str] = field(default_factory=dict)
    vulnerability_engines: dict[str, VulnEngineConfig] = field(default_factory=dict)
    _vuln_keys_file_fallback: dict[str, dict[str, str]] = field(default_factory=dict)

    @classmethod
    def default(cls) -> "HorcruxSettings":
        providers = {
            name: ProviderConfig(
                name=name,
                model=DEFAULT_MODELS.get(name, ""),
            )
            for name in ("groq", "openai", "anthropic", "google")
        }
        vuln_engines = {
            pid: VulnEngineConfig(provider_id=pid, enabled=True,
                                  endpoint=VULN_DEFAULT_ENDPOINTS.get(pid, ""))
            for pid in VULN_ENGINE_IDS
        }
        return cls(
            enabled=True,
            default_provider="groq",
            call_budget=50,
            fallback_sequence=["google", "openai"],
            providers=providers,
            vulnerability_engines=vuln_engines,
        )


class SettingsManager:
    SERVICE_NAME = "horcrux_ai_keys"
    VULN_SERVICE_NAME = "horcrux_vuln_keys"

    def __init__(self, config_dir: Path | None = None, use_keyring: bool = True):
        self.config_dir = config_dir or get_config_dir()
        self.settings_file = self.config_dir / "settings.json"
        self.cache_file = self.config_dir / "ai_cache.json"
        self.usage_file = self.config_dir / "ai_usage.json"
        self.use_keyring = use_keyring
        self._runtime_overrides: dict[str, str] = {}
        self._vuln_runtime_overrides: dict[str, dict[str, str]] = {}
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
                norm_name = normalize_provider_name(name)
                providers[norm_name] = ProviderConfig(
                    name=norm_name,
                    model=p_data.get("model", DEFAULT_MODELS.get(norm_name, "")),
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

            default_prov = normalize_provider_name(raw.get("default_provider", "groq"))
            if default_prov not in ("groq", "openai", "anthropic", "google"):
                default_prov = "groq"

            vuln_engines: dict[str, VulnEngineConfig] = {}
            for pid, v_data in (raw.get("vulnerability_engines", {}) or {}).items():
                norm = normalize_vuln_engine_id(pid)
                if not norm:
                    continue
                vuln_engines[norm] = VulnEngineConfig(
                    provider_id=norm,
                    enabled=v_data.get("enabled", True),
                    endpoint=v_data.get("endpoint", VULN_DEFAULT_ENDPOINTS.get(norm, "")),
                    last_test=v_data.get("last_test"),
                    last_status=v_data.get("last_status"),
                    extra={k: v for k, v in v_data.items()
                           if k not in ("provider_id", "enabled", "endpoint", "last_test", "last_status")},
                )
            for pid in VULN_ENGINE_IDS:
                if pid not in vuln_engines:
                    vuln_engines[pid] = VulnEngineConfig(
                        provider_id=pid, enabled=True,
                        endpoint=VULN_DEFAULT_ENDPOINTS.get(pid, ""))

            return HorcruxSettings(
                enabled=raw.get("enabled", True),
                default_provider=default_prov,
                call_budget=raw.get("call_budget", 50),
                fallback_sequence=[normalize_provider_name(s) for s in raw.get("fallback_sequence", ["google", "openai"])],
                providers=providers,
                _keys_file_fallback=raw.get("_keys_fallback", {}),
                vulnerability_engines=vuln_engines,
                _vuln_keys_file_fallback=raw.get("_vuln_keys_fallback", {}),
            )
        except Exception:
            return HorcruxSettings.default()

    def save(self, settings: HorcruxSettings | None = None) -> None:
        """Atomic write of configuration to prevent corruption."""
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
            "vulnerability_engines": {
                pid: {"provider_id": cfg.provider_id, "enabled": cfg.enabled,
                      "endpoint": cfg.endpoint, "last_test": cfg.last_test,
                      "last_status": cfg.last_status, **cfg.extra}
                for pid, cfg in self.settings.vulnerability_engines.items()
            },
            "_vuln_keys_fallback": self.settings._vuln_keys_file_fallback,
        }
        self.settings_file.parent.mkdir(parents=True, exist_ok=True)

        tmp_file = self.settings_file.with_suffix(".tmp")
        tmp_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

        if sys.platform != "win32":
            try:
                os.chmod(tmp_file, 0o600)
            except Exception:
                pass

        os.replace(tmp_file, self.settings_file)

    def set_runtime_credential(self, provider: str, key: str) -> None:
        """Set in-memory runtime credential override (highest priority)."""
        prov = normalize_provider_name(provider)
        if key and key.strip():
            self._runtime_overrides[prov] = key.strip()
        else:
            self._runtime_overrides.pop(prov, None)

    def get_credential_info(self, provider: str) -> CredentialInfo:
        """
        Centralized credential resolution following strict precedence:
          1. Explicit runtime credential override
          2. Persisted HORCRUX settings credential (keyring / settings file fallback)
          3. Environment variable fallback
          4. No credential
        """
        prov = normalize_provider_name(provider)

        # 1. Runtime override
        if prov in self._runtime_overrides:
            val = self._runtime_overrides[prov]
            if val and val.strip():
                k = val.strip()
                return CredentialInfo(
                    source="runtime",
                    key=k,
                    masked=mask_key(k),
                    fingerprint=fingerprint_key(k),
                    is_configured=True,
                )

        # 2. Persisted credential
        # Check system keyring first
        if self.use_keyring and keyring is not None:
            try:
                stored = keyring.get_password(self.SERVICE_NAME, prov)
                if stored and stored.strip():
                    k = stored.strip()
                    return CredentialInfo(
                        source="persisted",
                        key=k,
                        masked=mask_key(k),
                        fingerprint=fingerprint_key(k),
                        is_configured=True,
                    )
            except Exception:
                pass

        # Check settings file fallback
        if prov in self.settings._keys_file_fallback:
            val = self.settings._keys_file_fallback[prov]
            if val and val.strip():
                k = val.strip()
                return CredentialInfo(
                    source="persisted",
                    key=k,
                    masked=mask_key(k),
                    fingerprint=fingerprint_key(k),
                    is_configured=True,
                )

        # 3. Environment variable fallback
        env_names = ENV_KEY_NAMES.get(prov, [f"{prov.upper()}_API_KEY"])
        for env_var in env_names:
            val = os.environ.get(env_var)
            if val and val.strip():
                k = val.strip()
                return CredentialInfo(
                    source="environment",
                    key=k,
                    masked=mask_key(k),
                    fingerprint=fingerprint_key(k),
                    is_configured=True,
                    env_var=env_var,
                )

        # 4. No credential
        return CredentialInfo(
            source="none",
            key="",
            masked="NOT CONFIGURED",
            fingerprint="NONE",
            is_configured=False,
        )

    def get_api_key(self, provider: str) -> str:
        """Resolve API key using centralized precedence."""
        return self.get_credential_info(provider).key

    def set_api_key(self, provider: str, key: str) -> None:
        """Store new API key atomically, replacing previous credential."""
        prov = normalize_provider_name(provider)
        key = key.strip()
        if not key:
            raise ValueError(f"API key for provider '{prov}' cannot be empty.")

        # Save to keyring or file fallback
        stored_in_keyring = False
        if self.use_keyring and keyring is not None:
            try:
                keyring.set_password(self.SERVICE_NAME, prov, key)
                stored_in_keyring = True
            except Exception:
                stored_in_keyring = False

        if not stored_in_keyring:
            self.settings._keys_file_fallback[prov] = key
        else:
            self.settings._keys_file_fallback.pop(prov, None)

        self.save()

    def remove_api_key(self, provider: str) -> None:
        """Remove stored API key and safely update default provider if needed."""
        prov = normalize_provider_name(provider)
        if self.use_keyring and keyring is not None:
            try:
                keyring.delete_password(self.SERVICE_NAME, prov)
            except Exception:
                pass
        self.settings._keys_file_fallback.pop(prov, None)
        self._runtime_overrides.pop(prov, None)


        # If removed provider was default, switch to another configured provider if one exists
        if self.settings.default_provider == prov:
            other_configured = [
                p for p in ("groq", "google", "openai", "anthropic")
                if p != prov and self.get_credential_info(p).is_configured
            ]
            if other_configured:
                self.settings.default_provider = other_configured[0]

        self.save()

    def get_key_source(self, provider: str) -> str:
        info = self.get_credential_info(provider)
        if info.source == "environment" and info.env_var:
            return f"environment (${info.env_var})"
        return info.source

    def get_provider_status(self, provider: str) -> tuple[bool, str]:
        info = self.get_credential_info(provider)
        return info.is_configured, info.masked

    def get_model(self, provider: str) -> str:
        prov = normalize_provider_name(provider)
        env_names = ENV_MODEL_NAMES.get(prov, [f"{prov.upper()}_MODEL"])
        for env_var in env_names:
            val = os.environ.get(env_var)
            if val and val.strip():
                return val.strip()
        if prov in self.settings.providers:
            return self.settings.providers[prov].model or DEFAULT_MODELS.get(prov, "")
        return DEFAULT_MODELS.get(prov, "")

    def set_model(self, provider: str, model: str) -> None:
        prov = normalize_provider_name(provider)
        m = model.strip()
        if not m:
            raise ValueError(f"Model name for provider '{prov}' cannot be empty.")
        if prov not in self.settings.providers:
            self.settings.providers[prov] = ProviderConfig(name=prov, model=m)
        else:
            self.settings.providers[prov].model = m
        self.save()

    def reset_model(self, provider: str) -> str:
        """Reset model for a provider to its canonical default."""
        prov = normalize_provider_name(provider)
        def_model = DEFAULT_MODELS.get(prov, "")
        if prov in self.settings.providers:
            self.settings.providers[prov].model = def_model
            self.save()
        return def_model

    def set_provider_validation(self, provider: str, valid: bool, status: str) -> None:
        import datetime
        prov = normalize_provider_name(provider)
        if prov in self.settings.providers:
            self.settings.providers[prov].last_validated = datetime.datetime.now(datetime.timezone.utc).isoformat()
            self.settings.providers[prov].last_status = status
            self.save()

    def set_fallback_sequence(self, sequence: list[str]) -> None:
        self.settings.fallback_sequence = [normalize_provider_name(s) for s in sequence if normalize_provider_name(s) in self.settings.providers]
        self.save()

    def set_default_provider(self, provider: str) -> None:
        prov = normalize_provider_name(provider)
        if prov in self.settings.providers:
            self.settings.default_provider = prov
            self.save()

    def set_enabled(self, enabled: bool) -> None:
        self.settings.enabled = enabled
        self.save()

    # ── Vulnerability engines (settings → VULNERABILITY ENGINES) ──────────
    def _vuln_cfg(self, provider: str) -> VulnEngineConfig:
        pid = normalize_vuln_engine_id(provider)
        if pid not in self.settings.vulnerability_engines:
            self.settings.vulnerability_engines[pid] = VulnEngineConfig(
                provider_id=pid, endpoint=VULN_DEFAULT_ENDPOINTS.get(pid, ""))
        return self.settings.vulnerability_engines[pid]

    def get_vuln_engine_config(self, provider: str) -> dict[str, Any]:
        """Config dict for engine adapters (endpoint/enabled/extra, no secrets)."""
        cfg = self._vuln_cfg(provider)
        out: dict[str, Any] = {"endpoint": cfg.endpoint, "enabled": cfg.enabled,
                               "last_test": cfg.last_test, "last_status": cfg.last_status}
        out.update(cfg.extra or {})
        return out

    def set_vuln_engine_fields(self, provider: str, fields: dict[str, Any]) -> None:
        cfg = self._vuln_cfg(provider)
        for key, value in (fields or {}).items():
            if key == "endpoint":
                cfg.endpoint = str(value)
            elif key == "enabled":
                cfg.enabled = bool(value) if not isinstance(value, str) else value.lower() in ("1", "true", "yes")
            elif key in ("last_test", "last_status"):
                setattr(cfg, key, value)
            else:
                cfg.extra[key] = value
        self.save()

    def set_vuln_enabled(self, provider: str, enabled: bool) -> None:
        self.set_vuln_engine_fields(provider, {"enabled": enabled})

    def set_vuln_endpoint(self, provider: str, endpoint: str) -> None:
        self.set_vuln_engine_fields(provider, {"endpoint": endpoint.strip()})

    def set_vuln_validation(self, provider: str, status: str) -> None:
        import datetime
        self.set_vuln_engine_fields(provider, {
            "last_test": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "last_status": status,
        })

    def set_vuln_runtime_credentials(self, provider: str, fields: dict[str, str]) -> None:
        pid = normalize_vuln_engine_id(provider)
        cleaned = {k: v.strip() for k, v in (fields or {}).items() if v and str(v).strip()}
        if cleaned:
            self._vuln_runtime_overrides[pid] = cleaned
        else:
            self._vuln_runtime_overrides.pop(pid, None)

    def get_vuln_credentials(self, provider: str) -> dict[str, str]:
        """Resolve engine credentials: runtime > keyring/file persisted > environment."""
        import json as _json

        pid = normalize_vuln_engine_id(provider)
        fields = VULN_CREDENTIAL_FIELDS.get(pid, ["api_key"])
        resolved: dict[str, str] = {}

        persisted: dict[str, str] = {}
        if self.use_keyring and keyring is not None:
            try:
                stored = keyring.get_password(self.VULN_SERVICE_NAME, f"vuln:{pid}")
                if stored:
                    try:
                        persisted = {k: str(v) for k, v in _json.loads(stored).items()}
                    except Exception:
                        persisted = {}
            except Exception:
                pass
        if not persisted:
            fallback = self.settings._vuln_keys_file_fallback.get(pid, {})
            if isinstance(fallback, dict):
                persisted = {k: str(v) for k, v in fallback.items()}

        env_map = VULN_ENV_VARS.get(pid, {})
        for fname in fields:
            # 1. runtime override
            runtime = self._vuln_runtime_overrides.get(pid, {}).get(fname, "")
            if runtime and runtime.strip():
                resolved[fname] = runtime.strip()
                continue
            # 2. persisted
            if persisted.get(fname, "").strip():
                resolved[fname] = persisted[fname].strip()
                continue
            # 3. environment
            for env_var in env_map.get(fname, []):
                val = os.environ.get(env_var, "")
                if val and val.strip():
                    resolved[fname] = val.strip()
                    break
        return resolved

    def get_vuln_credential_source(self, provider: str, fname: str) -> str:
        pid = normalize_vuln_engine_id(provider)
        if self._vuln_runtime_overrides.get(pid, {}).get(fname):
            return "runtime"
        if self.use_keyring and keyring is not None:
            try:
                import json as _json
                stored = keyring.get_password(self.VULN_SERVICE_NAME, f"vuln:{pid}")
                if stored and _json.loads(stored).get(fname):
                    return "persisted"
            except Exception:
                pass
        if self.settings._vuln_keys_file_fallback.get(pid, {}).get(fname):
            return "persisted"
        env_map = VULN_ENV_VARS.get(pid, {}).get(fname, [])
        for env_var in env_map:
            if os.environ.get(env_var):
                return f"environment (${env_var})"
        return "none"

    def is_vuln_configured(self, provider: str) -> bool:
        pid = normalize_vuln_engine_id(provider)
        creds = self.get_vuln_credentials(pid)
        if pid == "msdefender":
            return bool(creds.get("bearer_token") or (
                creds.get("tenant_id") and creds.get("client_id") and creds.get("client_secret")))
        if pid == "rapid7":
            return bool(creds.get("api_key") or (creds.get("username") and creds.get("password")))
        fields = VULN_CREDENTIAL_FIELDS.get(pid, [])
        required = [f for f in fields if f != "bearer_token"]
        return all(creds.get(f) for f in required)

    def set_vuln_credentials(self, provider: str, fields: dict[str, str]) -> None:
        import json as _json

        pid = normalize_vuln_engine_id(provider)
        cleaned = {k: str(v).strip() for k, v in (fields or {}).items() if str(v or "").strip()}
        if not cleaned:
            raise ValueError(f"No credential fields supplied for engine '{pid}'.")
        stored_in_keyring = False
        if self.use_keyring and keyring is not None:
            try:
                keyring.set_password(self.VULN_SERVICE_NAME, f"vuln:{pid}", _json.dumps(cleaned))
                stored_in_keyring = True
            except Exception:
                stored_in_keyring = False
        if not stored_in_keyring:
            self.settings._vuln_keys_file_fallback[pid] = cleaned
        else:
            self.settings._vuln_keys_file_fallback.pop(pid, None)
        self.save()

    def remove_vuln_config(self, provider: str) -> None:
        pid = normalize_vuln_engine_id(provider)
        if self.use_keyring and keyring is not None:
            try:
                keyring.delete_password(self.VULN_SERVICE_NAME, f"vuln:{pid}")
            except Exception:
                pass
        self.settings._vuln_keys_file_fallback.pop(pid, None)
        self._vuln_runtime_overrides.pop(pid, None)
        if pid in self.settings.vulnerability_engines:
            cfg = self.settings.vulnerability_engines[pid]
            cfg.last_status = None
            cfg.last_test = None
        self.save()

    def masked_vuln_credentials(self, provider: str) -> dict[str, str]:
        creds = self.get_vuln_credentials(provider)
        return {k: (mask_key(v) if v else "NOT CONFIGURED") for k, v in creds.items()}
