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
    schema_version: int = 2
    enabled: bool = True
    default_provider: str = "groq"
    call_budget: int = 50
    fallback_sequence: list[str] = field(default_factory=lambda: ["google", "openai"])
    providers: dict[str, ProviderConfig] = field(default_factory=dict)
    _keys_file_fallback: dict[str, str] = field(default_factory=dict)
    vulnerability_engines: dict[str, VulnEngineConfig] = field(default_factory=dict)
    _vuln_keys_file_fallback: dict[str, dict[str, str]] = field(default_factory=dict)
    integrations: dict[str, dict[str, Any]] = field(default_factory=dict)
    _integration_credentials_fallback: dict[str, dict[str, str]] = field(default_factory=dict)

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
        integrations: dict[str, dict[str, Any]] = {}
        for name, p in providers.items():
            integrations[name] = {
                "enabled": True,
                "model": p.model,
                "custom_endpoint": p.custom_endpoint,
                "timeout": p.timeout,
                "max_tokens": p.max_tokens,
                "temperature": p.temperature,
            }
        for pid, v in vuln_engines.items():
            integrations[pid] = {
                "enabled": v.enabled,
                "endpoint": v.endpoint,
            }
        integrations["playwright"] = {
            "enabled": True,
            "browser_type": "chromium",
            "headless": True,
            "timeout_ms": 30000,
        }
        for tid in ("nmap", "nuclei", "ffuf", "whatweb"):
            integrations[tid] = {
                "enabled": True,
                "custom_path": "",
            }

        return cls(
            schema_version=2,
            enabled=True,
            default_provider="groq",
            call_budget=50,
            fallback_sequence=["google", "openai"],
            providers=providers,
            vulnerability_engines=vuln_engines,
            integrations=integrations,
        )


class SettingsManager:
    SERVICE_NAME = "horcrux_ai_keys"
    VULN_SERVICE_NAME = "horcrux_vuln_keys"
    INTEGRATIONS_SERVICE_NAME = "horcrux_integrations"

    def __init__(self, config_dir: Path | None = None, use_keyring: bool = True):
        self.config_dir = config_dir or get_config_dir()
        self.settings_file = self.config_dir / "settings.json"
        self.cache_file = self.config_dir / "ai_cache.json"
        self.usage_file = self.config_dir / "ai_usage.json"
        self.use_keyring = use_keyring
        self._runtime_overrides: dict[str, str] = {}
        self._vuln_runtime_overrides: dict[str, dict[str, str]] = {}
        self._integration_runtime_overrides: dict[str, dict[str, str]] = {}
        self.settings = self.load()

    @staticmethod
    def _migrate_v1_to_v2(raw: dict[str, Any]) -> dict[str, Any]:
        """Automatically and idempotently migrate schema version 1 to schema version 2."""
        version = raw.get("schema_version", 1)
        if version >= 2 and "integrations" in raw:
            return raw

        integrations = dict(raw.get("integrations", {}))
        cred_fallback = dict(raw.get("_integration_credentials_fallback", {}))

        # Migrate AI providers
        for name, p_data in raw.get("providers", {}).items():
            norm_name = normalize_provider_name(name)
            if norm_name not in integrations:
                integrations[norm_name] = {
                    "enabled": True,
                    "model": p_data.get("model", DEFAULT_MODELS.get(norm_name, "")),
                    "custom_endpoint": p_data.get("custom_endpoint", ""),
                    "timeout": p_data.get("timeout", 60),
                    "max_tokens": p_data.get("max_tokens", 2048),
                    "temperature": p_data.get("temperature", 0.2),
                    "last_validated": p_data.get("last_validated"),
                    "last_status": p_data.get("last_status"),
                }

        # Migrate AI keys
        for prov, key in raw.get("_keys_fallback", {}).items():
            norm_prov = normalize_provider_name(prov)
            if norm_prov not in cred_fallback:
                cred_fallback[norm_prov] = {}
            if key and isinstance(key, str):
                cred_fallback[norm_prov]["api_key"] = key

        # Migrate Vulnerability engines
        for pid, v_data in (raw.get("vulnerability_engines", {}) or {}).items():
            norm_pid = normalize_vuln_engine_id(pid)
            if not norm_pid:
                continue
            if norm_pid not in integrations:
                integrations[norm_pid] = {
                    "enabled": v_data.get("enabled", True),
                    "endpoint": v_data.get("endpoint", VULN_DEFAULT_ENDPOINTS.get(norm_pid, "")),
                    "last_test": v_data.get("last_test"),
                    "last_status": v_data.get("last_status"),
                    **{k: v for k, v in v_data.items() if k not in ("provider_id", "enabled", "endpoint", "last_test", "last_status")},
                }

        # Migrate Vuln keys
        for pid, cred_dict in raw.get("_vuln_keys_fallback", {}).items():
            norm_pid = normalize_vuln_engine_id(pid)
            if norm_pid not in cred_fallback:
                cred_fallback[norm_pid] = {}
            if isinstance(cred_dict, dict):
                cred_fallback[norm_pid].update(cred_dict)

        raw["schema_version"] = 2
        raw["integrations"] = integrations
        raw["_integration_credentials_fallback"] = cred_fallback
        return raw

    def load(self) -> HorcruxSettings:
        if not self.settings_file.exists():
            default_settings = HorcruxSettings.default()
            self.save(default_settings)
            return default_settings

        try:
            raw = json.loads(self.settings_file.read_text(encoding="utf-8"))
            raw = self._migrate_v1_to_v2(raw)

            providers: dict[str, ProviderConfig] = {}
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

            integrations: dict[str, dict[str, Any]] = raw.get("integrations", {})
            # Ensure AI providers are present in integrations
            for name, p in providers.items():
                if name not in integrations:
                    integrations[name] = {
                        "enabled": True,
                        "model": p.model,
                        "custom_endpoint": p.custom_endpoint,
                        "timeout": p.timeout,
                        "max_tokens": p.max_tokens,
                        "temperature": p.temperature,
                        "last_validated": p.last_validated,
                        "last_status": p.last_status,
                    }
            # Ensure Vuln engines are present in integrations
            for pid, v in vuln_engines.items():
                if pid not in integrations:
                    integrations[pid] = {
                        "enabled": v.enabled,
                        "endpoint": v.endpoint,
                        "last_test": v.last_test,
                        "last_status": v.last_status,
                        **(v.extra or {}),
                    }

            return HorcruxSettings(
                schema_version=2,
                enabled=raw.get("enabled", True),
                default_provider=default_prov,
                call_budget=raw.get("call_budget", 50),
                fallback_sequence=[normalize_provider_name(s) for s in raw.get("fallback_sequence", ["google", "openai"])],
                providers=providers,
                _keys_file_fallback=raw.get("_keys_fallback", {}),
                vulnerability_engines=vuln_engines,
                _vuln_keys_file_fallback=raw.get("_vuln_keys_fallback", {}),
                integrations=integrations,
                _integration_credentials_fallback=raw.get("_integration_credentials_fallback", {}),
            )
        except Exception:
            return HorcruxSettings.default()

    def save(self, settings: HorcruxSettings | None = None) -> None:
        """Atomic write of configuration to prevent corruption."""
        if settings is not None:
            self.settings = settings

        # Sync providers into integrations
        for name, p in self.settings.providers.items():
            if name not in self.settings.integrations:
                self.settings.integrations[name] = {}
            self.settings.integrations[name].update({
                "model": p.model,
                "custom_endpoint": p.custom_endpoint,
                "timeout": p.timeout,
                "max_tokens": p.max_tokens,
                "temperature": p.temperature,
                "last_validated": p.last_validated,
                "last_status": p.last_status,
            })

        # Sync vuln engines into integrations
        for pid, cfg in self.settings.vulnerability_engines.items():
            if pid not in self.settings.integrations:
                self.settings.integrations[pid] = {}
            self.settings.integrations[pid].update({
                "enabled": cfg.enabled,
                "endpoint": cfg.endpoint,
                "last_test": cfg.last_test,
                "last_status": cfg.last_status,
                **(cfg.extra or {}),
            })

        data = {
            "schema_version": 2,
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
            "integrations": self.settings.integrations,
            "_integration_credentials_fallback": self.settings._integration_credentials_fallback,
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

    # ── Unified Integration Control Plane Methods ─────────────────────────

    @staticmethod
    def _resolve_integration_id(identifier: str) -> str:
        if not identifier:
            return ""
        norm = identifier.strip().lower().replace("-", "_")
        norm_prov = normalize_provider_name(norm)
        if norm_prov in ("groq", "openai", "anthropic", "google"):
            return norm_prov
        norm_vuln = normalize_vuln_engine_id(norm)
        if norm_vuln in VULN_ENGINE_IDS:
            return norm_vuln
        return norm

    def get_integration_config(self, integration_id: str) -> dict[str, Any]:
        """Return non-secret configuration dict for an integration."""
        iid = self._resolve_integration_id(integration_id)
        if iid in self.settings.integrations:
            return dict(self.settings.integrations[iid])
        if iid in self.settings.providers:
            p = self.settings.providers[iid]
            return {
                "enabled": True, "model": p.model, "custom_endpoint": p.custom_endpoint,
                "timeout": p.timeout, "max_tokens": p.max_tokens, "temperature": p.temperature,
            }
        if iid in self.settings.vulnerability_engines:
            return self.get_vuln_engine_config(iid)
        return {"enabled": True}

    def set_integration_config(self, integration_id: str, config: dict[str, Any]) -> None:
        """Persist non-secret configuration dict for an integration."""
        iid = self._resolve_integration_id(integration_id)
        if iid not in self.settings.integrations:
            self.settings.integrations[iid] = {}
        self.settings.integrations[iid].update(config)

        # Synchronize with legacy provider structures
        if iid in ("groq", "openai", "anthropic", "google"):
            if "model" in config and config["model"]:
                self.set_model(iid, str(config["model"]))
            if iid in self.settings.providers:
                if "custom_endpoint" in config:
                    self.settings.providers[iid].custom_endpoint = str(config["custom_endpoint"])
        elif iid in VULN_ENGINE_IDS or normalize_vuln_engine_id(iid) in VULN_ENGINE_IDS:
            norm_v = normalize_vuln_engine_id(iid)
            self.set_vuln_engine_fields(norm_v, config)

        self.save()

    def set_integration_runtime_credential(self, integration_id: str, key: str, value: str) -> None:
        """Set an in-memory runtime credential override for any integration."""
        iid = self._resolve_integration_id(integration_id)
        if iid not in self._integration_runtime_overrides:
            self._integration_runtime_overrides[iid] = {}
        if value and value.strip():
            self._integration_runtime_overrides[iid][key] = value.strip()
        else:
            self._integration_runtime_overrides[iid].pop(key, None)

        if iid in ("groq", "openai", "anthropic", "google") and key == "api_key":
            self.set_runtime_credential(iid, value)
        elif iid in VULN_ENGINE_IDS or normalize_vuln_engine_id(iid) in VULN_ENGINE_IDS:
            self.set_vuln_runtime_credentials(iid, {key: value})

    def get_integration_credentials(self, integration_id: str, fields: list[Any] | None = None) -> dict[str, str]:
        """Resolve credentials for an integration following strict precedence:
        1. Runtime overrides
        2. OS Keyring / Secure storage
        3. Settings file fallback
        4. Environment variables
        """
        iid = self._resolve_integration_id(integration_id)
        resolved: dict[str, str] = {}

        field_names: list[str] = []
        env_map: dict[str, list[str]] = {}

        if fields:
            for f in fields:
                fname = getattr(f, "name", str(f))
                field_names.append(fname)
                env_list = getattr(f, "env_vars", [])
                if env_list:
                    env_map[fname] = list(env_list)

        if not field_names:
            if iid in ("groq", "openai", "anthropic", "google"):
                field_names = ["api_key"]
                env_map["api_key"] = ENV_KEY_NAMES.get(iid, [f"{iid.upper()}_API_KEY"])
            elif iid in VULN_CREDENTIAL_FIELDS:
                field_names = VULN_CREDENTIAL_FIELDS[iid]
                env_map = VULN_ENV_VARS.get(iid, {})

        keyring_creds: dict[str, str] = {}
        if self.use_keyring and keyring is not None:
            try:
                stored = keyring.get_password(self.INTEGRATIONS_SERVICE_NAME, iid)
                if stored:
                    try:
                        keyring_creds = json.loads(stored)
                    except Exception:
                        pass
            except Exception:
                pass

            if not keyring_creds and iid in ("groq", "openai", "anthropic", "google"):
                try:
                    k_val = keyring.get_password(self.SERVICE_NAME, iid)
                    if k_val:
                        keyring_creds["api_key"] = k_val
                except Exception:
                    pass

            if not keyring_creds and (iid in VULN_ENGINE_IDS or normalize_vuln_engine_id(iid) in VULN_ENGINE_IDS):
                try:
                    norm_v = normalize_vuln_engine_id(iid)
                    stored_v = keyring.get_password(self.VULN_SERVICE_NAME, f"vuln:{norm_v}")
                    if stored_v:
                        keyring_creds = json.loads(stored_v)
                except Exception:
                    pass

        file_creds: dict[str, str] = dict(self.settings._integration_credentials_fallback.get(iid, {}))
        if not file_creds and iid in self.settings._keys_file_fallback:
            file_creds["api_key"] = self.settings._keys_file_fallback[iid]
        if not file_creds and normalize_vuln_engine_id(iid) in self.settings._vuln_keys_file_fallback:
            file_creds = dict(self.settings._vuln_keys_file_fallback[normalize_vuln_engine_id(iid)])

        runtime_creds: dict[str, str] = dict(self._integration_runtime_overrides.get(iid, {}))
        if iid in self._runtime_overrides:
            runtime_creds["api_key"] = self._runtime_overrides[iid]
        if normalize_vuln_engine_id(iid) in self._vuln_runtime_overrides:
            runtime_creds.update(self._vuln_runtime_overrides[normalize_vuln_engine_id(iid)])

        for fn in field_names:
            # 1. Runtime override
            if runtime_creds.get(fn):
                resolved[fn] = runtime_creds[fn]
                continue
            # 2. Keyring
            if keyring_creds.get(fn):
                resolved[fn] = keyring_creds[fn]
                continue
            # 3. Settings file fallback
            if file_creds.get(fn):
                resolved[fn] = file_creds[fn]
                continue
            # 4. Environment variable
            for ev in env_map.get(fn, []):
                val = os.environ.get(ev)
                if val and val.strip():
                    resolved[fn] = val.strip()
                    break

        return resolved

    def set_integration_credentials(self, integration_id: str, credentials: dict[str, str]) -> None:
        """Store credentials for an integration securely."""
        iid = self._resolve_integration_id(integration_id)
        cleaned = {k: str(v).strip() for k, v in credentials.items() if str(v or "").strip()}
        if not cleaned:
            return

        stored_in_keyring = False
        if self.use_keyring and keyring is not None:
            try:
                keyring.set_password(self.INTEGRATIONS_SERVICE_NAME, iid, json.dumps(cleaned))
                stored_in_keyring = True
            except Exception:
                stored_in_keyring = False

        if not stored_in_keyring:
            if iid not in self.settings._integration_credentials_fallback:
                self.settings._integration_credentials_fallback[iid] = {}
            self.settings._integration_credentials_fallback[iid].update(cleaned)
        else:
            self.settings._integration_credentials_fallback.pop(iid, None)

        # Legacy backward compatibility sync
        if iid in ("groq", "openai", "anthropic", "google") and "api_key" in cleaned:
            if stored_in_keyring:
                try:
                    keyring.set_password(self.SERVICE_NAME, iid, cleaned["api_key"])
                except Exception:
                    pass
            else:
                self.settings._keys_file_fallback[iid] = cleaned["api_key"]
        elif iid in VULN_ENGINE_IDS or normalize_vuln_engine_id(iid) in VULN_ENGINE_IDS:
            norm_v = normalize_vuln_engine_id(iid)
            if stored_in_keyring:
                try:
                    keyring.set_password(self.VULN_SERVICE_NAME, f"vuln:{norm_v}", json.dumps(cleaned))
                except Exception:
                    pass
            else:
                self.settings._vuln_keys_file_fallback[norm_v] = cleaned

        self.save()

    def remove_integration(self, integration_id: str, fields: list[Any] | None = None) -> None:
        """Remove stored credentials and reset configuration for an integration."""
        iid = self._resolve_integration_id(integration_id)
        if self.use_keyring and keyring is not None:
            try:
                keyring.delete_password(self.INTEGRATIONS_SERVICE_NAME, iid)
            except Exception:
                pass
        self.settings._integration_credentials_fallback.pop(iid, None)
        self._integration_runtime_overrides.pop(iid, None)

        if iid in ("groq", "openai", "anthropic", "google"):
            self.remove_api_key(iid)
        elif iid in VULN_ENGINE_IDS or normalize_vuln_engine_id(iid) in VULN_ENGINE_IDS:
            self.remove_vuln_config(normalize_vuln_engine_id(iid))

        if iid in self.settings.integrations:
            self.settings.integrations[iid]["enabled"] = True
            self.settings.integrations[iid].pop("last_test", None)
            self.settings.integrations[iid].pop("last_status", None)

        self.save()

    # ── Legacy AI Provider Facades ────────────────────────────────────────

    def set_runtime_credential(self, provider: str, key: str) -> None:
        """Set in-memory runtime credential override (highest priority)."""
        prov = normalize_provider_name(provider)
        if key and key.strip():
            self._runtime_overrides[prov] = key.strip()
        else:
            self._runtime_overrides.pop(prov, None)

    def get_credential_info(self, provider: str) -> CredentialInfo:
        """Centralized credential resolution following strict precedence."""
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

        # 2. Persisted credential (keyring)
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
            try:
                stored = keyring.get_password(self.INTEGRATIONS_SERVICE_NAME, prov)
                if stored:
                    data = json.loads(stored)
                    if data.get("api_key"):
                        k = data["api_key"].strip()
                        return CredentialInfo(
                            source="persisted",
                            key=k,
                            masked=mask_key(k),
                            fingerprint=fingerprint_key(k),
                            is_configured=True,
                        )
            except Exception:
                pass

        # Settings file fallback
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
        if prov in self.settings._integration_credentials_fallback:
            val = self.settings._integration_credentials_fallback[prov].get("api_key")
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

        stored_in_keyring = False
        if self.use_keyring and keyring is not None:
            try:
                keyring.set_password(self.SERVICE_NAME, prov, key)
                keyring.set_password(self.INTEGRATIONS_SERVICE_NAME, prov, json.dumps({"api_key": key}))
                stored_in_keyring = True
            except Exception:
                stored_in_keyring = False

        if not stored_in_keyring:
            self.settings._keys_file_fallback[prov] = key
            if prov not in self.settings._integration_credentials_fallback:
                self.settings._integration_credentials_fallback[prov] = {}
            self.settings._integration_credentials_fallback[prov]["api_key"] = key
        else:
            self.settings._keys_file_fallback.pop(prov, None)
            self.settings._integration_credentials_fallback.pop(prov, None)

        self.save()

    def remove_api_key(self, provider: str) -> None:
        """Remove stored API key and safely update default provider if needed."""
        prov = normalize_provider_name(provider)
        if self.use_keyring and keyring is not None:
            try:
                keyring.delete_password(self.SERVICE_NAME, prov)
            except Exception:
                pass
            try:
                keyring.delete_password(self.INTEGRATIONS_SERVICE_NAME, prov)
            except Exception:
                pass
        self.settings._keys_file_fallback.pop(prov, None)
        self.settings._integration_credentials_fallback.pop(prov, None)
        self._runtime_overrides.pop(prov, None)
        self._integration_runtime_overrides.pop(prov, None)

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
        if prov in self.settings.integrations and self.settings.integrations[prov].get("model"):
            return str(self.settings.integrations[prov]["model"])
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

        if prov not in self.settings.integrations:
            self.settings.integrations[prov] = {}
        self.settings.integrations[prov]["model"] = m
        self.save()

    def reset_model(self, provider: str) -> str:
        prov = normalize_provider_name(provider)
        def_model = DEFAULT_MODELS.get(prov, "")
        if prov in self.settings.providers:
            self.settings.providers[prov].model = def_model
        if prov in self.settings.integrations:
            self.settings.integrations[prov]["model"] = def_model
        self.save()
        return def_model

    def set_provider_validation(self, provider: str, valid: bool, status: str) -> None:
        import datetime
        prov = normalize_provider_name(provider)
        iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        if prov in self.settings.providers:
            self.settings.providers[prov].last_validated = iso
            self.settings.providers[prov].last_status = status
        if prov in self.settings.integrations:
            self.settings.integrations[prov]["last_validated"] = iso
            self.settings.integrations[prov]["last_status"] = status
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

    # ── Vulnerability Engines Facades ─────────────────────────────────────

    def _vuln_cfg(self, provider: str) -> VulnEngineConfig:
        pid = normalize_vuln_engine_id(provider)
        if pid not in self.settings.vulnerability_engines:
            self.settings.vulnerability_engines[pid] = VulnEngineConfig(
                provider_id=pid, endpoint=VULN_DEFAULT_ENDPOINTS.get(pid, ""))
        return self.settings.vulnerability_engines[pid]

    def get_vuln_engine_config(self, provider: str) -> dict[str, Any]:
        """Config dict for engine adapters (endpoint/enabled/extra, no secrets)."""
        pid = normalize_vuln_engine_id(provider)
        if pid in self.settings.integrations:
            cfg_dict = dict(self.settings.integrations[pid])
            cfg_dict.setdefault("endpoint", VULN_DEFAULT_ENDPOINTS.get(pid, ""))
            cfg_dict.setdefault("enabled", True)
            return cfg_dict
        cfg = self._vuln_cfg(provider)
        out: dict[str, Any] = {"endpoint": cfg.endpoint, "enabled": cfg.enabled,
                               "last_test": cfg.last_test, "last_status": cfg.last_status}
        out.update(cfg.extra or {})
        return out

    def set_vuln_engine_fields(self, provider: str, fields: dict[str, Any]) -> None:
        pid = normalize_vuln_engine_id(provider)
        cfg = self._vuln_cfg(provider)
        if pid not in self.settings.integrations:
            self.settings.integrations[pid] = {}

        for key, value in (fields or {}).items():
            if key == "endpoint":
                cfg.endpoint = str(value)
                self.settings.integrations[pid]["endpoint"] = str(value)
            elif key == "enabled":
                en = bool(value) if not isinstance(value, str) else value.lower() in ("1", "true", "yes")
                cfg.enabled = en
                self.settings.integrations[pid]["enabled"] = en
            elif key in ("last_test", "last_status"):
                setattr(cfg, key, value)
                self.settings.integrations[pid][key] = value
            else:
                cfg.extra[key] = value
                self.settings.integrations[pid][key] = value
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
            if pid not in self._integration_runtime_overrides:
                self._integration_runtime_overrides[pid] = {}
            self._integration_runtime_overrides[pid].update(cleaned)
        else:
            self._vuln_runtime_overrides.pop(pid, None)
            self._integration_runtime_overrides.pop(pid, None)

    def get_vuln_credentials(self, provider: str) -> dict[str, str]:
        """Resolve engine credentials: runtime > keyring/file persisted > environment."""
        pid = normalize_vuln_engine_id(provider)
        return self.get_integration_credentials(pid)

    def get_vuln_credential_source(self, provider: str, fname: str) -> str:
        pid = normalize_vuln_engine_id(provider)
        if self._vuln_runtime_overrides.get(pid, {}).get(fname) or self._integration_runtime_overrides.get(pid, {}).get(fname):
            return "runtime"
        if self.use_keyring and keyring is not None:
            try:
                stored = keyring.get_password(self.INTEGRATIONS_SERVICE_NAME, pid)
                if stored and json.loads(stored).get(fname):
                    return "persisted"
            except Exception:
                pass
            try:
                stored = keyring.get_password(self.VULN_SERVICE_NAME, f"vuln:{pid}")
                if stored and json.loads(stored).get(fname):
                    return "persisted"
            except Exception:
                pass
        if self.settings._integration_credentials_fallback.get(pid, {}).get(fname):
            return "persisted"
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
        return all(bool(creds.get(f)) for f in required)

    def set_vuln_credentials(self, provider: str, fields: dict[str, str]) -> None:
        pid = normalize_vuln_engine_id(provider)
        cleaned = {k: str(v).strip() for k, v in (fields or {}).items() if str(v or "").strip()}
        if not cleaned:
            raise ValueError(f"No credential fields supplied for engine '{pid}'.")
        self.set_integration_credentials(pid, cleaned)

    def remove_vuln_config(self, provider: str) -> None:
        pid = normalize_vuln_engine_id(provider)
        if self.use_keyring and keyring is not None:
            try:
                keyring.delete_password(self.VULN_SERVICE_NAME, f"vuln:{pid}")
            except Exception:
                pass
            try:
                keyring.delete_password(self.INTEGRATIONS_SERVICE_NAME, pid)
            except Exception:
                pass
        self.settings._vuln_keys_file_fallback.pop(pid, None)
        self.settings._integration_credentials_fallback.pop(pid, None)
        self._vuln_runtime_overrides.pop(pid, None)
        self._integration_runtime_overrides.pop(pid, None)
        if pid in self.settings.vulnerability_engines:
            cfg = self.settings.vulnerability_engines[pid]
            cfg.last_status = None
            cfg.last_test = None
        if pid in self.settings.integrations:
            self.settings.integrations[pid].pop("last_test", None)
            self.settings.integrations[pid].pop("last_status", None)
        self.save()

    def masked_vuln_credentials(self, provider: str) -> dict[str, str]:
        creds = self.get_vuln_credentials(provider)
        return {k: (mask_key(v) if v else "NOT CONFIGURED") for k, v in creds.items()}


_GLOBAL_SETTINGS_MANAGER: SettingsManager | None = None


def get_settings_manager(config_dir: Path | None = None, use_keyring: bool = True) -> SettingsManager:
    """Global singleton accessor for SettingsManager."""
    global _GLOBAL_SETTINGS_MANAGER
    if _GLOBAL_SETTINGS_MANAGER is None or config_dir is not None:
        _GLOBAL_SETTINGS_MANAGER = SettingsManager(config_dir=config_dir, use_keyring=use_keyring)
    return _GLOBAL_SETTINGS_MANAGER

