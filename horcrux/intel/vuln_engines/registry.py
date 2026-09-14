"""Provider registry — adding a scanner = new adapter, no core changes."""

from __future__ import annotations

from typing import Any, Callable

from horcrux.intel.vuln_engines.base import ExternalVulnerabilityEngine
from horcrux.intel.vuln_engines.providers.greenbone import GreenboneEngine
from horcrux.intel.vuln_engines.providers.msdefender import MicrosoftDefenderEngine
from horcrux.intel.vuln_engines.providers.qualys import QualysEngine
from horcrux.intel.vuln_engines.providers.rapid7 import Rapid7Engine
from horcrux.intel.vuln_engines.providers.tenable import TenableEngine

_ENGINE_CLASSES: dict[str, type[ExternalVulnerabilityEngine]] = {
    "tenable": TenableEngine,
    "qualys": QualysEngine,
    "rapid7": Rapid7Engine,
    "greenbone": GreenboneEngine,
    "msdefender": MicrosoftDefenderEngine,
}

ALIASES = {
    "nessus": "tenable",
    "tenable_vm": "tenable",
    "tenable_one": "tenable",
    "insightvm": "rapid7",
    "nexpose": "rapid7",
    "openvas": "greenbone",
    "gvm": "greenbone",
    "defender": "msdefender",
    "mstv": "msdefender",
    "microsoft": "msdefender",
}


def normalize_engine_id(name: str) -> str:
    n = (name or "").strip().lower().replace("-", "_")
    return ALIASES.get(n, n)


def provider_ids() -> list[str]:
    return sorted(_ENGINE_CLASSES)


def get_engine(
    provider_id: str,
    config: dict[str, Any] | None = None,
    credentials: dict[str, Any] | None = None,
    client: Any | None = None,
) -> ExternalVulnerabilityEngine:
    pid = normalize_engine_id(provider_id)
    cls = _ENGINE_CLASSES.get(pid)
    if cls is None:
        raise ValueError(f"unknown vulnerability engine '{provider_id}' "
                         f"(supported: {', '.join(provider_ids())})")
    return cls(config=config, credentials=credentials, client=client)


def register_engine(provider_id: str, cls: type[ExternalVulnerabilityEngine]) -> None:
    """Extension point for future scanners without touching core logic."""
    _ENGINE_CLASSES[normalize_engine_id(provider_id)] = cls


def engine_factory_resolver(
    settings_manager: Any | None = None,
    client_factory: Callable[[str], Any] | None = None,
) -> Callable[[str], ExternalVulnerabilityEngine]:
    def resolve(provider_id: str) -> ExternalVulnerabilityEngine:
        pid = normalize_engine_id(provider_id)
        config: dict[str, Any] = {}
        creds: dict[str, Any] = {}
        if settings_manager is not None and hasattr(settings_manager, "get_vuln_engine_config"):
            try:
                config = settings_manager.get_vuln_engine_config(pid)
            except Exception:
                config = {}
        if settings_manager is not None and hasattr(settings_manager, "get_vuln_credentials"):
            try:
                creds = settings_manager.get_vuln_credentials(pid)
            except Exception:
                creds = {}
        client = client_factory(pid) if client_factory else None
        return get_engine(pid, config=config, credentials=creds, client=client)

    return resolve
