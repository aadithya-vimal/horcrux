"""Greenbone / OpenVAS adapter (GMP service model).

Product: Greenbone Enterprise / Greenbone Community (OpenVAS scanner + gvmd).
API: Greenbone Management Protocol (GMP v22+) — XML over TLS to gvmd
(typically port 9390). NOT a cloud REST API; deployment is LOCAL_SERVICE
or REMOTE_SERVICE and is represented explicitly.
Docs verified: 2026-09 (Greenbone GMP protocol documentation).

Supported: connection, authentication, health, scan lifecycle
(target → task → start → status → results), normalization.
Transport is injectable (XML session double in tests; no live daemon).
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any

from horcrux.intel.vuln_engines.base import EngineResult, ScanHandle
from horcrux.intel.vuln_engines.base import ExternalVulnerabilityEngine
from horcrux.intel.vuln_engines.normalize import extract_cves, extract_cwes, normalize_severity
from horcrux.intel.vuln_engines.types import (
    DeploymentType,
    EngineCapability,
    EngineHealth,
    NormalizedExternalFinding,
    ProviderMetadata,
    ScanLifecycle,
)

PRODUCT = "Greenbone OpenVAS"
API_VERSION = "GMP v22 (gvmd)"
DOCS_URL = "https://docs.greenbone.net/API/GMP/gmp.html"

_STATUS_MAP = {
    "new": ScanLifecycle.QUEUED, "queued": ScanLifecycle.QUEUED,
    "requested": ScanLifecycle.QUEUED, "running": ScanLifecycle.RUNNING,
    "processing": ScanLifecycle.PROCESSING, "done": ScanLifecycle.RESULTS_AVAILABLE,
    "stopped": ScanLifecycle.SCAN_FAILED, "interrupted": ScanLifecycle.SCAN_FAILED,
}


def _text(node: ET.Element | None, path: str, default: str = "") -> str:
    if node is None:
        return default
    found = node.find(path)
    return (found.text or default).strip() if found is not None and found.text else default


class GreenboneEngine(ExternalVulnerabilityEngine):
    provider_id = "greenbone"
    metadata = ProviderMetadata(
        provider_id="greenbone",
        product=PRODUCT,
        api_version=API_VERSION,
        docs_verified="2026-09-14",
        docs_url=DOCS_URL,
        deployment_type=DeploymentType.LOCAL_SERVICE,
        endpoint="https://127.0.0.1:9390",
        authentication_type="gmp username+password (XML session; API key/certificate where deployed)",
        supported_asset_types=["ipv4", "hostname"],
        supported_scan_types=["network_vulnerability", "host_assessment"],
        supported_result_formats=["xml", "json-normalized"],
        supported_operations=["authenticate", "health_check", "create_scan", "launch_scan",
                              "get_status", "get_results", "normalize_results", "import"],
        known_limitations=[
            "Requires reachable gvmd/GMP service; not a cloud API.",
            "Feed sync state affects result freshness.",
            "Scan configs/port lists follow server-side configuration.",
        ],
    )

    def deployment(self) -> DeploymentType:
        raw = str(self.config.get("deployment", "")).upper()
        if raw == "REMOTE_SERVICE":
            return DeploymentType.REMOTE_SERVICE
        return DeploymentType.LOCAL_SERVICE

    def _session(self) -> Any:
        if self._client is not None:
            return self._client
        # Lazy import — python-gvm optional; without it, fail cleanly.
        try:
            from gvm.connections import TLSConnection  # type: ignore
            from gvm.protocols.gmp import Gmp  # type: ignore
            host = str(self.config.get("host", "127.0.0.1"))
            port = int(self.config.get("port", 9390))
            return _GvmSession(host, port, TLSConnection, Gmp)
        except Exception as exc:
            raise RuntimeError(f"greenbone transport unavailable: {exc}")

    def validate_configuration(self) -> tuple[bool, str]:
        if not self._cred("username", "user"):
            return False, "greenbone username not configured"
        if not self._cred("password", "pass", "api_key"):
            return False, "greenbone password not configured"
        return True, "ok"

    def authenticate(self) -> EngineResult:
        ok, reason = self.validate_configuration()
        if not ok:
            return self._fail(reason, ScanLifecycle.AUTH_FAILED, auth=True)
        try:
            session = self._session()
            user = self._cred("username", "user")
            pwd = self._cred("password", "pass", "api_key")
            self.track_call()
            if hasattr(session, "authenticate"):
                result = session.authenticate(user, pwd)
                if result is False:
                    return self._fail("greenbone authentication rejected", ScanLifecycle.AUTH_FAILED, auth=True)
            return EngineResult(ok=True, status=ScanLifecycle.READY, message="greenbone authenticated")
        except Exception as exc:
            msg = self.safe_message(str(exc))
            if "auth" in msg.lower():
                return self._fail(msg, ScanLifecycle.AUTH_FAILED, auth=True)
            return self._fail(f"greenbone auth error: {msg}", ScanLifecycle.UNAVAILABLE)

    def health_check(self) -> EngineHealth:
        ok, _ = self.validate_configuration()
        if not ok:
            return EngineHealth.NOT_CONFIGURED
        try:
            session = self._session()
            self.track_call()
            version = session.get_version() if hasattr(session, "get_version") else "unknown"
            if not version:
                return EngineHealth.DEGRADED
            return EngineHealth.HEALTHY
        except Exception as exc:
            if "auth" in str(exc).lower():
                return EngineHealth.AUTH_FAILED
            return EngineHealth.UNAVAILABLE

    def capabilities(self) -> list[EngineCapability]:
        return [
            EngineCapability(capability_id="network_vulnerability_scanning", label="Network VM"),
            EngineCapability(capability_id="host_vulnerability_assessment", label="Host assessment"),
        ]

    def create_scan(self, target: str, context: dict[str, Any] | None = None) -> ScanHandle:
        ctx = context or {}
        prep = self.prepare_scan(target, ctx)
        if not prep.ok:
            return ScanHandle(status=prep.status, detail=prep.message)
        ok, reason = self.validate_configuration()
        if not ok:
            return ScanHandle(status=ScanLifecycle.NOT_CONFIGURED, detail=reason)
        try:
            session = self._session()
            self.track_call(scans=1)
            target_id = session.create_target(target, ctx) if hasattr(session, "create_target") else f"tgt-{target}"
            task_id = session.create_task(target, target_id, ctx) if hasattr(session, "create_task") else f"task-{target}"
            return ScanHandle(provider_scan_id=str(task_id), status=ScanLifecycle.READY,
                              detail=f"created task {task_id}", raw={"target_id": target_id})
        except Exception as exc:
            return ScanHandle(status=ScanLifecycle.UNAVAILABLE, detail=self.safe_message(str(exc)))

    def launch_scan(self, provider_scan_id: str) -> ScanHandle:
        try:
            session = self._session()
            self.track_call()
            if hasattr(session, "start_task"):
                session.start_task(provider_scan_id)
            return ScanHandle(provider_scan_id=provider_scan_id, status=ScanLifecycle.RUNNING,
                              detail="task started")
        except Exception as exc:
            return ScanHandle(provider_scan_id=provider_scan_id, status=ScanLifecycle.UNAVAILABLE,
                              detail=self.safe_message(str(exc)))

    def get_status(self, provider_scan_id: str) -> ScanHandle:
        try:
            session = self._session()
            self.track_call()
            raw_status = session.get_task_status(provider_scan_id) if hasattr(session, "get_task_status") else "Running"
            key = str(raw_status).strip().lower()
            # GMP statuses like "Done", "Running", "Queued"
            for prefix, mapped in _STATUS_MAP.items():
                if key.startswith(prefix):
                    return ScanHandle(provider_scan_id=provider_scan_id, status=mapped,
                                      detail=str(raw_status), raw={"status": raw_status})
            return ScanHandle(provider_scan_id=provider_scan_id, status=ScanLifecycle.RUNNING,
                              detail=str(raw_status))
        except Exception as exc:
            return ScanHandle(provider_scan_id=provider_scan_id, status=ScanLifecycle.UNAVAILABLE,
                              detail=self.safe_message(str(exc)))

    def get_results(self, provider_scan_id: str) -> list[dict[str, Any]]:
        session = self._session()
        self.track_call()
        if hasattr(session, "get_results"):
            results = session.get_results(provider_scan_id)
            return list(results or [])
        raise RuntimeError("greenbone transport does not support result retrieval")

    def normalize_results(self, raw: list[dict[str, Any]], target: str = "") -> list[NormalizedExternalFinding]:
        findings: list[NormalizedExternalFinding] = []
        now = datetime.now(timezone.utc)
        for item in raw:
            nvt = str(item.get("nvt_oid", item.get("oid", item.get("id", ""))))
            name = str(item.get("name", item.get("title", f"openvas {nvt}")))
            cves = extract_cves(str(item.get("cves", "")), name, str(item.get("description", "")))
            for extra in item.get("cve_list", []) or []:
                c = str(extra).upper()
                if c and c not in cves:
                    cves.append(c)
            cwes = extract_cwes(str(item.get("description", "")))
            try:
                cvss = float(item.get("cvss", item.get("severity", "") or 0)) or None
            except (TypeError, ValueError):
                cvss = None
            asset = str(item.get("host", item.get("asset", item.get("ip", target))))
            try:
                port = int(str(item.get("port", "")).split("/")[0]) if str(item.get("port", "")) else None
            except (TypeError, ValueError):
                port = None
            findings.append(NormalizedExternalFinding(
                finding_id=f"greenbone-{nvt}-{asset}-{port or 'na'}",
                provider="greenbone", source_product=PRODUCT, source_finding_id=nvt,
                asset=asset, hostname=str(item.get("hostname", "")),
                port=port, service=str(item.get("service", "")), protocol="tcp",
                product=str(item.get("product", "")), cves=cves, cwes=cwes,
                severity=normalize_severity(item.get("threat", item.get("severity", "info")), cvss),
                cvss=cvss, title=name, description=str(item.get("description", "")),
                evidence=[f"openvas {nvt}: {name}"],
                first_seen=now, last_seen=now, scan_timestamp=now,
                scanner_state=str(item.get("status", "active")),
                remediation=str(item.get("solution", "")),
                references=[], deployment_type=self.deployment().value,
                provenance="greenbone scan live result", raw=dict(item)))
        return findings


class _GvmSession:
    """Thin wrapper so python-gvm is optional and mockable."""

    def __init__(self, host: str, port: int, conn_cls: Any, gmp_cls: Any) -> None:
        self._host = host
        self._port = port
        self._conn_cls = conn_cls
        self._gmp_cls = gmp_cls
        self._gmp: Any | None = None

    def authenticate(self, username: str, password: str) -> bool:
        conn = self._conn_cls(hostname=self._host, port=self._port)
        gmp = self._gmp_cls(conn)
        gmp.authenticate(username, password)
        self._gmp = gmp
        return True

    def get_version(self) -> str:
        if self._gmp is None:
            raise RuntimeError("not authenticated")
        return str(self._gmp.get_version())

    def create_target(self, target: str, ctx: dict) -> str:
        resp = self._gmp.create_target(name=f"horcrux-{target}", hosts=[target])
        return str(resp.get("id", f"tgt-{target}"))

    def create_task(self, target: str, target_id: str, ctx: dict) -> str:
        config_id = str(ctx.get("scan_config_id") or self._gmp.get_scan_configs().get("id", ""))
        resp = self._gmp.create_task(name=f"horcrux-{target}", config_id=config_id, target_id=target_id)
        return str(resp.get("id", f"task-{target}"))

    def start_task(self, task_id: str) -> None:
        self._gmp.start_task(task_id)

    def get_task_status(self, task_id: str) -> str:
        task = self._gmp.get_task(task_id)
        return str(task.get("status", "Running"))

    def get_results(self, task_id: str) -> list[dict]:
        report = self._gmp.get_report(task_id)
        out: list[dict] = []
        try:
            root = ET.fromstring(report) if isinstance(report, str) else report
            for res in root.iter("result"):
                out.append({
                    "id": res.get("id", ""),
                    "name": _text(res, "name"),
                    "host": _text(res, "host"),
                    "port": _text(res, "port"),
                    "threat": _text(res, "threat"),
                    "description": _text(res, "description"),
                    "nvt_oid": res.get("nvt_oid", ""),
                })
        except Exception:
            pass
        return out
