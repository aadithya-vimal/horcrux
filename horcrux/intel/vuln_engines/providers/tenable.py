"""Tenable One Vulnerability Management adapter.

Product: Tenable One Vulnerability Management (cloud VM, formerly Tenable.io).
API: Tenable Vulnerability Management API (cloud.tenable.com).
Auth: X-ApiKeys header — accessKey + secretKey pair.
Docs verified: 2026-09 (Tenable Developer Portal, Vulnerability Management API).

Supported: authenticate, health, template discovery, scan creation,
target injection, launch, status polling, result retrieval, normalization.
Limits: API rate limits honored; permissions depend on operator role;
template UUIDs are discovered dynamically (never hard-coded).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from horcrux.intel.vuln_engines.base import EngineResult, ScanHandle
from horcrux.intel.vuln_engines.base import ExternalVulnerabilityEngine
from horcrux.intel.vuln_engines.normalize import (
    extract_cves,
    extract_cwes,
    normalize_severity,
)
from horcrux.intel.vuln_engines.types import (
    DeploymentType,
    EngineCapability,
    EngineHealth,
    NormalizedExternalFinding,
    ProviderMetadata,
    ScanLifecycle,
)

PRODUCT = "Tenable One Vulnerability Management"
API_VERSION = "Tenable VM API (cloud.tenable.com)"
DOCS_URL = "https://developer.tenable.com/reference/vulnerability-management"

_STATUS_MAP = {
    "empty": ScanLifecycle.QUEUED,
    "pending": ScanLifecycle.QUEUED,
    "running": ScanLifecycle.RUNNING,
    "importing": ScanLifecycle.PROCESSING,
    "paused": ScanLifecycle.RUNNING,
    "stopping": ScanLifecycle.PROCESSING,
    "completed": ScanLifecycle.RESULTS_AVAILABLE,
    "canceled": ScanLifecycle.SCAN_FAILED,
    "aborted": ScanLifecycle.SCAN_FAILED,
    "failed": ScanLifecycle.SCAN_FAILED,
}


class TenableEngine(ExternalVulnerabilityEngine):
    provider_id = "tenable"
    metadata = ProviderMetadata(
        provider_id="tenable",
        product=PRODUCT,
        api_version=API_VERSION,
        docs_verified="2026-09-14",
        docs_url=DOCS_URL,
        deployment_type=DeploymentType.CLOUD,
        endpoint="https://cloud.tenable.com",
        authentication_type="access_key+secret_key (X-ApiKeys header)",
        supported_asset_types=["ipv4", "ipv6", "hostname", "fqdn"],
        supported_scan_types=["network_vulnerability", "host_assessment", "config_audit"],
        supported_result_formats=["json", "nessus_xml"],
        supported_operations=["authenticate", "health_check", "create_scan", "launch_scan",
                              "get_status", "get_results", "normalize_results", "import"],
        known_limitations=[
            "Requires Tenable One VM license; scan concurrency limited by license.",
            "Template UUIDs vary per tenant — discovered via /editor/scan/templates.",
            "API rate limits apply; 429 responses surface as RATE_LIMITED.",
            "Credentialed scans require credentials configured in Tenable, not HORCRUX.",
        ],
    )

    def _base(self) -> str:
        return str(self.config.get("endpoint") or "https://cloud.tenable.com").rstrip("/")

    def _headers(self) -> dict[str, str]:
        access = self._cred("access_key", "accessKey", "username")
        secret = self._cred("secret_key", "secretKey", "password")
        return {"X-ApiKeys": f"accessKey={access}; secretKey={secret}",
                "Accept": "application/json", "Content-Type": "application/json"}

    # -- contract ------------------------------------------------------
    def validate_configuration(self) -> tuple[bool, str]:
        if not self._cred("access_key", "accessKey", "username"):
            return False, "tenable access_key not configured"
        if not self._cred("secret_key", "secretKey", "password"):
            return False, "tenable secret_key not configured"
        return True, "ok"

    def authenticate(self) -> EngineResult:
        ok, reason = self.validate_configuration()
        if not ok:
            return self._fail(reason, ScanLifecycle.AUTH_FAILED, auth=True)
        try:
            client = self.client()
            resp = client.get(f"{self._base()}/session", headers=self._headers())
            self.track_call()
            if resp.status_code == 401:
                return self._fail("tenable authentication rejected (401)", ScanLifecycle.AUTH_FAILED, auth=True)
            if resp.status_code == 429:
                return self._fail("tenable rate limited", ScanLifecycle.RATE_LIMITED, rate=True)
            if resp.status_code >= 400:
                return self._fail(f"tenable auth check HTTP {resp.status_code}", ScanLifecycle.AUTH_FAILED)
            return EngineResult(ok=True, status=ScanLifecycle.READY, message="tenable authenticated")
        except Exception as exc:
            return self._fail(f"tenable auth error: {exc}", ScanLifecycle.UNAVAILABLE)

    def health_check(self) -> EngineHealth:
        ok, _ = self.validate_configuration()
        if not ok:
            return EngineHealth.NOT_CONFIGURED
        if not str(self.config.get("enabled", "true")).lower() in ("1", "true", "yes"):
            return EngineHealth.CONFIGURED
        try:
            client = self.client()
            resp = client.get(f"{self._base()}/scans", params={"limit": 1}, headers=self._headers())
            self.track_call()
            if resp.status_code == 401:
                return EngineHealth.AUTH_FAILED
            if resp.status_code == 429:
                return EngineHealth.RATE_LIMITED
            if resp.status_code >= 500:
                return EngineHealth.UNAVAILABLE
            if resp.status_code >= 400:
                return EngineHealth.DEGRADED
            return EngineHealth.HEALTHY
        except Exception:
            return EngineHealth.UNAVAILABLE

    def capabilities(self) -> list[EngineCapability]:
        return [
            EngineCapability(capability_id="network_vulnerability_scanning", label="Network VM",
                             description="Network vulnerability assessment via Tenable One VM"),
            EngineCapability(capability_id="host_vulnerability_assessment", label="Host assessment"),
            EngineCapability(capability_id="configuration_assessment", label="Configuration audit"),
            EngineCapability(capability_id="result_import", label="Nessus/result import"),
        ]

    def list_templates(self) -> list[dict[str, Any]]:
        client = self.client()
        resp = client.get(f"{self._base()}/editor/scan/templates", headers=self._headers())
        self.track_call()
        if resp.status_code != 200:
            return []
        try:
            return resp.json().get("templates", [])
        except Exception:
            return []

    def create_scan(self, target: str, context: dict[str, Any] | None = None) -> ScanHandle:
        ctx = context or {}
        prep = self.prepare_scan(target, ctx)
        if not prep.ok:
            return ScanHandle(status=prep.status, detail=prep.message)
        ok, reason = self.validate_configuration()
        if not ok:
            return ScanHandle(status=ScanLifecycle.NOT_CONFIGURED, detail=reason)
        # Reuse existing scan with matching name where practical (avoid duplicates)
        scan_name = str(ctx.get("scan_name") or f"horcrux-{target}")
        try:
            client = self.client()
            existing = self._find_scan_by_name(client, scan_name)
            if existing:
                return ScanHandle(provider_scan_id=str(existing), status=ScanLifecycle.READY,
                                  detail=f"reused existing tenable scan {existing}")
            template = str(ctx.get("template_uuid") or self.config.get("template_uuid") or "")
            if not template:
                templates = self.list_templates()
                template = self._pick_template(templates, ctx)
            if not template:
                return ScanHandle(status=ScanLifecycle.CONFIGURATION_ERROR,
                                  detail="no tenable scan template available (none discovered, none configured)")
            payload: dict[str, Any] = {
                "uuid": template,
                "settings": {"name": scan_name, "text_targets": target,
                             "enabled": False, "launch": "ON_DEMAND"},
            }
            if ctx.get("credentials"):
                payload["credentials"] = ctx["credentials"]
            resp = client.post(f"{self._base()}/scans", json=payload, headers=self._headers())
            self.track_call(scans=1)
            if resp.status_code == 401:
                return ScanHandle(status=ScanLifecycle.AUTH_FAILED, detail="tenable auth rejected")
            if resp.status_code == 429:
                return ScanHandle(status=ScanLifecycle.RATE_LIMITED, detail="tenable rate limited")
            if resp.status_code not in (200, 201):
                return ScanHandle(status=ScanLifecycle.SCAN_FAILED,
                                  detail=f"tenable create HTTP {resp.status_code}")
            scan_id = str(resp.json().get("scan", {}).get("id", ""))
            if not scan_id:
                return ScanHandle(status=ScanLifecycle.SCAN_FAILED,
                                  detail="tenable create returned no scan id")
            return ScanHandle(provider_scan_id=scan_id, status=ScanLifecycle.READY,
                              detail=f"created tenable scan {scan_id}")
        except Exception as exc:
            return ScanHandle(status=ScanLifecycle.UNAVAILABLE, detail=self.safe_message(str(exc)))

    def launch_scan(self, provider_scan_id: str) -> ScanHandle:
        try:
            client = self.client()
            resp = client.post(f"{self._base()}/scans/{provider_scan_id}/launch", headers=self._headers())
            self.track_call()
            if resp.status_code == 401:
                return ScanHandle(provider_scan_id=provider_scan_id, status=ScanLifecycle.AUTH_FAILED,
                                  detail="tenable auth rejected")
            if resp.status_code == 429:
                return ScanHandle(provider_scan_id=provider_scan_id, status=ScanLifecycle.RATE_LIMITED,
                                  detail="tenable rate limited")
            if resp.status_code not in (200, 201):
                return ScanHandle(provider_scan_id=provider_scan_id, status=ScanLifecycle.SCAN_FAILED,
                                  detail=f"tenable launch HTTP {resp.status_code}")
            return ScanHandle(provider_scan_id=provider_scan_id, status=ScanLifecycle.RUNNING,
                              detail="launched")
        except Exception as exc:
            return ScanHandle(provider_scan_id=provider_scan_id, status=ScanLifecycle.UNAVAILABLE,
                              detail=self.safe_message(str(exc)))

    def get_status(self, provider_scan_id: str) -> ScanHandle:
        try:
            client = self.client()
            resp = client.get(f"{self._base()}/scans/{provider_scan_id}", headers=self._headers())
            self.track_call()
            if resp.status_code == 401:
                return ScanHandle(provider_scan_id=provider_scan_id, status=ScanLifecycle.AUTH_FAILED,
                                  detail="auth rejected")
            if resp.status_code == 429:
                return ScanHandle(provider_scan_id=provider_scan_id, status=ScanLifecycle.RATE_LIMITED,
                                  detail="rate limited")
            if resp.status_code != 200:
                return ScanHandle(provider_scan_id=provider_scan_id,
                                  status=ScanLifecycle.RESULT_RETRIEVAL_FAILED,
                                  detail=f"HTTP {resp.status_code}")
            info = resp.json().get("info", {})
            raw_status = str(info.get("status", "")).lower()
            return ScanHandle(provider_scan_id=provider_scan_id,
                              status=_STATUS_MAP.get(raw_status, ScanLifecycle.RUNNING),
                              detail=raw_status, raw=info)
        except Exception as exc:
            return ScanHandle(provider_scan_id=provider_scan_id, status=ScanLifecycle.UNAVAILABLE,
                              detail=self.safe_message(str(exc)))

    def get_results(self, provider_scan_id: str) -> list[dict[str, Any]]:
        client = self.client()
        # Primary: per-scan hosts → per-host vulns. Tolerant of fixture shapes.
        resp = client.get(f"{self._base()}/scans/{provider_scan_id}/hosts", headers=self._headers())
        self.track_call()
        if resp.status_code == 429:
            raise RuntimeError("tenable rate limited (429)")
        if resp.status_code == 401:
            raise RuntimeError("tenable authentication failed (401)")
        resp.raise_for_status()
        hosts = resp.json().get("hosts", []) if isinstance(resp.json(), dict) else []
        results: list[dict[str, Any]] = []
        for host in hosts:
            hid = host.get("host_id", host.get("host_id".upper(), ""))
            hresp = client.get(f"{self._base()}/scans/{provider_scan_id}/hosts/{hid}",
                               headers=self._headers())
            self.track_call()
            if hresp.status_code != 200:
                continue
            for vuln in hresp.json().get("vulnerabilities", []):
                vuln = dict(vuln)
                vuln.setdefault("hostname", host.get("hostname", ""))
                vuln.setdefault("host-ip", host.get("host-ip", host.get("host_ip", "")))
                results.append(vuln)
        if not results:
            # Fallback: vulns/export style or direct list payloads (used by fixtures)
            try:
                direct = resp.json()
                if isinstance(direct, dict) and isinstance(direct.get("vulnerabilities"), list):
                    results.extend(direct["vulnerabilities"])
            except Exception:
                pass
        return results

    def normalize_results(self, raw: list[dict[str, Any]], target: str = "") -> list[NormalizedExternalFinding]:
        findings: list[NormalizedExternalFinding] = []
        now = datetime.now(timezone.utc)
        for item in raw:
            plugin = str(item.get("plugin_name", item.get("name", item.get("title", "tenable finding"))))
            cves = extract_cves(str(item.get("cve", "")), plugin,
                                str(item.get("description", "")), str(item.get("synopsis", "")))
            for extra in item.get("cves", []) or []:
                c = str(extra).upper()
                if c and c not in cves:
                    cves.append(c)
            cwes = extract_cwes(str(item.get("description", "")))
            cvss = item.get("cvss3_base_score", item.get("cvss_base_score", item.get("cvss")))
            try:
                cvss_f = float(cvss) if cvss not in (None, "") else None
            except (TypeError, ValueError):
                cvss_f = None
            sev_raw = item.get("severity", item.get("severity_current", "info"))
            if isinstance(sev_raw, int):
                sev_raw = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}.get(sev_raw, "info")
            asset = str(item.get("host-ip", item.get("host_ip", item.get("asset", item.get("host", target)))))
            try:
                port = int(item.get("port")) if str(item.get("port", "")) not in ("", "0", "None") else None
            except (TypeError, ValueError):
                port = None
            findings.append(NormalizedExternalFinding(
                finding_id=f"tenable-{item.get('plugin_id', item.get('pluginID', ''))}-{asset}-{port or 'na'}",
                provider="tenable", source_product=PRODUCT,
                source_finding_id=str(item.get("plugin_id", item.get("pluginID", ""))),
                asset=asset, hostname=str(item.get("hostname", "")),
                port=port, service=str(item.get("svc_name", item.get("service", ""))),
                protocol=str(item.get("protocol", "tcp")),
                product=str(item.get("product", "") or item.get("plugin_family", "")),
                cpe=str(item.get("cpe", "")),
                cves=cves, cwes=cwes,
                severity=normalize_severity(sev_raw, cvss_f), cvss=cvss_f,
                title=plugin, description=str(item.get("description", item.get("synopsis", ""))),
                evidence=[f"tenable plugin {item.get('plugin_id', '?')}: {plugin}"],
                first_seen=now, last_seen=now, scan_timestamp=now,
                scanner_state=str(item.get("vuln_state", item.get("state", "active"))),
                remediation=str(item.get("solution", "")),
                references=[str(r) for r in (item.get("see_also", []) or []) if r],
                deployment_type=DeploymentType.CLOUD.value,
                provenance=f"tenable scan live result",
                raw=dict(item),
            ))
        return findings

    # -- internals -----------------------------------------------------
    def _find_scan_by_name(self, client: Any, name: str) -> str:
        try:
            resp = client.get(f"{self._base()}/scans", params={"limit": 100}, headers=self._headers())
            self.track_call()
            if resp.status_code != 200:
                return ""
            for scan in resp.json().get("scans", []):
                if scan.get("name") == name:
                    return str(scan.get("id", ""))
        except Exception:
            pass
        return ""

    @staticmethod
    def _pick_template(templates: list[dict[str, Any]], ctx: dict[str, Any]) -> str:
        preferred = [str(ctx.get("template_name") or "").lower(),
                     str((ctx.get("scan_type") or "")).lower()]
        # Prefer basic/network templates; never hard-code UUIDs.
        for t in templates:
            name = str(t.get("name", "")).lower()
            if any(p and p in name for p in preferred if p):
                if t.get("uuid"):
                    return str(t["uuid"])
        for t in templates:
            name = str(t.get("name", "")).lower()
            if "basic" in name or "network" in name:
                if t.get("uuid"):
                    return str(t["uuid"])
        for t in templates:
            if t.get("uuid"):
                return str(t["uuid"])
        return ""
