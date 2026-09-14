"""Rapid7 InsightVM adapter (Security Console API v3).

Product: Rapid7 InsightVM (on-prem Security Console + cloud Platform).
API target: Security Console REST API v3 (https://console:3780/api/3).
Auth: Console username+password (HTTP Basic) or platform API key where
configured; deployment type is explicit (REMOTE_SERVICE vs CLOUD).
Docs verified: 2026-09 (Rapid7 InsightVM Security Console API v3 docs).

Supported: configure, health, scan initiation where supported, status,
results, normalization. Cloud vs on-prem deployment is NOT conflated.
"""

from __future__ import annotations

import base64
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

PRODUCT = "Rapid7 InsightVM"
API_VERSION = "Security Console API v3"
DOCS_URL = "https://help.rapid7.com/insightvm/en-us/api/index.html"

_STATUS_MAP = {
    "running": ScanLifecycle.RUNNING, "dispatched": ScanLifecycle.QUEUED,
    "queued": ScanLifecycle.QUEUED, "integrating": ScanLifecycle.PROCESSING,
    "finished": ScanLifecycle.RESULTS_AVAILABLE, "stopped": ScanLifecycle.SCAN_FAILED,
    "failed": ScanLifecycle.SCAN_FAILED, "aborted": ScanLifecycle.SCAN_FAILED,
}


class Rapid7Engine(ExternalVulnerabilityEngine):
    provider_id = "rapid7"
    metadata = ProviderMetadata(
        provider_id="rapid7",
        product=PRODUCT,
        api_version=API_VERSION,
        docs_verified="2026-09-14",
        docs_url=DOCS_URL,
        deployment_type=DeploymentType.REMOTE_SERVICE,
        endpoint="https://console:3780",
        authentication_type="console username+password (Basic) or platform API key",
        supported_asset_types=["ipv4", "hostname"],
        supported_scan_types=["network_vulnerability", "host_assessment", "policy_assessment"],
        supported_result_formats=["json"],
        supported_operations=["authenticate", "health_check", "create_scan", "launch_scan",
                              "get_status", "get_results", "normalize_results", "import"],
        known_limitations=[
            "Security Console workflow is site-centric; a site_id is required to launch scans.",
            "Cloud Platform API differs from Console API — endpoint determines behavior.",
            "Scan templates/engine assignment follow console configuration.",
        ],
    )

    def _base(self) -> str:
        return str(self.config.get("endpoint") or "https://console:3780").rstrip("/")

    def _headers(self) -> dict[str, str]:
        api_key = self._cred("api_key", "apiKey", "token")
        if api_key:
            return {"X-Api-Key": api_key, "Accept": "application/json", "Content-Type": "application/json"}
        user = self._cred("username", "user")
        pwd = self._cred("password", "pass")
        token = base64.b64encode(f"{user}:{pwd}".encode()).decode()
        return {"Authorization": f"Basic {token}", "Accept": "application/json",
                "Content-Type": "application/json"}

    def deployment(self) -> DeploymentType:
        raw = str(self.config.get("deployment", "")).upper()
        if raw == "CLOUD":
            return DeploymentType.CLOUD
        if raw in ("LOCAL_SERVICE", "ON_PREM", "ONPREM"):
            return DeploymentType.LOCAL_SERVICE
        return DeploymentType.REMOTE_SERVICE

    def validate_configuration(self) -> tuple[bool, str]:
        if self._cred("api_key", "apiKey", "token"):
            return True, "ok"
        if not self._cred("username", "user"):
            return False, "rapid7 username (or api_key) not configured"
        if not self._cred("password", "pass"):
            return False, "rapid7 password not configured"
        return True, "ok"

    def authenticate(self) -> EngineResult:
        ok, reason = self.validate_configuration()
        if not ok:
            return self._fail(reason, ScanLifecycle.AUTH_FAILED, auth=True)
        try:
            client = self.client()
            resp = client.get(f"{self._base()}/api/3/sites", params={"size": 1}, headers=self._headers())
            self.track_call()
            if resp.status_code == 401:
                return self._fail("rapid7 authentication rejected (401)", ScanLifecycle.AUTH_FAILED, auth=True)
            if resp.status_code == 429:
                return self._fail("rapid7 rate limited", ScanLifecycle.RATE_LIMITED, rate=True)
            if resp.status_code >= 400:
                return self._fail(f"rapid7 auth check HTTP {resp.status_code}", ScanLifecycle.UNAVAILABLE)
            return EngineResult(ok=True, status=ScanLifecycle.READY, message="rapid7 authenticated")
        except Exception as exc:
            return self._fail(f"rapid7 auth error: {exc}", ScanLifecycle.UNAVAILABLE)

    def health_check(self) -> EngineHealth:
        ok, _ = self.validate_configuration()
        if not ok:
            return EngineHealth.NOT_CONFIGURED
        try:
            client = self.client()
            resp = client.get(f"{self._base()}/api/3/administration/properties",
                              headers=self._headers())
            self.track_call()
            if resp.status_code == 401:
                return EngineHealth.AUTH_FAILED
            if resp.status_code == 429:
                return EngineHealth.RATE_LIMITED
            if resp.status_code == 404:
                # properties endpoint optional; fall back to sites listing
                resp = client.get(f"{self._base()}/api/3/sites", params={"size": 1},
                                  headers=self._headers())
                self.track_call()
            if resp.status_code >= 500:
                return EngineHealth.UNAVAILABLE
            if resp.status_code >= 400:
                return EngineHealth.DEGRADED
            return EngineHealth.HEALTHY
        except Exception:
            return EngineHealth.UNAVAILABLE

    def capabilities(self) -> list[EngineCapability]:
        return [
            EngineCapability(capability_id="network_vulnerability_scanning", label="Network VM"),
            EngineCapability(capability_id="host_vulnerability_assessment", label="Host assessment"),
            EngineCapability(capability_id="policy_assessment", label="Policy assessment"),
        ]

    def create_scan(self, target: str, context: dict[str, Any] | None = None) -> ScanHandle:
        ctx = context or {}
        prep = self.prepare_scan(target, ctx)
        if not prep.ok:
            return ScanHandle(status=prep.status, detail=prep.message)
        ok, reason = self.validate_configuration()
        if not ok:
            return ScanHandle(status=ScanLifecycle.NOT_CONFIGURED, detail=reason)
        site_id = str(ctx.get("site_id") or self.config.get("site_id") or "")
        if not site_id:
            return ScanHandle(status=ScanLifecycle.CONFIGURATION_ERROR,
                              detail="rapid7 site_id required (console scans are site-centric)")
        return ScanHandle(provider_scan_id=f"site:{site_id}|target:{target}",
                          status=ScanLifecycle.READY, detail=f"prepared site scan {site_id}")

    def launch_scan(self, provider_scan_id: str) -> ScanHandle:
        try:
            site_id = self._site_of(provider_scan_id)
            client = self.client()
            payload: dict[str, Any] = {"name": f"horcrux-{site_id}"}
            template = self.config.get("template_id") or self.config.get("scan_template")
            if template:
                payload["templateId"] = template
            engine = self.config.get("engine_id")
            if engine:
                payload["engineId"] = engine
            if provider_scan_id.startswith("site:") and "|target:" in provider_scan_id:
                payload["targets"] = [provider_scan_id.split("|target:", 1)[1]]
            resp = client.post(f"{self._base()}/api/3/sites/{site_id}/scans",
                               json=payload, headers=self._headers())
            self.track_call(scans=1)
            if resp.status_code == 401:
                return ScanHandle(provider_scan_id=provider_scan_id, status=ScanLifecycle.AUTH_FAILED,
                                  detail="rapid7 auth rejected")
            if resp.status_code == 429:
                return ScanHandle(provider_scan_id=provider_scan_id, status=ScanLifecycle.RATE_LIMITED,
                                  detail="rapid7 rate limited")
            if resp.status_code not in (200, 201):
                return ScanHandle(provider_scan_id=provider_scan_id, status=ScanLifecycle.SCAN_FAILED,
                                  detail=f"rapid7 launch HTTP {resp.status_code}")
            scan_id = str(resp.json().get("id", ""))
            return ScanHandle(provider_scan_id=scan_id or provider_scan_id,
                              status=ScanLifecycle.RUNNING, detail="launched")
        except Exception as exc:
            return ScanHandle(provider_scan_id=provider_scan_id, status=ScanLifecycle.UNAVAILABLE,
                              detail=self.safe_message(str(exc)))

    def get_status(self, provider_scan_id: str) -> ScanHandle:
        if provider_scan_id.startswith("site:"):
            return ScanHandle(provider_scan_id=provider_scan_id, status=ScanLifecycle.QUEUED,
                              detail="prepared, not yet launched")
        try:
            client = self.client()
            resp = client.get(f"{self._base()}/api/3/scans/{provider_scan_id}", headers=self._headers())
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
            raw_status = str(resp.json().get("status", "")).lower()
            return ScanHandle(provider_scan_id=provider_scan_id,
                              status=_STATUS_MAP.get(raw_status, ScanLifecycle.RUNNING),
                              detail=raw_status, raw=resp.json())
        except Exception as exc:
            return ScanHandle(provider_scan_id=provider_scan_id, status=ScanLifecycle.UNAVAILABLE,
                              detail=self.safe_message(str(exc)))

    def get_results(self, provider_scan_id: str) -> list[dict[str, Any]]:
        client = self.client()
        resp = client.get(f"{self._base()}/api/3/scans/{provider_scan_id}/vulnerabilities",
                          headers=self._headers())
        self.track_call()
        if resp.status_code == 429:
            raise RuntimeError("rapid7 rate limited (429)")
        if resp.status_code == 401:
            raise RuntimeError("rapid7 authentication failed (401)")
        if resp.status_code == 404:
            # fallback: assets of scan → per-asset vulns
            return self._results_via_assets(client, provider_scan_id)
        resp.raise_for_status()
        payload = resp.json()
        resources = payload.get("resources", payload if isinstance(payload, list) else [])
        if isinstance(payload, dict) and isinstance(payload.get("vulnerabilities"), list):
            resources = payload["vulnerabilities"]
        return resources if isinstance(resources, list) else []

    def normalize_results(self, raw: list[dict[str, Any]], target: str = "") -> list[NormalizedExternalFinding]:
        findings: list[NormalizedExternalFinding] = []
        now = datetime.now(timezone.utc)
        for item in raw:
            vuln = item.get("vulnerability", item) if isinstance(item.get("vulnerability"), dict) else item
            vid = str(vuln.get("id", item.get("id", "")))
            title = str(vuln.get("title", item.get("title", f"rapid7 {vid}")))
            cves = extract_cves(title, str(vuln.get("description", "")))
            for extra in vuln.get("cves", []) or item.get("cves", []) or []:
                c = str(extra).upper()
                if c and c not in cves:
                    cves.append(c)
            cwes = extract_cwes(str(vuln.get("description", "")))
            try:
                cvss = float(vuln.get("cvssScore", vuln.get("cvss", item.get("cvss", "") or 0))) or None
            except (TypeError, ValueError):
                cvss = None
            asset = str(item.get("asset", item.get("host", item.get("ip", target))))
            try:
                port = int(item.get("port")) if str(item.get("port", "")) not in ("", "None") else None
            except (TypeError, ValueError):
                port = None
            findings.append(NormalizedExternalFinding(
                finding_id=f"rapid7-{vid}-{asset}-{port or 'na'}",
                provider="rapid7", source_product=PRODUCT, source_finding_id=vid,
                asset=asset, hostname=str(item.get("hostname", "")),
                port=port, service=str(item.get("service", "")), protocol="tcp",
                product=str(vuln.get("product", "")), cves=cves, cwes=cwes,
                severity=normalize_severity(vuln.get("severity", item.get("severity", "info")), cvss),
                cvss=cvss, title=title, description=str(vuln.get("description", "")),
                evidence=[f"rapid7 {vid}: {title}"],
                first_seen=now, last_seen=now, scan_timestamp=now,
                scanner_state=str(item.get("status", "vulnerable")),
                remediation=str(vuln.get("solution", "")),
                references=[], deployment_type=self.deployment().value,
                provenance="rapid7 scan live result", raw=dict(item)))
        return findings

    # -- internals -----------------------------------------------------
    @staticmethod
    def _site_of(scan_id: str) -> str:
        if scan_id.startswith("site:"):
            return scan_id[len("site:"):].split("|", 1)[0]
        return scan_id

    def _results_via_assets(self, client: Any, scan_id: str) -> list[dict[str, Any]]:
        resp = client.get(f"{self._base()}/api/3/scans/{scan_id}/assets", headers=self._headers())
        self.track_call()
        resp.raise_for_status()
        assets = resp.json().get("resources", [])
        out: list[dict[str, Any]] = []
        for asset in assets:
            aid = asset.get("id")
            vresp = client.get(f"{self._base()}/api/3/assets/{aid}/vulnerabilities",
                               headers=self._headers())
            self.track_call()
            if vresp.status_code != 200:
                continue
            for vuln in vresp.json().get("resources", []):
                vuln = dict(vuln)
                vuln.setdefault("asset", asset.get("hostName", asset.get("ip", "")))
                out.append(vuln)
        return out
