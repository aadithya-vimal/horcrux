"""Microsoft Defender Vulnerability Management connector.

Product: Microsoft Defender Vulnerability Management (Defender for Endpoint).
API: Microsoft Defender for Endpoint / Defender XDR APIs surfaced via
https://api.security.microsoft.com (vulnerabilities + recommendations).
Auth: OAuth2 client-credentials (tenant + client id + client secret) bearer token.
Docs verified: 2026-09 (Microsoft Defender for Endpoint API docs).

Role: enterprise/cloud vulnerability-INTELLIGENCE connector. It is NOT a
direct network-scanner replacement — no scan lifecycle is fabricated.
Supported: authenticate (token), health, vulnerability observation pull,
recommendation pull, normalization. create/launch return NOT_APPLICABLE.
"""

from __future__ import annotations

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

PRODUCT = "Microsoft Defender Vulnerability Management"
API_VERSION = "Defender for Endpoint API (api.security.microsoft.com)"
DOCS_URL = "https://learn.microsoft.com/en-us/defender-endpoint/apis-intro"


class MicrosoftDefenderEngine(ExternalVulnerabilityEngine):
    provider_id = "msdefender"
    metadata = ProviderMetadata(
        provider_id="msdefender",
        product=PRODUCT,
        api_version=API_VERSION,
        docs_verified="2026-09-14",
        docs_url=DOCS_URL,
        deployment_type=DeploymentType.CLOUD,
        endpoint="https://api.security.microsoft.com",
        authentication_type="OAuth2 client-credentials bearer token (tenant+client+secret)",
        supported_asset_types=["device_id", "hostname"],
        supported_scan_types=["vulnerability_intelligence", "recommendations"],
        supported_result_formats=["json"],
        supported_operations=["authenticate", "health_check", "get_results",
                              "normalize_results", "import"],
        known_limitations=[
            "Intelligence connector only: exposes vulnerabilities/recommendations for enrolled devices.",
            "Does NOT launch network scans; create/launch report NOT_APPLICABLE by design.",
            "Requires Azure AD app with Device.Read/Vulnerability.Read scopes.",
        ],
    )

    def _base(self) -> str:
        return str(self.config.get("endpoint") or "https://api.security.microsoft.com").rstrip("/")

    def _token(self) -> str:
        if self._client is not None and hasattr(self._client, "get_token"):
            return str(self._client.get_token())
        tenant = self._cred("tenant_id", "tenant")
        client_id = self._cred("client_id", "clientId")
        secret = self._cred("client_secret", "clientSecret", "secret")
        import httpx

        http = self._client if hasattr(self._client, "post") else httpx.Client(timeout=30)
        resp = http.post(
            f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
            data={"grant_type": "client_credentials", "client_id": client_id,
                  "client_secret": secret, "scope": "https://api.security.microsoft.com/.default"})
        self.track_call()
        resp.raise_for_status()
        return str(resp.json().get("access_token", ""))

    def _headers(self) -> dict[str, str]:
        token = self._cred("bearer_token", "token") or ""
        if not token:
            token = self._token()
        return {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    def validate_configuration(self) -> tuple[bool, str]:
        if self._cred("bearer_token", "token"):
            return True, "ok"
        missing = [k for k in ("tenant_id", "client_id", "client_secret")
                   if not self._cred(k, k.replace("_", ""), "secret" if k == "client_secret" else k)]
        if missing:
            return False, f"msdefender missing: {', '.join(missing)} (or bearer_token)"
        return True, "ok"

    def authenticate(self) -> EngineResult:
        ok, reason = self.validate_configuration()
        if not ok:
            return self._fail(reason, ScanLifecycle.AUTH_FAILED, auth=True)
        try:
            headers = self._headers()
            if "REDACTED" in headers.get("Authorization", "") and not self._cred("bearer_token", "token"):
                pass
            client = self.client() if not hasattr(self._client, "get_token") else _HttpShim(self._client)
            resp = client.get(f"{self._base()}/api/vulnerabilities/machinesVulnerabilities",
                              params={"$top": 1}, headers=headers)
            self.track_call()
            if resp.status_code == 401:
                return self._fail("msdefender token rejected (401)", ScanLifecycle.AUTH_FAILED, auth=True)
            if resp.status_code == 429:
                return self._fail("msdefender rate limited", ScanLifecycle.RATE_LIMITED, rate=True)
            if resp.status_code >= 400:
                return self._fail(f"msdefender auth check HTTP {resp.status_code}", ScanLifecycle.UNAVAILABLE)
            return EngineResult(ok=True, status=ScanLifecycle.READY, message="msdefender authenticated")
        except Exception as exc:
            return self._fail(f"msdefender auth error: {exc}", ScanLifecycle.UNAVAILABLE)

    def health_check(self) -> EngineHealth:
        ok, _ = self.validate_configuration()
        if not ok:
            return EngineHealth.NOT_CONFIGURED
        try:
            headers = self._headers()
            client = self.client() if not hasattr(self._client, "get_token") else _HttpShim(self._client)
            resp = client.get(f"{self._base()}/api/vulnerabilities/machinesVulnerabilities",
                              params={"$top": 1}, headers=headers)
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
            EngineCapability(capability_id="vulnerability_intelligence",
                             label="Vulnerability observations",
                             description="Affected machines/assets + severity context"),
            EngineCapability(capability_id="recommendations", label="Security recommendations"),
        ]

    def supports_scan_lifecycle(self) -> bool:
        return False

    def create_scan(self, target: str, context: dict[str, Any] | None = None) -> ScanHandle:  # noqa: ARG002
        return ScanHandle(status=ScanLifecycle.NOT_APPLICABLE,
                          detail="defender vulnerability management does not expose a network scan lifecycle")

    def launch_scan(self, provider_scan_id: str) -> ScanHandle:
        return ScanHandle(provider_scan_id=provider_scan_id, status=ScanLifecycle.NOT_APPLICABLE,
                          detail="defender vulnerability management does not expose a network scan lifecycle")

    def get_status(self, provider_scan_id: str) -> ScanHandle:
        return ScanHandle(provider_scan_id=provider_scan_id, status=ScanLifecycle.NOT_APPLICABLE,
                          detail="intelligence connector: pull observations via get_results")

    def get_results(self, provider_scan_id: str = "") -> list[dict[str, Any]]:  # noqa: ARG002
        headers = self._headers()
        client = self.client() if not hasattr(self._client, "get_token") else _HttpShim(self._client)
        out: list[dict[str, Any]] = []
        for path in ("/api/vulnerabilities/machinesVulnerabilities", "/api/vulnerabilities"):
            resp = client.get(f"{self._base()}{path}", headers=headers)
            self.track_call()
            if resp.status_code in (401, 429):
                raise RuntimeError(f"msdefender {path} HTTP {resp.status_code}")
            if resp.status_code == 404:
                continue
            resp.raise_for_status()
            payload = resp.json()
            items = payload.get("value", payload) if isinstance(payload, dict) else payload
            if isinstance(items, list):
                out.extend(items)
        # recommendations enrich context
        try:
            rresp = client.get(f"{self._base()}/api/recommendations", headers=headers)
            self.track_call()
            if rresp.status_code == 200:
                payload = rresp.json()
                items = payload.get("value", []) if isinstance(payload, dict) else []
                for rec in items if isinstance(items, list) else []:
                    out.append({"_recommendation": rec})
        except Exception:
            pass
        return out

    def normalize_results(self, raw: list[dict[str, Any]], target: str = "") -> list[NormalizedExternalFinding]:
        findings: list[NormalizedExternalFinding] = []
        now = datetime.now(timezone.utc)
        for item in raw:
            if "_recommendation" in item:
                rec = item["_recommendation"] if isinstance(item["_recommendation"], dict) else {}
                findings.append(NormalizedExternalFinding(
                    finding_id=f"msdefender-rec-{rec.get('id', rec.get('productName', 'x'))}",
                    provider="msdefender", source_product=PRODUCT,
                    source_finding_id=str(rec.get("id", "")),
                    asset=target, title=str(rec.get("recommendationName", rec.get("productName", "recommendation"))),
                    description=str(rec.get("recommendationCategory", "")),
                    severity=normalize_severity(rec.get("severity", "info")),
                    remediation=str(rec.get("remediationSteps", "")),
                    evidence=[f"defender recommendation {rec.get('id', '?')}"],
                    first_seen=now, last_seen=now, scan_timestamp=now,
                    deployment_type=DeploymentType.CLOUD.value,
                    provenance="defender recommendation intelligence", raw=dict(item)))
                continue
            cve = str(item.get("cveId", item.get("cve", ""))).upper()
            cves = [cve] if cve else extract_cves(str(item.get("name", "")), str(item.get("description", "")))
            cwes = extract_cwes(str(item.get("description", "")))
            try:
                cvss = float(item.get("cvssScore", item.get("cvss", "") or 0)) or None
            except (TypeError, ValueError):
                cvss = None
            asset = str(item.get("machineId", item.get("deviceName", item.get("asset", target))))
            findings.append(NormalizedExternalFinding(
                finding_id=f"msdefender-{cve or item.get('id', 'x')}-{asset}",
                provider="msdefender", source_product=PRODUCT,
                source_finding_id=str(item.get("id", cve)),
                asset=asset, hostname=str(item.get("deviceName", "")),
                product=str(item.get("productName", item.get("product", ""))),
                version=str(item.get("productVersion", "")),
                cves=cves, cwes=cwes,
                severity=normalize_severity(item.get("severity", "info"), cvss), cvss=cvss,
                title=str(item.get("name", cve or "defender vulnerability")),
                description=str(item.get("description", "")),
                evidence=[f"defender observes {cve or 'vuln'} on {asset}"],
                first_seen=now, last_seen=now, scan_timestamp=now,
                scanner_state="active",
                remediation=str(item.get("fixingKbId", "")),
                references=[], deployment_type=DeploymentType.CLOUD.value,
                provenance="defender vulnerability intelligence", raw=dict(item)))
        return findings


class _HttpShim:
    """Adapt token-double clients to the httpx surface used above."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner

    def get(self, *args: Any, **kwargs: Any) -> Any:
        return self._inner.get(*args, **kwargs)

    def post(self, *args: Any, **kwargs: Any) -> Any:
        return self._inner.post(*args, **kwargs)
