"""Qualys VMDR adapter.

Product: Qualys Vulnerability Management, Detection and Response (VMDR).
API: Qualys VM API v2 (per-POD base, e.g. https://qualysapi.qualys.com).
Auth: Qualys account credentials (HTTP Basic / session login); API returns XML.
Docs verified: 2026-09 (Qualys API v2 user guide, VM scan + asset/detection APIs).

Supported: authenticate, health, scan launch/list/status/cancel,
detection (result) retrieval, normalization.
Limits: scan launch is asynchronous; result retrieval polls detections;
request throttling/concurrency limits honored via 429/rate handling.
"""

from __future__ import annotations

import base64
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

PRODUCT = "Qualys VMDR"
API_VERSION = "Qualys VM API v2"
DOCS_URL = "https://www.qualys.com/docs/qualys-api-v2-user-guide.pdf"


def _text(node: ET.Element | None, path: str, default: str = "") -> str:
    if node is None:
        return default
    found = node.find(path)
    return (found.text or default).strip() if found is not None and found.text else default


class QualysEngine(ExternalVulnerabilityEngine):
    provider_id = "qualys"
    metadata = ProviderMetadata(
        provider_id="qualys",
        product=PRODUCT,
        api_version=API_VERSION,
        docs_verified="2026-09-14",
        docs_url=DOCS_URL,
        deployment_type=DeploymentType.CLOUD,
        endpoint="https://qualysapi.qualys.com",
        authentication_type="qualys username+password (Basic/session, XML API v2)",
        supported_asset_types=["ipv4", "hostname", "netblock"],
        supported_scan_types=["network_vulnerability", "host_assessment"],
        supported_result_formats=["xml", "json-normalized"],
        supported_operations=["authenticate", "health_check", "create_scan", "launch_scan",
                              "get_status", "get_results", "normalize_results", "import"],
        known_limitations=[
            "API base URL is POD-specific; operator must set the correct platform endpoint.",
            "Scan API is asynchronous; status must be polled.",
            "Concurrent-scan limits enforced by subscription.",
            "XML response parsing; large detection sets paginate.",
        ],
    )

    def _base(self) -> str:
        return str(self.config.get("endpoint") or "https://qualysapi.qualys.com").rstrip("/")

    def _headers(self) -> dict[str, str]:
        user = self._cred("username", "user")
        pwd = self._cred("password", "pass", "api_key")
        token = base64.b64encode(f"{user}:{pwd}".encode()).decode()
        return {"Authorization": f"Basic {token}", "X-Requested-With": "horcrux",
                "Content-Type": "application/x-www-form-urlencoded"}

    def validate_configuration(self) -> tuple[bool, str]:
        if not self._cred("username", "user"):
            return False, "qualys username not configured"
        if not self._cred("password", "pass", "api_key"):
            return False, "qualys password not configured"
        return True, "ok"

    def authenticate(self) -> EngineResult:
        ok, reason = self.validate_configuration()
        if not ok:
            return self._fail(reason, ScanLifecycle.AUTH_FAILED, auth=True)
        try:
            client = self.client()
            resp = client.post(f"{self._base()}/api/2.0/fo/scan/",
                               data={"action": "list", "state": "Running", "truncated": "true"},
                               headers=self._headers())
            self.track_call()
            return self._interpret(resp, ok_msg="qualys authenticated")
        except Exception as exc:
            return self._fail(f"qualys auth error: {exc}", ScanLifecycle.UNAVAILABLE)

    def health_check(self) -> EngineHealth:
        ok, _ = self.validate_configuration()
        if not ok:
            return EngineHealth.NOT_CONFIGURED
        try:
            client = self.client()
            resp = client.post(f"{self._base()}/api/2.0/fo/scan/",
                               data={"action": "list", "state": "Running", "truncated": "true"},
                               headers=self._headers())
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
            EngineCapability(capability_id="network_vulnerability_scanning", label="Network VM"),
            EngineCapability(capability_id="host_vulnerability_assessment", label="Host assessment"),
            EngineCapability(capability_id="result_import", label="Scan import"),
        ]

    def create_scan(self, target: str, context: dict[str, Any] | None = None) -> ScanHandle:
        ctx = context or {}
        prep = self.prepare_scan(target, ctx)
        if not prep.ok:
            return ScanHandle(status=prep.status, detail=prep.message)
        ok, reason = self.validate_configuration()
        if not ok:
            return ScanHandle(status=ScanLifecycle.NOT_CONFIGURED, detail=reason)
        # Qualys launch == create (scan_title + ip + option profile)
        return self.launch_scan(f"launch:{target}|{ctx.get('scan_title', '')}|{ctx.get('option_title', '')}")

    def launch_scan(self, provider_scan_id: str) -> ScanHandle:
        try:
            target, title, option = self._split_launch_id(provider_scan_id)
            client = self.client()
            data = {"action": "launch", "scan_title": title or f"horcrux-{target}",
                    "ip": target, "iscanner_name": str(self.config.get("scanner", "External"))}
            if option:
                data["option_title"] = option
            resp = client.post(f"{self._base()}/api/2.0/fo/scan/", data=data, headers=self._headers())
            self.track_call(scans=1)
            if resp.status_code == 401:
                return ScanHandle(provider_scan_id=provider_scan_id, status=ScanLifecycle.AUTH_FAILED,
                                  detail="qualys auth rejected")
            if resp.status_code == 429:
                return ScanHandle(provider_scan_id=provider_scan_id, status=ScanLifecycle.RATE_LIMITED,
                                  detail="qualys rate limited")
            ref = self._parse_scan_ref(resp.text)
            if not ref:
                return ScanHandle(provider_scan_id=provider_scan_id, status=ScanLifecycle.SCAN_FAILED,
                                  detail=self.safe_message(resp.text[:300]))
            return ScanHandle(provider_scan_id=ref, status=ScanLifecycle.RUNNING, detail="launched")
        except Exception as exc:
            return ScanHandle(provider_scan_id=provider_scan_id, status=ScanLifecycle.UNAVAILABLE,
                              detail=self.safe_message(str(exc)))

    def get_status(self, provider_scan_id: str) -> ScanHandle:
        try:
            client = self.client()
            resp = client.post(f"{self._base()}/api/2.0/fo/scan/",
                               data={"action": "list", "scan_ref": provider_scan_id,
                                     "show_status": "1", "truncated": "true"},
                               headers=self._headers())
            self.track_call()
            state = self._parse_scan_state(resp.text)
            mapping = {"running": ScanLifecycle.RUNNING, "paused": ScanLifecycle.RUNNING,
                       "finished": ScanLifecycle.RESULTS_AVAILABLE, "canceled": ScanLifecycle.SCAN_FAILED,
                       "error": ScanLifecycle.SCAN_FAILED, "queued": ScanLifecycle.QUEUED}
            return ScanHandle(provider_scan_id=provider_scan_id,
                              status=mapping.get(state.lower(), ScanLifecycle.RUNNING),
                              detail=state or "unknown", raw={"state": state})
        except Exception as exc:
            return ScanHandle(provider_scan_id=provider_scan_id, status=ScanLifecycle.UNAVAILABLE,
                              detail=self.safe_message(str(exc)))

    def cancel_scan(self, provider_scan_id: str) -> EngineResult:
        try:
            client = self.client()
            resp = client.post(f"{self._base()}/api/2.0/fo/scan/",
                               data={"action": "cancel", "scan_ref": provider_scan_id},
                               headers=self._headers())
            self.track_call()
            if resp.status_code != 200:
                return self._fail(f"qualys cancel HTTP {resp.status_code}", ScanLifecycle.SCAN_FAILED)
            return EngineResult(ok=True, status=ScanLifecycle.COMPLETE, message="cancelled")
        except Exception as exc:
            return self._fail(f"qualys cancel error: {exc}", ScanLifecycle.UNAVAILABLE)

    def get_results(self, provider_scan_id: str) -> list[dict[str, Any]]:
        client = self.client()
        resp = client.post(f"{self._base()}/api/2.0/fo/asset/host/vm/detection/",
                           data={"action": "list", "scan_ref": provider_scan_id,
                                 "show_results": "1", "truncated": "false"},
                           headers=self._headers())
        self.track_call()
        if resp.status_code == 429:
            raise RuntimeError("qualys rate limited (429)")
        if resp.status_code == 401:
            raise RuntimeError("qualys authentication failed (401)")
        resp.raise_for_status()
        # Fixtures may return JSON directly
        ctype = resp.headers.get("content-type", "") if hasattr(resp, "headers") else ""
        if "json" in ctype:
            try:
                payload = resp.json()
                if isinstance(payload, list):
                    return payload
                if isinstance(payload, dict) and isinstance(payload.get("detections"), list):
                    return payload["detections"]
            except Exception:
                pass
        return self._parse_detections(resp.text)

    def normalize_results(self, raw: list[dict[str, Any]], target: str = "") -> list[NormalizedExternalFinding]:
        findings: list[NormalizedExternalFinding] = []
        now = datetime.now(timezone.utc)
        for item in raw:
            qid = str(item.get("qid", item.get("QID", "")))
            title = str(item.get("title", item.get("vuln_title", f"qualys QID {qid}")))
            cves = extract_cves(str(item.get("cves", "")), title, str(item.get("diagnosis", "")))
            for extra in item.get("cve_list", []) or []:
                c = str(extra).upper()
                if c and c not in cves:
                    cves.append(c)
            cwes = extract_cwes(str(item.get("diagnosis", "")))
            try:
                cvss = float(item.get("cvss", item.get("cvss_base", "")) or 0) or None
            except (TypeError, ValueError):
                cvss = None
            asset = str(item.get("ip", item.get("asset", item.get("host", target))))
            try:
                port = int(item.get("port")) if str(item.get("port", "")) not in ("", "None") else None
            except (TypeError, ValueError):
                port = None
            findings.append(NormalizedExternalFinding(
                finding_id=f"qualys-{qid}-{asset}-{port or 'na'}",
                provider="qualys", source_product=PRODUCT, source_finding_id=qid,
                asset=asset, hostname=str(item.get("dns", item.get("hostname", ""))),
                port=port, service=str(item.get("service", "")), protocol=str(item.get("protocol", "tcp")),
                product=str(item.get("software", "")), cves=cves, cwes=cwes,
                severity=normalize_severity(item.get("severity", "info"), cvss), cvss=cvss,
                title=title, description=str(item.get("diagnosis", item.get("consequence", ""))),
                evidence=[f"qualys QID {qid}: {title}"],
                first_seen=now, last_seen=now, scan_timestamp=now,
                scanner_state=str(item.get("status", "active")),
                remediation=str(item.get("solution", "")),
                references=[], deployment_type=DeploymentType.CLOUD.value,
                provenance="qualys scan live result", raw=dict(item)))
        return findings

    # -- internals -----------------------------------------------------
    def _interpret(self, resp: Any, ok_msg: str) -> EngineResult:
        if resp.status_code == 401:
            return self._fail("qualys authentication rejected (401)", ScanLifecycle.AUTH_FAILED, auth=True)
        if resp.status_code == 429:
            return self._fail("qualys rate limited", ScanLifecycle.RATE_LIMITED, rate=True)
        if resp.status_code >= 400:
            return self._fail(f"qualys HTTP {resp.status_code}", ScanLifecycle.UNAVAILABLE)
        if "INVALID" in (resp.text or "").upper() and "LOGIN" in (resp.text or "").upper():
            return self._fail("qualys credentials rejected", ScanLifecycle.AUTH_FAILED, auth=True)
        return EngineResult(ok=True, status=ScanLifecycle.READY, message=ok_msg)

    @staticmethod
    def _split_launch_id(scan_id: str) -> tuple[str, str, str]:
        if scan_id.startswith("launch:"):
            parts = scan_id[len("launch:"):].split("|")
            return (parts[0] if len(parts) > 0 else "", parts[1] if len(parts) > 1 else "",
                    parts[2] if len(parts) > 2 else "")
        return scan_id, "", ""

    @staticmethod
    def _parse_scan_ref(xml_text: str) -> str:
        try:
            root = ET.fromstring(xml_text)
            for elem in root.iter():
                if elem.tag in ("SCAN_REF", "scan_ref", "ID") and elem.text:
                    return elem.text.strip()
            # JSON fixture fallback
            import json
            try:
                payload = json.loads(xml_text)
                return str(payload.get("scan_ref", payload.get("id", "")))
            except Exception:
                return ""
        except ET.ParseError:
            return ""

    @staticmethod
    def _parse_scan_state(xml_text: str) -> str:
        try:
            root = ET.fromstring(xml_text)
            for elem in root.iter():
                if elem.tag in ("STATE", "STATUS") and elem.text:
                    return elem.text.strip()
        except ET.ParseError:
            pass
        return ""

    @staticmethod
    def _parse_detections(xml_text: str) -> list[dict[str, Any]]:
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return []
        out: list[dict[str, Any]] = []
        hosts = list(root.iter("HOST"))
        if hosts:
            for host in hosts:
                ip = _text(host, "IP") or _text(host, "IP_ADDRESS")
                dns = _text(host, "DNS") or _text(host, "DNS_DATA")
                for det in host.iter("DETECTION"):
                    out.append({
                        "ip": ip, "dns": dns,
                        "qid": _text(det, "QID"),
                        "title": _text(det, "TITLE"),
                        "severity": _text(det, "SEVERITY"),
                        "port": _text(det, "PORT"),
                        "protocol": _text(det, "PROTOCOL", "tcp"),
                        "diagnosis": _text(det, "DIAGNOSIS"),
                        "solution": _text(det, "SOLUTION"),
                        "status": _text(det, "STATUS", "active"),
                    })
            return out
        for det in root.iter("DETECTION"):
            out.append({
                "qid": _text(det, "QID"),
                "title": _text(det, "TITLE"),
                "severity": _text(det, "SEVERITY"),
                "port": _text(det, "PORT"),
                "protocol": _text(det, "PROTOCOL", "tcp"),
                "diagnosis": _text(det, "DIAGNOSIS"),
                "consequence": _text(det, "CONSEQUENCE"),
                "solution": _text(det, "SOLUTION"),
                "status": _text(det, "STATUS", "active"),
            })
        return out
