"""Provider-contract tests — mocked transports only. No live cloud calls."""

from __future__ import annotations

import httpx

from horcrux.intel.vuln_engines.registry import get_engine
from horcrux.intel.vuln_engines.types import EngineHealth, ScanLifecycle


def _mock_client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


# ── Tenable ──────────────────────────────────────────────────────────────
def _tenable_handler(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if path == "/session":
        return httpx.Response(200, json={"id": 1}, request=request)
    if path == "/scans" and request.method == "GET":
        params = dict(request.url.params)
        if params.get("limit") == "1":
            return httpx.Response(200, json={"scans": []}, request=request)
        return httpx.Response(200, json={"scans": [{"id": 7, "name": "other"}]}, request=request)
    if path == "/editor/scan/templates":
        return httpx.Response(200, json={"templates": [{"name": "Basic Network Scan", "uuid": "tmpl-1"}]},
                              request=request)
    if path == "/scans" and request.method == "POST":
        return httpx.Response(200, json={"scan": {"id": 42}}, request=request)
    if path == "/scans/42/launch":
        return httpx.Response(200, json={"scan_uuid": "abc"}, request=request)
    if path == "/scans/42":
        return httpx.Response(200, json={"info": {"status": "completed", "name": "horcrux-t"}}, request=request)
    if path == "/scans/42/hosts":
        return httpx.Response(200, json={"hosts": [{"host_id": 1, "hostname": "web",
                                                    "host-ip": "10.0.0.5"}]}, request=request)
    if path == "/scans/42/hosts/1":
        return httpx.Response(200, json={"vulnerabilities": [
            {"plugin_id": "104743", "plugin_name": "Apache HTTP Server CVE-2021-41773",
             "cve": "CVE-2021-41773", "severity": 4, "port": 80, "protocol": "tcp",
             "host-ip": "10.0.0.5", "cvss3_base_score": 7.5,
             "description": "path traversal", "solution": "upgrade",
             "plugin_family": "Web Servers"}]}, request=request)
    return httpx.Response(404, json={}, request=request)


def test_tenable_lifecycle_mocked():
    eng = get_engine("tenable", config={"endpoint": "https://cloud.tenable.com"},
                     credentials={"access_key": "AK", "secret_key": "SK"},
                     client=_mock_client(_tenable_handler))
    assert eng.validate_configuration() == (True, "ok")
    assert eng.authenticate().ok
    assert eng.health_check() == EngineHealth.HEALTHY
    assert any(c.capability_id == "network_vulnerability_scanning" for c in eng.capabilities())
    handle = eng.create_scan("10.0.0.5", {"scan_name": "horcrux-t"})
    assert handle.provider_scan_id == "42"
    launched = eng.launch_scan("42")
    assert launched.status == ScanLifecycle.RUNNING
    status = eng.get_status("42")
    assert status.status == ScanLifecycle.RESULTS_AVAILABLE
    raw = eng.get_results("42")
    assert len(raw) == 1
    findings = eng.normalize_results(raw, "10.0.0.5")
    assert findings[0].cves == ["CVE-2021-41773"]
    assert findings[0].severity in ("high", "critical")
    assert findings[0].deployment_type == "CLOUD"


def test_tenable_auth_failure_and_rate_limit():
    def handler_401(request):
        return httpx.Response(401, json={}, request=request)

    eng = get_engine("tenable", config={}, credentials={"access_key": "A", "secret_key": "S"},
                     client=_mock_client(handler_401))
    assert eng.health_check() == EngineHealth.AUTH_FAILED
    assert not eng.authenticate().ok

    def handler_429(request):
        return httpx.Response(429, json={}, request=request)

    eng2 = get_engine("tenable", config={}, credentials={"access_key": "A", "secret_key": "S"},
                      client=_mock_client(handler_429))
    assert eng2.health_check() == EngineHealth.RATE_LIMITED
    assert eng2.get_status("1").status == ScanLifecycle.RATE_LIMITED


def test_tenable_not_configured():
    eng = get_engine("tenable", config={}, credentials={})
    assert eng.health_check() == EngineHealth.NOT_CONFIGURED
    assert eng.create_scan("t").status == ScanLifecycle.NOT_CONFIGURED


# ── Qualys ───────────────────────────────────────────────────────────────
def _qualys_handler(request: httpx.Request) -> httpx.Response:
    body = request.content.decode()
    if "asset/host/vm/detection" in request.url.path:
        return httpx.Response(200, text=(
            "<HOST_LIST_VM_DETECTION_OUTPUT><HOST><IP>10.0.0.6</IP>"
            "<DETECTION_LIST><DETECTION><QID>150001</QID><TITLE>Apache Vuln</TITLE>"
            "<SEVERITY>4</SEVERITY><PORT>80</PORT><PROTOCOL>tcp</PROTOCOL>"
            "<DIAGNOSIS>CVE-2021-41773 present</DIAGNOSIS>"
            "<SOLUTION>patch</SOLUTION><STATUS>active</STATUS></DETECTION>"
            "</DETECTION_LIST></HOST></HOST_LIST_VM_DETECTION_OUTPUT>"),
            headers={"content-type": "text/xml"}, request=request)
    if "action=launch" in body or "action%22%3A+%22launch" in body or "launch" in body:
        return httpx.Response(200, text="<SCAN><SCAN_REF>scan/123</SCAN_REF></SCAN>",
                              headers={"content-type": "text/xml"}, request=request)
    if "show_status" in body:
        return httpx.Response(200, text="<SCAN_LIST><SCAN><STATE>Finished</STATE></SCAN></SCAN_LIST>",
                              headers={"content-type": "text/xml"}, request=request)
    return httpx.Response(200, text="<SCAN_LIST></SCAN_LIST>",
                          headers={"content-type": "text/xml"}, request=request)


def test_qualys_scan_result_failure_paths():
    eng = get_engine("qualys", config={"endpoint": "https://qualysapi.qualys.com"},
                     credentials={"username": "u", "password": "p"},
                     client=_mock_client(_qualys_handler))
    assert eng.authenticate().ok
    assert eng.health_check() == EngineHealth.HEALTHY
    handle = eng.create_scan("10.0.0.6")
    assert handle.status == ScanLifecycle.RUNNING
    assert eng.get_status(handle.provider_scan_id).status == ScanLifecycle.RESULTS_AVAILABLE
    raw = eng.get_results(handle.provider_scan_id)
    assert raw and raw[0]["qid"] == "150001"
    findings = eng.normalize_results(raw, "10.0.0.6")
    assert "CVE-2021-41773" in findings[0].cves

    def h401(request):
        return httpx.Response(401, text="unauthorized", request=request)

    eng2 = get_engine("qualys", config={}, credentials={"username": "u", "password": "bad"},
                      client=_mock_client(h401))
    assert eng2.health_check() == EngineHealth.AUTH_FAILED


# ── Rapid7 ───────────────────────────────────────────────────────────────
def _rapid7_handler(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if path == "/api/3/sites/9/scans" and request.method == "POST":
        return httpx.Response(201, json={"id": 55, "status": "running"}, request=request)
    if path == "/api/3/scans/55":
        return httpx.Response(200, json={"id": 55, "status": "finished"}, request=request)
    if path == "/api/3/scans/55/vulnerabilities":
        return httpx.Response(200, json={"resources": [
            {"id": "apache-cve", "vulnerability": {"id": "v1", "title": "Apache CVE-2021-41773",
             "description": "CVE-2021-41773", "severity": "High", "cvssScore": 7.5},
             "asset": "10.0.0.7", "port": 80, "status": "vulnerable"}]}, request=request)
    if path in ("/api/3/sites", "/api/3/administration/properties"):
        return httpx.Response(200, json={"resources": []}, request=request)
    return httpx.Response(404, json={}, request=request)


def test_rapid7_scan_and_results():
    eng = get_engine("rapid7", config={"endpoint": "https://console:3780", "site_id": "9"},
                     credentials={"username": "u", "password": "p"},
                     client=_mock_client(_rapid7_handler))
    assert eng.health_check() == EngineHealth.HEALTHY
    handle = eng.create_scan("10.0.0.7")
    assert handle.status == ScanLifecycle.READY
    launched = eng.launch_scan(handle.provider_scan_id)
    assert launched.status == ScanLifecycle.RUNNING
    assert eng.get_status("55").status == ScanLifecycle.RESULTS_AVAILABLE
    findings = eng.normalize_results(eng.get_results("55"), "10.0.0.7")
    assert findings and "CVE-2021-41773" in findings[0].cves
    assert findings[0].deployment_type == "REMOTE_SERVICE"


def test_rapid7_requires_site():
    eng = get_engine("rapid7", config={}, credentials={"username": "u", "password": "p"},
                     client=_mock_client(_rapid7_handler))
    assert eng.create_scan("t").status == ScanLifecycle.CONFIGURATION_ERROR


# ── Greenbone ────────────────────────────────────────────────────────────
class _GmpDouble:
    def __init__(self, authed=True):
        self.authed = authed
        self.calls: list[str] = []

    def authenticate(self, user, password):
        self.calls.append("auth")
        return self.authed

    def get_version(self):
        self.calls.append("version")
        return "22.6"

    def create_target(self, target, ctx):
        return "tgt-1"

    def create_task(self, target, target_id, ctx):
        return "task-1"

    def start_task(self, task_id):
        self.calls.append(f"start:{task_id}")

    def get_task_status(self, task_id):
        return "Done"

    def get_results(self, task_id):
        return [{"id": "r1", "nvt_oid": "1.3.6.1.4.1.25623.1.0.1", "name": "Apache CVE-2021-41773",
                 "host": "10.0.0.8", "port": "80/tcp", "threat": "High",
                 "description": "CVE-2021-41773", "solution": "upgrade"}]


def test_greenbone_lifecycle_mocked():
    eng = get_engine("greenbone", config={"deployment": "LOCAL_SERVICE"},
                     credentials={"username": "admin", "password": "pw"},
                     client=_GmpDouble())
    assert eng.authenticate().ok
    assert eng.health_check() == EngineHealth.HEALTHY
    handle = eng.create_scan("10.0.0.8")
    assert handle.provider_scan_id == "task-1"
    assert eng.launch_scan("task-1").status == ScanLifecycle.RUNNING
    assert eng.get_status("task-1").status == ScanLifecycle.RESULTS_AVAILABLE
    findings = eng.normalize_results(eng.get_results("task-1"), "10.0.0.8")
    assert findings[0].cves == ["CVE-2021-41773"]
    assert findings[0].deployment_type == "LOCAL_SERVICE"  # never labeled cloud


def test_greenbone_auth_failure():
    eng = get_engine("greenbone", config={}, credentials={"username": "a", "password": "b"},
                     client=_GmpDouble(authed=False))
    assert not eng.authenticate().ok


# ── Microsoft Defender ───────────────────────────────────────────────────
def _defender_handler(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if "oauth2" in path or "token" in path:
        return httpx.Response(200, json={"access_token": "tok"}, request=request)
    if "machinesVulnerabilities" in path:
        return httpx.Response(200, json={"value": [
            {"id": "v1", "cveId": "CVE-2021-41773", "machineId": "m1", "deviceName": "ws-01",
             "productName": "Apache HTTP Server", "severity": "High", "cvssScore": 7.5}]},
            request=request)
    if path.endswith("/api/vulnerabilities"):
        return httpx.Response(404, json={}, request=request)
    if "recommendations" in path:
        return httpx.Response(200, json={"value": [
            {"id": "rec1", "recommendationName": "Update Apache", "severity": "Medium"}]},
            request=request)
    return httpx.Response(404, json={}, request=request)


def test_msdefender_intel_only():
    eng = get_engine("msdefender", config={},
                     credentials={"tenant_id": "t", "client_id": "c", "client_secret": "s"},
                     client=_mock_client(_defender_handler))
    assert eng.authenticate().ok
    assert eng.health_check() == EngineHealth.HEALTHY
    # no fabricated scan lifecycle
    assert eng.create_scan("ws-01").status == ScanLifecycle.NOT_APPLICABLE
    assert eng.launch_scan("x").status == ScanLifecycle.NOT_APPLICABLE
    raw = eng.get_results("")
    vulns = [r for r in raw if "_recommendation" not in r]
    assert vulns and vulns[0]["cveId"] == "CVE-2021-41773"
    findings = eng.normalize_results(raw, "ws-01")
    assert any("CVE-2021-41773" in f.cves for f in findings)
    assert any(f.provider == "msdefender" for f in findings)


def test_provider_metadata_currency():
    for pid in ("tenable", "qualys", "rapid7", "greenbone", "msdefender"):
        eng = get_engine(pid, config={}, credentials={})
        assert eng.metadata is not None
        assert eng.metadata.docs_verified, pid
        assert eng.metadata.authentication_type, pid
        assert eng.metadata.supported_asset_types, pid
        # current naming: no stale Tenable.io product label
        if pid == "tenable":
            assert "Tenable One" in eng.metadata.product
            assert eng.metadata.product != "Tenable.io"
