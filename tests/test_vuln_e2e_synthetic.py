"""Synthetic multi-provider E2E: native + Tenable + Qualys + Rapid7.

provider results → normalized observations → deduplicated entities →
service correlation → attack-path update → report with LIMITED discipline.
"""

from __future__ import annotations

from datetime import datetime, timezone

import httpx

from horcrux.core.settings import SettingsManager
from horcrux.core.storage import Workspace
from horcrux.intel.vuln_engines.orchestrator import execute_selection, readiness_audit
from horcrux.intel.vuln_engines.selector import select_engines
from horcrux.intel.vuln_engines.types import EngineReadiness, SelectedEngine
from horcrux.models import Service, Software


def _client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def _tenable(request: httpx.Request) -> httpx.Response:
    p = request.url.path
    if p == "/scans" and request.method == "POST":
        return httpx.Response(200, json={"scan": {"id": 1}}, request=request)
    if p in ("/session", "/scans"):
        return httpx.Response(200, json={"scans": []}, request=request)
    if p == "/editor/scan/templates":
        return httpx.Response(200, json={"templates": [{"name": "Basic", "uuid": "t1"}]}, request=request)
    if p == "/scans/1/launch":
        return httpx.Response(200, json={}, request=request)
    if p == "/scans/1":
        return httpx.Response(200, json={"info": {"status": "completed"}}, request=request)
    if p == "/scans/1/hosts":
        return httpx.Response(200, json={"hosts": [{"host_id": 1, "host-ip": "10.9.9.9"}]}, request=request)
    if p == "/scans/1/hosts/1":
        return httpx.Response(200, json={"vulnerabilities": [
            {"plugin_id": "100", "plugin_name": "Apache CVE-2021-41773", "cve": "CVE-2021-41773",
             "severity": 3, "port": 80, "host-ip": "10.9.9.9", "cvss3_base_score": 7.5,
             "product": "Apache httpd", "plugin_family": "Web Servers",
             "description": "traversal", "solution": "upgrade"}]},
            request=request)
    return httpx.Response(404, json={}, request=request)


def _qualys(request: httpx.Request) -> httpx.Response:
    body = request.content.decode()
    if "vm/detection" in request.url.path:
        return httpx.Response(200, text=(
            "<OUT><HOST><IP>10.9.9.9</IP><DETECTION_LIST><DETECTION>"
            "<QID>200</QID><TITLE>Apache CVE-2021-41773</TITLE><SEVERITY>4</SEVERITY>"
            "<PORT>80</PORT><DIAGNOSIS>CVE-2021-41773</DIAGNOSIS>"
            "<SOLUTION>patch</SOLUTION></DETECTION></DETECTION_LIST></HOST></OUT>"),
            headers={"content-type": "text/xml"}, request=request)
    if "launch" in body:
        return httpx.Response(200, text="<SCAN><SCAN_REF>scan/9</SCAN_REF></SCAN>",
                              headers={"content-type": "text/xml"}, request=request)
    if "show_status" in body:
        return httpx.Response(200, text="<L><SCAN><STATE>Finished</STATE></SCAN></L>",
                              headers={"content-type": "text/xml"}, request=request)
    return httpx.Response(200, text="<L></L>", headers={"content-type": "text/xml"}, request=request)


def _rapid7(request: httpx.Request) -> httpx.Response:
    p = request.url.path
    if p == "/api/3/sites/3/scans" and request.method == "POST":
        return httpx.Response(201, json={"id": 3}, request=request)
    if p == "/api/3/scans/3":
        return httpx.Response(200, json={"status": "finished"}, request=request)
    if p == "/api/3/scans/3/vulnerabilities":
        return httpx.Response(200, json={"resources": [
            {"vulnerability": {"id": "r1", "title": "Apache CVE-2021-41773",
                               "description": "CVE-2021-41773", "severity": "High",
                               "cvssScore": 7.5, "product": "Apache httpd"},
             "asset": "10.9.9.9", "port": 80}]}, request=request)
    return httpx.Response(200, json={"resources": []}, request=request)


def _mgr(tmp_path):
    mgr = SettingsManager(config_dir=tmp_path, use_keyring=False)
    mgr.set_vuln_credentials("tenable", {"access_key": "A", "secret_key": "S"})
    mgr.set_vuln_credentials("qualys", {"username": "u", "password": "p"})
    mgr.set_vuln_credentials("rapid7", {"username": "u", "password": "p"})
    mgr.set_vuln_engine_fields("rapid7", {"site_id": "3"})
    return mgr


def test_synthetic_multi_provider_e2e(tmp_path):
    mgr = _mgr(tmp_path)
    ws = Workspace("e2e-synth", base=str(tmp_path / "ws"))
    state = ws.load()
    state.services = [Service(host="10.9.9.9", port=80, protocol="tcp", service="http",
                              product="Apache httpd", version="2.4.49")]
    state.software = [Software(product="Apache httpd", version="2.4.49", service="http",
                               source="nmap", confidence=0.9)]
    ws.save(state)

    clients = {"tenable": _client(_tenable), "qualys": _client(_qualys), "rapid7": _client(_rapid7)}
    audit = readiness_audit(mgr, check_health=False)
    assert sum(1 for r in audit if r.configured) >= 3
    selection = select_engines(audit, profile="deep", engine_mode="all")
    selected_ids = sorted(s.provider_id for s in selection if s.mode == "selected")
    assert {"tenable", "qualys", "rapid7"} <= set(selected_ids)

    result = execute_selection(ws, "10.9.9.9", selection, audit, mgr,
                               client_factory=lambda pid: clients.get(pid))
    assert result["findings"] >= 3  # one per provider minimum
    # duplicated CVE across three providers → single entity with three sources
    state = ws.load()
    entities = list(state.correlated_vulnerabilities or [])
    cve_entities = [e for e in entities if "CVE-2021-41773" in (e.get("cves", []) or [])]
    assert len(cve_entities) == 1, f"expected 1 deduped entity, got {len(cve_entities)}"
    entity = cve_entities[0]
    assert sorted(entity["sources"]) == ["qualys", "rapid7", "tenable"]
    assert entity["asset"] == "10.9.9.9"
    # correlated with native Apache evidence → CORROBORATED, not auto-CONFIRMED vuln
    assert entity["disposition"] == "CORROBORATED"
    # attack paths gained an evidence-labeled external path
    assert any("External vuln path" in (p.get("name", "")) for p in (state.attack_paths or []))
    # evidence model carries observations
    assert any(getattr(o, "source_tool", "").startswith("vuln:") for o in state.raw_observations)
    # coverage reflects executed engines
    cov = state.get_security_coverage()
    assert cov.get_engine_state("tenable") == "COMPLETE"
    # provider scan IDs persisted (assessment ↔ scan mapping)
    assert state.external_engine_runs["tenable"].get("provider_scan_id") == "1"


def test_import_mode_marked_imported(tmp_path):
    from horcrux.intel.vuln_engines.importers import import_nessus_xml

    nessus = tmp_path / "scan.nessus"
    nessus.write_text(
        '<?xml version="1.0"?><NessusClientData_v2><Report name="t">'
        '<ReportHost name="10.1.1.1"><HostProperties>'
        '<tag name="host-fqdn">web.local</tag></HostProperties>'
        '<ReportItem port="443" svc_name="https" protocol="tcp" severity="3" '
        'pluginID="20001" pluginName="Apache CVE-2020-1234">'
        '<description>details CVE-2020-1234</description>'
        '<solution>upgrade</solution><cve>CVE-2020-1234</cve>'
        '</ReportItem></ReportHost></Report></NessusClientData_v2>',
        encoding="utf-8")
    findings = import_nessus_xml(nessus)
    assert len(findings) == 1
    assert findings[0].imported is True
    assert findings[0].deployment_type == "IMPORTED_RESULT"
    assert findings[0].cves == ["CVE-2020-1234"]
    assert "imported" in findings[0].provenance


def test_report_never_claims_secure_when_engines_missing(tmp_path):
    from horcrux.reporting.reports import markdown

    ws = Workspace("e2e-report", base=str(tmp_path / "ws"))
    state = ws.load()
    ws.save(state)
    out = markdown(ws)
    content = out.read_text(encoding="utf-8")
    assert "Vulnerability Engine Coverage" in content
    assert "Results from unavailable engines are not represented as negative evidence." in content
    assert "No confirmed vulnerabilities identified within the assessed scope" in content
    assert "Target secure" not in content


def test_provider_failure_does_not_crash_assessment(tmp_path):
    mgr = _mgr(tmp_path)

    def boom(request):
        raise httpx.ConnectError("no route", request=request)

    ws = Workspace("e2e-fail", base=str(tmp_path / "ws"))
    audit = readiness_audit(mgr, check_health=False)
    selection = [SelectedEngine(provider_id="tenable", reason="test"),
                 SelectedEngine(provider_id="greenbone", reason="test")]
    result = execute_selection(ws, "10.0.0.1", selection, audit, mgr,
                               client_factory=lambda pid: _client(boom))
    assert "tenable" in result["runs"]
    state = ws.load()
    assert state.external_engine_runs["tenable"]["status"] in (
        "FAILED", "UNAVAILABLE", "RESULT_RETRIEVAL_FAILED", "AUTH_FAILED",
        "SCAN_FAILED", "RATE_LIMITED", "RUNNING", "QUEUED", "READY")


def test_profile_gating_quick_skips_engines(tmp_path):
    from horcrux.intel.vuln_engines.selector import select_engines

    mgr = _mgr(tmp_path)
    audit = readiness_audit(mgr, check_health=False)
    sel = select_engines(audit, profile="quick")
    assert all(s.mode == "skipped" for s in sel)
    sel_full = select_engines(audit, profile="full", engine_mode="all")
    assert any(s.mode == "selected" for s in sel_full)
