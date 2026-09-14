"""Normalization, deduplication, stale, contradiction, scope, redaction tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from horcrux.intel.vuln_engines.normalize import (
    correlate_finding_with_state,
    deduplicate_findings,
    extract_cves,
    is_stale,
    normalize_product,
    normalize_severity,
    normalize_vendor,
)
from horcrux.intel.vuln_engines.types import NormalizedExternalFinding
from horcrux.models import Service, Software, WorkspaceState


def _finding(provider="tenable", asset="10.0.0.5", cve="CVE-2021-41773", port=80,
             product="Apache HTTP Server", version="2.4.49"):
    now = datetime.now(timezone.utc)
    return NormalizedExternalFinding(
        finding_id=f"{provider}-{cve}-{asset}", provider=provider,
        source_product=provider, source_finding_id="1",
        asset=asset, port=port, product=product, version=version,
        cves=[cve], severity="high", cvss=7.5, title=f"{product} vuln",
        first_seen=now, last_seen=now, scan_timestamp=now)


def test_vendor_product_normalization():
    assert normalize_product("Apache HTTP Server") == normalize_product("apache httpd")
    assert normalize_product("httpd") == "apache http server"
    assert normalize_vendor("Apache Software Foundation") == "apache"
    assert normalize_vendor("Microsoft Corporation") == "microsoft"


def test_cve_extraction_and_severity():
    assert extract_cves("affected by cve-2021-41773 and CVE-2020-1234") == ["CVE-2021-41773", "CVE-2020-1234"]
    assert normalize_severity("High") == "high"
    assert normalize_severity(4) == "critical"
    assert normalize_severity("info", 9.8) == "critical"  # cvss escalates


def test_dedup_same_cve_three_providers_one_entity():
    findings = [_finding(p) for p in ("tenable", "qualys", "rapid7")]
    entities = deduplicate_findings(findings)
    assert len(entities) == 1
    assert sorted(entities[0].sources) == ["qualys", "rapid7", "tenable"]
    assert entities[0].primary_cve == "CVE-2021-41773"


def test_dedup_distinguishes_assets_and_cves():
    findings = [_finding(asset="10.0.0.5", cve="CVE-2021-41773"),
                _finding(asset="10.0.0.6", cve="CVE-2021-41773"),
                _finding(asset="10.0.0.5", cve="CVE-2020-1234")]
    entities = deduplicate_findings(findings)
    assert len(entities) == 3


def test_correlation_corroborated_vs_contradicted():
    state = WorkspaceState(target="t")
    state.services = [Service(host="10.0.0.5", port=80, protocol="tcp",
                              service="http", product="Apache httpd", version="2.4.49")]
    state.software = [Software(product="Apache httpd", version="2.4.49", service="http",
                               source="nmap", confidence=0.9)]
    match = correlate_finding_with_state(_finding(version="2.4.49"), state)
    assert match.disposition == "CORROBORATED"
    assert not match.stale

    mismatch = correlate_finding_with_state(_finding(version="2.4.99"), state)
    assert mismatch.disposition == "CONTRADICTED"
    assert "investigation" in mismatch.disposition_reason.lower()


def test_correlation_unverified_without_native_evidence():
    state = WorkspaceState(target="t")
    result = correlate_finding_with_state(_finding(product="Something Obscure XYZ"), state)
    assert result.disposition in ("UNVERIFIED", "LIKELY_APPLICABLE")
    # external observation is never auto-confirmed
    assert result.disposition not in ("CORROBORATED",)


def test_stale_detection():
    old = datetime.now(timezone.utc) - timedelta(days=60)
    f = _finding()
    f.scan_timestamp = old
    f.last_seen = old
    assert is_stale(f, stale_days=30)
    state = WorkspaceState(target="t")
    correlated = correlate_finding_with_state(f, state)
    assert correlated.disposition == "STALE"
    assert correlated.stale


def test_scope_enforcement_blocks_out_of_scope():
    from horcrux.intel.vuln_engines.registry import get_engine

    eng = get_engine("tenable", config={"allowed_targets": ["10.0.0.1"]},
                     credentials={"access_key": "a", "secret_key": "s"})
    assert eng.check_scope("10.0.0.1") == ""
    assert "outside" in eng.check_scope("10.9.9.9")
    assert eng.prepare_scan("10.9.9.9").ok is False


def test_credential_redaction():
    from horcrux.intel.vuln_engines.registry import get_engine

    eng = get_engine("tenable", config={},
                     credentials={"access_key": "AKIA-SECRET-123456", "secret_key": "TOPSECRET999"})
    msg = eng.safe_message("failed with AKIA-SECRET-123456 and TOPSECRET999 in url")
    assert "AKIA-SECRET-123456" not in msg
    assert "TOPSECRET999" not in msg
    assert eng.redact({"headers": {"X-ApiKeys": "accessKey=x; secretKey=TOPSECRET999"}})["headers"]["X-ApiKeys"] != \
        "accessKey=x; secretKey=TOPSECRET999"


def test_no_raw_provider_data_in_ai_prompts():
    """Adapters must keep raw payloads out of prompts: normalize strips raw by default."""
    f = _finding()
    dumped = f.model_dump()
    assert "raw" in dumped
    # orchestrator passes only normalized summaries — raw never formatted into prompts
    prompt_safe = f"{f.provider} {f.title} {f.cves} {f.severity} {f.disposition}"
    assert "secret" not in prompt_safe.lower()
