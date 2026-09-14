"""Settings / coverage / readiness integration for the engine fabric."""

from __future__ import annotations

from horcrux.core.settings import SettingsManager


def _mgr(tmp_path):
    return SettingsManager(config_dir=tmp_path, use_keyring=False)


def test_vuln_credentials_roundtrip_and_removal(tmp_path):
    mgr = _mgr(tmp_path)
    mgr.set_vuln_credentials("tenable", {"access_key": "AK", "secret_key": "SK"})
    creds = mgr.get_vuln_credentials("tenable")
    assert creds == {"access_key": "AK", "secret_key": "SK"}
    assert mgr.is_vuln_configured("tenable")
    assert not mgr.is_vuln_configured("qualys")
    masked = mgr.masked_vuln_credentials("tenable")
    assert "AK" not in str(masked.values())
    mgr.remove_vuln_config("tenable")
    assert not mgr.is_vuln_configured("tenable")


def test_vuln_endpoint_enable_and_env_fallback(tmp_path, monkeypatch):
    mgr = _mgr(tmp_path)
    mgr.set_vuln_endpoint("qualys", "https://qualysapi.qg2.apps.qualys.com")
    assert mgr.get_vuln_engine_config("qualys")["endpoint"] == "https://qualysapi.qg2.apps.qualys.com"
    mgr.set_vuln_enabled("qualys", False)
    assert mgr.get_vuln_engine_config("qualys")["enabled"] is False

    monkeypatch.setenv("GREENBONE_USERNAME", "admin")
    monkeypatch.setenv("GREENBONE_PASSWORD", "pw")
    assert mgr.is_vuln_configured("greenbone")
    assert mgr.get_vuln_credential_source("greenbone", "username").startswith("environment")


def test_settings_persistence_keeps_vuln_config(tmp_path):
    mgr = _mgr(tmp_path)
    mgr.set_vuln_endpoint("rapid7", "https://insightvm:3780")
    mgr.set_vuln_credentials("rapid7", {"username": "u", "password": "p"})
    mgr2 = SettingsManager(config_dir=tmp_path, use_keyring=False)
    assert mgr2.get_vuln_engine_config("rapid7")["endpoint"] == "https://insightvm:3780"
    assert mgr2.is_vuln_configured("rapid7")


def test_readiness_audit_marks_unconfigured(tmp_path):
    from horcrux.intel.vuln_engines.orchestrator import readiness_audit

    mgr = _mgr(tmp_path)
    audit = readiness_audit(mgr, check_health=False)
    assert {r.provider_id for r in audit} == {"tenable", "qualys", "rapid7", "greenbone", "msdefender"}
    assert all(r.health.value == "NOT_CONFIGURED" for r in audit)
    assert all(not r.configured for r in audit)


def test_coverage_engine_dimensions_and_verdict():
    from horcrux.intel.coverage import SecurityCoverageModel

    cov = SecurityCoverageModel()
    cov.ensure_properties()
    for pid in ("vuln.external_intel", "vuln.network_scanning", "vuln.host_assessment",
                "vuln.config_assessment", "vuln.credentialed_assessment", "vuln.web_scanning"):
        assert pid in cov.properties
    assert cov.engine_coverage_verdict() == "NOT_ASSESSED"
    cov.set_engine_state("tenable", "COMPLETE")
    cov.set_engine_state("qualys", "NOT_CONFIGURED")
    assert cov.engine_coverage_verdict() == "PARTIAL"
    summary = cov.engine_coverage_summary()
    assert summary["executed"] == 1 and summary["not_configured"] == 1


def test_missing_engine_yields_limited_and_qualified_language(tmp_path):
    from horcrux.core.storage import Workspace
    from horcrux.intel.coverage import assessment_completeness
    from horcrux.intel.vuln_engines.orchestrator import coverage_warning_text, readiness_audit

    mgr = _mgr(tmp_path)
    audit = readiness_audit(mgr, check_health=False)
    warning = coverage_warning_text(audit)
    assert "LIMITED" in warning
    assert "NOT COMPREHENSIVE" in warning

    ws = Workspace("vuln-cov-test", base=str(tmp_path / "ws"))
    state = ws.load()
    comp = assessment_completeness(state)
    assert "external_engine_verdict" in comp
    assert "external_engines_not_configured" in comp
    assert "tenable" in comp["external_engines_not_configured"]


def test_operator_excluded_reported_distinctly():
    from horcrux.intel.vuln_engines.selector import select_engines
    from horcrux.intel.vuln_engines.types import EngineHealth, EngineReadiness

    ready = EngineReadiness(provider_id="tenable", product="Tenable", configured=True,
                            enabled=True, health=EngineHealth.HEALTHY,
                            capabilities=["network_vulnerability_scanning"])
    sel = select_engines([ready], profile="deep", operator_exclude=["tenable"])
    assert sel[0].mode == "skipped"
    assert "operator excluded" in sel[0].skip_reason


def test_skipped_states_never_conflate_not_configured(tmp_path):
    """NOT_CONFIGURED ≠ OPERATOR_EXCLUDED ≠ NOT_APPLICABLE end to end."""
    from horcrux.core.storage import Workspace
    from horcrux.intel.vuln_engines.orchestrator import execute_selection, readiness_audit
    from horcrux.intel.vuln_engines.selector import select_engines

    mgr = _mgr(tmp_path)  # nothing configured
    ws = Workspace("vuln-states", base=str(tmp_path / "ws"))
    audit = readiness_audit(mgr, check_health=False)
    selection = select_engines(audit, profile="deep")
    assert all(s.mode == "skipped" for s in selection)
    result = execute_selection(ws, "10.0.0.1", selection, audit, mgr)
    assert all(r["status"] == "NOT_CONFIGURED" for r in result["runs"].values())
    state = ws.load()
    cov = state.get_security_coverage()
    assert cov.engine_coverage_verdict() == "LIMITED"
    assert all(v == "NOT_CONFIGURED" for v in cov.external_engines.values())

    # operator exclusion is a different state, not a missing credential
    selection2 = select_engines(audit, profile="deep", operator_exclude=["tenable"])
    result2 = execute_selection(ws, "10.0.0.1", selection2, audit, mgr)
    assert result2["runs"]["tenable"]["status"] == "OPERATOR_EXCLUDED"
    state2 = ws.load()
    assert state2.external_engine_runs["tenable"]["status"] == "OPERATOR_EXCLUDED"
