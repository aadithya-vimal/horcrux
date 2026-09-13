from __future__ import annotations

import httpx
from horcrux.models import AuditStatus, DiscoveredPath, ValidationState
from horcrux.modules.web.validator import (
    BaselineFingerprint,
    validate_directory_listing,
    validate_env_content,
    validate_generic_candidate,
)
from horcrux.modules.web.wordlists import resolve_wordlist


def test_wordlist_resolution_fallback():
    # Calling with empty custom path returns a valid file path and records fallback or preferred
    path, is_fallback, msg = resolve_wordlist("quickhits")
    assert path.exists()
    assert len(msg) > 0


def test_discovered_path_model():
    p = DiscoveredPath(
        url="http://10.0.0.1:80/admin",
        path="/admin",
        status=200,
        size=1520,
        source="ffuf",
    )
    assert p.path == "/admin"
    assert p.status == 200
    assert p.size == 1520
    assert p.validated is False
    assert p.validation_state == ValidationState.unverified


def test_soft_404_and_baseline_suppression():
    # Baseline for a custom 404 handler returning 200 OK HTML
    baseline_request = httpx.Request("GET", "http://10.0.0.1/_horcrux_baseline_123")
    baseline_resp = httpx.Response(
        200,
        request=baseline_request,
        text="<html><head><title>Custom Error Page</title></head><body>Nothing here!</body></html>",
        headers={"Content-Type": "text/html; charset=utf-8"},
    )
    baseline = BaselineFingerprint.analyze(baseline_resp)

    # A fuzzing tool discovers /backup returning identical soft-404 HTML
    candidate_request = httpx.Request("GET", "http://10.0.0.1/backup")
    candidate_resp = httpx.Response(
        200,
        request=candidate_request,
        text="<html><head><title>Custom Error Page</title></head><body>Nothing here!</body></html>",
        headers={"Content-Type": "text/html; charset=utf-8"},
    )

    result = validate_generic_candidate("/backup", candidate_resp, baseline)
    assert result.is_valid is False
    assert result.validation_state == ValidationState.false_positive
    assert result.audit_status == AuditStatus.hardened
    assert "Suppressed" in result.evidence[0]


def test_real_env_vs_fake_env_validation():
    # Baseline 404
    base_req = httpx.Request("GET", "http://10.0.0.1/404")
    base_resp = httpx.Response(404, request=base_req, text="Not Found")
    baseline = BaselineFingerprint.analyze(base_resp)

    # Real .env file with KEY=VALUE pairs
    real_env_req = httpx.Request("GET", "http://10.0.0.1/.env")
    real_env_resp = httpx.Response(
        200,
        request=real_env_req,
        text="APP_ENV=production\nDB_HOST=127.0.0.1\nDB_PASSWORD=SuperSecretPass123\nAWS_SECRET_KEY=AKIAIOSFODNN7EXAMPLE\n",
        headers={"Content-Type": "text/plain"},
    )
    result_real = validate_env_content(real_env_resp, baseline)
    assert result_real.is_valid is True
    assert result_real.validation_state == ValidationState.confirmed
    assert result_real.confidence >= 0.95

    # Fake .env returning 200 with HTML generic page (e.g. SPA index)
    fake_env_req = httpx.Request("GET", "http://10.0.0.1/.env")
    fake_env_resp = httpx.Response(
        200,
        request=fake_env_req,
        text="<!DOCTYPE html><html><head><title>Welcome to React App</title></head><body><div id='root'></div></body></html>",
        headers={"Content-Type": "text/html"},
    )
    result_fake = validate_env_content(fake_env_resp, baseline)
    assert result_fake.is_valid is False
    assert result_fake.validation_state == ValidationState.false_positive


def test_directory_listing_validation():
    base_req = httpx.Request("GET", "http://10.0.0.1/404")
    base_resp = httpx.Response(404, request=base_req, text="Not Found")
    baseline = BaselineFingerprint.analyze(base_resp)

    dir_req = httpx.Request("GET", "http://10.0.0.1/uploads/")
    dir_resp = httpx.Response(
        200,
        request=dir_req,
        text="<html><head><title>Index of /uploads</title></head><body><h1>Index of /uploads</h1><hr><pre><a href='../'>Parent Directory</a> <a href='file.txt'>file.txt</a></pre></body></html>",
        headers={"Content-Type": "text/html"},
    )
    res = validate_directory_listing(dir_resp, baseline)
    assert res.is_valid is True
    assert res.validation_state == ValidationState.confirmed
    assert "Directory indexing" in res.evidence[0]
