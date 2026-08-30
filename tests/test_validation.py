import httpx
import pytest

from horcrux.models import ValidationState
from horcrux.modules.web.validator import (
    BaselineFingerprint,
    ValidatorRegistry,
    validate_admin_surface,
    validate_env_content,
    validate_git_head,
    validate_passwd_content,
    validate_robots_content,
)


def mock_response(status_code: int, text: str, headers: dict = None) -> httpx.Response:
    request = httpx.Request("GET", "http://target:80/dummy")
    default_headers = {"content-type": "text/html; charset=utf-8"}
    if headers:
        default_headers.update(headers)
    return httpx.Response(
        status_code=status_code,
        headers=default_headers,
        text=text,
        request=request,
    )


def test_baseline_soft404_detection():
    # Simulated soft-404 returning 200 with generic error template
    baseline_resp = mock_response(200, "<html><head><title>Page Not Found</title></head><body>Nothing here</body></html>")
    baseline = BaselineFingerprint.analyze(baseline_resp)
    assert baseline.status_code == 200

    # Another non-existent endpoint returning similar error
    test_resp = mock_response(200, "<html><head><title>Page Not Found</title></head><body>Nothing here!</body></html>")
    assert baseline.is_similar(test_resp) is True


def test_baseline_spa_fallback():
    spa_html = """<!DOCTYPE html>
    <html><head><title>App</title></head><body>
    <div id="root"></div>
    <script src="/static/bundle.js"></script>
    </body></html>"""
    baseline_resp = mock_response(200, spa_html)
    baseline = BaselineFingerprint.analyze(baseline_resp)
    assert baseline.is_spa is True

    # When /.env returns the SPA fallback, it must be detected as similar
    env_fake_resp = mock_response(200, spa_html)
    assert baseline.is_similar(env_fake_resp) is True

    # Content validator should reject it
    result = validate_env_content(env_fake_resp, baseline)
    assert result.is_valid is False
    assert result.validation_state == ValidationState.false_positive


def test_genuine_env_detection():
    normal_404 = mock_response(404, "404 Not Found")
    baseline = BaselineFingerprint.analyze(normal_404)

    real_env = """
    APP_NAME=Horcrux
    DB_HOST=127.0.0.1
    DB_PASSWORD=SuperSecretPass123!
    AWS_SECRET_KEY=AKIAIOSFODNN7EXAMPLE
    """
    env_resp = mock_response(200, real_env, headers={"content-type": "text/plain"})
    result = validate_env_content(env_resp, baseline)

    assert result.is_valid is True
    assert result.validation_state == ValidationState.confirmed
    assert result.confidence >= 0.95
    assert any("DB_PASSWORD" in ev or "APP_NAME" in ev for ev in result.evidence)


def test_fake_env_html_rejection():
    normal_404 = mock_response(404, "404 Not Found")
    baseline = BaselineFingerprint.analyze(normal_404)

    fake_html = "<html><body><h1>Error 404: Not Found</h1></body></html>"
    fake_resp = mock_response(200, fake_html, headers={"content-type": "text/html"})
    result = validate_env_content(fake_resp, baseline)

    assert result.is_valid is False
    assert result.validation_state == ValidationState.false_positive


def test_genuine_git_head():
    normal_404 = mock_response(404, "404 Not Found")
    baseline = BaselineFingerprint.analyze(normal_404)

    # Valid Git HEAD
    git_head = "ref: refs/heads/main\n"
    resp = mock_response(200, git_head, headers={"content-type": "text/plain"})
    result = validate_git_head(resp, baseline)
    assert result.is_valid is True
    assert result.validation_state == ValidationState.confirmed

    # Fake Git HEAD returning HTML
    fake_git = "<html><body><h1>Directory Listing</h1></body></html>"
    fake_resp = mock_response(200, fake_git, headers={"content-type": "text/html"})
    fake_result = validate_git_head(fake_resp, baseline)
    assert fake_result.is_valid is False
    assert fake_result.validation_state == ValidationState.false_positive


def test_genuine_passwd_detection():
    normal_404 = mock_response(404, "404 Not Found")
    baseline = BaselineFingerprint.analyze(normal_404)

    real_passwd = (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "operator:x:1000:1000:Operator,,,:/home/operator:/bin/bash\n"
    )
    resp = mock_response(200, real_passwd, headers={"content-type": "text/plain"})
    result = validate_passwd_content(resp, baseline)
    assert result.is_valid is True
    assert result.validation_state == ValidationState.confirmed
    assert "Discovered 3 valid Unix passwd" in result.evidence[0]


def test_admin_surface_verification():
    normal_404 = mock_response(404, "404 Not Found")
    baseline = BaselineFingerprint.analyze(normal_404)

    # Generic 200 without admin indicators -> false positive
    generic_200 = mock_response(200, "<html><body><h1>Welcome to our shop!</h1></body></html>")
    result_generic = validate_admin_surface(generic_200, baseline)
    assert result_generic.is_valid is False

    # Real admin interface
    admin_html = "<html><head><title>Admin Control Panel</title></head><body><h1>Administrator Dashboard</h1><input type='password' name='pass'/></body></html>"
    admin_resp = mock_response(200, admin_html)
    result_admin = validate_admin_surface(admin_resp, baseline)
    assert result_admin.is_valid is True
    assert result_admin.validation_state == ValidationState.confirmed


def test_pluggable_registry():
    registry = ValidatorRegistry()
    assert registry.get("/.env") is not None
    assert registry.get("/.git/HEAD") is not None
    assert registry.get("/etc/passwd") is not None
    assert registry.get("/admin") is not None
