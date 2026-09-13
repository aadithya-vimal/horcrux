from __future__ import annotations

from horcrux.core.sanitizer import fingerprint_key, redact_secrets


def test_fingerprint_key():
    assert fingerprint_key("") == "NONE"
    assert fingerprint_key("   ") == "NONE"
    fp1 = fingerprint_key("AIzaSyFakeKey1234567890abcdef")
    assert fp1.startswith("SHA256: ")
    assert len(fp1) > 15
    # Irreversible and deterministic
    fp2 = fingerprint_key("AIzaSyFakeKey1234567890abcdef")
    assert fp1 == fp2
    assert "AIzaSy" not in fp1


def test_redact_url_query_keys():
    url1 = "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.6-flash:generateContent?key=AIzaSyB1234567890abcdef2E91"
    clean1 = redact_secrets(url1)
    assert "AIzaSyB1234567890abcdef2E91" not in clean1
    assert "key=[REDACTED]" in clean1

    url2 = "https://example.com/api?foo=bar&api_key=secret_token_12345&baz=qux"
    clean2 = redact_secrets(url2)
    assert "secret_token_12345" not in clean2
    assert "api_key=[REDACTED]" in clean2


def test_redact_headers():
    header1 = "Authorization: Bearer sk-ant-api03-abcdef123456789012345678"
    clean1 = redact_secrets(header1)
    assert "sk-ant-api03" not in clean1
    assert "Authorization: Bearer [REDACTED]" in clean1

    header2 = "x-goog-api-key: AIzaSyB1234567890abcdef2E91"
    clean2 = redact_secrets(header2)
    assert "AIzaSyB" not in clean2
    assert "x-goog-api-key: [REDACTED]" in clean2

    header3 = "x-api-key: secret_custom_key_val"
    clean3 = redact_secrets(header3)
    assert "secret_custom_key_val" not in clean3
    assert "x-api-key: [REDACTED]" in clean3


def test_redact_known_secrets():
    known_key = "AIzaSySuperSecretGoogleKey9999"
    err = f"Failed to connect using key {known_key} after 3 attempts."
    clean = redact_secrets(err, extra_secrets=[known_key])
    assert known_key not in clean
    assert "AIza" in clean  # Masked preview prefix allowed
