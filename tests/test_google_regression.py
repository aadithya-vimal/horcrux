from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import patch
import httpx

from horcrux.core.settings import SettingsManager
from horcrux.intel.ai.base import AIError, AIErrorType
from horcrux.intel.ai.google import GoogleProvider


def test_google_gemini_obsolete_model_regression_404():
    """
    CRITICAL REGRESSION TEST:
    When Google Gemini returns HTTP 404 for an obsolete or unavailable model (e.g. gemini-2.5-flash),
    the provider must normalize it to MODEL_UNAVAILABLE, NOT AUTHENTICATION_FAILED.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        mgr = SettingsManager(config_dir=Path(tmpdir))
        mgr.set_api_key("google", "AIzaSyFakeKey1234567890")
        mgr.set_model("google", "gemini-2.5-flash")

        provider = GoogleProvider(mgr)

        # Mock Google 404 response indicating model is no longer available
        error_body = {
            "error": {
                "code": 404,
                "message": "models/gemini-2.5-flash is not found for API version v1beta, or is not supported for generateContent. Call ListModels to see the list of available models and their supported methods.",
                "status": "NOT_FOUND",
            }
        }
        mock_resp = httpx.Response(
            404,
            json=error_body,
            request=httpx.Request("POST", "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"),
        )

        with patch("httpx.Client.post", return_value=mock_resp):
            try:
                provider.complete("Test prompt")
                assert False, "Expected AIError for unavailable model"
            except AIError as exc:
                assert exc.error_type == AIErrorType.MODEL_UNAVAILABLE
                assert "gemini-2.5-flash" in exc.message
                assert "settings models" in exc.suggested_action.lower()

            ok, msg, err_type, _ = provider.validate_credentials()
            assert ok is False
            assert err_type == AIErrorType.MODEL_UNAVAILABLE
            assert "settings models" in msg.lower()


def test_google_gemini_active_model_success():
    """
    Verifies that an active Gemini model (e.g. gemini-3.6-flash or gemini-1.5-flash) succeeds.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        mgr = SettingsManager(config_dir=Path(tmpdir))
        mgr.set_api_key("google", "AIzaSyFakeKey1234567890")
        mgr.set_model("google", "gemini-3.6-flash")

        provider = GoogleProvider(mgr)

        success_body = {
            "candidates": [
                {
                    "content": {
                        "parts": [{"text": "HORCRUX READY"}],
                        "role": "model",
                    },
                    "finishReason": "STOP",
                }
            ],
            "usageMetadata": {
                "promptTokenCount": 15,
                "candidatesTokenCount": 3,
                "totalTokenCount": 18,
                "thoughtsTokenCount": 0,
            },
        }
        mock_resp = httpx.Response(
            200,
            json=success_body,
            request=httpx.Request("POST", "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.6-flash:generateContent"),
        )

        with patch("httpx.Client.post", return_value=mock_resp):
            resp = provider.complete("Test prompt")
            assert resp.content == "HORCRUX READY"
            assert resp.model == "gemini-3.6-flash"
            assert resp.provider == "google"
            assert resp.total_tokens == 18

            ok, msg, err_type, latency = provider.validate_credentials()
            assert ok is True
            assert err_type is None
            assert "gemini-3.6-flash" in msg
