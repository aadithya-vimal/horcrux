from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import patch
import httpx

from horcrux.core.settings import SettingsManager
from horcrux.intel.ai.base import AIError, AIErrorType
from horcrux.intel.ai.google import GoogleProvider


def test_google_parse_real_gemini_shape_with_thought_signature():
    """
    Test real observed Gemini API response containing candidate with text and thoughtSignature.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        mgr = SettingsManager(config_dir=Path(tmpdir))
        mgr.set_api_key("google", "AIzaSyTestKey1234567890")
        provider = GoogleProvider(mgr)

        real_payload = {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {
                                "text": "HORCRUX READY",
                                "thoughtSignature": "eJyLzivNydFRMDRTMDBTMDCzMDE0MjC2MDc1szRR0gQAaVoGnA==",
                            }
                        ],
                        "role": "model",
                    },
                    "finishReason": "STOP",
                }
            ],
            "usageMetadata": {
                "promptTokenCount": 22,
                "candidatesTokenCount": 4,
                "totalTokenCount": 26,
                "thoughtsTokenCount": 0,
            },
        }

        mock_resp = httpx.Response(
            200,
            json=real_payload,
            request=httpx.Request("POST", "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.6-flash:generateContent"),
        )

        with patch("httpx.Client.post", return_value=mock_resp):
            resp = provider.complete("Say ready")
            assert resp.content == "HORCRUX READY"
            assert resp.text == "HORCRUX READY"
            assert resp.total_tokens == 26
            assert resp.finish_reason == "STOP"


def test_google_parse_multi_part_and_multi_candidate():
    """Verify that multiple text parts across candidates are concatenated properly."""
    with tempfile.TemporaryDirectory() as tmpdir:
        mgr = SettingsManager(config_dir=Path(tmpdir))
        mgr.set_api_key("google", "AIzaSyTestKey1234567890")
        provider = GoogleProvider(mgr)

        payload = {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {"text": "Part 1 of response. "},
                            {"thought": True, "text": "Internal thinking process..."},
                            {"text": "Part 2 of response."},
                        ],
                        "role": "model",
                    },
                    "finishReason": "STOP",
                }
            ],
            "usageMetadata": {
                "promptTokenCount": 10,
                "candidatesTokenCount": 8,
                "thoughtsTokenCount": 15,
                "totalTokenCount": 33,
            },
        }

        mock_resp = httpx.Response(
            200,
            json=payload,
            request=httpx.Request("POST", "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.6-flash:generateContent"),
        )

        with patch("httpx.Client.post", return_value=mock_resp):
            resp = provider.complete("Test multi part")
            # Internal thoughts MUST be excluded from user-visible text
            assert "Internal thinking process" not in resp.content
            assert resp.content == "Part 1 of response. Part 2 of response."
            assert resp.reasoning_tokens == 15


def test_google_empty_text_raises_invalid_response_with_diagnostics():
    """Verify that a 200 OK with no candidate text parts raises INVALID_RESPONSE with diagnostics."""
    with tempfile.TemporaryDirectory() as tmpdir:
        mgr = SettingsManager(config_dir=Path(tmpdir))
        mgr.set_api_key("google", "AIzaSyTestKey1234567890")
        provider = GoogleProvider(mgr)

        empty_payload = {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {"thought": True, "text": "Only thought parts produced..."}
                        ],
                        "role": "model",
                    },
                    "finishReason": "MAX_TOKENS",
                }
            ],
            "usageMetadata": {"promptTokenCount": 5, "totalTokenCount": 10},
        }

        mock_resp = httpx.Response(
            200,
            json=empty_payload,
            request=httpx.Request("POST", "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.6-flash:generateContent"),
        )

        with patch("httpx.Client.post", return_value=mock_resp):
            try:
                provider.complete("Test empty")
                assert False, "Expected AIError for response with no usable text"
            except AIError as exc:
                assert exc.error_type == AIErrorType.INVALID_RESPONSE
                assert "MAX_TOKENS" in exc.message
                assert "no candidate text parts" in exc.suggested_action.lower()


def test_google_safety_block_handling():
    """Verify promptFeedback blockReason and candidate SAFETY finishReason."""
    with tempfile.TemporaryDirectory() as tmpdir:
        mgr = SettingsManager(config_dir=Path(tmpdir))
        mgr.set_api_key("google", "AIzaSyTestKey1234567890")
        provider = GoogleProvider(mgr)

        blocked_payload = {
            "promptFeedback": {
                "blockReason": "SAFETY",
                "safetyRatings": [{"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "probability": "HIGH"}],
            }
        }

        mock_resp = httpx.Response(
            200,
            json=blocked_payload,
            request=httpx.Request("POST", "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.6-flash:generateContent"),
        )

        with patch("httpx.Client.post", return_value=mock_resp):
            try:
                provider.complete("Test safety")
                assert False, "Expected AIError for blocked prompt"
            except AIError as exc:
                assert exc.error_type == AIErrorType.SAFETY_BLOCK
                assert "SAFETY" in exc.message


def test_google_shared_generation_pathway():
    """
    Verify that validate_credentials() and complete() use the exact same request pathway
    and do not suffer from divergent parsing logic.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        mgr = SettingsManager(config_dir=Path(tmpdir))
        mgr.set_api_key("google", "AIzaSyTestKey1234567890")
        mgr.set_model("google", "gemini-3.6-flash")
        provider = GoogleProvider(mgr)

        success_payload = {
            "candidates": [
                {
                    "content": {
                        "parts": [{"text": "OK"}],
                        "role": "model",
                    },
                    "finishReason": "STOP",
                }
            ],
            "usageMetadata": {"promptTokenCount": 2, "candidatesTokenCount": 1, "totalTokenCount": 3},
        }
        mock_resp = httpx.Response(
            200,
            json=success_payload,
            request=httpx.Request("POST", "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.6-flash:generateContent"),
        )

        with patch("httpx.Client.post", return_value=mock_resp):
            # Test validate_credentials (which powers settings test)
            ok, msg, err_type, latency = provider.validate_credentials()
            assert ok is True
            assert err_type is None
            assert "gemini-3.6-flash" in msg

            # Test complete (which powers ask)
            resp = provider.complete("Hello")
            assert resp.content == "OK"
            assert resp.model == "gemini-3.6-flash"
