from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import patch
import httpx
import pytest

from horcrux.core.settings import SettingsManager
from horcrux.intel.ai.anthropic import AnthropicProvider
from horcrux.intel.ai.base import AIError, AIErrorType
from horcrux.intel.ai.google import GoogleProvider
from horcrux.intel.ai.groq import GroqProvider
from horcrux.intel.ai.openai import OpenAIProvider


# ---------------------------------------------------------------------------
# GROQ TESTS
# ---------------------------------------------------------------------------

def test_groq_matrix():
    with tempfile.TemporaryDirectory() as tmpdir:
        mgr = SettingsManager(config_dir=Path(tmpdir))
        mgr.set_api_key("groq", "gsk_testkey1234567890abcdef")
        p = GroqProvider(mgr)

        # 1. Model Listing
        models_data = {"data": [{"id": "llama-3.3-70b-versatile", "context_window": 128000}, {"id": "whisper-large-v3"}]}
        with patch("httpx.Client.get", return_value=httpx.Response(200, json=models_data, request=httpx.Request("GET", "http://test"))):
            models = p.list_models()
            model_ids = [m.id for m in models]
            assert "llama-3.3-70b-versatile" in model_ids
            assert "whisper-large-v3" not in model_ids

        # 2. Valid Completion & Token Usage
        chat_data = {
            "choices": [{"message": {"content": '{"test": "passed"}'}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 20, "completion_tokens": 10, "total_tokens": 30},
        }
        with patch("httpx.Client.post", return_value=httpx.Response(200, json=chat_data, request=httpx.Request("POST", "http://test"))):
            resp = p.complete("Hello")
            assert resp.content == '{"test": "passed"}'
            assert resp.total_tokens == 30
            assert resp.provider == "groq"

            struct_resp = p.structured("Give JSON")
            assert struct_resp.structured == {"test": "passed"}

        # 3. 401 Auth Failure
        with patch("httpx.Client.post", return_value=httpx.Response(401, text="invalid_api_key", request=httpx.Request("POST", "http://test"))):
            with pytest.raises(AIError) as exc_info:
                p.complete("Hello")
            assert exc_info.value.error_type == AIErrorType.AUTHENTICATION_FAILED

        # 4. 404 Model Not Found
        with patch("httpx.Client.post", return_value=httpx.Response(404, text="model_not_found", request=httpx.Request("POST", "http://test"))):
            with pytest.raises(AIError) as exc_info:
                p.complete("Hello")
            assert exc_info.value.error_type == AIErrorType.MODEL_UNAVAILABLE

        # 5. 429 Rate Limited
        with patch("httpx.Client.post", return_value=httpx.Response(429, text="rate_limit_exceeded", request=httpx.Request("POST", "http://test"))):
            with pytest.raises(AIError) as exc_info:
                p.complete("Hello")
            assert exc_info.value.error_type == AIErrorType.RATE_LIMITED

        # 6. Timeout
        with patch("httpx.Client.post", side_effect=httpx.ReadTimeout("Read timed out")):
            with pytest.raises(AIError) as exc_info:
                p.complete("Hello")
            assert exc_info.value.error_type == AIErrorType.TIMEOUT


# ---------------------------------------------------------------------------
# OPENAI TESTS
# ---------------------------------------------------------------------------

def test_openai_matrix():
    with tempfile.TemporaryDirectory() as tmpdir:
        mgr = SettingsManager(config_dir=Path(tmpdir))
        mgr.set_api_key("openai", "sk-proj-testkey1234567890abcdef")
        p = OpenAIProvider(mgr)

        # 1. Model Listing
        models_data = {"data": [{"id": "gpt-4o"}, {"id": "o3-mini"}, {"id": "text-embedding-3"}]}
        with patch("httpx.Client.get", return_value=httpx.Response(200, json=models_data, request=httpx.Request("GET", "http://test"))):
            models = p.list_models()
            model_ids = [m.id for m in models]
            assert "gpt-4o" in model_ids
            assert "o3-mini" in model_ids
            assert "text-embedding-3" not in model_ids

        # 2. Completion with reasoning tokens
        chat_data = {
            "choices": [{"message": {"content": "OpenAI Response"}, "finish_reason": "stop"}],
            "usage": {
                "prompt_tokens": 40,
                "completion_tokens": 15,
                "total_tokens": 55,
                "completion_tokens_details": {"reasoning_tokens": 8},
            },
        }
        with patch("httpx.Client.post", return_value=httpx.Response(200, json=chat_data, request=httpx.Request("POST", "http://test"))):
            resp = p.complete("Hello")
            assert resp.content == "OpenAI Response"
            assert resp.reasoning_tokens == 8
            assert resp.total_tokens == 55

        # 3. 401 Auth Failure
        with patch("httpx.Client.post", return_value=httpx.Response(401, text="Incorrect API key", request=httpx.Request("POST", "http://test"))):
            with pytest.raises(AIError) as exc_info:
                p.complete("Hello")
            assert exc_info.value.error_type == AIErrorType.AUTHENTICATION_FAILED

        # 4. 429 Quota Exceeded
        with patch("httpx.Client.post", return_value=httpx.Response(429, text="insufficient_quota", request=httpx.Request("POST", "http://test"))):
            with pytest.raises(AIError) as exc_info:
                p.complete("Hello")
            assert exc_info.value.error_type == AIErrorType.QUOTA_EXCEEDED


# ---------------------------------------------------------------------------
# ANTHROPIC TESTS
# ---------------------------------------------------------------------------

def test_anthropic_matrix():
    with tempfile.TemporaryDirectory() as tmpdir:
        mgr = SettingsManager(config_dir=Path(tmpdir))
        mgr.set_api_key("anthropic", "sk-ant-api03-testkey1234567890abcdef")
        p = AnthropicProvider(mgr)

        # 1. Model Listing
        models_data = {"data": [{"id": "claude-3-5-sonnet-latest", "display_name": "Claude 3.5 Sonnet"}]}
        with patch("httpx.Client.get", return_value=httpx.Response(200, json=models_data, request=httpx.Request("GET", "http://test"))):
            models = p.list_models()
            model_ids = [m.id for m in models]
            assert "claude-3-5-sonnet-latest" in model_ids

        # 2. Messages Completion & Usage
        msg_data = {
            "content": [{"type": "text", "text": "Claude Output"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 30, "output_tokens": 12},
        }
        with patch("httpx.Client.post", return_value=httpx.Response(200, json=msg_data, request=httpx.Request("POST", "http://test"))):
            resp = p.complete("Hello")
            assert resp.content == "Claude Output"
            assert resp.prompt_tokens == 30
            assert resp.completion_tokens == 12
            assert resp.total_tokens == 42
            assert resp.provider == "anthropic"

        # 3. 401 Auth Failure
        with patch("httpx.Client.post", return_value=httpx.Response(401, text="authentication_error", request=httpx.Request("POST", "http://test"))):
            with pytest.raises(AIError) as exc_info:
                p.complete("Hello")
            assert exc_info.value.error_type == AIErrorType.AUTHENTICATION_FAILED

        # 4. 429 Rate Limit
        with patch("httpx.Client.post", return_value=httpx.Response(429, text="rate_limit_error", request=httpx.Request("POST", "http://test"))):
            with pytest.raises(AIError) as exc_info:
                p.complete("Hello")
            assert exc_info.value.error_type == AIErrorType.RATE_LIMITED


# ---------------------------------------------------------------------------
# GOOGLE TESTS
# ---------------------------------------------------------------------------

def test_google_matrix():
    with tempfile.TemporaryDirectory() as tmpdir:
        mgr = SettingsManager(config_dir=Path(tmpdir))
        mgr.set_api_key("google", "AIzaSyTestKey1234567890")
        p = GoogleProvider(mgr)

        # 1. Dynamic Model Listing
        models_data = {
            "models": [
                {
                    "name": "models/gemini-1.5-flash",
                    "displayName": "Gemini 1.5 Flash",
                    "supportedGenerationMethods": ["generateContent"],
                    "inputTokenLimit": 1000000,
                    "outputTokenLimit": 8192,
                },
                {
                    "name": "models/gemini-3.6-flash",
                    "displayName": "Gemini 3.6 Flash",
                    "supportedGenerationMethods": ["generateContent"],
                    "inputTokenLimit": 1000000,
                    "outputTokenLimit": 8192,
                },
                {
                    "name": "models/embedding-001",
                    "displayName": "Embedding 001",
                    "supportedGenerationMethods": ["embedContent"],
                },
            ]
        }
        with patch("httpx.Client.get", return_value=httpx.Response(200, json=models_data, request=httpx.Request("GET", "http://test"))):
            models = p.list_models()
            model_ids = [m.id for m in models]
            assert "gemini-1.5-flash" in model_ids
            assert "gemini-3.6-flash" in model_ids
            assert "embedding-001" not in model_ids

        # 2. 401 Auth Failure
        with patch("httpx.Client.post", return_value=httpx.Response(400, text="api_key_invalid", request=httpx.Request("POST", "http://test"))):
            with pytest.raises(AIError) as exc_info:
                p.complete("Hello")
            assert exc_info.value.error_type == AIErrorType.AUTHENTICATION_FAILED

        # 3. 429 Rate Limit
        with patch("httpx.Client.post", return_value=httpx.Response(429, text="Resource exhausted", request=httpx.Request("POST", "http://test"))):
            with pytest.raises(AIError) as exc_info:
                p.complete("Hello")
            assert exc_info.value.error_type == AIErrorType.RATE_LIMITED
