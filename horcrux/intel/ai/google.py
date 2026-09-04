from __future__ import annotations

import time
from typing import Any, Generator, Optional
import httpx

from horcrux.core.sanitizer import redact_secrets
from horcrux.core.settings import DEFAULT_MODELS, SettingsManager
from horcrux.intel.ai.base import (
    AIError,
    AIErrorType,
    AIProvider,
    AIResponse,
    HORCRUX_EVIDENCE_POLICY,
    ModelInfo,
    ProviderCapabilities,
)


class GoogleProvider(AIProvider):
    def __init__(self, settings_manager: SettingsManager):
        super().__init__(settings_manager)
        self._cached_models: list[ModelInfo] = []
        self._cached_models_time: float = 0.0

    @property
    def name(self) -> str:
        return "google"

    @property
    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            supports_model_listing=True,
            supports_streaming=True,
            supports_system_prompt=True,
            supports_usage_metadata=True,
            supports_reasoning_metadata=True,
        )

    def _normalize_model_id(self, model: str) -> str:
        m = model.strip()
        if not m.startswith("models/"):
            return f"models/{m}"
        return m

    def complete(
        self,
        prompt: str,
        system_prompt: str = "",
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> AIResponse:
        key = self.get_api_key()
        if not key:
            raise AIError(
                AIErrorType.AUTHENTICATION_FAILED,
                "Google Gemini API key is not configured.",
                "Run 'settings provider google' to set your API key.",
                provider="google",
            )

        selected_model = self.get_active_model()
        canonical_model = self._normalize_model_id(selected_model)

        cfg = self.config
        base_endpoint = cfg.custom_endpoint or f"https://generativelanguage.googleapis.com/v1beta/{canonical_model}:generateContent"
        if "{model}" in base_endpoint:
            base_endpoint = base_endpoint.replace("{model}", canonical_model)

        timeout_sec = cfg.timeout or 60
        client_timeout = httpx.Timeout(connect=10.0, read=float(timeout_sec), write=10.0, pool=10.0)
        temp = temperature if temperature is not None else cfg.temperature
        max_tok = max_tokens if max_tokens is not None else cfg.max_tokens

        system = system_prompt or HORCRUX_EVIDENCE_POLICY
        full_text = f"{system}\n\n{prompt}" if system else prompt

        payload: dict[str, Any] = {
            "contents": [
                {
                    "parts": [{"text": full_text}]
                }
            ],
            "generationConfig": {
                "temperature": temp,
                "maxOutputTokens": max_tok,
            },
        }

        # Google Gemini officially supports the x-goog-api-key header
        headers = {
            "x-goog-api-key": key,
            "Content-Type": "application/json",
            "User-Agent": "Horcrux-AI/1.0",
        }

        t0 = time.perf_counter()
        resp_data: dict[str, Any] = {}
        status = 0

        # Implement retries for transient errors (up to 2 retries)
        max_attempts = 3
        for attempt in range(max_attempts):
            try:
                with httpx.Client(timeout=client_timeout) as client:
                    resp = client.post(base_endpoint, json=payload, headers=headers)
                    status = resp.status_code

                    # Redact response text in case error body echoed the key
                    body_clean = redact_secrets(resp.text, extra_secrets=[key])

                    if status == 404 or (status == 400 and ("not found" in body_clean.lower() or "no longer available" in body_clean.lower())):
                        raise AIError(
                            AIErrorType.MODEL_UNAVAILABLE,
                            f"Model '{selected_model}' is not available or discontinued for this Google AI Studio project.",
                            "Run 'settings models google' to discover and select an active Gemini model (e.g. gemini-3.6-flash).",
                            provider="google",
                            raw_status=status,
                        )

                    if status == 401 or (status == 400 and "api_key_invalid" in body_clean.lower()):
                        raise AIError(
                            AIErrorType.AUTHENTICATION_FAILED,
                            "Google authentication failed. The configured API key was rejected.",
                            "Run: settings provider google",
                            provider="google",
                            raw_status=status,
                        )

                    if status == 403:
                        raise AIError(
                            AIErrorType.PERMISSION_DENIED,
                            "Google AI Studio access forbidden or insufficient permissions.",
                            "Check API key enablement and project billing.",
                            provider="google",
                            raw_status=status,
                        )

                    if status == 429:
                        if attempt < max_attempts - 1:
                            retry_after = resp.headers.get("Retry-After")
                            wait = min(float(retry_after), 5.0) if retry_after and retry_after.isdigit() else (attempt + 1) * 1.5
                            time.sleep(wait)
                            continue
                        raise AIError(
                            AIErrorType.RATE_LIMITED,
                            "Google Gemini rate limit exceeded.",
                            "Wait before retrying or switch to another provider.",
                            provider="google",
                            raw_status=status,
                        )

                    if status >= 500:
                        if attempt < max_attempts - 1:
                            time.sleep((attempt + 1) * 1.0)
                            continue
                        raise AIError(
                            AIErrorType.PROVIDER_UNAVAILABLE,
                            f"Google Gemini service is temporarily unavailable (HTTP {status}).",
                            "Retry shortly or switch default provider.",
                            provider="google",
                            raw_status=status,
                        )

                    resp.raise_for_status()
                    resp_data = resp.json()
                    break

            except AIError:
                raise
            except httpx.TimeoutException:
                if attempt < max_attempts - 1:
                    time.sleep(1.0)
                    continue
                raise AIError(
                    AIErrorType.TIMEOUT,
                    f"Google request timed out after {timeout_sec} seconds.",
                    "Check connectivity or try again.",
                    provider="google",
                )
            except (httpx.ConnectError, httpx.NetworkError) as net_err:
                if attempt < max_attempts - 1:
                    time.sleep(1.0)
                    continue
                err_type, msg, hint = self.normalize_error(net_err)
                raise AIError(err_type, msg, hint, provider="google")
            except Exception as exc:
                err_type, msg, hint = self.normalize_error(exc)
                raise AIError(err_type, msg, hint, provider="google")

        latency = time.perf_counter() - t0

        # Robust multi-candidate and multi-part response extraction
        candidates = resp_data.get("candidates") or []
        prompt_feedback = resp_data.get("promptFeedback") or {}

        if not candidates:
            block_reason = prompt_feedback.get("blockReason", "")
            if block_reason:
                raise AIError(
                    AIErrorType.SAFETY_BLOCK,
                    f"Google Gemini blocked prompt execution (Reason: {block_reason}).",
                    "Adjust prompt or safety thresholds.",
                    provider="google",
                )
            raise AIError(
                AIErrorType.INVALID_RESPONSE,
                "Google Gemini returned no candidate completions.",
                f"Diagnostic: prompt feedback={prompt_feedback or 'none'}",
                provider="google",
            )

        collected_text: list[str] = []
        finish_reason = ""

        for candidate in candidates:
            if not finish_reason:
                finish_reason = candidate.get("finishReason", "")
            content_obj = candidate.get("content") or {}
            parts = content_obj.get("parts") or []
            for part in parts:
                # Do NOT treat thinking / thoughts as user-visible text
                if part.get("thought") is True:
                    continue
                # Extract text if present and meaningful
                part_text = part.get("text")
                if part_text:
                    collected_text.append(part_text)

        text = "".join(collected_text).strip()

        if not text:
            if finish_reason in ("SAFETY", "BLOCKLIST", "PROHIBITED_CONTENT"):
                raise AIError(
                    AIErrorType.SAFETY_BLOCK,
                    f"Google Gemini candidate blocked due to policy (finishReason: {finish_reason}).",
                    "Review prompt content.",
                    provider="google",
                )
            raise AIError(
                AIErrorType.INVALID_RESPONSE,
                f"Google returned a successful response but no usable text (finishReason: {finish_reason or 'UNKNOWN'}).",
                "Diagnostic: no candidate text parts were present.",
                provider="google",
            )

        usage = resp_data.get("usageMetadata") or {}
        prompt_tokens = usage.get("promptTokenCount", 0)
        completion_tokens = usage.get("candidatesTokenCount", 0)
        reasoning_tokens = usage.get("thoughtsTokenCount", 0)
        total_tokens = usage.get("totalTokenCount", prompt_tokens + completion_tokens)

        return AIResponse(
            content=text,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            reasoning_tokens=reasoning_tokens,
            total_tokens=total_tokens,
            model=selected_model,
            provider="google",
            latency=round(latency, 2),
            finish_reason=finish_reason,
            raw_metadata=resp_data,
        )

    def list_models(self) -> list[ModelInfo]:
        """Query Google Gemini API for available generation models with caching."""
        now = time.time()
        if self._cached_models and (now - self._cached_models_time) < 300:
            return self._cached_models

        key = self.get_api_key()
        if not key:
            from horcrux.core.settings import AVAILABLE_MODELS
            return [ModelInfo(id=m, name=m, context_window=1000000) for m in AVAILABLE_MODELS.get("google", [])]

        headers = {
            "x-goog-api-key": key,
            "User-Agent": "Horcrux-AI/1.0",
        }

        try:
            with httpx.Client(timeout=10.0) as client:
                resp = client.get("https://generativelanguage.googleapis.com/v1beta/models", headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    models: list[ModelInfo] = []
                    for m in data.get("models", []):
                        raw_name = m.get("name", "")
                        methods = m.get("supportedGenerationMethods", [])
                        if ("generateContent" in methods or "interactions" in methods) and "gemini" in raw_name.lower():
                            clean_id = raw_name.replace("models/", "")
                            display_name = m.get("displayName", clean_id)
                            input_tok = m.get("inputTokenLimit", 1000000)
                            output_tok = m.get("outputTokenLimit", 8192)
                            models.append(
                                ModelInfo(
                                    id=clean_id,
                                    name=display_name,
                                    context_window=input_tok,
                                    max_output_tokens=output_tok,
                                    description=m.get("description", ""),
                                )
                            )
                    if models:
                        self._cached_models = models
                        self._cached_models_time = now
                        return models
        except Exception:
            pass

        from horcrux.core.settings import AVAILABLE_MODELS
        return [ModelInfo(id=m, name=m, context_window=1000000) for m in AVAILABLE_MODELS.get("google", [])]

    def stream(
        self,
        prompt: str,
        system_prompt: str = "",
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> Generator[str, None, None]:
        resp = self.complete(prompt, system_prompt=system_prompt, temperature=temperature, max_tokens=max_tokens)
        yield resp.content
