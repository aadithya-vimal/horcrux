from __future__ import annotations

import time
from typing import Any, Generator, Optional
import httpx

from horcrux.core.settings import DEFAULT_MODELS, SettingsManager
from horcrux.intel.ai.base import (
    AIError,
    AIErrorType,
    AIProvider,
    AIResponse,
    HORCRUX_EVIDENCE_POLICY,
    ModelInfo,
)


class GoogleProvider(AIProvider):
    @property
    def name(self) -> str:
        return "google"

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

        cfg = self.config
        selected_model = self.settings.get_model("google") or cfg.model or DEFAULT_MODELS["google"]
        canonical_model = self._normalize_model_id(selected_model)

        endpoint = cfg.custom_endpoint or f"https://generativelanguage.googleapis.com/v1beta/{canonical_model}:generateContent?key={key}"
        if "{model}" in endpoint:
            endpoint = endpoint.replace("{model}", canonical_model)
        if "{key}" in endpoint:
            endpoint = endpoint.replace("{key}", key)
        elif "key=" not in endpoint:
            sep = "&" if "?" in endpoint else "?"
            endpoint = f"{endpoint}{sep}key={key}"

        timeout = cfg.timeout or 60
        temp = temperature if temperature is not None else cfg.temperature
        max_tok = max_tokens if max_tokens is not None else cfg.max_tokens

        system = system_prompt or HORCRUX_EVIDENCE_POLICY
        full_text = f"{system}\n\n{prompt}" if system else prompt

        payload = {
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

        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Horcrux-AI/1.0",
        }

        t0 = time.perf_counter()
        try:
            with httpx.Client(timeout=timeout) as client:
                resp = client.post(endpoint, json=payload, headers=headers)
                status = resp.status_code

                if status == 404 or (status == 400 and ("not found" in resp.text.lower() or "no longer available" in resp.text.lower())):
                    raise AIError(
                        AIErrorType.MODEL_UNAVAILABLE,
                        f"Model '{selected_model}' is not available or discontinued for this Google AI Studio project.",
                        "Run 'settings models' to discover and select an active Gemini model (e.g. gemini-3.6-flash).",
                        provider="google",
                        raw_status=status,
                    )

                if status == 401 or (status == 400 and "api_key_invalid" in resp.text.lower()):
                    raise AIError(
                        AIErrorType.AUTHENTICATION_FAILED,
                        "Invalid Google API key provided.",
                        "Verify your Google AI Studio API key at https://aistudio.google.com/.",
                        provider="google",
                        raw_status=status,
                    )

                if status == 429:
                    raise AIError(
                        AIErrorType.RATE_LIMITED,
                        "Google Gemini rate limit exceeded.",
                        "Wait before retrying or switch to another provider.",
                        provider="google",
                        raw_status=status,
                    )

                resp.raise_for_status()
                data = resp.json()
        except AIError:
            raise
        except httpx.TimeoutException:
            raise AIError(
                AIErrorType.TIMEOUT,
                "Google Gemini request timed out.",
                "Check connectivity or increase timeout in settings.",
                provider="google",
            )
        except Exception as exc:
            err_type, msg, hint = self.normalize_error(exc)
            raise AIError(err_type, msg, hint, provider="google")

        latency = time.perf_counter() - t0

        candidates = data.get("candidates", [])
        if not candidates:
            raise AIError(
                AIErrorType.INVALID_RESPONSE,
                "Google Gemini returned no candidate completions.",
                "Inspect safety blocks or adjust prompt parameters.",
                provider="google",
            )

        parts = candidates[0].get("content", {}).get("parts", [])
        text = "".join(p.get("text", "") for p in parts).strip()
        finish_reason = candidates[0].get("finishReason", "")

        usage = data.get("usageMetadata", {})
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
        )

    def list_models(self) -> list[ModelInfo]:
        key = self.get_api_key()
        if not key:
            from horcrux.core.settings import AVAILABLE_MODELS
            return [ModelInfo(id=m, name=m, context_window=1000000) for m in AVAILABLE_MODELS.get("google", [])]

        try:
            with httpx.Client(timeout=10) as client:
                resp = client.get(f"https://generativelanguage.googleapis.com/v1beta/models?key={key}")
                if resp.status_code == 200:
                    data = resp.json()
                    models: list[ModelInfo] = []
                    for m in data.get("models", []):
                        raw_name = m.get("name", "")
                        methods = m.get("supportedGenerationMethods", [])
                        if ("generateContent" in methods or "interactions" in methods) and "gemini" in raw_name.lower():
                            display_name = m.get("displayName", raw_name.replace("models/", ""))
                            input_tok = m.get("inputTokenLimit", 1000000)
                            output_tok = m.get("outputTokenLimit", 8192)
                            models.append(
                                ModelInfo(
                                    id=raw_name.replace("models/", ""),
                                    name=display_name,
                                    context_window=input_tok,
                                    max_output_tokens=output_tok,
                                    description=m.get("description", ""),
                                )
                            )
                    if models:
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
