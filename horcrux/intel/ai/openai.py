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
    extract_json_payload,
)


class OpenAIProvider(AIProvider):
    @property
    def name(self) -> str:
        return "openai"

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
                "OpenAI API key is not configured.",
                "Run 'settings provider openai' to set your OpenAI API key.",
                provider="openai",
            )

        cfg = self.config
        selected_model = self.settings.get_model("openai") or cfg.model or DEFAULT_MODELS["openai"]
        endpoint = cfg.custom_endpoint or "https://api.openai.com/v1/chat/completions"
        timeout = cfg.timeout or 60
        temp = temperature if temperature is not None else cfg.temperature
        max_tok = max_tokens if max_tokens is not None else cfg.max_tokens

        system = system_prompt or HORCRUX_EVIDENCE_POLICY
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ]

        payload: dict[str, Any] = {
            "model": selected_model,
            "messages": messages,
        }
        # o1/o3 reasoning models use max_completion_tokens and do not support custom temperature
        if selected_model.startswith(("o1", "o3")):
            payload["max_completion_tokens"] = max_tok
        else:
            payload["temperature"] = temp
            payload["max_tokens"] = max_tok

        headers = {
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "User-Agent": "Horcrux-AI/1.0",
        }

        t0 = time.perf_counter()
        try:
            with httpx.Client(timeout=timeout) as client:
                resp = client.post(endpoint, json=payload, headers=headers)
                status = resp.status_code

                if status == 401:
                    raise AIError(
                        AIErrorType.AUTHENTICATION_FAILED,
                        "Invalid OpenAI API key provided.",
                        "Verify your key at https://platform.openai.com/api-keys and update with 'settings provider openai'.",
                        provider="openai",
                        raw_status=status,
                    )
                if status == 404 or (status == 400 and "model_not_found" in resp.text.lower()):
                    raise AIError(
                        AIErrorType.MODEL_UNAVAILABLE,
                        f"OpenAI model '{selected_model}' does not exist or account lacks permission.",
                        "Run 'settings models openai' to select an active model (e.g. gpt-4o or gpt-4o-mini).",
                        provider="openai",
                        raw_status=status,
                    )
                if status == 429:
                    err_text = resp.text.lower()
                    if "insufficient_quota" in err_text or "quota" in err_text:
                        raise AIError(
                            AIErrorType.QUOTA_EXCEEDED,
                            "OpenAI account quota exceeded. Check billing status.",
                            "Check usage limits at https://platform.openai.com/account/billing.",
                            provider="openai",
                            raw_status=status,
                        )
                    raise AIError(
                        AIErrorType.RATE_LIMITED,
                        "OpenAI rate limit reached.",
                        "Wait briefly or switch to another provider.",
                        provider="openai",
                        raw_status=status,
                    )

                resp.raise_for_status()
                data = resp.json()
        except AIError:
            raise
        except httpx.TimeoutException:
            raise AIError(
                AIErrorType.TIMEOUT,
                "OpenAI request timed out.",
                "Increase timeout in settings or verify connection.",
                provider="openai",
            )
        except Exception as exc:
            err_type, msg, hint = self.normalize_error(exc)
            raise AIError(err_type, msg, hint, provider="openai")

        latency = time.perf_counter() - t0

        choices = data.get("choices", [])
        if not choices:
            raise AIError(
                AIErrorType.INVALID_RESPONSE,
                "OpenAI returned no completion choices.",
                provider="openai",
            )

        content = choices[0].get("message", {}).get("content", "").strip()
        finish_reason = choices[0].get("finish_reason", "")
        usage = data.get("usage", {})
        prompt_tokens = usage.get("prompt_tokens", 0)
        completion_tokens = usage.get("completion_tokens", 0)
        reasoning_tokens = usage.get("completion_tokens_details", {}).get("reasoning_tokens", 0)
        total_tokens = usage.get("total_tokens", prompt_tokens + completion_tokens)

        return AIResponse(
            content=content,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            reasoning_tokens=reasoning_tokens,
            total_tokens=total_tokens,
            model=selected_model,
            provider="openai",
            latency=round(latency, 2),
            finish_reason=finish_reason,
        )

    def structured(
        self,
        prompt: str,
        system_prompt: str = "",
        schema: Any | None = None,
        temperature: float = 0.1,
        max_tokens: int | None = None,
    ) -> AIResponse:
        key = self.get_api_key()
        if not key:
            raise AIError(AIErrorType.AUTHENTICATION_FAILED, "OpenAI API key not configured.", provider="openai")

        cfg = self.config
        selected_model = self.settings.get_model("openai") or cfg.model or DEFAULT_MODELS["openai"]
        endpoint = cfg.custom_endpoint or "https://api.openai.com/v1/chat/completions"
        timeout = cfg.timeout or 60
        max_tok = max_tokens if max_tokens is not None else cfg.max_tokens

        system = (system_prompt or HORCRUX_EVIDENCE_POLICY) + "\n\nRespond ONLY with valid JSON."
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ]

        payload: dict[str, Any] = {
            "model": selected_model,
            "messages": messages,
            "response_format": {"type": "json_object"},
        }
        if selected_model.startswith(("o1", "o3")):
            payload["max_completion_tokens"] = max_tok
        else:
            payload["temperature"] = temperature
            payload["max_tokens"] = max_tok

        headers = {
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "User-Agent": "Horcrux-AI/1.0",
        }

        t0 = time.perf_counter()
        try:
            with httpx.Client(timeout=timeout) as client:
                resp = client.post(endpoint, json=payload, headers=headers)
                resp.raise_for_status()
                data = resp.json()
        except Exception:
            return super().structured(prompt, system_prompt=system_prompt, schema=schema, temperature=temperature, max_tokens=max_tokens)

        latency = time.perf_counter() - t0
        content = data.get("choices", [{}])[0].get("message", {}).get("content", "").strip()
        usage = data.get("usage", {})
        reasoning_tokens = usage.get("completion_tokens_details", {}).get("reasoning_tokens", 0)

        return AIResponse(
            content=content,
            structured=extract_json_payload(content),
            prompt_tokens=usage.get("prompt_tokens", 0),
            completion_tokens=usage.get("completion_tokens", 0),
            reasoning_tokens=reasoning_tokens,
            total_tokens=usage.get("total_tokens", 0),
            model=selected_model,
            provider="openai",
            latency=round(latency, 2),
        )

    def list_models(self) -> list[ModelInfo]:
        key = self.get_api_key()
        if not key:
            from horcrux.core.settings import AVAILABLE_MODELS
            return [ModelInfo(id=m, name=m, context_window=128000) for m in AVAILABLE_MODELS.get("openai", [])]

        try:
            headers = {"Authorization": f"Bearer {key}", "User-Agent": "Horcrux-AI/1.0"}
            with httpx.Client(timeout=8) as client:
                resp = client.get("https://api.openai.com/v1/models", headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    models: list[ModelInfo] = []
                    for m in data.get("data", []):
                        m_id = m.get("id", "")
                        if m_id.startswith(("gpt-4", "gpt-3.5", "o1", "o3", "chatgpt")) and not any(
                            x in m_id for x in ["realtime", "audio", "transcribe", "tts", "search", "preview"]
                        ):
                            ctx = 128000 if "gpt-4" in m_id or "o1" in m_id or "o3" in m_id else 16384
                            models.append(
                                ModelInfo(
                                    id=m_id,
                                    name=m_id,
                                    context_window=ctx,
                                    description=f"OpenAI model ({ctx:,} ctx)",
                                )
                            )
                    if models:
                        return models
        except Exception:
            pass

        from horcrux.core.settings import AVAILABLE_MODELS
        return [ModelInfo(id=m, name=m, context_window=128000) for m in AVAILABLE_MODELS.get("openai", [])]

    def stream(
        self,
        prompt: str,
        system_prompt: str = "",
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> Generator[str, None, None]:
        resp = self.complete(prompt, system_prompt=system_prompt, temperature=temperature, max_tokens=max_tokens)
        yield resp.content
