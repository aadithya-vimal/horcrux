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
    extract_json_payload,
)


class OpenAIProvider(AIProvider):
    @property
    def name(self) -> str:
        return "openai"

    @property
    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            supports_model_listing=True,
            supports_streaming=True,
            supports_system_prompt=True,
            supports_usage_metadata=True,
            supports_reasoning_metadata=True,
        )

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
        selected_model = self.get_active_model()
        endpoint = cfg.custom_endpoint or "https://api.openai.com/v1/chat/completions"
        timeout_sec = cfg.timeout or 60
        client_timeout = httpx.Timeout(connect=10.0, read=float(timeout_sec), write=10.0, pool=10.0)
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
        data: dict[str, Any] = {}
        max_attempts = 3

        for attempt in range(max_attempts):
            try:
                with httpx.Client(timeout=client_timeout) as client:
                    resp = client.post(endpoint, json=payload, headers=headers)
                    status = resp.status_code

                    body_clean = redact_secrets(resp.text, extra_secrets=[key])

                    if status == 401:
                        raise AIError(
                            AIErrorType.AUTHENTICATION_FAILED,
                            "Invalid OpenAI API key provided.",
                            "Verify your key at https://platform.openai.com/api-keys and update with 'settings provider openai'.",
                            provider="openai",
                            raw_status=status,
                        )
                    if status == 404 or (status == 400 and "model_not_found" in body_clean.lower()):
                        raise AIError(
                            AIErrorType.MODEL_UNAVAILABLE,
                            f"OpenAI model '{selected_model}' does not exist or account lacks permission.",
                            "Run 'settings models openai' to select an active model (e.g. gpt-4o or gpt-4o-mini).",
                            provider="openai",
                            raw_status=status,
                        )
                    if status == 429:
                        if "insufficient_quota" in body_clean.lower() or "quota" in body_clean.lower():
                            raise AIError(
                                AIErrorType.QUOTA_EXCEEDED,
                                "OpenAI account quota exceeded. Check billing status.",
                                "Check usage limits at https://platform.openai.com/account/billing.",
                                provider="openai",
                                raw_status=status,
                            )
                        if attempt < max_attempts - 1:
                            retry_after = resp.headers.get("Retry-After")
                            wait = min(float(retry_after), 5.0) if retry_after and retry_after.isdigit() else (attempt + 1) * 1.5
                            time.sleep(wait)
                            continue
                        raise AIError(
                            AIErrorType.RATE_LIMITED,
                            "OpenAI rate limit reached.",
                            "Wait briefly or switch to another provider.",
                            provider="openai",
                            raw_status=status,
                        )
                    if status >= 500:
                        if attempt < max_attempts - 1:
                            time.sleep((attempt + 1) * 1.0)
                            continue
                        raise AIError(
                            AIErrorType.PROVIDER_UNAVAILABLE,
                            f"OpenAI service is temporarily unavailable (HTTP {status}).",
                            "Retry shortly or switch default provider.",
                            provider="openai",
                            raw_status=status,
                        )

                    resp.raise_for_status()
                    data = resp.json()
                    break
            except AIError:
                raise
            except httpx.TimeoutException:
                if attempt < max_attempts - 1:
                    time.sleep(1.0)
                    continue
                raise AIError(
                    AIErrorType.TIMEOUT,
                    f"OpenAI request timed out after {timeout_sec} seconds.",
                    "Increase timeout in settings or verify connection.",
                    provider="openai",
                )
            except (httpx.ConnectError, httpx.NetworkError) as net_err:
                if attempt < max_attempts - 1:
                    time.sleep(1.0)
                    continue
                err_type, msg, hint = self.normalize_error(net_err)
                raise AIError(err_type, msg, hint, provider="openai")
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
            raw_metadata=data,
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
        selected_model = self.get_active_model()
        endpoint = cfg.custom_endpoint or "https://api.openai.com/v1/chat/completions"
        timeout_sec = cfg.timeout or 60
        client_timeout = httpx.Timeout(connect=10.0, read=float(timeout_sec), write=10.0, pool=10.0)

        system = (system_prompt or HORCRUX_EVIDENCE_POLICY) + "\n\nRespond ONLY with a valid JSON object matching the requested schema. No conversational prose."
        payload: dict[str, Any] = {
            "model": selected_model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "response_format": {"type": "json_object"},
        }
        if selected_model.startswith(("o1", "o3")):
            payload["max_completion_tokens"] = max_tokens or cfg.max_tokens
        else:
            payload["temperature"] = temperature
            payload["max_tokens"] = max_tokens or cfg.max_tokens

        headers = {
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "User-Agent": "Horcrux-AI/1.0",
        }

        t0 = time.perf_counter()
        try:
            with httpx.Client(timeout=client_timeout) as client:
                resp = client.post(endpoint, json=payload, headers=headers)
                resp.raise_for_status()
                data = resp.json()
        except Exception:
            return super().structured(prompt, system_prompt=system_prompt, schema=schema, temperature=temperature, max_tokens=max_tokens)

        latency = time.perf_counter() - t0
        content = data.get("choices", [{}])[0].get("message", {}).get("content", "").strip()
        usage = data.get("usage", {})
        prompt_tokens = usage.get("prompt_tokens", 0)
        completion_tokens = usage.get("completion_tokens", 0)

        return AIResponse(
            content=content,
            structured=extract_json_payload(content),
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=usage.get("total_tokens", prompt_tokens + completion_tokens),
            model=selected_model,
            provider="openai",
            latency=round(latency, 2),
            raw_metadata=data,
        )

    def list_models(self) -> list[ModelInfo]:
        key = self.get_api_key()
        if not key:
            from horcrux.core.settings import AVAILABLE_MODELS
            return [ModelInfo(id=m, name=m, context_window=128000) for m in AVAILABLE_MODELS.get("openai", [])]

        try:
            headers = {"Authorization": f"Bearer {key}", "User-Agent": "Horcrux-AI/1.0"}
            with httpx.Client(timeout=httpx.Timeout(connect=5.0, read=8.0, write=5.0, pool=5.0)) as client:
                resp = client.get("https://api.openai.com/v1/models", headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    models: list[ModelInfo] = []
                    for m in data.get("data", []):
                        m_id = m.get("id", "")
                        if any(prefix in m_id for prefix in ["gpt-4", "o1", "o3", "chatgpt"]) and not any(s in m_id for s in ["whisper", "tts", "dall-e", "embedding", "realtime", "audio"]):
                            ctx = 128000 if ("gpt-4" in m_id or "o1" in m_id or "o3" in m_id) else 16384
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
