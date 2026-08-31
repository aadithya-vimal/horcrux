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


class AnthropicProvider(AIProvider):
    @property
    def name(self) -> str:
        return "anthropic"

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
                "Anthropic API key is not configured.",
                "Run 'settings provider anthropic' to configure your API key.",
                provider="anthropic",
            )

        cfg = self.config
        selected_model = self.settings.get_model("anthropic") or cfg.model or DEFAULT_MODELS["anthropic"]
        endpoint = cfg.custom_endpoint or "https://api.anthropic.com/v1/messages"
        timeout = cfg.timeout or 60
        temp = temperature if temperature is not None else cfg.temperature
        max_tok = max_tokens if max_tokens is not None else cfg.max_tokens

        system = system_prompt or HORCRUX_EVIDENCE_POLICY
        payload = {
            "model": selected_model,
            "system": system,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": max_tok,
            "temperature": temp,
        }

        headers = {
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
            "user-agent": "Horcrux-AI/1.0",
        }

        t0 = time.perf_counter()
        try:
            with httpx.Client(timeout=timeout) as client:
                resp = client.post(endpoint, json=payload, headers=headers)
                status = resp.status_code

                if status == 401:
                    raise AIError(
                        AIErrorType.AUTHENTICATION_FAILED,
                        "Invalid Anthropic API key provided.",
                        "Verify your key at https://console.anthropic.com/settings/keys.",
                        provider="anthropic",
                        raw_status=status,
                    )
                if status == 404 or (status == 400 and "not_found_error" in resp.text.lower()):
                    raise AIError(
                        AIErrorType.MODEL_UNAVAILABLE,
                        f"Anthropic model '{selected_model}' not found or unavailable.",
                        "Run 'settings models anthropic' to select an active model (e.g. claude-3-5-sonnet-latest).",
                        provider="anthropic",
                        raw_status=status,
                    )
                if status == 429:
                    raise AIError(
                        AIErrorType.RATE_LIMITED,
                        "Anthropic rate limit exceeded.",
                        "Wait before retrying or switch default provider.",
                        provider="anthropic",
                        raw_status=status,
                    )

                resp.raise_for_status()
                data = resp.json()
        except AIError:
            raise
        except httpx.TimeoutException:
            raise AIError(
                AIErrorType.TIMEOUT,
                "Anthropic request timed out.",
                "Increase timeout in settings or verify connection.",
                provider="anthropic",
            )
        except Exception as exc:
            err_type, msg, hint = self.normalize_error(exc)
            raise AIError(err_type, msg, hint, provider="anthropic")

        latency = time.perf_counter() - t0

        content_blocks = data.get("content", [])
        text = "".join(b.get("text", "") for b in content_blocks if b.get("type") == "text").strip()
        stop_reason = data.get("stop_reason", "")

        usage = data.get("usage", {})
        prompt_tokens = usage.get("input_tokens", 0)
        completion_tokens = usage.get("output_tokens", 0)
        total_tokens = prompt_tokens + completion_tokens

        return AIResponse(
            content=text,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            model=selected_model,
            provider="anthropic",
            latency=round(latency, 2),
            finish_reason=stop_reason,
        )

    def list_models(self) -> list[ModelInfo]:
        key = self.get_api_key()
        if not key:
            from horcrux.core.settings import AVAILABLE_MODELS
            return [ModelInfo(id=m, name=m, context_window=200000) for m in AVAILABLE_MODELS.get("anthropic", [])]

        try:
            headers = {
                "x-api-key": key,
                "anthropic-version": "2023-06-01",
                "user-agent": "Horcrux-AI/1.0",
            }
            with httpx.Client(timeout=8) as client:
                resp = client.get("https://api.anthropic.com/v1/models", headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    models: list[ModelInfo] = []
                    for m in data.get("data", []):
                        m_id = m.get("id", "")
                        display = m.get("display_name", m_id)
                        if m_id:
                            models.append(
                                ModelInfo(
                                    id=m_id,
                                    name=display,
                                    context_window=200000,
                                    description="Anthropic Claude model (200k ctx)",
                                )
                            )
                    if models:
                        return models
        except Exception:
            pass

        from horcrux.core.settings import AVAILABLE_MODELS
        return [ModelInfo(id=m, name=m, context_window=200000) for m in AVAILABLE_MODELS.get("anthropic", [])]

    def stream(
        self,
        prompt: str,
        system_prompt: str = "",
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> Generator[str, None, None]:
        resp = self.complete(prompt, system_prompt=system_prompt, temperature=temperature, max_tokens=max_tokens)
        yield resp.content
