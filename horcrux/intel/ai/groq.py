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


class GroqProvider(AIProvider):
    @property
    def name(self) -> str:
        return "groq"

    @property
    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            supports_model_listing=True,
            supports_streaming=True,
            supports_system_prompt=True,
            supports_usage_metadata=True,
            supports_reasoning_metadata=False,
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
                "Groq API key is not configured.",
                "Run 'settings provider groq' to configure your Groq API key.",
                provider="groq",
            )

        cfg = self.config
        selected_model = self.get_active_model()
        endpoint = cfg.custom_endpoint or "https://api.groq.com/openai/v1/chat/completions"
        timeout_sec = cfg.timeout or 60
        client_timeout = httpx.Timeout(connect=10.0, read=float(timeout_sec), write=10.0, pool=10.0)
        temp = temperature if temperature is not None else cfg.temperature
        max_tok = max_tokens if max_tokens is not None else cfg.max_tokens

        system = system_prompt or HORCRUX_EVIDENCE_POLICY
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ]

        payload = {
            "model": selected_model,
            "messages": messages,
            "temperature": temp,
            "max_tokens": max_tok,
        }

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
                            "Invalid Groq API key provided.",
                            "Check your key at https://console.groq.com/keys and update with 'settings provider groq'.",
                            provider="groq",
                            raw_status=status,
                        )
                    if status == 404 or (status == 400 and "model_not_found" in body_clean.lower()):
                        raise AIError(
                            AIErrorType.MODEL_UNAVAILABLE,
                            f"Groq model '{selected_model}' was not found or has been decommissioned.",
                            "Run 'settings models groq' to select an active model (e.g. llama-3.3-70b-versatile).",
                            provider="groq",
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
                            "Groq rate limit or TPM/RPM threshold reached.",
                            "Wait briefly or switch to another provider.",
                            provider="groq",
                            raw_status=status,
                        )
                    if status >= 500:
                        if attempt < max_attempts - 1:
                            time.sleep((attempt + 1) * 1.0)
                            continue
                        raise AIError(
                            AIErrorType.PROVIDER_UNAVAILABLE,
                            f"Groq service is temporarily unavailable (HTTP {status}).",
                            "Retry shortly or switch default provider.",
                            provider="groq",
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
                    f"Groq request timed out after {timeout_sec} seconds.",
                    "Increase timeout in settings or verify connection.",
                    provider="groq",
                )
            except (httpx.ConnectError, httpx.NetworkError) as net_err:
                if attempt < max_attempts - 1:
                    time.sleep(1.0)
                    continue
                err_type, msg, hint = self.normalize_error(net_err)
                raise AIError(err_type, msg, hint, provider="groq")
            except Exception as exc:
                err_type, msg, hint = self.normalize_error(exc)
                raise AIError(err_type, msg, hint, provider="groq")

        latency = time.perf_counter() - t0

        choices = data.get("choices", [])
        if not choices:
            raise AIError(
                AIErrorType.INVALID_RESPONSE,
                "Groq returned no completion choices.",
                provider="groq",
            )

        content = choices[0].get("message", {}).get("content", "").strip()
        finish_reason = choices[0].get("finish_reason", "")
        usage = data.get("usage", {})
        prompt_tokens = usage.get("prompt_tokens", 0)
        completion_tokens = usage.get("completion_tokens", 0)
        total_tokens = usage.get("total_tokens", prompt_tokens + completion_tokens)

        return AIResponse(
            content=content,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            model=selected_model,
            provider="groq",
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
            raise AIError(AIErrorType.AUTHENTICATION_FAILED, "Groq API key not configured.", provider="groq")

        cfg = self.config
        selected_model = self.get_active_model()
        endpoint = cfg.custom_endpoint or "https://api.groq.com/openai/v1/chat/completions"
        timeout_sec = cfg.timeout or 60
        client_timeout = httpx.Timeout(connect=10.0, read=float(timeout_sec), write=10.0, pool=10.0)

        system = (system_prompt or HORCRUX_EVIDENCE_POLICY) + "\n\nRespond ONLY with a valid JSON object matching the requested schema. No markdown formatting."
        payload = {
            "model": selected_model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "response_format": {"type": "json_object"},
            "temperature": temperature,
            "max_tokens": max_tokens or cfg.max_tokens,
        }
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

        return AIResponse(
            content=content,
            structured=extract_json_payload(content),
            prompt_tokens=usage.get("prompt_tokens", 0),
            completion_tokens=usage.get("completion_tokens", 0),
            total_tokens=usage.get("total_tokens", 0),
            model=selected_model,
            provider="groq",
            latency=round(latency, 2),
            raw_metadata=data,
        )

    def list_models(self) -> list[ModelInfo]:
        key = self.get_api_key()
        if not key:
            from horcrux.core.settings import AVAILABLE_MODELS
            return [ModelInfo(id=m, name=m, context_window=128000) for m in AVAILABLE_MODELS.get("groq", [])]

        try:
            headers = {"Authorization": f"Bearer {key}", "User-Agent": "Horcrux-AI/1.0"}
            with httpx.Client(timeout=httpx.Timeout(connect=5.0, read=8.0, write=5.0, pool=5.0)) as client:
                resp = client.get("https://api.groq.com/openai/v1/models", headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    models: list[ModelInfo] = []
                    for m in data.get("data", []):
                        m_id = m.get("id", "")
                        if m_id and not any(s in m_id.lower() for s in ["whisper", "tts", "embed"]):
                            ctx = m.get("context_window", 128000)
                            models.append(
                                ModelInfo(
                                    id=m_id,
                                    name=m_id,
                                    context_window=ctx,
                                    description=f"Groq LLM ({ctx:,} ctx)",
                                )
                            )
                    if models:
                        return models
        except Exception:
            pass

        from horcrux.core.settings import AVAILABLE_MODELS
        return [ModelInfo(id=m, name=m, context_window=128000) for m in AVAILABLE_MODELS.get("groq", [])]

    def stream(
        self,
        prompt: str,
        system_prompt: str = "",
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> Generator[str, None, None]:
        resp = self.complete(prompt, system_prompt=system_prompt, temperature=temperature, max_tokens=max_tokens)
        yield resp.content
