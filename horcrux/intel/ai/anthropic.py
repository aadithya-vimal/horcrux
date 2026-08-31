from __future__ import annotations

import httpx

from horcrux.core.settings import DEFAULT_MODELS, SettingsManager
from horcrux.intel.ai.base import AIProvider, AIResponse, HORCRUX_EVIDENCE_POLICY


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
            raise ValueError("Anthropic API key is not configured.")

        cfg = self.config
        model = cfg.model or DEFAULT_MODELS["anthropic"]
        endpoint = cfg.custom_endpoint or "https://api.anthropic.com/v1/messages"
        timeout = cfg.timeout or 60
        temp = temperature if temperature is not None else cfg.temperature
        max_tok = max_tokens if max_tokens is not None else cfg.max_tokens

        system = system_prompt or HORCRUX_EVIDENCE_POLICY
        payload = {
            "model": model,
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

        with httpx.Client(timeout=timeout) as client:
            resp = client.post(endpoint, json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()

        content_blocks = data.get("content", [])
        text = "".join(b.get("text", "") for b in content_blocks if b.get("type") == "text").strip()

        usage = data.get("usage", {})
        prompt_tokens = usage.get("input_tokens", 0)
        completion_tokens = usage.get("output_tokens", 0)
        total_tokens = prompt_tokens + completion_tokens

        return AIResponse(
            content=text,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            model=model,
            provider="anthropic",
        )

    def fetch_models(self) -> list[str]:
        key = self.get_api_key()
        if not key:
            return self.models()
        try:
            headers = {
                "x-api-key": key,
                "anthropic-version": "2023-06-01",
                "User-Agent": "Horcrux-AI/1.0",
            }
            with httpx.Client(timeout=8) as client:
                resp = client.get("https://api.anthropic.com/v1/models", headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    ids = [m["id"] for m in data.get("data", []) if "id" in m]
                    if ids:
                        cur = self.config.model
                        res = [cur] if cur in ids else []
                        for m_id in sorted(ids):
                            if m_id not in res:
                                res.append(m_id)
                        return res
        except Exception:
            pass
        return self.models()
