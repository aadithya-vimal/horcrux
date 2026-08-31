from __future__ import annotations

import httpx

from horcrux.core.settings import DEFAULT_MODELS, SettingsManager
from horcrux.intel.ai.base import AIProvider, AIResponse, HORCRUX_EVIDENCE_POLICY


class GroqProvider(AIProvider):
    @property
    def name(self) -> str:
        return "groq"

    def complete(
        self,
        prompt: str,
        system_prompt: str = "",
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> AIResponse:
        key = self.get_api_key()
        if not key:
            raise ValueError("Groq API key is not configured.")

        cfg = self.config
        model = cfg.model or DEFAULT_MODELS["groq"]
        endpoint = cfg.custom_endpoint or "https://api.groq.com/openai/v1/chat/completions"
        timeout = cfg.timeout or 60
        temp = temperature if temperature is not None else cfg.temperature
        max_tok = max_tokens if max_tokens is not None else cfg.max_tokens

        system = system_prompt or HORCRUX_EVIDENCE_POLICY
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ]

        payload = {
            "model": model,
            "messages": messages,
            "temperature": temp,
            "max_tokens": max_tok,
        }

        headers = {
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "User-Agent": "Horcrux-AI/1.0",
        }

        with httpx.Client(timeout=timeout) as client:
            resp = client.post(endpoint, json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()

        choices = data.get("choices", [])
        if not choices:
            raise ValueError("Groq returned no completion choices.")

        content = choices[0].get("message", {}).get("content", "").strip()
        usage = data.get("usage", {})
        prompt_tokens = usage.get("prompt_tokens", 0)
        completion_tokens = usage.get("completion_tokens", 0)
        total_tokens = usage.get("total_tokens", prompt_tokens + completion_tokens)

        return AIResponse(
            content=content,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            model=model,
            provider="groq",
        )

    def fetch_models(self) -> list[str]:
        key = self.get_api_key()
        if not key:
            return self.models()
        try:
            headers = {"Authorization": f"Bearer {key}", "User-Agent": "Horcrux-AI/1.0"}
            with httpx.Client(timeout=8) as client:
                resp = client.get("https://api.groq.com/openai/v1/models", headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    ids = [m["id"] for m in data.get("data", []) if "id" in m and not m.get("id", "").startswith("whisper")]
                    if ids:
                        # Put current model or default at the top, then others
                        cur = self.config.model
                        res = [cur] if cur in ids else []
                        for m_id in sorted(ids):
                            if m_id not in res:
                                res.append(m_id)
                        return res
        except Exception:
            pass
        return self.models()
