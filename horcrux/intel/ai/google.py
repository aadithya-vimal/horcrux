from __future__ import annotations

import httpx

from horcrux.core.settings import DEFAULT_MODELS, SettingsManager
from horcrux.intel.ai.base import AIProvider, AIResponse, HORCRUX_EVIDENCE_POLICY


class GoogleProvider(AIProvider):
    @property
    def name(self) -> str:
        return "google"

    def complete(
        self,
        prompt: str,
        system_prompt: str = "",
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> AIResponse:
        key = self.get_api_key()
        if not key:
            raise ValueError("Google Gemini API key is not configured.")

        cfg = self.config
        model = cfg.model or DEFAULT_MODELS["google"]
        endpoint = (
            cfg.custom_endpoint
            or f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}"
        )
        if "{model}" in endpoint:
            endpoint = endpoint.replace("{model}", model)
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

        with httpx.Client(timeout=timeout) as client:
            resp = client.post(endpoint, json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()

        candidates = data.get("candidates", [])
        if not candidates:
            raise ValueError("Google Gemini returned no candidates.")

        parts = candidates[0].get("content", {}).get("parts", [])
        text = "".join(p.get("text", "") for p in parts).strip()

        usage = data.get("usageMetadata", {})
        prompt_tokens = usage.get("promptTokenCount", 0)
        completion_tokens = usage.get("candidatesTokenCount", 0)
        total_tokens = usage.get("totalTokenCount", prompt_tokens + completion_tokens)

        return AIResponse(
            content=text,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            model=model,
            provider="google",
        )

    def fetch_models(self) -> list[str]:
        key = self.get_api_key()
        if not key:
            return self.models()
        try:
            with httpx.Client(timeout=8) as client:
                resp = client.get(f"https://generativelanguage.googleapis.com/v1beta/models?key={key}")
                if resp.status_code == 200:
                    data = resp.json()
                    models = []
                    for m in data.get("models", []):
                        name = m.get("name", "")
                        methods = m.get("supportedGenerationMethods", [])
                        if "generateContent" in methods and "gemini" in name.lower():
                            clean = name.replace("models/", "")
                            models.append(clean)
                    if models:
                        cur = self.config.model
                        res = [cur] if cur in models else []
                        for m_id in sorted(models):
                            if m_id not in res:
                                res.append(m_id)
                        return res
        except Exception:
            pass
        return self.models()
