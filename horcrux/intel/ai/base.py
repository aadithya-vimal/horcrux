from __future__ import annotations

import abc
import json
import re
from dataclasses import dataclass
from typing import Any, Optional

from horcrux.core.settings import AVAILABLE_MODELS, DEFAULT_MODELS, ProviderConfig, SettingsManager


HORCRUX_EVIDENCE_POLICY = """You are HORCRUX AI, an expert senior offensive-security reasoning analyst.
STRICT EVIDENCE RULES:
1. Use ONLY supplied evidence from the operator's workspace.
2. Do NOT invent versions, services, credentials, CVEs, exploit success, or vulnerabilities.
3. Clearly distinguish direct observation from inference.
4. If evidence is insufficient or ambiguous, explicitly state that.
5. Never promote unverified evidence or hypothetical exploits to CONFIRMED status without deterministic evidence.
6. Present reasoning using the structure:
   OBSERVATION: <exact evidence from scan>
   REASONING: <technical impact or prerequisite check>
   RECOMMENDATION: <prioritized, actionable next step>
"""


def extract_json_payload(text: str) -> Any:
    """Robustly extracts JSON object or array from LLM response text."""
    text = text.strip()
    if not text:
        return {}

    # Check for fenced code block ```json ... ```
    match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text, re.I)
    if match:
        candidate = match.group(1).strip()
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass

    # Find outermost { ... } or [ ... ]
    first_brace = text.find("{")
    first_bracket = text.find("[")
    
    start_pos = -1
    end_char = ""
    if first_brace != -1 and (first_bracket == -1 or first_brace < first_bracket):
        start_pos = first_brace
        end_char = "}"
    elif first_bracket != -1:
        start_pos = first_bracket
        end_char = "]"

    if start_pos != -1:
        end_pos = text.rfind(end_char)
        if end_pos > start_pos:
            candidate = text[start_pos : end_pos + 1]
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                pass

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"raw": text}


@dataclass
class AIResponse:
    content: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    model: str = ""
    provider: str = ""


class AIProvider(abc.ABC):
    def __init__(self, settings_manager: SettingsManager):
        self.settings = settings_manager

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Provider name, e.g. 'groq', 'openai', 'anthropic', 'google'."""
        pass

    @property
    def config(self) -> ProviderConfig:
        return self.settings.settings.providers.get(
            self.name,
            ProviderConfig(name=self.name, model=DEFAULT_MODELS.get(self.name, "")),
        )

    def get_api_key(self) -> str:
        return self.settings.get_api_key(self.name)

    def is_configured(self) -> bool:
        return bool(self.get_api_key())

    def models(self) -> list[str]:
        return AVAILABLE_MODELS.get(self.name, [self.config.model])

    @abc.abstractmethod
    def complete(
        self,
        prompt: str,
        system_prompt: str = "",
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> AIResponse:
        """Send completion request to provider."""
        pass

    def structured(
        self,
        prompt: str,
        system_prompt: str = "",
        temperature: float = 0.1,
        max_tokens: int = 2048,
    ) -> Any:
        """Helper to get and parse JSON response from LLM."""
        sys = (system_prompt or HORCRUX_EVIDENCE_POLICY) + "\n\nRespond ONLY with valid JSON."
        resp = self.complete(prompt, system_prompt=sys, temperature=temperature, max_tokens=max_tokens)
        return extract_json_payload(resp.content)

    def validate_key(self) -> tuple[bool, str]:
        """Test API key with a minimal completion request."""
        if not self.is_configured():
            return False, "No API key configured"
        try:
            resp = self.complete("Say ok in one word.", max_tokens=10)
            if resp and resp.content:
                return True, "API connection verified successfully"
            return False, "Received empty response from provider"
        except Exception as exc:
            return False, f"API test failed: {exc}"
