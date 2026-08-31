from __future__ import annotations

from horcrux.core.settings import SettingsManager
from horcrux.intel.ai.base import AIResponse
from horcrux.intel.ai.groq import GroqProvider


def get_groq_provider(settings_manager: SettingsManager | None = None) -> GroqProvider:
    return GroqProvider(settings_manager or SettingsManager())


def query_groq(
    prompt: str,
    system_prompt: str = "",
    model: str | None = None,
    settings_manager: SettingsManager | None = None,
) -> AIResponse:
    provider = get_groq_provider(settings_manager)
    return provider.complete(prompt, system_prompt=system_prompt)
