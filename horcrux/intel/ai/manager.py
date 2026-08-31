from __future__ import annotations

import logging
from typing import Any, Optional

from horcrux.core.settings import AVAILABLE_MODELS, SettingsManager
from horcrux.intel.ai.anthropic import AnthropicProvider
from horcrux.intel.ai.base import (
    AIError,
    AIErrorType,
    AIProvider,
    AIResponse,
    HORCRUX_EVIDENCE_POLICY,
    ModelInfo,
)
from horcrux.intel.ai.google import GoogleProvider
from horcrux.intel.ai.groq import GroqProvider
from horcrux.intel.ai.openai import OpenAIProvider
from horcrux.intel.cache import AICacheManager
from horcrux.models import Action, ExploitCandidate, WorkspaceState

logger = logging.getLogger("horcrux.ai")


class AIManager:
    """
    Central AI Manager for HORCRUX.
    Orchestrates provider selection, dynamic model discovery, multi-provider fallback,
    bounded token caching, usage tracking, and security reasoning tasks.
    """

    def __init__(self, settings_manager: SettingsManager | None = None):
        self.settings = settings_manager or SettingsManager()
        self.cache = AICacheManager(self.settings)
        self.providers: dict[str, AIProvider] = {
            "groq": GroqProvider(self.settings),
            "openai": OpenAIProvider(self.settings),
            "anthropic": AnthropicProvider(self.settings),
            "google": GoogleProvider(self.settings),
        }

    @property
    def is_enabled(self) -> bool:
        return self.settings.settings.enabled

    def get_provider(self, name: str | None = None) -> AIProvider | None:
        """Returns the requested provider if configured, or the default configured provider."""
        target_name = (name or self.settings.settings.default_provider).lower()
        provider = self.providers.get(target_name)
        if provider and provider.is_configured():
            return provider

        # Fallback to any configured provider
        for p in self.providers.values():
            if p.is_configured():
                return p
        return None

    def active_provider_name(self) -> str:
        p = self.get_provider()
        return p.name if p else "none"

    def get_available_models(self, provider_name: str) -> list[ModelInfo]:
        p = self.providers.get(provider_name.lower())
        if p:
            return p.list_models()
        return [ModelInfo(id=m, name=m) for m in AVAILABLE_MODELS.get(provider_name.lower(), [])]

    @property
    def stats(self):
        summary = self.cache.get_summary()
        class _Stats:
            def __init__(self, s):
                self.calls = s["total_calls"]
                self.cached_calls = s["total_cached_calls"]
                self.prompt_tokens = s["total_input_tokens"]
                self.completion_tokens = s["total_output_tokens"]
                self.reasoning_tokens = s["total_reasoning_tokens"]
                self.total_tokens = s["total_tokens"]
        return _Stats(summary)

    @property
    def _memory_cache(self) -> dict[str, Any]:
        return self.cache._cache

    def status(self) -> dict[str, Any]:


        p = self.get_provider()
        configured = p is not None
        model = p.config.model if p else "none"
        name = p.name if p else "none"
        status_label = "READY" if (configured and self.is_enabled) else ("DISABLED" if not self.is_enabled else "NOT CONFIGURED")

        usage = self.cache.get_summary()
        return {
            "enabled": self.is_enabled,
            "status": status_label,
            "provider": name,
            "model": model,
            "calls": usage["total_calls"],
            "cached_calls": usage["total_cached_calls"],
            "total_tokens": usage["total_tokens"],
            "input_tokens": usage["total_input_tokens"],
            "output_tokens": usage["total_output_tokens"],
            "reasoning_tokens": usage["total_reasoning_tokens"],
        }

    def clear_cache(self) -> None:
        self.cache.clear()

    def get_usage(self) -> dict[str, Any]:
        return self.cache.get_summary()

    def call_task(
        self,
        task_name: str,
        prompt: str,
        payload: Any = None,
        system_prompt: str = "",
        max_tokens: int | None = None,
        temperature: float = 0.1,
    ) -> AIResponse | None:
        """
        Executes an AI task with caching, multi-provider fallback, and usage accounting.
        """
        if not self.is_enabled:
            return None

        primary = self.get_provider()
        if not primary:
            return None

        # Build fallback provider candidates
        configured_fallbacks = [
            self.providers[p_name]
            for p_name in self.settings.settings.fallback_sequence
            if p_name in self.providers and p_name != primary.name and self.providers[p_name].is_configured()
        ]
        candidates = [primary] + configured_fallbacks

        # 1. Check cache using primary provider & model
        model = self.settings.get_model(primary.name)
        cached_resp = self.cache.get(primary.name, model, task_name, payload or prompt)
        if cached_resp:
            return cached_resp

        last_error = None
        for idx, provider in enumerate(candidates):
            curr_model = self.settings.get_model(provider.name)
            try:
                if idx > 0:
                    logger.info(f"[AI] Falling back to provider: {provider.name}")

                resp = provider.structured(
                    prompt,
                    system_prompt=system_prompt,
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
                if resp and (resp.content or resp.structured):
                    # Record in cache & usage
                    self.cache.put(provider.name, curr_model, task_name, payload or prompt, resp)
                    self.cache.record_usage(resp)
                    return resp
            except AIError as err:
                last_error = err
                # Only fail over on transient errors (rate limit, timeout, provider down)
                if err.error_type in (AIErrorType.RATE_LIMITED, AIErrorType.TIMEOUT, AIErrorType.PROVIDER_UNAVAILABLE, AIErrorType.NETWORK_ERROR):
                    continue
                else:
                    # Configuration or authentication error; do not silently try other providers
                    break
            except Exception as exc:
                last_error = exc
                continue

        return None

    # -----------------------------------------------------------------------
    # Delegated Security Analysis Tasks
    # -----------------------------------------------------------------------
    def triage_exploits(
        self,
        state: WorkspaceState,
        candidates: list[ExploitCandidate],
    ) -> list[ExploitCandidate]:
        from horcrux.intel.tasks.triage import execute_exploit_triage
        return execute_exploit_triage(self, state, candidates)

    def rank_actions(
        self,
        state: WorkspaceState,
        candidate_actions: list[Action],
    ) -> list[Action]:
        from horcrux.intel.tasks.actions import execute_action_reasoning
        return execute_action_reasoning(self, state, candidate_actions)

    def synthesize_attack_paths(
        self,
        state: WorkspaceState,
    ) -> list[dict]:
        from horcrux.intel.tasks.attack_path import execute_attack_path_synthesis
        return execute_attack_path_synthesis(self, state)

    def generate_executive_summary(
        self,
        state: WorkspaceState,
    ) -> str:
        from horcrux.intel.tasks.summarize import execute_executive_summary
        return execute_executive_summary(self, state)

    def complete(
        self,
        prompt: str,
        system_prompt: str = "",
        provider_name: str | None = None,
        use_cache: bool = True,
    ) -> AIResponse | None:
        if not self.is_enabled:
            return None
        provider = self.get_provider(provider_name)
        if not provider:
            return None
        model = self.settings.get_model(provider.name)
        if use_cache:
            cached = self.cache.get(provider.name, model, "complete", prompt)
            if cached:
                return cached
        try:
            resp = provider.complete(prompt, system_prompt=system_prompt)
            if use_cache:
                self.cache.put(provider.name, model, "complete", prompt, resp)
                self.cache.record_usage(resp)
            return resp
        except Exception:
            return None

    def ask(
        self,
        question: str | WorkspaceState,
        state: WorkspaceState | str | None = None,
    ) -> str:
        if isinstance(question, WorkspaceState):
            q_str = str(state or "")
            st = question
        elif isinstance(state, WorkspaceState):
            q_str = str(question or "")
            st = state
        else:
            q_str = str(question or "")
            st = WorkspaceState()
        from horcrux.intel.tasks.ask import execute_operator_ask
        return execute_operator_ask(self, q_str, st)

