from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Optional

from horcrux.core.settings import SettingsManager
from horcrux.models import Action, ExploitCandidate, WorkspaceState
from horcrux.intel.ai.anthropic import AnthropicProvider
from horcrux.intel.ai.base import AIProvider, AIResponse, HORCRUX_EVIDENCE_POLICY
from horcrux.intel.ai.google import GoogleProvider
from horcrux.intel.ai.groq import GroqProvider
from horcrux.intel.ai.openai import OpenAIProvider


@dataclass
class UsageStats:
    calls: int = 0
    cached_calls: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


class AIManager:
    def __init__(self, settings_manager: SettingsManager | None = None):
        self.settings = settings_manager or SettingsManager()
        self.providers: dict[str, AIProvider] = {
            "groq": GroqProvider(self.settings),
            "openai": OpenAIProvider(self.settings),
            "anthropic": AnthropicProvider(self.settings),
            "google": GoogleProvider(self.settings),
        }
        self.stats = UsageStats()
        self._memory_cache: dict[str, dict] = {}
        self._load_cache()

    @property
    def is_enabled(self) -> bool:
        return self.settings.settings.enabled

    def get_provider(self, name: str | None = None) -> AIProvider | None:
        target_name = (name or self.settings.settings.default_provider).lower()
        provider = self.providers.get(target_name)
        if provider and provider.is_configured():
            return provider

        # Fallback: first configured provider
        for p in self.providers.values():
            if p.is_configured():
                return p
        return None

    def active_provider_name(self) -> str:
        p = self.get_provider()
        return p.name if p else "none"

    def get_available_models(self, provider_name: str) -> list[str]:
        p = self.providers.get(provider_name.lower())
        if p:
            return p.fetch_models()
        return AVAILABLE_MODELS.get(provider_name.lower(), [])

    def status(self) -> dict[str, Any]:
        p = self.get_provider()
        configured = p is not None
        model = p.config.model if p else "none"
        name = p.name if p else "none"

        status_label = "READY" if (configured and self.is_enabled) else ("DISABLED" if not self.is_enabled else "NOT CONFIGURED")

        return {
            "enabled": self.is_enabled,
            "status": status_label,
            "provider": name,
            "model": model,
            "calls": self.stats.calls,
            "cached_calls": self.stats.cached_calls,
            "total_tokens": self.stats.total_tokens,
        }

    # -----------------------------------------------------------------------
    # Caching
    # -----------------------------------------------------------------------
    def _cache_key(self, provider_name: str, model: str, prompt: str, system_prompt: str) -> str:
        data = f"{provider_name}:{model}:{system_prompt}:{prompt}".encode("utf-8")
        return hashlib.sha256(data).hexdigest()

    def _load_cache(self) -> None:
        cache_path = self.settings.cache_file
        if cache_path.exists():
            try:
                self._memory_cache = json.loads(cache_path.read_text(encoding="utf-8"))
            except Exception:
                self._memory_cache = {}

    def _save_cache(self) -> None:
        cache_path = self.settings.cache_file
        try:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_text(json.dumps(self._memory_cache, indent=2), encoding="utf-8")
        except Exception:
            pass

    def clear_cache(self) -> None:
        self._memory_cache.clear()
        self._save_cache()

    # -----------------------------------------------------------------------
    # Core completion with caching & token budget
    # -----------------------------------------------------------------------
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

        model = provider.config.model
        ckey = self._cache_key(provider.name, model, prompt, system_prompt)

        if use_cache and ckey in self._memory_cache:
            entry = self._memory_cache[ckey]
            self.stats.cached_calls += 1
            return AIResponse(
                content=entry.get("content", ""),
                prompt_tokens=entry.get("prompt_tokens", 0),
                completion_tokens=entry.get("completion_tokens", 0),
                total_tokens=entry.get("total_tokens", 0),
                model=model,
                provider=provider.name,
            )

        try:
            resp = provider.complete(prompt, system_prompt=system_prompt)
            self.stats.calls += 1
            self.stats.prompt_tokens += resp.prompt_tokens
            self.stats.completion_tokens += resp.completion_tokens
            self.stats.total_tokens += resp.total_tokens

            if use_cache:
                self._memory_cache[ckey] = {
                    "content": resp.content,
                    "prompt_tokens": resp.prompt_tokens,
                    "completion_tokens": resp.completion_tokens,
                    "total_tokens": resp.total_tokens,
                }
                self._save_cache()

            return resp
        except Exception as exc:
            return None

    def structured(
        self,
        prompt: str,
        system_prompt: str = "",
        provider_name: str | None = None,
    ) -> Any:
        sys = (system_prompt or HORCRUX_EVIDENCE_POLICY) + "\n\nRespond ONLY with valid JSON. Do not include markdown code block formatting if possible."
        resp = self.complete(prompt, system_prompt=sys, provider_name=provider_name)
        if not resp or not resp.content:
            return None
        from horcrux.intel.ai.base import extract_json_payload
        return extract_json_payload(resp.content)

    # -----------------------------------------------------------------------
    # High-level Security Analysis Workflows
    # -----------------------------------------------------------------------
    def build_compact_state(self, state: WorkspaceState) -> dict[str, Any]:
        """Builds a token-efficient structured summary of the workspace state."""
        return {
            "target": state.target,
            "services": [
                {
                    "port": s.port,
                    "protocol": s.protocol,
                    "service": s.service,
                    "product": s.product,
                    "version": s.version,
                }
                for s in state.services
            ],
            "software": [
                {
                    "product": s.product,
                    "version": s.version,
                    "confidence": s.confidence,
                }
                for s in state.software
            ],
            "technologies": state.technologies[:15],
            "credentials": [
                {"username": c.username, "source": c.source, "kind": c.kind}
                for c in state.credentials
            ],
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "confidence": f.confidence,
                    "state": f.validation_state.value,
                }
                for f in state.findings
            ],
            "audited_checks": [
                {"asset": a.asset, "check": a.check_name, "status": a.status.value}
                for a in state.audit[:15]
            ],
        }

    def triage_exploits(
        self,
        state: WorkspaceState,
        candidates: list[ExploitCandidate],
    ) -> list[ExploitCandidate]:
        """Evaluates SearchSploit candidates against target context using AI."""
        if not candidates or not self.is_enabled or not self.get_provider():
            return candidates

        compact_state = self.build_compact_state(state)
        # Bounded subset: triage top 10 candidates
        candidates_to_triage = candidates[:10]
        payload = {
            "target_context": compact_state,
            "candidates": [
                {
                    "title": c.title,
                    "product": c.product,
                    "version": c.version,
                    "cve": c.cve,
                    "source": c.source,
                    "exploitability": c.exploitability,
                }
                for c in candidates_to_triage
            ],
        }

        prompt = f"""Evaluate the applicability of these exploit candidates against the discovered host environment.
Input:
{json.dumps(payload, indent=2)}

Return a JSON list of evaluations for each candidate in order:
[
  {{
    "decision": "HIGHLY_RELEVANT" | "POTENTIAL" | "REJECTED",
    "confidence": 0.0 to 1.0,
    "attack_type": "remote" | "local" | "dos",
    "reasoning": "string explaining exact technical match or contradiction",
    "missing_prerequisites": ["string"],
    "recommended_action": "concrete verification step"
  }}
]
"""
        result = self.structured(prompt)
        if isinstance(result, list) and len(result) == len(candidates_to_triage):
            for idx, eval_data in enumerate(result):
                cand = candidates_to_triage[idx]
                if isinstance(eval_data, dict):
                    cand.ai_triaged = True
                    cand.ai_decision = eval_data.get("decision", cand.relevance)
                    cand.confidence = float(eval_data.get("confidence", cand.confidence))
                    cand.relevance_reasoning = eval_data.get("reasoning", cand.relevance_reasoning)
                    cand.attack_type = eval_data.get("attack_type", cand.attack_type)
                    cand.missing_prerequisites = eval_data.get("missing_prerequisites", cand.missing_prerequisites)
                    if cand.ai_decision == "REJECTED":
                        cand.relevance = "REJECTED"
                    elif cand.ai_decision == "HIGHLY_RELEVANT":
                        cand.relevance = "CONFIRMED VERSION MATCH"

        return candidates

    def rank_actions(
        self,
        state: WorkspaceState,
        candidate_actions: list[Action],
    ) -> list[Action]:
        """Ranks candidate actions contextually based on observed evidence."""
        if not candidate_actions or not self.is_enabled or not self.get_provider():
            return sorted(candidate_actions, key=lambda a: -a.score)

        compact_state = self.build_compact_state(state)
        payload = {
            "target_state": compact_state,
            "candidate_actions": [
                {"id": a.id, "title": a.title, "initial_score": a.score, "reason": a.reason}
                for a in candidate_actions
            ],
        }

        prompt = f"""Given the authorized penetration testing evidence, prioritize and rank these candidate operator actions.
Evidence:
{json.dumps(payload, indent=2)}

Return a JSON array of ranked actions ordered highest priority first:
[
  {{
    "id": "<action_id>",
    "title": "<concise tactical action title>",
    "reason": "<technical prerequisite or evidence-backed rationale>",
    "score": 10 to 99
  }}
]
"""
        result = self.structured(prompt)
        if isinstance(result, list) and result:
            id_map = {a.id: a for a in candidate_actions}
            ranked = []
            for item in result:
                if isinstance(item, dict) and "id" in item and item["id"] in id_map:
                    act = id_map[item["id"]]
                    act.title = item.get("title", act.title)
                    act.reason = item.get("reason", act.reason)
                    act.score = float(item.get("score", act.score))
                    ranked.append(act)
            # Include any actions missing from AI response
            for a in candidate_actions:
                if a not in ranked:
                    ranked.append(a)
            return sorted(ranked, key=lambda x: -x.score)

        return sorted(candidate_actions, key=lambda a: -a.score)

    def synthesize_attack_paths(self, state: WorkspaceState) -> list[dict]:
        """Synthesizes plausible attack chains from observed evidence."""
        if not self.is_enabled or not self.get_provider():
            return []

        compact_state = self.build_compact_state(state)
        prompt = f"""Analyze this target's attack surface and construct plausible, evidence-grounded attack paths.
Every step MUST reference observed services, software, credentials, or findings. Do NOT invent vulnerabilities.

Evidence:
{json.dumps(compact_state, indent=2)}

Return a JSON list of attack paths:
[
  {{
    "name": "string",
    "probability": "HIGH" | "MEDIUM" | "LOW",
    "steps": [
      "1. Step description referencing evidence",
      "2. Next step description"
    ],
    "prerequisites": "string",
    "recommended_verification": "string"
  }}
]
"""
        result = self.structured(prompt)
        return result if isinstance(result, list) else []

    def ask(self, state: WorkspaceState, question: str) -> str:
        """Answers an operator's technical query given the current workspace state."""
        compact_state = self.build_compact_state(state)
        system = HORCRUX_EVIDENCE_POLICY

        prompt = f"""TARGET WORKSPACE CONTEXT:
{json.dumps(compact_state, indent=2)}

OPERATOR QUESTION:
"{question}"

Answer the question following the OBSERVATION -> REASONING -> RECOMMENDATION format. Be concise, tactical, and strictly evidence-grounded.
"""
        resp = self.complete(prompt, system_prompt=system)
        if resp and resp.content:
            return resp.content

        return "AI analysis unavailable. (Ensure an AI provider like Groq is configured via 'settings provider groq <key>' and AI is enabled)."

    def generate_executive_summary(self, state: WorkspaceState) -> str:
        """Generates an executive risk briefing for the engagement report."""
        compact_state = self.build_compact_state(state)
        prompt = f"""Write a concise, professional Executive Risk Summary for a penetration test assessment report against target {state.target}.
Highlight verified exposures, hardened controls, software inventory risk, and top priorities.
Do NOT invent unobserved vulnerabilities.

Scan Evidence:
{json.dumps(compact_state, indent=2)}

Write 2-3 focused paragraphs in Markdown.
"""
        resp = self.complete(prompt)
        if resp and resp.content:
            return resp.content
        return f"Reconnaissance and attack surface assessment completed against target {state.target}. Total services discovered: {len(state.services)}. Security findings: {len(state.findings)}. Audited controls: {len(state.audit)}."
