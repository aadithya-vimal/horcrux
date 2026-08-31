from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

from horcrux.core.settings import SettingsManager
from horcrux.intel.ai.base import AIResponse


@dataclass
class UsageRecord:
    provider: str
    model: str
    calls: int = 0
    cached_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    reasoning_tokens: int = 0
    total_tokens: int = 0
    total_latency: float = 0.0


class AICacheManager:
    """
    Manages bounded AI response caching and persistent token usage tracking.
    Never stores sensitive API keys.
    """

    def __init__(self, settings_manager: SettingsManager):
        self.settings = settings_manager
        self.cache_file = self.settings.cache_file
        self.usage_file = self.settings.usage_file
        self._cache: dict[str, dict[str, Any]] = {}
        self._usage: dict[str, dict[str, Any]] = {}
        self._load()

    def _load(self) -> None:
        if self.cache_file.exists():
            try:
                self._cache = json.loads(self.cache_file.read_text(encoding="utf-8"))
            except Exception:
                self._cache = {}
        if self.usage_file.exists():
            try:
                self._usage = json.loads(self.usage_file.read_text(encoding="utf-8"))
            except Exception:
                self._usage = {}

    def _save_cache(self) -> None:
        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            self.cache_file.write_text(json.dumps(self._cache, indent=2), encoding="utf-8")
        except Exception:
            pass

    def _save_usage(self) -> None:
        try:
            self.usage_file.parent.mkdir(parents=True, exist_ok=True)
            self.usage_file.write_text(json.dumps(self._usage, indent=2), encoding="utf-8")
        except Exception:
            pass

    def compute_key(self, provider: str, model: str, task: str, payload: Any) -> str:
        serialized = json.dumps(payload, sort_keys=True) if not isinstance(payload, str) else payload
        data = f"{provider}:{model}:{task}:{serialized}".encode("utf-8")
        return hashlib.sha256(data).hexdigest()

    def get(self, provider: str, model: str, task: str, payload: Any) -> AIResponse | None:
        key = self.compute_key(provider, model, task, payload)
        entry = self._cache.get(key)
        if entry:
            self.record_hit(provider, model)
            return AIResponse(
                content=entry.get("content", ""),
                structured=entry.get("structured"),
                prompt_tokens=entry.get("prompt_tokens", 0),
                completion_tokens=entry.get("completion_tokens", 0),
                reasoning_tokens=entry.get("reasoning_tokens", 0),
                total_tokens=entry.get("total_tokens", 0),
                model=model,
                provider=provider,
                cached=True,
            )
        return None

    def put(self, provider: str, model: str, task: str, payload: Any, response: AIResponse) -> None:
        key = self.compute_key(provider, model, task, payload)
        self._cache[key] = {
            "content": response.content,
            "structured": response.structured,
            "prompt_tokens": response.prompt_tokens,
            "completion_tokens": response.completion_tokens,
            "reasoning_tokens": response.reasoning_tokens,
            "total_tokens": response.total_tokens,
            "cached_at": time.time(),
        }
        self._save_cache()

    def record_usage(self, response: AIResponse) -> None:
        p_key = f"{response.provider}:{response.model}"
        if p_key not in self._usage:
            self._usage[p_key] = {
                "provider": response.provider,
                "model": response.model,
                "calls": 0,
                "cached_calls": 0,
                "input_tokens": 0,
                "output_tokens": 0,
                "reasoning_tokens": 0,
                "total_tokens": 0,
                "total_latency": 0.0,
            }
        rec = self._usage[p_key]
        rec["calls"] += 1
        rec["input_tokens"] += response.prompt_tokens
        rec["output_tokens"] += response.completion_tokens
        rec["reasoning_tokens"] += response.reasoning_tokens
        rec["total_tokens"] += response.total_tokens
        rec["total_latency"] += response.latency
        self._save_usage()

    def record_hit(self, provider: str, model: str) -> None:
        p_key = f"{provider}:{model}"
        if p_key not in self._usage:
            self._usage[p_key] = {
                "provider": provider,
                "model": model,
                "calls": 0,
                "cached_calls": 0,
                "input_tokens": 0,
                "output_tokens": 0,
                "reasoning_tokens": 0,
                "total_tokens": 0,
                "total_latency": 0.0,
            }
        self._usage[p_key]["cached_calls"] += 1
        self._save_usage()


    def clear(self) -> None:
        self._cache.clear()
        self._save_cache()

    def get_summary(self) -> dict[str, Any]:
        total_calls = sum(r.get("calls", 0) for r in self._usage.values())
        total_cached = sum(r.get("cached_calls", 0) for r in self._usage.values())
        total_in = sum(r.get("input_tokens", 0) for r in self._usage.values())
        total_out = sum(r.get("output_tokens", 0) for r in self._usage.values())
        total_reasoning = sum(r.get("reasoning_tokens", 0) for r in self._usage.values())
        total_tokens = sum(r.get("total_tokens", 0) for r in self._usage.values())

        return {
            "total_calls": total_calls,
            "total_cached_calls": total_cached,
            "total_input_tokens": total_in,
            "total_output_tokens": total_out,
            "total_reasoning_tokens": total_reasoning,
            "total_tokens": total_tokens,
            "by_model": self._usage,
        }
