"""Provider-agnostic model capability registry + task routing (Phase 7, Part 14)."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ModelCapabilities:
    model: str
    provider: str
    structured_output: bool = True
    tool_calling: bool = False
    vision: bool = False
    long_context: bool = False
    reasoning: bool = False
    streaming: bool = True
    json_schema: bool = False
    context_window: int = 0


_KNOWN: dict[str, ModelCapabilities] = {}


def _register_defaults() -> None:
    defaults = [
        ("groq", "llama-3.3-70b-versatile", True, False, False, True, False, True, True, 128000),
        ("openai", "gpt-4o-mini", True, True, True, True, False, True, True, 128000),
        ("openai", "gpt-4o", True, True, True, True, True, True, True, 128000),
        ("anthropic", "claude-3-5-sonnet-latest", True, True, True, True, True, True, False, 200000),
        ("google", "gemini-1.5-flash", True, True, True, True, False, True, True, 1000000),
        ("google", "gemini-1.5-pro", True, True, True, True, True, True, True, 2000000),
    ]
    for prov, model, structured, tools, vision, long_ctx, reasoning, stream, jschema, window in defaults:
        _KNOWN[f"{prov}:{model}"] = ModelCapabilities(
            model=model, provider=prov, structured_output=structured,
            tool_calling=tools, vision=vision, long_context=long_ctx,
            reasoning=reasoning, streaming=stream, json_schema=jschema,
            context_window=window)


_register_defaults()


def get_model_capabilities(provider: str, model: str) -> ModelCapabilities:
    key = f"{provider}:{model}"
    if key in _KNOWN:
        return _KNOWN[key]
    # Conservative default for unknown / local OpenAI-compatible models.
    return ModelCapabilities(model=model, provider=provider)


CHEAP_TASKS = {"evidence_normalization", "classification", "deduplication",
               "triage", "ranking"}
STRONG_TASKS = {"business_logic", "attack_path", "hypothesis_generation",
                "reasoning_after_hypothesis_creation", "reasoning_before_final_synthesis"}


def route_task(task: str, primary_provider: str, primary_model: str,
               fallback_provider: str = "", fallback_model: str = "") -> dict[str, str]:
    """Route cheap tasks to the cheap model, strong tasks to the strong model."""
    task_l = (task or "").lower()
    is_strong = any(k in task_l for k in
                    ("business", "attack_path", "hypothes", "synthesis", "reasoning"))
    if is_strong and fallback_model:
        return {"provider": fallback_provider or primary_provider,
                "model": fallback_model, "tier": "strong"}
    return {"provider": primary_provider, "model": primary_model,
            "tier": "cheap" if not is_strong else "strong"}


# --- Phase 8 reasoning cost control (Part 20) ---

# Checkpoints needing strong multi-step reasoning; everything else is cheap
# or fully deterministic (no model call at all for simple state queries).
STRONG_CHECKPOINTS = {"after_hypothesis_creation", "before_final_synthesis",
                      "after_investigation_completion"}
CHEAP_TASK_HINTS = ("normalization", "categorization", "deduplication",
                    "extraction", "classification", "triage", "ranking")


def select_reasoning_tier(task_name: str) -> tuple[str, str]:
    """Return (tier, reason) without invoking any model (deterministic-first)."""
    name = (task_name or "").lower()
    if any(h in name for h in CHEAP_TASK_HINTS):
        return "cheap", "normalization/classification task; cheap tier sufficient"
    if "reasoning_" in name:
        checkpoint = name.replace("reasoning_", "")
        if checkpoint in STRONG_CHECKPOINTS:
            return "strong", f"checkpoint {checkpoint} needs multi-step reasoning"
        return "cheap", f"checkpoint {checkpoint} is summarization-grade"
    if any(k in name for k in ("business", "attack_path", "hypothes", "contradiction")):
        return "strong", "multi-step authorization/business-logic reasoning"
    return "cheap", "default cheap tier"


def usage_record(provider: str, model: str, tier: str, latency_s: float,
                 prompt_tokens: int = 0, completion_tokens: int = 0,
                 success: bool = True, reason: str = "") -> dict[str, object]:
    """Structured AI usage entry for status/reporting aggregation."""
    total = (prompt_tokens or 0) + (completion_tokens or 0)
    return {"provider": provider, "model": model, "tier": tier,
            "reason": reason, "latency_s": round(latency_s, 3),
            "prompt_tokens": prompt_tokens or 0,
            "completion_tokens": completion_tokens or 0,
            "total_tokens": total, "success": success}


def summarize_ai_usage(workspace: Any = None, ai_manager: Any = None) -> dict[str, Any]:
    """Aggregate AI usage for status/reporting (Part 20).

    Combines structured reasoning records from the event log with the
    manager cache summary. Never raises.
    """
    summary: dict[str, Any] = {"calls": 0, "success": 0, "failed": 0,
                               "total_tokens": 0, "tiers": {}, "models": {}}
    try:
        if workspace is not None:
            from horcrux.intel.events import read_events
            for rec in read_events(workspace, limit=200,
                                   event_filter="AI_REASONING_COMPLETED"):
                d = rec.get("detail", {}) or {}
                summary["calls"] += 1
                summary["success" if d.get("success", True) else "failed"] += 1
                summary["total_tokens"] += int(d.get("total_tokens", 0) or 0)
                tier = str(d.get("tier", "unknown"))
                summary["tiers"][tier] = summary["tiers"].get(tier, 0) + 1
                model = str(d.get("model", "unknown")) or "unknown"
                summary["models"][model] = summary["models"].get(model, 0) + 1
    except Exception:
        pass
    try:
        if ai_manager is not None and hasattr(ai_manager, "get_usage"):
            usage = ai_manager.get_usage() or {}
            summary["cache_calls"] = usage.get("total_calls", 0)
            summary["cached_calls"] = usage.get("total_cached_calls", 0)
            summary["provider"] = getattr(ai_manager, "active_provider_name", lambda: "")()
    except Exception:
        pass
    return summary
