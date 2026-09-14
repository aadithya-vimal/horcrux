# Providers & Reasoning Cost

Provider-agnostic layer (`horcrux/intel/ai/`): Groq, OpenAI, Anthropic,
Google, OpenAI-compatible locals. `horcrux/intel/ai/capabilities.py`
registers model capabilities (structured output, tool calling, vision,
long context, reasoning, streaming, JSON schema).

Cost control (`select_reasoning_tier`): normalization, categorization,
dedup, extraction, and classification use cheap/deterministic paths;
business logic, authorization reasoning, contradictions, attack paths, and
hypothesis synthesis route to strong models. Every reasoning checkpoint
records provider, model, tier, reason, latency, and token counts
(`model_routing`); `summarize_ai_usage()` aggregates calls, tokens, and
tiers for `status` and reports.

Failures (`horcrux/intel/ai/failures.py`) are classified (authentication,
rate limit, quota, unavailable model, malformed output, timeout, network,
safety refusal, unsupported capability). Safety refusals are never retried
verbatim — the task is reframed around evidence and validation — and the
deterministic assessment always continues.
