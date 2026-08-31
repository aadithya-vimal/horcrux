from __future__ import annotations

import json
from horcrux.models import WorkspaceState
from horcrux.intel.tasks.triage import build_compact_state


def execute_operator_ask(
    ai_manager,
    question: str,
    state: WorkspaceState,
) -> str:
    """
    Answers operator queries using bounded workspace context and strict evidence discipline.
    """
    if not ai_manager.is_enabled:
        return (
            "[dim yellow]AI assistant is currently disabled.[/dim yellow]\n"
            "Enable AI with 'ai enable' or configure a provider with 'settings'."
        )

    compact_state = build_compact_state(state)

    # Contextual check: if question mentions a specific finding ID, extract full detail
    specific_finding_ctx = None
    for f in state.findings:
        if f.id.lower() in question.lower():
            specific_finding_ctx = {
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value,
                "validation_state": f.validation_state.value,
                "evidence": f.evidence[:5],
                "reproduction": f.reproduction[:3],
                "impact": f.why_it_matters,
            }
            break

    payload = {
        "question": question,
        "target_context": compact_state,
        "specific_finding": specific_finding_ctx,
    }

    prompt = f"""You are the HORCRUX AI Offensive Security Analyst. Answer the operator's question.
Follow the STRICT EVIDENCE RULES:
1. Base your answer ONLY on the provided workspace state.
2. If the answer cannot be determined from the evidence, state what enumeration is missing.
3. Be direct, technical, and concise.

Context:
{json.dumps(payload, indent=2)}

Operator Question:
{question}
"""

    resp = ai_manager.call_task("operator_ask", prompt, payload=payload, max_tokens=1024)
    if resp and resp.content:
        return resp.content.strip()

    return (
        "[dim red]AI provider did not return a response.[/dim red]\n"
        "Check provider configuration with 'settings test' or switch provider with 'settings default'."
    )
