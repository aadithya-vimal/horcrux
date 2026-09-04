from __future__ import annotations

import json
from typing import Any, Optional
from horcrux.models import WorkspaceState
from horcrux.intel.tasks.triage import build_compact_state


def build_bounded_workspace_context(state: WorkspaceState, question: str, max_chars: int = 6000) -> dict[str, Any]:
    """
    Assembles prioritized, token-efficient workspace context adhering to strict token budgets.
    Prioritizes:
      1. Target identifier
      2. Confirmed & likely security findings
      3. Open network services & protocols
      4. Validated software inventory
      5. Prioritized actions / recommendations
      6. Specific finding evidence (if mentioned in question)
    """
    # 1. Target
    ctx: dict[str, Any] = {
        "target": state.target,
    }

    # 2. Confirmed / likely findings
    findings = []
    for f in state.findings:
        findings.append({
            "id": f.id,
            "title": f.title,
            "severity": f.severity.value,
            "validation_state": f.validation_state.value,
            "why_it_matters": f.why_it_matters[:150] if f.why_it_matters else "",
        })
    ctx["findings"] = findings[:12]

    # 3. Open network services
    services = []
    for s in state.services:
        services.append({
            "port": s.port,
            "protocol": s.protocol,
            "service": s.service,
            "product": s.product,
            "version": s.version,
        })
    ctx["services"] = services[:20]

    # 4. Validated software
    software = []
    for sw in state.software:
        software.append({
            "product": sw.product,
            "version": sw.version,
            "confidence": round(sw.confidence, 2),
        })
    ctx["software"] = software[:15]

    # 5. Audited security controls
    audit = []
    for a in state.audit[:8]:
        audit.append({
            "asset": a.asset,
            "check": a.check_name,
            "status": a.status.value,
        })
    ctx["audit"] = audit

    # 6. Specific finding deep-dive if referenced by ID in question
    q_lower = question.lower()
    for f in state.findings:
        if f.id.lower() in q_lower:
            ctx["focused_finding"] = {
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value,
                "validation_state": f.validation_state.value,
                "evidence": f.evidence[:5],
                "reproduction": f.reproduction[:3],
                "impact": f.why_it_matters,
            }
            break

    # Bound size
    serialized = json.dumps(ctx)
    if len(serialized) > max_chars:
        # Trim services and findings to fit
        ctx["services"] = ctx["services"][:10]
        ctx["findings"] = ctx["findings"][:6]
        ctx["software"] = ctx["software"][:8]

    return ctx


def execute_operator_ask(
    ai_manager,
    question: str,
    state: Optional[WorkspaceState] = None,
) -> str:
    """
    Answers operator queries.
    - If a target workspace is loaded: leverages bounded, structured workspace context.
    - If no workspace is loaded: acts as a general offensive security advisor.
    """
    if not ai_manager.is_enabled:
        return (
            "[dim yellow]AI assistant is currently disabled.[/dim yellow]\n"
            "Enable AI with 'ai enable' or configure a provider with 'settings'."
        )

    has_workspace = (
        state is not None
        and bool(state.target)
        and state.target != "ready"
        and (bool(state.services) or bool(state.findings) or bool(state.software))
    )

    if not has_workspace:
        # General offensive security assistant prompt (No workspace required)
        prompt = f"""You are the HORCRUX AI Offensive Security Analyst, an expert security consultant.
Answer the operator's question authoritatively, accurately, concisely, and with technical rigor.
Explain relevant attack techniques, defensive concepts, risk factors, or testing methodologies directly.

Operator Question:
{question}
"""
        payload = {"question": question, "mode": "general"}
        resp = ai_manager.call_task("operator_ask_general", prompt, payload=payload, max_tokens=1024)
        if resp and resp.content and resp.content.strip():
            return resp.content.strip()

        return (
            "[dim red]AI provider did not return a response.[/dim red]\n"
            "Check provider configuration with 'settings test' or switch provider with 'settings default'."
        )

    # Workspace-aware context assembly with strict token controls
    bounded_ctx = build_bounded_workspace_context(state, question)
    payload = {
        "question": question,
        "workspace_context": bounded_ctx,
    }

    evidence_schema = """EVIDENCE TAXONOMY:
- CONFIRMED: Deterministically verified with active proof/command output.
- LIKELY: High-confidence correlation (e.g. exact software banner match).
- POTENTIAL: Heuristic or theoretical surface requiring active validation.
- UNVERIFIED: Untested hypothesis.
- FALSE_POSITIVE: Validated as non-vulnerable or hardened.

RULES:
1. Base target analysis strictly on the provided workspace context.
2. Distinguish observed facts, inferences, and recommended actions.
3. Do not invent open ports, versions, or vulnerabilities.
4. If context is insufficient, state exactly what enumeration step is needed next.
"""

    prompt = f"""You are the HORCRUX AI Offensive Security Analyst advising an operator during an assessment.
{evidence_schema}

Workspace Context:
{json.dumps(bounded_ctx, indent=2)}

Operator Question:
{question}
"""
    resp = ai_manager.call_task("operator_ask", prompt, payload=payload, max_tokens=1024)
    if resp and resp.content and resp.content.strip():
        return resp.content.strip()

    return (
        "[dim red]AI provider did not return a response.[/dim red]\n"
        "Check provider configuration with 'settings test' or switch provider with 'settings default'."
    )
