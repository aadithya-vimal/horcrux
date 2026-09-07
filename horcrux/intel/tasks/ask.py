from __future__ import annotations

import json
import re
from typing import Any, Optional
from horcrux.models import WorkspaceState
from horcrux.intel.tasks.triage import build_compact_state


def build_bounded_workspace_context(state: WorkspaceState, question: str, max_chars: int = 8000) -> dict[str, Any]:
    """
    Assembles prioritized, token-efficient workspace context adhering to strict token budgets.
    Prioritizes:
      1. Target identifier
      2. Confirmed & likely security findings (with full evidence)
      3. Open network services & protocols
      4. Validated software inventory
      5. Prioritized actions / recommendations
      6. Specific finding evidence (if mentioned in question)
      7. Web targets, parameters, and discovered paths
      8. Credentials (presence only, no raw secrets)
      9. Exploit candidates
    """
    # 1. Target
    ctx: dict[str, Any] = {
        "target": state.target,
    }

    # 2. Confirmed / likely findings with full evidence
    findings = []
    for f in state.findings:
        findings.append({
            "id": f.id,
            "title": f.title,
            "severity": f.severity.value,
            "confidence": round(f.confidence, 2),
            "validation_state": f.validation_state.value,
            "why_it_matters": f.why_it_matters[:200] if f.why_it_matters else "",
            "evidence": f.evidence[:4],
            "recommended_next_action": f.recommended_next_action[:150] if f.recommended_next_action else "",
        })
    ctx["findings"] = findings[:15]

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
    ctx["services"] = services[:25]

    # 4. Validated software
    software = []
    for sw in state.software:
        software.append({
            "product": sw.product,
            "version": sw.version,
            "confidence": round(sw.confidence, 2),
            "cpe": sw.cpe or "",
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

    # 6. Web targets & attack surface
    if state.web_targets:
        web_targets = []
        for wt in state.web_targets[:6]:
            web_targets.append({
                "port": wt.port,
                "app_type": wt.application_type.value,
                "baseline": wt.baseline_classification.value,
                "endpoints": [ep.path for ep in wt.endpoints[:12]],
                "technologies": [t.name for t in wt.technologies[:10]],
                "parameters": [p.name for p in wt.parameters[:10]],
            })
        ctx["web_targets"] = web_targets

    # 7. Credentials (presence only — no raw secrets exposed to AI)
    if state.credentials:
        ctx["credentials"] = [
            {"kind": c.kind, "username": c.username, "source": c.source}
            for c in state.credentials[:5]
        ]

    # 8. Exploit candidates (top 5 by confidence)
    if state.exploits:
        top_exploits = sorted(state.exploits, key=lambda e: e.confidence, reverse=True)[:5]
        ctx["exploit_candidates"] = [
            {
                "product": e.product,
                "version": e.version,
                "cve": e.cve,
                "title": e.title,
                "relevance": e.relevance,
                "confidence": round(e.confidence, 2),
            }
            for e in top_exploits
        ]

    # 9. Specific finding deep-dive if referenced by ID in question
    q_lower = question.lower()
    for f in state.findings:
        if f.id.lower() in q_lower:
            ctx["focused_finding"] = {
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value,
                "validation_state": f.validation_state.value,
                "evidence": f.evidence[:8],
                "reproduction": f.reproduction[:5],
                "impact": f.why_it_matters,
                "recommended_next_action": f.recommended_next_action,
            }
            break

    # Bound total size — trim collections proportionally
    serialized = json.dumps(ctx)
    if len(serialized) > max_chars:
        ctx["services"] = ctx["services"][:10]
        ctx["findings"] = ctx["findings"][:8]
        ctx["software"] = ctx["software"][:8]
        if "web_targets" in ctx:
            ctx["web_targets"] = ctx["web_targets"][:2]
        if "exploit_candidates" in ctx:
            ctx["exploit_candidates"] = ctx["exploit_candidates"][:3]

    return ctx


def _json_to_prose(data: Any, indent: int = 0) -> str:
    """
    Converts a JSON dict/list (from a structured AI response) into readable prose.
    Only called when the AI accidentally returns raw JSON instead of prose.
    """
    prefix = "  " * indent
    if isinstance(data, str):
        return data
    if isinstance(data, list):
        lines = []
        for item in data:
            if isinstance(item, (dict, list)):
                lines.append(_json_to_prose(item, indent + 1))
            else:
                lines.append(f"{prefix}• {item}")
        return "\n".join(lines)
    if isinstance(data, dict):
        lines = []
        FIELD_LABELS = {
            "finding": "Finding",
            "observation": "Observation",
            "assessment": "Assessment",
            "severity": "Severity",
            "confidence": "Confidence",
            "evidence": "Evidence",
            "impact": "Impact",
            "rationale": "Rationale",
            "attack_surface": "Attack Surface",
            "recommendation": "Recommendation",
            "next_action": "Next Action",
            "prerequisites": "Prerequisites",
            "limitations": "Limitations",
            "references": "References",
            "summary": "Summary",
            "title": "Title",
            "reason": "Reason",
        }
        for key, val in data.items():
            label = FIELD_LABELS.get(key, key.replace("_", " ").title())
            if isinstance(val, (dict, list)):
                lines.append(f"{prefix}**{label}:**")
                lines.append(_json_to_prose(val, indent + 1))
            else:
                lines.append(f"{prefix}**{label}:** {val}")
        return "\n".join(lines)
    return str(data)


def _ensure_prose(text: str) -> str:
    """
    If the AI returned raw JSON instead of prose, convert it to readable text.
    Otherwise return the original text unchanged.
    """
    stripped = text.strip()
    # Fast path: doesn't look like JSON
    if not (stripped.startswith("{") or stripped.startswith("[")):
        return text

    # Also check for fenced JSON blocks
    fence_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", stripped, re.I)
    json_str = fence_match.group(1) if fence_match else stripped

    try:
        parsed = json.loads(json_str)
        if isinstance(parsed, (dict, list)):
            return _json_to_prose(parsed)
    except (json.JSONDecodeError, ValueError):
        pass

    return text


_MARKDOWN_SYSTEM_PROMPT = """\
You are HORCRUX AI, an expert senior offensive-security reasoning analyst.

RESPONSE FORMAT RULES (CRITICAL):
1. Respond ONLY in well-formatted Markdown.
2. Use ## headings for major sections (Observation, Assessment, Recommendations, etc.)
3. Use bullet lists (- item) for evidence, findings, or enumerated points.
4. Use **bold** for key terms, CVEs, ports, services, and severity labels.
5. Use inline `code` for commands, paths, hostnames, and tool names.
6. Use fenced ```bash code blocks for multi-line reproduction commands.
7. Do NOT return JSON, XML, or raw dicts — always prose with Markdown structure.
8. Start with a brief 1-2 sentence summary of your assessment.

EVIDENCE RULES:
- Use ONLY the supplied workspace evidence. Never invent ports, versions, or CVEs.
- Clearly distinguish: CONFIRMED (active proof) / LIKELY (banner/correlation) / POTENTIAL (heuristic) / UNVERIFIED (not tested).
- If evidence is insufficient, state exactly what enumeration step is needed and why.
- Do NOT promote unverified evidence to CONFIRMED status.
"""

_MARKDOWN_SYSTEM_PROMPT_GENERAL = """\
You are HORCRUX AI, an expert senior offensive-security reasoning analyst and consultant.

RESPONSE FORMAT RULES (CRITICAL):
1. Respond ONLY in well-formatted Markdown.
2. Use ## headings for major sections.
3. Use bullet lists (- item) for enumerated points, techniques, or steps.
4. Use **bold** for key terms, tool names, CVEs, and protocols.
5. Use inline `code` for commands, flags, and filenames.
6. Use fenced ```bash code blocks for commands and payloads.
7. Do NOT return JSON — always return readable prose with Markdown structure.
8. Be concise, technically rigorous, and actionable.
"""


def execute_operator_ask(
    ai_manager,
    question: str,
    state: Optional[WorkspaceState] = None,
) -> str:
    """
    Answers operator queries.
    - If a target workspace is loaded: leverages bounded, structured workspace context.
    - If no workspace is loaded: acts as a general offensive security advisor.

    Always returns prose Markdown. If the AI returns JSON, it is converted to readable prose.
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
        # General offensive security assistant — no workspace required
        prompt = f"""You are the HORCRUX AI Offensive Security Analyst.
Answer the operator's question with technical authority, precision, and depth.
Cover attack techniques, defensive concepts, risk factors, or testing methodologies directly.
Format your response in Markdown with headings, bullets, bold terms, and code blocks.

Operator Question:
{question}
"""
        payload = {"question": question, "mode": "general"}
        resp = ai_manager.call_task(
            "operator_ask_general",
            prompt,
            payload=payload,
            system_prompt=_MARKDOWN_SYSTEM_PROMPT_GENERAL,
            max_tokens=2048,
            structured=False,
        )
        if resp and resp.content and resp.content.strip():
            return _ensure_prose(resp.content.strip())

        return (
            "[dim red]AI provider did not return a response.[/dim red]\n"
            "Check provider configuration with 'settings test' or switch provider with 'settings default'."
        )

    # Workspace-aware context assembly
    bounded_ctx = build_bounded_workspace_context(state, question)
    payload = {
        "question": question,
        "workspace_context": bounded_ctx,
    }

    evidence_schema = """EVIDENCE TAXONOMY (use in your analysis):
- **CONFIRMED**: Deterministically verified with active proof or command output.
- **LIKELY**: High-confidence correlation (e.g. exact software banner match).
- **POTENTIAL**: Heuristic or theoretical surface requiring active validation.
- **UNVERIFIED**: Untested hypothesis.
- **FALSE_POSITIVE**: Validated as non-vulnerable or hardened.

ANALYSIS RULES:
1. Base all analysis strictly on the provided workspace evidence below.
2. Label each claim with its evidence classification (CONFIRMED / LIKELY / POTENTIAL / UNVERIFIED).
3. Do not invent open ports, software versions, or vulnerabilities.
4. If context is insufficient, state exactly what enumeration step is needed next.
5. Format your full response in Markdown — headings, bullets, bold, code blocks.
"""

    prompt = f"""You are the HORCRUX AI Offensive Security Analyst advising an operator during an active engagement.

{evidence_schema}

## Workspace Evidence
```json
{json.dumps(bounded_ctx, indent=2)}
```

## Operator Question
{question}
"""
    resp = ai_manager.call_task(
        "operator_ask",
        prompt,
        payload=payload,
        system_prompt=_MARKDOWN_SYSTEM_PROMPT,
        max_tokens=2048,
        structured=False,
    )
    if resp and resp.content and resp.content.strip():
        return _ensure_prose(resp.content.strip())

    return (
        "[dim red]AI provider did not return a response.[/dim red]\n"
        "Check provider configuration with 'settings test' or switch provider with 'settings default'."
    )
