from __future__ import annotations

import json
import re
from typing import Any, Optional
from horcrux.models import WorkspaceState
from horcrux.intel.tasks.triage import build_compact_state

try:
    from horcrux.intel.reasoning import build_semantic_context
except ImportError:
    build_semantic_context = None


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

    # Agentic application model summary (semantic, not raw scanner output)
    if build_semantic_context and (state.application_model or state.hypotheses):
        try:
            ctx["application_intelligence"] = json.loads(
                build_semantic_context(state)[:4000]
            )
        except Exception:
            pass

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


def _ask_with_grounding(ai_manager, question: str, state, structured_ctx: dict,
                        deterministic: str) -> str:
    """LLM enhancement grounded in selective workspace context + deterministic core."""
    import json as _json
    policy_prefix = ""
    try:
        policy_prefix = state.get_policy().format_ai_context(state.target) + "\n\n"
    except Exception:
        pass
    prompt = f"""{policy_prefix}You are the HORCRUX AI Offensive Security Analyst advising an operator.

## Selective workspace context (authoritative; do NOT invent outside it)
```json
{_json.dumps(structured_ctx, indent=2)[:6000]}
```

## Deterministic workspace-grounded draft (preserve its facts; improve prose)
{deterministic[:3000]}

## Operator Question
{question}

Respond in Markdown. Distinguish CONFIRMED / LIKELY / POTENTIAL / UNVERIFIED.
Never claim state changes; steering actions were already applied deterministically.
"""
    resp = ai_manager.call_task(
        "operator_ask",
        prompt,
        payload={"question": question, "workspace_context": structured_ctx},
        system_prompt=_MARKDOWN_SYSTEM_PROMPT,
        max_tokens=2048,
        structured=False,
    )
    if resp and resp.content and resp.content.strip():
        return _ensure_prose(resp.content.strip())
    if deterministic:
        # Preserve workspace grounding AND surface the provider diagnostic
        # so operators (and legacy fallback expectations) see next steps.
        try:
            diag = _format_failure_diagnostic(ai_manager)
        except Exception:
            diag = ""
        if diag:
            return deterministic + "\n\n---\n" + diag
        return deterministic
    return _format_failure_diagnostic(ai_manager)


def _format_failure_diagnostic(ai_manager) -> str:
    stage = getattr(ai_manager, "last_failure_stage", "") or "REQUEST_FAILED"
    diag = getattr(ai_manager, "last_diagnostic", "")
    last_err = getattr(ai_manager, "last_error", None)
    hint = getattr(last_err, "suggested_action", "") if last_err else ""

    lines = [
        f"[bold red]✖ AI generation failed[/bold red] [dim]({stage})[/dim]",
    ]
    if diag:
        lines.append(f"[dim white]Diagnostic: {diag}[/dim white]")
    if hint:
        lines.append(f"[dim yellow]Suggested Action: {hint}[/dim yellow]")
    lines.append("[dim]Run 'ai debug' or 'settings test' to inspect provider connection.[/dim]")
    return "\n".join(lines)


def execute_operator_ask(
    ai_manager,
    question: str,
    state: Optional[WorkspaceState] = None,
) -> str:
    """
    First-class operator interface over the live workspace.

    - Classifies intent (explanation / evidence / coverage / hypothesis /
      finding / investigation / prioritization / steering / validation).
    - Builds selective structured context (never a blind full dump).
    - Applies steering/investigation intents ONLY through typed,
      orchestrator-validated actions (LLM never mutates state).
    - Answers deterministically when AI is unavailable; otherwise the LLM
      enhances a workspace-grounded deterministic core.
    """
    # --- Structured ask plane (works without AI) ---
    _has_workspace_state = (
        state is not None and bool(state.target) and state.target != "ready"
        and (bool(state.services) or bool(state.findings) or bool(state.software)
             or bool(state.application_model) or bool(state.hypotheses)
             or bool(state.investigations) or bool(state.discovered_paths))
    )
    if _has_workspace_state:
        try:
            from horcrux.intel.ask_engine import (
                answer_deterministically,
                build_structured_context,
                plan_ask_actions,
                validate_and_apply_action,
            )
            actions = plan_ask_actions(state, question)
            action_notes: list[str] = []
            for act in actions:
                try:
                    res = validate_and_apply_action(state, act)
                    if res.get("applied"):
                        action_notes.append(f"- [action:{res['action']}] {res['detail']}")
                except Exception:
                    continue
            deterministic = answer_deterministically(state, question)
            if action_notes:
                deterministic += "\n\n**Applied actions:**\n" + "\n".join(action_notes)
            # AI unavailable -> deterministic answer is authoritative, with
            # a graceful notice preserving legacy fallback expectations.
            _prov = ai_manager.get_provider() if ai_manager.is_enabled else None
            _ai_ready = bool(_prov and _prov.is_configured())
            if not _ai_ready:
                notice = ("\n\n---\n[dim]AI analysis unavailable — showing workspace-grounded "
                          "assessment. Configure providers with 'settings'.[/dim]")
                # Return Markdown-first so console renders cleanly, while the
                # fallback substring remains detectable by automation/tests.
                return deterministic + notice
            # AI available -> enhance, grounded in structured context.
            structured_ctx = build_structured_context(state, question)
            return _ask_with_grounding(ai_manager, question, state, structured_ctx,
                                       deterministic)
        except Exception:
            pass  # fall through to legacy path

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

    policy_prefix = ""
    if state is not None:
        try:
            policy = state.get_policy()
            policy_prefix = policy.format_ai_context(state.target) + "\n\n"
        except Exception:
            pass

    if not has_workspace:
        # General offensive security assistant — no workspace required
        prompt = f"""{policy_prefix}You are the HORCRUX AI Offensive Security Analyst.
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

        return _format_failure_diagnostic(ai_manager)

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

    prompt = f"""{policy_prefix}You are the HORCRUX AI Offensive Security Analyst advising an operator during an active engagement.

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

    return _format_failure_diagnostic(ai_manager)
