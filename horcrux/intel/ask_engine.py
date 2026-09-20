"""First-class operator interface for `ask` (Phase 7, Part 3).

`ask` is NOT question -> generic LLM response. It operates over the actual
workspace: intent classification (A-I), selective structured context,
deterministic answers, and typed state-changing actions validated by the
orchestrator. The LLM may enhance prose but NEVER mutates state directly.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class AskIntent(str, Enum):
    EXPLANATION = "explanation"  # A / EXPLAIN
    EVIDENCE_LOOKUP = "evidence_lookup"  # B / EVIDENCE
    COVERAGE_GAP = "coverage_gap"  # C / GAP_ANALYSIS
    HYPOTHESIS_ANALYSIS = "hypothesis_analysis"  # D / HYPOTHESIS
    FINDING_ANALYSIS = "finding_analysis"  # E / FINDING
    INVESTIGATION_REQUEST = "investigation_request"  # F / INVESTIGATE
    PRIORITIZATION = "prioritization"  # G / PRIORITIZE
    OPERATOR_STEERING = "operator_steering"  # H / STEER
    MANUAL_VALIDATION = "manual_validation"  # I / MANUAL_GUIDANCE
    REPORT = "report"  # REPORT
    STATUS = "status"  # STATUS


# Deterministic-first router aliases (Part 19 supported classes).
INTENT_ALIASES = {
    "EXPLAIN": AskIntent.EXPLANATION,
    "EVIDENCE": AskIntent.EVIDENCE_LOOKUP,
    "GAP_ANALYSIS": AskIntent.COVERAGE_GAP,
    "HYPOTHESIS": AskIntent.HYPOTHESIS_ANALYSIS,
    "FINDING": AskIntent.FINDING_ANALYSIS,
    "INVESTIGATE": AskIntent.INVESTIGATION_REQUEST,
    "PRIORITIZE": AskIntent.PRIORITIZATION,
    "STEER": AskIntent.OPERATOR_STEERING,
    "REPORT": AskIntent.REPORT,
    "STATUS": AskIntent.STATUS,
    "MANUAL_GUIDANCE": AskIntent.MANUAL_VALIDATION,
}


class AskActionType(str, Enum):
    EXPLAIN_FINDING = "explain_finding"
    INSPECT_EVIDENCE = "inspect_evidence"
    INSPECT_GAP = "inspect_gap"
    CREATE_INVESTIGATION = "create_investigation"
    REPRIORITIZE_INVESTIGATION = "reprioritize_investigation"
    SET_OPERATOR_FOCUS = "set_operator_focus"
    PAUSE_ASSESSMENT = "pause_assessment"
    RESUME_ASSESSMENT = "resume_assessment"
    SKIP_INVESTIGATION = "skip_investigation"
    REQUEST_OPERATOR_APPROVAL = "request_operator_approval"


class AskAction(BaseModel):
    action: AskActionType
    args: dict[str, Any] = Field(default_factory=dict)
    rationale: str = ""


def classify_ask_intent(question: str) -> AskIntent:
    """Deterministic-first intent router (Part 19). LLM only for ambiguity."""
    q = (question or "").lower().strip()
    # State-delta questions route to STATUS with a delta flag handled by answers.
    if re.search(r"\bwhat changed\b|\bwhat('s| is) new\b|\bsince last\b|\bdelta\b|\bprogress\b", q):
        return AskIntent.STATUS
    if re.search(r"\bstatus\b|\bwhere are we\b|\bstate of\b|\bsummar(y|ize).*(assessment|progress|state)\b", q):
        return AskIntent.STATUS
    if re.search(r"\breport\b|\bwrite.?up\b|\bdocument\b.*\b(assessment|finding)\b", q):
        return AskIntent.REPORT
    if re.search(r"\bstop\b|\bpause\b|\bhold\b", q):
        return AskIntent.OPERATOR_STEERING
    if re.search(r"\bresume\b|\bcontinue\b", q):
        return AskIntent.OPERATOR_STEERING
    if re.search(r"\bfocus\b|\bprioritize\b|\bprioritise\b|\bconcentrate\b", q):
        return AskIntent.OPERATOR_STEERING if "focus" in q else AskIntent.PRIORITIZATION
    if re.search(r"\bskip\b|\bignore\b|\bdepriorit", q):
        return AskIntent.OPERATOR_STEERING
    if re.search(r"\binvestigat\w*\b|\btest\b|\bcheck\b|\bprobe\b|\bscan\b", q):
        return AskIntent.INVESTIGATION_REQUEST
    if re.search(r"\bnot tested\b|\bnot covered\b|\bgap\b|\bmissing\b|\bwhat.*left\b|\bwhat.*next\b", q):
        return AskIntent.COVERAGE_GAP
    if re.search(r"\bwhy\b.*\b(likely|finding|confidence|severity)\b|\bwhy\b", q):
        return AskIntent.FINDING_ANALYSIS
    if re.search(r"\bhypothes\w*\b|\bbola\b|\bidor\b", q):
        return AskIntent.HYPOTHESIS_ANALYSIS
    if re.search(r"\bevidence\b|\bshow me\b|\bprove\b|\bsupport\b", q):
        return AskIntent.EVIDENCE_LOOKUP
    if re.search(r"\bfinding\b|\bvulnerab\w*\b|\bexploit\b", q):
        return AskIntent.FINDING_ANALYSIS
    if re.search(r"\bhow (do|to|can) i (validat|verif|test|confirm)\b|\bmanual\b|\breproduc\w*\b", q):
        return AskIntent.MANUAL_VALIDATION
    if re.search(r"\bprioriti[sz]\w*\b|\bmost important\b|\bhighest value\b|\border\b", q):
        return AskIntent.PRIORITIZATION
    return AskIntent.EXPLANATION


def build_structured_context(state: Any, question: str,
                             max_items: int = 8) -> dict[str, Any]:
    """Select relevant semantic context based on the question (never full dump)."""
    intent = classify_ask_intent(question)
    q = (question or "").lower()
    app = state.get_application_model()
    ctx: dict[str, Any] = {"target": state.target, "intent": intent.value}
    summary = app.summary()
    ctx["application"] = {"type": summary["application"]["type"],
                          "framework": summary["application"]["framework"],
                          "endpoints": summary["endpoints"],
                          "object_bearing": summary["object_bearing_endpoints"],
                          "admin": summary["admin_endpoints"]}
    if intent in (AskIntent.EVIDENCE_LOOKUP, AskIntent.HYPOTHESIS_ANALYSIS,
                  AskIntent.FINDING_ANALYSIS, AskIntent.EXPLANATION):
        # Focused finding/hypothesis retrieval.
        fmatch = _match_finding(state, q)
        if fmatch is not None:
            ctx["finding"] = {"id": fmatch.id, "title": fmatch.title,
                              "severity": fmatch.severity.value,
                              "validation_state": fmatch.validation_state.value,
                              "confidence": fmatch.confidence,
                              "evidence": fmatch.evidence[:8],
                              "reproduction": fmatch.reproduction[:5],
                              "why": fmatch.why_it_matters,
                              "next": fmatch.recommended_next_action}
        hmatch = _match_hypothesis(state, q)
        if hmatch is not None:
            ctx["hypothesis"] = {"id": hmatch.id, "title": hmatch.title,
                                 "class": hmatch.hypothesis_class.value,
                                 "status": hmatch.status.value,
                                 "confidence": hmatch.confidence,
                                 "evidence_refs": hmatch.evidence_refs[:8],
                                 "validation": hmatch.validation_requirements,
                                 "assumptions": hmatch.assumptions}
        else:
            ctx["hypotheses"] = [{"id": h.id, "title": h.title,
                                  "status": h.status.value, "confidence": h.confidence}
                                 for h in state.get_hypotheses()[:max_items]]
        if intent == AskIntent.EVIDENCE_LOOKUP and hmatch is not None:
            ctx["endpoints"] = [{"path": e.path, "sources": e.sources,
                                 "evidence_refs": e.evidence_refs[:4]}
                                for e in app.endpoints
                                if e.id in (hmatch.asset_refs or [])][:max_items]
    if intent in (AskIntent.COVERAGE_GAP, AskIntent.PRIORITIZATION,
                  AskIntent.INVESTIGATION_REQUEST, AskIntent.EXPLANATION,
                  AskIntent.REPORT, AskIntent.STATUS):
        cov = state.get_security_coverage()
        try:
            cov.ensure_domains()
            ctx["coverage"] = {d: dc.status.value for d, dc in cov.domains.items()}
            ctx["coverage_pct"] = cov.percentage_complete()
        except Exception:
            ctx["coverage"] = {}
        invs = state.get_investigations()
        ctx["investigations"] = [{"id": i.id, "objective": i.objective,
                                  "state": i.state.value,
                                  "priority": round(i.priority, 3),
                                  "specialist": i.specialist}
                                 for i in invs[:max_items]]
        skipped = getattr(state.operator_focus, "skip_investigation_ids", [])
        if skipped:
            ctx["skipped"] = skipped[:10]
    if intent == AskIntent.MANUAL_VALIDATION:
        fmatch = _match_finding(state, q)
        if fmatch is not None:
            ctx["validation"] = {"finding": fmatch.id, "reproduction": fmatch.reproduction,
                                 "evidence": fmatch.evidence[:6],
                                 "prerequisites": ["Operator authorization", "Scoped access"]}
    if intent == AskIntent.OPERATOR_STEERING:
        ctx["operator_focus"] = state.operator_focus.model_dump() \
            if hasattr(state.operator_focus, "model_dump") else dict(state.operator_focus)
        ctx["assessment_phase"] = getattr(state, "assessment_phase", "")
    # Always include compact attack-path + handoff counts (cheap).
    paths = getattr(state, "attack_paths", []) or []
    ctx["attack_paths"] = len(paths)
    # Attack-path explanation: include nodes/edges/evidence/assumptions.
    if "attack path" in q or "attack-path" in q:
        ctx["attack_path_detail"] = [
            {"name": p.get("name"), "probability": p.get("probability"),
             "status": p.get("status", "HYPOTHESIS"),
             "finding_ids": p.get("finding_ids", []),
             "hypothesis_id": p.get("hypothesis_id", ""),
             "investigation_ids": p.get("investigation_ids", []),
             "validation": p.get("validation_state"),
             "nodes": [(n.get("node_type"), n.get("label"), n.get("status", ""),
                        n.get("finding_id", "")) for n in p.get("nodes", [])],
             "edges": [{"type": e.get("edge_type"), "evidence": e.get("evidence", [])[:3],
                        "security_evidence": e.get("security_evidence", False),
                        "inference": e.get("inference", False)} for e in p.get("edges", [])],
             "assumptions": p.get("assumptions", []),
             "rank_why": p.get("rank_why", "")}
            for p in paths[:3]]
    ctx["handoffs"] = len(getattr(state, "exploit_handoffs", []) or [])
    ctx["identities"] = [i.role.value for i in app.identities][:5]
    if intent in (AskIntent.STATUS, AskIntent.REPORT):
        ctx["phase"] = getattr(state, "assessment_phase", "")
        ctx["focus"] = state.operator_focus.model_dump() \
            if hasattr(state.operator_focus, "model_dump") else {}
        try:
            from horcrux.intel.events import snapshot_counts, state_delta
            hist = (getattr(state, "scheduler_state", {}) or {}).get("history", [])
            ctx["current_counts"] = snapshot_counts(state)
            if len(hist) >= 2:
                ctx["delta"] = state_delta(hist[-2], hist[-1])
            elif hist:
                ctx["delta"] = state_delta(hist[-1], ctx["current_counts"])
        except Exception:
            pass
    return ctx


def _match_finding(state: Any, q: str) -> Any | None:
    for f in getattr(state, "findings", []):
        if f.id.lower() in q or q in f.id.lower() or q in f.title.lower():
            return f
    # Keyword fallback: bola/authorization/admin.
    for f in getattr(state, "findings", []):
        title = f.title.lower()
        if ("bola" in q or "idor" in q) and ("author" in title or "object" in title):
            return f
        if "admin" in q and "admin" in title:
            return f
    return None


def _match_hypothesis(state: Any, q: str) -> Any | None:
    hyps = state.get_hypotheses() if hasattr(state, "get_hypotheses") else []
    for h in hyps:
        if h.id.lower() in q:
            return h
    for h in hyps:
        title = h.title.lower()
        if ("bola" in q or "idor" in q) and "object" in title:
            return h
        if "admin" in q and "privileg" in title:
            return h
        if "business logic" in q and "business" in title:
            return h
        if "graphql" in q and "graphql" in title:
            return h
    if hyps and any(k in q for k in ("this hypothesis", "the hypothesis")):
        return hyps[0]
    return None


def plan_ask_actions(state: Any, question: str) -> list[AskAction]:
    """Derive typed, orchestrator-validated actions from steering/investigation intents."""
    q = (question or "").lower()
    actions: list[AskAction] = []
    # Stop / pause.
    if re.search(r"\bstop\b\.?$|\bpause\b", q) and "resume" not in q:
        actions.append(AskAction(action=AskActionType.PAUSE_ASSESSMENT,
                                 rationale="Operator requested stop/pause"))
        return actions
    if re.search(r"\bresume\b", q):
        actions.append(AskAction(action=AskActionType.RESUME_ASSESSMENT,
                                 rationale="Operator requested resume"))
        return actions
    # Focus steering.
    m = re.search(r"focus\s+(?:on\s+)?([a-z\- ]+)", q)
    if m:
        area = m.group(1).strip()
        actions.append(AskAction(action=AskActionType.SET_OPERATOR_FOCUS,
                                 args={"focus_area": area},
                                 rationale=f"Operator focus: {area}"))
        return actions
    # Skip.
    m = re.search(r"skip\s+(\S+)", q)
    if m:
        actions.append(AskAction(action=AskActionType.SKIP_INVESTIGATION,
                                 args={"investigation_ref": m.group(1)},
                                 rationale="Operator requested skip"))
        return actions
    # Prioritize.
    m = re.search(r"prioritize\s+(\S+)", q)
    if m:
        actions.append(AskAction(action=AskActionType.REPRIORITIZE_INVESTIGATION,
                                 args={"investigation_ref": m.group(1)},
                                 rationale="Operator requested prioritization"))
        return actions
    # Investigation request -> create/reprioritize.
    if classify_ask_intent(question) == AskIntent.INVESTIGATION_REQUEST:
        target_area = ""
        for key in ("authorization", "order", "admin", "graphql", "upload",
                    "business logic", "auth", "api", "injection", "ssrf"):
            if key in q:
                target_area = key
                break
        actions.append(AskAction(action=AskActionType.CREATE_INVESTIGATION,
                                 args={"area": target_area or question[:80]},
                                 rationale="Operator requested investigation"))
    return actions


def validate_and_apply_action(state: Any, action: AskAction,
                              workspace: Any = None) -> dict[str, Any]:
    """Orchestrator-validated state mutation. LLM never mutates directly."""
    from horcrux.intel.investigations import Investigation, InvestigationState
    kind = action.action
    if kind == AskActionType.PAUSE_ASSESSMENT:
        state.operator_focus.paused = True
        return {"applied": True, "action": kind.value, "detail": "Assessment paused; running subprocess cleanup allowed, no new work scheduled."}
    if kind == AskActionType.RESUME_ASSESSMENT:
        state.operator_focus.paused = False
        state.operator_focus.stopped = False
        return {"applied": True, "action": kind.value, "detail": "Assessment resumed."}
    if kind == AskActionType.SET_OPERATOR_FOCUS:
        area = str(action.args.get("focus_area", "")).lower()
        mapping = {"web": "web", "api": "api", "auth": "auth",
                   "authz": "authz", "authorization": "authz",
                   "business-logic": "business_logic", "business logic": "business_logic",
                   "network": "network", "all": "all", "": "all"}
        normalized = "all"
        for key, val in mapping.items():
            if key and key in area:
                normalized = val
                break
        state.operator_focus.focus_type = "area"
        state.operator_focus.focus_id = normalized
        _apply_focus_boost(state, normalized)
        return {"applied": True, "action": kind.value, "detail": f"Operator focus set to '{normalized}'."}
    if kind == AskActionType.SKIP_INVESTIGATION:
        ref = str(action.args.get("investigation_ref", ""))
        inv = _resolve_investigation(state, ref)
        if inv is None:
            return {"applied": False, "action": kind.value,
                    "detail": f"No investigation matching '{ref}'."}
        if inv.id not in state.operator_focus.skip_investigation_ids:
            state.operator_focus.skip_investigation_ids.append(inv.id)
        return {"applied": True, "action": kind.value, "detail": f"Investigation '{inv.objective[:60]}' skipped."}
    if kind == AskActionType.REPRIORITIZE_INVESTIGATION:
        ref = str(action.args.get("investigation_ref", ""))
        inv = _resolve_investigation(state, ref)
        if inv is None:
            return {"applied": False, "action": kind.value,
                    "detail": f"No investigation matching '{ref}'."}
        state.operator_focus.prioritize_investigation_id = inv.id
        return {"applied": True, "action": kind.value, "detail": f"Investigation '{inv.objective[:60]}' prioritized."}
    if kind == AskActionType.CREATE_INVESTIGATION:
        area = str(action.args.get("area", ""))
        created = _create_investigation_for_area(state, area)
        if created is None:
            return {"applied": False, "action": kind.value,
                    "detail": "No matching hypothesis area; no investigation created."}
        return {"applied": True, "action": kind.value,
                "detail": f"Investigation '{created.objective[:60]}' queued.",
                "investigation_id": created.id}
    if kind in (AskActionType.EXPLAIN_FINDING, AskActionType.INSPECT_EVIDENCE,
                AskActionType.INSPECT_GAP, AskActionType.REQUEST_OPERATOR_APPROVAL):
        return {"applied": True, "action": kind.value, "detail": "Read-only inspection; no mutation."}
    return {"applied": False, "action": str(kind), "detail": "Unknown action."}


def _resolve_investigation(state: Any, ref: str) -> Any | None:
    ref_l = (ref or "").lower()
    for inv in state.get_investigations():
        if inv.id.lower() == ref_l or ref_l in inv.id.lower() \
                or ref_l in inv.objective.lower():
            return inv
    return None


def _apply_focus_boost(state: Any, area: str) -> None:
    from horcrux.intel.investigations import InvestigationState
    area_map = {"authz": ("AuthorizationAgent",), "auth": ("AuthenticationAgent",),
                "api": ("APIAgent",), "web": ("WebAgent",),
                "business_logic": ("BusinessLogicAgent",),
                "network": ("NetworkAgent",)}
    specialists = area_map.get(area, ())
    if not specialists or area == "all":
        return
    invs = state.get_investigations()
    for inv in invs:
        if inv.specialist in specialists and inv.state in (
                InvestigationState.READY, InvestigationState.PENDING):
            inv.score.expected_information_gain = min(
                1.0, inv.score.expected_information_gain + 0.15)
            inv.priority = inv.score.total
    state.set_investigations(sorted(invs, key=lambda i: -i.priority))


def _create_investigation_for_area(state: Any, area: str) -> Any | None:
    from horcrux.intel.investigations import (
        HYPOTHESIS_TO_INVESTIGATIONS,
        Investigation,
        InvestigationScore,
        InvestigationState,
    )
    area_l = (area or "").lower()
    hyps = state.get_hypotheses()
    # Pick hypothesis whose class/objective matches the area.
    chosen = None
    for h in hyps:
        title = h.title.lower()
        cls = h.hypothesis_class.value
        if any(k in area_l for k in ("author", "order", "bola", "idor")) and cls == "idor_bola":
            chosen = h
            break
        if "admin" in area_l and cls == "privilege_escalation":
            chosen = h
            break
        if "graphql" in area_l and cls == "graphql":
            chosen = h
            break
        if "upload" in area_l and cls == "file_upload":
            chosen = h
            break
        if "business" in area_l and cls == "business_logic":
            chosen = h
            break
        if area_l in title or cls in area_l:
            chosen = h
            break
    if chosen is None and hyps:
        chosen = hyps[0]
    if chosen is None:
        return None
    templates = HYPOTHESIS_TO_INVESTIGATIONS.get(chosen.hypothesis_class, [])
    if not templates:
        return None
    tmpl = templates[0]
    inv = Investigation(objective=tmpl["objective"],
                        reason=f"Operator-requested via ask: {area[:60]} (hypothesis: {chosen.title[:50]})",
                        evidence_refs=chosen.evidence_refs[:8],
                        vulnerability_classes=[chosen.hypothesis_class.value],
                        required_capabilities=tmpl["capabilities"],
                        candidate_tools=tmpl["tools"],
                        expected_information_gain=tmpl["gain"],
                        hypothesis_id=chosen.id,
                        specialist=tmpl["specialist"],
                        state=InvestigationState.READY,
                        score=InvestigationScore(
                            evidence_relevance=0.8, expected_information_gain=0.9,
                            impact_potential=tmpl.get("impact", 0.8),
                            coverage_gap=0.9))
    inv.priority = inv.score.total
    inv.ensure_id()
    existing = state.get_investigations()
    if not any(i.id == inv.id for i in existing):
        existing.append(inv)
        state.set_investigations(existing)
    return inv


def answer_deterministically(state: Any, question: str) -> str:
    """Deterministic workspace-grounded answer (no LLM required)."""
    from horcrux.intel.coverage import CoverageStatus
    intent = classify_ask_intent(question)
    ctx = build_structured_context(state, question)
    lines = [f"## {intent.value.replace('_', ' ').title()}", ""]
    if intent == AskIntent.COVERAGE_GAP:
        cov = ctx.get("coverage", {})
        gaps = [d for d, s in cov.items() if s == CoverageStatus.NOT_REVIEWED.value]
        invs = ctx.get("investigations", [])
        lines.append(f"Target **{state.target}** coverage: "
                     + (", ".join(f"{k} {v:.0f}%" for k, v in ctx.get("coverage_pct", {}).items()) or "no data"))
        if gaps:
            lines.append(f"\n**Not yet tested:** {', '.join(gaps[:10])}")
        else:
            lines.append("\nNo NOT_REVIEWED domains remain.")
        if invs:
            lines.append("\n**Next investigations:**")
            for i in invs[:5]:
                lines.append(f"- {i['objective']} [{i['state']}, priority {i['priority']}]")
        return "\n".join(lines)
    if intent == AskIntent.FINDING_ANALYSIS and "finding" in ctx:
        f = ctx["finding"]
        lines.append(f"**{f['title']}** ({f['severity']}, {f['validation_state']}, confidence {f['confidence']:.0%})")
        lines.append(f"\n**Why this confidence:** evidence count {len(f['evidence'])}; "
                     "LIKELY requires cross-identity or second-source validation for CONFIRMED.")
        for ev in f["evidence"][:5]:
            lines.append(f"- {ev}")
        if f.get("next"):
            lines.append(f"\n**Next:** {f['next']}")
        return "\n".join(lines)
    if intent == AskIntent.HYPOTHESIS_ANALYSIS and "hypothesis" in ctx:
        h = ctx["hypothesis"]
        lines.append(f"**{h['title']}** [{h['status']}, confidence {h['confidence']:.0%}]")
        lines.append(f"\n**Missing validation:** {'; '.join(h['validation'][:3])}")
        lines.append(f"**Evidence refs ({len(h['evidence_refs'])}):**")
        for r in h["evidence_refs"][:6]:
            lines.append(f"- `{r}`")
        if re.search(r"disprove|refute|falsif", question.lower()):
            lines.append("\n**Evidence that would disprove it:**")
            for req in h["validation"][:3]:
                lines.append(f"- negative result for: {req}")
            lines.append("- authorization enforced across tested identities")
        return "\n".join(lines)
    if intent == AskIntent.EVIDENCE_LOOKUP and "hypothesis" in ctx:
        h = ctx["hypothesis"]
        lines.append(f"**Evidence chain for:** {h['title']}")
        for r in h["evidence_refs"][:8]:
            lines.append(f"- `{r}`")
        for e in ctx.get("endpoints", [])[:5]:
            lines.append(f"- endpoint `{e['path']}` via {', '.join(e['sources'][:3])}")
        return "\n".join(lines)
    if intent == AskIntent.PRIORITIZATION:
        lines.append("**Highest-value investigations:**")
        for i in ctx.get("investigations", [])[:5]:
            lines.append(f"- {i['objective']} (priority {i['priority']}, {i['state']})")
        return "\n".join(lines)
    if intent == AskIntent.OPERATOR_STEERING:
        lines.append("Steering acknowledged — applied via validated orchestrator action.")
        return "\n".join(lines)
    if intent == AskIntent.INVESTIGATION_REQUEST:
        lines.append("Investigation queued from workspace hypotheses; ranked by information gain.")
        for i in ctx.get("investigations", [])[:5]:
            lines.append(f"- {i['objective']} [{i['state']}]")
        return "\n".join(lines)
    if intent == AskIntent.MANUAL_VALIDATION and "validation" in ctx:
        v = ctx["validation"]
        lines.append("**Manual validation guidance (non-destructive):**")
        for step in v.get("reproduction", [])[:5]:
            lines.append(f"1. {step}")
        lines.append("\nPrerequisites: operator authorization; scoped access only.")
        return "\n".join(lines)
    if intent == AskIntent.STATUS:
        lines.append(f"Target **{state.target}** — phase `{ctx.get('phase', '')}`.")
        cur = ctx.get("current_counts", {})
        if cur:
            lines.append(f"\n**State:** {cur.get('endpoints', 0)} endpoints, "
                         f"{cur.get('hypotheses', 0)} hypotheses, "
                         f"{cur.get('investigations', 0)} investigations, "
                         f"{cur.get('findings', 0)} findings, "
                         f"{cur.get('attack_paths', 0)} attack paths.")
        delta = ctx.get("delta", {})
        if delta:
            lines.append("\n**What changed since the last reassessment:**")
            for key, change in delta.items():
                lines.append(f"- {key}: {change['before']} → {change['after']}")
        else:
            lines.append("\nNo changes recorded since the last reassessment checkpoint.")
        return "\n".join(lines)
    if intent == AskIntent.REPORT:
        lines.append(f"Target **{state.target}** — investigation-graph summary "
                     "(full narrative via `report`).")
        for i in ctx.get("investigations", [])[:8]:
            lines.append(f"- {i['objective']} [{i['state']}]")
        lines.append(f"\nFindings: {len(state.findings)}; "
                     f"attack paths: {ctx.get('attack_paths', 0)}; "
                     f"handoffs: {ctx.get('handoffs', 0)}.")
        return "\n".join(lines)
    if "attack_path_detail" in ctx and ctx["attack_path_detail"]:
        for p in ctx["attack_path_detail"][:2]:
            lines.append(f"**Path:** {p['name']} [{p['probability']}, "
                         f"{p.get('status', p['validation'])}]")
            nodes = [tuple(n) for n in p["nodes"][:6]]
            lines.append("Nodes: " + " → ".join(
                f"{t}:{l}" + (f"[{s}]" if s else "") for t, l, s, *_ in nodes))
            for e in p["edges"][:6]:
                if e.get("inference"):
                    tag = "inference"
                elif e.get("security_evidence"):
                    tag = "validator evidence"
                else:
                    tag = f"observation({len(e['evidence'])})"
                lines.append(f"- edge {e['type']} [{tag}]")
            if p["assumptions"]:
                lines.append(f"Assumptions: {'; '.join(p['assumptions'][:3])}")
            if p.get("rank_why"):
                lines.append(f"Prioritized: {p['rank_why']}")
        return "\n".join(lines)
    # Default explanation.
    app = ctx.get("application", {})
    lines.append(f"Target **{state.target}**: {app.get('endpoints', 0)} endpoints, "
                 f"{app.get('object_bearing', 0)} object-bearing, {app.get('admin', 0)} admin. "
                 f"{len(state.get_hypotheses())} hypotheses, {len(state.get_investigations())} investigations, "
                 f"{len(state.findings)} findings, {ctx.get('attack_paths', 0)} attack paths.")
    return "\n".join(lines)
