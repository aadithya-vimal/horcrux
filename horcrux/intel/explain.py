"""Structured agent rationale (Phase 7, Part 17).

Explains actual internal state without exposing raw chain-of-thought.
"""

from __future__ import annotations

from typing import Any


def build_why_summary(state: Any) -> str:
    try:
        app = state.get_application_model()
        summary = app.summary()
    except Exception:
        summary = {}
    focus = getattr(state, "operator_focus", None)
    focus_label = getattr(focus, "focus_id", "") or getattr(focus, "focus_area", "all") or "all"
    if focus_label in ("", "all"):
        focus_label = _infer_focus(state)
    observed: list[str] = []
    if summary.get("object_bearing_endpoints"):
        observed.append(f"{summary['object_bearing_endpoints']} object-bearing API routes")
    if summary.get("identities") is not None:
        idents = summary.get("identities", [])
        if idents:
            observed.append(f"{len(idents)} identities")
    admin = summary.get("admin_endpoints", 0)
    if admin:
        observed.append(f"{admin} privileged endpoints")
    if summary.get("endpoints"):
        observed.append(f"{summary['endpoints']} endpoints mapped")
    if summary.get("authentication_surfaces"):
        observed.append(f"{summary['authentication_surfaces']} auth surfaces")
    if not observed:
        observed = ["initial reconnaissance state"]
    unknowns = _unknowns(state)
    hyp = _top_hypothesis(state)
    nxt = _next_investigation(state)
    reason = _reason(state, nxt)
    lines = [f"Current focus: {focus_label}", "",
             "Observed:"]
    lines += [f"- {o}" for o in observed]
    lines += ["", "Unknown:"]
    lines += [f"- {u}" for u in unknowns] or ["- none material"]
    if hyp:
        lines += ["", "Hypothesis:", f"- {hyp}"]
    if nxt:
        lines += ["", "Next investigation:", f"- {nxt}"]
    lines += ["", "Reason:", f"- {reason}"]
    return "\n".join(lines)


def _infer_focus(state: Any) -> str:
    try:
        invs = state.get_investigations()
        prio = getattr(state.operator_focus, "prioritize_investigation_id", "")
        if prio:
            for i in invs:
                if i.id == prio:
                    return i.specialist.replace("Agent", "")
        open_inv = [i for i in invs if i.state.value in {"READY", "PENDING"}]
        if open_inv:
            top = max(open_inv, key=lambda i: i.priority)
            spec = top.specialist.replace("AuthorizationAgent", "Authorization")
            return spec.replace("Agent", "")
    except Exception:
        pass
    return "Authorization"


def _unknowns(state: Any) -> list[str]:
    out: list[str] = []
    try:
        app = state.get_application_model()
        if any(e.has_object_reference for e in app.endpoints):
            out.append("cross-user object access")
        if app.authentication and len(app.identities) < 2:
            out.append("authenticated vs anonymous behavior")
        if app.workflows:
            out.append("workflow state-transition enforcement")
        cov = state.get_security_coverage()
        cov.ensure_domains()
        gaps = [d for d, dc in cov.domains.items() if dc.status.value == "NOT_REVIEWED"]
        if gaps:
            out.append(f"coverage gaps: {', '.join(gaps[:4])}")
    except Exception:
        pass
    return out[:4]


def _top_hypothesis(state: Any) -> str:
    try:
        hyps = [h for h in state.get_hypotheses()
                if h.status.value in {"OPEN", "INVESTIGATING"}]
        if not hyps:
            return ""
        top = max(hyps, key=lambda h: h.confidence)
        return f"{top.title} (confidence {top.confidence:.0%})"
    except Exception:
        return ""


def _next_investigation(state: Any) -> str:
    try:
        invs = [i for i in state.get_investigations()
                if i.state.value in {"READY", "PENDING"}]
        if not invs:
            return "none — assessment complete or blocked"
        top = max(invs, key=lambda i: i.priority)
        return f"{top.objective} [{top.specialist}]"
    except Exception:
        return ""


def _reason(state: Any, nxt: str) -> str:
    parts = []
    try:
        invs = [i for i in state.get_investigations()
                if i.state.value in {"READY", "PENDING"}]
        if invs:
            top = max(invs, key=lambda i: i.priority)
            if top.expected_information_gain == "high":
                parts.append("high information gain")
            if top.score.coverage_gap >= 0.7:
                parts.append("high coverage gap")
            if top.score.execution_cost <= 0.3:
                parts.append("low execution cost")
    except Exception:
        pass
    return "; ".join(parts) or "highest ranked executable investigation"


# ---------------------------------------------------------------------------
# Phase 8 targeted explainers (Part 37) — structured rationale, no CoT leak.
# ---------------------------------------------------------------------------

def explain_investigation(state: Any, ref: str) -> str:
    """Why this investigation: gain, gap, capability, dependency evidence."""
    inv = _resolve(state, ref)
    if inv is None:
        return f"No investigation matching '{ref}'."
    lines = [f"**{inv.objective}** [{inv.state.value}, priority {inv.priority:.2f}]",
             f"- information gain: {inv.expected_information_gain} "
             f"(relevance {inv.score.evidence_relevance:.2f}, gap {inv.score.coverage_gap:.2f})",
             f"- specialist: {inv.specialist}; tools: {', '.join(inv.candidate_tools or ['none'])}"]
    if inv.hypothesis_id:
        hyp = next((h for h in state.get_hypotheses() if h.id == inv.hypothesis_id), None)
        if hyp is not None:
            lines.append(f"- depends on evidence: hypothesis '{hyp.title[:70]}' [{hyp.status.value}]")
    try:
        from horcrux.intel.dependencies import evaluate_prerequisites
        _, blocked = evaluate_prerequisites(state, inv)
        if blocked:
            lines.append(f"- blocked: {'; '.join(blocked)}")
        else:
            lines.append("- prerequisites satisfied; capability available for scheduling")
    except Exception:
        pass
    try:
        from horcrux.agents.tools.capabilities import CapabilityRegistry
        rep = CapabilityRegistry().availability_report()
        for tool in (inv.candidate_tools or [])[:3]:
            info = rep.get(tool, {})
            lines.append(f"- capability {tool}: {info.get('status', '?')} ({info.get('mode', '?')})")
    except Exception:
        pass
    return "\n".join(lines)


def explain_finding_confidence(state: Any, ref: str) -> str:
    """Why LIKELY (not CONFIRMED): exact supporting vs missing evidence."""
    f = next((x for x in getattr(state, "findings", [])
              if x.id.lower() == ref.lower() or ref.lower() in x.id.lower()
              or ref.lower() in x.title.lower()), None)
    if f is None:
        return f"No finding matching '{ref}'."
    lines = [f"**{f.title}** — {f.validation_state.value} (confidence {f.confidence:.0%})",
             f"- supporting evidence ({len(f.evidence)}):"]
    for ev in (f.evidence or [])[:6]:
        lines.append(f"  - {ev}")
    missing = []
    if f.validation_state.value == "LIKELY":
        missing = ["cross-identity validation with a second account",
                   "second independent evidence source"]
    elif f.validation_state.value not in ("CONFIRMED",):
        missing = [f"validation requirements for {f.category}",
                   "operator confirmation per reproduction steps"]
    if missing:
        lines.append(f"- missing for CONFIRMED: {'; '.join(missing)}")
        lines.append("- therefore confidence remains " + f.validation_state.value)
    return "\n".join(lines)


def explain_not_investigated(state: Any, ref: str) -> str:
    """Why something was not investigated: capability/prereq/skip/scope."""
    inv = _resolve(state, ref)
    if inv is None:
        # Maybe a hypothesis or domain name.
        hyps = [h for h in state.get_hypotheses() if ref.lower() in h.title.lower()]
        if hyps:
            h = hyps[0]
            linked = [i for i in state.get_investigations() if i.hypothesis_id == h.id]
            if not linked:
                return (f"Hypothesis '{h.title[:60]}' has no investigation: "
                        f"no template for class {h.hypothesis_class.value}.")
            return explain_not_investigated(state, linked[0].id)
        try:
            from horcrux.intel.coverage import SECURITY_DOMAINS
            if ref.lower() in SECURITY_DOMAINS:
                cov = state.get_security_coverage()
                status = cov.get(ref.lower()).value
                return f"Domain '{ref}': {status}."
        except Exception:
            pass
        return f"No investigation, hypothesis, or domain matching '{ref}'."
    reasons = []
    if inv.id in (getattr(state.operator_focus, "skip_investigation_ids", []) or []):
        reasons.append("operator skipped it")
    try:
        from horcrux.core.policy import EngagementPolicy  # noqa: F401
        if inv.state.value == "SCOPE_BLOCKED":
            reasons.append("out of scope: " + (inv.result_summary or "policy"))
    except Exception:
        pass
    if inv.state.value == "UNAVAILABLE":
        reasons.append("required capability unavailable: " + (inv.result_summary or ""))
    if inv.state.value == "BLOCKED":
        reasons.append("prerequisite missing: " + (inv.result_summary or ""))
    if inv.state.value == "APPROVAL_REQUIRED":
        reasons.append("waiting on explicit operator approval")
    if not reasons:
        reasons.append(f"state is {inv.state.value}; scheduled by priority {inv.priority:.2f}")
    return f"**{inv.objective}** was not investigated: " + "; ".join(reasons) + "."


def _resolve(state: Any, ref: str) -> Any | None:
    ref_l = (ref or "").lower()
    for inv in state.get_investigations():
        if inv.id.lower() == ref_l or ref_l in inv.id.lower() \
                or ref_l in inv.objective.lower():
            return inv
    return None
