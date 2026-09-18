"""Investigation-graph reporting (Phase 8, Parts 28-29).

Reports reflect the deterministic investigation graph — model, hypotheses,
investigations, coverage, attack paths, handoffs — not just scanner output.
A clean assessment explains what was covered and why completion criteria
were satisfied; it never just says "no vulnerabilities found".
"""

from __future__ import annotations

from pathlib import Path
from horcrux.core.sanitizer import redact_secrets
from horcrux.models import AuditStatus, ValidationState


def markdown(ws, output: Path | None = None) -> Path:
    state = ws.load()
    output = output or (ws.reports / "report.md")
    app = state.get_application_model()
    summary = app.summary()

    # Executive risk summary (AI-assisted if configured, otherwise deterministic)
    exec_summary = state.executive_summary
    if not exec_summary:
        try:
            from horcrux.intel.ai.manager import AIManager
            ai_mgr = AIManager()
            if ai_mgr.is_enabled and ai_mgr.get_provider():
                exec_summary = ai_mgr.generate_executive_summary(state)
                state.executive_summary = exec_summary
                ws.save(state)
        except Exception:
            pass
    if not exec_summary:
        exec_summary = _deterministic_summary(state, app, summary)

    lines = [f"# HORCRUX REPORT — {state.target}", ""]

    # Legacy-compatible executive summary (also preamble to §1–§19).
    lines += ["## Executive Risk Summary", "", exec_summary, ""]

    # 1. Target and scope
    lines += ["## 1. Target and Scope", ""]
    try:
        policy = state.get_policy()
        scope = policy.scope
        lines.append(f"- **Host / Target**: `{state.target}`")
        lines.append(f"- **Allowed targets**: {', '.join(scope.allowed_targets) or state.target}")
        lines.append(f"- **Engagement mode**: `{policy.mode.value}`")
    except Exception:
        lines.append(f"- **Host / Target**: `{state.target}`")
    lines += [f"- **Updated At**: `{state.updated_at.isoformat()}`",
              f"- **Workspace Path**: `{ws.root}`", ""]

    # 2. Assessment lifecycle
    lines += ["## 2. Assessment Lifecycle", ""]
    lines.append(f"- **Phase**: `{state.assessment_phase}`")
    lines.append(f"- **Run ID**: `{state.assessment_run_id or 'n/a'}`")
    sched = state.scheduler_state or {}
    if sched.get("recovered"):
        lines.append(f"- **Recovered investigations**: {len(sched['recovered'])} (resumed after interruption)")
    lines.append(f"- **Scheduler**: `{sched.get('mode', 'sequential')}` "
                 f"(max_workers={sched.get('max_workers', 1)})")
    lines.append(f"- **Reasoning checkpoints used**: {state.reasoning_checkpoints_used}")
    mission = state.get_mission()
    if mission:
        lines.append(f"- **Headless Mission ID**: `{mission.mission_id}`")
        lines.append(f"- **Mission Stage**: `{mission.current_stage.value}`")
        lines.append(f"- **Mission Status**: `{mission.status.value}`")
        lines.append(f"- **Completion Verdict**: `{mission.completion_verdict}`")
        lines.append(f"- **Runtime**: `{int(mission.budget.runtime_seconds)}s` (checkpoints: {mission.checkpoints_count})")
        if mission.identities:
            lines.append(f"- **Identities Tested**: {', '.join(f'{i.identity_id} ({i.role})' for i in mission.identities)}")
    lines.append("")

    # 3. Application overview
    lines += ["## 3. Application Overview", ""]
    lines.append(f"- **Type**: `{summary['application']['type']}` "
                 f"(framework: {summary['application']['framework'] or 'unknown'})")
    lines.append(f"- **Endpoints**: {summary['endpoints']} "
                 f"({summary['object_bearing_endpoints']} object-bearing, "
                 f"{summary['admin_endpoints']} privileged)")
    lines.append(f"- **Auth surfaces**: {summary['authentication_surfaces']}, "
                 f"**identities**: {len(app.identities)}, "
                 f"**sessions**: {len(app.sessions)}")
    lines.append(f"- **Workflows**: {len(app.workflows)} "
                 f"({len(app.workflow_transitions)} transitions), "
                 f"**object lifecycles**: {len(app.object_lifecycles)}")
    lines += [""]

    # 4. Application model
    lines += ["## 4. Application Model", ""]
    lines.append(f"- **Routes**: {len(app.routes)}, **pages**: {len(app.pages)}, "
                 f"**parameters**: {len(app.parameters)}")
    lines.append(f"- **API operations**: {len(app.api_operations)}, "
                 f"**GraphQL operations**: {len(app.graphql_operations)}")
    lines.append(f"- **Object types**: {', '.join(summary['object_types'][:10]) or 'none'}")
    lines.append(f"- **Service facts**: {len(app.service_facts)}")
    lines += [""]

    # 5. Technologies/services
    lines += ["## 5. Technologies and Services", ""]
    if state.services:
        for service in sorted(state.services, key=lambda x: (x.port, x.protocol)):
            cpe_str = f" (`{service.cpe}`)" if service.cpe else ""
            lines.append(f"- `{service.port}/{service.protocol.upper()}` — "
                         f"**{service.service or 'unknown'}** {service.product} "
                         f"{service.version}{cpe_str}".strip())
    else:
        lines.append("- *No open network services identified.*")
    if state.technologies:
        lines.append(f"- **Web technologies**: {', '.join(f'`{t}`' for t in state.technologies)}")
    if state.software:
        for software in state.software:
            lines.append(f"- `{software.product} {software.version}` — {software.service} "
                         f"({software.source}, confidence: {software.confidence:.0%})")
    lines += [""]

    # 6. Identities/roles
    lines += ["## 6. Identities and Roles", ""]
    if app.identities:
        for ident in app.identities:
            lines.append(f"- **{ident.label}** (`{ident.role.value}`, privilege {ident.privilege_level}) — "
                         f"{len(ident.observed_endpoints)} endpoints, "
                         f"{len(ident.observed_objects)} objects, "
                         f"{len(ident.session_ids)} sessions")
    else:
        lines.append("- *No identities modeled.*")
    lines += [""]

    # 7. Attack surface (legacy header preserved for compatibility).
    lines += ["## Attack Surface", ""]
    for ep in sorted(app.endpoints, key=lambda e: e.path)[:60]:
        flags = []
        if ep.has_object_reference:
            flags.append("object")
        if ep.is_mutation:
            flags.append("mutation")
        if "admin" in ep.path.lower():
            flags.append("privileged")
        flag_str = f" [{', '.join(flags)}]" if flags else ""
        lines.append(f"- `{ep.method} {ep.path}`{flag_str} "
                     f"(via {', '.join(ep.sources[:3]) or 'unknown'})")
    if len(app.endpoints) > 60:
        lines.append(f"- *... and {len(app.endpoints) - 60} more endpoints.*")
    if not app.endpoints:
        lines.append("- *No application endpoints mapped.*")
    lines += [""]

    # 8. Security coverage
    lines += ["## 8. Security Coverage", ""]
    try:
        coverage = state.get_security_coverage()
        coverage.ensure_domains()
        pct = coverage.percentage_complete()
        for group, value in pct.items():
            lines.append(f"- **{group}**: {value:.0f}%")
        lines.append("")
        for domain, dc in sorted(coverage.domains.items()):
            detail = (f"observed={dc.observed} investigated={dc.investigated} "
                      f"validated={dc.validated} blocked={dc.blocked}")
            lines.append(f"- `{domain}`: **{dc.status.value}** ({detail})"
                         + (f" — {dc.notes}" if dc.notes else ""))
    except Exception:
        lines.append("- *Coverage unavailable.*")
    lines += [""]

    confirmed = [f for f in state.findings if f.validation_state == ValidationState.confirmed]
    likely = [f for f in state.findings if f.validation_state == ValidationState.likely]
    potential = [f for f in state.findings if f.validation_state == ValidationState.potential]

    # 8b. Vulnerability engine coverage (external fabric — spec §32).
    lines += ["## Vulnerability Engine Coverage", ""]
    try:
        runs = dict(getattr(state, "external_engine_runs", {}) or {})
        cov = state.get_security_coverage()
        eng_verdict = cov.engine_coverage_verdict() if hasattr(cov, "engine_coverage_verdict") else "NOT_ASSESSED"
        lines.append("- **Native HORCRUX**: Executed")
        for pid in ("tenable", "qualys", "rapid7", "greenbone", "msdefender"):
            run = runs.get(pid)
            if run and str(run.get("status", "")).upper() == "COMPLETE":
                detail = f"Executed ({run.get('results', '?')} observations)"
                if run.get("imported"):
                    detail = "Imported (IMPORTED_RESULT — not executed by HORCRUX)"
                lines.append(f"- **{pid.title()}**: {detail}")
            elif run and str(run.get("status", "")).upper() == "OPERATOR_EXCLUDED":
                lines.append(f"- **{pid.title()}**: Operator excluded")
            elif run:
                lines.append(f"- **{pid.title()}**: {str(run.get('status', 'FAILED')).title()} — "
                             f"{str(run.get('reason', ''))[:100]}")
            else:
                lines.append(f"- **{pid.title()}**: Not configured")
        lines.append("")
        lines.append(f"- **External vulnerability coverage**: {eng_verdict}")
        lines.append("- *Results from unavailable engines are not represented as negative evidence.*")
        missing = [pid for pid in ("tenable", "qualys", "rapid7", "greenbone")
                   if pid not in runs or str(runs[pid].get("status", "")).upper() != "COMPLETE"]
        correlated = list(getattr(state, "correlated_vulnerabilities", []) or [])
        if correlated:
            lines.append(f"- **Deduplicated external entities**: {len(correlated)} "
                         f"(sources: {', '.join(sorted({s for e in correlated for s in e.get('sources', [])})) or 'n/a'})")
        if missing and not (confirmed or likely):
            lines.append("")
            lines.append("> **Assessment limited: external vulnerability intelligence "
                         f"{', '.join(missing)} did not contribute results.**")
            lines.append("> Potential vulnerabilities identifiable by this unavailable assessment "
                         "source may not be represented in this report.")
    except Exception:
        lines.append("- *Engine coverage unavailable.*")
    lines += [""]

    # 9. Investigations performed
    lines += ["## 9. Investigations Performed", ""]
    invs = state.get_investigations()
    if invs:
        by_state: dict[str, int] = {}
        for inv in invs:
            by_state[inv.state.value] = by_state.get(inv.state.value, 0) + 1
        lines.append(f"- **Total**: {len(invs)} "
                     + ", ".join(f"{s}: {n}" for s, n in sorted(by_state.items())))
        for inv in invs[:30]:
            blocked = f" — {inv.result_summary[:100]}" if inv.state.value in {
                "BLOCKED", "SCOPE_BLOCKED", "UNAVAILABLE", "FAILED",
                "APPROVAL_REQUIRED"} and inv.result_summary else ""
            lines.append(f"- [{inv.state.value}] **{inv.objective}** "
                         f"({inv.specialist}, priority {inv.priority:.2f}){blocked}")
    else:
        lines.append("- *No investigations recorded.*")
    lines += [""]

    # 10. Findings (legacy ## headers preserved for compatibility).
    lines += ["## Findings", "",
              "_Evidence-backed conclusions from the investigation graph._", ""]
    lines += ["## Confirmed Findings", ""]
    confirmed = [f for f in state.findings if f.validation_state == ValidationState.confirmed]
    likely = [f for f in state.findings if f.validation_state == ValidationState.likely]
    potential = [f for f in state.findings if f.validation_state == ValidationState.potential]
    if confirmed:
        for f in confirmed:
            lines.append(f"### [{f.severity.value.upper()}] {f.title} (CONFIRMED)")
            lines.append(f"- **Asset**: `{f.affected_asset or f.target}` — "
                         f"confidence {f.confidence:.0%}")
            for ev in f.evidence[:6]:
                lines.append(f"  - {redact_secrets(str(ev))}")
            for rep in f.reproduction[:5]:
                lines.append(f"  - `{redact_secrets(str(rep))}`")
            lines.append("")
    if likely:
        for f in likely:
            lines.append(f"- **[{f.severity.value.upper()}]** {f.title} "
                         f"(LIKELY, {f.confidence:.0%})")
            for ev in f.evidence[:4]:
                lines.append(f"  - {redact_secrets(str(ev))}")
    if potential:
        for f in potential:
            lines.append(f"- **[{f.severity.value.upper()}]** {f.title} "
                         f"(POTENTIAL, {f.confidence:.0%})")
    if not (confirmed or likely or potential):
        lines.append("- *No findings requiring action. See §19 for what this means.*")
        lines += [""]
    lines += ["## Likely Findings", ""]
    if likely:
        for f in likely:
            lines.append(f"- **[{f.severity.value.upper()}]** {f.title} "
                         f"(LIKELY, {f.confidence:.0%})")
            for ev in f.evidence[:4]:
                lines.append(f"  - {redact_secrets(str(ev))}")
    else:
        lines.append("- *No likely findings.*")
    lines += ["", "## Potential Findings", ""]
    if potential:
        for f in potential:
            lines.append(f"- **[{f.severity.value.upper()}]** {f.title} "
                         f"(POTENTIAL, {f.confidence:.0%})")
            for ev in f.evidence[:4]:
                lines.append(f"  - {redact_secrets(str(ev))}")
    else:
        lines.append("- *No potential findings requiring verification.*")
    lines += [""]

    # Legacy-compatible audited-controls section (content restored, Part 42).
    lines += ["## Audited / Hardened Controls", ""]
    if state.audit:
        for item in state.audit[:40]:
            badge = f"[{item.status.value}]"
            lines.append(f"- **{badge}** `{item.asset}` — {item.check_name}: {item.reason}")
    else:
        lines.append("- *No defensive controls audited.*")
    lines += [""]

    # 11. Evidence
    lines += ["## 11. Evidence Index", ""]
    n_refs = sum(len(e.evidence_refs) for e in app.endpoints)
    lines.append(f"- **Endpoint evidence refs**: {n_refs}")
    lines.append(f"- **Raw observations**: {len(state.raw_observations)}")
    lines.append(f"- **Artifacts**: {len(state.artifacts)} "
                 f"(raw output under `{ws.raw}`)")
    lines.append(f"- **Finding evidence items**: {sum(len(f.evidence) for f in state.findings)}")
    lines += [""]

    # 12. Attack paths
    lines += ["## 12. Attack Paths", ""]
    if state.attack_paths:
        for idx, path in enumerate(state.attack_paths, 1):
            name = path.get("name", f"Attack Path #{idx}")
            prob = path.get("probability", "MEDIUM")
            lines.append(f"### Path {idx}: {name} [{prob}] "
                         f"(score {path.get('rank_score', '?')})")
            for step in path.get("steps", []):
                lines.append(f"- {redact_secrets(str(step))}")
            if path.get("prerequisites"):
                lines.append(f"- **Prerequisites**: {path['prerequisites']}")
            if path.get("assumptions"):
                lines.append(f"- **Assumptions**: {'; '.join(path['assumptions'][:4])}")
            if path.get("rank_why"):
                lines.append(f"- **Why prioritized**: {path['rank_why']}")
            lines.append("")
    else:
        lines.append("- *No multi-stage attack paths synthesized.*")
        lines.append("")

    # 13. Exploit handoffs
    lines += ["## 13. Exploit Handoffs (Operator Approval Required)", ""]
    if state.exploit_handoffs:
        for h in state.exploit_handoffs:
            lines.append(f"- **{h.vulnerability}** on `{h.affected_asset}` "
                         f"(confidence {h.confidence:.0%})")
            lines.append(f"  - Action: {h.recommended_operator_action}")
            lines.append(f"  - Why manual: {h.why_manual_approval_required}")
    else:
        lines.append("- *No validated findings reached the handoff boundary.*")
    lines += [""]

    # 14. Unresolved hypotheses
    lines += ["## 14. Unresolved Hypotheses", ""]
    open_hyps = [h for h in state.get_hypotheses()
                 if h.status.value in {"OPEN", "INVESTIGATING"}]
    if open_hyps:
        for h in open_hyps[:20]:
            lines.append(f"- [{h.status.value}] **{h.title}** ({h.confidence:.0%}) — "
                         f"missing: {'; '.join(h.validation_requirements[:2])}")
    else:
        lines.append("- *No unresolved hypotheses.*")
    lines += [""]

    # 15. Blocked capabilities
    lines += ["## 15. Blocked Capabilities and Investigations", ""]
    blocked = [i for i in invs if i.state.value in {
        "BLOCKED", "SCOPE_BLOCKED", "UNAVAILABLE", "FAILED", "APPROVAL_REQUIRED"}]
    if blocked:
        for inv in blocked[:20]:
            lines.append(f"- [{inv.state.value}] **{inv.objective}**: "
                         f"{inv.result_summary[:140]}")
    else:
        lines.append("- *Nothing blocked.*")
    lines += [""]

    # 16. Tool availability
    lines += ["## 16. Tool Availability", ""]
    try:
        from horcrux.agents.tools.capabilities import environment_availability_report
        report = environment_availability_report()
        live = sorted(k for k, v in report.items() if v.get("mode") == "live")
        degraded = sorted(k for k, v in report.items()
                          if v.get("status") not in {"AVAILABLE", "MISSING"})
        missing = sorted(k for k, v in report.items() if v.get("status") == "MISSING")
        lines.append(f"- **Live backends**: {', '.join(f'`{k}`' for k in live) or 'none'}")
        if degraded:
            lines.append(f"- **Degraded**: {', '.join(f'`{k}`' for k in degraded[:12])}")
        if missing:
            lines.append(f"- **Missing**: {', '.join(f'`{k}`' for k in missing)}")
        try:
            from horcrux.intel.browser import browser_backend_status
            for key, val in browser_backend_status().items():
                icon = "✔" if val["available"] else "✖"
                lines.append(f"- {icon} **browser/{key}**: {val['reason']}")
        except Exception:
            pass
    except Exception:
        lines.append("- *Availability intelligence unavailable.*")
    lines += [""]

    # 17. Limitations
    lines += ["## 17. Limitations", ""]
    lines += ["- Assessments are non-destructive and limited to authorized target scope.",
              "- Exploit intelligence correlates version metadata; operator validation is required.",
              "- Hypotheses marked OPEN need the validation steps in §14 before conclusions.",
              "- AI reasoning is advisory; deterministic evidence is authoritative.", ""]

    # 18. Operator actions
    lines += ["## 18. Operator Actions", ""]
    focus = state.operator_focus
    lines.append(f"- **Focus**: `{focus.focus_id or focus.focus_area or 'all'}`")
    if focus.skip_investigation_ids:
        lines.append(f"- **Skipped**: {len(focus.skip_investigation_ids)} investigation(s)")
    if focus.prioritize_investigation_id:
        lines.append(f"- **Prioritized**: `{focus.prioritize_investigation_id[:16]}`")
    lines.append(f"- **Paused**: {focus.paused}, **Stopped**: {focus.stopped}")
    if state.actions:
        for idx, action in enumerate(state.actions[:5], 1):
            lines.append(f"- {idx}. **{action.title}** (Score: {int(action.score)}): {action.reason}")
    lines += [""]

    # 19. Assessment completeness
    lines += ["## 19. Assessment Completeness", ""]
    try:
        from horcrux.intel.coverage import assessment_completeness
        comp = assessment_completeness(state)
        lines.append(f"- **Sufficient**: `{comp['sufficient']}`")
        lines.append(f"- **High-value surfaces**: {comp['high_value_surfaces']}")
        lines.append(f"- **Open hypotheses**: {comp['open_hypotheses']}")
        lines.append(f"- **Pending high-value investigations**: {comp['pending_high_investigations']}")
        if comp.get("external_engine_verdict") and comp["external_engine_verdict"] != "NOT_ASSESSED":
            lines.append(f"- **External engine verdict**: `{comp['external_engine_verdict']}` "
                         f"(executed: {', '.join(comp.get('external_engines_executed', [])) or 'none'}; "
                         f"failed: {', '.join(comp.get('external_engines_failed', [])) or 'none'}; "
                         f"not configured: {', '.join(comp.get('external_engines_not_configured', [])) or 'none'})")
        if comp.get("external_engine_verdict") in ("LIMITED", "PARTIAL"):
            lines.append("- **Assessment status**: `LIMITED` — external vulnerability intelligence incomplete. "
                         "Potential vulnerabilities identifiable by unavailable engines may not be represented.")
        if not (confirmed or likely):
            lines.append("")
            lines.append(_clean_narrative(state, comp))
    except Exception:
        pass
    lines += [""]

    if mission and mission.narrative_timeline:
        lines += ["## 20. Autonomous Assessment Timeline", ""]
        for entry in mission.narrative_timeline[-40:]:
            lines.append(f"- `[{entry.get('stage', '').lower()}]` **{entry.get('header', '')}**: {entry.get('detail', '')}")
        lines += [""]

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines), encoding="utf-8")
    return output


def _deterministic_summary(state, app, summary) -> str:
    return (
        f"Automated security assessment for target `{state.target}`. "
        f"Mapped {summary['endpoints']} endpoint(s) "
        f"({summary['object_bearing_endpoints']} object-bearing), "
        f"{len(state.get_hypotheses())} hypothese(s), "
        f"{len(state.get_investigations())} investigation(s), "
        f"{len(state.findings)} finding(s), and "
        f"{len(state.attack_paths or [])} attack path(s).")


def _clean_narrative(state, comp: dict) -> str:
    """A clean result explains coverage — never just 'no vulns found' (P29).

    Client-grade rule: 'No vulnerabilities found' is only valid when
    completeness criteria are satisfied. Otherwise qualify scope/coverage
    and name the unavailable engines explicitly.
    """
    try:
        coverage = state.get_security_coverage()
        coverage.ensure_domains()
        reviewed = [d for d, dc in coverage.domains.items()
                    if dc.status.value in {"REVIEWED", "SUPPORTED", "CONFIRMED", "REFUTED"}]
        blocked = [d for d, dc in coverage.domains.items()
                   if dc.status.value == "BLOCKED"]
        unknown = [d for d, dc in coverage.domains.items()
                   if dc.status.value == "NOT_REVIEWED"]
    except Exception:
        reviewed, blocked, unknown = [], [], []
    missing_engines = list(comp.get("external_engines_not_configured", []) or [])
    failed_engines = list(comp.get("external_engines_failed", []) or [])
    parts = ["> **No confirmed vulnerabilities identified within the assessed scope "
             "and completed coverage.** This means: sufficient security "
             "properties were investigated without producing validated findings — "
             "not that scanning was skipped."]
    parts.append(f"> Investigated properties: {', '.join(reviewed) or 'none yet'}.")
    if unknown:
        parts.append(f"> Remaining unknown: {', '.join(unknown)}.")
    if blocked:
        parts.append(f"> Blocked: {', '.join(blocked)} (see §15).")
    if missing_engines or failed_engines:
        absent = ", ".join(missing_engines + [f"{e} (failed)" for e in failed_engines])
        parts.append(f"> Assessment limited: external vulnerability intelligence ({absent}) "
                     "did not contribute results. Potential vulnerabilities identifiable by "
                     "this unavailable assessment source may not be represented in this report.")
    parts.append(f"> Completion criteria satisfied: `{comp['sufficient']}` "
                 f"({comp['high_value_surfaces']} high-value surfaces, "
                 f"{comp['pending_high_investigations']} pending high-value investigations).")
    return "\n".join(parts)
