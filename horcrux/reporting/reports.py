from __future__ import annotations

from pathlib import Path
from horcrux.models import AuditStatus, ValidationState


def markdown(ws, output: Path | None = None) -> Path:
    state = ws.load()
    output = output or (ws.reports / "report.md")

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
        exec_summary = (
            f"Automated security reconnaissance and validation completed for target `{state.target}`. "
            f"Discovered {len(state.services)} active network service(s), {len(state.findings)} potential vulnerability finding(s), "
            f"and {len(state.audit)} audited/hardened control check(s)."
        )

    lines = [
        f"# HORCRUX REPORT — {state.target}",
        "",
        "## Executive Risk Summary",
        "",
        exec_summary,
        "",
        "## Target",
        "",
        f"- **Host / Target**: `{state.target}`",
        f"- **Updated At**: `{state.updated_at.isoformat()}`",
        f"- **Workspace Path**: `{ws.root}`",
        "",
        "## Scan Metadata",
        "",
        f"- **Services Discovered**: {len(state.services)}",
        f"- **Software Components**: {len(state.software)}",
        f"- **Confirmed Findings**: {len([f for f in state.findings if f.validation_state == ValidationState.confirmed])}",
        f"- **Likely Findings**: {len([f for f in state.findings if f.validation_state == ValidationState.likely])}",
        f"- **Potential Findings**: {len([f for f in state.findings if f.validation_state == ValidationState.potential])}",
        f"- **Audited Controls**: {len(state.audit)}",
        f"- **Exploit Candidates**: {len(state.exploits)}",
        "",
        "## Attack Surface",
        "",
    ]

    if state.services:
        for service in sorted(state.services, key=lambda x: (x.port, x.protocol)):
            cpe_str = f" (`{service.cpe}`)" if service.cpe else ""
            lines.append(
                f"- `{service.port}/{service.protocol.upper()}` — "
                f"**{service.service or 'unknown'}** {service.product} {service.version}{cpe_str}".strip()
            )
    else:
        lines.append("- *No open network services identified.*")

    lines += ["", "## Services", ""]
    for service in sorted(state.services, key=lambda x: (x.port, x.protocol)):
        lines.append(f"- **Port {service.port}/{service.protocol.upper()}**: `{service.service}` {service.product} {service.version} {service.extrainfo}".strip())

    lines += ["", "## Software", ""]
    if state.software:
        for software in state.software:
            cpe_str = f" [CPE: `{software.cpe}`]" if software.cpe else ""
            lines.append(
                f"- `{software.product} {software.version}` — "
                f"{software.service} ({software.source}, confidence: {software.confidence:.0%}){cpe_str}"
            )
    else:
        lines.append("- *No discrete software versions fingerprinted.*")

    lines += ["", "## Technologies", ""]
    if state.technologies:
        for tech in state.technologies:
            lines.append(f"- `{tech}`")
    else:
        lines.append("- *No web technologies fingerprinted.*")

    # Confirmed Findings
    confirmed = [f for f in state.findings if f.validation_state == ValidationState.confirmed]
    likely = [f for f in state.findings if f.validation_state == ValidationState.likely]
    potential = [f for f in state.findings if f.validation_state == ValidationState.potential]

    lines += ["", "## Confirmed Findings", ""]
    if confirmed:
        for f in confirmed:
            lines.append(f"### [{f.severity.value.upper()}] {f.title}")
            lines.append(f"- **Target Asset**: `{f.affected_asset or f.target}`")
            lines.append(f"- **Confidence**: {f.confidence:.0%}")
            lines.append(f"- **Status**: `{f.status.value}`")
            if f.why_it_matters:
                lines.append(f"- **Impact**: {f.why_it_matters}")
            if f.evidence:
                lines.append("- **Evidence**:")
                for ev in f.evidence:
                    lines.append(f"  - {ev}")
            if f.reproduction:
                lines.append("- **Reproduction**:")
                for rep in f.reproduction:
                    lines.append(f"  - `{rep}`")
            if f.recommended_next_action:
                lines.append(f"- **Remediation / Next Step**: {f.recommended_next_action}")
            lines.append("")
    else:
        lines.append("- *No confirmed high-confidence vulnerabilities identified.*")

    lines += ["", "## Likely Findings", ""]
    if likely:
        for f in likely:
            lines.append(f"- **[{f.severity.value.upper()}]** {f.title} (Confidence: {f.confidence:.0%})")
            for ev in f.evidence:
                lines.append(f"  - Evidence: {ev}")
    else:
        lines.append("- *No likely findings.*")

    lines += ["", "## Potential Findings", ""]
    if potential:
        for f in potential:
            lines.append(f"- **[{f.severity.value.upper()}]** {f.title} (Confidence: {f.confidence:.0%})")
            for ev in f.evidence:
                lines.append(f"  - Evidence: {ev}")
    else:
        lines.append("- *No potential findings requiring verification.*")

    # Audited / Hardened Controls
    lines += ["", "## Audited / Hardened Controls", ""]
    if state.audit:
        for item in state.audit:
            badge = f"[{item.status.value}]"
            lines.append(f"- **{badge}** `{item.asset}` — {item.check_name}: {item.reason}")
    else:
        lines.append("- *No defensive controls audited.*")

    # CVE Intelligence
    lines += ["", "## CVE Intelligence", ""]
    cve_candidates = [e for e in state.exploits if e.cve]
    if cve_candidates:
        for exploit in cve_candidates:
            lines.append(f"- **{exploit.cve}** (`{exploit.product} {exploit.version}`): {exploit.title} [{exploit.relevance}]")
    else:
        lines.append("- *No validated CVE matches.*")

    # SearchSploit Intelligence & Exploit Candidates
    lines += ["", "## SearchSploit Intelligence", ""]
    if state.exploits:
        for exploit in state.exploits:
            lines.append(
                f"- `{exploit.product} {exploit.version}` — {exploit.title} — `{exploit.source}` "
                f"[{exploit.exploitability} | {exploit.relevance}]"
            )
            if exploit.relevance_reasoning:
                lines.append(f"  - Reasoning: {exploit.relevance_reasoning}")
    else:
        lines.append("- *No SearchSploit candidates correlated.*")

    lines += ["", "## Exploit Candidates", ""]
    relevant_exploits = [e for e in state.exploits if e.relevance in {"CONFIRMED VERSION MATCH", "HIGH-CONFIDENCE CANDIDATE", "HIGHLY_RELEVANT"}]
    if relevant_exploits:
        for exploit in relevant_exploits:
            lines.append(f"- **{exploit.title}** ({exploit.product} {exploit.version})")
            lines.append(f"  - Exploitability: {exploit.exploitability}")
            lines.append(f"  - Path / PoC: `{exploit.source}`")
    else:
        lines.append("- *No immediately actionable exploit candidates confirmed.*")

    # Suggested Attack Paths
    lines += ["", "## Suggested Attack Paths", ""]
    if state.attack_paths:
        for idx, path in enumerate(state.attack_paths, 1):
            name = path.get("name", f"Attack Path #{idx}")
            prob = path.get("probability", "MEDIUM")
            lines.append(f"### Path {idx}: {name} [{prob}]")
            for step in path.get("steps", []):
                lines.append(f"- {step}")
            if path.get("prerequisites"):
                lines.append(f"- **Prerequisites**: {path['prerequisites']}")
            lines.append("")
    else:
        lines.append("- *No multi-stage attack paths synthesized.*")

    # Next Best Actions
    lines += ["", "## Next Best Actions", ""]
    if state.actions:
        for idx, action in enumerate(state.actions, 1):
            lines.append(f"{idx}. **{action.title}** (Score: {int(action.score)}): {action.reason}")
    else:
        lines.append("- *No pending actions in queue.*")

    lines += [
        "",
        "## Enumeration Performed",
        "",
    ]
    if state.subsystem_states:
        for sub, st in state.subsystem_states.items():
            badge = "✓" if "COMPLETE" in st else "▶" if st == "RUNNING" else "✖"
            lines.append(f"- {badge} **{sub.replace('_', ' ').title()}**: `{st}`")
    else:
        lines.append("- *Initial surface discovery performed.*")

    lines += [
        "",
        "## Missing / Unavailable Tooling",
        "",
    ]
    try:
        from horcrux.core.doctor import check_tools
        tool_rows, _ = check_tools()
        missing = [row for row in tool_rows if not row[1]]
        if missing:
            for name, path, purpose, install_cmd in missing[:12]:
                lines.append(f"- ✖ `{name}` — {purpose}. *Install: `{install_cmd}`*")
        else:
            lines.append("- *All core tooling installed and verified.*")
    except Exception:
        lines.append("- *Tooling audit unavailable.*")

    lines += [
        "",
        "## Artifacts",
        "",
        f"- Raw command output stored under: `{ws.raw}`",
        f"- HTTP responses stored under: `{ws.responses}`",
        f"- HTTP headers stored under: `{ws.headers}`",
        "",
        "## Limitations",
        "",
        "- Assessments are non-destructive and limited to authorized target scope.",
        "- Exploit intelligence correlates software version metadata; operator validation is required before reproduction.",
        "",
    ]

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines), encoding="utf-8")
    return output


