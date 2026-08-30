from __future__ import annotations

from pathlib import Path
from horcrux.models import ValidationState


def markdown(ws, output: Path | None = None):
    state = ws.load()
    output = output or (ws.reports / "report.md")

    lines = [
        f"# HORCRUX REPORT — {state.target}",
        "",
        "## Target",
        f"- **Host / Target**: `{state.target}`",
        f"- **Updated At**: `{state.updated_at.isoformat()}`",
        "",
        "## Services",
        "",
    ]

    for service in sorted(state.services, key=lambda x: (x.port, x.protocol)):
        cpe_str = f" (`{service.cpe}`)" if service.cpe else ""
        lines.append(
            f"- `{service.port}/{service.protocol}` — "
            f"{service.service} {service.product} {service.version}{cpe_str}".strip()
        )

    lines += ["", "## Software Inventory", ""]
    for software in state.software:
        cpe_str = f" [CPE: `{software.cpe}`]" if software.cpe else ""
        lines.append(
            f"- `{software.product} {software.version}` — "
            f"{software.service} ({software.source}, confidence: {software.confidence:.0%}){cpe_str}"
        )

    # Confirmed Findings
    confirmed = [f for f in state.findings if f.validation_state == ValidationState.confirmed]
    likely = [f for f in state.findings if f.validation_state == ValidationState.likely]
    potential = [f for f in state.findings if f.validation_state == ValidationState.potential]

    lines += ["", "## Confirmed Findings", ""]
    if confirmed:
        for f in confirmed:
            lines.append(f"- **[{f.severity.value.upper()}]** {f.title} (Confidence: {f.confidence:.0%})")
            for ev in f.evidence:
                lines.append(f"  - Evidence: {ev}")
            if f.why_it_matters:
                lines.append(f"  - Impact: {f.why_it_matters}")
            if f.recommended_next_action:
                lines.append(f"  - Action: {f.recommended_next_action}")
    else:
        lines.append("- *No confirmed findings.*")

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
        lines.append("- *No potential findings.*")

    lines += ["", "## CVE / SearchSploit Candidates", ""]
    if state.exploits:
        for exploit in state.exploits:
            label = f"{exploit.cve} " if exploit.cve else ""
            lines.append(
                f"- `{label}{exploit.product} {exploit.version}` — "
                f"{exploit.title} — `{exploit.source}` [{exploit.exploitability}]"
            )
    else:
        lines.append("- *No candidates.*")

    lines += ["", "## Next Best Actions", ""]
    for action in state.actions:
        lines.append(f"- **{action.title}** (Score: {int(action.score)}): {action.reason}")

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines), encoding="utf-8")
    return output
