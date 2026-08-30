from __future__ import annotations

from pathlib import Path


def markdown(ws, output: Path | None = None):
    state = ws.load()
    output = output or (ws.reports / "report.md")

    lines = [
        f"# Horcrux Report — {state.target}",
        "",
        "## Services",
        "",
    ]

    for service in sorted(state.services, key=lambda x: (x.port, x.protocol)):
        lines.append(
            f"- `{service.port}/{service.protocol}` — "
            f"{service.service} {service.product} {service.version}".strip()
        )

    lines += ["", "## Software", ""]
    for software in state.software:
        lines.append(
            f"- `{software.product} {software.version}` — "
            f"{software.service} — {software.source}"
        )

    lines += ["", "## Findings", ""]
    for finding in state.findings:
        lines.append(
            f"- **{finding.severity.value.upper()}** "
            f"{finding.title} — {finding.confidence:.0%}"
        )
        for evidence in finding.evidence:
            lines.append(f"  - {evidence}")

    lines += ["", "## CVE / SearchSploit Candidates", ""]
    for exploit in state.exploits:
        label = f"{exploit.cve} " if exploit.cve else ""
        lines.append(
            f"- `{label}{exploit.product} {exploit.version}` — "
            f"{exploit.title} — `{exploit.source}`"
        )

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines), encoding="utf-8")
    return output
