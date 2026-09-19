"""Non-interactive Rich terminal presentation for autonomous headless missions."""

from __future__ import annotations

from typing import Any, Optional

from rich import box
from rich.align import Align
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from horcrux.core.mission import AssessmentMission, MissionBrief, MissionStage


class HeadlessDisplay:
    """Renders structured, non-spammy operator panels for headless missions."""

    def __init__(self, console: Optional[Console] = None, quiet: bool = False) -> None:
        self.console = console or Console()
        self.quiet = quiet

    def render_banner(self, mission: AssessmentMission) -> None:
        if self.quiet:
            return

        header = Text()
        header.append("⚡ HORCRUX AUTONOMOUS VAPT OPERATOR ⚡\n", style="bold bright_magenta")
        header.append(f"Target: {mission.target}   ", style="bold bright_cyan")
        header.append(f"Mission: {mission.mission_id}   ", style="bold bright_yellow")
        header.append(f"Profile: {mission.profile}", style="dim")

        self.console.print()
        self.console.print(Panel(Align.center(header), box=box.ROUNDED, border_style="bright_magenta"))
        self.console.print()

    def render_brief(self, brief: MissionBrief) -> None:
        if self.quiet:
            return

        table = Table(
            title="[bold bright_yellow]✦ PRE-FLIGHT MISSION BRIEF ✦[/bold bright_yellow]",
            box=box.ROUNDED,
            border_style="yellow",
            header_style="bold bright_cyan",
            expand=True,
        )
        table.add_column("Property", style="bold bright_white", width=24)
        table.add_column("Configuration Details", style="cyan")

        table.add_row("Target Perimeter", brief.target)
        table.add_row("Authorized Scope", ", ".join(brief.scope) or brief.target)
        table.add_row("Assessment Profile", brief.profile)
        table.add_row("Mission Objectives", ", ".join(brief.objectives) or "Full Surface & Vulnerability Assessment")
        contexts = getattr(brief, "available_access_contexts", None) or brief.available_identities
        table.add_row("Access Contexts", ", ".join(contexts) or "anonymous (default)")
        table.add_row("Local Capabilities", ", ".join(brief.available_capabilities[:8]) + ("..." if len(brief.available_capabilities) > 8 else ""))
        
        ext_status = ", ".join(f"{k}: {v}" for k, v in list(brief.external_integrations.items())[:5]) or "Native Horcrux Engine"
        table.add_row("External Integrations", ext_status)

        limits_str = f"Max Runtime: {brief.execution_budget.get('max_runtime', 1800)}s | Max Iterations: {brief.execution_budget.get('max_iterations', 25)}"
        table.add_row("Execution Budget", limits_str)
        table.add_row("Safety Boundary", "Safe Non-Destructive Validation Only (Exploits stopped at handoff-ready)")

        self.console.print(table)
        self.console.print()

    def render_stage_transition(self, stage: MissionStage, action: str = "started") -> None:
        if self.quiet:
            return
        stage_name = stage.value if hasattr(stage, "value") else str(stage)
        color = "bright_magenta" if action == "started" else "green"
        symbol = "▶" if action == "started" else "✔"
        self.console.print(f"[{color}]{symbol} STAGE {stage_name} {action.upper()}[/{color}]")

    def render_investigation_card(
        self,
        investigation_id: str,
        objective: str,
        hypothesis_title: str,
        confidence: float,
        blast_radius: str,
        queue_stats: dict[str, int],
        evidence_count: int,
    ) -> None:
        if self.quiet:
            return

        conf_pct = int(confidence * 100)
        blast_color = "red" if blast_radius in ("high", "critical") else ("yellow" if blast_radius == "medium" else "cyan")

        card_content = (
            f"[bold bright_white]Investigation:[/bold bright_white] {objective}\n"
            f"[bold bright_yellow]Hypothesis:[/bold bright_yellow]    {hypothesis_title or 'Attack surface evaluation'}\n"
            f"[bold cyan]Confidence:[/bold cyan]    {conf_pct}%   [bold {blast_color}]Blast Radius:[/bold {blast_color}] {blast_radius.upper()}   "
            f"[bold magenta]Evidence Signals:[/bold magenta] {evidence_count}\n"
            f"[dim]Queue: READY={queue_stats.get('READY', 0)} RUNNING={queue_stats.get('RUNNING', 0)} "
            f"BLOCKED={queue_stats.get('BLOCKED', 0)} COMPLETE={queue_stats.get('COMPLETE', 0)}[/dim]"
        )

        self.console.print(
            Panel(
                card_content,
                title=f"[bold cyan]CURRENT INVESTIGATION [{investigation_id[:10]}][/bold cyan]",
                box=box.ROUNDED,
                border_style="cyan",
            )
        )

    def render_narrative(self, stage: str, header: str, detail: str) -> None:
        if self.quiet:
            return
        self.console.print(f"[bold bright_blue][{stage.lower()}][/bold bright_blue] [bold bright_white]{header}[/bold bright_white]")
        if detail:
            self.console.print(f"  [dim italic]{detail}[/dim italic]")

    def render_completion(
        self,
        mission: AssessmentMission,
        completeness: dict[str, Any],
        fn_audit: dict[str, Any] | None = None,
    ) -> None:
        if self.quiet:
            return

        verdict = completeness.get("verdict", mission.completion_verdict or "COMPLETE")
        verdict_color = "bright_green" if verdict == "COMPLETE" else ("yellow" if verdict == "COMPLETE_WITH_LIMITATIONS" else "red")

        summary_text = (
            f"[bold {verdict_color}]❖ ASSESSMENT CONVERGED: {verdict}[/bold {verdict_color}]\n\n"
            f"Target: [bold]{mission.target}[/bold] | Mission ID: [bold]{mission.mission_id}[/bold]\n"
            f"Duration: {int(mission.budget.runtime_seconds)}s | Checkpoints: {mission.checkpoints_count}\n\n"
            f"Coverage verdict: [bold]{verdict}[/bold]\n"
        )

        if completeness.get("blocking_reasons"):
            summary_text += "\n[bold bright_yellow]Limitations & Remaining Blind Spots:[/bold bright_yellow]\n"
            for b in completeness["blocking_reasons"][:6]:
                summary_text += f"  • {b}\n"

        if fn_audit and fn_audit.get("gaps"):
            summary_text += f"\n[bold bright_yellow]False-Negative Audit Gaps: {fn_audit.get('total_gaps', 0)}[/bold bright_yellow]\n"
            for g in fn_audit.get("gaps", [])[:4]:
                summary_text += f"  • [{g.get('severity', 'medium').upper()}] {g.get('description', '')}\n"

        self.console.print()
        self.console.print(
            Panel(
                summary_text,
                title="[bold bright_magenta]✦ AUTONOMOUS ASSESSMENT REPORT SUMMARY ✦[/bold bright_magenta]",
                box=box.DOUBLE,
                border_style="bright_magenta",
            )
        )
        self.console.print()
