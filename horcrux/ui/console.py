from __future__ import annotations

import shlex
import sys
from typing import List

from rich import box
from rich.align import Align
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from horcrux.core.doctor import check_tools, CATEGORIES
from horcrux.core.intel import run_nuclei
from horcrux.core.runner import CommandRunner
from horcrux.core.settings import AVAILABLE_MODELS, DEFAULT_MODELS, SettingsManager, mask_key
from horcrux.core.storage import Workspace
from horcrux.intel.ai.manager import AIManager
from horcrux.intel.search import searchsploit_workspace
from horcrux.models import AuditStatus, ValidationState
from horcrux.modules.local import enumerate_linux
from horcrux.reporting.reports import markdown
from horcrux.core.orchestrator import Orchestrator
from horcrux.ui.ascii import banner, loading, fanfare, show_gallery, GRAPHIC_DATA

# Ensure UTF-8 output encoding across platforms (especially Windows consoles)
if sys.platform == "win32":
    try:
        if sys.stdout and hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        if sys.stderr and hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass


def get_severity_badge(severity_val: str) -> str:
    sev = str(severity_val).lower()
    if sev == "critical":
        return "[bold white on red] ✖ CRITICAL [/]"
    elif sev == "high":
        return "[bold black on bright_red] ▲ HIGH [/]"
    elif sev == "medium":
        return "[bold black on yellow] ◈ MEDIUM [/]"
    elif sev == "low":
        return "[bold black on cyan] ● LOW [/]"
    return "[bold white on blue] ℹ INFO [/]"


def get_confidence_meter(confidence: float) -> str:
    filled = int(round(confidence * 8))
    empty = 8 - filled
    bar = "█" * filled + "░" * empty
    if confidence >= 0.8:
        return f"[bold green]{bar} {confidence:.0%}[/bold green]"
    elif confidence >= 0.5:
        return f"[bold yellow]{bar} {confidence:.0%}[/bold yellow]"
    return f"[dim cyan]{bar} {confidence:.0%}[/dim cyan]"


def get_status_badge(status_val: str) -> str:
    st = str(status_val).lower()
    if st == "verified":
        return "[bold green]✔ VERIFIED[/bold green]"
    elif st == "exploited":
        return "[bold red]☠ EXPLOITED[/bold red]"
    elif st == "suspected":
        return "[bold yellow]❓ SUSPECTED[/bold yellow]"
    elif st == "mitigated":
        return "[dim green]🛡 MITIGATED[/dim green]"
    return f"[dim]{status_val}[/dim]"


def get_audit_badge(status_val: str) -> str:
    st = str(status_val).upper()
    if st == "HARDENED":
        return "[bold green]🛡 HARDENED[/bold green]"
    elif st == "AUDITED":
        return "[bold cyan]✔ AUDITED[/bold cyan]"
    elif st == "SUSPICIOUS":
        return "[bold yellow]▲ SUSPICIOUS[/bold yellow]"
    elif st == "DISMISSED":
        return "[dim]✖ DISMISSED[/dim]"
    return f"[dim]{status_val}[/dim]"


def get_validation_badge(val_state: str) -> str:
    vs = str(val_state).upper()
    if vs == "CONFIRMED":
        return "[bold green]CONFIRMED[/bold green]"
    elif vs == "LIKELY":
        return "[bold yellow]LIKELY[/bold yellow]"
    elif vs == "POTENTIAL":
        return "[dim yellow]POTENTIAL[/dim yellow]"
    elif vs == "FALSE_POSITIVE":
        return "[dim red]FALSE_POSITIVE[/dim red]"
    return f"[dim cyan]{val_state}[/dim cyan]"


def get_exploit_decision_badge(relevance: str, decision: str = "") -> str:
    tag = (decision or relevance).upper()
    if "CONFIRMED" in tag or "HIGHLY" in tag:
        return "[bold green]★ HIGHLY RELEVANT[/bold green]"
    elif "CANDIDATE" in tag or "POTENTIAL" in tag:
        return "[bold yellow]◈ POTENTIAL[/bold yellow]"
    elif "REJECTED" in tag or "MISMATCH" in tag:
        return "[dim red]✖ REJECTED[/dim red]"
    return f"[dim cyan]{tag}[/dim cyan]"


class ConsoleApp:
    def __init__(self):
        self.console = Console()
        self.workspace: Workspace | None = None
        self.ai_manager = AIManager()

    def print_help(self):
        grid = Table.grid(padding=(0, 2))
        grid.add_column(style="bold bright_cyan", justify="left")
        grid.add_column(style="dim white", justify="left")

        categories = [
            (
                "⚡ RECONNAISSANCE & ATTACK SURFACE",
                [
                    ("scan <target> [--profile <name>] [--deep] [--verify]", "Full automated attack surface discovery"),
                    ("status", "Display current workspace metrics & indicators"),
                    ("surface", "Network attack surface (open ports & protocols)"),
                    ("services", "Service inventory with protocols and versions"),
                    ("software", "Software & framework detection breakdown"),
                    ("web", "Web attack surface and technology fingerprinting"),
                ]
            ),
            (
                "🎯 INTELLIGENCE & CORRELATION",
                [
                    ("findings", "Security findings with severity & confidence meters"),
                    ("inspect <id>", "Deep-dive inspection of finding evidence & reproduction"),
                    ("audit", "Audited and verified hardened security controls"),
                    ("next", "Ranked Next Best Actions prioritized by confidence"),
                    ("creds", "Recovered credentials with masked secrets"),
                    ("graph", "Interactive attack surface graph visualization"),
                    ("cve / searchsploit", "Correlate software with known exploit candidates"),
                    ("exploit", "Review actionable exploit candidates & AI decisions"),
                    ("intel", "Execute exploit correlation & AI triage pipeline"),
                    ("nuclei", "Execute targeted Nuclei templates against web targets"),
                ]
            ),
            (
                "🤖 AI ASSISTANT & SETTINGS",
                [
                    ("ask <question>", "Query AI security analyst with workspace context"),
                    ("ai [status|enable|disable|usage|clear-cache]", "Manage AI engine, model, and cache"),
                    ("settings", "Interactive settings & provider configuration"),
                ]
            ),
            (
                "🛡 EXPLOIT & POST-EXPLOITATION",
                [
                    ("local", "Perform Linux local privilege escalation checks"),
                ]
            ),
            (
                "🛠 UTILITIES & ARTIFACTS",
                [
                    ("doctor", "Audit installed tools, categories, wordlists, and AI"),
                    ("tools", "Fast check of external binary availability"),
                    ("artifacts / gallery", "View the Horcrux ASCII art gallery"),
                    ("source <artifact>", "Inspect raw tool output or response body"),
                    ("raw <module>", "Inspect raw output file for specific module"),
                    ("report", "Generate structured Markdown engagement report"),
                    ("clear", "Clear terminal screen"),
                    ("exit / quit", "Leave the Horcrux console"),
                ]
            )
        ]

        table = Table(
            title="[bold bright_magenta]✦ HORCRUX OPERATOR COMMAND REFERENCE ✦[/bold bright_magenta]",
            box=box.ROUNDED,
            border_style="magenta",
            header_style="bold bright_cyan",
            expand=True,
        )
        table.add_column("Command", style="bold bright_cyan", no_wrap=True)
        table.add_column("Description", style="bright_white")

        for cat_title, cmds in categories:
            table.add_section()
            table.add_row(f"[bold bright_yellow]{cat_title}[/bold bright_yellow]", "")
            for cmd, desc in cmds:
                table.add_row(f"  {cmd}", desc)

        self.console.print()
        self.console.print(table)
        self.console.print()

    def run(self):
        banner(self.console, duration=1.0)
        self.console.print("[dim cyan]⚡ Welcome to HORCRUX.[/dim cyan] [dim white]Type [bold magenta]'help'[/bold magenta] for command reference.[/dim white]\n")

        while True:
            target_str = self.workspace.target if self.workspace else "ready"
            prompt_text = f"[bold magenta]⚡ horcrux[/bold magenta][dim white]@[/dim white][bold cyan]{target_str}[/bold cyan] [bold bright_magenta]❯[/bold bright_magenta] "

            try:
                line = Prompt.ask(prompt_text).strip()
            except (EOFError, KeyboardInterrupt):
                self.console.print()
                return

            if not line:
                continue

            if line.lower() in {"exit", "quit"}:
                self.console.print("\n[bold magenta]✦ The fragments remain intact. Farewell.[/bold magenta]\n")
                return

            try:
                self.dispatch(shlex.split(line))
            except Exception as exc:
                self.console.print(f"[bold red]✖ Error:[/bold red] {exc}")

    def dispatch(self, args: list[str]):
        if not args:
            return

        command = args[0].lower()

        if command == "help":
            self.print_help()
            return

        if command == "clear":
            self.console.clear()
            return

        if command == "doctor":
            self.doctor()
            return

        if command == "tools":
            self.doctor(only_tools=True)
            return

        if command in {"artifacts", "gallery", "art"}:
            show_gallery(self.console)
            return

        if command == "settings":
            self.settings_cmd(args)
            return

        if command == "ai":
            self.ai_cmd(args)
            return

        if command == "scan":
            if len(args) < 2:
                raise ValueError("usage: scan <target> [--profile <name>] [--deep] [--verify]")

            target = args[1]
            deep = "--deep" in args[2:]
            verify = "--verify" in args[2:]
            profile_name = "deep" if deep else "standard"

            # Parse optional --profile <name>
            for i, arg in enumerate(args[2:], start=2):
                if arg in {"--profile", "-p"} and i + 1 < len(args):
                    profile_name = args[i + 1]

            self.workspace = Workspace(target)
            banner(self.console, duration=0.4)

            Orchestrator(
                target,
                self.workspace,
                self.console,
                profile=profile_name,
            ).scan(
                deep=deep,
                verify=verify,
            )

            fanfare(self.console, f"TARGET SYNTHESIS COMPLETE: {target}")
            self.status()
            return

        if command == "local":
            self.require_workspace()
            loading(self.console, "Running Linux local enumeration", 0.5)
            enumerate_linux(self.workspace, CommandRunner(self.workspace))
            self.console.print(
                f"[bold green]✔ Saved:[/bold green] [cyan]{self.workspace.root}[/cyan]"
            )
            return

        self.require_workspace()

        if command == "status":
            self.status()

        elif command == "surface":
            self.surface()

        elif command == "services":
            self.services()

        elif command == "software":
            self.software()

        elif command == "audit":
            self.audit()

        elif command == "findings":
            self.findings()

        elif command == "inspect":
            self.inspect_finding(args)

        elif command == "ask":
            self.ask_cmd(args)

        elif command == "next":
            self.next_actions()

        elif command == "creds":
            self.credentials()

        elif command == "graph":
            self.graph()

        elif command == "web":
            self.web()

        elif command in {"cve", "searchsploit"}:
            loading(self.console, "Correlating with SearchSploit intelligence", 0.5)
            self.exploits(
                searchsploit_workspace(
                    self.workspace,
                    CommandRunner(self.workspace),
                )
            )

        elif command == "intel":
            self.intel()

        elif command == "nuclei":
            self.nuclei()

        elif command == "exploit":
            self.exploits(self.workspace.load().exploits)
            self.console.print(
                "\n[bold yellow]⚡ OPERATOR NOTICE:[/bold yellow] [dim white]Review candidates before using external PoCs. "
                "Horcrux preserves operator control and does not silently fire destructive code.[/dim white]\n"
            )

        elif command == "source":
            if len(args) < 2:
                raise ValueError("usage: source <artifact>")
            path = self.workspace.root / args[1]
            if not path.exists():
                raise ValueError(f"artifact not found: {args[1]}")
            self.console.print(
                Panel(
                    path.read_text(encoding="utf-8", errors="replace"),
                    title=f"[bold bright_cyan]{args[1]}[/bold bright_cyan]",
                    box=box.ROUNDED,
                    border_style="cyan",
                )
            )

        elif command == "raw":
            self.raw_cmd(args)

        elif command == "report":
            report_path = markdown(self.workspace)
            self.console.print(
                Panel(
                    f"[bold green]✔ Structured report generated successfully:[/bold green]\n[bold bright_white]{report_path}[/bold bright_white]",
                    title="[bold bright_magenta]REPORT WRITTEN[/bold bright_magenta]",
                    box=box.ROUNDED,
                    border_style="bright_magenta",
                )
            )

        else:
            raise ValueError(f"unknown command: '{command}' — type 'help' for command reference")


    def require_workspace(self):
        if not self.workspace:
            raise ValueError("no workspace loaded; run 'scan <target>' first")

    def status(self):
        state = self.workspace.load()

        # Build metric cards
        cards = [
            Panel(
                f"[bold green]{len(state.services)}[/bold green]\n[dim]Open[/dim]",
                title="[bold green]🌐 SERVICES[/bold green]",
                box=box.ROUNDED,
                border_style="green",
                padding=(0, 1),
            ),
            Panel(
                f"[bold blue]{len(state.audit)}[/bold blue]\n[dim]Audited[/dim]",
                title="[bold blue]🛡 AUDITED[/bold blue]",
                box=box.ROUNDED,
                border_style="blue",
                padding=(0, 1),
            ),
            Panel(
                f"[bold red]{len(state.findings)}[/bold red]\n[dim]Recorded[/dim]",
                title="[bold red]⚡ FINDINGS[/bold red]",
                box=box.ROUNDED,
                border_style="red",
                padding=(0, 1),
            ),
            Panel(
                f"[bold cyan]{len(state.software)}[/bold cyan]\n[dim]Identified[/dim]",
                title="[bold cyan]📦 SOFTWARE[/bold cyan]",
                box=box.ROUNDED,
                border_style="cyan",
                padding=(0, 1),
            ),
            Panel(
                f"[bold yellow]{len(state.credentials)}[/bold yellow]\n[dim]Captured[/dim]",
                title="[bold yellow]🔑 CREDS[/bold yellow]",
                box=box.ROUNDED,
                border_style="yellow",
                padding=(0, 1),
            ),
            Panel(
                f"[bold magenta]{len(state.exploits)}[/bold magenta]\n[dim]Correlated[/dim]",
                title="[bold magenta]🎯 EXPLOITS[/bold magenta]",
                box=box.ROUNDED,
                border_style="magenta",
                padding=(0, 1),
            ),
        ]

        self.console.print()
        self.console.print(
            Panel(
                Align.center(
                    Text.assemble(
                        ("❖ TARGET WORKSPACE: ", "bold bright_magenta"),
                        (state.target, "bold bright_cyan"),
                        ("  |  STORAGE: ", "dim white"),
                        (str(self.workspace.root), "italic dim cyan"),
                    )
                ),
                box=box.HEAVY,
                border_style="bright_magenta",
            )
        )
        self.console.print(Columns(cards, equal=True, expand=True))

        if state.technologies:
            tech_text = "  •  ".join(f"[bold bright_cyan]{t}[/bold bright_cyan]" for t in state.technologies)
            self.console.print(
                Panel(
                    tech_text,
                    title="[bold bright_blue]⬡ DETECTED WEB TECHNOLOGIES[/bold bright_blue]",
                    box=box.ROUNDED,
                    border_style="blue",
                    padding=(0, 2),
                )
            )

        if state.actions:
            best_action = state.actions[0]
            self.console.print(
                Panel(
                    f"[bold bright_yellow]⚡ {best_action.title}[/bold bright_yellow]\n"
                    f"[dim white]Reason:[/dim white] [italic cyan]{best_action.reason}[/italic cyan]  "
                    f"[bold bright_magenta]• Score: {int(best_action.score)}[/bold bright_magenta]",
                    title="[bold bright_yellow]★ NEXT BEST ACTION ★[/bold bright_yellow]",
                    box=box.DOUBLE,
                    border_style="bright_yellow",
                    padding=(0, 2),
                )
            )
        self.console.print()

    def surface(self):
        state = self.workspace.load()
        if not state.services:
            self.console.print("\n[dim yellow]No network services discovered yet.[/dim yellow]\n")
            return

        table = Table(
            title=f"[bold bright_cyan]✦ NETWORK ATTACK SURFACE — {state.target} ✦[/bold bright_cyan]",
            box=box.ROUNDED,
            border_style="cyan",
            header_style="bold bright_white",
            expand=True,
        )
        table.add_column("Port", style="bold bright_white")
        table.add_column("Proto", style="dim cyan")
        table.add_column("Service", style="bold bright_yellow")
        table.add_column("Product", style="bright_cyan")
        table.add_column("Version", style="bold bright_green")
        table.add_column("Exposure Role", style="dim italic white")

        for service in sorted(
            state.services,
            key=lambda item: (item.port, item.protocol),
        ):
            port_color = "bright_green" if service.port in {80, 443, 8080, 8443} else "cyan"
            role = "Web Application" if service.port in {80, 443, 8080, 8443, 3000, 5000} else (
                "Domain / Auth" if service.port in {22, 445, 139, 88, 389, 636} else (
                    "Database" if service.port in {3306, 5432, 6379, 27017, 1433} else "Network Service"
                )
            )
            table.add_row(
                f"[{port_color}]{service.port}[/{port_color}]",
                service.protocol.upper(),
                service.service or "[dim]unknown[/dim]",
                service.product or "-",
                service.version or "-",
                role,
            )

        self.console.print()
        self.console.print(table)
        self.console.print()

    def services(self):
        state = self.workspace.load()
        table = Table(
            title=f"[bold bright_magenta]✦ DISCOVERED SERVICES — {state.target} ✦[/bold bright_magenta]",
            box=box.ROUNDED,
            border_style="magenta",
            header_style="bold bright_cyan",
            expand=True,
        )
        table.add_column("Port", style="bold bright_white")
        table.add_column("Proto", style="dim cyan")
        table.add_column("Service", style="bold bright_yellow")
        table.add_column("Product", style="bright_cyan")
        table.add_column("Version", style="bold bright_green")

        for service in sorted(
            state.services,
            key=lambda item: (item.port, item.protocol),
        ):
            port_color = "bright_green" if service.port in {80, 443, 8080, 8443} else "cyan"
            table.add_row(
                f"[{port_color}]{service.port}[/{port_color}]",
                service.protocol.upper(),
                service.service or "[dim]unknown[/dim]",
                service.product or "-",
                service.version or "-",
            )

        self.console.print()
        self.console.print(table)
        self.console.print()

    def software(self):
        state = self.workspace.load()
        table = Table(
            title=f"[bold bright_cyan]✦ SOFTWARE & FRAMEWORK INVENTORY — {state.target} ✦[/bold bright_cyan]",
            box=box.ROUNDED,
            border_style="cyan",
            header_style="bold bright_magenta",
            expand=True,
        )
        table.add_column("Product", style="bold bright_white")
        table.add_column("Version", style="bold bright_green")
        table.add_column("Service", style="bright_yellow")
        table.add_column("Evidence Source", style="dim italic white")

        for software in state.software:
            table.add_row(
                software.product,
                software.version or "[dim]unspecified[/dim]",
                software.service or "-",
                software.source,
            )

        self.console.print()
        self.console.print(table)
        self.console.print()

    def audit(self):
        state = self.workspace.load()
        if not state.audit:
            self.console.print("\n[dim yellow]No audited security controls recorded yet.[/dim yellow]\n")
            return

        table = Table(
            title=f"[bold bright_blue]✦ AUDITED & HARDENED CONTROLS — {state.target} ✦[/bold bright_blue]",
            box=box.ROUNDED,
            border_style="blue",
            header_style="bold bright_cyan",
            expand=True,
        )
        table.add_column("Status", justify="center", no_wrap=True)
        table.add_column("Asset / Scope", style="bold bright_white")
        table.add_column("Check / Rule", style="bright_cyan")
        table.add_column("Reason / Observation", style="dim white")

        for item in sorted(state.audit, key=lambda a: a.status.value):
            table.add_row(
                get_audit_badge(item.status.value),
                item.asset,
                item.check_name,
                item.reason,
            )

        self.console.print()
        self.console.print(table)
        self.console.print()

    def findings(self):
        state = self.workspace.load()
        if not state.findings:
            self.console.print("\n[dim yellow]No security findings recorded yet.[/dim yellow]\n")
            return

        table = Table(
            title=f"[bold bright_red]✦ SECURITY FINDINGS — {state.target} ✦[/bold bright_red]",
            box=box.ROUNDED,
            border_style="red",
            header_style="bold bright_white",
            expand=True,
        )
        table.add_column("Severity", justify="center", no_wrap=True)
        table.add_column("Confidence", justify="left", no_wrap=True)
        table.add_column("Title", style="bold bright_white")
        table.add_column("Validation State", justify="center", no_wrap=True)
        table.add_column("Asset", style="dim cyan")
        table.add_column("Finding ID", style="italic white")

        for finding in sorted(
            state.findings,
            key=lambda item: -item.confidence,
        ):
            table.add_row(
                get_severity_badge(finding.severity.value),
                get_confidence_meter(finding.confidence),
                finding.title,
                get_validation_badge(finding.validation_state.value),
                finding.affected_asset or finding.target,
                finding.id,
            )

        self.console.print()
        self.console.print(table)
        self.console.print(
            "[dim cyan]💡 Tip: Use [bold magenta]'inspect <id>'[/bold magenta] to view reproduction commands and detailed evidence snippets.[/dim cyan]\n"
        )

    def inspect_finding(self, args: list[str]):
        if len(args) < 2:
            raise ValueError("usage: inspect <finding-id>")

        query = args[1].lower()
        state = self.workspace.load()
        match = None
        for f in state.findings:
            if f.id.lower() == query or query in f.id.lower() or query in f.title.lower():
                match = f
                break

        if not match:
            raise ValueError(f"No finding matching '{query}' found. Type 'findings' to see list of IDs.")

        header_text = Text.assemble(
            ("FINDING: ", "bold bright_magenta"),
            (match.title, "bold bright_white"),
            ("\nAsset: ", "dim white"),
            (match.affected_asset or match.target, "bold bright_cyan"),
            ("  |  Port: ", "dim white"),
            (str(match.port or "any"), "bright_yellow"),
            ("  |  Protocol: ", "dim white"),
            (match.protocol.upper(), "dim cyan"),
            ("  |  Confidence: ", "dim white"),
            (f"{match.confidence:.0%}", "bold green" if match.confidence >= 0.8 else "bold yellow"),
            ("  |  State: ", "dim white"),
            (match.validation_state.value, "bold bright_magenta"),
        )

        cards = [
            Panel(
                header_text,
                title=f"[bold bright_red]✦ {get_severity_badge(match.severity.value)} ✦[/bold bright_red]",
                box=box.ROUNDED,
                border_style="red",
            ),
        ]

        if match.why_it_matters:
            cards.append(
                Panel(
                    match.why_it_matters,
                    title="[bold bright_yellow]⚡ WHY IT MATTERS (IMPACT)[/bold bright_yellow]",
                    box=box.ROUNDED,
                    border_style="yellow",
                )
            )

        if match.evidence:
            ev_text = "\n".join(f"• {ev}" for ev in match.evidence)
            cards.append(
                Panel(
                    ev_text,
                    title="[bold bright_cyan]🔍 VERIFIED EVIDENCE[/bold bright_cyan]",
                    box=box.ROUNDED,
                    border_style="cyan",
                )
            )

        if match.reproduction:
            repro_text = "\n".join(match.reproduction)
            cards.append(
                Panel(
                    f"[bold bright_green]{repro_text}[/bold bright_green]",
                    title="[bold bright_green]🚀 REPRODUCTION COMMAND[/bold bright_green]",
                    box=box.ROUNDED,
                    border_style="green",
                )
            )

        if match.recommended_next_action:
            cards.append(
                Panel(
                    match.recommended_next_action,
                    title="[bold bright_magenta]🎯 RECOMMENDED OPERATOR ACTION[/bold bright_magenta]",
                    box=box.ROUNDED,
                    border_style="bright_magenta",
                )
            )

        self.console.print()
        for card in cards:
            self.console.print(card)
        self.console.print()


    def next_actions(self):
        state = self.workspace.load()
        if not state.actions:
            self.console.print("\n[dim yellow]No pending actions in queue.[/dim yellow]\n")
            return

        table = Table(
            title=f"[bold bright_yellow]✦ PRIORITIZED NEXT ACTIONS — {state.target} ✦[/bold bright_yellow]",
            box=box.ROUNDED,
            border_style="yellow",
            header_style="bold bright_cyan",
            expand=True,
        )
        table.add_column("Rank", justify="center", style="bold bright_yellow", no_wrap=True)
        table.add_column("Score", justify="center", no_wrap=True)
        table.add_column("Action", style="bold bright_white")
        table.add_column("Reason / Prerequisite", style="dim italic cyan")

        rank_symbols = ["①", "②", "③", "④", "⑤", "⑥", "⑦", "⑧", "⑨", "⑩"]
        for idx, action in enumerate(state.actions):
            sym = rank_symbols[idx] if idx < len(rank_symbols) else f"#{idx + 1}"
            score_color = "bright_magenta" if action.score >= 90 else "bright_yellow" if action.score >= 80 else "cyan"
            table.add_row(
                sym,
                f"[{score_color}]{int(action.score)}[/{score_color}]",
                action.title,
                action.reason,
            )

        self.console.print()
        self.console.print(table)
        self.console.print()

    def credentials(self):
        state = self.workspace.load()
        if not state.credentials:
            self.console.print("\n[dim yellow]No credentials recovered yet.[/dim yellow]\n")
            return

        table = Table(
            title=f"[bold bright_yellow]✦ RECOVERED CREDENTIALS — {state.target} ✦[/bold bright_yellow]",
            box=box.ROUNDED,
            border_style="yellow",
            header_style="bold bright_cyan",
            expand=True,
        )
        table.add_column("Kind", style="bold bright_yellow")
        table.add_column("Username", style="bold bright_white")
        table.add_column("Secret", style="dim white")
        table.add_column("Source", style="dim italic cyan")

        for credential in state.credentials:
            secret = (
                "[dim]🔒 " + ("*" * min(10, max(4, len(credential.secret)))) + "[/dim]"
                if credential.secret else "-"
            )
            table.add_row(
                credential.kind.upper(),
                credential.username or "[dim]none[/dim]",
                secret,
                credential.source,
            )

        self.console.print()
        self.console.print(table)
        self.console.print()

    def graph(self):
        state = self.workspace.load()

        root_tree = Tree(
            f"[bold bright_magenta]❖ TARGET[/bold bright_magenta] [bold bright_cyan]{state.target}[/bold bright_cyan]",
            guide_style="bold magenta",
        )

        # Services branch
        services_branch = root_tree.add(
            f"[bold bright_white]🌐 OPEN SERVICES ({len(state.services)})[/bold bright_white]",
            guide_style="cyan",
        )
        for service in sorted(state.services, key=lambda s: s.port):
            svc_node = services_branch.add(
                f"[bold green]● {service.port}/{service.protocol.upper()}[/bold green] "
                f"[bold bright_white]{service.service or 'service'}[/bold bright_white] "
                f"[dim]({service.product or ''} {service.version or ''})[/dim]"
            )
            # Link findings directly related to this service or port
            for finding in state.findings:
                if f":{service.port}" in finding.title or service.service and service.service.lower() in finding.title.lower():
                    svc_node.add(
                        f"{get_severity_badge(finding.severity.value)} [bright_white]{finding.title}[/bright_white]"
                    )

        # Findings branch
        if state.findings:
            findings_branch = root_tree.add(
                f"[bold red]⚡ DETECTED FINDINGS ({len(state.findings)})[/bold red]",
                guide_style="red",
            )
            for finding in state.findings:
                findings_branch.add(
                    f"{get_severity_badge(finding.severity.value)} "
                    f"[bright_white]{finding.title}[/bright_white] "
                    f"[dim]({finding.status.value})[/dim]"
                )

        # Credentials branch
        if state.credentials:
            creds_branch = root_tree.add(
                f"[bold yellow]🔑 CREDENTIALS ({len(state.credentials)})[/bold yellow]",
                guide_style="yellow",
            )
            for cred in state.credentials:
                creds_branch.add(
                    f"[bold yellow]{cred.username}[/bold yellow] [dim]({cred.kind}) from {cred.source}[/dim]"
                )

        # Tech branch
        if state.technologies:
            tech_branch = root_tree.add(
                f"[bold blue]⬡ WEB TECHNOLOGIES ({len(state.technologies)})[/bold blue]",
                guide_style="blue",
            )
            for tech in state.technologies:
                tech_branch.add(f"[bright_cyan]{tech}[/bright_cyan]")

        self.console.print()
        self.console.print(
            Panel(
                root_tree,
                title=f"[bold bright_magenta]✦ ATTACK SURFACE GRAPH — {state.target} ✦[/bold bright_magenta]",
                box=box.ROUNDED,
                border_style="bright_magenta",
                padding=(1, 2),
            )
        )
        self.console.print()

    def web(self):
        state = self.workspace.load()
        table = Table(
            title=f"[bold bright_blue]✦ WEB ATTACK SURFACE — {state.target} ✦[/bold bright_blue]",
            box=box.ROUNDED,
            border_style="blue",
            header_style="bold bright_cyan",
            expand=True,
        )
        table.add_column("Property", style="bold bright_white")
        table.add_column("Details", style="bright_cyan")

        table.add_row(
            "Identified Technologies",
            ", ".join(state.technologies) if state.technologies else "[dim]none detected[/dim]",
        )
        table.add_row(
            "HTTP Response Artifacts",
            f"{self.workspace.root / 'responses'}",
        )
        table.add_row(
            "Header Logs",
            f"{self.workspace.root / 'headers'}",
        )

        self.console.print()
        self.console.print(table)
        self.console.print(
            "[dim cyan]💡 Tip: Use [bold magenta]'source <artifact>'[/bold magenta] to inspect raw HTTP response bodies and headers.[/dim cyan]\n"
        )

    def exploits(self, candidates):
        if not candidates:
            self.console.print(
                "\n[dim yellow]No SearchSploit candidates stored. "
                "SearchSploit may not be installed or returned no matching exploits.[/dim yellow]\n"
            )
            return

        table = Table(
            title="[bold bright_magenta]✦ CVE / SEARCHSPLOIT CANDIDATES ✦[/bold bright_magenta]",
            box=box.ROUNDED,
            border_style="magenta",
            header_style="bold bright_cyan",
            expand=True,
        )
        table.add_column("Confidence", justify="center", no_wrap=True)
        table.add_column("CVE", style="bold bright_red", no_wrap=True)
        table.add_column("Product", style="bright_white")
        table.add_column("Version", style="bold bright_green")
        table.add_column("Relevance / Decision", justify="center", no_wrap=True)
        table.add_column("Exploitability", style="dim cyan")
        table.add_column("Title", style="italic white")

        for candidate in candidates:
            dec_badge = get_exploit_decision_badge(candidate.relevance, candidate.ai_decision)
            table.add_row(
                get_confidence_meter(candidate.confidence),
                candidate.cve or "[dim]-[/dim]",
                candidate.product,
                candidate.version or "[dim]any[/dim]",
                dec_badge,
                candidate.exploitability,
                candidate.title,
            )

        self.console.print()
        self.console.print(table)
        self.console.print()

    def intel(self):
        loading(self.console, "Correlating with SearchSploit intelligence", 0.5)
        candidates = searchsploit_workspace(self.workspace, CommandRunner(self.workspace))
        state = self.workspace.load()

        if self.ai_manager.is_enabled and self.ai_manager.get_provider() and candidates:
            loading(self.console, f"AI Triaging {len(candidates[:10])} exploit candidate(s)", 0.6)
            candidates = self.ai_manager.triage_exploits(state, candidates)
            self.workspace.set_exploits(candidates)

        self.exploits(candidates)

    def nuclei(self):
        state = self.workspace.load()
        http_service = next(
            (
                item for item in state.services
                if item.port in {
                    80, 81, 443, 3000, 5000, 8000,
                    8080, 8081, 8443, 8888, 9000
                }
            ),
            None,
        )

        if not http_service:
            raise ValueError("no common HTTP service discovered on target")

        scheme = "https" if http_service.port in {443, 8443} else "http"
        url = f"{scheme}://{self.workspace.target}:{http_service.port}"

        loading(self.console, f"Running Nuclei scan against {url}", 0.6)
        result = run_nuclei(
            self.workspace,
            CommandRunner(self.workspace),
            url,
        )

        if result is None:
            self.console.print("[bold yellow]✖ Nuclei is not installed or not in PATH.[/bold yellow]")
        else:
            self.console.print(
                f"[bold green]✔ Nuclei completed successfully (code {result.returncode}).[/bold green]"
            )

    def ask_cmd(self, args: list[str]):
        if len(args) < 2:
            raise ValueError("usage: ask <question in quotes>")
        question = " ".join(args[1:])
        state = self.workspace.load()

        loading(self.console, "Consulting HORCRUX AI reasoning engine", 0.6)
        answer = self.ai_manager.ask(state, question)

        self.console.print()
        self.console.print(
            Panel(
                answer,
                title=f"[bold bright_magenta]⚡ HORCRUX AI ADVISOR — '{question[:45]}'[/bold bright_magenta]",
                box=box.ROUNDED,
                border_style="bright_magenta",
                padding=(1, 2),
            )
        )
        self.console.print()

    def settings_cmd(self, args: list[str]):
        mgr = SettingsManager()

        if len(args) == 1:
            st = mgr.settings
            default_p = st.default_provider
            default_m = st.providers.get(default_p, None)
            model_name = default_m.model if default_m else "-"
            ai_status = "[bold green]ENABLED[/bold green]" if st.enabled else "[bold red]DISABLED[/bold red]"

            providers_lines = []
            symbols = ["①", "②", "③", "④"]
            prov_names = [
                ("groq", "Groq"),
                ("openai", "OpenAI"),
                ("anthropic", "Anthropic / Claude"),
                ("google", "Google AI Studio / Gemini"),
            ]

            for idx, (p_id, p_label) in enumerate(prov_names):
                sym = symbols[idx]
                has_key, masked = mgr.get_provider_status(p_id)
                status_icon = "[bold green]● CONFIGURED[/bold green]" if has_key else "[dim]○ NOT CONFIGURED[/dim]"
                model = st.providers.get(p_id, None)
                m_str = f"[dim cyan]Model: {model.model}[/dim cyan]" if (model and model.model) else ""
                key_str = f"[dim white]({masked})[/dim white]" if has_key else ""
                providers_lines.append(f"  {sym} [bold bright_white]{p_label:<24}[/bold bright_white] {status_icon} {key_str}")
                if m_str:
                    providers_lines.append(f"     {m_str}")
                providers_lines.append("")

            body = (
                "[bold bright_magenta]AI PROVIDERS[/bold bright_magenta]\n\n"
                + "\n".join(providers_lines)
                + f"[bold bright_yellow]Default Provider:[/bold bright_yellow] [bold bright_cyan]{default_p.upper()}[/bold bright_cyan]\n"
                + f"[bold bright_yellow]Default Model:   [/bold bright_yellow] [bold bright_cyan]{model_name}[/bold bright_cyan]\n"
                + f"[bold bright_yellow]AI Engine Status:[/bold bright_yellow] {ai_status}\n\n"
                + "[dim cyan]💡 Tip: Model availability may vary by region or account. Use 'settings model' to select or switch.[/dim cyan]\n\n"
                + "[dim white]Commands:\n"
                + "  settings provider <groq|openai|anthropic|google> [api_key]\n"
                + "  settings model [provider] [model_name]  (select or change model)\n"
                + "  settings models [provider]              (list available regional models)\n"
                + "  settings default <provider>\n"
                + "  settings test [provider]\n"
                + "  settings remove <provider>[/dim white]"
            )

            self.console.print()
            self.console.print(
                Panel(
                    body,
                    title="[bold bright_magenta]✦ HORCRUX SETTINGS ✦[/bold bright_magenta]",
                    box=box.ROUNDED,
                    border_style="bright_magenta",
                    padding=(1, 2),
                )
            )
            self.console.print()
            return

        sub = args[1].lower()
        if sub == "provider":
            if len(args) < 3:
                raise ValueError("usage: settings provider <groq|openai|anthropic|google> [api_key]")
            p_name = args[2].lower()
            if len(args) >= 4:
                key_val = args[3].strip()
            else:
                key_val = Prompt.ask(f"[bold bright_cyan]Enter API key for {p_name.upper()}[/bold bright_cyan]", password=True).strip()
            if key_val:
                mgr.set_api_key(p_name, key_val)
                self.ai_manager = AIManager()
                self.console.print(f"[bold green]✔ API key stored securely for provider '{p_name}'.[/bold green]")
                try:
                    choose_model = Prompt.ask(
                        f"[dim cyan]Would you like to select a specific model for {p_name.upper()}? (may vary by region)[/dim cyan]",
                        choices=["y", "n"],
                        default="n",
                    )
                    if choose_model.lower() == "y":
                        self.settings_cmd(["settings", "model", p_name])
                except Exception:
                    pass
            else:
                self.console.print("[yellow]No key provided.[/yellow]")

        elif sub in {"model", "models"}:
            # Determine provider
            if len(args) >= 3 and args[2].lower() in {"groq", "openai", "anthropic", "google"}:
                p_name = args[2].lower()
            else:
                p_name = Prompt.ask(
                    "[bold bright_cyan]Select AI Provider[/bold bright_cyan]",
                    choices=["groq", "openai", "anthropic", "google"],
                    default=mgr.settings.default_provider,
                ).lower()

            # Direct CLI or console set: `settings model <provider> <model_name>`
            if len(args) >= 4 and sub == "model":
                m_name = " ".join(args[3:]).strip()
                mgr.set_model(p_name, m_name)
                self.ai_manager = AIManager()
                self.console.print(f"[bold green]✔ Active model for '{p_name}' set to '{m_name}'.[/bold green]")
                return

            # Interactive model selector with regional discovery
            cur_model = mgr.settings.providers.get(p_name, ProviderConfig(name=p_name, model=DEFAULT_MODELS.get(p_name, ""))).model

            loading(self.console, f"Discovering available models for {p_name.upper()} (regional/account)...", 0.4)
            available = self.ai_manager.get_available_models(p_name)
            if not available:
                available = AVAILABLE_MODELS.get(p_name, [cur_model])

            if cur_model and cur_model not in available:
                available = [cur_model] + available

            table = Table(
                title=f"[bold bright_magenta]✦ {p_name.upper()} AVAILABLE MODELS (REGIONAL SELECTION) ✦[/bold bright_magenta]",
                box=box.ROUNDED,
                border_style="magenta",
                header_style="bold bright_cyan",
            )
            table.add_column("#", justify="center", style="bold yellow", no_wrap=True)
            table.add_column("Model Identifier", style="bold bright_white")
            table.add_column("Status", justify="center", no_wrap=True)

            for idx, m_id in enumerate(available, 1):
                st_badge = "[bold green]★ CURRENT[/bold green]" if m_id == cur_model else "[dim cyan]available[/dim cyan]"
                table.add_row(str(idx), m_id, st_badge)

            self.console.print()
            self.console.print(table)
            self.console.print(
                "[dim cyan]💡 Tip: Model availability varies by region, quota, or enterprise tenancy.\n"
                "   Choose a number [1-N], enter a custom model name (e.g. gemini-1.5-flash), or press Enter to keep current.[/dim cyan]\n"
            )

            choice = Prompt.ask(
                f"[bold bright_yellow]Select model for {p_name.upper()} [1-{len(available)} or custom][/bold bright_yellow]",
                default=cur_model,
            ).strip()

            if not choice or choice == cur_model:
                self.console.print(f"[dim]Retaining current model '{cur_model}'.[/dim]")
                return

            if choice.isdigit() and 1 <= int(choice) <= len(available):
                chosen_model = available[int(choice) - 1]
            else:
                chosen_model = choice

            mgr.set_model(p_name, chosen_model)
            self.ai_manager = AIManager()
            self.console.print(f"[bold green]✔ Active model for '{p_name}' successfully set to '{chosen_model}'.[/bold green]")


        elif sub == "default":
            if len(args) < 3:
                raise ValueError("usage: settings default <groq|openai|anthropic|google>")
            p_name = args[2].lower()
            mgr.set_default_provider(p_name)
            self.ai_manager = AIManager()
            self.console.print(f"[bold green]✔ Default provider set to '{p_name}'.[/bold green]")

        elif sub == "remove":
            if len(args) < 3:
                raise ValueError("usage: settings remove <provider>")
            p_name = args[2].lower()
            mgr.remove_api_key(p_name)
            self.ai_manager = AIManager()
            self.console.print(f"[bold yellow]✔ Removed stored API key for '{p_name}'.[/bold yellow]")

        elif sub == "test":
            p_name = args[2].lower() if len(args) >= 3 else mgr.settings.default_provider
            loading(self.console, f"Testing API connection to {p_name.upper()}", 0.5)
            provider = self.ai_manager.providers.get(p_name)
            if not provider:
                self.console.print(f"[bold red]✖ Unknown provider '{p_name}'.[/bold red]")
                return
            ok, msg = provider.validate_key()
            if ok:
                self.console.print(f"[bold green]✔ {msg}[/bold green]")
            else:
                self.console.print(f"[bold red]✖ {msg}[/bold red]")

    def ai_cmd(self, args: list[str]):
        if len(args) == 1 or args[1].lower() == "status":
            st = self.ai_manager.status()
            status_badge = "[bold green]READY[/bold green]" if st["status"] == "READY" else f"[dim yellow]{st['status']}[/dim yellow]"
            body = (
                f"[bold bright_yellow]Status:          [/bold bright_yellow] {status_badge}\n"
                f"[bold bright_yellow]Active Provider: [/bold bright_yellow] [bold bright_cyan]{st['provider'].upper()}[/bold bright_cyan]\n"
                f"[bold bright_yellow]Active Model:    [/bold bright_yellow] [bold bright_white]{st['model']}[/bold bright_white]\n"
                f"[bold bright_yellow]Calls Made:      [/bold bright_yellow] {st['calls']}\n"
                f"[bold bright_yellow]Cached Responses:[/bold bright_yellow] {st['cached_calls']}\n"
                f"[bold bright_yellow]Total Tokens:    [/bold bright_yellow] {st['total_tokens']}\n"
            )
            self.console.print()
            self.console.print(
                Panel(
                    body,
                    title="[bold bright_magenta]✦ AI ENGINE STATUS ✦[/bold bright_magenta]",
                    box=box.ROUNDED,
                    border_style="magenta",
                )
            )
            self.console.print()
            return

        sub = args[1].lower()
        if sub == "enable":
            self.ai_manager.settings.set_enabled(True)
            self.console.print("[bold green]✔ AI engine enabled.[/bold green]")
        elif sub == "disable":
            self.ai_manager.settings.set_enabled(False)
            self.console.print("[bold yellow]✔ AI engine disabled. Falling back to local deterministic intelligence.[/bold yellow]")
        elif sub in {"clear-cache", "clearcache"}:
            self.ai_manager.clear_cache()
            self.console.print("[bold green]✔ AI response cache cleared.[/bold green]")
        elif sub == "usage":
            self.ai_cmd(["ai", "status"])
        else:
            raise ValueError("usage: ai [status|enable|disable|usage|clear-cache]")

    def raw_cmd(self, args: list[str]):
        if len(args) < 2:
            raise ValueError("usage: raw <module_name> (e.g. raw nmap-tcp, raw nuclei, raw smbclient)")
        target_name = args[1].lower()
        matching = list(self.workspace.raw.glob(f"*{target_name}*"))
        if not matching:
            raise ValueError(f"No raw artifacts matching '{target_name}' found in {self.workspace.raw}")
        content = matching[0].read_text(encoding="utf-8", errors="replace")
        self.console.print(
            Panel(
                content[:4000] + ("\n... [truncated]" if len(content) > 4000 else ""),
                title=f"[bold bright_cyan]{matching[0].name}[/bold bright_cyan]",
                box=box.ROUNDED,
                border_style="cyan",
            )
        )

    def doctor(self, only_tools=False):
        tools, wordlists = check_tools()

        # Group tools by CATEGORIES
        table = Table(
            title="[bold bright_cyan]✦ HORCRUX PLATFORM & TOOL ECOSYSTEM AUDIT ✦[/bold bright_cyan]",
            box=box.ROUNDED,
            border_style="cyan",
            header_style="bold bright_magenta",
            expand=True,
        )
        table.add_column("Category", style="bold bright_yellow", no_wrap=True)
        table.add_column("Tool", style="bold bright_white")
        table.add_column("Status", justify="center", no_wrap=True)
        table.add_column("Purpose", style="dim white")
        table.add_column("Install Guidance", style="italic yellow")

        tool_map = {item[0]: item for item in tools}

        for cat_name, cat_tools in CATEGORIES.items():
            for tool_name, desc in cat_tools.items():
                item = tool_map.get(tool_name)
                path = item[1] if item else None
                install_guide = item[3] if item and len(item) > 3 else ""
                status_text = "[bold green]✔ OK[/bold green]" if path else "[dim red]✖ MISSING[/dim red]"
                guide_text = "" if path else install_guide
                table.add_row(cat_name, tool_name, status_text, desc, guide_text)

        self.console.print()
        self.console.print(table)

        if only_tools:
            self.console.print()
            return

        # AI Configuration Audit
        ai_table = Table(
            title="[bold bright_magenta]✦ AI ENGINE & KEYCHAIN AUDIT ✦[/bold bright_magenta]",
            box=box.ROUNDED,
            border_style="magenta",
            header_style="bold bright_cyan",
            expand=True,
        )
        ai_table.add_column("Provider", style="bold bright_white")
        ai_table.add_column("Status", justify="center", no_wrap=True)
        ai_table.add_column("Default Model", style="bold bright_green")
        ai_table.add_column("Key Availability", style="dim white")

        mgr = SettingsManager()
        for p_name in ("groq", "openai", "anthropic", "google"):
            has_key, masked = mgr.get_provider_status(p_name)
            model = mgr.settings.providers.get(p_name, None)
            m_str = model.model if model else "-"
            st_text = "[bold green]✔ CONFIGURED[/bold green]" if has_key else "[dim]○ NOT CONFIGURED[/dim]"
            ai_table.add_row(p_name.upper(), st_text, m_str, masked)

        self.console.print()
        self.console.print(ai_table)

        words = Table(
            title="[bold bright_yellow]✦ WORDLIST DISCOVERY AUDIT ✦[/bold bright_yellow]",
            box=box.ROUNDED,
            border_style="yellow",
            header_style="bold bright_cyan",
            expand=True,
        )
        words.add_column("Wordlist", style="bold bright_white")
        words.add_column("Status", justify="center", no_wrap=True)
        words.add_column("Location / Path", style="dim cyan")

        for name, path in wordlists:
            status_text = "[bold green]✔ FOUND[/bold green]" if path else "[dim yellow]– MISSING[/dim yellow]"
            words.add_row(name, status_text, str(path or "-"))

        self.console.print()
        self.console.print(words)
        self.console.print()

