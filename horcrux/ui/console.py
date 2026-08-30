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

from horcrux.core.doctor import check_tools
from horcrux.core.intel import run_nuclei
from horcrux.core.runner import CommandRunner
from horcrux.core.storage import Workspace
from horcrux.intel.search import searchsploit_workspace
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
    sev = severity_val.lower()
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
    st = status_val.lower()
    if st == "verified":
        return "[bold green]✔ VERIFIED[/bold green]"
    elif st == "exploited":
        return "[bold red]☠ EXPLOITED[/bold red]"
    elif st == "suspected":
        return "[bold yellow]❓ SUSPECTED[/bold yellow]"
    elif st == "mitigated":
        return "[dim green]🛡 MITIGATED[/dim green]"
    return f"[dim]{status_val}[/dim]"


class ConsoleApp:
    def __init__(self):
        self.console = Console()
        self.workspace: Workspace | None = None

    def print_help(self):
        grid = Table.grid(padding=(0, 2))
        grid.add_column(style="bold bright_cyan", justify="left")
        grid.add_column(style="dim white", justify="left")

        categories = [
            (
                "⚡ RECONNAISSANCE",
                [
                    ("scan <target> [--deep] [--verify]", "Full automated attack surface discovery"),
                    ("status", "Display current workspace metrics & indicators"),
                    ("services", "Service inventory with protocols and versions"),
                    ("software", "Software & framework detection breakdown"),
                    ("web", "Web attack surface and technology fingerprinting"),
                ]
            ),
            (
                "🎯 INTELLIGENCE & CORRELATION",
                [
                    ("findings", "Security findings with evidence & confidence meters"),
                    ("next", "Ranked Next Best Actions prioritized by confidence"),
                    ("creds", "Recovered credentials with masked secrets"),
                    ("graph", "Interactive attack surface graph visualization"),
                    ("cve / searchsploit", "Correlate software with known exploit candidates"),
                    ("nuclei", "Execute targeted Nuclei templates against web targets"),
                ]
            ),
            (
                "🛡 EXPLOIT & POST-EXPLOITATION",
                [
                    ("exploit", "Review actionable exploit candidates"),
                    ("local", "Perform Linux local privilege escalation checks"),
                ]
            ),
            (
                "🛠 UTILITIES & VISUALS",
                [
                    ("doctor", "Audit installed tools and Kali SecLists wordlists"),
                    ("tools", "Fast check of external binary availability"),
                    ("artifacts / gallery", "View the Horcrux ASCII art gallery"),
                    ("source <artifact>", "Inspect raw tool output or response body"),
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

        elif command == "services":
            self.services()

        elif command == "software":
            self.software()

        elif command == "findings":
            self.findings()

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
                f"[bold cyan]{len(state.software)}[/bold cyan]\n[dim]Identified[/dim]",
                title="[bold cyan]📦 SOFTWARE[/bold cyan]",
                box=box.ROUNDED,
                border_style="cyan",
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
        table.add_column("Status", justify="center", no_wrap=True)

        for finding in sorted(
            state.findings,
            key=lambda item: -item.confidence,
        ):
            table.add_row(
                get_severity_badge(finding.severity.value),
                get_confidence_meter(finding.confidence),
                finding.title,
                get_status_badge(finding.status.value),
            )

        self.console.print()
        self.console.print(table)
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
        table.add_column("Title", style="italic white")
        table.add_column("Source", style="dim cyan")

        for candidate in candidates:
            table.add_row(
                get_confidence_meter(candidate.confidence),
                candidate.cve or "[dim]-[/dim]",
                candidate.product,
                candidate.version or "[dim]any[/dim]",
                candidate.title,
                candidate.source,
            )

        self.console.print()
        self.console.print(table)
        self.console.print()

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

    def doctor(self, only_tools=False):
        tools, wordlists = check_tools()

        table = Table(
            title="[bold bright_cyan]✦ HORCRUX TOOL ECOSYSTEM AUDIT ✦[/bold bright_cyan]",
            box=box.ROUNDED,
            border_style="cyan",
            header_style="bold bright_magenta",
            expand=True,
        )
        table.add_column("Tool", style="bold bright_white")
        table.add_column("Status", justify="center", no_wrap=True)
        table.add_column("Purpose", style="dim white")
        table.add_column("Install Guidance", style="italic yellow")

        for item in tools:
            name, path, purpose = item[0], item[1], item[2]
            install_guide = item[3] if len(item) > 3 else ""
            status_text = "[bold green]✔ OK[/bold green]" if path else "[bold red]✖ MISSING[/bold red]"
            guide_text = "" if path else install_guide
            table.add_row(name, status_text, purpose, guide_text)

        self.console.print()
        self.console.print(table)

        if only_tools:
            self.console.print()
            return

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
