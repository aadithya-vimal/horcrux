from __future__ import annotations

import shlex

from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table

from horcrux.core.doctor import check_tools
from horcrux.core.intel import run_nuclei
from horcrux.core.runner import CommandRunner
from horcrux.core.storage import Workspace
from horcrux.intel.search import searchsploit_workspace
from horcrux.modules.local import enumerate_linux
from horcrux.reporting.reports import markdown
from horcrux.core.orchestrator import Orchestrator
from horcrux.ui.ascii import banner, loading


HELP = """
scan <target> [--deep] [--verify]  run reconnaissance
status                             workspace summary
services                           service inventory
software                           software/version inventory
findings                           findings
next                               ranked next actions
creds                              credentials (masked)
graph                              compact attack graph
web                                HTTP summary
cve                                SearchSploit/CVE intelligence
searchsploit                       alias for cve
nuclei                             run Nuclei for discovered HTTP
exploit                             review exploit candidates
local                              Linux local enumeration
doctor                             tool + wordlist audit
tools                              tools only
source <artifact>                  intentionally display raw artifact
report                             Markdown report
clear                              clear terminal
help                               command help
exit                               leave Horcrux
"""


class ConsoleApp:
    def __init__(self):
        self.console = Console()
        self.workspace: Workspace | None = None

    def run(self):
        banner(self.console, duration=1.0)
        self.console.print("[dim]Type 'help' for commands.[/dim]\n")

        while True:
            try:
                line = Prompt.ask("[bold magenta]horcrux[/bold magenta]").strip()
            except (EOFError, KeyboardInterrupt):
                self.console.print()
                return

            if not line:
                continue

            if line.lower() in {"exit", "quit"}:
                return

            try:
                self.dispatch(shlex.split(line))
            except Exception as exc:
                self.console.print(f"[red]Error:[/red] {exc}")

    def dispatch(self, args: list[str]):
        if not args:
            return

        command = args[0].lower()

        if command == "help":
            self.console.print(HELP)
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

        if command == "scan":
            if len(args) < 2:
                raise ValueError("usage: scan <target> [--deep] [--verify]")

            self.workspace = Workspace(args[1])
            banner(self.console, duration=.35)

            Orchestrator(
                args[1],
                self.workspace,
                self.console,
            ).scan(
                deep="--deep" in args[2:],
                verify="--verify" in args[2:],
            )

            self.status()
            return

        if command == "local":
            self.require_workspace()
            loading(self.console, "Running Linux local enumeration", .5)
            enumerate_linux(self.workspace, CommandRunner(self.workspace))
            self.console.print(
                f"[green]Saved:[/green] {self.workspace.root}"
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
            loading(self.console, "Searching SearchSploit", .55)
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
                "[yellow]Review candidates before using external PoCs or exploit modules; "
                "Horcrux does not silently fire arbitrary exploit code.[/yellow]"
            )

        elif command == "source":
            if len(args) < 2:
                raise ValueError("usage: source <artifact>")
            path = self.workspace.root / args[1]
            if not path.exists():
                raise ValueError(f"artifact not found: {args[1]}")
            self.console.print(
                path.read_text(encoding="utf-8", errors="replace")
            )

        elif command == "report":
            self.console.print(
                f"[green]Report written:[/green] {markdown(self.workspace)}"
            )

        else:
            raise ValueError(f"unknown command: {command}")

    def require_workspace(self):
        if not self.workspace:
            raise ValueError("no workspace loaded; run scan <target> first")

    def status(self):
        state = self.workspace.load()

        table = Table(title=f"STATUS — {state.target}")
        table.add_column("Metric")
        table.add_column("Value")

        metrics = [
            ("Services", len(state.services)),
            ("Software", len(state.software)),
            ("Technologies", ", ".join(state.technologies) or "-"),
            ("Findings", len(state.findings)),
            ("Credentials", len(state.credentials)),
            ("Exploit candidates", len(state.exploits)),
        ]

        for name, value in metrics:
            table.add_row(name, str(value))

        self.console.print(table)

    def services(self):
        table = Table(title="SERVICES")
        for column in ["Port", "Proto", "Service", "Product", "Version"]:
            table.add_column(column)

        for service in sorted(
            self.workspace.load().services,
            key=lambda item: (item.port, item.protocol),
        ):
            table.add_row(
                str(service.port),
                service.protocol,
                service.service,
                service.product,
                service.version,
            )

        self.console.print(table)

    def software(self):
        table = Table(title="SOFTWARE INVENTORY")
        for column in ["Product", "Version", "Service", "Source"]:
            table.add_column(column)

        for software in self.workspace.load().software:
            table.add_row(
                software.product,
                software.version,
                software.service,
                software.source,
            )

        self.console.print(table)

    def findings(self):
        table = Table(title="FINDINGS")
        for column in ["Severity", "Confidence", "Title", "Status"]:
            table.add_column(column)

        for finding in sorted(
            self.workspace.load().findings,
            key=lambda item: -item.confidence,
        ):
            table.add_row(
                finding.severity.value.upper(),
                f"{finding.confidence:.0%}",
                finding.title,
                finding.status.value,
            )

        self.console.print(table)

    def next_actions(self):
        table = Table(title="NEXT BEST ACTIONS")
        for column in ["Score", "Action", "Reason"]:
            table.add_column(column)

        for action in self.workspace.load().actions:
            table.add_row(
                str(int(action.score)),
                action.title,
                action.reason,
            )

        self.console.print(table)

    def credentials(self):
        table = Table(title="CREDENTIALS")
        for column in ["Kind", "Username", "Secret", "Source"]:
            table.add_column(column)

        for credential in self.workspace.load().credentials:
            secret = (
                "*" * min(12, max(4, len(credential.secret)))
                if credential.secret else "-"
            )
            table.add_row(
                credential.kind,
                credential.username,
                secret,
                credential.source,
            )

        self.console.print(table)

    def graph(self):
        state = self.workspace.load()

        self.console.print(
            f"[bold]TARGET[/bold] {state.target}"
        )

        for service in state.services:
            self.console.print(
                f"  └─ {service.port}/{service.protocol} → "
                f"{service.service or service.product or 'unknown'}"
            )

        for finding in state.findings:
            self.console.print(
                f"      └─ [{finding.severity.value.upper()}] "
                f"{finding.title}"
            )

    def web(self):
        state = self.workspace.load()
        table = Table(title="WEB SURFACE")
        table.add_column("Metric")
        table.add_column("Value")
        table.add_row(
            "Technologies",
            ", ".join(state.technologies) or "-",
        )
        self.console.print(table)
        self.console.print(
            "[dim]Bodies and headers are stored in responses/ and headers/.[/dim]"
        )

    def exploits(self, candidates):
        if not candidates:
            self.console.print(
                "[yellow]No SearchSploit candidates stored. "
                "SearchSploit may be missing or no matches were returned.[/yellow]"
            )
            return

        table = Table(title="CVE / SEARCHSPLOIT CANDIDATES")
        for column in [
            "Confidence", "CVE", "Product", "Version", "Title", "Source"
        ]:
            table.add_column(column)

        for candidate in candidates:
            table.add_row(
                f"{candidate.confidence:.0%}",
                candidate.cve or "-",
                candidate.product,
                candidate.version,
                candidate.title,
                candidate.source,
            )

        self.console.print(table)

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
            raise ValueError("no common HTTP service discovered")

        scheme = "https" if http_service.port in {443, 8443} else "http"
        url = f"{scheme}://{self.workspace.target}:{http_service.port}"

        loading(self.console, "Running Nuclei", .5)
        result = run_nuclei(
            self.workspace,
            CommandRunner(self.workspace),
            url,
        )

        if result is None:
            self.console.print("[yellow]Nuclei is not installed.[/yellow]")
        else:
            self.console.print(
                f"[green]Nuclei finished with exit code "
                f"{result.returncode}.[/green]"
            )

    def doctor(self, only_tools=False):
        tools, wordlists = check_tools()

        table = Table(
            title="HORCRUX TOOLS" if only_tools else "HORCRUX DOCTOR"
        )
        table.add_column("Tool")
        table.add_column("Status")
        table.add_column("Purpose")

        for name, path, purpose in tools:
            table.add_row(
                name,
                "[green]OK[/green]" if path else "[red]MISSING[/red]",
                purpose,
            )

        self.console.print(table)

        if only_tools:
            return

        words = Table(title="WORDLISTS")
        words.add_column("Wordlist")
        words.add_column("Status")
        words.add_column("Location")

        for name, path in wordlists:
            words.add_row(
                name,
                "[green]FOUND[/green]" if path else "[yellow]MISSING[/yellow]",
                str(path or "-"),
            )

        self.console.print(words)
