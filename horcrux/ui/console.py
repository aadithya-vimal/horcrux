from __future__ import annotations

import difflib
import shlex
import sys
import time
from typing import List

from rich import box
from rich.align import Align
from rich.columns import Columns
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from horcrux import __version__
from horcrux.core.actions import compute_next_actions
from horcrux.core.doctor import check_tools, CATEGORIES, ToolImportance
from horcrux.ui.progress import AIProgressManager
from horcrux.core.intel import run_nuclei
from horcrux.core.runner import CommandRunner
from horcrux.core.sanitizer import fingerprint_key
from horcrux.core.settings import (
    AVAILABLE_MODELS,
    DEFAULT_MODELS,
    SettingsManager,
    mask_key,
    normalize_provider_name,
)
from horcrux.core.storage import Workspace
from horcrux.intel.ai.manager import AIManager
from horcrux.intel.search import searchsploit_workspace
from horcrux.models import AuditStatus, SubsystemState, ValidationState

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


PATH_STATUS_BADGES = {
    "CONFIRMED": "[bold red]CONFIRMED FINDING[/bold red]",
    "SUPPORTED": "[green]SUPPORTED[/green]",
    "REFUTED": "[dim]REFUTED[/dim]",
    "INSUFFICIENT_EVIDENCE": "[yellow]INSUFFICIENT_EVIDENCE[/yellow]",
    "BLOCKED": "[yellow]BLOCKED[/yellow]",
    "HYPOTHESIS": "[cyan]HYPOTHESIS[/cyan]",
}


def path_status_badge(status: str) -> str:
    """Canonical graph status label. Unknown/missing means HYPOTHESIS."""
    return PATH_STATUS_BADGES.get(str(status or "HYPOTHESIS"), f"[dim]{status}[/dim]")


def edge_display_kind(edge: dict) -> str:
    """One of inferred|evidenced|observed|unverified.

    'evidenced' requires validator/adjudication evidence
    (security_evidence); discovery observations render as 'observed'.
    """
    e = edge or {}
    if e.get("inference"):
        return "inferred"
    if e.get("security_evidence"):
        return "evidenced"
    if e.get("evidence"):
        return "observed"
    return "unverified"


def _edge_display_line(edge: dict) -> str:
    kind = edge_display_kind(edge)
    if kind == "inferred":
        return "[yellow]╌ inferred — needs validation[/yellow]"
    if kind == "evidenced":
        return "[green]━ evidenced (validator)[/green]"
    if kind == "observed":
        return "[dim]┄ observed (not security evidence)[/dim]"
    return "[dim]┄ unverified[/dim]"


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


def _parse_engines_flag(args: list[str]) -> list[str] | None:
    """Parse --engines a,b from console scan args (operator override)."""
    for i, tok in enumerate(args):
        if tok == "--engines" and i + 1 < len(args):
            return [e.strip() for e in args[i + 1].split(",") if e.strip()]
        if tok.startswith("--engines="):
            return [e.strip() for e in tok.split("=", 1)[1].split(",") if e.strip()]
    return None


def _parse_engine_mode(args: list[str]) -> str:
    for i, tok in enumerate(args):
        if tok == "--engine-mode" and i + 1 < len(args):
            return args[i + 1].strip().lower() or "best"
        if tok.startswith("--engine-mode="):
            return tok.split("=", 1)[1].strip().lower() or "best"
    return "best"


class ConsoleApp:
    def __init__(self, console: Console | None = None):
        self.console = console or Console()
        self.workspace: Workspace | None = None
        self.ai_manager = AIManager()
        self.banner_rendered: bool = False
        self.banner_count: int = 0

    def startup(self, duration: float = 1.0) -> None:
        """Render the application startup banner exactly once per console session."""
        if not self.banner_rendered:
            banner(self.console, duration=duration)
            self.banner_rendered = True
            self.banner_count += 1
            self.console.print("[dim cyan]⚡ Welcome to HORCRUX.[/dim cyan] [dim white]Type [bold magenta]'help'[/bold magenta] for command reference.[/dim white]\n")

    def print_help(self):
        grid = Table.grid(padding=(0, 2))
        grid.add_column(style="bold bright_cyan", justify="left")
        grid.add_column(style="dim white", justify="left")

        categories = [
            (
                "ASSESSMENT",
                [
                    ("scan <target> [--profile <name>] [--deep] [--verify]", "Full automated attack surface discovery"),
                    ("assess [--iterations N] [--workers W]", "Run continuous agentic assessment loop"),
                    ("status", "Workspace, coverage, queue, and AI health overview"),
                ]
            ),
            (
                "INVESTIGATION",
                [
                    ("next / actions", "Highest-value next actions from live state"),
                    ("findings", "Security findings with validation states"),
                    ("inspect <id>", "Evidence, reproduction, and impact for one finding"),
                    ("why [<id>]", "Structured rationale for the current decision"),
                    ("ask <question>", "State-grounded analysis (coverage, gaps, paths)"),
                    ("graph", "Attack surface and attack path visualization"),
                ]
            ),
            (
                "OPERATOR CONTROL",
                [
                    ("focus <area>", "Steer the loop: web, api, auth, authz, business-logic, network, all"),
                    ("pause / resume", "Halt or continue scheduling new work"),
                    ("skip <id>", "Park an investigation without deleting it"),
                    ("prioritize <id>", "Move an investigation to the front of the queue"),
                ]
            ),
            (
                "RECONNAISSANCE & CORRELATION",
                [
                    ("surface", "Network attack surface (open ports & protocols)"),
                    ("services", "Service inventory with protocols and versions"),
                    ("software", "Software & framework detection breakdown"),
                    ("web", "Web attack surface and technology fingerprinting"),
                    ("subsystems / states", "Reconnaissance & enumeration subsystem states"),
                    ("creds", "Recovered credentials with masked secrets"),
                    ("audit", "Audited and verified hardened security controls"),
                    ("cve / searchsploit", "Correlate software with known exploit candidates"),
                    ("exploit", "Review actionable exploit candidates & AI decisions"),
                    ("intel", "Execute exploit correlation & AI triage pipeline"),
                    ("nuclei", "Execute targeted Nuclei templates against web targets"),
                    ("local", "Linux local privilege escalation checks"),
                ]
            ),
            (
                "CONFIGURATION & ARTIFACTS",
                [
                    ("replay [--script PATH]", "Replay assessment deterministically from evidence script"),
                    ("benchmark [fixture|all]", "Run the synthetic benchmark suite (offline)"),
                    ("ai [status|enable|disable|usage|clear-cache]", "Manage AI engine, model, and cache"),
                    ("settings", "Interactive settings & provider configuration"),
                    ("settings vulnerability ...", "External vulnerability engines (test, endpoint, keys)"),
                    ("engines [status|test|info]", "Vulnerability engine readiness & health"),
                    ("import <file> [--provider X]", "Import scanner results as IMPORTED_RESULT"),
                    ("doctor / tools", "Audit installed tools, wordlists, AI, and engines"),
                    ("source <artifact> / raw <module>", "Inspect raw tool output or response body"),
                    ("report", "Generate structured Markdown engagement report"),
                    ("artifacts / gallery", "View the Horcrux ASCII art gallery"),
                    ("clear", "Clear terminal screen"),
                    ("exit / quit", "Leave the Horcrux console"),
                ]
            )
        ]

        table = Table(
            title="[bold bright_magenta]HORCRUX OPERATOR COMMANDS[/bold bright_magenta]",
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
        self.startup(duration=0.6)

        while True:
            target_str = self.workspace.target if self.workspace else "ready"
            prompt_text = (
                "[bold bright_magenta]HORCRUX[/bold bright_magenta]"
                "[dim] › [/dim]"
                f"[bold cyan]{target_str}[/bold cyan] "
                "[dim]›[/dim] "
            )

            try:
                line = Prompt.ask(prompt_text).strip()
            except (EOFError, KeyboardInterrupt):
                self.console.print()
                return

            if not line:
                continue

            if line.lower() in {"exit", "quit"}:
                self.console.print("\n[dim]Assessment state saved. HORCRUX standing by.[/dim]\n")
                return

            try:
                self.dispatch(shlex.split(line))
            except Exception as exc:
                from horcrux.ui import theme as _theme
                self.console.print()
                self.console.print(_theme.error_card(
                    "Command failed",
                    why=str(exc) or exc.__class__.__name__,
                    action="No workspace state was changed.",
                    nxt="Type 'help' for command reference.",
                ))
                self.console.print()

    def dispatch(self, args: list[str]):
        GLOBAL_COMMANDS = {
            "help",
            "clear",
            "exit",
            "quit",
            "version",
            "doctor",
            "tools",
            "artifacts",
            "gallery",
            "art",
            "settings",
            "ai",
            "scan",
            "ask",
            "engines",
            "import",
            "headless",
        }

        # Clean leading colons or slashes and filter empty arguments
        cleaned_args = []
        for arg in args:
            if arg in {":", "/"}:
                continue
            if arg.startswith(":") or arg.startswith("/"):
                arg = arg.lstrip(":").lstrip("/")
            if arg:
                cleaned_args.append(arg)

        if not cleaned_args:
            return

        args = cleaned_args
        command = args[0].lower()

        if command == "help":
            self.print_help()
            return

        if command == "clear":
            self.console.clear()
            return

        if command == "version":
            self.console.print(f"[bold bright_magenta]HORCRUX[/bold bright_magenta] version [bold bright_cyan]{__version__}[/bold bright_cyan]\n")
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

        if command == "ask":
            self.ask_cmd(args)
            return

        if command == "engines":
            self.engines_cmd(args)
            return

        if command == "import":
            self.import_cmd(args)
            return

        if command == "assess":
            if self.workspace is None:
                raise ValueError("no workspace loaded; run 'scan <target>' first")
            self.assess_cmd(args)
            return

        if command == "replay":
            if self.workspace is None:
                raise ValueError("no workspace loaded; run 'scan <target>' first")
            self.replay_cmd(args)
            return

        if command == "benchmark":
            self.benchmark_cmd(args)
            return

        if command in {"focus", "pause", "resume", "skip", "prioritize", "why"}:
            # Operator steering is global; workspace required for focus state.
            if self.workspace is None:
                raise ValueError("no workspace loaded; run 'scan <target>' first")
            self.steering_cmd(args)
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
            self.console.print(f"\n[bold bright_magenta]⚡ SCANNING:[/bold bright_magenta] [bold bright_cyan]{target}[/bold bright_cyan]  [dim]profile={profile_name}[/dim]\n")

            Orchestrator(
                target,
                self.workspace,
                self.console,
                profile=profile_name,
                engines=_parse_engines_flag(args),
                skip_engines=("--skip-engines" in args[2:]),
                engine_mode=_parse_engine_mode(args),
            ).scan(
                deep=deep,
                verify=verify,
            )

            fanfare(self.console, f"TARGET SYNTHESIS COMPLETE: {target}")
            self.status()
            return


        # Commands below this guard strictly require an active target workspace
        self.require_workspace()

        if command == "local":
            loading(self.console, "Running Linux local enumeration", 0.5)
            enumerate_linux(self.workspace, CommandRunner(self.workspace))
            self.console.print(
                f"[bold green]✔ Saved:[/bold green] [cyan]{self.workspace.root}[/cyan]"
            )
            return

        if command == "status":
            self.status()

        elif command == "surface":
            self.surface()

        elif command in {"services", "service"}:
            self.services()

        elif command == "software":
            self.software()

        elif command == "audit":
            self.audit()

        elif command in {"findings", "finding"}:
            self.findings()

        elif command == "inspect":
            self.inspect_finding(args)

        elif command in {"next", "actions", "action"}:
            self.next_actions()

        elif command in {"creds", "credentials"}:
            self.credentials()

        elif command == "graph":
            self.graph()

        elif command == "web":
            self.web()

        elif command in {"subsystems", "states"}:
            self.subsystems()

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

        elif command in {"exploit", "exploits"}:
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

        elif command in {"focus", "pause", "resume", "skip", "prioritize", "why"}:
            self.steering_cmd(args)

        elif command == "assess":
            self.assess_cmd(args)

        elif command == "replay":
            self.replay_cmd(args)

        elif command == "benchmark":
            self.benchmark_cmd(args)

        elif command == "raw":
            self.raw_cmd(args)

        elif command == "headless":
            self.headless_cmd(args)

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
            _ALL_COMMANDS = [
                "scan", "assess", "headless", "replay", "benchmark", "status", "surface", "services", "software", "web", "audit",
                "findings", "inspect", "next", "actions", "creds", "credentials",
                "graph", "subsystems", "states", "cve", "searchsploit", "intel",
                "nuclei", "exploit", "exploits", "source", "raw", "report",
                "local", "ask", "ai", "settings", "doctor", "tools", "help",
                "artifacts", "gallery", "art", "version", "clear",
                "focus", "pause", "resume", "skip", "prioritize", "why",
                "engines", "import",
            ]
            close = difflib.get_close_matches(command, _ALL_COMMANDS, n=1, cutoff=0.6)
            hint = f" — did you mean '[bold bright_cyan]{close[0]}[/bold bright_cyan]'?" if close else " — type 'help' for command reference"
            raise ValueError(f"unknown command: '{command}'{hint}")


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

        # --- Agentic assessment state (Part 36 operator console) ---
        try:
            self._print_assessment_status(state)
        except Exception:
            pass
        self.console.print()

    def _print_assessment_status(self, state) -> None:
        """Serious operator console: state without raw tool-output flooding."""
        from horcrux.intel.ai.capabilities import summarize_ai_usage
        from horcrux.ui import theme as _theme
        focus = state.operator_focus
        focus_label = getattr(focus, "focus_id", "") or getattr(focus, "focus_area", "all") or "all"
        phase = "PAUSED" if focus.paused else ("STOPPED" if focus.stopped else state.assessment_phase)
        try:
            scope_targets = state.get_policy().scope.allowed_targets or [state.target]
        except Exception:
            scope_targets = [state.target]
        app = state.get_application_model()
        summ = app.summary()
        cov = state.get_security_coverage()
        cov.ensure_domains()
        pct = cov.percentage_complete()
        cov_text = "  ".join(f"{k} {v:.0f}%" for k, v in pct.items())
        invs = state.get_investigations()
        open_inv = [i for i in invs if i.state.value in {"READY", "PENDING"}]
        blocked = [i for i in invs if i.state.value in {
            "BLOCKED", "SCOPE_BLOCKED", "UNAVAILABLE", "FAILED", "APPROVAL_REQUIRED"}]
        hyps = state.get_hypotheses()
        open_hyps = [h for h in hyps if h.status.value in {"OPEN", "INVESTIGATING"}]

        api_eps = [e for e in app.endpoints
                   if e.path.startswith(("/api", "/rest", "/v1", "/graphql"))]
        self.console.print(
            _theme.kv_panel(
                "[bold bright_cyan]APPLICATION MODEL[/bold bright_cyan]",
                [
                    ("Routes", f"[bold bright_white]{summ['routes']}[/bold bright_white]"),
                    ("APIs", f"[bold bright_white]{len(api_eps)}[/bold bright_white]"),
                    ("Identities", f"[bold bright_white]{len(app.identities)}[/bold bright_white]"),
                    ("Objects", f"[bold bright_white]{len(app.object_types)}[/bold bright_white]"),
                    ("Workflows", f"[bold bright_white]{len(app.workflows)}[/bold bright_white]"),
                    ("Services", f"[bold bright_white]{len(app.services)}[/bold bright_white]"),
                ],
            )
        )

        self.console.print(
            Panel(
                f"[bold cyan]TARGET:[/bold cyan] {state.target}   "
                f"[bold cyan]SCOPE:[/bold cyan] {', '.join(scope_targets[:3])}   "
                f"[bold cyan]PHASE:[/bold cyan] {phase}\n"
                f"[bold cyan]APPLICATION:[/bold cyan] {summ['application']['type']} "
                f"({summ['application']['framework'] or 'unknown framework'}) — "
                f"{summ['endpoints']} endpoints, {summ['object_bearing_endpoints']} object-bearing, "
                f"{summ['admin_endpoints']} privileged\n"
                f"[bold cyan]IDENTITIES:[/bold cyan] "
                f"{', '.join(f'{i.label}({i.role.value})' for i in app.identities[:6]) or 'none'}   "
                f"[bold cyan]SESSIONS:[/bold cyan] {len(app.sessions)}\n"
                f"[bold cyan]OBJECTS:[/bold cyan] {', '.join(summ['object_types'][:6]) or 'none'}   "
                f"[bold cyan]WORKFLOWS:[/bold cyan] {', '.join(summ['workflows'][:4]) or 'none'}\n"
                f"[bold cyan]COVERAGE:[/bold cyan] {cov_text}\n"
                f"[bold cyan]HYPOTHESES:[/bold cyan] {len(open_hyps)} open / {len(hyps)} total   "
                f"[bold cyan]QUEUE:[/bold cyan] {len(open_inv)} pending / {len(invs)} total   "
                f"[bold cyan]BLOCKED:[/bold cyan] {len(blocked)}\n"
                f"[bold cyan]FOCUS:[/bold cyan] {focus_label}   "
                f"[bold cyan]PAUSE:[/bold cyan] {'yes' if focus.paused else 'no'}   "
                f"[bold cyan]FINDINGS:[/bold cyan] {len(state.findings)}   "
                f"[bold cyan]ATTACK PATHS:[/bold cyan] {len(state.attack_paths or [])}   "
                f"[bold cyan]HANDOFFS:[/bold cyan] {len(state.exploit_handoffs or [])}",
                title="[bold bright_magenta]AGENTIC ASSESSMENT[/bold bright_magenta]",
                box=box.ROUNDED,
                border_style="magenta",
                padding=(0, 2),
            )
        )

        # Current investigation + queue peek.
        if open_inv:
            top = max(open_inv, key=lambda i: i.priority)
            table = Table(box=box.ROUNDED, border_style="yellow", expand=True,
                          title="[bold bright_yellow]CURRENT INVESTIGATION & QUEUE[/bold bright_yellow]")
            table.add_column("Objective", style="bright_white")
            table.add_column("Specialist", style="cyan")
            table.add_column("State", justify="center")
            table.add_column("Priority", justify="right")
            table.add_row(f"▶ {top.objective[:70]}", top.specialist, top.state.value,
                          f"{top.priority:.2f}")
            for inv in sorted(open_inv, key=lambda i: -i.priority)[1:4]:
                if inv.id != top.id:
                    table.add_row(f"  {inv.objective[:70]}", inv.specialist,
                                  inv.state.value, f"{inv.priority:.2f}")
            self.console.print(table)
        if blocked:
            self.console.print(
                f"[dim yellow]Blocked work ({len(blocked)}):[/dim yellow] " +
                "; ".join(f"{b.objective[:45]} [{b.state.value}]" for b in blocked[:3]))

        # Agents + capabilities.
        agents = [a for a in (state.agent_states or []) if a.status in {"RUNNING", "READY"}][:6]
        if agents:
            self.console.print(
                "[bold cyan]AGENTS:[/bold cyan] " +
                ", ".join(f"{a.name}({a.status})" for a in agents))
        try:
            from horcrux.agents.tools.capabilities import environment_availability_report
            rep = environment_availability_report()
            live = sorted(k for k, v in rep.items() if v.get("mode") == "live")
            avail = sum(1 for v in rep.values() if v.get("available"))
            missing = sorted(k for k, v in rep.items() if v.get("status") in {"MISSING"})
            unavailable = sorted(k for k, v in rep.items()
                                 if v.get("status") not in {"AVAILABLE", "MISSING"})
            cap_line = (f"[bold cyan]CAPABILITIES:[/bold cyan] {len(live)} live / "
                        f"{avail} available")
            if missing:
                cap_line += f" — missing: {', '.join(missing[:5])}"
            if unavailable:
                cap_line += f" — degraded: {', '.join(unavailable[:5])}"
            try:
                from horcrux.intel.browser import browser_backend_status
                bw = browser_backend_status()
                cap_line += " — browser: " + ", ".join(
                    f"{k}={'✔' if v['available'] else '✖'}" for k, v in bw.items())
            except Exception:
                pass
            self.console.print(cap_line)
        except Exception:
            pass

        # AI provider / health / usage.
        try:
            prov = self.ai_manager.active_provider_name()
            usage = summarize_ai_usage(self.workspace, self.ai_manager)
            ai_line = (f"[bold cyan]AI:[/bold cyan] provider={prov} "
                       f"calls={usage.get('calls', 0)} "
                       f"tokens={usage.get('total_tokens', 0)}")
            if usage.get("tiers"):
                ai_line += " tiers=" + ",".join(f"{k}:{v}" for k, v in usage["tiers"].items())
            self.console.print(ai_line)
        except Exception:
            pass

        # Recent state changes (redacted event tail).
        try:
            from horcrux.intel.events import read_events
            recent = read_events(self.workspace, limit=5)
            if recent:
                self.console.print(
                    "[bold cyan]RECENT:[/bold cyan] " +
                    " · ".join(f"{r.get('event')}" for r in recent))
        except Exception:
            pass
        self.console.print(
            "[dim]Steer via focus/pause/skip/prioritize; details via 'why', 'ask', 'next'.[/dim]")

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
        actions = compute_next_actions(state)
        self.workspace.set_actions(actions)
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

        # Attack paths branch (evidence-backed chains, not flat findings)
        attack_paths = state.attack_paths or []
        if attack_paths:
            paths_branch = root_tree.add(
                f"[bold bright_magenta]ATTACK PATHS ({len(attack_paths)})[/bold bright_magenta]",
                guide_style="magenta",
            )
            for path in attack_paths[:5]:
                name = path.get("name", "path")
                prob = path.get("probability", "")
                status = str(path.get("status", "") or "HYPOTHESIS")
                finding_ids = path.get("finding_ids", []) or []
                badge = path_status_badge(status)
                header = f"[bright_white]{name}[/bright_white] [dim]({prob})[/dim] {badge}"
                if finding_ids:
                    header += f" [dim]finding:{finding_ids[0][:12]}[/dim]"
                node = paths_branch.add(header)
                for edge in path.get("edges", [])[:4]:
                    node.add(_edge_display_line(edge))

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
            "Discovered Endpoints",
            str(len(state.discovered_paths)) if state.discovered_paths else "[dim]none discovered (run scan --profile web)[/dim]",
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

        if state.discovered_paths:
            path_table = Table(
                title="[bold bright_cyan]✦ DISCOVERED WEB PATHS & VALIDATION ✦[/bold bright_cyan]",
                box=box.ROUNDED,
                border_style="cyan",
                header_style="bold bright_white",
                expand=True,
            )
            path_table.add_column("Path", style="bold bright_white")
            path_table.add_column("Status", justify="center")
            path_table.add_column("Size", justify="right", style="dim white")
            path_table.add_column("Tool", style="dim cyan")
            path_table.add_column("Validation State", justify="center")

            for dp in state.discovered_paths[:40]:
                st_color = "bright_green" if dp.status < 300 else "bright_yellow" if dp.status < 400 else "red"
                val_badge = (
                    "[bold green]✔ CONFIRMED[/]" if dp.validation_state == ValidationState.confirmed
                    else "[bold yellow]⚠ LIKELY[/]" if dp.validation_state == ValidationState.likely
                    else "[dim red]✖ SOFT-404[/]" if dp.validation_state == ValidationState.false_positive
                    else "[dim]UNVERIFIED[/]"
                )
                path_table.add_row(
                    dp.path,
                    f"[{st_color}]{dp.status}[/{st_color}]",
                    f"{dp.size}B",
                    dp.source,
                    val_badge,
                )
            self.console.print(path_table)

        self.console.print(
            "[dim cyan]💡 Tip: Use [bold magenta]'source <artifact>'[/bold magenta] to inspect raw HTTP response bodies and headers.[/dim cyan]\n"
        )

    def subsystems(self):
        state = self.workspace.load()
        table = Table(
            title=f"[bold bright_magenta]✦ SUBSYSTEM RECONNAISSANCE STATES — {state.target} ✦[/bold bright_magenta]",
            box=box.ROUNDED,
            border_style="magenta",
            header_style="bold bright_cyan",
            expand=True,
        )
        table.add_column("Subsystem", style="bold bright_white")
        table.add_column("State", justify="center")
        table.add_column("Notes", style="dim white")

        subsystem_descriptions = {
            "web_discovery": "HTTP endpoint fuzzing and path discovery (FFUF/Gobuster)",
            "web_validation": "Baseline & soft-404 verification of discovered web endpoints",
            "cve_intelligence": "SearchSploit and CVE vulnerability correlation",
            "smb_enum": "SMB null session, share listing, and signing requirement audit",
            "ldap_enum": "Active Directory LDAP RootDSE and user enumeration",
            "kerberos_enum": "Kerberos KDC presence and authentication surface",
            "ssh_enum": "SSH banner grab, OpenSSH version detection, and cipher audit",
            "ftp_enum": "FTP welcome banner and anonymous access audit",
            "smtp_enum": "SMTP banner grab, EHLO capabilities, and open relay test",
            "dns_enum": "DNS record discovery and AXFR zone transfer test",
            "snmp_enum": "SNMP public community string and MIB inspection",
            "database_enum": "Database (Redis/MySQL/Postgres) authentication audit",
        }

        for sub, desc in subsystem_descriptions.items():
            curr = state.get_subsystem_state(sub)
            badge = (
                "[bold green]✔ COMPLETE[/]" if curr == SubsystemState.COMPLETE
                else "[bold green]✔ COMPLETE (CANDIDATES)[/]" if curr == SubsystemState.COMPLETE_WITH_CANDIDATES
                else "[dim yellow]○ COMPLETE (0 MATCHES)[/]" if curr == SubsystemState.COMPLETE_NO_CANDIDATES
                else "[bold yellow]▶ RUNNING[/]" if curr == SubsystemState.RUNNING
                else "[dim red]✖ FAILED[/]" if curr == SubsystemState.FAILED
                else "[dim]NOT RUN[/]"
            )
            table.add_row(sub, badge, desc)

        self.console.print()
        self.console.print(table)
        self.console.print()


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

        from horcrux.ui import theme as _theme
        if result is None:
            self.console.print()
            self.console.print(_theme.error_card(
                "Capability unavailable",
                why="Nuclei was not found on PATH.",
                action="Investigation skipped and deprioritized.",
                nxt="Assessment continues. Install Nuclei to enable template scans.",
            ))
            self.console.print()
        else:
            state = self.workspace.load()
            nuclei_hits = [f for f in state.findings if f.source_tool == "nuclei"]
            self.console.print()
            self.console.print(_theme.tool_card(
                "Nuclei",
                f"[bold green]{_theme.OK} Completed[/bold green] (code {result.returncode})",
                result=f"{len(nuclei_hits)} finding(s) recorded",
                evidence=f"target {url}",
            ))
            self.console.print()

    def ask_cmd(self, args: list[str]):
        if len(args) < 2:
            raise ValueError("usage: ask <question in quotes>")
        question = " ".join(args[1:]).strip()
        state = self.workspace.load() if self.workspace else None

        active_provider = self.ai_manager.active_provider_name()
        provider_obj = self.ai_manager.get_provider()
        active_model = provider_obj.get_active_model() if provider_obj else ""

        with AIProgressManager(
            self.console,
            task_name="HORCRUX AI Reasoning",
            provider=active_provider,
            model=active_model,
        ) as ai_prog:
            ai_prog.set_phase("Preparing context & scope")
            time.sleep(0.04)
            ai_prog.set_phase(f"Consulting {active_provider.upper()}")
            answer = self.ai_manager.ask(question, state)
            ai_prog.set_phase("Normalizing response")
            time.sleep(0.02)

        # Persist any orchestrator-validated state mutations from ask actions.
        if self.workspace is not None and state is not None:
            try:
                self.workspace.save(state)
            except Exception:
                pass

        # Build a clean question preview for the subtitle — truncate at word boundary
        preview = question
        if len(preview) > 60:
            preview = preview[:57].rsplit(" ", 1)[0] + "…"

        # Detect if the response contains Rich markup (dim, bold) vs plain Markdown
        # Rich markup errors are returned as plain dim strings — render them directly.
        # Proper Markdown responses are rendered with rich.markdown.Markdown.
        is_rich_markup = answer.strip().startswith("[") and ("[dim" in answer or "[bold" in answer)

        self.console.print()
        self.console.print(
            Panel(
                answer if is_rich_markup else Markdown(answer),
                title="[bold bright_magenta]HORCRUX ANALYSIS[/bold bright_magenta]",
                subtitle=f"[dim]grounded in workspace state • {preview}[/dim]",
                box=box.ROUNDED,
                border_style="bright_magenta",
                padding=(1, 2),
            )
        )
        self.console.print()


    def steering_cmd(self, args: list[str]):
        """Operator focus controls: focus / pause / resume / skip / prioritize / why."""
        from horcrux.agents.focus import apply_focus, pause, prioritize, resume, skip
        from horcrux.intel.explain import build_why_summary
        cmd = args[0].lower()
        state = self.workspace.load()
        if cmd == "focus":
            area = " ".join(args[1:]).strip() or "all"
            res = apply_focus(state, area)
            self.workspace.save(state)
            self.console.print(f"\n[bold cyan]Focus:[/bold cyan] {res['detail']}\n")
            return
        if cmd == "pause":
            res = pause(state)
            self.workspace.save(state)
            self.console.print(f"\n[bold yellow]{res['detail']}[/bold yellow]\n")
            return
        if cmd == "resume":
            res = resume(state)
            self.workspace.save(state)
            self.console.print(f"\n[bold green]{res['detail']}[/bold green]\n")
            return
        if cmd == "skip":
            if len(args) < 2:
                raise ValueError("usage: skip <investigation-id-or-keyword>")
            res = skip(state, " ".join(args[1:]))
            self.workspace.save(state)
            self.console.print(f"\n[bold yellow]Skip:[/bold yellow] {res['detail']}\n")
            return
        if cmd == "prioritize":
            if len(args) < 2:
                raise ValueError("usage: prioritize <investigation-id-or-keyword>")
            res = prioritize(state, " ".join(args[1:]))
            self.workspace.save(state)
            self.console.print(f"\n[bold green]Prioritized:[/bold green] {res['detail']}\n")
            return
        if cmd == "why":
            from horcrux.intel.explain import (build_why_summary, explain_finding_confidence,
                                               explain_investigation, explain_not_investigated)
            self.console.print()
            target = " ".join(args[1:]).strip()
            if not target:
                body = build_why_summary(state)
            elif target.lower().startswith("finding "):
                body = explain_finding_confidence(state, target[8:].strip())
            elif target.lower().startswith("not "):
                body = explain_not_investigated(state, target[4:].strip())
            else:
                body = explain_investigation(state, target)
                if body.startswith("No investigation"):
                    body += "\n\n" + explain_not_investigated(state, target)
            self.console.print(Panel(Markdown(body),
                                     title="[bold bright_magenta]WHY[/bold bright_magenta]",
                                     subtitle="[dim]structured rationale • no chain-of-thought[/dim]",
                                     box=box.ROUNDED, border_style="bright_magenta",
                                     padding=(1, 2)))
            self.console.print()
            return

    def assess_cmd(self, args: list[str]):
        """Run the continuous agentic assessment loop (live phase tracker)."""
        from horcrux.agents.coordinator import run_full_assessment
        from horcrux.ui.progress import AssessmentProgress
        iterations = 15
        workers = 1
        for i, a in enumerate(args):
            if a in ("--iterations", "-n") and i + 1 < len(args):
                try:
                    iterations = int(args[i + 1])
                except ValueError:
                    pass
            if a in ("--workers", "-w") and i + 1 < len(args):
                try:
                    workers = max(1, int(args[i + 1]))
                except ValueError:
                    pass
        self.console.print(f"\n[bold bright_magenta]⚡ ASSESSMENT:[/bold bright_magenta] "
                           f"[bold bright_cyan]{self.workspace.target}[/bold bright_cyan] "
                           f"[dim]iterations={iterations} workers={workers}[/dim]\n")
        tracker = AssessmentProgress(self.console, self.workspace.target)
        with tracker:
            run_full_assessment(self.workspace, ai_manager=self.ai_manager,
                                max_iterations=iterations, max_workers=workers,
                                observer=tracker.observer())
        self.console.print(tracker.render_text())
        self.console.print()
        self.status()

    def headless_cmd(self, args: list[str]):
        """Manage autonomous headless missions from interactive console."""
        if len(args) < 2 or args[1].lower() == "help":
            self.console.print("[bold bright_magenta]HEADLESS OPERATOR COMMANDS:[/bold bright_magenta]")
            self.console.print("  headless scan <target> [--profile P] [--config C]")
            self.console.print("  headless status")
            self.console.print("  headless pause")
            self.console.print("  headless resume")
            self.console.print("  headless abort")
            self.console.print("  headless export")
            return

        sub = args[1].lower()
        from horcrux.core.headless.controller import HeadlessMissionController
        from horcrux.core.headless.config import build_mission_from_config

        target = self.workspace.target if self.workspace else ""
        if len(args) >= 3 and not args[2].startswith("-"):
            target = args[2]

        if sub == "scan":
            if not target or target == "ready":
                raise ValueError("usage: headless scan <target> [--profile standard|deep|full]")
            mission = build_mission_from_config(target=target)
            ws = Workspace(target)
            ctrl = HeadlessMissionController(ws, mission, console=self.console)
            ctrl.run()
            self.workspace = ws
        elif sub == "status":
            if not self.workspace:
                raise ValueError("No workspace loaded.")
            state = self.workspace.load()
            m = state.get_mission()
            if not m:
                self.console.print(f"[bold red]No headless mission found in workspace '{self.workspace.target}'.[/bold red]")
                return
            ctrl = HeadlessMissionController(self.workspace, m, console=self.console)
            summary = ctrl.status_summary()
            self.console.print(f"[bold cyan]Mission {summary['mission_id']}:[/bold cyan] stage={summary['stage']} status={summary['status']} verdict={summary['completion_verdict']} findings={summary['findings_count']}")
        elif sub == "pause":
            if not self.workspace:
                raise ValueError("No workspace loaded.")
            state = self.workspace.load()
            m = state.get_mission()
            if m:
                ctrl = HeadlessMissionController(self.workspace, m, console=self.console)
                ctrl.pause()
                self.console.print(f"[bold yellow]✔ Headless mission {m.mission_id} paused.[/bold yellow]")
        elif sub == "resume":
            if not self.workspace:
                raise ValueError("No workspace loaded.")
            state = self.workspace.load()
            m = state.get_mission()
            if m:
                ctrl = HeadlessMissionController(self.workspace, m, console=self.console)
                ctrl.resume()
        elif sub == "abort":
            if not self.workspace:
                raise ValueError("No workspace loaded.")
            state = self.workspace.load()
            m = state.get_mission()
            if m:
                ctrl = HeadlessMissionController(self.workspace, m, console=self.console)
                ctrl.abort()
                self.console.print(f"[bold red]✔ Headless mission {m.mission_id} aborted.[/bold red]")
        elif sub == "export":
            if not self.workspace:
                raise ValueError("No workspace loaded.")
            state = self.workspace.load()
            m = state.get_mission()
            if m:
                ctrl = HeadlessMissionController(self.workspace, m, console=self.console)
                from horcrux.reporting.reports import markdown
                rpath = markdown(self.workspace)
                self.console.print(f"[bold green]✔ Report exported:[/bold green] {rpath}")

    def replay_cmd(self, args: list[str]):
        """Replay assessment deterministically from a recorded evidence script."""
        from pathlib import Path as _Path
        from horcrux.bench.runner import replay_workspace, write_evidence_script
        script = ""
        for i, a in enumerate(args):
            if a in ("--script", "-s") and i + 1 < len(args):
                script = args[i + 1]
        script_path = _Path(script) if script else (self.workspace.root / "evidence-script.json")
        if not script_path.exists():
            script_path = write_evidence_script(self.workspace)
            self.console.print(f"[dim]Recorded evidence script: {script_path}[/dim]")
        state = replay_workspace(self.workspace.target, script_path)
        app = state.get_application_model()
        self.console.print(f"\n[bold green]✔ Replay complete:[/bold green] "
                           f"{len(app.endpoints)} endpoints, "
                           f"{len(state.get_hypotheses())} hypotheses, "
                           f"{len(state.get_investigations())} investigations, "
                           f"{len(state.attack_paths or [])} attack paths.\n")

    def benchmark_cmd(self, args: list[str]):
        """Run the synthetic benchmark suite (offline)."""
        import tempfile
        from pathlib import Path as _Path
        from horcrux.bench.fixtures import FIXTURES
        from horcrux.bench.runner import run_suite
        names = [a for a in args[1:] if not a.startswith("-")]
        selected = sorted(FIXTURES) if not names or names == ["all"] else names
        unknown = [n for n in selected if n not in FIXTURES]
        if unknown:
            raise ValueError(f"unknown fixture(s): {', '.join(unknown)} "
                             f"(choose from: {', '.join(sorted(FIXTURES))})")
        with tempfile.TemporaryDirectory() as tmp:
            report = run_suite(selected, _Path(tmp))
        self.console.print(f"\n[bold]Benchmark:[/bold] {report['passed']}/{report['fixtures']} "
                           f">= 0.60 (mean {report['mean_score']})\n")
        for res in report["results"]:
            mark = "[green]✔[/green]" if res["score"] >= 0.6 else "[red]✖[/red]"
            self.console.print(f"  {mark} {res['fixture']:<22} score={res['score']}\n")

    def settings_cmd(self, args: list[str]):
        from horcrux.core.integrations.controller import SettingsController
        mgr = SettingsManager()
        ctrl = SettingsController(console=self.console, settings_manager=mgr)

        if len(args) == 1:
            ctrl.render_overview()
            return

        sub = args[1].lower()

        if sub in {"status", "diagnostics"}:
            ctrl.render_status()
            return

        if sub in {"vulnerability", "vuln", "vulns", "engines"}:
            self.vuln_settings_cmd(["vulnerability"] + args[2:])
            return

        if sub in {"ai", "tools", "automation", "security", "security_tools", "browser", "playwright", "nmap", "nuclei", "ffuf", "whatweb"}:
            ctrl.handle_command(args[1:])
            return

        if sub == "provider":
            if len(args) < 3:
                raise ValueError("usage: settings provider <groq|openai|anthropic|google> [api_key]")
            p_name = normalize_provider_name(args[2])
            if p_name not in ("groq", "openai", "anthropic", "google"):
                raise ValueError(f"unknown provider '{args[2]}' — choose groq, openai, anthropic, or google")

            existing_cred = mgr.get_credential_info(p_name)
            if existing_cred.is_configured and len(args) < 4:
                replace = Prompt.ask(
                    f"[yellow]A key is already configured for {p_name.upper()} ({existing_cred.masked}). Replace it?[/yellow]",
                    choices=["y", "n"],
                    default="n",
                )
                if replace.lower() != "y":
                    self.console.print(f"[dim]Existing key for '{p_name}' retained.[/dim]")
                    return

            if len(args) >= 4:
                key_val = args[3].strip()
            else:
                key_val = Prompt.ask(f"[bold bright_cyan]Enter API key for {p_name.upper()}[/bold bright_cyan]", password=True).strip()

            if not key_val:
                self.console.print("[yellow]No key provided. Configuration unchanged.[/yellow]")
                return

            mgr.set_api_key(p_name, key_val)
            self.ai_manager = AIManager(mgr)
            self.console.print(f"[bold green]✔ API key stored securely for provider '{p_name}'.[/bold green]")

            try:
                choose_model = Prompt.ask(
                    f"[dim cyan]Would you like to select a specific model for {p_name.upper()}?[/dim cyan]",
                    choices=["y", "n"],
                    default="n",
                )
                if choose_model.lower() == "y":
                    self.settings_cmd(["settings", "model", p_name])
            except Exception:
                pass

        elif sub in {"model", "models"}:
            if len(args) >= 3 and normalize_provider_name(args[2]) in {"groq", "openai", "anthropic", "google"}:
                p_name = normalize_provider_name(args[2])
            else:
                p_name = normalize_provider_name(Prompt.ask(
                    "[bold bright_cyan]Select AI Provider[/bold bright_cyan]",
                    choices=["groq", "openai", "anthropic", "google"],
                    default=mgr.settings.default_provider,
                ))

            # Direct CLI set: `settings model <provider> <model_name>`
            if len(args) >= 4 and sub == "model":
                m_name = " ".join(args[3:]).strip()
                mgr.set_model(p_name, m_name)
                self.ai_manager = AIManager(mgr)
                self.console.print(f"[bold green]✔ Active model for '{p_name}' set to '{m_name}'.[/bold green]")
                return

            # Interactive model selector with dynamic discovery
            cur_model = mgr.get_model(p_name)
            loading(self.console, f"Discovering available models for {p_name.upper()}...", 0.4)
            available = self.ai_manager.get_available_models(p_name)
            avail_ids = [m.id for m in available]
            if not avail_ids:
                avail_ids = AVAILABLE_MODELS.get(p_name, [cur_model])

            if cur_model and cur_model not in avail_ids:
                avail_ids = [cur_model] + avail_ids

            table = Table(
                title=f"[bold bright_magenta]✦ {p_name.upper()} AVAILABLE GENERATION MODELS ✦[/bold bright_magenta]",
                box=box.ROUNDED,
                border_style="magenta",
                header_style="bold bright_cyan",
            )
            table.add_column("#", justify="center", style="bold yellow", no_wrap=True)
            table.add_column("Model Identifier", style="bold bright_white")
            table.add_column("Context Window", justify="right", style="cyan")
            table.add_column("Status", justify="center", no_wrap=True)

            model_map = {m.id: m for m in available}
            for idx, m_id in enumerate(avail_ids, 1):
                st_badge = "[bold green]★ CURRENT[/bold green]" if m_id == cur_model else "[dim cyan]available[/dim cyan]"
                m_info = model_map.get(m_id)
                ctx_str = f"{m_info.context_window:,}" if (m_info and m_info.context_window) else "standard"
                table.add_row(str(idx), m_id, ctx_str, st_badge)

            self.console.print()
            self.console.print(table)

            if sub == "models":
                return

            self.console.print(
                "[dim cyan]💡 Tip: Choose a number [1-N], enter a custom model name, or press Enter to keep current.[/dim cyan]\n"
            )
            choice = Prompt.ask(
                f"[bold bright_yellow]Select model for {p_name.upper()} [1-{len(avail_ids)} or custom][/bold bright_yellow]",
                default=cur_model,
            ).strip()

            if not choice or choice == cur_model:
                self.console.print(f"[dim]Retaining current model '{cur_model}'.[/dim]")
                return

            if choice.isdigit() and 1 <= int(choice) <= len(avail_ids):
                chosen_model = avail_ids[int(choice) - 1]
            else:
                chosen_model = choice

            mgr.set_model(p_name, chosen_model)
            self.ai_manager = AIManager(mgr)
            self.console.print(f"[bold green]✔ Active model for '{p_name}' successfully set to '{chosen_model}'.[/bold green]")

        elif sub == "default":
            if len(args) < 3:
                raise ValueError("usage: settings default <groq|openai|anthropic|google>")
            p_name = normalize_provider_name(args[2])
            if p_name not in ("groq", "openai", "anthropic", "google"):
                raise ValueError(f"unknown provider '{args[2]}' — choose groq, openai, anthropic, or google")

            cred = mgr.get_credential_info(p_name)
            if not cred.is_configured:
                confirm = Prompt.ask(
                    f"[yellow]Provider '{p_name.upper()}' has no configured API key. Set as default anyway?[/yellow]",
                    choices=["y", "n"],
                    default="n",
                )
                if confirm.lower() != "y":
                    return

            mgr.set_default_provider(p_name)
            self.ai_manager = AIManager(mgr)
            self.console.print(f"[bold green]✔ Default provider set to '{p_name.upper()}'.[/bold green]")

        elif sub == "remove":
            if len(args) < 3:
                raise ValueError("usage: settings remove <groq|openai|anthropic|google>")
            p_name = normalize_provider_name(args[2])
            confirm = Prompt.ask(
                f"[yellow]Remove stored API key for provider '{p_name.upper()}'?[/yellow]",
                choices=["y", "n"],
                default="n",
            )
            if confirm.lower() != "y":
                self.console.print("[dim]Key removal cancelled.[/dim]")
                return

            prev_default = mgr.settings.default_provider
            mgr.remove_api_key(p_name)
            self.ai_manager = AIManager(mgr)
            self.console.print(f"[bold yellow]✔ Removed stored API key for '{p_name}'.[/bold yellow]")
            if prev_default == p_name and mgr.settings.default_provider != prev_default:
                self.console.print(f"[dim cyan]Default provider automatically updated to '{mgr.settings.default_provider.upper()}'.[/dim cyan]")

        elif sub in {"reset-model", "resetmodel"}:
            if len(args) < 3:
                raise ValueError("usage: settings reset-model <groq|openai|anthropic|google>")
            p_name = normalize_provider_name(args[2])
            def_model = mgr.reset_model(p_name)
            self.ai_manager = AIManager(mgr)
            self.console.print(f"[bold green]✔ Active model for '{p_name}' reset to default '{def_model}'.[/bold green]")

        elif sub == "test":
            p_name = normalize_provider_name(args[2]) if len(args) >= 3 else mgr.settings.default_provider
            cred = mgr.get_credential_info(p_name)
            active_model = mgr.get_model(p_name)

            self.console.print(f"\n[bold bright_cyan]✔ Testing API connection to {p_name.upper()}[/bold bright_cyan]")
            self.console.print(f"  [dim white]Model:             {active_model}[/dim white]")
            self.console.print(f"  [dim white]Credential source: {cred.source}[/dim white]")
            if cred.source == "environment":
                self.console.print(f"  [dim white]Environment var:   ${cred.env_var}[/dim white]")

            provider = self.ai_manager.providers.get(p_name)
            if not provider:
                self.console.print(f"[bold red]✖ Unknown provider '{p_name}'.[/bold red]\n")
                return

            loading(self.console, f"Executing live test generation for {p_name.upper()}...", 0.4)
            ok, msg, err_type, latency = provider.validate_credentials()

            if ok:
                latency_ms = int(latency * 1000)
                self.console.print(f"\n[bold green]✔ Connection successful[/bold green]")
                self.console.print(f"[bold green]✔ Response received[/bold green]")
                self.console.print(f"[bold green]✔ Latency: {latency_ms} ms ({latency}s)[/bold green]")
                self.console.print(f"[bold green]✔ Model: {active_model}[/bold green]\n")
            else:
                err_label = err_type.value if err_type else "ERROR"
                self.console.print(f"\n[bold red]✖ {p_name.upper()} connection failed[/bold red]")
                self.console.print(f"[bold red]Reason: {err_label}[/bold red]")
                self.console.print(f"[white]{msg}[/white]\n")

        else:
            if ctrl.handle_command(args[1:]) != 0:
                raise ValueError(f"unknown settings command: '{sub}' — run 'settings' for help")

    # ── Vulnerability engine fabric UX (settings → VULNERABILITY ENGINES) ──
    def vuln_settings_cmd(self, args: list[str]):
        """Manage external vulnerability engines: settings vulnerability ..."""
        from horcrux.core.settings import (
            VULN_CREDENTIAL_FIELDS,
            VULN_ENGINE_IDS,
            VULN_ENGINE_LABELS,
            normalize_vuln_engine_id,
        )
        mgr = SettingsManager()
        rest = list(args[1:])

        if not rest or rest[0].lower() in {"status", "list"}:
            try:
                from horcrux.intel.vuln_engines.orchestrator import readiness_audit
                audit = readiness_audit(mgr, check_health=False)
            except Exception:
                audit = []
            by_id = {r.provider_id: r for r in audit}
            lines = ["[bold bright_magenta]VULNERABILITY ENGINES[/bold bright_magenta]\n"]
            for pid in VULN_ENGINE_IDS:
                label = VULN_ENGINE_LABELS.get(pid, pid)
                r = by_id.get(pid)
                cfg = mgr.settings.vulnerability_engines.get(pid)
                configured = mgr.is_vuln_configured(pid)
                status_icon = "[bold green]● CONFIGURED[/bold green]" if configured else "[dim]○ NOT CONFIGURED[/dim]"
                health = (r.health.value if r else "NOT_CONFIGURED")
                last = (cfg.last_status if cfg and cfg.last_status else "NOT TESTED")
                last_str = "[dim green]Last Test: PASSED[/dim green]" if last in ("READY", "HEALTHY", "PASSED", "OK") else (
                    f"[dim red]Last Test: {last}[/dim red]" if last != "NOT TESTED" else "[dim]Last Test: NOT TESTED[/dim]")
                endpoint = (cfg.endpoint if cfg and cfg.endpoint else "-")
                state = getattr(cfg, "enabled", True)
                en_str = "[green]enabled[/green]" if state else "[yellow]disabled[/yellow]"
                caps = ", ".join((r.capabilities[:3] if r and r.capabilities else ["-"]))
                lines.append(f"  [bold bright_white]{label}[/bold bright_white] {status_icon}")
                lines.append(f"     [dim]Health: {health} | {last_str} | {en_str}[/dim]")
                lines.append(f"     [dim]Endpoint: {endpoint} | Capabilities: {caps}[/dim]\n")
            lines.append("[dim white]Commands:\n"
                         "  settings vulnerability status              (this overview)\n"
                         "  settings vulnerability test <engine>       (connection test)\n"
                         "  settings vulnerability enable <engine>     (enable engine)\n"
                         "  settings vulnerability disable <engine>    (disable engine)\n"
                         "  settings vulnerability endpoint <engine> <url>  (set endpoint/region)\n"
                         "  settings vulnerability configure <engine>  (store credentials)\n"
                         "  settings vulnerability remove <engine>     (remove configuration)[/dim white]")
            self.console.print()
            self.console.print(Panel("\n".join(lines),
                                     title="[bold bright_magenta]✦ VULNERABILITY ENGINES ✦[/bold bright_magenta]",
                                     box=box.ROUNDED, border_style="bright_magenta", padding=(1, 2)))
            self.console.print()
            return

        sub = rest[0].lower()
        if sub == "test":
            target = normalize_vuln_engine_id(rest[1]) if len(rest) >= 2 else ""
            if not target:
                raise ValueError("usage: settings vulnerability test <tenable|qualys|rapid7|greenbone|msdefender>")
            self.engines_test(target)
            return
        if sub in {"enable", "disable"}:
            if len(rest) < 2:
                raise ValueError(f"usage: settings vulnerability {sub} <engine>")
            pid = normalize_vuln_engine_id(rest[1])
            mgr.set_vuln_enabled(pid, sub == "enable")
            self.console.print(f"[bold green]✔ Engine '{pid}' {sub}d.[/bold green]")
            return
        if sub == "endpoint":
            if len(rest) < 3:
                raise ValueError("usage: settings vulnerability endpoint <engine> <url>")
            pid = normalize_vuln_engine_id(rest[1])
            mgr.set_vuln_endpoint(pid, " ".join(rest[2:]))
            self.console.print(f"[bold green]✔ Endpoint for '{pid}' updated.[/bold green]")
            return
        if sub in {"configure", "provider", "key", "creds", "credentials"}:
            if len(rest) < 2:
                raise ValueError("usage: settings vulnerability configure <engine>")
            pid = normalize_vuln_engine_id(rest[1])
            fields = VULN_CREDENTIAL_FIELDS.get(pid, ["api_key"])
            supplied: dict[str, str] = {}
            # allow key=value pairs on the CLI to avoid interactive prompts in scripts
            for token in rest[2:]:
                if "=" in token:
                    k, _, v = token.partition("=")
                    if k.strip() in fields and v.strip():
                        supplied[k.strip()] = v.strip()
            for fname in fields:
                if fname not in supplied:
                    try:
                        val = Prompt.ask(f"[bold bright_cyan]Enter {fname} for {pid.upper()}[/bold bright_cyan]",
                                         password=True).strip()
                    except Exception:
                        val = ""
                    if val:
                        supplied[fname] = val
            if not supplied:
                self.console.print("[yellow]No credentials provided. Configuration unchanged.[/yellow]")
                return
            mgr.set_vuln_credentials(pid, supplied)
            self.console.print(f"[bold green]✔ Credentials stored securely for engine '{pid}'.[/bold green]")
            return
        if sub in {"remove", "delete", "clear"}:
            if len(rest) < 2:
                raise ValueError("usage: settings vulnerability remove <engine>")
            pid = normalize_vuln_engine_id(rest[1])
            mgr.remove_vuln_config(pid)
            self.console.print(f"[bold yellow]✔ Removed configuration for '{pid}'.[/bold yellow]")
            return
        if normalize_vuln_engine_id(sub) in VULN_ENGINE_IDS:
            from horcrux.core.integrations.controller import SettingsController
            ctrl = SettingsController(console=self.console, settings_manager=mgr)
            ctrl.handle_command(["vulnerability"] + rest)
            return
        raise ValueError(f"unknown vulnerability command: '{sub}' — run 'settings vulnerability' for help")

    def engines_cmd(self, args: list[str]):
        rest = [a for a in args[1:]]
        if not rest or rest[0].lower() == "status":
            self.engines_status()
        elif rest[0].lower() == "test":
            self.engines_test(rest[1] if len(rest) > 1 else "")
        elif rest[0].lower() == "info":
            self.engines_info(rest[1] if len(rest) > 1 else "")
        else:
            raise ValueError(f"unknown engines command: '{rest[0]}' — use status, test, or info")

    def engines_status(self):
        from horcrux.core.settings import VULN_ENGINE_IDS, VULN_ENGINE_LABELS
        mgr = SettingsManager()
        try:
            from horcrux.intel.vuln_engines.orchestrator import readiness_audit
            audit = readiness_audit(mgr, check_health=False)
        except Exception:
            audit = []
        by_id = {r.provider_id: r for r in audit}
        table = Table(title="[bold bright_magenta]✦ VULNERABILITY ENGINE READINESS ✦[/bold bright_magenta]",
                      box=box.ROUNDED, border_style="magenta", header_style="bold bright_cyan", expand=True)
        table.add_column("Engine", style="bold bright_white")
        table.add_column("Configured", justify="center")
        table.add_column("Health", justify="center")
        table.add_column("Last Test", justify="center")
        table.add_column("Capabilities", style="dim cyan")
        for pid in VULN_ENGINE_IDS:
            label = VULN_ENGINE_LABELS.get(pid, pid)
            r = by_id.get(pid)
            configured = mgr.is_vuln_configured(pid)
            conf_badge = "[bold green]YES[/bold green]" if configured else "[dim]NO[/dim]"
            health = (r.health.value if r else "NOT_CONFIGURED")
            if health in ("HEALTHY", "CONFIGURED"):
                h_badge = f"[bold green]{health}[/bold green]"
            elif health == "NOT_CONFIGURED":
                h_badge = "[dim]NOT_CONFIGURED[/dim]"
            else:
                h_badge = f"[yellow]{health}[/yellow]"
            cfg = mgr.settings.vulnerability_engines.get(pid)
            last = (cfg.last_status if cfg and cfg.last_status else "NOT TESTED")
            caps = ", ".join((r.capabilities[:2] if r and r.capabilities else ["-"]))
            table.add_row(label, conf_badge, h_badge, last, caps)
        self.console.print()
        self.console.print(table)
        self.console.print()

    def engines_test(self, provider: str):
        from horcrux.core.settings import normalize_vuln_engine_id
        pid = normalize_vuln_engine_id(provider or "")
        if not pid:
            raise ValueError("usage: engines test <tenable|qualys|rapid7|greenbone|msdefender>")
        mgr = SettingsManager()
        try:
            from horcrux.intel.vuln_engines.registry import get_engine
            engine = get_engine(pid, config=mgr.get_vuln_engine_config(pid),
                                credentials=mgr.get_vuln_credentials(pid))
        except Exception as exc:
            self.console.print(f"[bold red]✖ Unknown engine '{provider}': {exc}[/bold red]")
            return
        self.console.print(f"\n[bold bright_cyan]✔ Testing connection to {engine.product}[/bold bright_cyan]")
        try:
            health = engine.health_check()
        except Exception as exc:
            health = "BROKEN"
            self.console.print(f"[bold red]✖ Health check error: {exc}[/bold red]")
        from horcrux.intel.vuln_engines.types import EngineHealth as _EH
        ok = health in (_EH.HEALTHY, _EH.CONFIGURED)
        try:
            mgr.set_vuln_validation(pid, "READY" if ok else str(getattr(health, 'value', health)))
        except Exception:
            pass
        if ok:
            self.console.print("[bold green]✔ Connection successful[/bold green]")
            self.console.print(f"[bold green]✔ Health: {getattr(health, 'value', health)}[/bold green]\n")
        else:
            self.console.print(f"[bold red]✖ Engine not healthy: {getattr(health, 'value', health)}[/bold red]\n")

    def engines_info(self, provider: str):
        from horcrux.core.settings import VULN_ENGINE_IDS, normalize_vuln_engine_id
        mgr = SettingsManager()
        targets = [normalize_vuln_engine_id(provider)] if (provider or "").strip() else list(VULN_ENGINE_IDS)
        try:
            from horcrux.intel.vuln_engines.registry import get_engine
        except Exception as exc:
            self.console.print(f"[bold red]✖ Engine registry unavailable: {exc}[/bold red]")
            return
        for pid in targets:
            try:
                engine = get_engine(pid, config=mgr.get_vuln_engine_config(pid),
                                    credentials=mgr.get_vuln_credentials(pid))
                info = engine.describe()
            except Exception as exc:
                self.console.print(f"[bold red]✖ {pid}: {exc}[/bold red]")
                continue
            body = (
                f"[bold bright_yellow]Product:[/bold bright_yellow] {info['product']}\n"
                f"[bold bright_yellow]API:[/bold bright_yellow] {info['api_version']}\n"
                f"[bold bright_yellow]Docs verified:[/bold bright_yellow] {info['docs_verified']}\n"
                f"[bold bright_yellow]Deployment:[/bold bright_yellow] {info['deployment_type']}\n"
                f"[bold bright_yellow]Endpoint:[/bold bright_yellow] {info['endpoint'] or '-'}\n"
                f"[bold bright_yellow]Auth:[/bold bright_yellow] {info['authentication_type']}\n"
                f"[bold bright_yellow]Capabilities:[/bold bright_yellow] {', '.join(info['capabilities']) or '-'}\n"
                f"[bold bright_yellow]Asset types:[/bold bright_yellow] {', '.join(info['supported_asset_types']) or '-'}\n"
                f"[bold bright_yellow]Result formats:[/bold bright_yellow] {', '.join(info['supported_result_formats']) or '-'}\n"
                f"[bold bright_yellow]Limitations:[/bold bright_yellow]\n"
                + "\n".join(f"  • {lim}" for lim in info['known_limitations'][:5]))
            self.console.print()
            self.console.print(Panel(body, title=f"[bold bright_magenta]✦ {pid.upper()} ✦[/bold bright_magenta]",
                                     box=box.ROUNDED, border_style="magenta", padding=(0, 2)))
        self.console.print()

    def import_cmd(self, args: list[str]):
        """Import external scanner results: import <path> [--provider tenable]."""
        self.require_workspace()
        if len(args) < 2:
            raise ValueError("usage: import <result-file> [--provider tenable|qualys|rapid7|greenbone]")
        path = args[1]
        provider = "auto"
        for i, tok in enumerate(args[2:], start=2):
            if tok == "--provider" and i + 1 < len(args):
                provider = args[i + 1]
        from pathlib import Path as _Path
        if not _Path(path).exists():
            raise ValueError(f"result file not found: {path}")
        try:
            from horcrux.intel.vuln_engines.importers import import_results, summarize_import
            from horcrux.intel.vuln_engines.orchestrator import correlate_and_store, persist_runs
        except Exception as exc:
            raise ValueError(f"import subsystem unavailable: {exc}")
        findings = import_results(path, provider=provider)
        state = self.workspace.load()
        entities = correlate_and_store(self.workspace, state, findings)
        summary = summarize_import(findings)
        persist_runs(self.workspace, {f"import:{summary['provenance'][0] if summary['provenance'] else path}": {
            "status": "COMPLETE", "reason": "imported result (IMPORTED_RESULT)",
            "results": len(findings), "imported": True}})
        self.console.print(f"[bold green]✔ Imported {len(findings)} observations "
                           f"({len(entities)} deduplicated entities) as IMPORTED_RESULT.[/bold green]")

    def ai_cmd(self, args: list[str]):
        mgr = self.ai_manager.settings

        if len(args) == 1 or args[1].lower() == "status":
            import time as _time
            st = self.ai_manager.status()
            status_badge = "[bold green]READY[/bold green]" if st["status"] == "READY" else f"[dim yellow]{st['status']}[/dim yellow]"
            last_req = st.get("last_request", {})

            # Format last-request section
            if last_req:
                lr_at = last_req.get("at", 0)
                lr_ago = ""
                if lr_at:
                    diff = _time.time() - lr_at
                    if diff < 60:
                        lr_ago = f"{int(diff)}s ago"
                    elif diff < 3600:
                        lr_ago = f"{int(diff // 60)}m ago"
                    else:
                        lr_ago = f"{int(diff // 3600)}h ago"
                lr_provider = last_req.get("provider", "-").upper()
                lr_model = last_req.get("model", "-")
                lr_latency = last_req.get("latency_ms", 0)
                lr_status = last_req.get("status", "-")
                lr_finish = last_req.get("finish_reason", "")
                lr_in = last_req.get("input_tokens", 0)
                lr_out = last_req.get("output_tokens", 0)
                lr_total = last_req.get("total_tokens", 0)
                lr_cached = " [dim green](cached)[/dim green]" if last_req.get("cached") else ""
                status_color = "green" if lr_status == "OK" else "red"
                last_req_block = (
                    f"\n[bold bright_yellow]── LAST REQUEST ─────────────────[/bold bright_yellow]\n"
                    f"[bold bright_yellow]  Time:                [/bold bright_yellow] [dim]{lr_ago}[/dim]{lr_cached}\n"
                    f"[bold bright_yellow]  Provider / Model:    [/bold bright_yellow] [bold bright_cyan]{lr_provider}[/bold bright_cyan] / [bright_white]{lr_model}[/bright_white]\n"
                    f"[bold bright_yellow]  Latency:             [/bold bright_yellow] [bold]{lr_latency} ms[/bold]\n"
                    f"[bold bright_yellow]  Status:              [/bold bright_yellow] [{status_color}]{lr_status}[/{status_color}]"
                    + (f"  [dim]finish={lr_finish}[/dim]" if lr_finish else "") + "\n"
                    f"[bold bright_yellow]  Tokens (in/out/tot): [/bold bright_yellow] {lr_in:,} / {lr_out:,} / {lr_total:,}\n"
                )
            else:
                last_req_block = "\n[dim]No requests recorded in this session.[/dim]\n"

            body = (
                f"[bold bright_yellow]Status:                 [/bold bright_yellow] {status_badge}\n"
                f"[bold bright_yellow]Active Provider:        [/bold bright_yellow] [bold bright_cyan]{st['provider'].upper()}[/bold bright_cyan]\n"
                f"[bold bright_yellow]Active Model:           [/bold bright_yellow] [bold bright_white]{st['model']}[/bold bright_white]\n"
                f"[bold bright_yellow]Credential Source:      [/bold bright_yellow] [dim]{st['credential_source']}[/dim]\n"
                f"[bold bright_yellow]Credential Fingerprint: [/bold bright_yellow] [dim]{st['credential_fingerprint']}[/dim]\n"
                f"\n[bold bright_yellow]── LIFETIME USAGE ───────────────[/bold bright_yellow]\n"
                f"[bold bright_yellow]  Calls Made:           [/bold bright_yellow] {st['calls']}\n"
                f"[bold bright_yellow]  Cached Responses:     [/bold bright_yellow] {st['cached_calls']}\n"
                f"[bold bright_yellow]  Input Tokens:         [/bold bright_yellow] {st['input_tokens']:,}\n"
                f"[bold bright_yellow]  Output Tokens:        [/bold bright_yellow] {st['output_tokens']:,}\n"
                f"[bold bright_yellow]  Reasoning Tokens:     [/bold bright_yellow] {st['reasoning_tokens']:,}\n"
                f"[bold bright_yellow]  Total Tokens:         [/bold bright_yellow] {st['total_tokens']:,}\n"
                + last_req_block
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

        if sub in {"providers", "provider"}:
            table = Table(
                title="[bold bright_magenta]✦ HORCRUX AI PROVIDERS ECOSYSTEM ✦[/bold bright_magenta]",
                box=box.ROUNDED,
                border_style="magenta",
                header_style="bold bright_cyan",
            )
            table.add_column("Provider", style="bold bright_white")
            table.add_column("Status", justify="center")
            table.add_column("Model", style="cyan")
            table.add_column("Credential Source", style="dim white")
            table.add_column("Fingerprint", style="dim yellow")
            table.add_column("Last Test", justify="center")

            def_prov = mgr.settings.default_provider
            for p_id in ("groq", "openai", "anthropic", "google"):
                cred = mgr.get_credential_info(p_id)
                st_badge = "[bold green]CONFIGURED[/bold green]" if cred.is_configured else "[dim]NOT CONFIGURED[/dim]"
                model = mgr.get_model(p_id)
                cfg = mgr.settings.providers.get(p_id)
                last_st = cfg.last_status if cfg and cfg.last_status else "NOT TESTED"
                test_badge = "[green]SUCCESS[/green]" if last_st == "READY" else (f"[red]{last_st}[/red]" if last_st != "NOT TESTED" else "[dim]NOT TESTED[/dim]")
                p_display = f"{p_id.upper()} [bold yellow]★ DEFAULT[/bold yellow]" if p_id == def_prov else p_id.upper()
                table.add_row(p_display, st_badge, model, cred.source, cred.fingerprint, test_badge)

            self.console.print()
            self.console.print(table)
            self.console.print()

        elif sub in {"models", "model"}:
            self.settings_cmd(["settings", "models"] + args[2:])

        elif sub == "enable":
            self.ai_manager.settings.set_enabled(True)
            self.console.print("[bold green]✔ AI engine enabled.[/bold green]")

        elif sub == "disable":
            self.ai_manager.settings.set_enabled(False)
            self.console.print("[bold yellow]✔ AI engine disabled. Falling back to local deterministic intelligence.[/bold yellow]")

        elif sub in {"clear-cache", "clearcache"}:
            self.ai_manager.clear_cache()
            self.console.print("[bold green]✔ AI response cache cleared.[/bold green]")

        elif sub in {"reset-stats", "resetstats"}:
            self.ai_manager.reset_stats()
            self.console.print("[bold green]✔ AI usage statistics reset to zero.[/bold green]")

        elif sub in {"debug", "diag"}:
            st = self.ai_manager.status()
            last_req = st.get("last_request", {})
            last_err = getattr(self.ai_manager, "last_error", None)
            last_stage = getattr(self.ai_manager, "last_failure_stage", "") or last_req.get("failure_stage", "")
            last_diag = getattr(self.ai_manager, "last_diagnostic", "") or last_req.get("diagnostic", "")
            last_resp = getattr(self.ai_manager, "last_response", None)

            debug_table = Table(
                title="[bold bright_magenta]✦ HORCRUX AI INTERNAL NORMALIZATION & PIPELINE DIAGNOSTICS ✦[/bold bright_magenta]",
                box=box.ROUNDED,
                border_style="bright_magenta",
                expand=True,
            )
            debug_table.add_column("Component", style="bold bright_yellow", width=24)
            debug_table.add_column("Diagnostic Value", style="bright_white")

            debug_table.add_row("Configured Provider", f"[bold bright_cyan]{st['provider'].upper()}[/bold bright_cyan]")
            debug_table.add_row("Configured Model", f"[bright_white]{st['model']}[/bright_white]")
            debug_table.add_row("Provider Status", f"[bold green]{st['status']}[/bold green]" if st['status'] == 'READY' else f"[bold red]{st['status']}[/bold red]")
            debug_table.add_row("Credential Source", f"[dim]{st['credential_source']}[/dim]")
            debug_table.add_row("Last Failure Stage", f"[bold red]{last_stage}[/bold red]" if last_stage else "[dim green]NONE (last operation successful)[/dim green]")
            if last_diag:
                debug_table.add_row("Last Diagnostic", f"[italic white]{last_diag}[/italic white]")
            if last_err:
                debug_table.add_row("Last Raw Error", f"[red]{type(last_err).__name__}: {last_err}[/red]")
            if last_resp:
                debug_table.add_row(
                    "Last Response Shape",
                    f"tokens(in={last_resp.prompt_tokens}, out={last_resp.completion_tokens}, reason={last_resp.reasoning_tokens}) latency={last_resp.latency}s finish={last_resp.finish_reason or 'stop'}"
                )
                preview_content = last_resp.content[:120] + "..." if len(last_resp.content) > 120 else last_resp.content
                debug_table.add_row("Content Preview", f"[dim]{preview_content}[/dim]")

            self.console.print()
            self.console.print(debug_table)
            self.console.print()

        elif sub == "usage":
            usage = self.ai_manager.get_usage()
            table = Table(
                title="[bold bright_magenta]✦ AI ENGINE TOKEN & CALL USAGE ✦[/bold bright_magenta]",
                box=box.ROUNDED,
                border_style="magenta",
                header_style="bold bright_cyan",
            )
            table.add_column("Provider:Model", style="bold white")
            table.add_column("Calls", justify="center")
            table.add_column("Cached", justify="center", style="dim green")
            table.add_column("Input", justify="right", style="cyan")
            table.add_column("Output", justify="right", style="cyan")
            table.add_column("Reasoning", justify="right", style="yellow")
            table.add_column("Total Tokens", justify="right", style="bold yellow")

            for k, rec in usage.get("by_model", {}).items():
                table.add_row(
                    k,
                    str(rec.get("calls", 0)),
                    str(rec.get("cached_calls", 0)),
                    f"{rec.get('input_tokens', 0):,}",
                    f"{rec.get('output_tokens', 0):,}",
                    f"{rec.get('reasoning_tokens', 0):,}",
                    f"{rec.get('total_tokens', 0):,}",
                )

            self.console.print()
            if usage.get("by_model"):
                self.console.print(table)
            else:
                self.console.print("[dim yellow]No recorded AI usage yet.[/dim yellow]")
            self.console.print(
                f"[bold bright_yellow]Total Tokens:[/bold bright_yellow] {usage['total_tokens']:,} | "
                f"[bold bright_yellow]Total Calls:[/bold bright_yellow] {usage['total_calls']} "
                f"([green]{usage['total_cached_calls']} cached[/green])\n"
            )
        else:
            raise ValueError("usage: ai [status|providers|models|enable|disable|usage|clear-cache|reset-stats]")

    def raw_cmd(self, args: list[str]):
        if len(args) < 2:
            raise ValueError("usage: raw <module_name> (e.g. raw nmap-tcp, raw nuclei, raw smbclient)")
        target_name = args[1].lower()
        matching = list(self.workspace.raw.glob(f"*{target_name}*"))
        if not matching:
            raise ValueError(f"No raw artifacts matching '{target_name}' found in {self.workspace.raw}")
        path = matching[0]
        content = path.read_text(encoding="utf-8", errors="replace")
        size_kb = path.stat().st_size / 1024
        subtitle = f"[dim]{path.name}  •  {size_kb:.1f} KB[/dim]"
        if size_kb > 50:
            self.console.print(f"[dim yellow]⚠ Large artifact ({size_kb:.1f} KB) — displaying full content.[/dim yellow]")
        self.console.print(
            Panel(
                content,
                title=f"[bold bright_cyan]{path.name}[/bold bright_cyan]",
                subtitle=subtitle,
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
        table.add_column("Importance", justify="center", no_wrap=True)
        table.add_column("Status", justify="center", no_wrap=True)
        table.add_column("Purpose", style="dim white")
        table.add_column("Install Guidance", style="italic yellow")

        tool_map = {item[0]: item for item in tools}

        for cat_name, cat_tools in CATEGORIES.items():
            for tool_name, desc in cat_tools.items():
                item = tool_map.get(tool_name)
                path = item[1] if item else None
                install_guide = item[3] if item and len(item) > 3 else ""
                importance = item[4] if item and len(item) > 4 else ToolImportance.OPTIONAL

                if importance == ToolImportance.REQUIRED:
                    imp_badge = "[bold red]REQUIRED[/bold red]"
                elif importance == ToolImportance.RECOMMENDED:
                    imp_badge = "[bold yellow]RECOMMENDED[/bold yellow]"
                elif importance == ToolImportance.ENVIRONMENT:
                    imp_badge = "[dim]ENV-SPECIFIC[/dim]"
                else:
                    imp_badge = "[dim cyan]OPTIONAL[/dim cyan]"

                status_text = "[bold green]✔ OK[/bold green]" if path else "[dim red]✖ MISSING[/dim red]"
                guide_text = "" if path else install_guide
                table.add_row(cat_name, tool_name, imp_badge, status_text, desc, guide_text)

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
        ai_table.add_column("Configured Model", style="bold bright_green")
        ai_table.add_column("Last Test", justify="center", style="dim white")
        ai_table.add_column("Storage", justify="center", style="dim cyan")
        ai_table.add_column("Key Availability", style="dim white")

        mgr = SettingsManager()
        for p_name in ("groq", "openai", "anthropic", "google"):
            has_key, masked = mgr.get_provider_status(p_name)
            p_cfg = mgr.settings.providers.get(p_name)
            model_id = mgr.get_model(p_name)
            storage_src = mgr.get_key_source(p_name)

            if not has_key:
                st_badge = "[dim]○ NOT CONFIGURED[/dim]"
                test_str = "-"
            elif p_cfg and p_cfg.last_status == "READY":
                st_badge = "[bold green]READY[/bold green]"
                test_str = "[bold green]PASSED[/bold green]"
            elif p_cfg and p_cfg.last_status:
                st_badge = f"[dim red]ERROR ({p_cfg.last_status})[/dim red]"
                test_str = f"[red]{p_cfg.last_status}[/red]"
            else:
                st_badge = "[bold green]CONFIGURED[/bold green]"
                test_str = "[dim]untested[/dim]"

            ai_table.add_row(p_name.upper(), st_badge, model_id, test_str, storage_src, masked)

        self.console.print()
        self.console.print(ai_table)

        # External vulnerability engine audit (no secrets exposed)
        try:
            from horcrux.core.settings import VULN_ENGINE_IDS, VULN_ENGINE_LABELS
            from horcrux.intel.vuln_engines.orchestrator import readiness_audit
            eng_audit = readiness_audit(mgr, check_health=False)
            eng_by_id = {r.provider_id: r for r in eng_audit}
            eng_table = Table(
                title="[bold bright_magenta]✦ EXTERNAL VULNERABILITY ENGINES ✦[/bold bright_magenta]",
                box=box.ROUNDED,
                border_style="magenta",
                header_style="bold bright_cyan",
                expand=True,
            )
            eng_table.add_column("Engine", style="bold bright_white")
            eng_table.add_column("Configured", justify="center", no_wrap=True)
            eng_table.add_column("Health", justify="center", no_wrap=True)
            eng_table.add_column("Capabilities", style="dim cyan")
            eng_table.add_column("Last Test", justify="center", style="dim white")
            for pid in VULN_ENGINE_IDS:
                r = eng_by_id.get(pid)
                configured = mgr.is_vuln_configured(pid)
                conf_badge = "[bold green]YES[/bold green]" if configured else "[dim]NO[/dim]"
                health = (r.health.value if r else "NOT_CONFIGURED")
                if health in ("HEALTHY", "CONFIGURED"):
                    h_badge = f"[bold green]{health}[/bold green]"
                elif health == "NOT_CONFIGURED":
                    h_badge = "[dim]NOT_CONFIGURED[/dim]"
                else:
                    h_badge = f"[yellow]{health}[/yellow]"
                caps = ", ".join((r.capabilities[:2] if r and r.capabilities else ["-"]))
                cfg = mgr.settings.vulnerability_engines.get(pid)
                last = (cfg.last_status if cfg and cfg.last_status else "-")
                eng_table.add_row(VULN_ENGINE_LABELS.get(pid, pid), conf_badge, h_badge, caps, last)
            self.console.print()
            self.console.print(eng_table)
        except Exception:
            pass

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

