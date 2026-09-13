from __future__ import annotations

import sys
import typer
from rich.console import Console

from horcrux import __version__
from horcrux.core.orchestrator import Orchestrator
from horcrux.core.storage import Workspace
from horcrux.ui.ascii import banner, show_gallery
from horcrux.ui.console import ConsoleApp

# Ensure UTF-8 output encoding across platforms
if sys.platform == "win32":
    try:
        if sys.stdout and hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        if sys.stderr and hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

app = typer.Typer(
    add_completion=False,
    no_args_is_help=False,
    help="HORCRUX offensive-security operator console and attack surface platform",
)


@app.callback(invoke_without_command=True)
def root(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", "-v", help="Display version and animated banner"),
):
    if version:
        banner(Console(), __version__, duration=0.8)
        raise typer.Exit()


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target IP, hostname, or CIDR range"),
    profile: str = typer.Option("standard", "--profile", "-p", help="Scan profile: quick, standard, deep, network, web, service, intel, local"),
    deep: bool = typer.Option(False, "--deep", help="Run deep port scanning and enumeration"),
    verify: bool = typer.Option(False, "--verify", help="Execute non-destructive verification checks"),
):
    """Run full automated attack surface reconnaissance against a target."""
    console = Console()
    selected_profile = "deep" if deep else profile
    console.print(f"\n[bold bright_magenta]⚡ SCANNING:[/bold bright_magenta] [bold bright_cyan]{target}[/bold bright_cyan]  [dim]profile={selected_profile}[/dim]\n")
    ws = Workspace(target)
    Orchestrator(
        target,
        ws,
        console,
        profile=selected_profile,
    ).scan(deep=deep, verify=verify)
    from horcrux.ui.ascii import fanfare
    fanfare(console, f"TARGET SYNTHESIS COMPLETE: {target}")


@app.command()
def doctor():
    """Check external security tools and wordlist availability."""
    ConsoleApp().doctor()


@app.command()
def tools():
    """Quick audit of external tool binary availability."""
    ConsoleApp().doctor(only_tools=True)


@app.command()
def console():
    """Launch the interactive operator console."""
    ConsoleApp().run()


@app.command(
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
)
def settings(
    ctx: typer.Context,
):
    """View and configure AI providers, keys, and regional models."""
    args = ["settings"] + list(ctx.args)
    ConsoleApp().settings_cmd(args)


@app.command()
def report(
    target: str = typer.Argument(..., help="Target workspace name to generate report for"),
):
    """Generate Markdown engagement report for target workspace."""
    from horcrux.reporting.reports import markdown
    ws = Workspace(target)
    out = markdown(ws)
    Console().print(f"[bold green]✔ Report written to:[/bold green] {out}")


@app.command()
def ask(
    question: str = typer.Argument(..., help="Question to ask AI security analyst"),
    target: str = typer.Option("", "--target", "-t", help="Target workspace context (optional)"),
):
    """Query the HORCRUX AI security analyst with target context."""
    app_inst = ConsoleApp()
    if target and target.lower() != "ready":
        app_inst.workspace = Workspace(target)
    else:
        app_inst.workspace = None
    app_inst.ask_cmd(["ask", question])


@app.command(name="gallery")
def gallery_cmd():
    """Display the Horcrux ASCII art gallery and relics."""
    show_gallery(Console())


@app.command(name="artifacts")
def artifacts_cmd():
    """Display the Horcrux ASCII art gallery and relics."""
    show_gallery(Console())


@app.command(
    name="ai",
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
)
def ai_cli(ctx: typer.Context):
    """Manage AI engine status, usage metrics, cache, and enable/disable."""
    args = ["ai"] + list(ctx.args)
    ConsoleApp().ai_cmd(args)


@app.command()
def assess(
    target: str = typer.Argument(..., help="Target workspace to assess"),
    iterations: int = typer.Option(15, "--iterations", "-n", help="Max investigation loop iterations"),
):
    """Run agentic VAPT assessment loop against a target workspace."""
    from horcrux.agents.coordinator import run_full_assessment
    from horcrux.ui.ascii import fanfare

    console = Console()
    ws = Workspace(target)
    state = ws.load()
    console.print(f"\n[bold bright_magenta]⚡ ASSESSMENT:[/bold bright_magenta] [bold bright_cyan]{target}[/bold bright_cyan]\n")

    run_full_assessment(ws, max_iterations=iterations)

    state = ws.load()
    app = state.get_application_model()
    coverage = state.get_security_coverage().percentage_complete()
    agents = state.agent_states
    investigations = state.get_investigations()

    console.print("[bold]Application understanding[/bold]")
    if app.endpoints:
        console.print(f"  [green]✔[/green] {len(app.endpoints)} endpoints mapped")
    if app.profile.app_type != "unknown":
        console.print(f"  [green]✔[/green] {app.profile.app_type} detected ({app.profile.framework})")
    if app.authentication:
        console.print(f"  [green]✔[/green] {len(app.authentication)} authentication surface(s)")

    console.print("\n[bold]Agents[/bold]")
    for agent in agents[:6]:
        color = {"RUNNING": "yellow", "READY": "green", "COMPLETE": "blue"}.get(agent.status, "dim")
        console.print(f"  {agent.name:<22} [{color}]{agent.status}[/{color}]")

    console.print("\n[bold]Investigations[/bold]")
    for inv in investigations[:5]:
        console.print(f"  {inv.objective[:50]:<50} {inv.state.value}")

    console.print("\n[bold]Coverage[/bold]")
    for domain, pct in coverage.items():
        console.print(f"  {domain:<18} {pct:.0f}%")

    console.print(f"\n[bold]Hypotheses:[/bold] {len(state.get_hypotheses())}  [bold]Findings:[/bold] {len(state.findings)}")
    fanfare(console, f"ASSESSMENT CYCLE COMPLETE: {target}")


KNOWN_COMMANDS = {
    "scan", "assess", "doctor", "tools", "console", "gallery", "artifacts",
    "settings", "report", "ask", "ai",
    "--help", "-h", "--version", "-v",
}



def main():
    if len(sys.argv) == 1:
        ConsoleApp().run()
        return

    first = sys.argv[1].lower()
    # If the operator runs `horcrux 10.10.10.10 [--deep]`, route to `scan` command
    if first not in KNOWN_COMMANDS and not first.startswith("-"):
        sys.argv.insert(1, "scan")

    app()


if __name__ == "__main__":
    main()

