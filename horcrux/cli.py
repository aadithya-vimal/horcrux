from __future__ import annotations

import json
import sys
import typer
from rich import box
from rich.console import Console
from rich.table import Table

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
    profile: str = typer.Option("standard", "--profile", "-p", help="Scan profile: quick, standard, deep, full, network, web, service, intel, local"),
    deep: bool = typer.Option(False, "--deep", help="Run deep port scanning and enumeration"),
    verify: bool = typer.Option(False, "--verify", help="Execute non-destructive verification checks"),
    engines: str = typer.Option("", "--engines", help="Comma-separated vulnerability engines to use (tenable,qualys,rapid7,greenbone,msdefender)"),
    skip_engines: bool = typer.Option(False, "--skip-engines", help="Skip all external vulnerability engines (native only)"),
    engine_mode: str = typer.Option("best", "--engine-mode", help="Engine strategy: best (dedupe redundant) or all"),
):
    """Run full automated attack surface reconnaissance against a target."""
    console = Console()
    selected_profile = "deep" if deep else profile
    engine_list = [e.strip() for e in engines.split(",") if e.strip()] or None
    console.print(f"\n[bold bright_magenta]⚡ SCANNING:[/bold bright_magenta] [bold bright_cyan]{target}[/bold bright_cyan]  [dim]profile={selected_profile}[/dim]\n")
    ws = Workspace(target)
    Orchestrator(
        target,
        ws,
        console,
        profile=selected_profile,
        engines=engine_list,
        skip_engines=skip_engines,
        engine_mode=engine_mode,
    ).scan(deep=deep, verify=verify)
    from horcrux.ui.ascii import fanfare
    fanfare(console, f"TARGET SYNTHESIS COMPLETE: {target}")


@app.command()
def engines(
    action: str = typer.Argument("status", help="status, test, or info"),
    provider: str = typer.Argument("", help="Engine id: tenable, qualys, rapid7, greenbone, msdefender"),
):
    """Inspect external vulnerability engine readiness, health, and capabilities."""
    app_inst = ConsoleApp()
    if action.lower() == "status":
        app_inst.engines_status()
    elif action.lower() == "test":
        app_inst.engines_test(provider)
    elif action.lower() == "info":
        app_inst.engines_info(provider)
    else:
        Console().print(f"[bold red]Unknown engines action '{action}'.[/bold red] Use status, test, or info.")


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
def status(
    target: str = typer.Argument(..., help="Target workspace to show status for"),
):
    """Show the operator status console for a target workspace (no scan)."""
    app_inst = ConsoleApp()
    app_inst.workspace = Workspace(target)
    app_inst.status()


@app.command()
def replay(
    target: str = typer.Argument(..., help="Target workspace to replay"),
    script: str = typer.Option("", "--script", "-s", help="Evidence script path (default: workspace evidence-script.json)"),
):
    """Replay an assessment deterministically from recorded evidence (no network)."""
    from pathlib import Path as _Path
    from horcrux.bench.runner import replay_workspace
    console = Console()
    ws = Workspace(target)
    script_path = _Path(script) if script else (ws.root / "evidence-script.json")
    if not script_path.exists():
        from horcrux.bench.runner import write_evidence_script
        script_path = write_evidence_script(ws)
        console.print(f"[dim]Recorded evidence script: {script_path}[/dim]")
    state = replay_workspace(target, script_path)
    app = state.get_application_model()
    console.print(f"\n[bold bright_magenta]REPLAY COMPLETE:[/bold bright_magenta] "
                  f"[bold bright_cyan]{target}[/bold bright_cyan]\n")
    console.print(f"  endpoints={len(app.endpoints)} "
                  f"hypotheses={len(state.get_hypotheses())} "
                  f"investigations={len(state.get_investigations())} "
                  f"paths={len(state.attack_paths or [])}")


@app.command()
def benchmark(
    fixture: str = typer.Argument("", help="Fixture name or 'all' (default: all)"),
):
    """Run the synthetic benchmark suite (fully offline, no external targets)."""
    import tempfile
    from pathlib import Path as _Path
    from horcrux.bench.fixtures import FIXTURES
    from horcrux.bench.runner import run_suite
    console = Console()
    names = sorted(FIXTURES) if fixture in ("", "all") else [fixture]
    unknown = [n for n in names if n not in FIXTURES]
    if unknown:
        console.print(f"[bold red]Unknown fixture(s):[/bold red] {', '.join(unknown)}")
        raise typer.Exit(code=1)
    with tempfile.TemporaryDirectory() as tmp:
        report = run_suite(names, _Path(tmp))
    console.print(f"\n[bold]Benchmark:[/bold] {report['passed']}/{report['fixtures']} "
                  f"suites >= 0.60 (mean score {report['mean_score']})")
    for res in report["results"]:
        mark = "[green]✔[/green]" if res["score"] >= 0.6 else "[red]✖[/red]"
        console.print(f"  {mark} {res['fixture']:<22} score={res['score']} "
                      f"({res['passed']}/{res['total']})")


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


# ── HEADLESS AUTONOMOUS COMMANDS ──────────────────────────────────────────
headless_app = typer.Typer(
    name="headless",
    help="Autonomous headless VAPT assessment operator and mission controller",
    no_args_is_help=True,
)


def _resolve_workspace_for_mission(target_or_id: str) -> Workspace:
    ws = Workspace(target_or_id)
    if ws.state_file.exists():
        return ws
    from pathlib import Path
    base = Path("workspaces")
    if base.exists():
        for d in base.iterdir():
            if d.is_dir() and (d / "state.json").exists():
                try:
                    cand_ws = Workspace(d.name)
                    st = cand_ws.load()
                    m = st.get_mission()
                    if m and m.mission_id == target_or_id:
                        return cand_ws
                except Exception:
                    pass
    return ws


@headless_app.command("scan")
def headless_scan(
    target: str = typer.Argument(..., help="Target URL, hostname, or IP address"),
    profile: str = typer.Option("standard", "--profile", "-p", help="Scan profile: quick, standard, deep, full"),
    config: str = typer.Option("", "--config", "-c", help="Path to engagement configuration YAML/JSON file"),
    jsonl: bool = typer.Option(False, "--jsonl", help="Stream machine-readable JSONL event stream to stdout"),
    max_iterations: int = typer.Option(25, "--max-iterations", "-n", help="Max autonomous investigation loop iterations"),
    max_runtime: int = typer.Option(1800, "--max-runtime", "-t", help="Max runtime in seconds"),
    concurrency: int = typer.Option(2, "--concurrency", "-w", help="Concurrency level"),
):
    """Execute a fully autonomous headless VAPT assessment against a target."""
    from horcrux.core.headless.config import build_mission_from_config, load_engagement_config
    from horcrux.core.headless.controller import HeadlessMissionController

    cfg_data = {}
    if config:
        cfg_data = load_engagement_config(config)

    overrides = {
        "profile": profile,
        "max_iterations": max_iterations,
        "max_runtime": max_runtime,
        "concurrency": concurrency,
    }

    mission = build_mission_from_config(
        target=target,
        profile=profile,
        config_data=cfg_data,
        execution_overrides=overrides,
    )

    ws = Workspace(mission.target)
    controller = HeadlessMissionController(
        workspace=ws,
        mission=mission,
        stdout_jsonl=jsonl,
    )
    final_mission = controller.run()
    if not jsonl:
        Console().print(f"\n[bold green]✔ Headless mission finished:[/bold green] status={final_mission.status.value} verdict={final_mission.completion_verdict}")


@headless_app.command("status")
def headless_status(
    mission_id_or_target: str = typer.Argument(..., help="Mission ID or target name"),
):
    """Inspect the status and queue metrics of a headless assessment mission."""
    from horcrux.core.headless.controller import HeadlessMissionController
    ws = _resolve_workspace_for_mission(mission_id_or_target)
    st = ws.load()
    m = st.get_mission()
    if not m:
        Console().print(f"[bold red]No headless mission record found for:[/bold red] {mission_id_or_target}")
        raise typer.Exit(code=1)
    ctrl = HeadlessMissionController(ws, m)
    summary = ctrl.status_summary()
    table = Table(
        title=f"[bold bright_magenta]✦ MISSION STATUS: {summary['mission_id']} ✦[/bold bright_magenta]",
        box=box.ROUNDED,
        border_style="magenta",
    )
    table.add_column("Property", style="bold bright_white")
    table.add_column("Value", style="cyan")
    table.add_row("Target", summary["target"])
    table.add_row("Stage", summary["stage"])
    table.add_row("Status", summary["status"])
    table.add_row("Verdict", summary["completion_verdict"])
    table.add_row("Runtime", f"{summary['runtime_seconds']}s")
    table.add_row("Findings Count", str(summary["findings_count"]))
    table.add_row("Exploit Handoffs", str(summary["handoffs_count"]))
    table.add_row(
        "Investigation Queue",
        f"READY: {summary['investigations']['ready']} | "
        f"RUNNING: {summary['investigations']['running']} | "
        f"BLOCKED: {summary['investigations']['blocked']} | "
        f"COMPLETE: {summary['investigations']['complete']}",
    )
    Console().print(table)


@headless_app.command("pause")
def headless_pause(
    mission_id_or_target: str = typer.Argument(..., help="Mission ID or target name"),
):
    """Pause an active headless assessment mission."""
    from horcrux.core.headless.controller import HeadlessMissionController
    ws = _resolve_workspace_for_mission(mission_id_or_target)
    st = ws.load()
    m = st.get_mission()
    if not m:
        Console().print(f"[bold red]No headless mission found for:[/bold red] {mission_id_or_target}")
        raise typer.Exit(code=1)
    ctrl = HeadlessMissionController(ws, m)
    res = ctrl.pause()
    Console().print(f"[bold yellow]✔ Mission {res['mission_id']} paused.[/bold yellow]")


@headless_app.command("resume")
def headless_resume(
    mission_id_or_target: str = typer.Argument(..., help="Mission ID or target name"),
):
    """Resume a paused or interrupted headless assessment mission."""
    from horcrux.core.headless.controller import HeadlessMissionController
    ws = _resolve_workspace_for_mission(mission_id_or_target)
    st = ws.load()
    m = st.get_mission()
    if not m:
        Console().print(f"[bold red]No headless mission found to resume for:[/bold red] {mission_id_or_target}")
        raise typer.Exit(code=1)
    ctrl = HeadlessMissionController(ws, m)
    Console().print(f"[bold green]✔ Resuming headless mission {m.mission_id}...[/bold green]")
    ctrl.resume()


@headless_app.command("abort")
def headless_abort(
    mission_id_or_target: str = typer.Argument(..., help="Mission ID or target name"),
):
    """Abort a headless assessment mission."""
    from horcrux.core.headless.controller import HeadlessMissionController
    ws = _resolve_workspace_for_mission(mission_id_or_target)
    st = ws.load()
    m = st.get_mission()
    if not m:
        Console().print(f"[bold red]No headless mission found to abort for:[/bold red] {mission_id_or_target}")
        raise typer.Exit(code=1)
    ctrl = HeadlessMissionController(ws, m)
    res = ctrl.abort()
    Console().print(f"[bold red]✔ Mission {res['mission_id']} aborted.[/bold red]")


@headless_app.command("attach")
def headless_attach(
    mission_id_or_target: str = typer.Argument(..., help="Mission ID or target name"),
):
    """Attach the interactive operator console to a headless assessment workspace."""
    ws = _resolve_workspace_for_mission(mission_id_or_target)
    st = ws.load()
    m = st.get_mission()
    target_name = m.target if m else ws.target
    Console().print(f"[bold cyan]Attaching interactive console to workspace:[/bold cyan] {target_name}")
    app_inst = ConsoleApp()
    app_inst.workspace = ws
    app_inst.run()


@headless_app.command("export")
def headless_export(
    mission_id_or_target: str = typer.Argument(..., help="Mission ID or target name"),
    format: str = typer.Option("json", "--format", "-f", help="Export format: json or markdown"),
):
    """Export mission state and findings as JSON or Markdown."""
    ws = _resolve_workspace_for_mission(mission_id_or_target)
    st = ws.load()
    m = st.get_mission()
    if not m:
        Console().print(f"[bold red]No mission record found to export for:[/bold red] {mission_id_or_target}")
        raise typer.Exit(code=1)
    if format.lower() in ("md", "markdown"):
        from horcrux.reporting.reports import markdown
        report_path = markdown(ws)
        Console().print(f"[bold green]✔ Report written to:[/bold green] {report_path}")
    else:
        out_file = ws.root / "raw" / "mission-export.json"
        data = {
            "mission": m.model_dump(),
            "findings": [f.model_dump() for f in st.findings],
            "handoffs": [h.model_dump() for h in st.exploit_handoffs],
            "attack_paths": st.attack_paths,
            "false_negative_audit": st.false_negative_audit,
        }
        out_file.write_text(json.dumps(data, default=str, indent=2), encoding="utf-8")
        Console().print(f"[bold green]✔ Mission data exported to:[/bold green] {out_file}")


app.add_typer(headless_app, name="headless")


KNOWN_COMMANDS = {
    "scan", "assess", "headless", "doctor", "tools", "console", "gallery", "artifacts",
    "settings", "report", "ask", "ai", "status", "replay", "benchmark",
    "engines", "--help", "-h", "--version", "-v",
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

