from __future__ import annotations

import sys

import typer
from rich.console import Console

from horcrux import __version__
from horcrux.core.orchestrator import Orchestrator
from horcrux.core.storage import Workspace
from horcrux.ui.ascii import banner
from horcrux.ui.console import ConsoleApp


app = typer.Typer(
    add_completion=False,
    no_args_is_help=False,
    help="HORCRUX offensive-security operator console",
)


@app.callback(invoke_without_command=True)
def root(
    target: str | None = typer.Argument(None),
    deep: bool = typer.Option(False, "--deep"),
    verify: bool = typer.Option(False, "--verify"),
    version: bool = typer.Option(False, "--version"),
):
    if version:
        banner(Console(), __version__, duration=1.0)
        raise typer.Exit()

    if target:
        console = Console()
        banner(console, __version__, duration=.5)
        Orchestrator(
            target,
            Workspace(target),
            console,
        ).scan(deep=deep, verify=verify)


@app.command()
def doctor():
    """Check external tools and wordlists."""
    ConsoleApp().doctor()


@app.command()
def tools():
    """Check external tool availability."""
    ConsoleApp().doctor(only_tools=True)


@app.command()
def console():
    """Open the interactive operator console."""
    ConsoleApp().run()


def main():
    if len(sys.argv) == 1:
        ConsoleApp().run()
    else:
        app()


if __name__ == "__main__":
    main()
