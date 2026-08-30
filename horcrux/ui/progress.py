from __future__ import annotations

import sys
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from rich import box
from rich.align import Align
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from horcrux.ui.ascii import render_gradient_text


class StageState(str, Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    SKIPPED = "SKIPPED"
    FAILED = "FAILED"


@dataclass
class ScanStage:
    key: str
    name: str
    state: StageState = StageState.QUEUED
    started_at: Optional[float] = None
    ended_at: Optional[float] = None
    progress_pct: Optional[float] = None  # Only when tool provides genuine progress
    current_command: str = ""
    error_message: str = ""

    @property
    def elapsed(self) -> float:
        if self.started_at is None:
            return 0.0
        end = self.ended_at or time.monotonic()
        return max(0.0, end - self.started_at)


class ScanProgressManager:
    """
    Operator-grade Metasploit-style live scan console renderer.
    Renders actual subprocess state, true elapsed times, active executables,
    and stage lifecycle (queued / running / completed / skipped / failed)
    without dumping noisy tool output into the terminal.
    """

    DEFAULT_STAGES = [
        ("reachability", "Target validation"),
        ("ports", "Port discovery"),
        ("services", "Service identification"),
        ("enumeration", "Service-specific enumeration"),
        ("validation", "Evidence validation"),
        ("intel", "Vulnerability / CVE correlation"),
        ("synthesis", "Attack surface synthesis"),
    ]

    def __init__(self, console: Console, target: str, profile_name: str = "standard"):
        self.console = console
        self.target = target
        self.profile_name = profile_name
        self.start_time = time.monotonic()

        self.stages: dict[str, ScanStage] = {
            key: ScanStage(key=key, name=name)
            for key, name in self.DEFAULT_STAGES
        }

        self.active_tool: str = ""
        self.active_args: list[str] = []
        self.active_tool_start: Optional[float] = None
        self.total_tools_executed = 0

        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._live: Optional[Live] = None
        self._spinner_idx = 0

        # Metasploit-style spinner frames & arcane runes
        self._pulse_frames = [
            "[*       ]",
            "[**      ]",
            "[***     ]",
            "[ ***    ]",
            "[  ***   ]",
            "[   ***  ]",
            "[    *** ]",
            "[     ***]",
            "[      **]",
            "[       *]",
            "[        ]",
        ]
        self._sparks = ["✦", "✧", "✶", "✷", "✸", "✹", "✺", "✵"]

    def __enter__(self) -> "ScanProgressManager":
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop()

    def start(self) -> None:
        with self._lock:
            if self._running:
                return
            self._running = True
            self.start_time = time.monotonic()
            self._live = Live(
                console=self.console,
                refresh_per_second=12,
                transient=True,
                auto_refresh=False,
            )
            self._live.start()
            self._thread = threading.Thread(target=self._render_loop, daemon=True)
            self._thread.start()

    def stop(self) -> None:
        with self._lock:
            if not self._running:
                return
            self._running = False

        if self._thread:
            self._thread.join(timeout=1.0)
            self._thread = None

        if self._live:
            try:
                self._live.stop()
            except Exception:
                pass
            self._live = None

    def start_stage(self, key: str) -> None:
        with self._lock:
            if key in self.stages:
                stage = self.stages[key]
                stage.state = StageState.RUNNING
                stage.started_at = time.monotonic()

    def complete_stage(self, key: str) -> None:
        with self._lock:
            if key in self.stages:
                stage = self.stages[key]
                stage.state = StageState.COMPLETED
                stage.ended_at = time.monotonic()
                stage.progress_pct = 100.0

    def skip_stage(self, key: str, reason: str = "") -> None:
        with self._lock:
            if key in self.stages:
                stage = self.stages[key]
                stage.state = StageState.SKIPPED
                stage.error_message = reason

    def fail_stage(self, key: str, error: str) -> None:
        with self._lock:
            if key in self.stages:
                stage = self.stages[key]
                stage.state = StageState.FAILED
                stage.ended_at = time.monotonic()
                stage.error_message = error

    def update_stage_progress(self, key: str, progress_pct: float) -> None:
        with self._lock:
            if key in self.stages:
                self.stages[key].progress_pct = max(0.0, min(100.0, progress_pct))

    def on_command_start(self, args: list[str]) -> None:
        """Invoked by CommandRunner in real time when a subprocess launches."""
        with self._lock:
            self.active_args = args
            self.active_tool = args[0] if args else ""
            self.active_tool_start = time.monotonic()
            self.total_tools_executed += 1

    def on_command_finish(self, args: list[str], returncode: int) -> None:
        """Invoked by CommandRunner when a subprocess terminates."""
        with self._lock:
            self.active_tool = ""
            self.active_args = []
            self.active_tool_start = None

    def _format_time(self, seconds: float) -> str:
        mins, secs = divmod(int(seconds), 60)
        return f"{mins:02d}:{secs:02d}"

    def _render_loop(self) -> None:
        while self._running:
            try:
                renderable = self._build_display()
                if self._live:
                    self._live.update(renderable, refresh=True)
            except Exception:
                pass
            self._spinner_idx += 1
            time.sleep(0.08)

    def _build_display(self) -> Group:
        with self._lock:
            now = time.monotonic()
            total_elapsed = self._format_time(now - self.start_time)
            pulse = self._pulse_frames[self._spinner_idx % len(self._pulse_frames)]
            spark = self._sparks[self._spinner_idx % len(self._sparks)]

            # Build stage items table
            table = Table(
                box=box.MINIMAL,
                show_header=False,
                padding=(0, 1),
                expand=True,
            )
            table.add_column("Indicator", justify="left", width=16, no_wrap=True)
            table.add_column("Stage", justify="left", style="bold bright_white")
            table.add_column("Status", justify="right", width=14, no_wrap=True)
            table.add_column("Elapsed", justify="right", width=8, style="dim cyan", no_wrap=True)

            for key, stage in self.stages.items():
                elapsed_str = self._format_time(stage.elapsed) if stage.started_at else "--:--"

                if stage.state == StageState.COMPLETED:
                    indicator = "[bold green][■■■■■■■■■■][/bold green]"
                    status_text = "[bold green]✔ DONE[/bold green]"
                    stage_name = f"[dim white]{stage.name}[/dim white]"
                elif stage.state == StageState.RUNNING:
                    # Animate running block bar or show real percentage if available
                    if stage.progress_pct is not None:
                        pct = int(stage.progress_pct / 10)
                        bar = "■" * pct + "□" * (10 - pct)
                        indicator = f"[bold bright_magenta][{bar}][/bold bright_magenta]"
                        status_text = f"[bold bright_yellow]{int(stage.progress_pct)}%[/bold bright_yellow]"
                    else:
                        # Moving block animation
                        pos = (self._spinner_idx // 2) % 10
                        bar_chars = ["□"] * 10
                        bar_chars[pos] = "■"
                        bar = "".join(bar_chars)
                        indicator = f"[bold bright_cyan][{bar}][/bold bright_cyan]"
                        status_text = f"[bold bright_cyan]{pulse}[/bold bright_cyan]"
                    stage_name = f"[bold bright_white]{stage.name}[/bold bright_white]"
                elif stage.state == StageState.SKIPPED:
                    indicator = "[dim][          ][/dim]"
                    status_text = "[dim yellow]⊘ SKIPPED[/dim yellow]"
                    stage_name = f"[dim]{stage.name}[/dim]"
                elif stage.state == StageState.FAILED:
                    indicator = "[bold red][ ✖ FAILED ][/bold red]"
                    status_text = "[bold red]✖ FAILED[/bold red]"
                    stage_name = f"[bold red]{stage.name}[/bold red]"
                else:  # QUEUED
                    indicator = "[dim][          ][/dim]"
                    status_text = "[dim]QUEUED[/dim]"
                    stage_name = f"[dim]{stage.name}[/dim]"

                table.add_row(indicator, stage_name, status_text, elapsed_str)

            # Subprocess Info Box
            sub_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1), expand=True)
            sub_table.add_column("Label", style="bold dim magenta", width=12)
            sub_table.add_column("Value", style="bright_white")

            sub_table.add_row("Target", f"[bold bright_cyan]{self.target}[/bold bright_cyan]")
            sub_table.add_row("Profile", f"[bold bright_yellow]{self.profile_name.upper()}[/bold bright_yellow]")

            if self.active_tool:
                cmd_summary = " ".join(self.active_args)
                if len(cmd_summary) > 75:
                    cmd_summary = cmd_summary[:72] + "..."
                tool_elapsed = self._format_time(now - (self.active_tool_start or now))
                sub_table.add_row("Running", f"[bold bright_green]{self.active_tool}[/bold bright_green] [dim]({tool_elapsed})[/dim]")
                sub_table.add_row("Command", f"[italic cyan]{cmd_summary}[/italic cyan]")
            else:
                sub_table.add_row("Running", "[dim italic]Idle / Analyzing evidence...[/dim italic]")

            sub_table.add_row("Total Time", f"[bold bright_cyan]{total_elapsed}[/bold bright_cyan]")

            panel = Panel(
                Group(
                    Align.center(
                        Text.assemble(
                            (f"  {spark}  ", "bold bright_magenta"),
                            ("HORCRUX RECONNAISSANCE ENGINE", "bold bright_white"),
                            (f"  {spark}  ", "bold bright_cyan"),
                        )
                    ),
                    Text(""),
                    table,
                    Text(""),
                    sub_table,
                ),
                title=f"[bold bright_magenta]✦ HORCRUX SCANNER • METASPLOIT-STYLE REALTIME MONITOR ✦[/bold bright_magenta]",
                subtitle=f"[dim]Subprocess stdout captured cleanly to workspace • Press Ctrl+C to abort[/dim]",
                box=box.ROUNDED,
                border_style="magenta",
                padding=(0, 1),
            )

            return Group(panel)
