"""Central HORCRUX visual system (terminal-only).

Single source of truth for palette, symbols, text hierarchy, panels, and
width-aware rendering. All CLI/TUI surfaces should build from these tokens
instead of scattering one-off Rich formatting.

Design: restrained dark-terminal palette; color always carries semantics;
labels never rely on color alone.
"""

from __future__ import annotations

import os

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


# ---------------------------------------------------------------------------
# Semantic palette (style names, not raw color soup)
# ---------------------------------------------------------------------------

IDENTITY = "bold bright_magenta"   # HORCRUX wordmark accents
TITLE = "bold bright_white"        # application / panel titles
SECTION = "bold bright_cyan"       # section headings
COMMAND = "bold bright_cyan"       # command names
META = "dim white"                 # metadata, timestamps, hints
METRIC = "bold bright_white"       # metric values
EVIDENCE = "cyan"                  # evidence lines
INFO = "cyan"                      # informational
ACTIVE = "bold bright_cyan"        # running / current
SUCCESS = "bold green"             # completed / confirmed-positive
WARNING = "bold yellow"            # warnings / likely
FAILURE = "bold red"               # errors / failed
BLOCKED = "yellow"                 # blocked / skipped / paused
HYPOTHESIS = "bright_blue"         # hypothesis entities
INVESTIGATION = "bright_cyan"      # investigation entities
CONFIRMED = "bold green"           # confirmed findings
APPROVAL = "bold bright_yellow"    # operator approval required
FAINT = "dim"                      # de-emphasized / queued


# ---------------------------------------------------------------------------
# Symbols (labels always accompany symbols; never color-only semantics)
# ---------------------------------------------------------------------------

OK = "✔"
FAIL = "✖"
WARN = "⚠"
BLOCKED_ICON = "⊘"
ACTIVE_DOT = "●"
QUEUED_DOT = "○"
ARROW_DOWN = "↓"
ARROW_RIGHT = "→"
SPARK = "✦"
BOLT = "⚡"
DIAMOND = "◆"
EDGE_CONFIRMED = "━"
EDGE_INFERRED = "╌"
EDGE_UNVERIFIED = "┄"

STATE_ICON = {
    "COMPLETED": OK,
    "COMPLETE": OK,
    "DONE": OK,
    "SUPPORTED": OK,
    "CONFIRMED": OK,
    "RUNNING": ACTIVE_DOT,
    "ACTIVE": ACTIVE_DOT,
    "CURRENT": ACTIVE_DOT,
    "FAILED": FAIL,
    "REFUTED": FAIL,
    "FALSE_POSITIVE": FAIL,
    "BLOCKED": BLOCKED_ICON,
    "SCOPE_BLOCKED": BLOCKED_ICON,
    "UNAVAILABLE": BLOCKED_ICON,
    "APPROVAL_REQUIRED": WARN,
    "SKIPPED": BLOCKED_ICON,
    "PAUSED": BLOCKED_ICON,
    "QUEUED": QUEUED_DOT,
    "PENDING": QUEUED_DOT,
    "READY": QUEUED_DOT,
    "LIKELY": WARN,
    "POTENTIAL": QUEUED_DOT,
    "UNVERIFIED": "?",
}

STATE_STYLE = {
    "COMPLETED": SUCCESS,
    "COMPLETE": SUCCESS,
    "DONE": SUCCESS,
    "SUPPORTED": SUCCESS,
    "CONFIRMED": CONFIRMED,
    "RUNNING": ACTIVE,
    "ACTIVE": ACTIVE,
    "CURRENT": ACTIVE,
    "FAILED": FAILURE,
    "REFUTED": FAINT,
    "FALSE_POSITIVE": FAINT,
    "BLOCKED": BLOCKED,
    "SCOPE_BLOCKED": BLOCKED,
    "UNAVAILABLE": BLOCKED,
    "APPROVAL_REQUIRED": APPROVAL,
    "SKIPPED": FAINT,
    "PAUSED": BLOCKED,
    "QUEUED": FAINT,
    "PENDING": FAINT,
    "READY": INVESTIGATION,
    "LIKELY": WARNING,
    "POTENTIAL": FAINT,
    "UNVERIFIED": FAINT,
}


def state_badge(state: str) -> str:
    """Icon + label for a state (never color-only)."""
    key = (state or "").upper()
    icon = STATE_ICON.get(key, "•")
    style = STATE_STYLE.get(key, META)
    return f"[{style}]{icon} {key}[/{style}]"


# ---------------------------------------------------------------------------
# Motion / width adaptation
# ---------------------------------------------------------------------------

def animations_enabled() -> bool:
    """Reduced-motion equivalent: env opt-out or dumb terminal."""
    if os.environ.get("HORCRUX_NO_ANIM", "").strip().lower() in {"1", "true", "yes"}:
        return False
    if os.environ.get("NO_COLOR", "").strip():
        return False
    if os.environ.get("TERM", "") == "dumb":
        return False
    return True


def console_width(console: Console | None = None) -> int:
    try:
        if console is not None:
            return max(40, console.size.width)
    except Exception:
        pass
    return 100


def fit(text: str, width: int) -> str:
    """Truncate with ellipsis; never break layout."""
    text = text or ""
    if len(text) <= width:
        return text
    if width <= 4:
        return text[:width]
    return text[: width - 1] + "…"


SUBTLE_SPINNER = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
PHASE_TICK = "▸"


# ---------------------------------------------------------------------------
# Wordmark (spelling source of truth: HORCRUX)
# ---------------------------------------------------------------------------

WORDMARK = "HORCRUX"


def wordmark_text(accent: bool = True) -> Text:
    t = Text()
    t.append("HORCRUX", style=IDENTITY if accent else TITLE)
    return t


def wordmark_block(max_width: int = 100) -> Text | str:
    """Block wordmark for wide terminals; spaced text fallback when narrow.

    Guarantees a readable, correctly-spelled mark at any width.
    """
    if max_width < 72:
        t = Text()
        t.append("H O R C R U X", style=IDENTITY)
        return t
    from horcrux.ui.ascii import render_gradient_text, TITLE
    art = "\n".join(TITLE.split("\n")[:-1])  # block rows only; caption added by caller
    return render_gradient_text(art, palette_name="horcrux", shift=0)


def thin_rule(width: int = 48, label: str = "") -> Text:
    t = Text()
    if label:
        t.append(f"── {label} ", style=META)
        t.append("─" * max(4, width - len(label) - 4), style=META)
    else:
        t.append("─" * width, style=META)
    return t


# ---------------------------------------------------------------------------
# Phase tracker (real state in, honest rendering out)
# ---------------------------------------------------------------------------

def phase_tracker(phases: list[tuple[str, str]], width: int = 100) -> list[str]:
    """Render `[(name, state)]` rows. States: DONE/ACTIVE/QUEUED/SKIPPED/FAILED.

    Returns plain strings with Rich markup (caller prints or embeds).
    """
    lines: list[str] = []
    name_w = max([len(p[0]) for p in phases] + [10])
    name_w = min(name_w, 16)
    for name, state in phases:
        key = (state or "QUEUED").upper()
        if key in {"DONE", "COMPLETED", "COMPLETE"}:
            mark = f"[bold green]{OK}[/bold green]"
            label = f"[green]{name:<{name_w}}[/green]"
            right = "[green]done[/green]"
        elif key == "ACTIVE":
            mark = f"[bold bright_cyan]{ACTIVE_DOT}[/bold bright_cyan]"
            label = f"[bold bright_white]{name:<{name_w}}[/bold bright_white]"
            right = "[bold bright_cyan]active[/bold bright_cyan]"
        elif key == "FAILED":
            mark = f"[bold red]{FAIL}[/bold red]"
            label = f"[red]{name:<{name_w}}[/red]"
            right = "[bold red]failed[/bold red]"
        elif key in {"SKIPPED", "BLOCKED"}:
            mark = f"[yellow]{BLOCKED_ICON}[/yellow]"
            label = f"[dim]{name:<{name_w}}[/dim]"
            right = "[dim]skipped[/dim]"
        else:
            mark = f"[dim]{QUEUED_DOT}[/dim]"
            label = f"[dim]{name:<{name_w}}[/dim]"
            right = ""
        lines.append(f"{mark} {label}  {right}".rstrip())
    return lines


# ---------------------------------------------------------------------------
# Structured cards
# ---------------------------------------------------------------------------

def error_card(what: str, why: str = "", action: str = "", nxt: str = "") -> Panel:
    """WHAT happened / WHY / WHAT HORCRUX did / WHAT happens next."""
    body = Text()
    body.append(f"{FAIL} {what}\n", style=FAILURE)
    if why:
        body.append("Cause: ", style=META)
        body.append(f"{why}\n")
    if action:
        body.append("HORCRUX: ", style=META)
        body.append(f"{action}\n")
    if nxt:
        body.append("Next: ", style=META)
        body.append(f"{nxt}")
    return Panel(body, title="[bold red]ERROR[/bold red]", box=box.ROUNDED,
                 border_style="red", padding=(0, 2))


def warn_card(title: str, lines: list[str]) -> Panel:
    body = Text("\n".join(lines))
    return Panel(body, title=f"[bold yellow]{WARN} {title}[/bold yellow]",
                 box=box.ROUNDED, border_style="yellow", padding=(0, 2))


def tool_card(tool: str, status: str, result: str = "",
              evidence: str = "") -> Panel:
    """Semantic tool summary — never raw subprocess output."""
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="dim white", justify="right", no_wrap=True)
    grid.add_column(style="bright_white", justify="left")
    grid.add_row("TOOL", f"[bold bright_cyan]{tool}[/bold bright_cyan]")
    grid.add_row("STATUS", status)
    if result:
        grid.add_row("RESULT", result)
    if evidence:
        grid.add_row("EVIDENCE", f"[cyan]{evidence}[/cyan]")
    return Panel(grid, box=box.ROUNDED, border_style="cyan", padding=(0, 2))


def kv_panel(title: str, rows: list[tuple[str, str]],
             border_style: str = "magenta") -> Panel:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="dim white", justify="right", no_wrap=True)
    grid.add_column(style="bright_white", justify="left")
    for key, value in rows:
        grid.add_row(key, value)
    return Panel(grid, title=title, box=box.ROUNDED,
                 border_style=border_style, padding=(0, 2))


def finding_header(title: str, validation: str, severity: str = "",
                   confidence: float | None = None) -> Text:
    """Label + layout per validation state (never color-only)."""
    key = (validation or "").upper()
    tag = {
        "CONFIRMED": ("CONFIRMED", CONFIRMED),
        "LIKELY": ("LIKELY", WARNING),
        "POTENTIAL": ("POTENTIAL", FAINT),
        "UNVERIFIED": ("UNVERIFIED", FAINT),
        "FALSE_POSITIVE": ("FALSE POSITIVE", FAINT),
    }.get(key, (key or "UNKNOWN", META))
    t = Text()
    t.append(f"[{tag[0]}] ", style=tag[1])
    if severity:
        t.append(f"{severity.upper()} ", style=TITLE)
    t.append(title, style=TITLE)
    if confidence is not None:
        t.append(f"  ({confidence:.0%})", style=META)
    return t


def attack_tree(name: str, nodes: list[str],
                edges: list[tuple[str, str]]) -> list[str]:
    """Readable vertical tree. edges: [(relation, kind)] where kind is
    confirmed|evidenced|observed|inferred|unverified."""
    lines = [f"[bold bright_white]{name}[/bold bright_white]"]
    for idx, node in enumerate(nodes):
        lines.append(f"  [dim]{ARROW_DOWN}[/dim]")
        lines.append(f"  [bright_white]{node}[/bright_white]")
        if idx < len(edges):
            relation, kind = edges[idx]
            if kind in ("confirmed", "evidenced"):
                mark = f"[green]{EDGE_CONFIRMED * 2} {relation} (evidenced)[/green]"
            elif kind == "inferred":
                mark = f"[yellow]{EDGE_INFERRED * 2} {relation} (inferred)[/yellow]"
            elif kind == "observed":
                mark = f"[dim]{EDGE_UNVERIFIED * 2} {relation} (observed)[/dim]"
            else:
                mark = f"[dim]{EDGE_UNVERIFIED * 2} {relation} (unverified)[/dim]"
            lines.append(f"  {mark}")
    return lines


def investigation_steps(steps: list[tuple[str, str]]) -> list[str]:
    """Step ladder with ↓ transitions; states: DONE/ACTIVE/QUEUED/FAILED."""
    lines: list[str] = []
    for idx, (label, state) in enumerate(steps):
        key = (state or "QUEUED").upper()
        icon = STATE_ICON.get(key, QUEUED_DOT)
        style = STATE_STYLE.get(key, FAINT)
        lines.append(f"  [{style}]{icon}[/{style}] [{style}]{label}[/{style}]")
        if idx < len(steps) - 1:
            lines.append(f"  [dim]{ARROW_DOWN}[/dim]")
    return lines
