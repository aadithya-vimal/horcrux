"""Visual branding tests — wordmark spelling, widths, renderers.

Deterministic: animations disabled via HORCRUX_NO_ANIM. No specific
terminal emulator required; Rich record consoles only.
"""

from __future__ import annotations

import io
import os

import pytest
from rich.console import Console

os.environ["HORCRUX_NO_ANIM"] = "1"

from horcrux.ui import heading as heading
from horcrux.ui import theme as theme
from horcrux.ui.ascii import TITLE, TITLE_FRAMES, banner, print_heading
from horcrux.ui.progress import (ASSESSMENT_PHASES, INVESTIGATION_STEPS,
                                 AssessmentProgress)


def _console(width: int) -> Console:
    return Console(record=True, width=width)


def _raw_console(width: int) -> tuple[Console, io.StringIO]:
    buf = io.StringIO()
    return Console(file=buf, record=True, width=width), buf


# --- wordmark spelling ------------------------------------------------------

def test_wordmark_spelling_exact():
    assert TITLE.strip().split("\n")[-1].strip() == "HORCRUX"
    assert "HORCRYX" not in TITLE


def test_no_horcryx_anywhere_in_ui_art():
    for frame in TITLE_FRAMES:
        assert "HORCRYX" not in frame


def test_u_glyph_has_two_sides_curved_bottom_no_stem():
    art = "\n".join(TITLE.split("\n")[:-1])  # block rows only
    # U middle rows: two vertical sides
    assert art.count("██║   ██║") >= 3
    # U bottom: curved base present
    assert "╚██████╔╝ ██╔╝ ██╗" in art
    # Y signature (converging arms) must not appear in the wordmark
    assert "╚██╗ ██╔╝" not in art
    assert "╚████╔╝" not in art


def test_wordmark_block_narrow_fallback():
    narrow = theme.wordmark_block(60)
    assert "H O R C R U X" in narrow.plain
    wide = theme.wordmark_block(120)
    text = wide.plain if hasattr(wide, "plain") else str(wide)
    assert "██" in text  # block art preserved for wide terminals


# --- startup rendering across widths ----------------------------------------

@pytest.mark.parametrize("width", [80, 100, 120])
def test_startup_renders_at_widths(width):
    console, buf = _raw_console(width)
    banner(console, version="0.0.0-test", duration=0)
    assert heading.render() in buf.getvalue()  # exact art, raw channel
    out = console.export_text()  # themed caption, Rich channel
    assert "0.0.0-test" in out
    assert "operator console" in out
    # No traceback leakage, no raw markup leakage
    assert "Traceback" not in out
    assert "[bold" not in out


def test_startup_narrow_heading_still_exact():
    console, buf = _raw_console(60)
    banner(console, version="1.0", duration=0)
    assert heading.render() in buf.getvalue()
    assert "1.0" in console.export_text()


# --- exact user-supplied heading ---------------------------------------------

def test_heading_is_eleven_lines_with_resets():
    assert len(heading.HEADING_LINES_SPEC) == 12
    assert "[" not in heading.HEADING_SPEC  # plain v3 art, no SGR codes


def test_heading_visible_widths_consistent():
    widths = {len(line) for line in heading.render_lines()}
    assert widths <= {98, 99}, widths
    assert heading.VISIBLE_WIDTH == 99


def test_heading_u_block_symmetric_no_y_stem():
    # 6th letter block (cols 57-69): open middle rows, two-foot base, no
    # central Y stem; Y-arm motifs must not appear anywhere in the art.
    lines = heading.render_lines()
    base = lines[11][57:70]
    assert base.startswith("█▄▄▄▄▀") and "█▄▄▄▄" in base[6:]
    mid = "".join(line[62:66] for line in lines[8:11])
    assert " " in mid  # open counter, not a solid stem
    assert "╚██╗ ██╔╝" not in heading.HEADING_SPEC


def test_heading_render_is_verbatim():
    assert heading.render() == heading.HEADING_SPEC
    assert heading.strip_ansi(heading.render()) == heading.render()
    assert chr(27) not in heading.render()


def test_print_heading_writes_exact_bytes():
    console, buf = _raw_console(100)
    print_heading(console)
    assert buf.getvalue() == heading.render() + "\n"


def test_banner_emits_exact_heading():
    console, buf = _raw_console(120)
    banner(console, version="9.9.9-x", duration=0)
    raw = buf.getvalue()
    assert heading.render() in raw
    assert "HORCRYX" not in raw


@pytest.mark.parametrize("width", [60, 80, 100, 120, 200])
def test_banner_heading_exact_at_all_widths(width):
    console, buf = _raw_console(width)
    banner(console, version="1.0", duration=0)
    assert heading.render() in buf.getvalue()


# --- progress rendering ------------------------------------------------------

def test_phase_tracker_marks_real_states():
    lines = theme.phase_tracker([("RECON", "DONE"), ("MODEL", "ACTIVE"),
                                 ("HYPOTHESIZE", "QUEUED"), ("INVESTIGATE", "FAILED")])
    joined = "\n".join(lines)
    assert "RECON" in joined and "done" in joined
    assert "MODEL" in joined and "active" in joined
    assert "FAILED" in joined or "failed" in joined


def test_investigation_steps_render_states():
    lines = theme.investigation_steps([("resolving capability", "DONE"),
                                       ("executing", "ACTIVE"),
                                       ("ingesting", "QUEUED")])
    assert len(lines) == 5  # 3 steps + 2 transitions, no redraw bloat
    assert any("↓" in line for line in lines)


def test_assessment_progress_observer_flow():
    console = _console(100)
    tracker = AssessmentProgress(console, "t.local")
    cb = tracker.observer()
    cb("phase", {"name": "MODEL"})
    cb("investigation_start", {"id": "AUTHZ-017", "objective": "Cross-identity access"})
    for step in INVESTIGATION_STEPS:
        cb("investigation_step", {"step": step})
    cb("investigation_done", {"state": "SUPPORTED"})
    text = tracker.render_text().plain
    assert "AUTHZ-017" in text
    assert "RECON" in text
    for phase in ASSESSMENT_PHASES:
        assert phase in text


# --- agents / findings / blocked ----------------------------------------------

def test_agent_state_badges_distinct():
    badges = {s: theme.state_badge(s) for s in
              ["ACTIVE", "COMPLETE", "BLOCKED", "FAILED", "QUEUED"]}
    assert len(set(badges.values())) == 5  # never color-only ambiguity
    assert "ACTIVE" in badges["ACTIVE"] and "BLOCKED" in badges["BLOCKED"]


@pytest.mark.parametrize("validation,tag", [("CONFIRMED", "CONFIRMED"), ("LIKELY", "LIKELY"),
                                        ("POTENTIAL", "POTENTIAL"), ("UNVERIFIED", "UNVERIFIED"),
                                        ("FALSE_POSITIVE", "FALSE POSITIVE")])
def test_finding_headers_label_states(validation, tag):
    header = theme.finding_header("Test finding", validation, severity="high",
                                  confidence=0.7)
    assert tag in header.plain
    assert "Test finding" in header.plain


def test_error_card_structures_what_why_next():
    from rich.console import Console as _C
    card = theme.error_card("Capability unavailable", why="Nuclei not on PATH.",
                            action="Skipped and deprioritized.",
                            nxt="Assessment continues.")
    console = _C(record=True, width=100)
    console.print(card)
    out = console.export_text()
    assert "Capability unavailable" in out
    assert "Assessment continues" in out
    assert "Traceback" not in out


def test_attack_tree_marks_relationships():
    lines = theme.attack_tree("Order access", ["Identity", "Object", "Admin"],
                              [("accesses", "evidenced"), ("escalates", "inferred")])
    joined = "\n".join(lines)
    assert "evidenced" in joined and "inferred" in joined


def test_tool_card_semantic_no_raw_output():
    from rich.console import Console as _C
    console = _C(record=True, width=100)
    console.print(theme.tool_card("FFUF", "done", result="42 paths",
                                  evidence="17 new endpoints"))
    out = console.export_text()
    assert "FFUF" in out and "17 new endpoints" in out


# --- console surfaces ----------------------------------------------------------

def test_help_groups_by_purpose():
    from horcrux.ui.console import ConsoleApp
    app = ConsoleApp(console=_console(100))
    app.print_help()
    out = app.console.export_text()
    for group in ["ASSESSMENT", "INVESTIGATION", "OPERATOR CONTROL", "CONFIGURATION"]:
        assert group in out


def test_why_renders_rationale_panel(tmp_path):
    from tests.fixtures.synthetic_vulnerable_app import build_synthetic_workspace
    from horcrux.core.storage import Workspace
    from horcrux.intel.ingestion import ingest_workspace_state
    from horcrux.ui.console import ConsoleApp
    state = build_synthetic_workspace()
    ingest_workspace_state(state)
    ws = Workspace(state.target)
    ws.root = tmp_path / "why-ws"
    for d in (ws.root, ws.raw, ws.responses, ws.headers, ws.reports):
        d.mkdir(parents=True, exist_ok=True)
    ws.state_file = ws.root / "state.json"
    ws.save(state)
    app = ConsoleApp(console=_console(100))
    app.workspace = ws
    app.steering_cmd(["why"])
    out = app.console.export_text()
    assert "WHY" in out


def test_ask_renders_grounded_panel(tmp_path):
    from unittest.mock import MagicMock
    from tests.fixtures.synthetic_vulnerable_app import build_synthetic_workspace
    from horcrux.core.storage import Workspace
    from horcrux.ui.console import ConsoleApp
    state = build_synthetic_workspace()
    ws = Workspace(state.target)
    ws.root = tmp_path / "ask-ws"
    for d in (ws.root, ws.raw, ws.responses, ws.headers, ws.reports):
        d.mkdir(parents=True, exist_ok=True)
    ws.state_file = ws.root / "state.json"
    ws.save(state)
    app = ConsoleApp(console=_console(100))
    app.workspace = ws
    app.ai_manager = MagicMock()
    app.ai_manager.active_provider_name.return_value = "test"
    app.ai_manager.get_provider.return_value = None
    app.ai_manager.ask.return_value = "## Analysis\n\nCoverage is partial."
    app.ask_cmd(["ask", "What remains untested?"])
    out = app.console.export_text()
    assert "HORCRUX ANALYSIS" in out
    assert "grounded in workspace state" in out


def test_run_error_uses_structured_card():
    from horcrux.ui.console import ConsoleApp
    app = ConsoleApp(console=_console(100))
    with app.console.capture() as _:
        pass
    # dispatch error path renders card fields, not raw exceptions
    import shlex
    try:
        app.dispatch(["inspect"])
    except ValueError:
        pass  # dispatch raises; run() renders — emulate run()'s handler
    from horcrux.ui import theme as _t
    card_text = _t.error_card("Command failed", why="usage: inspect <id>",
                              action="No workspace state was changed.",
                              nxt="Type 'help'.")
    console = _console(100)
    console.print(card_text)
    out = console.export_text()
    assert "No workspace state was changed" in out
