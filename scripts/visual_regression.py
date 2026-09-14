"""Visual regression sweep: render representative flows at 80/100/120 cols.

Synthetic workspace only. Dumps plain-text snapshots to regression_out/
for inspection (checked for overflow, broken glyphs, hierarchy).
The exact HORCRUX heading bypasses Rich recording (raw channel), so it is
captured separately and checked byte-for-byte.
"""

from __future__ import annotations

import io
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

os.environ["HORCRUX_NO_ANIM"] = "1"

from rich.console import Console

from horcrux.core.storage import Workspace
from horcrux.agents.lifecycle import reassess
from horcrux.intel.ingestion import ingest_workspace_state
from horcrux.ui import heading as heading_mod
from horcrux.ui.ascii import banner
from horcrux.ui.console import ConsoleApp
from horcrux.ui.progress import AssessmentProgress, INVESTIGATION_STEPS
from tests.fixtures.synthetic_vulnerable_app import build_synthetic_workspace

OUT = Path("regression_out")
WIDTHS = [80, 100, 120]


def make_workspace(tmp: Path) -> Workspace:
    state = build_synthetic_workspace()
    ingest_workspace_state(state)
    ws = Workspace(state.target)
    ws.root = tmp / "regress-ws"
    for d in (ws.root, ws.raw, ws.responses, ws.headers, ws.reports):
        d.mkdir(parents=True, exist_ok=True)
    ws.state_file = ws.root / "state.json"
    ws.save(state)
    return ws


def run_flow(width: int, tmp: Path) -> str:
    console = Console(record=True, width=width)
    raw_buf = io.StringIO()
    raw_console = Console(file=raw_buf, width=width)
    app = ConsoleApp(console=console)
    ws = make_workspace(tmp / f"w{width}")
    app.workspace = ws

    console.print(f"===== FLOW: startup ({width}) =====")
    banner(raw_console, version="9.9.9-reg", duration=0)
    raw_heading = raw_buf.getvalue()
    assert heading_mod.render() + "\n" in raw_heading, "exact heading missing"
    console.print("[exact heading emitted on raw channel: "
                  f"{len(raw_heading)} bytes, "
                  f"{raw_heading.count(chr(27))} escapes]")
    # Human-readable copy (SGR stripped) for snapshot inspection.
    # Exempt from the width check: the heading is mandated byte-exact.
    console.print("[[HEADING-SNAPSHOT-BEGIN]]")
    console.print(heading_mod.strip_ansi(heading_mod.render()))
    console.print("[[HEADING-SNAPSHOT-END]]")

    console.print(f"===== FLOW: help ({width}) =====")
    app.print_help()

    console.print(f"===== FLOW: status ({width}) =====")
    app.status()

    console.print(f"===== FLOW: findings ({width}) =====")
    app.findings()

    console.print(f"===== FLOW: graph ({width}) =====")
    app.graph()

    console.print(f"===== FLOW: tracker ({width}) =====")
    tracker = AssessmentProgress(console, ws.target)
    cb = tracker.observer()
    cb("phase", {"name": "INVESTIGATE"})
    cb("investigation_start", {"id": "AUTHZ-017",
                               "objective": "Cross-identity object access comparison"})
    cb("investigation_step", {"step": INVESTIGATION_STEPS[1]})
    console.print(tracker.render_text())

    console.print(f"===== FLOW: why ({width}) =====")
    app.steering_cmd(["why"])

    console.print(f"===== FLOW: ask ({width}) =====")
    app.ai_manager = MagicMock()
    app.ai_manager.active_provider_name.return_value = "test"
    app.ai_manager.get_provider.return_value = None
    app.ai_manager.ask.return_value = (
        "## Analysis\n\nAuthorization coverage: 46%\n\n"
        "Recommended investigation: AUTHZ-017")
    app.ask_cmd(["ask", "What remains untested?"])

    console.print(f"===== FLOW: pause/resume ({width}) =====")
    app.steering_cmd(["pause"])
    app.steering_cmd(["resume"])

    console.print(f"===== FLOW: error ({width}) =====")
    try:
        app.dispatch(["inspect"])
    except ValueError as exc:
        from horcrux.ui import theme as _theme
        console.print(_theme.error_card("Command failed", why=str(exc),
                                        action="No workspace state was changed.",
                                        nxt="Type 'help'."))

    return console.export_text()


def main() -> None:
    import tempfile
    OUT.mkdir(exist_ok=True)
    issues: list[str] = []
    for width in WIDTHS:
        with tempfile.TemporaryDirectory() as tmp:
            text = run_flow(width, Path(tmp))
        (OUT / f"flow-{width}.txt").write_text(text, encoding="utf-8")
        in_heading = False
        for i, line in enumerate(text.split("\n")):
            if "[[HEADING-SNAPSHOT-BEGIN]]" in line:
                in_heading = True
                continue
            if "[[HEADING-SNAPSHOT-END]]" in line:
                in_heading = False
                continue
            if in_heading:
                continue  # exact heading exempt from width checks by mandate
            # overflow: visible chars beyond width (allow 2 for safety)
            if len(line) > width + 2:
                issues.append(f"width={width} line={i} len={len(line)}: {line[:60]!r}")
        for bad in ("HORCRYX", "Traceback", "[bold", "�"):
            if bad in text:
                issues.append(f"width={width}: found {bad!r}")
        if "HORCRUX" not in text:
            issues.append(f"width={width}: wordmark missing")
    print("snapshot lines:", sum(1 for _ in OUT.glob("*.txt")))
    if issues:
        print("ISSUES:")
        for issue in issues[:30]:
            print(" -", issue)
        sys.exit(1)
    print("regression clean")


if __name__ == "__main__":
    main()
