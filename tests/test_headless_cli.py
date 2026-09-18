"""Tests for CLI headless commands."""

from __future__ import annotations

from pathlib import Path
from typer.testing import CliRunner

from horcrux.cli import app
from horcrux.core.storage import Workspace
from tests.fixtures.synthetic_vulnerable_app import build_synthetic_workspace

runner = CliRunner()


def test_headless_help():
    result = runner.invoke(app, ["headless", "--help"])
    assert result.exit_code == 0
    assert "scan" in result.output
    assert "status" in result.output
    assert "pause" in result.output
    assert "resume" in result.output
    assert "abort" in result.output


def test_headless_status_no_mission():
    result = runner.invoke(app, ["headless", "status", "non_existent_target_xyz_123"])
    assert result.exit_code != 0
    assert "No headless mission" in result.output or "not found" in result.output


def test_headless_scan_synthetic_and_export(tmp_path: Path):
    target = "cli-test.local"
    ws = Workspace(target)
    ws.save(build_synthetic_workspace())

    # Run headless scan with max-iterations=2 for fast execution
    result = runner.invoke(app, [
        "headless", "scan", target,
        "--max-iterations", "2",
        "--max-runtime", "30",
    ])
    assert result.exit_code == 0
    assert "Headless mission finished" in result.output

    # Test status command
    status_res = runner.invoke(app, ["headless", "status", target])
    assert status_res.exit_code == 0
    assert "MISSION STATUS" in status_res.output

    # Test export command
    export_res = runner.invoke(app, ["headless", "export", target, "--format", "json"])
    assert export_res.exit_code == 0
    assert "Mission data exported" in export_res.output
