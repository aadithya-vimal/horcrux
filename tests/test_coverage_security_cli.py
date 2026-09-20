"""Tests for the security coverage CLI command (Phase J)."""

from typer.testing import CliRunner
from horcrux.cli import app
from horcrux.core.storage import Workspace
from horcrux.intel.application_model import SemanticEndpoint
from horcrux.models import WorkspaceState

runner = CliRunner()


def test_coverage_security_cli_renders_table():
    target = "test-cov-cli.local"
    ws = Workspace(target)
    state = WorkspaceState(target=target)
    app_model = state.get_application_model()
    app_model.endpoints.append(
        SemanticEndpoint(path="/api/Products/1", method="GET")
    )
    state.set_application_model(app_model)
    ws.save(state)

    try:
        result = runner.invoke(app, ["coverage", "security", target])
        assert result.exit_code == 0
        assert "SECURITY CONTROL & TEST MATRIX COVERAGE" in result.output
        assert "Attack Surface Elements Mapped" in result.output
        assert "TOTAL DERIVED TESTS" in result.output
        assert "INVARIANT" in result.output
    finally:
        # Cleanup test workspace
        import shutil
        if ws.root.exists():
            shutil.rmtree(ws.root, ignore_errors=True)
