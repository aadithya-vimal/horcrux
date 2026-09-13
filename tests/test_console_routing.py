from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch

from horcrux.ui.console import ConsoleApp


def test_global_commands_work_without_workspace():
    """Verify that all global commands dispatch without raising workspace-required error."""
    app = ConsoleApp()
    assert app.workspace is None

    # settings overview
    with patch.object(app, "settings_cmd") as mock_settings:
        app.dispatch(["settings"])
        mock_settings.assert_called_once_with(["settings"])

    # settings status
    with patch.object(app, "settings_cmd") as mock_settings:
        app.dispatch(["settings", "status"])
        mock_settings.assert_called_once_with(["settings", "status"])

    # settings test
    with patch.object(app, "settings_cmd") as mock_settings:
        app.dispatch(["settings", "test"])
        mock_settings.assert_called_once_with(["settings", "test"])

    # ai / ai status / ai providers
    with patch.object(app, "ai_cmd") as mock_ai:
        app.dispatch(["ai"])
        mock_ai.assert_called_once_with(["ai"])

    with patch.object(app, "ai_cmd") as mock_ai:
        app.dispatch(["ai", "providers"])
        mock_ai.assert_called_once_with(["ai", "providers"])

    # version
    with patch("horcrux.ui.console.banner"):
        app.dispatch(["version"])

    # doctor and tools
    with patch.object(app, "doctor") as mock_doc:
        app.dispatch(["doctor"])
        mock_doc.assert_called_once_with()

    with patch.object(app, "doctor") as mock_doc:
        app.dispatch(["tools"])
        mock_doc.assert_called_once_with(only_tools=True)

    # ask without workspace
    with patch.object(app, "ask_cmd") as mock_ask:
        app.dispatch(["ask", "Explain", "CSRF"])
        mock_ask.assert_called_once_with(["ask", "Explain", "CSRF"])


def test_colon_prefix_stripping():
    """Verify that leading colons or slashes (e.g. : settings) are stripped cleanly."""
    app = ConsoleApp()
    assert app.workspace is None

    with patch.object(app, "settings_cmd") as mock_settings:
        # ": settings" split into [":", "settings"]
        app.dispatch([":", "settings"])
        mock_settings.assert_called_once_with(["settings"])

    with patch.object(app, "settings_cmd") as mock_settings:
        # ":settings"
        app.dispatch([":settings"])
        mock_settings.assert_called_once_with(["settings"])

    with patch.object(app, "ai_cmd") as mock_ai:
        # "/ai"
        app.dispatch(["/ai", "status"])
        mock_ai.assert_called_once_with(["ai", "status"])


def test_workspace_commands_require_workspace():
    """Verify that target-specific commands strictly fail when no workspace is loaded."""
    app = ConsoleApp()
    assert app.workspace is None

    workspace_commands = [
        "surface",
        "services",
        "software",
        "audit",
        "findings",
        "inspect",
        "next",
        "creds",
        "graph",
        "web",
        "intel",
        "report",
        "status",
    ]

    for cmd in workspace_commands:
        with pytest.raises(ValueError, match="no workspace loaded; run 'scan <target>' first"):
            app.dispatch([cmd])
