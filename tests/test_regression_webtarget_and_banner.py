from __future__ import annotations

from unittest.mock import MagicMock, patch
import pytest
from rich.console import Console

from horcrux.core.actions import compute_next_actions
from horcrux.core.orchestrator import Orchestrator
from horcrux.core.storage import Workspace
from horcrux.models import (
    ModuleDecision,
    ScanProfile,
    Service,
    SubsystemState,
    WebApplicationType,
    WebTarget,
)
from horcrux.ui.console import ConsoleApp


def test_webtarget_scan_pipeline(tmp_path):
    target = '127.0.0.1'
    ws = Workspace(target, base=str(tmp_path))

    http_service = Service(host=target, port=80, protocol='tcp', service='http')
    ws.upsert_services([http_service])

    console = Console(record=True)
    orchestrator = Orchestrator(target, ws, console, profile='quick')

    with patch('horcrux.core.orchestrator.run_network', return_value=([http_service], [])):
        with patch('horcrux.core.orchestrator.scan_http', return_value=([], [], ['nginx'])):
            with patch('horcrux.core.orchestrator.run_fingerprinting', return_value=(['nginx'], [])):
                orchestrator.scan()

    state = ws.load()
    assert len(state.web_targets) > 0
    web_target = state.get_web_target(80)
    assert web_target is not None
    assert web_target.port == 80
    assert web_target.host == target
    assert isinstance(web_target, WebTarget)
    assert state.get_subsystem_state('scan') == SubsystemState.COMPLETE


def test_startup_banner_lifecycle(tmp_path):
    with patch('horcrux.ui.console.banner') as mock_banner:
        app1 = ConsoleApp()
        app1.startup(duration=0.0)
        assert mock_banner.call_count == 1
        assert app1.banner_count == 1

        app1.startup(duration=0.0)
        assert mock_banner.call_count == 1

        ws = Workspace('127.0.0.1', base=str(tmp_path))
        ws.upsert_services([Service(host='127.0.0.1', port=80, protocol='tcp', service='http')])
        app1.workspace = ws

        with patch('horcrux.core.orchestrator.Orchestrator.scan'):
            app1.dispatch(['scan', '127.0.0.1'])
            assert mock_banner.call_count == 1

        app1.dispatch(['services'])
        assert mock_banner.call_count == 1

        app1.dispatch(['surface'])
        assert mock_banner.call_count == 1

        app1.dispatch(['web'])
        assert mock_banner.call_count == 1

        with patch.object(app1.ai_manager, 'ask', return_value='AI analysis response'):
            app1.dispatch(['ask', 'What is running on port 80?'])
            assert mock_banner.call_count == 1

        with patch.object(app1, 'doctor'):
            app1.dispatch(['doctor'])
            assert mock_banner.call_count == 1

        with patch.object(app1, 'settings_cmd'):
            app1.dispatch(['settings'])
            assert mock_banner.call_count == 1

        app1.dispatch(['version'])
        assert mock_banner.call_count == 1

        assert mock_banner.call_count == 1
        assert app1.banner_count == 1

        app2 = ConsoleApp()
        app2.startup(duration=0.0)
        assert mock_banner.call_count == 2
        assert app2.banner_count == 1


def test_failed_scan_state_consistency(tmp_path):
    target = '10.0.0.1'
    ws = Workspace(target, base=str(tmp_path))
    console = Console(record=True)
    orch = Orchestrator(target, ws, console, profile='quick')

    with patch('horcrux.core.orchestrator.run_network', side_effect=RuntimeError('Network unreachable')):
        with pytest.raises(RuntimeError, match='Network unreachable'):
            orch.scan()

    state = ws.load()
    assert state.get_subsystem_state('scan') == SubsystemState.FAILED

    actions = compute_next_actions(state)
    assert len(actions) > 0
    top_action = actions[0]
    assert 're-run' in top_action.title.lower() or 'retry' in top_action.id.lower() or 'scan' in top_action.title.lower()
