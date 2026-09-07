import tempfile
import time
from pathlib import Path
from unittest.mock import patch

import httpx
from rich.console import Console

from horcrux.core.doctor import ToolImportance, check_tools, get_tool_importance
from horcrux.core.operations import OperationState, OperationStatus
from horcrux.core.policy import (
    ActionProposal,
    EngagementMode,
    EngagementPolicy,
    EngagementScope,
    OperatorMode,
)
from horcrux.core.settings import SettingsManager
from horcrux.intel.ai.base import AIError, AIErrorType, AIResponse
from horcrux.intel.ai.google import GoogleProvider
from horcrux.intel.ai.manager import AIManager
from horcrux.intel.tasks.ask import _format_failure_diagnostic, execute_operator_ask
from horcrux.models import WorkspaceState
from horcrux.ui.progress import AIProgressManager, ScanProgressManager, StageState


def test_operation_state_lifecycle():
    op = OperationState(name="Reconnaissance Scan", target="10.10.10.5", total_items=5)
    assert op.status == OperationStatus.PENDING
    assert op.progress_pct is None

    op.start("Port Discovery", total_items=5)
    assert op.status == OperationStatus.RUNNING
    assert op.phase == "Port Discovery"

    op.update(current_item="nmap", completed_delta=2)
    assert op.completed_items == 2
    assert op.progress_pct == 40.0

    op.complete_partial(message="Partial ports scanned", error="Filtered")
    assert op.status == OperationStatus.PARTIAL

    op.complete("Scan finished")
    assert op.status == OperationStatus.COMPLETED
    assert op.progress_pct == 100.0


def test_scan_progress_manager_collapse_summary():
    console = Console(record=True)
    with ScanProgressManager(console, "10.10.10.50", "standard") as mgr:
        mgr.start_stage("reachability")
        mgr.complete_stage("reachability")

    text = console.export_text()
    assert "Scan complete" in text
    assert "1 phases completed" in text


def test_scan_progress_manager_cancel():
    console = Console(record=True)
    with ScanProgressManager(console, "10.10.10.50", "standard") as mgr:
        mgr.start_stage("reachability")
        mgr.cancel("User pressed Ctrl+C")

    text = console.export_text()
    assert "Scan aborted by operator" in text


def test_ai_progress_manager_lifecycle():
    console = Console(record=True)
    with AIProgressManager(console, "Security Assessment", "google", "gemini-2.5-flash") as ai_prog:
        ai_prog.set_phase("Analyzing workspace evidence")
        assert ai_prog.phase == "Analyzing workspace evidence"

    # Test error collapse
    console_err = Console(record=True)
    with AIProgressManager(console_err, "Security Assessment", "google", "gemini-2.5-flash") as ai_prog:
        ai_prog.fail("Quota exceeded (429)")

    text_err = console_err.export_text()
    assert "AI operation failed: Quota exceeded" in text_err


def test_gemini_safety_settings_and_system_instruction():
    with tempfile.TemporaryDirectory() as tmpdir:
        mgr = SettingsManager(config_dir=Path(tmpdir))
        mgr.set_api_key("google", "AIzaSyFakeKeyForTest123")
        provider = GoogleProvider(mgr)

        recorded_request = {}

        def mock_post(url, json=None, headers=None, timeout=None):
            recorded_request["url"] = str(url)
            recorded_request["json"] = json
            fake_resp = {
                "candidates": [
                    {
                        "content": {
                            "parts": [{"text": "Vulnerability assessment confirmed."}],
                            "role": "model",
                        },
                        "finishReason": "STOP",
                    }
                ],
                "usageMetadata": {
                    "promptTokenCount": 20,
                    "candidatesTokenCount": 15,
                    "totalTokenCount": 35,
                },
            }
            return httpx.Response(200, json=fake_resp, request=httpx.Request("POST", str(url)))

        with patch("httpx.Client.post", side_effect=mock_post):
            resp = provider.complete("Analyze target attack surface", system_prompt="Be concise")
            assert resp.content == "Vulnerability assessment confirmed."
            assert resp.prompt_tokens == 20
            assert resp.completion_tokens == 15

            payload = recorded_request.get("json", {})
            assert "safetySettings" in payload
            assert any(s.get("threshold") == "BLOCK_NONE" for s in payload["safetySettings"])
            assert "systemInstruction" in payload


def test_engagement_policy_target_scoping():
    scope = EngagementScope(
        allowed_targets=["10.10.10.5", "192.168.1.100"],
        allowed_networks=["172.16.0.0/16"],
        allowed_domains=["target.corp", "sub.target.corp"],
        excluded_targets=["172.16.0.1"],
    )
    policy = EngagementPolicy(mode=EngagementMode.AUTHORIZED, scope=scope)

    # Exact target match
    ok, _ = policy.is_target_allowed("10.10.10.5")
    assert ok is True

    # Network match
    ok, _ = policy.is_target_allowed("172.16.5.20")
    assert ok is True

    # Excluded target overrides network match
    ok, reason = policy.is_target_allowed("172.16.0.1")
    assert ok is False
    assert "excluded" in reason.lower()

    # Domain match
    ok, _ = policy.is_target_allowed("app.target.corp")
    assert ok is True

    # Out of scope target
    ok, reason = policy.is_target_allowed("8.8.8.8")
    assert ok is False
    assert "outside declared engagement scope" in reason.lower()


def test_engagement_policy_action_validation():
    policy = EngagementPolicy(mode=EngagementMode.READ_ONLY)
    proposal_safe = ActionProposal(
        action_type="service_enumeration",
        target="10.10.10.5",
        risk_level="SAFE",
    )
    proposal_active = ActionProposal(
        action_type="parameter_fuzz",
        target="10.10.10.5",
        risk_level="ACTIVE",
    )

    ok, _ = policy.is_action_allowed(proposal_safe)
    assert ok is True

    ok, reason = policy.is_action_allowed(proposal_active)
    assert ok is False
    assert "READ_ONLY" in reason

    # LAB mode allows AGGRESSIVE actions
    policy_lab = EngagementPolicy(mode=EngagementMode.LAB)
    proposal_agg = ActionProposal(
        action_type="cve_exploit",
        target="10.10.10.5",
        risk_level="AGGRESSIVE",
    )
    ok, _ = policy_lab.is_action_allowed(proposal_agg)
    assert ok is True


def test_engagement_policy_ai_context():
    scope = EngagementScope(allowed_targets=["10.10.10.5"])
    policy = EngagementPolicy(
        mode=EngagementMode.AUTHORIZED,
        operator_mode=OperatorMode.OPERATOR,
        scope=scope,
    )
    ctx = policy.format_ai_context("10.10.10.5")
    assert "ENGAGEMENT POLICY" in ctx
    assert "AUTHORIZED" in ctx
    assert "10.10.10.5" in ctx


def test_doctor_tool_importance():
    assert get_tool_importance("nmap") == ToolImportance.REQUIRED
    assert get_tool_importance("python") == ToolImportance.REQUIRED
    assert get_tool_importance("ffuf") == ToolImportance.RECOMMENDED
    assert get_tool_importance("httpx") == ToolImportance.RECOMMENDED
    assert get_tool_importance("docker") == ToolImportance.ENVIRONMENT
    assert get_tool_importance("some_obscure_tool") == ToolImportance.OPTIONAL

    tools, _ = check_tools()
    nmap_row = next(r for r in tools if r[0] == "nmap")
    assert len(nmap_row) == 5
    assert nmap_row[4] == ToolImportance.REQUIRED


def test_ai_manager_error_diagnostics_and_ask_formatting():
    with tempfile.TemporaryDirectory() as tmpdir:
        mgr = SettingsManager(config_dir=Path(tmpdir), use_keyring=False)
        ai = AIManager(mgr)
        # Disabled initially
        ai.settings.set_enabled(False)
        out = execute_operator_ask(ai, "What is SSH?")
        assert "disabled" in out.lower()

        # Enable without key
        ai.settings.set_enabled(True)
        resp = ai.call_task("test", "hello")
        assert resp is None
        assert ai.last_failure_stage == AIErrorType.CONFIGURATION_ERROR.value
        assert "not configured" in ai.last_diagnostic.lower()

        diag_out = _format_failure_diagnostic(ai)
        assert "AI generation failed" in diag_out
        assert "CONFIGURATION_ERROR" in diag_out
