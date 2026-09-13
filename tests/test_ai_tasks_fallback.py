from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import patch
import httpx

from horcrux.core.settings import SettingsManager
from horcrux.intel.ai.base import AIError, AIErrorType, AIResponse
from horcrux.intel.ai.manager import AIManager
from horcrux.models import (
    Action,
    ExploitCandidate,
    Finding,
    FindingStatus,
    Service,
    Severity,
    Software,
    ValidationState,
    WorkspaceState,
)


def test_exploit_triage_task():
    with tempfile.TemporaryDirectory() as tmpdir:
        mgr = SettingsManager(config_dir=Path(tmpdir))
        mgr.set_api_key("groq", "gsk_fake")
        ai = AIManager(mgr)

        state = WorkspaceState(
            target="192.168.1.50",
            services=[Service(host="192.168.1.50", port=80, protocol="tcp", service="http", product="Apache", version="2.4.49")],
            software=[Software(product="Apache", version="2.4.49", service="80/tcp", source="nmap", confidence=0.95)],
        )
        candidates = [
            ExploitCandidate(
                title="Apache 2.4.49 - Path Traversal RCE",
                product="Apache",
                version="2.4.49",
                cve="CVE-2021-41773",
                source="exploits/50383.sh",
                relevance="HIGH-CONFIDENCE CANDIDATE",
                confidence=0.8,
            )
        ]

        mock_structured = [
            {
                "decision": "HIGHLY_RELEVANT",
                "confidence": 0.98,
                "attack_type": "remote",
                "reasoning": "Exact Apache 2.4.49 match with confirmed path traversal vulnerability.",
                "missing_prerequisites": [],
                "recommended_verification": "curl -s --path-as-is http://target/cgi-bin/.%2e/%2e%2e/bin/sh",
            }
        ]

        with patch.object(ai, "call_task", return_value=AIResponse(content="", structured=mock_structured)):
            triaged = ai.triage_exploits(state, candidates)
            assert len(triaged) == 1
            assert triaged[0].relevance == "CONFIRMED VERSION MATCH"
            assert triaged[0].confidence == 0.98
            assert "Exact Apache 2.4.49" in triaged[0].relevance_reasoning


def test_next_action_reasoning_task():
    with tempfile.TemporaryDirectory() as tmpdir:
        mgr = SettingsManager(config_dir=Path(tmpdir))
        mgr.set_api_key("groq", "gsk_fake")
        ai = AIManager(mgr)

        state = WorkspaceState(target="192.168.1.50")
        actions = [
            Action(id="smb_enum", title="Enumerate SMB Shares", reason="TCP 445 open", score=80),
            Action(id="web_fuzz", title="Fuzz Web Routes", reason="HTTP 80 open", score=85),
        ]

        mock_structured = [
            {"id": "smb_enum", "adjusted_score": 96, "refined_reason": "SMB null session prioritized for rapid credential gain."}
        ]

        with patch.object(ai, "call_task", return_value=AIResponse(content="", structured=mock_structured)):
            ranked = ai.rank_actions(state, actions)
            assert ranked[0].id == "smb_enum"
            assert ranked[0].score == 96
            assert "credential gain" in ranked[0].reason


def test_multi_provider_fallback():
    with tempfile.TemporaryDirectory() as tmpdir:
        mgr = SettingsManager(config_dir=Path(tmpdir))
        mgr.set_api_key("groq", "gsk_fake_groq")
        mgr.set_api_key("google", "AIzaSy_fake_google")
        mgr.set_default_provider("groq")
        mgr.set_fallback_sequence(["google"])
        ai = AIManager(mgr)

        # Primary (groq) encounters rate limit
        def mock_groq_structured(*args, **kwargs):
            raise AIError(AIErrorType.RATE_LIMITED, "Groq TPM limit reached", provider="groq")

        # Secondary (google) succeeds
        def mock_google_structured(*args, **kwargs):
            return AIResponse(
                content='{"result": "ok"}',
                structured={"result": "ok"},
                provider="google",
                model="gemini-1.5-flash",
                prompt_tokens=10,
                completion_tokens=5,
                total_tokens=15,
            )

        ai.providers["groq"].structured = mock_groq_structured
        ai.providers["google"].structured = mock_google_structured

        resp = ai.call_task("test_task", "Hello world")
        assert resp is not None
        assert resp.provider == "google"
        assert resp.structured == {"result": "ok"}


def test_ai_disabled_deterministic_fallback():
    with tempfile.TemporaryDirectory() as tmpdir:
        mgr = SettingsManager(config_dir=Path(tmpdir))
        mgr.set_api_key("groq", "gsk_fake")
        mgr.set_enabled(False)
        ai = AIManager(mgr)

        state = WorkspaceState(target="192.168.1.50")
        answer = ai.ask("What is the top vulnerability?", state)
        assert "disabled" in answer.lower()

        paths = ai.synthesize_attack_paths(state)
        # Deterministic fallback returns paths list without error
        assert isinstance(paths, list)
