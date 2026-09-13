import tempfile
from pathlib import Path
from horcrux.core.settings import SettingsManager
from horcrux.intel.ai.base import AIResponse, extract_json_payload
from horcrux.intel.ai.manager import AIManager
from horcrux.models import Action, ExploitCandidate, Service, Software, WorkspaceState


def test_extract_json_payload():
    # Plain JSON
    assert extract_json_payload('{"key": "val"}') == {"key": "val"}
    # Codeblock JSON
    codeblock = "```json\n{\"foo\": [1, 2, 3]}\n```"
    assert extract_json_payload(codeblock) == {"foo": [1, 2, 3]}
    # Extra commentary surrounding JSON
    surrounded = "Here is the result:\n```\n[{\"decision\": \"REJECTED\"}]\n```\nHope that helps!"
    assert extract_json_payload(surrounded) == [{"decision": "REJECTED"}]


def test_ai_manager_disabled_fallback():
    with tempfile.TemporaryDirectory() as tmpdir:
        mgr = SettingsManager(config_dir=Path(tmpdir))
        ai = AIManager(mgr)

        state = WorkspaceState(
            target="10.10.10.5",
            services=[Service(host="10.10.10.5", port=80, protocol="tcp", service="http", product="Apache", version="2.4.49")],
            software=[Software(product="Apache", version="2.4.49", service="http", source="nmap", confidence=0.9)],
        )

        # Fallback when no provider key configured
        actions = [Action(id="cve", title="Review CVEs", reason="Software found", score=90)]
        ranked = ai.rank_actions(state, actions)
        assert len(ranked) == 1
        assert ranked[0].id == "cve"

        # Ask returns graceful fallback notice
        answer = ai.ask(state, "What is running?")
        assert "AI analysis unavailable" in answer or "settings" in answer


def test_ai_caching():
    with tempfile.TemporaryDirectory() as tmpdir:
        mgr = SettingsManager(config_dir=Path(tmpdir))
        ai = AIManager(mgr)

        # Mock a configured provider
        class MockProvider:
            name = "groq"
            config = mgr.settings.providers["groq"]

            def is_configured(self):
                return True

            def complete(self, prompt, system_prompt="", temperature=None, max_tokens=None):
                return AIResponse(
                    content='{"status": "ok"}',
                    prompt_tokens=10,
                    completion_tokens=5,
                    total_tokens=15,
                    model="mock-model",
                    provider="groq",
                )

        ai.providers["groq"] = MockProvider()

        # First call hits provider
        resp1 = ai.complete("Test query")
        assert resp1 is not None
        assert resp1.content == '{"status": "ok"}'
        assert ai.stats.calls == 1
        assert ai.stats.cached_calls == 0

        # Second identical call hits cache
        resp2 = ai.complete("Test query")
        assert resp2 is not None
        assert resp2.content == '{"status": "ok"}'
        assert ai.stats.calls == 1
        assert ai.stats.cached_calls == 1

        # Clear cache
        ai.clear_cache()
        assert len(ai._memory_cache) == 0
