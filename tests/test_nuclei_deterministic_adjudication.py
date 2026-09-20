"""Nuclei Adjudication Acceptance Test (Section 11)."""

from __future__ import annotations

from pathlib import Path
from horcrux.core.intel import run_nuclei
from horcrux.core.runner import CommandRunner
from horcrux.core.storage import Workspace
from horcrux.models import ValidationState, WorkspaceState


class MockNucleiRunner:
    def __init__(self, output_lines: list[str]):
        self.output_lines = output_lines

    def which(self, binary: str) -> str | None:
        return "/usr/bin/nuclei" if binary == "nuclei" else None

    def run(self, cmd, label, timeout=None):
        import json
        out_file = Path(cmd[cmd.index("-o") + 1])
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text("\n".join(self.output_lines), encoding="utf-8")
        class Res:
            returncode = 0
            stdout = ""
            stderr = ""
        return Res()


def test_section_11_nuclei_weak_matcher_vs_deterministic_proof(tmp_path: Path):
    """Section 11: High severity with weak matcher is NOT confirmed; lower severity with proof IS confirmed."""
    ws = Workspace("127.0.0.1")
    ws.root = tmp_path
    ws.raw = tmp_path / "raw"
    ws.raw.mkdir(parents=True, exist_ok=True)

    # 1. High severity template with ONLY weak banner match (no proof of exploitation)
    weak_line = (
        '{"template-id": "weak-banner-check", "info": {"name": "Potential Critical Flaw", "severity": "critical", '
        '"description": "Banner match only"}, "matched-at": "http://127.0.0.1:80", '
        '"type": "http", "matcher-name": "version-header"}'
    )

    # 2. Medium severity template with concrete extracted secret proof
    proof_line = (
        '{"template-id": "git-config-exposure", "info": {"name": "Exposed Git Config", "severity": "medium", '
        '"description": "Git repository configuration exposed", "classification": {"cwe-id": ["CWE-200"]}}, '
        '"matched-at": "http://127.0.0.1:80/.git/config", "type": "http", "matcher-name": "git-core", '
        '"extracted-results": ["repositoryformatversion = 0"]}'
    )

    runner = MockNucleiRunner([weak_line, proof_line])
    findings = run_nuclei(ws, runner, "http://127.0.0.1:80")

    assert len(findings) == 2

    # Weak matcher: must NOT be confirmed despite "critical" severity
    weak_f = next(f for f in findings if "weak-banner-check" in f.id)
    assert weak_f.validation_state != ValidationState.confirmed, "Weak matcher must not be confirmed"
    assert weak_f.validation_state == ValidationState.likely

    # Strong proof: confirmed
    proof_f = next(f for f in findings if "git-config-exposure" in f.id)
    assert proof_f.validation_state == ValidationState.confirmed, "Strong extracted proof must be confirmed"
