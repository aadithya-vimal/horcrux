"""Benchmark runner + evidence-script replay (Parts 30, 33).

- :func:`run_fixture` executes the full deterministic assessment loop over a
  synthetic fixture workspace (no network).
- :func:`record_evidence_script` exports recon-level workspace evidence to a
  portable script; :func:`replay_workspace` rebuilds an identical workspace
  from that script and re-runs hypothesis/investigation/coverage/attack-path
  reasoning without invoking any external target.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _workspace_in(tmp_path: Path, state: Any, name: str):  # tmp dirs in tests
    from horcrux.core.storage import Workspace
    ws = Workspace(state.target)
    ws.root = tmp_path / name
    for d in (ws.root, ws.raw, ws.responses, ws.headers, ws.reports):
        d.mkdir(parents=True, exist_ok=True)
    ws.state_file = ws.root / "state.json"
    ws.save(state)
    return ws


def collect_actual(state: Any) -> dict[str, Any]:
    """Collectors used by golden comparison."""
    try:
        app = state.get_application_model()
        endpoints = len(app.endpoints)
    except Exception:
        endpoints = 0
    try:
        classes = sorted({h.hypothesis_class.value for h in state.get_hypotheses()})
        invs = [i.objective for i in state.get_investigations()]
        states = [i.state.value for i in state.get_investigations()]
    except Exception:
        classes, invs, states = [], [], []
    paths = list(getattr(state, "attack_paths", []) or [])
    try:
        coverage = state.get_security_coverage().percentage_complete()
    except Exception:
        coverage = {}
    try:
        from horcrux.intel.contradictions import detect_contradictions
        contras = len(detect_contradictions(state))
    except Exception:
        contras = 0
    try:
        from horcrux.intel.coverage import assessment_completeness
        sufficient = bool(assessment_completeness(state)["sufficient"])
    except Exception:
        sufficient = False
    return {"endpoints": endpoints, "hypothesis_classes": classes,
            "investigations": invs,
            "attack_paths": len(paths),
            "attack_path_names": [p.get("name", "") for p in paths],
            "coverage": coverage, "contradictions": contras,
            "blocked": sum(1 for s in states if s in {"BLOCKED", "SCOPE_BLOCKED"}),
            "unavailable": sum(1 for s in states if s == "UNAVAILABLE"),
            "sufficient": sufficient,
            "crashed": False}


def run_fixture(name: str, tmp_path: Path, max_iterations: int = 6,
                ai_manager: Any = None, setup: Any = None) -> dict[str, Any]:
    """Run one benchmark fixture end-to-end (synthetic only)."""
    from horcrux.agents.root import RootVAPTOrchestrator
    from horcrux.bench import golden
    from horcrux.bench.fixtures import FIXTURES
    from horcrux.bench.metrics import evaluate
    builder = FIXTURES[name]
    state = builder()
    if setup is not None:
        setup(state)
    ws = _workspace_in(tmp_path, state, f"bench-{name}")
    crashed: str | None = None
    try:
        root = RootVAPTOrchestrator(ws, ai_manager=ai_manager,
                                    max_iterations=max_iterations)
        final = root.run_assessment_loop()
    except Exception as exc:
        crashed = f"{type(exc).__name__}: {exc}"
        final = ws.load()
    actual = collect_actual(final)
    if crashed:
        actual["crashed"] = True
        actual["crash_detail"] = crashed
    result = golden.compare(name, actual)
    result["metrics"] = evaluate(final, name, golden.GOLDEN.get(name, {}))
    result["actual"] = {k: v for k, v in actual.items() if k != "investigations"}
    return result


def run_suite(names: list[str] | None, tmp_path: Path,
              max_iterations: int = 6) -> dict[str, Any]:
    """Run a benchmark suite; returns aggregate + per-fixture results."""
    from horcrux.bench.fixtures import FIXTURES
    names = names or sorted(FIXTURES)
    results = [run_fixture(n, tmp_path / n, max_iterations) for n in names]
    scores = [r["score"] for r in results]
    return {"fixtures": len(results),
            "mean_score": round(sum(scores) / len(scores), 3) if scores else 0.0,
            "passed": sum(1 for r in results if r["score"] >= 0.6),
            "results": results}


# ---------------------------------------------------------------------------
# Replay (Part 33)
# ---------------------------------------------------------------------------

RECON_FIELDS = ("services", "software", "technologies", "discovered_paths",
                "parameters", "web_targets", "credentials")


def record_evidence_script(workspace: Any) -> dict[str, Any]:
    """Export recon-level evidence as a portable, network-free script."""
    state = workspace.load()
    script: dict[str, Any] = {"target": state.target, "version": 1, "evidence": {}}
    dump = state.model_dump(mode="json")
    for f in RECON_FIELDS:
        script["evidence"][f] = dump.get(f, [])
    return script


def write_evidence_script(workspace: Any, path: Path | None = None) -> Path:
    out = path or (workspace.root / "evidence-script.json")
    out.write_text(json.dumps(record_evidence_script(workspace), indent=2), encoding="utf-8")
    return out


def replay_workspace(target: str, script: dict[str, Any] | Path,
                     base: str = "workspaces") -> Any:
    """Rebuild a workspace from a recorded evidence script (no targets touched).

    Returns the loaded WorkspaceState after deterministic reassessment
    (hypotheses, ranking, coverage, attack paths) — without executing any
    capability or network call.
    """
    from horcrux.core.storage import Workspace
    from horcrux.models import WorkspaceState
    if isinstance(script, Path):
        script = json.loads(script.read_text(encoding="utf-8"))
    ws = Workspace(target or script.get("target", "replay"), base=base)
    evidence = script.get("evidence", {})
    data = {"target": ws.target}
    data.update({f: evidence.get(f, []) for f in RECON_FIELDS})
    state = WorkspaceState.model_validate(data)
    ws.save(state)
    from horcrux.agents.root import RootVAPTOrchestrator
    root = RootVAPTOrchestrator(ws, ai_manager=None)
    return root.ingest_and_reassess()
