# Benchmark Suite & Replay

`horcrux/bench/` — fully offline, synthetic-only.

- `fixtures.py`: 20 deterministic scenarios (BOLA, broken auth, BFLA,
  privesc, business logic, SSRF, injection, upload, GraphQL authz, JWT,
  data exposure, workflow state, multi-step path, contradictions,
  tool/browser failure, missing capability, AI unavailable, provider
  refusal, operator intervention).
- `golden.py`: expected facts/hypotheses/investigations/paths/coverage with
  tolerance for legitimate reasoning variance.
- `metrics.py`: model completeness, hypothesis recall, investigation
  relevance, evidence sufficiency, finding precision, coverage, attack-path
  accuracy, blocked handling, failure recovery, steering correctness,
  redundancy/low-value rates, completion quality. Never finding counts.
- `runner.py`: `run_suite()` executes fixtures through the real assessment
  loop without network.

Replay (`horcrux replay <target> [--script PATH]`): records recon-level
evidence to `evidence-script.json`, rebuilds an identical workspace from it,
and re-runs hypothesis generation, ranking, coverage, attack paths, and
reporting — no target is ever touched.

Run: `horcrux benchmark [fixture|all]` or console `benchmark`.
