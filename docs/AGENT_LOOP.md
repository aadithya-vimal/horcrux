# Agent Loop

`RootVAPTOrchestrator.run_assessment_loop()` (`horcrux/agents/root.py`):

1. Load workspace, recover interrupted `RUNNING` investigations to `READY`.
2. `reassess()`: ingest → ApplicationModel → hypotheses → investigations
   (dependency-gated) → rank → coverage → attack paths → reasoning checkpoint.
3. Contradiction detection may queue resolution investigations.
4. Dependency-aware batch selection (`horcrux/intel/dependencies.py`):
   sequential by default; `--workers N` runs capability execution concurrently
   for independent investigations while ingestion stays serial.
5. Execute → normalize → ingest → coverage → hypothesis update → findings.
6. Reasoning checkpoint every 2nd iteration or on SUPPORTED/REFUTED.
7. Repeat until coverage/exhaustion/hypothesis/failure completion criteria.

Completion is coverage + investigation exhaustion + unresolved high-value
hypotheses + execution failures. Never `findings == 0`.

Investigations support prerequisites (`two_identities`,
`authenticated_session`, `workflow_discovered`, `graphql_present`, ...).
Impossible work is parked as `BLOCKED` with reasons and unblocks
automatically when evidence arrives. Terminal/parked states are preserved
across reassessments (no repeated impossible investigations).
