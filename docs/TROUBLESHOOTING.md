# Troubleshooting

- **Assessment ends immediately**: check `status` — likely paused
  (`resume`), stopped, or scope-excluded target. See `raw/assessment-stop-reason.txt`.
- **Investigation BLOCKED**: `why <id>` shows the missing prerequisite
  (e.g. needs a second identity — configure `HORCRUX_IDENTITY_*` or add
  credentials, then reassess to unblock).
- **Capability MISSING/BROKEN**: `status` capabilities line and §16 of the
  report show live vs synthesis vs missing backends with install hints.
- **Browser automation unavailable**: `playwright` not installed — the
  scripted backend covers benchmarks/replay; install Playwright + browsers
  for live sessions.
- **AI errors**: `ai` command shows provider health; safety refusals fall
  back to deterministic reasoning automatically. Check `settings test`.
- **Resume after crash**: rerun `assess` — `RUNNING` work is requeued,
  terminal evidence is preserved, expensive work is not blindly rerun.
- **Secrets in output**: all reports, events, and errors pass through
  `horcrux/core/sanitizer.py`; `scan_for_secrets()` audits text.
- **Replay differs from live run**: replay reuses recorded recon evidence;
  nondeterminism comes only from AI prose (deterministic core is stable).
