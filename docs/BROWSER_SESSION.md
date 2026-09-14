# Browser / Session Support

`horcrux/intel/browser.py` — replaceable `BrowserAdapter` interface
(`launch`, `close`, `create_context`, `new_session`, `navigate`, `reload`,
`click`, `fill`, `submit`, `select`, `wait`, `screenshot`, `inspect_dom`,
`inspect_network`, `get_cookies`, `get_storage`, `get_current_url`,
`get_page_title`, `capture_console`, `capture_request`, `capture_response`).

Backends:

- `PlaywrightBrowserAdapter` — real automation when the `playwright`
  package and a browser runtime are installed. Every navigation is
  scope-gated; redirect escapes fail as `SCOPE_BLOCKED`.
- `ScriptedBrowserAdapter` — deterministic scripted page tables for
  synthetic benchmarks, replay, and offline use. No network ever.

`horcrux/intel/browser_session.py::record_browser_session` converges both
backends into the SAME ApplicationModel (requests → `ingest_http_request`,
DOM routes → routes, API calls → endpoints, cookies → hashed session
evidence, forms → forms/workflows). No browser-specific semantic model.

`horcrux/intel/sessions.py`:

- `TestIdentity` — researcher-configured accounts; secrets resolve from
  environment (`HORCRUX_IDENTITY_<N>_*` or `password_env`), never hard-coded.
- `authenticated_crawl()` — anonymous discovery → login → authenticated
  surface → object/workflow correlation.
- `compare_identities()` — endpoint/object/response/role/session comparison
  primitive used by authorization investigations (`identity_compare`).
