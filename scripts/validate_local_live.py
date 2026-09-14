# -*- coding: utf-8 -*-
"""PART 15 local runtime validation (operator-run, localhost only).

1. doctor tool rows for key binaries
2. status capability line on a localhost workspace
3. agentic loop reaching a newly-connected capability (content_discovery)
   through registry -> real handler -> evidence -> model update.
"""

import os
import tempfile
import threading
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

os.environ["HORCRUX_LIVE_LOCAL"] = "1"

from horcrux.agents.root import RootVAPTOrchestrator
from horcrux.agents.tools.capabilities import environment_availability_report
from horcrux.core.doctor import check_tools
from horcrux.core.storage import Workspace
from horcrux.models import DiscoveredPath, Service, WorkspaceState


def pick_port():
    import socket
    for port in (8080, 8000, 3000, 8888):
        with socket.socket() as sock:
            try:
                sock.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise RuntimeError("no local web port free")


def main():
    print("== doctor ==")
    rows, _ = check_tools()
    for name, path, _purpose, _inst, _imp in rows:
        if name.lower() in {"ffuf", "nuclei", "nikto", "httpx", "nmap",
                            "gobuster", "feroxbuster", "whatweb",
                            "searchsploit", "dig", "python", "node"}:
            print(f"  {name}: {'FOUND ' + path if path else 'missing'}")

    print("== status capabilities ==")
    rep = environment_availability_report()
    live = sorted(k for k, v in rep.items() if v.get("mode") == "live")
    print(f"  {len(live)} live / {len(rep)} total")
    for cap in ("content_discovery", "nuclei_scan", "nikto_audit",
                "browser_automate", "web_fingerprint", "nmap_discovery"):
        info = rep.get(cap, {})
        print(f"  {cap}: {info.get('status')}/{info.get('mode')} "
              f"[{info.get('reason', '')[:60]}]")

    print("== local web assessment ==")
    tmp = Path(tempfile.mkdtemp(prefix="horcrux-live-"))
    docroot = tmp / "www"
    docroot.mkdir()
    (docroot / "index.html").write_text("<html><body>hi</body></html>")
    (docroot / "login.html").write_text("<html><body>login</body></html>")
    (docroot / "login").write_text("<html><body>login</body></html>")
    (docroot / "api").write_text('{"ok": true}')
    port = pick_port()
    server = ThreadingHTTPServer(
        ("127.0.0.1", port),
        partial(SimpleHTTPRequestHandler, directory=str(docroot)))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        target = "127.0.0.1"
        state = WorkspaceState(target=target)
        state.services = [Service(host=target, port=port, service="http")]
        state.discovered_paths = [DiscoveredPath(
            url=f"http://{target}:{port}/", path="/", status=200,
            source="http_probe", validated=True)]
        ws = Workspace(target)
        ws.root = tmp / "ws"
        for d in (ws.root, ws.raw, ws.responses, ws.headers, ws.reports):
            d.mkdir(parents=True, exist_ok=True)
        ws.state_file = ws.root / "state.json"
        ws.save(state)

        root = RootVAPTOrchestrator(ws, ai_manager=None, max_iterations=4)
        final = root.run_assessment_loop()
        invs = final.get_investigations()
        reached = [i for i in invs
                   if set(i.candidate_tools or {}) & {"content_discovery"}
                   and i.state.value in {"COMPLETE", "SUPPORTED", "REFUTED",
                                         "INSUFFICIENT_EVIDENCE", "FAILED"}]
        print(f"  investigations: {len(invs)}, "
              f"content_discovery executed: {len(reached)}")
        for inv in reached:
            print(f"  - {inv.objective[:60]} [{inv.state.value}] "
                  f"{inv.result_summary[:80]}")
        app = final.get_application_model()
        print(f"  endpoints in model: {len(app.endpoints)}")
        for ep in app.endpoints:
            print(f"    {ep.method} {ep.path} via {','.join(ep.sources)}")
        assert reached, "newly-connected capability was NOT reached by the loop"
        assert len(app.endpoints) >= 2, "live evidence did not reach the model"
        print("  PROOF OK: agentic investigation -> registry -> real handler "
              "-> evidence -> model")
    finally:
        server.shutdown()
        thread.join(timeout=5)


if __name__ == "__main__":
    main()
