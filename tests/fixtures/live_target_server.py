"""SYNTHETIC TEST FIXTURE — NOT a real OWASP Juice Shop instance.

PROVENANCE: SYNTHETIC_TEST_TARGET
TARGET_CLASS: DETERMINISTIC_INTEGRATION_FIXTURE

This module is a Python ThreadingHTTPServer that serves deterministic
pre-programmed responses mimicking the Juice Shop API surface.

IT IS NOT:
  - The real OWASP Juice Shop application
  - A real vulnerable target
  - Evidence of live-target acceptance

It MAY be used for:
  - Deterministic integration tests (CI-safe, no network required)
  - Capability adapter unit tests
  - Regression testing of the HTTP discovery pipeline

It MUST NOT be used to satisfy:
  - "LIVE ACCEPTANCE PASSED" gate
  - "real target -> real findings" claims
  - production validation reports

When used in tests, the WorkspaceState must have:
    state.target_provenance = "SYNTHETIC_TEST_TARGET"
    state.execution_mode = "SYNTHETIC"
"""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class JuiceShopHandler(BaseHTTPRequestHandler):
    server_version = "Express"
    sys_version = ""

    def _set_headers(self, status: int = 200, content_type: str = "application/json"):
        self.send_response(status)
        self.send_header("Server", "Express")
        self.send_header("X-Powered-By", "Express")
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

    def do_GET(self):
        path = self.path.split("?")[0]

        if path in ("/", "/index.html"):
            self._set_headers(200, "text/html")
            html = (
                "<!DOCTYPE html>\n"
                "<html>\n"
                "<head><title>OWASP Juice Shop</title></head>\n"
                "<body>\n"
                "  <app-root></app-root>\n"
                "  <script src=\"/main.js\"></script>\n"
                "</body>\n"
                "</html>\n"
            )
            self.wfile.write(html.encode("utf-8"))
            return

        if path == "/main.js":
            self._set_headers(200, "application/javascript")
            js = (
                "// Angular SPA Route Bundle\n"
                "const routes = [\n"
                "  '/rest/user/login',\n"
                "  '/rest/user/whoami',\n"
                "  '/rest/user/1',\n"
                "  '/rest/basket/1',\n"
                "  '/rest/admin/application-version',\n"
                "  '/api/Users',\n"
                "  '/graphql',\n"
                "  '/api/feedbacks'\n"
                "];\n"
            )
            self.wfile.write(js.encode("utf-8"))
            return

        if path == "/rest/user/1":
            self._set_headers(200, "application/json")
            data = {
                "status": "success",
                "data": {
                    "id": 1,
                    "username": "admin@juice-sh.op",
                    "email": "admin@juice-sh.op",
                    "role": "admin",
                },
            }
            self.wfile.write(json.dumps(data).encode("utf-8"))
            return

        if path == "/rest/basket/1":
            self._set_headers(200, "application/json")
            data = {
                "status": "success",
                "data": {
                    "id": 1,
                    "UserId": 1,
                    "products": [{"id": 1, "name": "Apple Juice", "price": 1.99}],
                },
            }
            self.wfile.write(json.dumps(data).encode("utf-8"))
            return

        if path == "/rest/admin/application-version":
            self._set_headers(200, "application/json")
            self.wfile.write(json.dumps({"version": "14.3.1"}).encode("utf-8"))
            return

        if path == "/rest/user/login":
            self._set_headers(200, "application/json")
            self.wfile.write(
                json.dumps({
                    "authentication": {
                        "token": "sample-jwt-token",
                        "bid": 1,
                        "umail": "admin@juice-sh.op",
                    }
                }).encode("utf-8")
            )
            return

        if path == "/api/Users":
            self._set_headers(200, "application/json")
            self.wfile.write(
                json.dumps({
                    "status": "success",
                    "data": [{"id": 1, "email": "admin@juice-sh.op"}],
                }).encode("utf-8")
            )
            return

        if path == "/graphql":
            self._set_headers(200, "application/json")
            data = {
                "data": {
                    "__schema": {
                        "queryType": {"name": "Query"},
                        "types": [{"name": "User"}, {"name": "Basket"}, {"name": "Product"}],
                    }
                }
            }
            self.wfile.write(json.dumps(data).encode("utf-8"))
            return

        if path == "/robots.txt":
            self._set_headers(200, "text/plain")
            self.wfile.write(b"User-agent: *\nDisallow: /ftp\n")
            return

        if path == "/ftp":
            self._set_headers(200, "text/html")
            self.wfile.write(b"<html><body><a href=\"/ftp/package.json.bak\">package.json.bak</a></body></html>")
            return

        if path == "/api/feedbacks":
            self._set_headers(200, "application/json")
            self.wfile.write(json.dumps({"status": "success", "data": []}).encode("utf-8"))
            return

        # Default 404
        self._set_headers(404, "text/html")
        self.wfile.write(f"Cannot GET {path}".encode("utf-8"))

    def do_POST(self):
        path = self.path.split("?")[0]
        if path == "/graphql":
            self._set_headers(200, "application/json")
            data = {
                "data": {
                    "__schema": {
                        "queryType": {"name": "Query"},
                        "types": [{"name": "User"}, {"name": "Basket"}, {"name": "Product"}],
                    }
                }
            }
            self.wfile.write(json.dumps(data).encode("utf-8"))
            return

        self._set_headers(404, "text/html")
        self.wfile.write(b"Cannot POST")

    def log_message(self, format, *args):
        pass


def run_server(port: int = 3000):
    server_address = ("127.0.0.1", port)
    httpd = ThreadingHTTPServer(server_address, JuiceShopHandler)
    print(f"Target server listening on http://127.0.0.1:{port}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.server_close()


if __name__ == "__main__":
    port = 3000
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    run_server(port)
