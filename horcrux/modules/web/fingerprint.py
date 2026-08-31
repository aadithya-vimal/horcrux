from __future__ import annotations

import json
import re
from pathlib import Path
from horcrux.models import Software


def run_fingerprinting(ws, runner, target: str, port: int) -> tuple[list[str], list[Software]]:
    """
    Executes technology & WAF fingerprinting using available tools (whatweb, httpx, wafw00f).
    Normalizes findings into software inventory and technology list.
    """
    scheme = "https" if port in {443, 8443} else "http"
    base_url = f"{scheme}://{target}:{port}"

    technologies: set[str] = set()
    software: list[Software] = []

    # 1. WhatWeb
    if runner.which("whatweb"):
        out_json = ws.raw / f"whatweb-{port}.json"
        runner.run(
            [
                "whatweb",
                "--no-errors",
                "-a", "1",
                "-q",
                f"--log-json={out_json}",
                base_url,
            ],
            f"whatweb-{port}",
            timeout=120,
        )
        if out_json.exists():
            try:
                content = out_json.read_text(encoding="utf-8", errors="replace").strip()
                data = json.loads(content) if content.startswith(("[", "{")) else []
                if isinstance(data, dict):
                    data = [data]
                for entry in data:
                    plugins = entry.get("plugins", {})
                    for plugin_name, details in plugins.items():
                        technologies.add(plugin_name.lower())
                        version = ""
                        if isinstance(details, dict):
                            versions = details.get("version", [])
                            if versions and isinstance(versions, list):
                                version = str(versions[0])
                        if version:
                            software.append(
                                Software(
                                    product=plugin_name,
                                    version=version,
                                    service=f"{port}/tcp",
                                    source="whatweb",
                                    confidence=0.92,
                                    evidence=[f"WhatWeb fingerprint matched {plugin_name} version {version}"],
                                )
                            )
            except Exception as exc:
                ws.write(f"raw/whatweb-{port}.error", str(exc))

    # 2. Httpx (technology detection flag)
    if runner.which("httpx"):
        out_json = ws.raw / f"httpx-tech-{port}.json"
        runner.run(
            [
                "httpx",
                "-u", base_url,
                "-tech-detect",
                "-status-code",
                "-title",
                "-silent",
                "-json",
                "-o", str(out_json),
            ],
            f"httpx-{port}",
            timeout=90,
        )
        if out_json.exists():
            try:
                for line in out_json.read_text(encoding="utf-8", errors="replace").splitlines():
                    if not line.strip():
                        continue
                    rec = json.loads(line)
                    for tech in rec.get("tech", []):
                        technologies.add(tech.lower())
            except Exception:
                pass

    # 3. WAFW00F
    if runner.which("wafw00f"):
        out_txt = ws.raw / f"wafw00f-{port}.txt"
        res = runner.run(
            ["wafw00f", base_url, "-o", str(out_txt)],
            f"wafw00f-{port}",
            timeout=60,
        )
        if res and "is behind" in res.stdout:
            match = re.search(r"is behind\s+([A-Za-z0-9_\- ]+)\s+WAF", res.stdout, re.I)
            if match:
                waf_name = match.group(1).strip()
                technologies.add(f"WAF: {waf_name}")
                ws.write(f"raw/waf-{port}.txt", f"Detected WAF: {waf_name}")

    if software:
        ws.upsert_software(software)

    state = ws.load()
    state.technologies = sorted(set(state.technologies) | technologies)
    ws.save(state)

    return sorted(technologies), software
