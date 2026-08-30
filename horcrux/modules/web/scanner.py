from __future__ import annotations

import re
from urllib.parse import urljoin

import httpx

from horcrux.core.parsers import detect_technologies
from horcrux.models import Credential, Finding, Severity


WEB_PORTS = {80, 81, 443, 3000, 5000, 8000, 8008, 8080, 8081, 8443, 8888, 9000}


def scheme_for(port: int) -> str:
    return "https" if port in {443, 8443} else "http"


def scan_http(ws, target: str, port: int):
    base = f"{scheme_for(port)}://{target}:{port}"
    findings: list[Finding] = []
    credentials: list[Credential] = []
    technologies: set[str] = set()

    client = httpx.Client(
        follow_redirects=False,
        verify=False,
        timeout=10,
        headers={"User-Agent": "Horcrux/1.0"},
    )

    paths = [
        "/",
        "/login",
        "/admin",
        "/robots.txt",
        "/sitemap.xml",
        "/.git/HEAD",
        "/.env",
    ]

    for path in paths:
        key = path.strip("/").replace("/", "_") or "root"

        try:
            response = client.get(urljoin(base + "/", path.lstrip("/")))
        except Exception as exc:
            ws.write(f"responses/{key}.error", str(exc))
            continue

        headers = "\n".join(
            f"{k}: {v}" for k, v in response.headers.items()
        )

        ws.write(f"responses/{key}.body", response.text)
        ws.write(f"headers/{key}.txt", headers)

        technologies.update(detect_technologies(headers, response.text))

        if path == "/" and response.status_code < 500:
            title = re.search(
                r"<title[^>]*>(.*?)</title>",
                response.text,
                re.I | re.S,
            )
            if title:
                ws.write(
                    "responses/page-title.txt",
                    re.sub(r"\s+", " ", title.group(1)).strip(),
                )

        if path == "/.git/HEAD" and response.status_code == 200:
            findings.append(
                Finding(
                    id=f"web-git-{port}",
                    title="Exposed Git metadata",
                    category="web-file-exposure",
                    severity=Severity.high,
                    confidence=.99,
                    target=target,
                    evidence=["/.git/HEAD returned HTTP 200."],
                    artifacts=[f"responses/{key}.body"],
                    next_action="Inspect repository metadata/history.",
                )
            )

        if path == "/.env" and response.status_code == 200:
            findings.append(
                Finding(
                    id=f"web-env-{port}",
                    title="Exposed environment file",
                    category="web-file-exposure",
                    severity=Severity.high,
                    confidence=.99,
                    target=target,
                    evidence=["/.env returned HTTP 200."],
                    artifacts=[f"responses/{key}.body"],
                    next_action="Inspect for secrets without dumping the file to normal output.",
                )
            )

        if path == "/admin" and response.status_code in {200, 401, 403}:
            findings.append(
                Finding(
                    id=f"web-admin-{port}",
                    title="Administrative web surface",
                    category="web-discovery",
                    severity=Severity.medium,
                    confidence=.85,
                    target=target,
                    evidence=[f"/admin returned HTTP {response.status_code}."],
                    artifacts=[f"responses/{key}.body"],
                    next_action="Inspect authentication and authorization behavior.",
                )
            )

        if path == "/login" and response.status_code == 200:
            if re.search(r'type=["\']password["\']', response.text, re.I):
                findings.append(
                    Finding(
                        id=f"web-login-{port}",
                        title="Login surface identified",
                        category="authentication",
                        severity=Severity.info,
                        confidence=.98,
                        target=target,
                        evidence=["Password field detected at /login."],
                        artifacts=[f"responses/{key}.body"],
                        next_action="Inspect session/authentication behavior.",
                    )
                )

            match = re.search(
                r'(?im)\b(?:user(?:name)?|login)\s*:\s*([A-Za-z0-9_.-]+).*?'
                r'\bpass(?:word)?\s*:\s*([^\s<]+)',
                response.text,
            )

            if match:
                credentials.append(
                    Credential(
                        username=match.group(1),
                        secret=match.group(2),
                        kind="page-disclosed",
                        source=f"{base}/login",
                        confidence=.95,
                    )
                )
                findings.append(
                    Finding(
                        id=f"web-credential-disclosure-{port}",
                        title="Credential-like data disclosed by login page",
                        category="authentication",
                        severity=Severity.high,
                        confidence=.95,
                        target=target,
                        evidence=["Username/password-like values were found in the response."],
                        artifacts=[f"responses/{key}.body"],
                        next_action="Validate only against the authorized target.",
                    )
                )

    ws.write_json(
        f"web-{port}.json",
        {
            "base": base,
            "technologies": sorted(technologies),
        },
    )

    return findings, credentials, sorted(technologies)
