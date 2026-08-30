from __future__ import annotations

import re
from urllib.parse import urljoin

import httpx

from horcrux.core.parsers import detect_technologies
from horcrux.models import Credential, Finding, Severity


import secrets
from urllib.parse import urljoin

import httpx

from horcrux.core.parsers import detect_technologies
from horcrux.models import Credential, Finding, FindingStatus, Severity, ValidationState
from horcrux.modules.web.validator import BaselineFingerprint, ValidatorRegistry


WEB_PORTS = {80, 81, 443, 3000, 5000, 8000, 8008, 8080, 8081, 8443, 8888, 9000}


def scheme_for(port: int) -> str:
    return "https" if port in {443, 8443} else "http"


def scan_http(ws, target: str, port: int, registry: ValidatorRegistry | None = None):
    registry = registry or ValidatorRegistry()
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

    # 1. Establish Baseline Fingerprint with a random non-existent path
    random_token = f"_horcrux_baseline_{secrets.token_hex(6)}"
    baseline_url = urljoin(base + "/", random_token)
    try:
        baseline_resp = client.get(baseline_url)
        baseline = BaselineFingerprint.analyze(baseline_resp)
        ws.write("responses/baseline.txt", f"Status: {baseline.status_code}\nLength: {baseline.content_length}\nSPA: {baseline.is_spa}\nCatchall: {baseline.is_catchall_200}")
    except Exception as exc:
        baseline = BaselineFingerprint(
            status_code=404,
            content_length=0,
            content_type="",
            title="",
            body_hash="",
        )
        ws.write("responses/baseline.error", str(exc))

    # 2. General base path check (root & login)
    general_paths = ["/", "/login"]
    for path in general_paths:
        key = path.strip("/").replace("/", "_") or "root"
        try:
            response = client.get(urljoin(base + "/", path.lstrip("/")))
        except Exception as exc:
            ws.write(f"responses/{key}.error", str(exc))
            continue

        headers = "\n".join(f"{k}: {v}" for k, v in response.headers.items())
        ws.write(f"responses/{key}.body", response.text)
        ws.write(f"headers/{key}.txt", headers)

        technologies.update(detect_technologies(headers, response.text))

        if path == "/" and response.status_code < 500:
            title_match = re.search(r"<title[^>]*>(.*?)</title>", response.text, re.I | re.S)
            if title_match:
                ws.write(
                    "responses/page-title.txt",
                    re.sub(r"\s+", " ", title_match.group(1)).strip(),
                )

        if path == "/login" and response.status_code == 200 and not baseline.is_similar(response):
            if re.search(r'type=["\']password["\']', response.text, re.I):
                findings.append(
                    Finding(
                        id=f"web-login-{port}",
                        title="Login surface identified",
                        category="authentication",
                        severity=Severity.info,
                        confidence=0.98,
                        status=FindingStatus.verified,
                        validation_state=ValidationState.confirmed,
                        target=target,
                        affected_asset=f"{base}/login",
                        protocol="tcp",
                        port=port,
                        source_tool="web-probe",
                        evidence=["Password input element detected on live page."],
                        artifacts=[f"responses/{key}.body"],
                        why_it_matters="Identifies authentication gateway into application.",
                        recommended_next_action="Inspect session lifecycle, password policy, and rate limits.",
                        next_action="Inspect session lifecycle, password policy, and rate limits.",
                    )
                )

            # Check for credential leakage in login source
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
                        confidence=0.95,
                    )
                )
                findings.append(
                    Finding(
                        id=f"web-credential-disclosure-{port}",
                        title="Credential-like data disclosed by login page",
                        category="authentication",
                        severity=Severity.high,
                        confidence=0.95,
                        status=FindingStatus.verified,
                        validation_state=ValidationState.confirmed,
                        target=target,
                        affected_asset=f"{base}/login",
                        protocol="tcp",
                        port=port,
                        source_tool="web-probe",
                        evidence=["Username/password-like values found in login HTML source."],
                        artifacts=[f"responses/{key}.body"],
                        why_it_matters="Hardcoded or defaulted credentials leak access to the application.",
                        recommended_next_action="Validate credentials against authorized target only.",
                        next_action="Validate credentials against authorized target only.",
                    )
                )

    # 3. Pluggable Endpoint Validators Execution
    for validator in registry.all_validators():
        key = validator.path.strip("/").replace("/", "_") or "root"
        url = urljoin(base + "/", validator.path.lstrip("/"))

        try:
            resp = client.get(url)
        except Exception as exc:
            ws.write(f"responses/{key}.error", str(exc))
            continue

        headers = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        ws.write(f"responses/{key}.body", resp.text)
        ws.write(f"headers/{key}.txt", headers)

        # Run pluggable content validator function
        result = validator.validator_fn(resp, baseline)

        if result.is_valid and result.validation_state in {ValidationState.confirmed, ValidationState.likely, ValidationState.potential}:
            findings.append(
                Finding(
                    id=f"web-{key}-{port}",
                    title=validator.title or f"Discovered {validator.path}",
                    category=validator.category,
                    severity=validator.severity,
                    confidence=result.confidence,
                    status=FindingStatus.verified if result.validation_state == ValidationState.confirmed else FindingStatus.suspected,
                    validation_state=result.validation_state,
                    target=target,
                    affected_asset=url,
                    protocol="tcp",
                    port=port,
                    source_tool="web-validator",
                    evidence=result.evidence,
                    artifacts=[f"responses/{key}.body", f"headers/{key}.txt"],
                    why_it_matters=result.why_it_matters,
                    recommended_next_action=result.recommended_next_action,
                    next_action=result.recommended_next_action,
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
