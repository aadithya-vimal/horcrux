from __future__ import annotations

import secrets
from urllib.parse import urljoin
import httpx

from horcrux.models import AuditEntry, AuditStatus, DiscoveredPath, Finding, FindingStatus, Severity, SubsystemState, ValidationState
from horcrux.modules.web.fuzzer import run_fuzzer
from horcrux.modules.web.validator import BaselineFingerprint, ValidatorRegistry, validate_generic_candidate


def run(ws, runner, target: str, port: int, strategy: str = "common") -> tuple[list[Finding], list[AuditEntry], list[DiscoveredPath]]:
    """
    Full web discovery and response validation pipeline.
    1. Runs best available discovery tool (ffuf/gobuster/feroxbuster/native).
    2. Runs EVERY discovered candidate path through the response validation engine.
    3. Emits validated findings for confirmed exposures; audited controls for safe/hardened pages; suppresses soft-404s.
    """
    ws.set_subsystem_state("web_discovery", SubsystemState.RUNNING)
    paths = run_fuzzer(ws, runner, target, port, strategy=strategy)
    ws.set_subsystem_state("web_discovery", SubsystemState.COMPLETE)

    ws.set_subsystem_state("web_validation", SubsystemState.RUNNING)

    scheme = "https" if port in {443, 8443} else "http"
    base_url = f"{scheme}://{target}:{port}"

    findings: list[Finding] = []
    audits: list[AuditEntry] = []
    registry = ValidatorRegistry()

    # 1. Establish or load baseline
    client = httpx.Client(verify=False, timeout=8.0, headers={"User-Agent": "Horcrux-Validator/1.0"})
    try:
        random_token = f"_horcrux_discovery_base_{secrets.token_hex(6)}"
        baseline_resp = client.get(urljoin(base_url + "/", random_token))
        baseline = BaselineFingerprint.analyze(baseline_resp)
    except Exception:
        baseline = BaselineFingerprint(
            status_code=404,
            content_length=0,
            content_type="",
            title="",
            body_hash="",
        )

    # 2. Validate each discovered path
    for p in paths:
        url = p.url
        clean_path = p.path

        try:
            resp = client.get(url)
        except Exception:
            continue

        # Check if a specialized validator exists in registry
        specific_validator = registry.get(clean_path)
        if specific_validator:
            res = specific_validator.validator_fn(resp, baseline)
            cat = specific_validator.category
            sev = specific_validator.severity
            title = specific_validator.title or f"Exposed {clean_path}"
        else:
            res = validate_generic_candidate(clean_path, resp, baseline)
            cat = "web-content-discovery"
            sev = Severity.medium if res.validation_state == ValidationState.confirmed else Severity.info
            title = f"Verified Sensitive Content in {clean_path}" if res.validation_state == ValidationState.confirmed else f"Live Surface: {clean_path}"

        p.validated = True
        p.validation_state = res.validation_state

        if res.is_valid and res.validation_state in {ValidationState.confirmed, ValidationState.likely, ValidationState.potential}:
            f = Finding(
                id=f"web-discovered-{clean_path.strip('/').replace('/', '_') or 'root'}-{port}",
                title=title,
                category=cat,
                severity=sev,
                confidence=res.confidence,
                status=FindingStatus.verified if res.validation_state == ValidationState.confirmed else FindingStatus.suspected,
                validation_state=res.validation_state,
                target=target,
                affected_asset=url,
                protocol="tcp",
                port=port,
                source_tool=p.source or "web-fuzzer",
                evidence=res.evidence,
                artifacts=[f"raw/{p.source}-{port}.json" if p.source == "ffuf" else f"raw/discovered-paths-{port}.json"],
                why_it_matters=res.why_it_matters or "Discovered accessible endpoint exposing sensitive data or functionality.",
                recommended_next_action=res.recommended_next_action or f"Inspect {clean_path} response body and restrict public access.",
                next_action=res.recommended_next_action or f"Inspect {clean_path} response body and restrict public access.",
                reproduction=[f"curl -k -s -i '{url}'"],
            )
            findings.append(f)
            ws.upsert_finding(f)
        else:
            # Audit entry for hardened/safe/soft-404
            aud = AuditEntry(
                id=f"audit-path-{clean_path.strip('/').replace('/', '_') or 'root'}-{port}",
                category=cat,
                asset=url,
                check_name=f"Fuzz candidate audit: {clean_path}",
                status=res.audit_status,
                evidence=res.evidence,
                reason=f"Tested {clean_path} (HTTP {resp.status_code}): {res.evidence[0] if res.evidence else 'Non-vulnerable response structure verified.'}",
            )
            audits.append(aud)

    if audits:
        ws.upsert_audits(audits)

    ws.upsert_discovered_paths(paths)
    ws.set_subsystem_state("web_validation", SubsystemState.COMPLETE)

    return findings, audits, paths
