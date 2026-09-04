from __future__ import annotations

import secrets
from urllib.parse import urljoin
import httpx

from horcrux.models import (
    AuditEntry,
    AuditStatus,
    BaselineClassification,
    DiscoveredPath,
    EvidenceClassification,
    Finding,
    FindingStatus,
    ModuleDecision,
    Severity,
    SubsystemState,
    ValidationState,
    WebApplicationType,
    WebTarget,
)
from horcrux.modules.web.baseline import detect_baseline
from horcrux.modules.web.fuzzer import run_fuzzer
from horcrux.modules.web.js_analyzer import analyze_javascript_and_routes
from horcrux.modules.web.validator import (
    BaselineFingerprint,
    ValidatorRegistry,
    validate_generic_candidate,
)


def run(
    ws,
    runner,
    target: str,
    port: int,
    strategy: str = "common",
) -> tuple[list[Finding], list[AuditEntry], list[DiscoveredPath]]:
    """
    Evidence-gated web discovery and response validation pipeline.
    1. Multi-probe baseline detection establishes soft-404 / SPA fallback behavior.
    2. Identifies web application type (SPA, API, Traditional, Static).
    3. If SPA is detected, prioritizes JavaScript bundle analysis and API route extraction.
    4. Executes fuzzer with baseline suppression, removing catch-all noise from attack surface.
    5. Validates candidate endpoints against baseline; emits findings only for confirmed exposures.
    6. Isolates service state into an independent service-scoped WebTarget.
    """
    scheme = "https" if port in {443, 8443} else "http"
    base_url = f"{scheme}://{target}:{port}"

    client = httpx.Client(
        verify=False,
        timeout=8.0,
        headers={"User-Agent": "Horcrux-Validator/1.0"},
    )

    # 1. Establish Multi-Probe HTTP Baseline & Web App Classification
    base_class, base_fps, app_type = detect_baseline(client, base_url)

    web_target = ws.load().get_web_target(port) or WebTarget(
        scheme=scheme,
        host=target,
        port=port,
        base_url=base_url,
        service_identifier=f"{scheme}-{port}",
    )
    web_target.baseline_classification = base_class
    web_target.baseline_fingerprints = base_fps
    web_target.application_type = app_type

    # 2. SPA-Aware Discovery: Prioritize JavaScript Analysis if SPA
    js_candidate_paths: list[DiscoveredPath] = []
    if app_type == WebApplicationType.SPA or base_class == BaselineClassification.SPA_FALLBACK:
        web_target.module_decisions.append(
            ModuleDecision(
                module="js_analyzer",
                status="EXECUTED",
                reason="SPA architecture detected; prioritized client-side route, API, and parameter discovery.",
            )
        )
        try:
            root_resp = client.get(base_url, timeout=6.0)
            if root_resp.status_code == 200:
                js_candidate_paths, extracted_params, js_obs = analyze_javascript_and_routes(
                    client, base_url, root_resp.text
                )
                web_target.parameters.extend(extracted_params)
                ws.add_parameters(extracted_params)
                ws.add_raw_observations(js_obs)
        except Exception:
            pass

    # 3. Content Fuzzing with Baseline Noise Suppression
    ws.set_subsystem_state("web_discovery", SubsystemState.RUNNING)
    if base_class == BaselineClassification.SPA_FALLBACK and strategy == "quickhits":
        web_target.module_decisions.append(
            ModuleDecision(
                module="traditional_bruteforce",
                status="SKIPPED",
                reason="SPA fallback detected; aggressive status-code brute-forcing suppressed to prevent duplicate noise.",
            )
        )
        fuzzer_paths: list[DiscoveredPath] = []
    else:
        fuzzer_paths = run_fuzzer(
            ws,
            runner,
            target,
            port,
            strategy=strategy,
            baseline_fps=base_fps,
        )
        web_target.module_decisions.append(
            ModuleDecision(
                module="fuzzer",
                status="EXECUTED",
                reason="Executed wordlist-guided content discovery with response-family clustering.",
            )
        )
    ws.set_subsystem_state("web_discovery", SubsystemState.COMPLETE)

    # Combine unique candidates (JS routes + clean fuzzer paths)
    combined_paths: list[DiscoveredPath] = []
    seen_urls: set[str] = set()
    for p in js_candidate_paths + fuzzer_paths:
        if p.url not in seen_urls:
            seen_urls.add(p.url)
            combined_paths.append(p)

    # 4. Endpoint Validation Pipeline
    ws.set_subsystem_state("web_validation", SubsystemState.RUNNING)
    findings: list[Finding] = []
    audits: list[AuditEntry] = []
    registry = ValidatorRegistry()

    # Create baseline fingerprint for validator backward compatibility
    primary_base = base_fps[0] if base_fps else None
    baseline = BaselineFingerprint(
        status_code=primary_base.status_code if primary_base else 404,
        content_length=primary_base.normalized_body_length if primary_base else 0,
        content_type=primary_base.content_type if primary_base else "",
        title=primary_base.title if primary_base else "",
        body_hash=primary_base.normalized_body_hash if primary_base else "",
        is_spa=base_class == BaselineClassification.SPA_FALLBACK,
    )

    for p in combined_paths:
        # Never validate or emit findings for suppressed fallback noise
        if p.evidence_classification == EvidenceClassification.SUPPRESSED_FALLBACK:
            continue

        url = p.url
        clean_path = p.path

        try:
            resp = client.get(url, timeout=6.0)
        except Exception:
            continue

        specific_validator = registry.get(clean_path)
        if specific_validator:
            res = specific_validator.validator_fn(resp, baseline)
            cat = specific_validator.category
            sev = specific_validator.severity
            title = specific_validator.title or f"Exposed {clean_path}"
        else:
            res = validate_generic_candidate(clean_path, resp, baseline)
            cat = "web-content-discovery"
            sev = (
                Severity.medium
                if res.validation_state == ValidationState.confirmed
                else Severity.info
            )
            title = (
                f"Verified Sensitive Content in {clean_path}"
                if res.validation_state == ValidationState.confirmed
                else f"Live Surface: {clean_path}"
            )

        p.validated = True
        p.validation_state = res.validation_state
        if res.is_valid and res.validation_state in {
            ValidationState.confirmed,
            ValidationState.likely,
            ValidationState.potential,
        }:
            p.evidence_classification = EvidenceClassification.VALIDATED

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
                artifacts=[f"raw/discovered-paths-{port}.json"],
                why_it_matters=res.why_it_matters or "Discovered accessible endpoint exposing functionality or data.",
                recommended_next_action=res.recommended_next_action or f"Inspect {clean_path} response and verify authorization controls.",
                next_action=res.recommended_next_action or f"Inspect {clean_path} response and verify authorization controls.",
                reproduction=[f"curl -k -s -i '{url}'"],
            )
            findings.append(f)
            ws.upsert_finding(f)
        else:
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

    # 5. Persist isolated WebTarget state
    web_target.endpoints = combined_paths
    web_target.findings = findings
    ws.upsert_web_target(web_target)
    ws.upsert_discovered_paths(combined_paths)
    ws.set_subsystem_state("web_validation", SubsystemState.COMPLETE)

    return findings, audits, combined_paths

