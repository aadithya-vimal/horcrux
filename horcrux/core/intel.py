from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

from horcrux.core.runner import CommandRunner
from horcrux.intel.search import searchsploit_workspace
from horcrux.models import Finding, FindingStatus, Severity, ValidationState


def run_nuclei(ws, runner: CommandRunner, url: str) -> list[Finding]:
    """
    Executes targeted Nuclei scanning against target URL.
    Parses JSONL output and normalizes vulnerabilities into Finding models.
    """
    if not runner.which("nuclei"):
        return []

    parsed = urlparse(url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    out_file = ws.raw / f"nuclei-{port}.jsonl"

    runner.run(
        [
            "nuclei",
            "-u", url,
            "-jsonl",
            "-silent",
            "-t", "cves/,vulnerabilities/,exposures/,misconfiguration/",
            "-severity", "critical,high,medium,low",
            "-o", str(out_file),
        ],
        f"nuclei-{port}",
        timeout=1200,
    )

    findings: list[Finding] = []
    if not out_file.exists():
        return findings

    try:
        for line in out_file.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            data = json.loads(line)
            template_id = data.get("template-id", "nuclei-finding")
            info = data.get("info", {})
            name = info.get("name", template_id)
            raw_sev = str(info.get("severity", "info")).lower()
            matched_at = data.get("matched-at", url)
            curl_cmd = data.get("curl-command", "")
            extracted = data.get("extracted-results", [])

            classification = info.get("classification") or {}
            cve_field = classification.get("cve-id")
            cves: list[str] = []
            if isinstance(cve_field, list):
                cves = [str(c).upper() for c in cve_field if c]
            elif isinstance(cve_field, str) and cve_field:
                cves = [cve_field.upper()]
            if not cves and "cve-" in template_id.lower():
                cve_match = re.search(r"cve-\d{4}-\d{4,7}", template_id, re.I)
                if cve_match:
                    cves = [cve_match.group(0).upper()]

            cwe_field = classification.get("cwe-id")
            cwes: list[str] = []
            if isinstance(cwe_field, list):
                cwes = [str(c).upper() for c in cwe_field if c]
            elif isinstance(cwe_field, str) and cwe_field:
                cwes = [cwe_field.upper()]

            cvss_score = classification.get("cvss-score")
            try:
                cvss_val = float(cvss_score) if cvss_score is not None else None
            except (ValueError, TypeError):
                cvss_val = None
            cvss_vector = str(classification.get("cvss-metrics") or "")
            cpe = str(classification.get("cpe") or "")

            sev_map = {
                "critical": Severity.critical,
                "high": Severity.high,
                "medium": Severity.medium,
                "low": Severity.low,
                "info": Severity.info,
            }
            sev = sev_map.get(raw_sev, Severity.info)

            # Deterministic evidence adjudication (Defect F)
            # Confirmed ONLY when positive proof, extracted data, or explicit exploit verification exists
            matcher_name = str(data.get("matcher-name") or "").lower()
            has_proof = bool(extracted) or any(
                m in matcher_name for m in ("proof", "rce", "extract", "token", "secret", "passwd", "leak", "flag")
            )

            if has_proof:
                val_state = ValidationState.confirmed
                conf = 0.95
            elif sev in {Severity.critical, Severity.high}:
                val_state = ValidationState.likely
                conf = 0.85
            elif sev == Severity.medium:
                val_state = ValidationState.likely
                conf = 0.70
            else:
                val_state = ValidationState.potential
                conf = 0.50

            evidence_items = [f"Matched: {matched_at}"]
            if extracted:
                evidence_items.append(f"Extracted: {extracted}")
            if data.get("matcher-name"):
                evidence_items.append(f"Matcher: {data['matcher-name']}")

            f = Finding(
                id=f"nuclei-{template_id.replace('/', '-')}-{port}",
                title=name,
                category="nuclei-vulnerability",
                severity=sev,
                confidence=conf,
                status=FindingStatus.verified if val_state == ValidationState.confirmed else FindingStatus.suspected,
                validation_state=val_state,
                target=parsed.hostname or ws.target,
                affected_asset=matched_at,
                protocol="tcp",
                port=port,
                source_tool="nuclei",
                source_tools=["nuclei"],
                source_providers=["nuclei"],
                cves=cves,
                cwes=cwes,
                cvss=cvss_val,
                cvss_vector=cvss_vector,
                cpe=cpe,
                access_context="unauthenticated",
                exploitability_state="PUBLIC_EXPLOIT_AVAILABLE" if cves else "MANUAL_REVIEW",
                correlation_status="NATIVE",
                evidence=evidence_items,
                artifacts=[f"raw/nuclei-{port}.jsonl"],
                why_it_matters=info.get("description", "Nuclei template match confirms vulnerability or misconfiguration."),
                recommended_next_action="Remediate root cause indicated by Nuclei template reference.",
                next_action="Remediate root cause indicated by Nuclei template reference.",
                reproduction=[curl_cmd] if curl_cmd else [f"nuclei -u {url} -t {template_id}"],
            )
            findings.append(f)
            ws.upsert_finding(f)
    except Exception as exc:
        ws.write(f"raw/nuclei-{port}.parse-error", str(exc))

    return findings
