from __future__ import annotations

import re
from horcrux.models import AuditEntry, AuditStatus, Finding, FindingStatus, Severity, ValidationState


def run_nikto(ws, runner, target: str, port: int) -> tuple[list[Finding], list[AuditEntry]]:
    """
    Runs Nikto web scanner if installed on host.
    Captures raw output and parses relevant security observations.
    """
    if not runner.which("nikto"):
        return [], []

    scheme = "https" if port in {443, 8443} else "http"
    base_url = f"{scheme}://{target}:{port}"
    out_file = ws.raw / f"nikto-{port}.txt"

    res = runner.run(
        [
            "nikto",
            "-h", base_url,
            "-output", str(out_file),
            "-Format", "txt",
            "-Tuning", "1,2,3,4,8,9,0",
        ],
        f"nikto-{port}",
        timeout=600,
    )

    findings: list[Finding] = []
    audits: list[AuditEntry] = []

    if not out_file.exists():
        return findings, audits

    try:
        content = out_file.read_text(encoding="utf-8", errors="replace")
        for line in content.splitlines():
            line = line.strip()
            if not line.startswith("+ "):
                continue
            item = line[2:].strip()

            # Filter out generic noise / banner prints
            if any(ign in item.lower() for ign in ["target ip:", "target hostname:", "target port:", "start time:", "end time:"]):
                continue

            # Classify severity
            if any(kw in item.lower() for kw in ["vulnerable", "exploit", "remote code", "sql injection", "directory traversal"]):
                f = Finding(
                    id=f"nikto-{port}-{abs(hash(item)) % 100000}",
                    title=f"Nikto: {item[:60]}...",
                    category="web-vulnerability",
                    severity=Severity.high,
                    confidence=0.85,
                    status=FindingStatus.suspected,
                    validation_state=ValidationState.likely,
                    target=target,
                    affected_asset=base_url,
                    protocol="tcp",
                    port=port,
                    source_tool="nikto",
                    evidence=[item],
                    artifacts=[f"raw/nikto-{port}.txt"],
                    why_it_matters="Nikto identified potential web server vulnerability or misconfiguration.",
                    recommended_next_action="Perform manual reproduction and verify server configuration.",
                    next_action="Perform manual reproduction and verify server configuration.",
                )
                findings.append(f)
                ws.upsert_finding(f)
            else:
                aud = AuditEntry(
                    id=f"audit-nikto-{port}-{abs(hash(item)) % 100000}",
                    category="web-server-audit",
                    asset=base_url,
                    check_name="Nikto Observation",
                    status=AuditStatus.audited,
                    evidence=[item],
                    reason=item,
                )
                audits.append(aud)
    except Exception as exc:
        ws.write(f"raw/nikto-{port}.parse-error", str(exc))

    if audits:
        ws.upsert_audits(audits)

    return findings, audits
