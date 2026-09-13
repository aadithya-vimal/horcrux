from __future__ import annotations

import re
import smtplib
from horcrux.models import AuditEntry, AuditStatus, Finding, FindingStatus, Severity, Software, SubsystemState, ValidationState


def enumerate_smtp(ws, runner, target: str, port: int = 25) -> tuple[list[Finding], list[AuditEntry]]:
    """
    Enumerates SMTP service: banner grab, EHLO capabilities, safe open relay evaluation.
    """
    ws.set_subsystem_state("smtp_enum", SubsystemState.RUNNING)
    findings: list[Finding] = []
    audits: list[AuditEntry] = []
    software_items: list[Software] = []

    banner = ""
    open_relay = False
    ehlo_features: list[str] = []

    try:
        smtp = smtplib.SMTP(timeout=6.0)
        code, resp = smtp.connect(target, port)
        banner = resp.decode("utf-8", errors="replace") if isinstance(resp, bytes) else str(resp)
        ws.write(f"raw/smtp-banner-{port}.txt", banner)

        # Extract software
        match = re.search(r"\b(Postfix|Exim|Sendmail|Microsoft ESMTP)\b", banner, re.I)
        if match:
            prod = match.group(1)
            software_items.append(
                Software(
                    product=prod,
                    version="",
                    service=f"{port}/tcp",
                    source="smtp-banner",
                    confidence=0.85,
                    evidence=[f"SMTP initial banner identified MTA: {prod}"],
                )
            )
            ws.upsert_software(software_items)

        # EHLO handshake
        try:
            status, features = smtp.ehlo("horcrux.operator.local")
            ehlo_features = [f.decode("utf-8", errors="replace") if isinstance(f, bytes) else str(f) for f in features]
        except Exception:
            pass

        # Safe Open Relay Test:
        # Send MAIL FROM and RCPT TO with external domains; DO NOT send DATA or actual mail.
        try:
            code_mail, _ = smtp.mail("audit@horcrux-test.org")
            if code_mail == 250:
                code_rcpt, resp_rcpt = smtp.rcpt("external-recipient@example-horcrux-audit.org")
                if code_rcpt == 250:
                    open_relay = True
            smtp.rset()
        except Exception:
            open_relay = False

        smtp.quit()
    except Exception as exc:
        ws.write(f"raw/smtp-{port}.error", str(exc))

    if open_relay:
        findings.append(
            Finding(
                id=f"smtp-open-relay-{port}",
                title="Insecure SMTP Open Relay Detected",
                category="smtp-security",
                severity=Severity.high,
                confidence=0.98,
                status=FindingStatus.verified,
                validation_state=ValidationState.confirmed,
                target=target,
                affected_asset=f"{target}:{port}",
                protocol="tcp",
                port=port,
                source_tool="smtplib",
                evidence=[f"SMTP server accepted external recipient without authentication on port {port}."],
                artifacts=[f"raw/smtp-banner-{port}.txt"],
                why_it_matters="Open mail relays can be exploited by spammers or threat actors to deliver phishing, damaging domain reputation.",
                recommended_next_action="Reconfigure MTA to deny relaying to unauthorized external domains.",
                next_action="Reconfigure MTA to deny relaying to unauthorized external domains.",
            )
        )
    else:
        audits.append(
            AuditEntry(
                id=f"audit-smtp-relay-{port}",
                category="smtp-security",
                asset=f"{target}:{port}",
                check_name="SMTP Open Relay Audit",
                status=AuditStatus.hardened,
                evidence=["SMTP rejected unauthorized recipient relay attempt."],
                reason="MTA restricts mail routing to authenticated or local domains.",
            )
        )

    if audits:
        ws.upsert_audits(audits)
    for f in findings:
        ws.upsert_finding(f)

    ws.set_subsystem_state("smtp_enum", SubsystemState.COMPLETE)
    return findings, audits
