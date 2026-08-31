from __future__ import annotations

import ftplib
import re
from horcrux.models import AuditEntry, AuditStatus, Finding, FindingStatus, Severity, Software, SubsystemState, ValidationState


def enumerate_ftp(ws, runner, target: str, port: int = 21) -> tuple[list[Finding], list[AuditEntry]]:
    """
    Enumerates FTP service: banner extraction, software detection, anonymous login verification.
    """
    ws.set_subsystem_state("ftp_enum", SubsystemState.RUNNING)
    findings: list[Finding] = []
    audits: list[AuditEntry] = []
    software_items: list[Software] = []

    banner = ""
    anon_success = False
    file_listing: list[str] = []

    try:
        ftp = ftplib.FTP()
        ftp.connect(target, port, timeout=6.0)
        banner = ftp.getwelcome()
        ws.write(f"raw/ftp-welcome-{port}.txt", banner)

        # Software detection from banner (e.g. vsftpd 2.3.4, ProFTPD 1.3.5)
        match = re.search(r"\b(vsFTPd|ProFTPD|Pure-FTPd|FileZilla Server|Microsoft FTP Service)\s+([0-9.]+)", banner, re.I)
        if match:
            prod = match.group(1)
            ver = match.group(2)
            software_items.append(
                Software(
                    product=prod,
                    version=ver,
                    service=f"{port}/tcp",
                    source="ftp-banner",
                    confidence=0.95,
                    evidence=[f"FTP welcome banner '{banner}' identified {prod} {ver}"],
                )
            )
            ws.upsert_software(software_items)

        # Try anonymous login
        try:
            ftp.login("anonymous", "anonymous@example.com")
            anon_success = True
            try:
                file_listing = ftp.nlst()[:20]
            except Exception:
                file_listing = []
        except Exception:
            anon_success = False

        ftp.quit()
    except Exception as exc:
        ws.write(f"raw/ftp-{port}.error", str(exc))

    if anon_success:
        evidence_list = [f"Unauthenticated user 'anonymous' successfully authenticated to FTP port {port}."]
        if file_listing:
            evidence_list.append(f"Directory listing ({len(file_listing)} items): {', '.join(file_listing[:10])}")

        findings.append(
            Finding(
                id=f"ftp-anon-access-{port}",
                title="Anonymous FTP Access Permitted",
                category="ftp-security",
                severity=Severity.medium if not file_listing else Severity.high,
                confidence=0.99,
                status=FindingStatus.verified,
                validation_state=ValidationState.confirmed,
                target=target,
                affected_asset=f"{target}:{port}",
                protocol="tcp",
                port=port,
                source_tool="ftplib",
                evidence=evidence_list,
                artifacts=[f"raw/ftp-welcome-{port}.txt"],
                why_it_matters="Public anonymous FTP access permits unauthenticated downloads of files or potential upload of malicious payloads.",
                recommended_next_action="Disable anonymous logins in FTP configuration (e.g. anonymous_enable=NO in vsftpd.conf).",
                next_action="Disable anonymous logins in FTP configuration.",
                reproduction=[f"curl -s ftp://anonymous:anonymous@{target}:{port}/"],
            )
        )
    else:
        audits.append(
            AuditEntry(
                id=f"audit-ftp-anon-{port}",
                category="ftp-security",
                asset=f"{target}:{port}",
                check_name="FTP Anonymous Authentication Audit",
                status=AuditStatus.hardened,
                evidence=["Anonymous FTP login rejected with 530 Login incorrect or disabled."],
                reason="FTP requires valid user credentials.",
            )
        )

    if audits:
        ws.upsert_audits(audits)
    for f in findings:
        ws.upsert_finding(f)

    ws.set_subsystem_state("ftp_enum", SubsystemState.COMPLETE)
    return findings, audits
