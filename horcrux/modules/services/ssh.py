from __future__ import annotations

import re
import socket
from horcrux.models import AuditEntry, AuditStatus, Finding, FindingStatus, Severity, Software, SubsystemState, ValidationState


def enumerate_ssh(ws, runner, target: str, port: int = 22) -> tuple[list[Finding], list[AuditEntry]]:
    """
    Enumerates SSH service: banner grab, software version extraction, cipher suite audit.
    """
    ws.set_subsystem_state("ssh_enum", SubsystemState.RUNNING)
    findings: list[Finding] = []
    audits: list[AuditEntry] = []
    software_items: list[Software] = []

    banner = ""
    try:
        with socket.create_connection((target, port), timeout=5.0) as s:
            raw = s.recv(1024)
            banner = raw.decode("utf-8", errors="replace").strip()
            ws.write(f"raw/ssh-banner-{port}.txt", banner)
    except Exception as exc:
        ws.write(f"raw/ssh-banner-{port}.error", str(exc))

    if banner.startswith("SSH-"):
        audits.append(
            AuditEntry(
                id=f"audit-ssh-banner-{port}",
                category="ssh-audit",
                asset=f"{target}:{port}",
                check_name="SSH Protocol Banner",
                status=AuditStatus.audited,
                evidence=[f"Banner: {banner}"],
                reason="SSH protocol handshake successfully initiated.",
            )
        )

        # Parse OpenSSH or vendor versions
        match = re.search(r"SSH-[0-9.]+-OpenSSH_([A-Za-z0-9_.-]+)", banner)
        if match:
            v = match.group(1)
            software_items.append(
                Software(
                    product="OpenSSH",
                    version=v,
                    service=f"{port}/tcp",
                    source="ssh-banner",
                    confidence=0.98,
                    evidence=[f"Raw SSH banner '{banner}' matches OpenSSH version {v}."],
                )
            )
            ws.upsert_software(software_items)

    # If Nmap is available, run ssh2-enum-algos to audit weak ciphers
    if runner.which("nmap"):
        res = runner.run(
            ["nmap", "-Pn", "-p", str(port), "--script", "ssh2-enum-algos", target],
            f"nmap-ssh-{port}",
            timeout=90,
        )
        if res and res.stdout:
            raw_ciphers = res.stdout
            weak_algos = []
            for weak in ["diffie-hellman-group1-sha1", "arcfour", "3des-cbc", "blowfish-cbc"]:
                if weak in raw_ciphers.lower():
                    weak_algos.append(weak)

            if weak_algos:
                findings.append(
                    Finding(
                        id=f"ssh-weak-ciphers-{port}",
                        title="Deprecated or Weak SSH Cryptographic Algorithms Supported",
                        category="cryptography",
                        severity=Severity.low,
                        confidence=0.95,
                        status=FindingStatus.verified,
                        validation_state=ValidationState.confirmed,
                        target=target,
                        affected_asset=f"{target}:{port}",
                        protocol="tcp",
                        port=port,
                        source_tool="nmap-ssh",
                        evidence=[f"SSH server accepts deprecated cryptographic algorithms: {', '.join(weak_algos)}"],
                        artifacts=[f"raw/nmap-ssh-{port}.stdout"],
                        why_it_matters="Legacy ciphers and key exchange algorithms are vulnerable to practical cryptographic downgrade and collision attacks.",
                        recommended_next_action="Remove legacy ciphers and KEX from /etc/ssh/sshd_config (e.g. Ciphers chacha20-poly1305,aes256-gcm).",
                        next_action="Remove legacy ciphers and KEX from /etc/ssh/sshd_config.",
                    )
                )
            else:
                audits.append(
                    AuditEntry(
                        id=f"audit-ssh-ciphers-{port}",
                        category="cryptography",
                        asset=f"{target}:{port}",
                        check_name="SSH Cipher Hardening Audit",
                        status=AuditStatus.hardened,
                        evidence=["No deprecated ciphers (arcfour, 3des, diffie-hellman-group1) accepted."],
                        reason="SSH daemon enforces modern cryptographic suites.",
                    )
                )

    if audits:
        ws.upsert_audits(audits)
    for f in findings:
        ws.upsert_finding(f)

    ws.set_subsystem_state("ssh_enum", SubsystemState.COMPLETE)
    return findings, audits
