from __future__ import annotations

import re
from horcrux.models import AuditEntry, AuditStatus, Finding, FindingStatus, Severity, SubsystemState, ValidationState


def enumerate_smb(ws, runner, target: str, port: int = 445) -> tuple[list[Finding], list[AuditEntry]]:
    """
    Executes SMB enumeration using netexec, crackmapexec, smbclient, and enum4linux-ng.
    Determines anonymous share access, null session validity, and signing requirements.
    """
    ws.set_subsystem_state("smb_enum", SubsystemState.RUNNING)
    findings: list[Finding] = []
    audits: list[AuditEntry] = []

    smb_anon_allowed = False
    shares_found: list[str] = []
    signing_required = None
    domain_name = ""
    os_info = ""

    # 1. NetExec or CrackMapExec
    tool_bin = "netexec" if runner.which("netexec") else ("crackmapexec" if runner.which("crackmapexec") else None)
    if tool_bin:
        res = runner.run([tool_bin, "smb", target, "-u", "''", "-p", "''", "--shares"], f"{tool_bin}-smb", timeout=120)
        if res and res.stdout:
            raw = res.stdout
            if "signing:False" in raw.lower():
                signing_required = False
            elif "signing:True" in raw.lower():
                signing_required = True

            if "READ" in raw or "WRITE" in raw:
                smb_anon_allowed = True
                for line in raw.splitlines():
                    if "READ" in line or "WRITE" in line:
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            shares_found.append(line.strip())

    # 2. smbclient fallback/direct check
    if runner.which("smbclient"):
        res = runner.run(["smbclient", "-L", f"//{target}/", "-N"], "smbclient", timeout=90)
        if res and res.stdout:
            raw = res.stdout
            if "Sharename" in raw or "Disk" in raw:
                smb_anon_allowed = True
                for line in raw.splitlines():
                    match = re.search(r"^\s+([A-Za-z0-9_$.-]+)\s+(?:Disk|IPC)", line)
                    if match:
                        shares_found.append(match.group(1))

    # 3. enum4linux-ng if available
    if runner.which("enum4linux-ng"):
        runner.run(["enum4linux-ng", "-A", "-u", "''", "-p", "''", target], "enum4linux-ng", timeout=180)

    # Findings & Audit evaluation
    if smb_anon_allowed:
        evidence_list = [f"Unauthenticated null session successfully enumerated SMB shares on port {port}."]
        if shares_found:
            evidence_list.append(f"Accessible shares: {', '.join(shares_found[:10])}")

        findings.append(
            Finding(
                id=f"smb-anon-access-{port}",
                title="Anonymous SMB Share Access Allowed",
                category="smb-security",
                severity=Severity.high,
                confidence=0.98,
                status=FindingStatus.verified,
                validation_state=ValidationState.confirmed,
                target=target,
                affected_asset=f"{target}:{port}",
                protocol="tcp",
                port=port,
                source_tool="smbclient",
                evidence=evidence_list,
                artifacts=["raw/smbclient.stdout", "raw/netexec-smb.stdout"],
                why_it_matters="Anonymous users can browse network file shares, potentially exposing proprietary code, backups, or credentials.",
                recommended_next_action="Inspect listed shares for readable sensitive files and disable anonymous SMB access.",
                next_action="Inspect listed shares for readable sensitive files and disable anonymous SMB access.",
                reproduction=[f"smbclient -L //{target}/ -N"],
            )
        )
    else:
        audits.append(
            AuditEntry(
                id=f"audit-smb-anon-{target}-{port}",
                category="smb",
                asset=f"{target}:{port}",
                check_name="SMB Anonymous Authentication",
                status=AuditStatus.hardened,
                evidence=["Anonymous null session rejected or restricted."],
                reason="SMB service requires valid authenticated domain or local credentials.",
            )
        )

    # SMB signing check
    if signing_required is False:
        findings.append(
            Finding(
                id=f"smb-signing-disabled-{port}",
                title="SMB Message Signing Disabled or Not Required",
                category="smb-security",
                severity=Severity.medium,
                confidence=0.95,
                status=FindingStatus.verified,
                validation_state=ValidationState.confirmed,
                target=target,
                affected_asset=f"{target}:{port}",
                protocol="tcp",
                port=port,
                source_tool=tool_bin or "smb",
                evidence=["SMB server accepts unsigned communication (signing:False)."],
                artifacts=["raw/netexec-smb.stdout"],
                why_it_matters="Enables adversary-in-the-middle (AiTM) attacks such as NTLM relaying to compromise elevated domain sessions.",
                recommended_next_action="Enforce 'RequireSecuritySignature = 1' via GPO on all domain hosts.",
                next_action="Enforce 'RequireSecuritySignature = 1' via GPO on all domain hosts.",
            )
        )
    elif signing_required is True:
        audits.append(
            AuditEntry(
                id=f"audit-smb-signing-{target}-{port}",
                category="smb",
                asset=f"{target}:{port}",
                check_name="SMB Message Signing",
                status=AuditStatus.hardened,
                evidence=["SMB server enforces cryptographic message signing."],
                reason="Protects against NTLM relay attacks.",
            )
        )

    if audits:
        ws.upsert_audits(audits)
    for f in findings:
        ws.upsert_finding(f)

    ws.set_subsystem_state("smb_enum", SubsystemState.COMPLETE)
    return findings, audits
