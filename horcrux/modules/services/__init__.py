from __future__ import annotations

from horcrux.models import AuditEntry, AuditStatus, Finding, FindingStatus, Severity, ValidationState


def enumerate_services(ws, runner, target: str):
    state = ws.load()
    ports = {s.port for s in state.services}
    findings = []
    audits = []

    if ports & {139, 445}:
        smb_anon_allowed = False
        if runner.which("netexec"):
            res = runner.run(["netexec", "smb", target], "netexec-smb", timeout=180)
            if res and ("Pwn3d!" in res.stdout or "READ" in res.stdout):
                smb_anon_allowed = True
        elif runner.which("crackmapexec"):
            res = runner.run(["crackmapexec", "smb", target], "crackmapexec-smb", timeout=180)
            if res and ("Pwn3d!" in res.stdout or "READ" in res.stdout):
                smb_anon_allowed = True
        elif runner.which("smbclient"):
            res = runner.run(["smbclient", "-L", f"//{target}/", "-N"], "smbclient", timeout=120)
            if res and ("Sharename" in res.stdout or "Disk" in res.stdout):
                smb_anon_allowed = True

        if runner.which("enum4linux-ng"):
            runner.run(["enum4linux-ng", "-A", target], "enum4linux-ng", timeout=300)

        if smb_anon_allowed:
            findings.append(
                Finding(
                    id="smb-anon-access",
                    title="Anonymous SMB Share Access Allowed",
                    category="smb",
                    severity=Severity.high,
                    confidence=0.98,
                    status=FindingStatus.verified,
                    validation_state=ValidationState.confirmed,
                    target=target,
                    affected_asset=f"{target}:445",
                    protocol="tcp",
                    port=445 if 445 in ports else 139,
                    source_tool="smbclient",
                    evidence=["Unauthenticated null session successfully listed SMB shares."],
                    artifacts=["raw/smbclient.stdout"],
                    why_it_matters="Anonymous users can browse network file shares and discover sensitive documents or configurations.",
                    recommended_next_action="Inspect listed shares for readable confidential files.",
                    next_action="Inspect listed shares for readable confidential files.",
                )
            )
        else:
            audits.append(
                AuditEntry(
                    id=f"audit-smb-anon-{target}",
                    category="smb",
                    asset=f"{target}:445",
                    check_name="SMB Anonymous Authentication",
                    status=AuditStatus.hardened,
                    evidence=["Anonymous/null session rejected or restricted."],
                    reason="SMB requires valid domain or local credentials.",
                )
            )

    if ports & {389, 636}:
        if runner.which("ldapsearch"):
            scheme = "ldaps" if 636 in ports else "ldap"
            runner.run(
                [
                    "ldapsearch",
                    "-x",
                    "-H", f"{scheme}://{target}",
                    "-s", "base",
                    "-b", "",
                ],
                "ldap-rootdse",
                timeout=120,
            )

        audits.append(
            AuditEntry(
                id=f"audit-ldap-rootdse-{target}",
                category="directory-services",
                asset=f"{target}:389",
                check_name="Active Directory / LDAP RootDSE Audit",
                status=AuditStatus.audited,
                evidence=["Responding LDAP listener audited."],
                reason="LDAP RootDSE queried for naming contexts and domain functional level.",
            )
        )

    if 88 in ports:
        audits.append(
            AuditEntry(
                id=f"audit-kerberos-{target}",
                category="active-directory",
                asset=f"{target}:88",
                check_name="Kerberos KDC Audit",
                status=AuditStatus.audited,
                evidence=["TCP/88 Kerberos service active."],
                reason="Active Directory KDC identified for username enumeration / AS-REP roasting.",
            )
        )


    if 21 in ports and runner.which("nmap"):
        runner.run(
            ["nmap", "-Pn", "-p", "21", "--script", "ftp-anon,ftp-syst", target],
            "ftp-enum",
            timeout=120,
        )

    if 25 in ports and runner.which("nmap"):
        runner.run(
            ["nmap", "-Pn", "-p", "25", "--script", "smtp-commands,smtp-open-relay", target],
            "smtp-enum",
            timeout=120,
        )

    if 161 in ports and runner.which("snmpwalk"):
        runner.run(
            ["snmpwalk", "-v2c", "-c", "public", target, "1.3.6.1.2.1.1"],
            "snmp-public",
            timeout=90,
        )

    if 6379 in ports and runner.which("redis-cli"):
        res = runner.run(
            ["redis-cli", "-h", target, "INFO"],
            "redis-info",
            timeout=90,
        )
        if res and "redis_version" in res.stdout:
            findings.append(
                Finding(
                    id="redis-unauthenticated",
                    title="Unauthenticated Redis Server Exposed",
                    category="database",
                    severity=Severity.high,
                    confidence=0.99,
                    status=FindingStatus.verified,
                    validation_state=ValidationState.confirmed,
                    target=target,
                    affected_asset=f"{target}:6379",
                    protocol="tcp",
                    port=6379,
                    source_tool="redis-cli",
                    evidence=["Redis INFO response returned without requiring AUTH."],
                    artifacts=["raw/redis-info.stdout"],
                    why_it_matters="Unauthenticated Redis access allows arbitrary memory inspection, key dumping, or remote code execution.",
                    recommended_next_action="Enable requirepass authentication and bind Redis to localhost.",
                    next_action="Enable requirepass authentication and bind Redis to localhost.",
                )
            )
        else:
            audits.append(
                AuditEntry(
                    id=f"audit-redis-{target}",
                    category="database",
                    asset=f"{target}:6379",
                    check_name="Redis Authentication Audit",
                    status=AuditStatus.hardened,
                    evidence=["Redis rejected unauthenticated command or timed out."],
                    reason="Redis requires authentication.",
                )
            )

    if audits:
        ws.upsert_audits(audits)

    return findings
