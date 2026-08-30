from __future__ import annotations

from horcrux.models import Finding, FindingStatus, Severity, ValidationState


def enumerate_services(ws, runner, target: str):
    state = ws.load()
    ports = {s.port for s in state.services}
    findings = []

    if ports & {139, 445}:
        if runner.which("netexec"):
            runner.run(["netexec", "smb", target], "netexec-smb", timeout=180)
        elif runner.which("crackmapexec"):
            runner.run(["crackmapexec", "smb", target], "crackmapexec-smb", timeout=180)
        elif runner.which("smbclient"):
            runner.run(["smbclient", "-L", f"//{target}/", "-N"], "smbclient", timeout=120)

        if runner.which("enum4linux-ng"):
            runner.run(["enum4linux-ng", "-A", target], "enum4linux-ng", timeout=300)

        findings.append(
            Finding(
                id="smb-exposed",
                title="SMB service active",
                category="smb",
                severity=Severity.info,
                confidence=0.99,
                status=FindingStatus.verified,
                validation_state=ValidationState.confirmed,
                target=target,
                affected_asset=f"{target}:445",
                protocol="tcp",
                port=445 if 445 in ports else 139,
                source_tool="smb-enum",
                evidence=["TCP/139 and/or TCP/445 active with responding SMB listeners."],
                artifacts=[
                    "raw/netexec-smb.stdout",
                    "raw/smbclient.stdout",
                    "raw/enum4linux-ng.stdout",
                ],
                why_it_matters="SMB exposes network shares, user account names, domain membership, and authentication opportunities.",
                recommended_next_action="Inspect accessible shares, test anonymous/null sessions, and extract domain SID.",
                next_action="Inspect accessible shares, test anonymous/null sessions, and extract domain SID.",
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

        findings.append(
            Finding(
                id="ldap-exposed",
                title="Active Directory / LDAP RootDSE accessible",
                category="directory-services",
                severity=Severity.info,
                confidence=0.99,
                status=FindingStatus.verified,
                validation_state=ValidationState.confirmed,
                target=target,
                affected_asset=f"{target}:389",
                protocol="tcp",
                port=389 if 389 in ports else 636,
                source_tool="ldap-enum",
                evidence=["Responding LDAP listener detected."],
                artifacts=["raw/ldap-rootdse.stdout"],
                why_it_matters="LDAP RootDSE exposes forest naming contexts, domain functional level, and domain controller hostname.",
                recommended_next_action="Query naming contexts and extract Active Directory domain architecture details.",
                next_action="Query naming contexts and extract Active Directory domain architecture details.",
            )
        )

    if 88 in ports:
        findings.append(
            Finding(
                id="kerberos-exposed",
                title="Kerberos KDC exposed",
                category="active-directory",
                severity=Severity.info,
                confidence=0.99,
                status=FindingStatus.verified,
                validation_state=ValidationState.confirmed,
                target=target,
                affected_asset=f"{target}:88",
                protocol="tcp",
                port=88,
                source_tool="network",
                evidence=["TCP/88 detected."],
                why_it_matters="Indicates a Kerberos Key Distribution Center (Active Directory Domain Controller or realm).",
                recommended_next_action="Enumerate user accounts with Kerbrute and check for AS-REP Roastable accounts.",
                next_action="Enumerate user accounts with Kerbrute and check for AS-REP Roastable accounts.",
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
        runner.run(
            ["redis-cli", "-h", target, "INFO"],
            "redis-info",
            timeout=90,
        )

    return findings
