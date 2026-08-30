from __future__ import annotations

from horcrux.models import Finding, Severity


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
                title="SMB exposed",
                category="smb",
                severity=Severity.info,
                confidence=.99,
                target=target,
                evidence=["TCP/139 and/or TCP/445 detected."],
                artifacts=[
                    "raw/netexec-smb.stdout",
                    "raw/smbclient.stdout",
                    "raw/enum4linux-ng.stdout",
                ],
                next_action="Inspect shares, anonymous access, and domain information.",
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
                title="LDAP exposed",
                category="directory-services",
                severity=Severity.info,
                confidence=.99,
                target=target,
                evidence=["LDAP service detected."],
                artifacts=["raw/ldap-rootdse.stdout"],
                next_action="Inspect RootDSE and naming contexts.",
            )
        )

    if 88 in ports:
        findings.append(
            Finding(
                id="kerberos-exposed",
                title="Kerberos exposed",
                category="active-directory",
                severity=Severity.info,
                confidence=.99,
                target=target,
                evidence=["TCP/88 detected."],
                next_action="Enumerate the domain and SPN surface.",
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
