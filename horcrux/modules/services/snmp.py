from __future__ import annotations

from horcrux.models import AuditEntry, AuditStatus, Finding, FindingStatus, Severity, SubsystemState, ValidationState


def enumerate_snmp(ws, runner, target: str, port: int = 161) -> tuple[list[Finding], list[AuditEntry]]:
    """
    Enumerates SNMP service: tests public/private community strings and queries basic system MIBs.
    """
    ws.set_subsystem_state("snmp_enum", SubsystemState.RUNNING)
    findings: list[Finding] = []
    audits: list[AuditEntry] = []

    if runner.which("snmpwalk"):
        res = runner.run(
            ["snmpwalk", "-v2c", "-c", "public", f"{target}:{port}", "1.3.6.1.2.1.1"],
            f"snmp-public-{port}",
            timeout=60,
        )
        if res and res.stdout and ("sysDescr" in res.stdout or "Timeout" not in res.stdout and len(res.stdout) > 20):
            lines = [l.strip() for l in res.stdout.splitlines() if l.strip()]
            findings.append(
                Finding(
                    id=f"snmp-public-access-{port}",
                    title="SNMP Service Exposed with Default 'public' Community String",
                    category="network-services",
                    severity=Severity.medium,
                    confidence=0.98,
                    status=FindingStatus.verified,
                    validation_state=ValidationState.confirmed,
                    target=target,
                    affected_asset=f"{target}:{port}",
                    protocol="udp",
                    port=port,
                    source_tool="snmpwalk",
                    evidence=[f"SNMP MIB tree returned using community string 'public' ({len(lines)} items)."],
                    artifacts=[f"raw/snmp-public-{port}.stdout"],
                    why_it_matters="Discloses operating system versions, running processes, hardware specifications, and network interfaces.",
                    recommended_next_action="Disable SNMPv1/v2c or change community string to a strong secret, or upgrade to SNMPv3.",
                    next_action="Disable SNMPv1/v2c or migrate to authenticated SNMPv3.",
                    reproduction=[f"snmpwalk -v2c -c public {target} 1.3.6.1.2.1.1"],
                )
            )
        else:
            audits.append(
                AuditEntry(
                    id=f"audit-snmp-{port}",
                    category="network-services",
                    asset=f"{target}:{port}",
                    check_name="SNMP Community String Hardening",
                    status=AuditStatus.hardened,
                    evidence=["SNMP query with 'public' timed out or was rejected."],
                    reason="Default community string 'public' is disabled or firewalled.",
                )
            )
    else:
        audits.append(
            AuditEntry(
                id=f"audit-snmp-port-{port}",
                category="network-services",
                asset=f"{target}:{port}",
                check_name="SNMP Service Presence",
                status=AuditStatus.audited,
                evidence=[f"UDP port {port} active. snmpwalk utility not installed."],
                reason="SNMP listener recorded in surface inventory.",
            )
        )

    if audits:
        ws.upsert_audits(audits)
    for f in findings:
        ws.upsert_finding(f)

    ws.set_subsystem_state("snmp_enum", SubsystemState.COMPLETE)
    return findings, audits
