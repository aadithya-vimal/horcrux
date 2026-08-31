from __future__ import annotations

import re
from horcrux.models import AuditEntry, AuditStatus, Finding, FindingStatus, Severity, SubsystemState, ValidationState


def enumerate_dns(ws, runner, target: str, port: int = 53) -> tuple[list[Finding], list[AuditEntry]]:
    """
    Enumerates DNS service: standard record queries and zone transfer (AXFR) vulnerability checks.
    """
    ws.set_subsystem_state("dns_enum", SubsystemState.RUNNING)
    findings: list[Finding] = []
    audits: list[AuditEntry] = []

    out_file = ws.raw / f"dns-enum-{port}.txt"

    # Zone transfer test if dig is available
    if runner.which("dig"):
        res = runner.run(["dig", f"@{target}", "-p", str(port), "ANY", target], f"dig-any-{port}", timeout=45)
        axfr_res = runner.run(["dig", f"@{target}", "-p", str(port), "AXFR", target], f"dig-axfr-{port}", timeout=45)

        if axfr_res and axfr_res.stdout and "Transfer failed" not in axfr_res.stdout and "connection refused" not in axfr_res.stdout:
            records = [l for l in axfr_res.stdout.splitlines() if not l.startswith(";") and l.strip()]
            if len(records) > 3:
                findings.append(
                    Finding(
                        id=f"dns-zone-transfer-{port}",
                        title="Unrestricted DNS Zone Transfer (AXFR) Allowed",
                        category="dns-security",
                        severity=Severity.high,
                        confidence=0.99,
                        status=FindingStatus.verified,
                        validation_state=ValidationState.confirmed,
                        target=target,
                        affected_asset=f"{target}:{port}",
                        protocol="tcp",
                        port=port,
                        source_tool="dig",
                        evidence=[f"AXFR query successfully dumped {len(records)} DNS zone records."],
                        artifacts=[f"raw/dig-axfr-{port}.stdout"],
                        why_it_matters="Discloses complete internal network topology, server names, IP addresses, and mail routes.",
                        recommended_next_action="Restrict zone transfers in named.conf / BIND to authorized secondary nameservers.",
                        next_action="Restrict zone transfers in named.conf to authorized nameservers.",
                    )
                )
            else:
                audits.append(
                    AuditEntry(
                        id=f"audit-dns-axfr-{port}",
                        category="dns-security",
                        asset=f"{target}:{port}",
                        check_name="DNS Zone Transfer (AXFR) Audit",
                        status=AuditStatus.hardened,
                        evidence=["AXFR zone transfer rejected or refused."],
                        reason="DNS server restricts zone transfers.",
                    )
                )
        else:
            audits.append(
                AuditEntry(
                    id=f"audit-dns-axfr-{port}",
                    category="dns-security",
                    asset=f"{target}:{port}",
                    check_name="DNS Zone Transfer (AXFR) Audit",
                    status=AuditStatus.hardened,
                    evidence=["AXFR query refused or failed."],
                    reason="DNS nameserver properly denies anonymous AXFR zone transfers.",
                )
            )
    else:
        audits.append(
            AuditEntry(
                id=f"audit-dns-port-{port}",
                category="dns",
                asset=f"{target}:{port}",
                check_name="DNS Service Surface Audit",
                status=AuditStatus.audited,
                evidence=[f"Port {port} active DNS nameserver."],
                reason="DNS service mapped to attack surface.",
            )
        )

    if audits:
        ws.upsert_audits(audits)
    for f in findings:
        ws.upsert_finding(f)

    ws.set_subsystem_state("dns_enum", SubsystemState.COMPLETE)
    return findings, audits
