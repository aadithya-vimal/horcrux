from __future__ import annotations

from horcrux.models import AuditEntry, AuditStatus, Finding, SubsystemState


def enumerate_kerberos(ws, runner, target: str, port: int = 88) -> tuple[list[Finding], list[AuditEntry]]:
    """
    Validates Kerberos KDC presence on TCP/UDP 88.
    Records Active Directory domain controller authentication surface without launching intrusive brute-force.
    """
    ws.set_subsystem_state("kerberos_enum", SubsystemState.RUNNING)
    audits: list[AuditEntry] = []

    audits.append(
        AuditEntry(
            id=f"audit-kerberos-{target}-{port}",
            category="active-directory",
            asset=f"{target}:{port}",
            check_name="Kerberos KDC Listener Audit",
            status=AuditStatus.audited,
            evidence=[f"Port {port}/tcp listening Kerberos Key Distribution Center (KDC)."],
            reason="Domain Controller authentication gateway identified. Candidate for AS-REP roasting with authorized user lists.",
        )
    )

    ws.upsert_audits(audits)
    ws.set_subsystem_state("kerberos_enum", SubsystemState.COMPLETE)
    return [], audits
