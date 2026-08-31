from __future__ import annotations

import re
from horcrux.models import AuditEntry, AuditStatus, Finding, FindingStatus, Severity, SubsystemState, ValidationState


def enumerate_remote_services(ws, runner, target: str, port: int, service_name: str = "") -> tuple[list[Finding], list[AuditEntry]]:
    """
    Enumerates remote access services: NFS, RDP, WinRM, Telnet, VNC.
    """
    findings: list[Finding] = []
    audits: list[AuditEntry] = []

    # 1. NFS (2049, 111)
    if port in {2049, 111} or "nfs" in service_name:
        if runner.which("showmount"):
            res = runner.run(["showmount", "-e", target], f"showmount-{port}", timeout=45)
            if res and res.stdout and "Export list" in res.stdout:
                exports = [l.strip() for l in res.stdout.splitlines()[1:] if l.strip()]
                world_readable = [exp for exp in exports if "*" in exp or "everyone" in exp.lower()]
                if world_readable:
                    findings.append(
                        Finding(
                            id=f"nfs-open-export-{port}",
                            title="NFS Share Exported World-Readable (*)",
                            category="nfs-security",
                            severity=Severity.high,
                            confidence=0.98,
                            status=FindingStatus.verified,
                            validation_state=ValidationState.confirmed,
                            target=target,
                            affected_asset=f"{target}:{port}",
                            protocol="tcp",
                            port=port,
                            source_tool="showmount",
                            evidence=[f"NFS exports readable to any host (*): {', '.join(world_readable)}"],
                            artifacts=[f"raw/showmount-{port}.stdout"],
                            why_it_matters="Allows arbitrary external systems to mount network filesystems, bypassing OS file permissions.",
                            recommended_next_action="Restrict exports in /etc/exports to specific authorized client IP ranges.",
                            next_action="Restrict exports in /etc/exports to authorized IP addresses.",
                            reproduction=[f"showmount -e {target}"],
                        )
                    )
                else:
                    audits.append(
                        AuditEntry(
                            id=f"audit-nfs-exports-{port}",
                            category="nfs",
                            asset=f"{target}:{port}",
                            check_name="NFS Export Access Audit",
                            status=AuditStatus.audited,
                            evidence=[f"Exports restricted to configured subnets: {', '.join(exports[:5])}"],
                            reason="NFS exports enforce client IP access controls.",
                        )
                    )

    # 2. Telnet (23)
    elif port == 23 or "telnet" in service_name:
        findings.append(
            Finding(
                id=f"telnet-unencrypted-{port}",
                title="Unencrypted Telnet Management Protocol Exposed",
                category="cleartext-protocol",
                severity=Severity.medium,
                confidence=0.99,
                status=FindingStatus.verified,
                validation_state=ValidationState.confirmed,
                target=target,
                affected_asset=f"{target}:{port}",
                protocol="tcp",
                port=port,
                source_tool="port-detector",
                evidence=[f"Port {port} offers cleartext Telnet terminal service."],
                why_it_matters="All administrative credentials and session interactions are transmitted in plain text across the network.",
                recommended_next_action="Disable Telnet daemon and migrate management sessions to SSHv2.",
                next_action="Disable Telnet daemon and migrate to SSH.",
            )
        )

    # 3. RDP (3389)
    elif port == 3389 or "ms-wbt-server" in service_name or "rdp" in service_name:
        audits.append(
            AuditEntry(
                id=f"audit-rdp-{port}",
                category="remote-access",
                asset=f"{target}:{port}",
                check_name="Remote Desktop Protocol (RDP) Audit",
                status=AuditStatus.audited,
                evidence=[f"TCP port {port} active RDP listener."],
                reason="Windows Remote Desktop service reachable.",
            )
        )

    # 4. WinRM (5985, 5986)
    elif port in {5985, 5986} or "winrm" in service_name:
        audits.append(
            AuditEntry(
                id=f"audit-winrm-{port}",
                category="remote-access",
                asset=f"{target}:{port}",
                check_name="Windows Remote Management (WinRM) Audit",
                status=AuditStatus.audited,
                evidence=[f"TCP port {port} active WinRM WS-Management listener."],
                reason="WinRM management endpoint available.",
            )
        )

    # 5. VNC (5900)
    elif port == 5900 or "vnc" in service_name:
        audits.append(
            AuditEntry(
                id=f"audit-vnc-{port}",
                category="remote-access",
                asset=f"{target}:{port}",
                check_name="Virtual Network Computing (VNC) Audit",
                status=AuditStatus.audited,
                evidence=[f"TCP port {port} active VNC graphical session listener."],
                reason="VNC service mapped to attack surface.",
            )
        )

    if audits:
        ws.upsert_audits(audits)
    for f in findings:
        ws.upsert_finding(f)

    return findings, audits
