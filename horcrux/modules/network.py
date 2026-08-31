from __future__ import annotations

from horcrux.core.parsers import parse_nmap
from horcrux.models import AuditEntry, AuditStatus, Finding, FindingStatus, ScanProfile, Severity, ValidationState


def run_network(ws, runner, target: str, profile: ScanProfile | None = None, deep: bool = False):
    xml = ws.root / "raw" / "nmap.xml"

    # Profile port spec evaluation
    if profile:
        deep = profile.port_spec == "full" or deep
        timeout = profile.command_timeout
        include_udp = profile.include_udp
        udp_count = profile.udp_port_count
    else:
        timeout = 900 if deep else 450
        include_udp = not deep
        udp_count = 50

    tcp_args = [
        "nmap",
        "-Pn",
        "-sC",
        "-sV",
        "-oX",
        str(xml),
    ]

    if deep or (profile and profile.port_spec == "full"):
        tcp_args += ["-p-"]
    elif profile and profile.port_spec == "top100":
        tcp_args += ["--top-ports", "100"]
    else:
        tcp_args += ["--top-ports", "1000"]

    tcp_args += [target]

    result = runner.run(
        tcp_args,
        "nmap-tcp",
        timeout=timeout,
    )

    services, software = parse_nmap(
        xml.read_text(encoding="utf-8", errors="replace") if xml.exists() else "",
        target,
    )

    ws.upsert_services(services)
    ws.upsert_software(software)

    if include_udp:
        runner.run(
            [
                "nmap", "-Pn", "-sU", f"--top-ports", str(udp_count),
                "--version-light", target,
            ],
            "nmap-udp",
            timeout=timeout,
        )

    findings = []
    audits = []
    for service in services:
        if service.port == 23:
            audits.append(
                AuditEntry(
                    id=f"audit-telnet-{target}",
                    category="network-protocol",
                    asset=f"{target}:23",
                    check_name="Telnet Cleartext Protocol Audit",
                    status=AuditStatus.suspicious,
                    evidence=["TCP/23 Telnet is active; cleartext protocol transmits credentials unencrypted."],
                    reason="Legacy cleartext protocol detected on network perimeter.",
                )
            )
        elif service.port == 21:
            audits.append(
                AuditEntry(
                    id=f"audit-ftp-{target}",
                    category="network-protocol",
                    asset=f"{target}:21",
                    check_name="FTP Service Audit",
                    status=AuditStatus.audited,
                    evidence=["TCP/21 FTP service active."],
                    reason="FTP service exposed for enumeration.",
                )
            )

    if audits:
        ws.upsert_audits(audits)

    return result, findings

