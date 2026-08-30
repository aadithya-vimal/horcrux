from __future__ import annotations

from horcrux.core.parsers import parse_nmap
from horcrux.models import Finding, FindingStatus, ScanProfile, Severity, ValidationState


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
    for service in services:
        if service.port == 23:
            findings.append(
                Finding(
                    id="telnet-exposed",
                    title="Telnet exposed",
                    category="network",
                    severity=Severity.medium,
                    confidence=0.99,
                    status=FindingStatus.verified,
                    validation_state=ValidationState.confirmed,
                    target=target,
                    affected_asset=f"{target}:23",
                    protocol=service.protocol,
                    port=23,
                    source_tool="nmap",
                    evidence=["TCP/23 is open; cleartext Telnet protocol in use."],
                    artifacts=["raw/nmap-tcp.xml"],
                    why_it_matters="Cleartext telnet protocol transmits credentials unencrypted over the network.",
                    recommended_next_action="Assess cleartext authentication and upgrade to SSH.",
                    next_action="Assess cleartext authentication and upgrade to SSH.",
                )
            )
        elif service.port == 21:
            findings.append(
                Finding(
                    id="ftp-exposed",
                    title="FTP exposed",
                    category="network",
                    severity=Severity.info,
                    confidence=0.99,
                    status=FindingStatus.verified,
                    validation_state=ValidationState.confirmed,
                    target=target,
                    affected_asset=f"{target}:21",
                    protocol=service.protocol,
                    port=21,
                    source_tool="nmap",
                    evidence=["TCP/21 is open."],
                    artifacts=["raw/nmap-tcp.xml"],
                    why_it_matters="FTP can allow anonymous access or cleartext password transmission.",
                    recommended_next_action="Check anonymous access and server capabilities.",
                    next_action="Check anonymous access and server capabilities.",
                )
            )

    return result, findings
