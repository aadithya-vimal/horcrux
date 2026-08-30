from __future__ import annotations

from horcrux.core.parsers import parse_nmap
from horcrux.models import Finding, Severity


def run_network(ws, runner, target: str, deep: bool = False):
    xml = ws.root / "raw" / "nmap.xml"

    tcp_args = [
        "nmap",
        "-Pn",
        "-sC",
        "-sV",
        "-oX",
        str(xml),
    ]

    if deep:
        tcp_args += ["-p-"]
    else:
        tcp_args += ["--top-ports", "1000"]

    tcp_args += [target]

    result = runner.run(
        tcp_args,
        "nmap-tcp",
        timeout=900 if deep else 450,
    )

    services, software = parse_nmap(
        xml.read_text(encoding="utf-8", errors="replace") if xml.exists() else "",
        target,
    )

    ws.upsert_services(services)
    ws.upsert_software(software)

    if not deep:
        runner.run(
            [
                "nmap", "-Pn", "-sU", "--top-ports", "50",
                "--version-light", target,
            ],
            "nmap-udp",
            timeout=450,
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
                    confidence=.99,
                    target=target,
                    evidence=["TCP/23 is open."],
                    artifacts=["raw/nmap-tcp.xml"],
                    next_action="Assess cleartext authentication and configuration.",
                )
            )
        elif service.port == 21:
            findings.append(
                Finding(
                    id="ftp-exposed",
                    title="FTP exposed",
                    category="network",
                    severity=Severity.info,
                    confidence=.99,
                    target=target,
                    evidence=["TCP/21 is open."],
                    artifacts=["raw/nmap-tcp.xml"],
                    next_action="Check anonymous access and server capabilities.",
                )
            )

    return result, findings
