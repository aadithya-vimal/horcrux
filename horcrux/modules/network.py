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

    if not services:
        import socket
        from horcrux.modules.web.scanner import WEB_PORTS
        from horcrux.models import Service, Software
        ports_to_probe = sorted(set(WEB_PORTS | {21, 22, 23, 25, 53, 80, 443, 445, 1433, 1521, 3306, 3389, 5432, 6379, 8000, 8080, 8443, 8888, 9000, 27017}))
        host = target.split(":")[0] if ":" in target else target
        if ":" in target:
            try:
                ports_to_probe.insert(0, int(target.split(":")[1]))
            except ValueError:
                pass

        for port in ports_to_probe:
            try:
                with socket.create_connection((host, port), timeout=0.3):
                    svc_name = "http" if port in WEB_PORTS else "unknown"
                    services.append(Service(
                        host=host,
                        port=port,
                        protocol="tcp",
                        state="open",
                        service=svc_name,
                    ))
                    try:
                        st = ws.load()
                        st.record_live_execution(
                            capability_id="socket_connect",
                            target=target,
                            host=host,
                            port=port,
                            protocol="tcp",
                            success=True,
                            socket_result="connected",
                            evidence_reference=f"tcp://{host}:{port}",
                        )
                        ws.save(st)
                    except Exception:
                        pass
            except Exception:
                pass

        for s in services:
            if s.service == "http" or s.port in WEB_PORTS:
                try:
                    import httpx
                    scheme = "https" if s.port in (443, 8443) else "http"
                    url = f"{scheme}://{host}:{s.port}/"
                    with httpx.Client(verify=False, timeout=2.0) as client:
                        resp = client.get(url)
                        try:
                            st = ws.load()
                            st.record_live_execution(
                                capability_id="http_probe",
                                target=target,
                                host=host,
                                port=s.port,
                                protocol=scheme,
                                success=True,
                                status_code=resp.status_code,
                                socket_result=f"HTTP {resp.status_code}",
                                evidence_reference=url,
                            )
                            ws.save(st)
                        except Exception:
                            pass
                        server = resp.headers.get("server", "")
                        powered = resp.headers.get("x-powered-by", "")
                        prod = server or powered
                        if prod:
                            s.product = prod
                            software.append(Software(
                                product=prod,
                                version="",
                                service="http",
                                source="http_banner",
                                confidence=0.8,
                                evidence=[f"Banner on port {s.port}: Server={server} X-Powered-By={powered}"],
                            ))
                except Exception:
                    pass

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

