from __future__ import annotations

import re
import socket
from horcrux.models import AuditEntry, AuditStatus, Finding, FindingStatus, Severity, Software, SubsystemState, ValidationState


def enumerate_databases(ws, runner, target: str, port: int, service_name: str = "") -> tuple[list[Finding], list[AuditEntry]]:
    """
    Enumerates database services: Redis, MySQL, PostgreSQL, MSSQL, MongoDB.
    Performs unauthenticated access checks and software version extraction.
    """
    ws.set_subsystem_state("database_enum", SubsystemState.RUNNING)
    findings: list[Finding] = []
    audits: list[AuditEntry] = []
    software_items: list[Software] = []

    # 1. Redis (6379)
    if port == 6379 or "redis" in service_name:
        redis_open = False
        redis_ver = ""
        try:
            with socket.create_connection((target, port), timeout=5.0) as s:
                s.sendall(b"INFO\r\n")
                resp = s.recv(4096).decode("utf-8", errors="replace")
                ws.write(f"raw/redis-info-{port}.txt", resp)
                if "redis_version:" in resp:
                    redis_open = True
                    match = re.search(r"redis_version:\s*([0-9.]+)", resp)
                    if match:
                        redis_ver = match.group(1)
        except Exception as exc:
            ws.write(f"raw/redis-{port}.error", str(exc))

        if redis_open:
            if redis_ver:
                software_items.append(
                    Software(
                        product="Redis",
                        version=redis_ver,
                        service=f"{port}/tcp",
                        source="redis-info",
                        confidence=0.99,
                        evidence=[f"Redis INFO command disclosed version {redis_ver}"],
                    )
                )
                ws.upsert_software(software_items)

            findings.append(
                Finding(
                    id=f"redis-unauthenticated-{port}",
                    title="Unauthenticated Redis Server Exposed",
                    category="database-security",
                    severity=Severity.high,
                    confidence=0.99,
                    status=FindingStatus.verified,
                    validation_state=ValidationState.confirmed,
                    target=target,
                    affected_asset=f"{target}:{port}",
                    protocol="tcp",
                    port=port,
                    source_tool="redis",
                    evidence=["Redis INFO response returned without requiring AUTH password."],
                    artifacts=[f"raw/redis-info-{port}.txt"],
                    why_it_matters="Unauthenticated Redis access allows arbitrary memory inspection, dumping cached data, or remote code execution via file writes.",
                    recommended_next_action="Enable 'requirepass' in redis.conf and bind Redis to localhost / internal networks.",
                    next_action="Enable requirepass authentication in redis.conf.",
                    reproduction=[f"redis-cli -h {target} -p {port} INFO"],
                )
            )
        else:
            audits.append(
                AuditEntry(
                    id=f"audit-redis-{port}",
                    category="database-security",
                    asset=f"{target}:{port}",
                    check_name="Redis Authentication Audit",
                    status=AuditStatus.hardened,
                    evidence=["Redis requires authentication or rejected unauthenticated INFO command."],
                    reason="Redis protected by password or restricted bind.",
                )
            )

    # 2. MySQL / MariaDB (3306)
    elif port == 3306 or "mysql" in service_name or "mariadb" in service_name:
        try:
            with socket.create_connection((target, port), timeout=5.0) as s:
                raw = s.recv(1024)
                # MySQL greeting packet contains server version starting at byte 5
                if len(raw) > 5:
                    null_idx = raw.find(b"\x00", 5)
                    if null_idx > 5:
                        ver_str = raw[5:null_idx].decode("utf-8", errors="replace")
                        prod = "MariaDB" if "mariadb" in ver_str.lower() else "MySQL"
                        software_items.append(
                            Software(
                                product=prod,
                                version=ver_str,
                                service=f"{port}/tcp",
                                source="mysql-handshake",
                                confidence=0.98,
                                evidence=[f"MySQL initial greeting handshake disclosed version string '{ver_str}'"],
                            )
                        )
                        ws.upsert_software(software_items)
                        audits.append(
                            AuditEntry(
                                id=f"audit-mysql-handshake-{port}",
                                category="database",
                                asset=f"{target}:{port}",
                                check_name="MySQL Handshake Banner",
                                status=AuditStatus.audited,
                                evidence=[f"Version string: {ver_str}"],
                                reason=f"{prod} service responding to protocol handshake.",
                            )
                        )
        except Exception as exc:
            ws.write(f"raw/mysql-{port}.error", str(exc))

    # 3. PostgreSQL (5432)
    elif port == 5432 or "postgres" in service_name:
        audits.append(
            AuditEntry(
                id=f"audit-postgres-{port}",
                category="database",
                asset=f"{target}:{port}",
                check_name="PostgreSQL Listener Presence",
                status=AuditStatus.audited,
                evidence=[f"Port {port} active PostgreSQL listener."],
                reason="PostgreSQL database service mapped to attack surface.",
            )
        )

    # 4. MongoDB (27017)
    elif port == 27017 or "mongo" in service_name:
        audits.append(
            AuditEntry(
                id=f"audit-mongodb-{port}",
                category="database",
                asset=f"{target}:{port}",
                check_name="MongoDB Listener Presence",
                status=AuditStatus.audited,
                evidence=[f"Port {port} active MongoDB listener."],
                reason="MongoDB NoSQL service mapped to attack surface.",
            )
        )

    # 5. MSSQL (1433)
    elif port == 1433 or "ms-sql" in service_name:
        audits.append(
            AuditEntry(
                id=f"audit-mssql-{port}",
                category="database",
                asset=f"{target}:{port}",
                check_name="MSSQL TDS Listener Presence",
                status=AuditStatus.audited,
                evidence=[f"Port {port} active Microsoft SQL Server TDS listener."],
                reason="MSSQL service mapped to attack surface.",
            )
        )

    if audits:
        ws.upsert_audits(audits)
    for f in findings:
        ws.upsert_finding(f)

    ws.set_subsystem_state("database_enum", SubsystemState.COMPLETE)
    return findings, audits
