from __future__ import annotations

import re
from horcrux.models import AuditEntry, AuditStatus, Finding, FindingStatus, Severity, SubsystemState, ValidationState


def enumerate_ldap(ws, runner, target: str, port: int = 389) -> tuple[list[Finding], list[AuditEntry]]:
    """
    Executes LDAP / Active Directory reconnaissance.
    Retrieves RootDSE metadata, naming contexts, and tests for unauthenticated directory binds.
    """
    ws.set_subsystem_state("ldap_enum", SubsystemState.RUNNING)
    findings: list[Finding] = []
    audits: list[AuditEntry] = []

    scheme = "ldaps" if port in {636, 3269} else "ldap"
    out_file = ws.raw / f"ldap-rootdse-{port}.txt"

    if runner.which("ldapsearch"):
        res = runner.run(
            [
                "ldapsearch",
                "-x",
                "-H", f"{scheme}://{target}:{port}",
                "-s", "base",
                "-b", "",
                "(objectclass=*)",
                "namingContexts",
                "defaultNamingContext",
                "domainFunctionality",
                "supportedLDAPVersion",
            ],
            f"ldap-rootdse-{port}",
            timeout=90,
        )
        if res and res.stdout and "defaultNamingContext:" in res.stdout:
            match = re.search(r"defaultNamingContext:\s*([^\r\n]+)", res.stdout)
            domain_dn = match.group(1).strip() if match else ""

            # Check if user enumeration is allowed anonymously
            user_check = runner.run(
                [
                    "ldapsearch",
                    "-x",
                    "-H", f"{scheme}://{target}:{port}",
                    "-b", domain_dn,
                    "(objectclass=user)",
                    "sAMAccountName",
                ],
                f"ldap-anon-users-{port}",
                timeout=60,
            )
            if user_check and user_check.stdout and "sAMAccountName:" in user_check.stdout:
                users_found = re.findall(r"sAMAccountName:\s*([^\r\n]+)", user_check.stdout)
                findings.append(
                    Finding(
                        id=f"ldap-anon-bind-{port}",
                        title="Unauthenticated LDAP Directory Search Permitted",
                        category="directory-services",
                        severity=Severity.high,
                        confidence=0.98,
                        status=FindingStatus.verified,
                        validation_state=ValidationState.confirmed,
                        target=target,
                        affected_asset=f"{target}:{port}",
                        protocol="tcp",
                        port=port,
                        source_tool="ldapsearch",
                        evidence=[
                            f"Anonymous LDAP bind allowed querying domain '{domain_dn}'.",
                            f"Disclosed {len(users_found)} domain user accounts (Sample: {', '.join(users_found[:5])}).",
                        ],
                        artifacts=[f"raw/ldap-rootdse-{port}.stdout", f"raw/ldap-anon-users-{port}.stdout"],
                        why_it_matters="Allows unauthenticated external users to enumerate all domain users, groups, and Active Directory objects.",
                        recommended_next_action="Enforce LDAP signing and disable anonymous LDAP queries on domain controllers.",
                        next_action="Enforce LDAP signing and disable anonymous LDAP queries on domain controllers.",
                    )
                )
            else:
                audits.append(
                    AuditEntry(
                        id=f"audit-ldap-{port}",
                        category="directory-services",
                        asset=f"{target}:{port}",
                        check_name="Active Directory LDAP RootDSE Query",
                        status=AuditStatus.audited,
                        evidence=[f"RootDSE retrieved successfully. DefaultNamingContext: {domain_dn}"],
                        reason=f"Active Directory domain '{domain_dn}' mapped; anonymous user queries restricted.",
                    )
                )
        else:
            audits.append(
                AuditEntry(
                    id=f"audit-ldap-{port}",
                    category="directory-services",
                    asset=f"{target}:{port}",
                    check_name="LDAP Anonymous Bind Audit",
                    status=AuditStatus.hardened,
                    evidence=["LDAP server requires authentication or rejects anonymous RootDSE search."],
                    reason="LDAP queries restricted to authenticated sessions.",
                )
            )
    else:
        # Record audit item that port was mapped
        audits.append(
            AuditEntry(
                id=f"audit-ldap-port-{port}",
                category="directory-services",
                asset=f"{target}:{port}",
                check_name="LDAP Port Presence",
                status=AuditStatus.audited,
                evidence=[f"TCP port {port} listening ({scheme}). ldapsearch utility not present on host."],
                reason="LDAP listener recorded in surface inventory.",
            )
        )

    if audits:
        ws.upsert_audits(audits)
    for f in findings:
        ws.upsert_finding(f)

    ws.set_subsystem_state("ldap_enum", SubsystemState.COMPLETE)
    return findings, audits
