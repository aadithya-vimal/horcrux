from __future__ import annotations

from horcrux.models import Action, SubsystemState, ValidationState, WorkspaceState
from horcrux.modules.web.scanner import WEB_PORTS


def compute_next_actions(state: WorkspaceState) -> list[Action]:
    """
    Computes state-aware, dynamic Next Best Actions for the operator.
    Eliminates fixed/stale scores and never recommends completed or zero-candidate actions.
    """
    actions: list[Action] = []
    ports = {s.port for s in state.services}
    finding_ids = {f.id for f in state.findings}

    # 1. Harvested Credentials (Top Priority)
    if state.credentials:
        cred = state.credentials[0]
        actions.append(
            Action(
                id="cred_test",
                title=f"Test harvested credential for '{cred.username or 'user'}'",
                reason=f"Disclosed credentials recovered from {cred.source}; verify access against authorized perimeter.",
                score=98.0,
                command="creds",
            )
        )

    # 2. Confirmed Critical/High Findings Requiring Immediate Operator Review
    confirmed_findings = [f for f in state.findings if f.validation_state == ValidationState.confirmed]

    for f in confirmed_findings:
        if "smb-anon-access" in f.id:
            actions.append(
                Action(
                    id="smb_inspect_shares",
                    title="Inspect accessible SMB shares for sensitive files",
                    reason="Anonymous SMB share listing verified; download available documents and check write permissions.",
                    score=96.0,
                    command="inspect smb-anon-access",
                )
            )
        elif "redis-unauthenticated" in f.id:
            actions.append(
                Action(
                    id="redis_dump",
                    title="Inspect unauthenticated Redis database & memory keys",
                    reason="Redis INFO command verified accessible without authentication.",
                    score=95.0,
                    command=f"inspect {f.id}",
                )
            )
        elif "web-discovered-env" in f.id or "web-.env" in f.id:
            actions.append(
                Action(
                    id="review_env",
                    title="Harvest database credentials & secrets from exposed .env",
                    reason="Valid environment configuration disclosure confirmed.",
                    score=97.0,
                    command=f"inspect {f.id}",
                )
            )
        elif "dns-zone-transfer" in f.id:
            actions.append(
                Action(
                    id="review_dns_zone",
                    title="Analyze dumped DNS zone records for internal servers",
                    reason="Unrestricted AXFR zone transfer confirmed.",
                    score=93.0,
                    command=f"inspect {f.id}",
                )
            )

    # 3. Web Service Reconnaissance & Validation State
    web_ports_present = [s.port for s in state.services if s.port in WEB_PORTS or s.service.lower() in {"http", "https"}]
    if web_ports_present:
        web_disc_state = state.get_subsystem_state("web_discovery")
        web_val_state = state.get_subsystem_state("web_validation")

        if web_disc_state == SubsystemState.NOT_RUN:
            actions.append(
                Action(
                    id="web_discovery",
                    title="Execute web content discovery & path fuzzing",
                    reason=f"HTTP/HTTPS listener active on port(s) {', '.join(str(p) for p in web_ports_present[:4])} but content discovery has not run.",
                    score=92.0,
                    command=f"scan {state.target} --profile web",
                )
            )
        elif web_disc_state in {SubsystemState.COMPLETE, SubsystemState.RUNNING}:
            unvalidated = [p for p in state.discovered_paths if not p.validated]
            if unvalidated and web_val_state != SubsystemState.COMPLETE:
                actions.append(
                    Action(
                        id="web_validate",
                        title=f"Validate {len(unvalidated)} discovered endpoints against baseline",
                        reason="Discovered paths require soft-404 and content validation before classification.",
                        score=91.0,
                    )
                )

    # 4. SMB Enumeration State
    if ports & {139, 445}:
        smb_state = state.get_subsystem_state("smb_enum")
        if smb_state == SubsystemState.NOT_RUN:
            actions.append(
                Action(
                    id="smb_enum",
                    title="Enumerate SMB shares & null session authentication",
                    reason="Port 445/139 exposed; anonymous share and security signature audit has not run.",
                    score=90.0,
                    command=f"scan {state.target} --profile service",
                )
            )

    # 5. LDAP Enumeration State
    if ports & {389, 636}:
        ldap_state = state.get_subsystem_state("ldap_enum")
        if ldap_state == SubsystemState.NOT_RUN:
            actions.append(
                Action(
                    id="ldap_enum",
                    title="Query Active Directory LDAP naming contexts & anonymous bind",
                    reason="LDAP listener reachable on port 389/636; RootDSE audit has not run.",
                    score=88.0,
                )
            )

    # 6. FTP Enumeration State
    if 21 in ports:
        ftp_state = state.get_subsystem_state("ftp_enum")
        if ftp_state == SubsystemState.NOT_RUN:
            actions.append(
                Action(
                    id="ftp_enum",
                    title="Check anonymous FTP login and directory listings",
                    reason="FTP listener active on port 21; anonymous access test has not run.",
                    score=86.0,
                )
            )

    # 7. Database Enumeration State
    db_ports = ports & {3306, 5432, 1433, 6379, 27017}
    if db_ports:
        db_state = state.get_subsystem_state("database_enum")
        if db_state == SubsystemState.NOT_RUN:
            actions.append(
                Action(
                    id="db_enum",
                    title="Enumerate database authentication & version banners",
                    reason=f"Database listener exposed on port(s) {', '.join(str(p) for p in db_ports)}; unauthenticated access check has not run.",
                    score=87.0,
                )
            )

    # 8. CVE / SearchSploit Intelligence State
    # Gated by reliable software evidence: MUST have valid version and confidence >= 0.70
    reliable_software = [
        s for s in state.software
        if s.version and s.confidence >= 0.70 and s.product.lower() not in {"tcpwrapped", "unknown", "http", "https", "ppp"}
    ]

    cve_state = state.get_subsystem_state("cve_intelligence")

    if reliable_software:
        primary_sw = reliable_software[0]

        if cve_state == SubsystemState.NOT_RUN:
            actions.append(
                Action(
                    id="cve_intel",
                    title=f"Correlate CVEs for {primary_sw.product} {primary_sw.version}",
                    reason=f"Reliable versioned software '{primary_sw.product} {primary_sw.version}' identified with {int(primary_sw.confidence * 100)}% confidence.",
                    score=89.0,
                    command="cve",
                )
            )
        elif cve_state == SubsystemState.COMPLETE_WITH_CANDIDATES and state.exploits:
            top = state.exploits[0]
            actions.append(
                Action(
                    id="review_exploit",
                    title=f"Review candidate: {top.cve or top.title[:45]}",
                    reason=f"High-relevance candidate identified for {top.product or primary_sw.product} ({top.relevance}).",
                    score=94.0,
                    command="exploit",
                )
            )
        elif cve_state == SubsystemState.COMPLETE_NO_CANDIDATES:
            # DO NOT loop or recommend CVE correlation again!
            actions.append(
                Action(
                    id="review_config",
                    title=f"Review {primary_sw.product} configuration & security observations",
                    reason=f"Version '{primary_sw.product} {primary_sw.version}' identified but 0 relevant exploits matched; focus on configuration review.",
                    score=65.0,
                )
            )

    # 9. Fallback if initial stages complete and no immediate exposures
    if not actions:
        actions.append(
            Action(
                id="deep_recon",
                title="Perform deep full-port reconnaissance or custom parameter fuzzing",
                reason="Initial attack surface fully mapped without immediate high-severity exposures.",
                score=50.0,
                command=f"scan {state.target} --profile deep",
            )
        )

    # Deduplicate by action ID and sort by score descending
    unique_actions: dict[str, Action] = {}
    for a in sorted(actions, key=lambda x: -x.score):
        if a.id not in unique_actions:
            unique_actions[a.id] = a

    return list(unique_actions.values())
