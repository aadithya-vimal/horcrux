from __future__ import annotations

from horcrux.models import Action, SubsystemState, ValidationState, WorkspaceState
from horcrux.modules.web.scanner import WEB_PORTS


def completion_verdict(state: WorkspaceState) -> dict:
    """Assessment completion from the property ledger (Part 27).

    COMPLETED: all applicable properties executed (or explicitly blocked
    with reasons). LIMITED: executed with gaps. BLOCKED: nothing
    executable. INCONCLUSIVE: no applicable properties modeled yet.
    Never collapses not-tested into not-vulnerable.
    """
    try:
        from horcrux.engine.ledger import ledger_from_matrix_tests
        from horcrux.intel.test_matrix import derive_applicable_tests
        app = state.get_application_model()
        tests = derive_applicable_tests(app, state)
        if not tests:
            return {"verdict": "INCONCLUSIVE", "reason": "no applicable security tests modeled"}
        invs = state.get_investigations()
        exec_ids = {i.id for i in invs
                    if getattr(getattr(i, "state", ""), "value", str(getattr(i, "state", ""))) in
                    {"SUPPORTED", "REFUTED", "COMPLETE", "INSUFFICIENT_EVIDENCE",
                     "FAILED", "BLOCKED", "SCOPE_BLOCKED", "UNAVAILABLE"}}
        ledger = ledger_from_matrix_tests(tests, exec_ids, {})
        s = ledger.summary()
        if s["executed"] == 0:
            return {"verdict": "BLOCKED" if s["applicable"] else "INCONCLUSIVE",
                    "reason": f"{s['applicable']} applicable, 0 executed", "summary": s}
        if s["executed"] >= s["applicable"]:
            return {"verdict": "COMPLETED", "reason": "all applicable properties evaluated", "summary": s}
        return {"verdict": "LIMITED",
                "reason": f"{s['applicable'] - s['executed']} of {s['applicable']} applicable tests not executed",
                "summary": s}
    except Exception as exc:
        return {"verdict": "INCONCLUSIVE", "reason": f"ledger unavailable: {exc}"}


def ledger_next_reasons(state: WorkspaceState, limit: int = 3) -> list[str]:
    """Concrete remaining security work from the property ledger (Part 28)."""
    try:
        from horcrux.engine.ledger import ledger_from_matrix_tests
        from horcrux.intel.test_matrix import derive_applicable_tests
        app = state.get_application_model()
        tests = derive_applicable_tests(app, state)
        inv_ids = {i.id for i in state.get_investigations()}
        pending: dict[str, int] = {}
        for t in tests:
            if f"inv-{t.id}" not in inv_ids and t.id not in inv_ids:
                fam = t.family.value if hasattr(t.family, "value") else str(t.family)
                pending[fam] = pending.get(fam, 0) + 1
        top = sorted(pending.items(), key=lambda kv: -kv[1])[:limit]
        return [f"{fam}: {n} unexecuted test(s)" for fam, n in top]
    except Exception:
        return []


def get_authoritative_assessment_state(state: WorkspaceState) -> dict:
    """One authoritative assessment completion state.

    `next`, `assess`, `scan`, status display, and report generation must all
    consume this. If queue executable == 0, callers must return the
    exhausted payload — never fabricate a generic action.
    """
    investigations = state.get_investigations()
    executable = [i for i in investigations
                  if getattr(i.state, "value", str(i.state)) in {"READY", "PENDING", "RUNNING"}]
    by_state: dict[str, int] = {}
    blocked_details: list[str] = []
    insufficient = 0
    unavailable: list[str] = []
    for inv in investigations:
        sv = getattr(inv.state, "value", str(inv.state))
        by_state[sv] = by_state.get(sv, 0) + 1
        if sv in {"BLOCKED", "SCOPE_BLOCKED", "UNAVAILABLE", "FAILED",
                  "APPROVAL_REQUIRED", "OUT_OF_SCOPE", "NOT_APPLICABLE"}:
            blocked_details.append(f"{inv.objective[:80]} [{sv}]")
        if sv == "INSUFFICIENT_EVIDENCE":
            insufficient += 1
        if sv in {"UNAVAILABLE", "REQUIRES_TOOL"}:
            unavailable.append(inv.objective[:80])
    try:
        hyps = state.get_hypotheses()
    except Exception:
        hyps = []
    unresolved = [h for h in hyps
                  if getattr(getattr(h, "status", ""), "value", str(getattr(h, "status", ""))) in {"OPEN", "INVESTIGATING"}]
    # Required operator inputs: auth contexts, second identity, tools.
    required_inputs: list[str] = []
    needs_second = any("two_identities" in (getattr(i, "prerequisites", []) or []) for i in executable)
    if needs_second:
        required_inputs.append("second identity context for horizontal authorization comparison")
    needs_auth = any("REQUIRES_AUTH" in str(getattr(i.state, "value", i.state)) for i in investigations)
    if needs_auth or not any(getattr(a, "label", "") != "anonymous" for a in ([{}])):
        pass
    try:
        from horcrux.intel.coverage import assessment_completeness
        comp = assessment_completeness(state)
        blocking = list(comp.get("blocking_reasons", []))
    except Exception:
        blocking = []
    exhausted = len(executable) == 0
    return {
        "exhausted": exhausted,
        "queue_executable": len(executable),
        "executable_ids": [i.id for i in executable],
        "by_state": by_state,
        "total_investigations": len(investigations),
        "blocked": blocked_details[:10],
        "blocked_count": len(blocked_details),
        "insufficient": insufficient,
        "unavailable_capabilities": unavailable[:10],
        "unresolved_hypotheses": len(unresolved),
        "required_operator_inputs": required_inputs,
        "blocking_reasons": blocking,
        "findings": len(state.findings),
    }


def _exhausted_action(state: WorkspaceState, auth: dict) -> Action:
    parts = [
        f"{auth['total_investigations']} investigations",
        f"{auth['queue_executable']} executable",
        f"{auth['blocked_count']} blocked",
        f"{auth['insufficient']} insufficient",
        f"{auth['unresolved_hypotheses']} unresolved hypotheses",
        f"{auth['findings']} canonical findings",
    ]
    if auth.get("unavailable_capabilities"):
        parts.append(f"unavailable: {'; '.join(auth['unavailable_capabilities'][:2])}")
    if auth.get("required_operator_inputs"):
        parts.append(f"required inputs: {'; '.join(auth['required_operator_inputs'][:2])}")
    if auth.get("blocking_reasons"):
        parts.append(f"blocking: {auth['blocking_reasons'][0][:100]}")
    try:
        for _lr in ledger_next_reasons(state):
            parts.append(f"remaining: {_lr}")
    except Exception:
        pass
    return Action(
        id="assessment_exhausted",
        title="Assessment exhausted — no executable investigations remain.",
        reason="; ".join(parts) + ". See status.",
        score=0.0,
        command="status",
    )


def compute_investigation_actions(state: WorkspaceState) -> list[Action]:
    """Next actions sourced ONLY from materialized executable investigations.

    - READY/PENDING/RUNNING investigations -> ranked actions (highest first).
    - Otherwise -> a single explicit queue_drained terminal message.
    Hypotheses, coverage gaps, and raw parameters never synthesize actions.
    """
    investigations = state.get_investigations()
    actions: list[Action] = []

    for inv in investigations:
        if inv.state.value not in {"READY", "PENDING", "RUNNING"}:
            continue
        gain_boost = 10.0 if inv.expected_information_gain == "high" else 5.0
        actions.append(
            Action(
                id=f"investigate_{inv.id[:12]}",
                title=inv.objective,
                reason=inv.reason,
                score=min(99.0, 70.0 + inv.priority * 20 + gain_boost),
                command=f"assess focus investigation {inv.id}",
            )
        )

    if actions:
        unique: dict[str, Action] = {}
        for a in sorted(actions, key=lambda x: -x.score):
            if a.id not in unique:
                unique[a.id] = a
        return list(unique.values())

    # Queue drained: authoritative exhausted state. Never manufacture an
    # unrelated action from raw application-model parameters. Only
    # materialized executable investigations may appear in next().
    auth = get_authoritative_assessment_state(state)
    ex = _exhausted_action(state, auth)
    return [Action(
        id="queue_drained",
        title="No executable investigations remain. Assessment exhausted.",
        reason=ex.reason,
        score=0.0,
        command="status",
    )]


def compute_next_actions(state: WorkspaceState) -> list[Action]:
    """
    Computes state-aware, dynamic Next Best Actions for the operator.
    Eliminates fixed/stale scores and never recommends completed or zero-candidate actions.
    """
    actions: list[Action] = []
    ports = {s.port for s in state.services}
    finding_ids = {f.id for f in state.findings}

    # 0. Interrupted / Failed Scan Recovery (Top Priority)
    if state.get_subsystem_state("scan") == SubsystemState.FAILED:
        actions.append(
            Action(
                id="retry_scan",
                title=f"Re-run reconnaissance scan against {state.target}",
                reason="Previous reconnaissance pass failed or was interrupted before completion.",
                score=99.0,
                command=f"scan {state.target}",
            )
        )

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

    # 8. Validated API Endpoints
    validated_apis = [
        p for p in state.discovered_paths
        if p.path.startswith(("/api", "/v1", "/v2", "/graphql", "/rest")) and p.validated and p.status in (200, 204, 401, 403)
    ]
    if validated_apis:
        sample_api = validated_apis[0]
        actions.append(
            Action(
                id="api_inspect",
                title=f"Investigate validated API route: {sample_api.path}",
                reason="Accessible API endpoint confirmed on perimeter; inspect schemas, methods, and authorization.",
                score=93.5,
            )
        )

    # 9. Discovered Parameters (STRICTLY GATED BY SERVER-BOUND EVIDENCE)
    # A JS-extracted token (e.g. isPeriodic from polyfills.js) is never
    # actionable: the parameter must be bound to an actual server-side
    # request/API route present in the discovered/model route set.
    if state.parameters:
        try:
            from horcrux.intel.parameters import is_server_bound_parameter
            from horcrux.intel.test_matrix import normalize_matrix_path as _norm
            known: set[str] = set()
            try:
                for ep in state.get_application_model().endpoints:
                    known.add(_norm(ep.path))
            except Exception:
                pass
            try:
                for p in state.discovered_paths:
                    known.add(_norm(p.path))
            except Exception:
                pass
            try:
                for wt in state.web_targets:
                    for wep in wt.endpoints or []:
                        known.add(_norm(wep.path))
            except Exception:
                pass
            bound = [p for p in state.parameters if is_server_bound_parameter(p, known)]
        except Exception:
            bound = []
        if bound:
            try:
                app_params = {p.name.lower(): p.param_class
                              for p in state.get_application_model().parameters}
            except Exception:
                app_params = {}
            def _pkey(p):
                cls = str(app_params.get(p.name.lower(), "general"))
                high = cls in {"object_id", "url_fetch", "auth_credential", "file"}
                return (0 if high else 1, p.name)
            sample_param = sorted(bound, key=_pkey)[0]
            param_class = str(app_params.get(sample_param.name.lower(), "general"))
            high_value_param = param_class in {"object_id", "url_fetch",
                                               "auth_credential", "file"}
            actions.append(
                Action(
                    id="param_audit",
                    title=f"Audit input parameter '{sample_param.name}' ({sample_param.location})",
                    reason=f"Parameter evidence identified from {sample_param.source} on {sample_param.endpoint or 'web target'}; test input validation.",
                    score=91.5 if high_value_param else 62.0,
                )
            )

    # 10. CVE / SearchSploit Intelligence State
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

    # 11. Authoritative fallback: if no materialized work exists, return the
    # exhausted state — never fabricate a generic deep_recon action that
    # contradicts assessment state.
    if not actions:
        auth = get_authoritative_assessment_state(state)
        if auth["exhausted"]:
            return [Action(
                id="queue_drained",
                title="No executable investigations remain. Assessment exhausted.",
                reason=_exhausted_action(state, auth).reason,
                score=0.0,
                command="status",
            )]
        actions.append(
            Action(
                id="deep_recon",
                title="Perform deep full-port reconnaissance and service inspection",
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


evaluate_next_actions = compute_next_actions

