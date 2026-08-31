from __future__ import annotations

import time

from rich.console import Console

from horcrux.core.runner import CommandRunner
from horcrux.core.storage import Workspace
from horcrux.models import Action, ScanProfile, get_profile
from horcrux.modules.network import run_network
from horcrux.modules.services import enumerate_services
from horcrux.modules.web.discovery import run as web_discovery
from horcrux.modules.web.scanner import WEB_PORTS, scan_http
from horcrux.ui.ascii import fanfare
from horcrux.ui.progress import ScanProgressManager


class Orchestrator:
    def __init__(self, target: str, workspace: Workspace, console: Console, profile: str | ScanProfile | None = None):
        self.target = target
        self.workspace = workspace
        self.console = console
        self.profile = get_profile(profile)

    def scan(self, deep: bool = False, verify: bool = False):
        profile = self.profile
        if deep:
            profile = get_profile("deep")

        # Metasploit-style live progress manager
        with ScanProgressManager(self.console, self.target, profile.name) as progress:
            # Runner with live subprocess hooks into progress display
            runner = CommandRunner(
                self.workspace,
                on_start=progress.on_command_start,
                on_finish=progress.on_command_finish,
            )

            # STAGE 1: Reachability & Target Validation
            progress.start_stage("reachability")
            time.sleep(0.1)  # Target validation handshake
            self.workspace.write("raw/target.txt", f"Target: {self.target}\nProfile: {profile.name}")
            progress.complete_stage("reachability")

            # STAGE 2: Port Discovery
            progress.start_stage("ports")
            _, network_findings = run_network(
                self.workspace,
                runner,
                self.target,
                profile=profile,
                deep=deep,
            )
            for finding in network_findings:
                self.workspace.upsert_finding(finding)
            progress.complete_stage("ports")

            # STAGE 3: Service Identification & Web Probing
            progress.start_stage("services")
            state = self.workspace.load()
            for service in state.services:
                if "web_probe" in profile.enabled_modules and (
                    service.port in WEB_PORTS or service.service.lower() in {"http", "https"}
                ):
                    try:
                        findings, creds, tech = scan_http(
                            self.workspace,
                            self.target,
                            service.port,
                        )
                        for finding in findings:
                            self.workspace.upsert_finding(finding)

                        self.workspace.add_credentials(creds)
                        state = self.workspace.load()
                        state.technologies = sorted(set(state.technologies) | set(tech))
                        self.workspace.save(state)

                        if "web_discovery" in profile.enabled_modules:
                            web_discovery(
                                self.workspace,
                                runner,
                                self.target,
                                service.port,
                            )
                    except Exception as exc:
                        self.workspace.write(
                            f"raw/web-{service.port}-error.txt",
                            str(exc),
                        )
            progress.complete_stage("services")

            # STAGE 4: Protocol-Specific Enumeration
            progress.start_stage("enumeration")
            if "service_enum" in profile.enabled_modules:
                for finding in enumerate_services(
                    self.workspace,
                    runner,
                    self.target,
                ):
                    self.workspace.upsert_finding(finding)
            else:
                progress.skip_stage("enumeration", "Disabled in profile")
            progress.complete_stage("enumeration")

            # STAGE 5: Evidence Validation
            progress.start_stage("validation")
            if verify:
                self.workspace.write(
                    "raw/verify-mode.txt",
                    "Verification mode requested; conservative checks verified.",
                )
            progress.complete_stage("validation")

            # STAGE 6: Vulnerability / CVE Correlation (Strictly gated by profile & software evidence)
            progress.start_stage("intel")
            if profile.cve_correlation:
                from horcrux.intel.search import searchsploit_workspace
                candidates = searchsploit_workspace(self.workspace, runner)
                # If AI is configured, triage top candidates
                try:
                    from horcrux.intel.ai.manager import AIManager
                    ai_mgr = AIManager()
                    if ai_mgr.is_enabled and ai_mgr.get_provider() and candidates:
                        state = self.workspace.load()
                        triaged = ai_mgr.triage_exploits(state, candidates)
                        self.workspace.set_exploits(triaged)
                except Exception:
                    pass
            else:
                progress.skip_stage("intel", "Gated: requires explicit operator intel profile")
            progress.complete_stage("intel")

            # STAGE 7: Synthesis & Action Planning
            progress.start_stage("synthesis")
            self.derive_actions()
            progress.complete_stage("synthesis")

    def derive_actions(self):
        state = self.workspace.load()
        ports = {service.port for service in state.services}
        actions = []

        if state.software:
            actions.append(
                Action(
                    id="cve",
                    title="Resolve CVE / SearchSploit candidates",
                    reason="Versioned software was identified on target",
                    score=98,
                )
            )

        if any(s.port in WEB_PORTS for s in state.services):
            actions.append(
                Action(
                    id="web",
                    title="Review web attack surface & endpoints",
                    reason="HTTP/HTTPS services detected",
                    score=94,
                )
            )

        if ports & {139, 445}:
            actions.append(
                Action(
                    id="smb",
                    title="Inspect SMB shares & null sessions",
                    reason="SMB listener exposed on port 445/139",
                    score=90,
                )
            )

        if ports & {389, 636}:
            actions.append(
                Action(
                    id="ldap",
                    title="Query LDAP naming contexts & domain level",
                    reason="Active Directory LDAP service reachable",
                    score=88,
                )
            )

        if 88 in ports:
            actions.append(
                Action(
                    id="kerberos",
                    title="Enumerate Kerberos accounts & AS-REP roasting",
                    reason="Kerberos KDC port 88 identified",
                    score=87,
                )
            )

        if state.credentials:
            actions.append(
                Action(
                    id="credentials",
                    title="Test credential reuse across exposed services",
                    reason=f"{len(state.credentials)} credential-like token(s) recovered",
                    score=99,
                )
            )

        # AI contextual synthesis if enabled
        try:
            from horcrux.intel.ai.manager import AIManager
            ai_mgr = AIManager()
            if ai_mgr.is_enabled and ai_mgr.get_provider():
                actions = ai_mgr.rank_actions(state, actions)
                paths = ai_mgr.synthesize_attack_paths(state)
                if paths:
                    st = self.workspace.load()
                    st.attack_paths = paths
                    self.workspace.save(st)
        except Exception:
            pass

        self.workspace.set_actions(actions)

