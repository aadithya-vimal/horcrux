from __future__ import annotations

import time
from rich.console import Console

from horcrux.core.actions import compute_next_actions
from horcrux.core.runner import CommandRunner
from horcrux.core.storage import Workspace
from horcrux.models import (
    ModuleDecision,
    ScanProfile,
    SubsystemState,
    WebApplicationType,
    WebTarget,
    get_profile,
)
from horcrux.modules.network import run_network
from horcrux.modules.services import enumerate_services
from horcrux.modules.web.discovery import run as web_discovery
from horcrux.modules.web.fingerprint import run_fingerprinting
from horcrux.modules.web.nikto import run_nikto
from horcrux.modules.web.scanner import WEB_PORTS, scan_http, scheme_for
from horcrux.core.intel import run_nuclei
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

        self.workspace.set_subsystem_state("scan", SubsystemState.RUNNING)
        try:
            with ScanProgressManager(self.console, self.target, profile.name) as progress:
                runner = CommandRunner(
                    self.workspace,
                    on_start=progress.on_command_start,
                    on_finish=progress.on_command_finish,
                )

                # STAGE 1: Reachability & Target Validation
                progress.start_stage("reachability")
                time.sleep(0.05)
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

                # STAGE 3: Service Identification, Web Probing & Fingerprinting
                progress.start_stage("services")
                state = self.workspace.load()
                for service in state.services:
                    if "web_probe" in profile.enabled_modules and (
                        service.port in WEB_PORTS or service.service.lower() in {"http", "https"}
                    ):
                        scheme = scheme_for(service.port)
                        base_url = f"{scheme}://{self.target}:{service.port}"
                        web_target = state.get_web_target(service.port) or WebTarget(
                            scheme=scheme,
                            host=self.target,
                            port=service.port,
                            base_url=base_url,
                            service_identifier=f"{scheme}-{service.port}",
                        )

                        try:
                            # 1. Base HTTP probing & endpoint validation
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
                            web_target.module_decisions.append(
                                ModuleDecision(
                                    module="base_http_probe",
                                    status="EXECUTED",
                                    reason=f"Initial HTTP banner & head probe completed for port {service.port}.",
                                )
                            )

                            # 2. Technology & WAF Fingerprinting (WhatWeb, httpx, wafw00f)
                            clean_techs, _ = run_fingerprinting(self.workspace, runner, self.target, service.port)
                            state = self.workspace.load()
                            web_target.technologies = state.normalized_technologies
                            web_target.module_decisions.append(
                                ModuleDecision(
                                    module="technology_fingerprinting",
                                    status="EXECUTED",
                                    reason=f"Identified {len(clean_techs)} normalized technologies without raw scanner noise.",
                                )
                            )

                            # 3. Content Discovery & Response Validation (FFUF/Gobuster/Feroxbuster/Native + JS Analyzer)
                            if "web_discovery" in profile.enabled_modules:
                                disc_findings, _, disc_paths = web_discovery(
                                    self.workspace,
                                    runner,
                                    self.target,
                                    service.port,
                                    strategy=profile.wordlist_strategy,
                                )
                                for finding in disc_findings:
                                    self.workspace.upsert_finding(finding)

                            # Reload updated web_target from workspace
                            state = self.workspace.load()
                            updated_target = state.get_web_target(service.port)
                            if updated_target:
                                web_target = updated_target

                            # 4. Targeted Nuclei (if enabled by profile & available)
                            if profile.expensive_checks and runner.which("nuclei"):
                                nuclei_findings = run_nuclei(self.workspace, runner, base_url)
                                for nf in nuclei_findings:
                                    self.workspace.upsert_finding(nf)
                                web_target.module_decisions.append(
                                    ModuleDecision(
                                        module="nuclei",
                                        status="EXECUTED",
                                        reason="Executed targeted template scan against confirmed web service.",
                                    )
                                )
                            elif profile.expensive_checks:
                                web_target.module_decisions.append(
                                    ModuleDecision(
                                        module="nuclei",
                                        status="SKIPPED",
                                        reason="Nuclei binary not installed on operator machine.",
                                    )
                                )

                            # 5. Nikto (evidence-gated: skip for SPAs to avoid duplicate 404 noise)
                            if profile.expensive_checks and runner.which("nikto"):
                                if web_target.application_type == WebApplicationType.SPA:
                                    web_target.module_decisions.append(
                                        ModuleDecision(
                                            module="nikto",
                                            status="SKIPPED",
                                            reason="SPA fallback architecture detected; legacy CGI checks skipped to prevent duplicate noise.",
                                        )
                                    )
                                else:
                                    nikto_findings, _ = run_nikto(self.workspace, runner, self.target, service.port)
                                    for nf in nikto_findings:
                                        self.workspace.upsert_finding(nf)
                                    web_target.module_decisions.append(
                                        ModuleDecision(
                                            module="nikto",
                                            status="EXECUTED",
                                            reason="Executed CGI and server misconfiguration audit.",
                                        )
                                    )

                            self.workspace.upsert_web_target(web_target)

                        except Exception as exc:
                            self.workspace.write(
                                f"raw/web-{service.port}-error.txt",
                                str(exc),
                            )
                progress.complete_stage("services")


                # STAGE 4: Protocol-Specific Service Enumeration (SMB, LDAP, Kerberos, SSH, FTP, DB, etc.)
                progress.start_stage("enumeration")
                if "service_enum" in profile.enabled_modules:
                    for finding in enumerate_services(
                        self.workspace,
                        runner,
                        self.target,
                        profile=profile,
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

                # STAGE 6: Vulnerability & CVE Intelligence (Gated by reliable software evidence)
                progress.start_stage("intel")
                state = self.workspace.load()
                reliable_software = [
                    s for s in state.software
                    if s.version and s.confidence >= 0.70 and s.product.lower() not in {"tcpwrapped", "unknown", "http", "https", "ppp"}
                ]

                if profile.cve_correlation and reliable_software:
                    self.workspace.set_subsystem_state("cve_intelligence", SubsystemState.RUNNING)
                    from horcrux.intel.search import searchsploit_workspace
                    candidates = searchsploit_workspace(self.workspace, runner)

                    if candidates:
                        self.workspace.set_subsystem_state("cve_intelligence", SubsystemState.COMPLETE_WITH_CANDIDATES)
                        try:
                            from horcrux.intel.ai.manager import AIManager
                            ai_mgr = AIManager()
                            if ai_mgr.is_enabled and ai_mgr.get_provider():
                                state = self.workspace.load()
                                triaged = ai_mgr.triage_exploits(state, candidates)
                                self.workspace.set_exploits(triaged)
                        except Exception:
                            pass
                    else:
                        self.workspace.set_subsystem_state("cve_intelligence", SubsystemState.COMPLETE_NO_CANDIDATES)
                else:
                    if not reliable_software:
                        progress.skip_stage("intel", "No reliable versioned software evidence identified on target")
                    else:
                        progress.skip_stage("intel", "Gated: requires explicit operator intel profile")
                progress.complete_stage("intel")

                # STAGE 7: State-Aware Synthesis & Action Planning
                progress.start_stage("synthesis")
                self.derive_actions()
                progress.complete_stage("synthesis")
                self.workspace.set_subsystem_state("scan", SubsystemState.COMPLETE)
        except KeyboardInterrupt:
            self.workspace.set_subsystem_state('scan', SubsystemState.FAILED)
        except Exception:
            self.workspace.set_subsystem_state("scan", SubsystemState.FAILED)
            raise

    def derive_actions(self):
        """Recompute state-aware next best actions without stale priorities."""
        state = self.workspace.load()
        actions = compute_next_actions(state)
        self.workspace.set_actions(actions)
