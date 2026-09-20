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
    def __init__(self, target: str, workspace: Workspace, console: Console, profile: str | ScanProfile | None = None,
                 engines: list[str] | None = None, skip_engines: bool = False,
                 engine_mode: str = "best", settings_manager=None,
                 time_limit: int | None = None, request_limit: int | None = None,
                 rate_limit: str | None = None, identity: str | None = None,
                 max_iterations: int | None = None):
        self.target = target
        self.workspace = workspace
        self.console = console
        self.profile = get_profile(profile)
        self.engines = engines
        self.skip_engines = skip_engines
        self.engine_mode = engine_mode
        self._settings_manager = settings_manager
        self.time_limit = time_limit
        self.request_limit = request_limit
        self.rate_limit = rate_limit
        self.identity = identity
        self.max_iterations = max_iterations

    def scan(self, deep: bool = False, verify: bool = False):
        profile = self.profile
        if deep:
            profile = get_profile("deep")

        if self.identity:
            try:
                st = self.workspace.load()
                eng_cfg = st.get_engagement_config()
                cfg_dict = eng_cfg.model_dump() if hasattr(eng_cfg, "model_dump") else {}
                identities = cfg_dict.get("test_identities", []) or []
                parts = self.identity.split(":", 1)
                role = parts[0]
                token = parts[1] if len(parts) > 1 else ""
                identities.append({
                    "label": role,
                    "role": role if role in ("user", "admin") else "user",
                    "login_path": "/login",
                    "headers": {"Authorization": f"Bearer {token}" if not token.lower().startswith("bearer") else token} if token else {},
                })
                cfg_dict["test_identities"] = identities
                cfg_dict["test_identities_configured"] = True
                st.set_engagement_config(cfg_dict)
                self.workspace.save(st)
            except Exception:
                pass

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
                import secrets as _secrets
                state = self.workspace.load()
                if not getattr(state, "assessment_run_id", ""):
                    state.assessment_run_id = _secrets.token_hex(6)
                    self.workspace.save(state)
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

                # Record live network execution observation & derive target provenance
                from horcrux.core.acceptance import derive_target_provenance
                state = self.workspace.load()
                if state.services or network_findings:
                    state.live_execution_observed = True
                    state.provenance_source = "live_network_probe"
                state.target_provenance, state.provenance_source = derive_target_provenance(
                    self.target,
                    state.live_execution_observed,
                    getattr(state, "target_provenance", "UNKNOWN"),
                    getattr(state, "provenance_source", ""),
                )
                self.workspace.save(state)
                progress.complete_stage("ports")

                # STAGE 3: Service Identification, Web Probing & Fingerprinting
                progress.start_stage("services")
                state = self.workspace.load()
                for service in state.services:
                    if "web_probe" in profile.enabled_modules and (
                        service.port in WEB_PORTS or service.service.lower() in {"http", "https"}
                    ):
                        scheme = scheme_for(service.port)
                        target_host = self.target.split(":")[0] if ":" in self.target else self.target
                        base_url = f"{scheme}://{target_host}:{service.port}"
                        web_target = state.get_web_target(service.port) or WebTarget(
                            scheme=scheme,
                            host=target_host,
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
                            clean_techs, _ = run_fingerprinting(self.workspace, runner, target_host, service.port)
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
                                    target_host,
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

                should_run_intel = (profile.cve_correlation or profile.name in ("deep", "full", "service", "intel")) and reliable_software

                if should_run_intel:
                    self.workspace.set_subsystem_state("cve_intelligence", SubsystemState.RUNNING)
                    try:
                        from horcrux.intel.cve import correlate_software_vulnerabilities
                        correlate_software_vulnerabilities(self.workspace)
                    except Exception as exc:
                        self.workspace.write("raw/cve-resolver-error.txt", str(exc))

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

                # STAGE 7: External Vulnerability Engines (profile-driven, never fatal)
                progress.start_stage("engines")
                try:
                    self._run_external_engines(profile)
                except Exception as exc:
                    self.workspace.write("raw/vuln-engines-error.txt", str(exc)[:2000])
                progress.complete_stage("engines")

                # STAGE 8: Application Model Ingestion, Agentic Investigation & Reporting
                progress.start_stage("synthesis")
                try:
                    from horcrux.agents.coordinator import on_recon_complete
                    ai_mgr = None
                    try:
                        from horcrux.intel.ai.manager import AIManager
                        ai_mgr = AIManager()
                        if not (ai_mgr.is_enabled and ai_mgr.get_provider()):
                            ai_mgr = None
                    except Exception:
                        pass
                    on_recon_complete(self.workspace, ai_manager=ai_mgr)

                    # Autonomous agent investigation loop for standard / deep / full profiles
                    if profile.name in ("full", "deep", "standard"):
                        from horcrux.agents.coordinator import run_full_assessment
                        default_iter = 250 if profile.name in ("full", "deep") else 50
                        max_iter = self.max_iterations or default_iter
                        run_full_assessment(
                            self.workspace,
                            ai_manager=ai_mgr,
                            max_iterations=max_iter,
                            time_limit=self.time_limit,
                            request_limit=self.request_limit,
                        )
                except Exception as exc:
                    self.workspace.write("raw/agent-ingestion-error.txt", str(exc))
                self.derive_actions()

                # Generate client-grade markdown report
                try:
                    from horcrux.reporting.reports import markdown
                    markdown(self.workspace)
                except Exception as exc:
                    self.workspace.write("raw/report-error.txt", str(exc))

                progress.complete_stage("synthesis")
                self.workspace.set_subsystem_state("scan", SubsystemState.COMPLETE)
        except KeyboardInterrupt:
            self.workspace.set_subsystem_state('scan', SubsystemState.FAILED)
        except Exception:
            self.workspace.set_subsystem_state("scan", SubsystemState.FAILED)
            raise

    def _run_external_engines(self, profile) -> None:
        """Profile-driven external engine orchestration (spec §8-§9).

        quick/local: native only. standard: intelligence only. deep/full/
        network/web/service/intel: configured engines via best-available set.
        Operator flags (--engines/--skip-engines/--engine-mode) persist and
        are reported as OPERATOR_EXCLUDED, never NOT_CONFIGURED.
        """
        from horcrux.intel.vuln_engines.orchestrator import (
            coverage_warning_text,
            readiness_audit,
            readiness_text,
            run_external_engines,
        )

        mgr = self._settings_manager
        if mgr is None:
            try:
                from horcrux.core.settings import SettingsManager
                mgr = SettingsManager()
            except Exception:
                mgr = None

        state = self.workspace.load()
        exclusions: list[str] = list(getattr(state, "engine_operator_exclusions", []) or [])
        include = list(self.engines) if self.engines else None
        exclude = list(exclusions)
        if self.skip_engines:
            try:
                from horcrux.intel.vuln_engines.registry import provider_ids
                exclude = sorted(set(exclude) | set(provider_ids()))
            except Exception:
                pass
        try:
            audit = readiness_audit(mgr, operator_exclude=exclude, check_health=False)
        except Exception:
            return

        # Pre-scan readiness: compact, impossible to miss, not annoying.
        try:
            self.console.print()
            self.console.print(readiness_text(audit))
            warning = coverage_warning_text(audit)
            if warning and profile.name in ("deep", "full", "standard"):
                self.console.print(f"[bold yellow]{warning}[/bold yellow]")
        except Exception:
            pass

        if include:
            norm = []
            try:
                from horcrux.intel.vuln_engines.registry import normalize_engine_id
                norm = [normalize_engine_id(e) for e in include]
            except Exception:
                norm = list(include)
        else:
            norm = None
        try:
            result = run_external_engines(
                self.workspace, self.target, profile=profile.name,
                settings_manager=mgr, operator_include=norm,
                operator_exclude=exclude, engine_mode=self.engine_mode,
                console=self.console)
            # persist operator decision
            try:
                fresh = self.workspace.load()
                fresh.engine_operator_exclusions = sorted(set(exclude))
                self.workspace.save(fresh)
            except Exception:
                pass
            executed = [pid for pid, run in (result.get("runs") or {}).items()
                        if str(run.get("status", "")).upper() == "COMPLETE"]
            self.workspace.set_subsystem_state(
                "vulnerability_engines",
                SubsystemState.COMPLETE if executed else SubsystemState.COMPLETE_NO_CANDIDATES)
        except Exception as exc:
            self.workspace.write("raw/vuln-engines-error.txt", str(exc)[:2000])
            self.workspace.set_subsystem_state("vulnerability_engines", SubsystemState.FAILED)

    def derive_actions(self):
        """Recompute investigation-centric next actions."""
        from horcrux.core.actions import compute_investigation_actions
        state = self.workspace.load()
        actions = compute_investigation_actions(state)
        self.workspace.set_actions(actions)
