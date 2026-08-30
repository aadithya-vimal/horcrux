from __future__ import annotations

from rich.console import Console

from horcrux.core.runner import CommandRunner
from horcrux.core.storage import Workspace
from horcrux.models import Action
from horcrux.modules.network import run_network
from horcrux.modules.services import enumerate_services
from horcrux.modules.web.discovery import run as web_discovery
from horcrux.modules.web.scanner import WEB_PORTS, scan_http
from horcrux.ui.ascii import loading


class Orchestrator:
    def __init__(self, target: str, workspace: Workspace, console: Console):
        self.target = target
        self.workspace = workspace
        self.console = console
        self.runner = CommandRunner(workspace)

    def scan(self, deep=False, verify=False):
        loading(self.console, "Mapping TCP/UDP surface", .65)
        _, network_findings = run_network(
            self.workspace, self.runner, self.target, deep=deep
        )

        for finding in network_findings:
            self.workspace.upsert_finding(finding)

        state = self.workspace.load()

        for service in state.services:
            if service.port in WEB_PORTS or service.service.lower() in {"http", "https"}:
                loading(self.console, f"Fingerprinting HTTP :{service.port}", .35)

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
                    state.technologies = sorted(
                        set(state.technologies) | set(tech)
                    )
                    self.workspace.save(state)

                    loading(self.console, f"Content discovery :{service.port}", .30)
                    web_discovery(
                        self.workspace,
                        self.runner,
                        self.target,
                        service.port,
                    )
                except Exception as exc:
                    self.workspace.write(
                        f"raw/web-{service.port}-error.txt",
                        str(exc),
                    )

        loading(self.console, "Running service-specific enumeration", .55)
        for finding in enumerate_services(
            self.workspace,
            self.runner,
            self.target,
        ):
            self.workspace.upsert_finding(finding)

        if verify:
            loading(self.console, "Running conservative verification", .25)
            self.workspace.write(
                "raw/verify-mode.txt",
                "Verification mode requested; only conservative checks enabled.",
            )

        self.derive_actions()
        self.console.print("[bold green]✓ Scan complete.[/bold green]")

    def derive_actions(self):
        state = self.workspace.load()
        ports = {service.port for service in state.services}
        actions = []

        if state.software:
            actions.append(
                Action(
                    id="cve",
                    title="Resolve CVE / SearchSploit candidates",
                    reason="Versioned software was identified",
                    score=98,
                )
            )

        if any(s.port in WEB_PORTS for s in state.services):
            actions.append(
                Action(
                    id="web",
                    title="Review web attack surface",
                    reason="HTTP service detected",
                    score=94,
                )
            )

        if ports & {139, 445}:
            actions.append(
                Action(
                    id="smb",
                    title="Review SMB shares/domain data",
                    reason="SMB exposed",
                    score=90,
                )
            )

        if ports & {389, 636}:
            actions.append(
                Action(
                    id="ldap",
                    title="Review LDAP/domain data",
                    reason="LDAP exposed",
                    score=88,
                )
            )

        if 88 in ports:
            actions.append(
                Action(
                    id="kerberos",
                    title="Review Kerberos enumeration",
                    reason="Kerberos exposed",
                    score=87,
                )
            )

        if state.credentials:
            actions.append(
                Action(
                    id="credentials",
                    title="Review credential reuse",
                    reason="Credentials were recovered",
                    score=97,
                )
            )

        self.workspace.set_actions(actions)
