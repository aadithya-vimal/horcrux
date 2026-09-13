from __future__ import annotations

from horcrux.models import Finding, ScanProfile, get_profile
from horcrux.modules.router import ServiceRouter


def enumerate_services(ws, runner, target: str, profile: ScanProfile | str | None = None) -> list[Finding]:
    """
    Service enumeration orchestrator: uses the centralized ServiceRouter
    to inspect discovered services and dispatch tailored enumeration modules.
    """
    prof = get_profile(profile)
    state = ws.load()
    all_findings: list[Finding] = []

    for svc in state.services:
        route = ServiceRouter.route(svc, prof)
        # Web services have their dedicated web probe/discovery phase in orchestrator;
        # dispatch all other protocol modules here
        non_web_modules = [m for m in route.applicable_modules if not m.startswith("web_")]
        if non_web_modules:
            route.applicable_modules = non_web_modules
            findings = ServiceRouter.dispatch(ws, runner, target, route, prof)
            all_findings.extend(findings)

    return all_findings
