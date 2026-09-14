"""False-negative audit engine (Phase 9, Part 17).

"Why might we be missing this?" pass after major stages.

A false-negative audit systematically asks: what high-value security 
surfaces exist in the application model that have NOT been tested?
This produces prioritized gap investigations for the assessment loop.

CRITICAL: ABSENCE OF EVIDENCE IS NOT EVIDENCE OF ABSENCE.
A missing finding must NEVER implicitly mean the control was secure.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from horcrux.intel.application_model import ApplicationModel
    from horcrux.intel.investigations import Investigation
    from horcrux.models import WorkspaceState


@dataclass
class FalseNegativeGap:
    """A specific gap that may be causing false negatives."""
    gap_type: str           # category: untested_property, missing_identity, etc.
    description: str
    severity: str = "medium"   # low / medium / high
    evidence: list[str] = field(default_factory=list)
    suggested_investigation: str = ""
    specialist: str = ""
    candidate_tools: list[str] = field(default_factory=list)


@dataclass
class FalseNegativeReport:
    """Report of potential false-negative sources."""
    gaps: list[FalseNegativeGap] = field(default_factory=list)
    untouched_security_properties: int = 0
    api_routes_without_auth_context: int = 0
    object_endpoints_without_identity_comparison: int = 0
    workflows_not_observed: int = 0
    blocked_investigations: int = 0
    unavailable_tools: int = 0
    identity_gap: bool = False
    session_gap: bool = False
    total_gap_score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_gaps": len(self.gaps),
            "high_severity_gaps": sum(1 for g in self.gaps if g.severity == "high"),
            "medium_severity_gaps": sum(1 for g in self.gaps if g.severity == "medium"),
            "untouched_security_properties": self.untouched_security_properties,
            "api_routes_without_auth_context": self.api_routes_without_auth_context,
            "object_endpoints_without_identity_comparison": self.object_endpoints_without_identity_comparison,
            "workflows_not_observed": self.workflows_not_observed,
            "blocked_investigations": self.blocked_investigations,
            "unavailable_tools": self.unavailable_tools,
            "identity_gap": self.identity_gap,
            "session_gap": self.session_gap,
            "total_gap_score": round(self.total_gap_score, 2),
            "gaps": [
                {
                    "type": g.gap_type, "description": g.description,
                    "severity": g.severity, "evidence": g.evidence[:3],
                    "suggested_investigation": g.suggested_investigation,
                    "specialist": g.specialist,
                }
                for g in self.gaps
            ],
        }


def run_false_negative_audit(state: "WorkspaceState") -> FalseNegativeReport:
    """Run a full false-negative audit on the current assessment state.

    Produces a prioritized report of gaps that may be causing false negatives.
    Each gap can generate a new investigation.
    """
    report = FalseNegativeReport()
    app = state.get_application_model()

    try:
        from horcrux.intel.coverage import SecurityCoverageModel, PropertyStatus
        coverage = state.get_security_coverage()
        coverage.ensure_properties()

        # 1. Untouched security properties
        unknown_props = coverage.unknown_properties()
        report.untouched_security_properties = len(unknown_props)
        critical_unknown = coverage.critical_unknown_properties()
        if critical_unknown:
            names = [p.name for p in critical_unknown[:5]]
            report.gaps.append(FalseNegativeGap(
                gap_type="untested_critical_property",
                description=f"{len(critical_unknown)} critical security properties never tested: {', '.join(names)}",
                severity="high",
                evidence=[p.property_id for p in critical_unknown[:5]],
                suggested_investigation="Generate investigations for each untested critical property",
                specialist="WebAgent",
            ))
    except Exception:
        pass

    # 2. API routes without auth context
    api_eps = [e for e in app.endpoints if e.path.startswith(("/api", "/rest", "/v"))]
    no_auth_context = [e for e in api_eps if not e.authentication and not e.observed_identities]
    report.api_routes_without_auth_context = len(no_auth_context)
    if no_auth_context:
        report.gaps.append(FalseNegativeGap(
            gap_type="api_without_auth_context",
            description=f"{len(no_auth_context)} API routes with no authentication context tested",
            severity="high" if len(no_auth_context) > 3 else "medium",
            evidence=[e.id for e in no_auth_context[:5]],
            suggested_investigation="Test API routes as anonymous and authenticated identities",
            specialist="AuthorizationAgent",
            candidate_tools=["http_probe", "authz_compare"],
        ))

    # 3. Object endpoints without cross-identity comparison
    object_eps = [e for e in app.endpoints if e.has_object_reference]
    no_identity_comparison = [e for e in object_eps if len(e.observed_identities) < 2]
    report.object_endpoints_without_identity_comparison = len(no_identity_comparison)
    if no_identity_comparison and len(app.identities) > 1:
        report.gaps.append(FalseNegativeGap(
            gap_type="object_endpoint_no_identity_comparison",
            description=f"{len(no_identity_comparison)} object-bearing endpoints never compared across identities",
            severity="high",
            evidence=[e.id for e in no_identity_comparison[:5]],
            suggested_investigation="Compare object access for each identity against each object endpoint",
            specialist="AuthorizationAgent",
            candidate_tools=["authz_compare", "identity_compare"],
        ))

    # 4. Workflows not observed
    expected_workflows = _infer_expected_workflows(app)
    observed_workflow_names = {w.name.lower() for w in app.workflows}
    missing_workflows = [w for w in expected_workflows if w.lower() not in observed_workflow_names]
    report.workflows_not_observed = len(missing_workflows)
    if missing_workflows:
        report.gaps.append(FalseNegativeGap(
            gap_type="workflow_not_observed",
            description=f"Expected workflows not observed: {', '.join(missing_workflows[:4])}",
            severity="medium",
            evidence=[],
            suggested_investigation="Map and exercise each workflow for business-logic flaws",
            specialist="BusinessLogicAgent",
            candidate_tools=["browser_automate", "http_probe"],
        ))

    # 5. Suspicious endpoints without validation
    suspicious_eps = [
        e for e in app.endpoints
        if any(k in e.path.lower() for k in ("admin", "internal", "config", "backup", "debug"))
        and not any(h.hypothesis_class.value in ("privilege_escalation", "authentication")
                    for h in state.get_hypotheses()
                    if e.id in h.asset_refs)
    ]
    if suspicious_eps:
        report.gaps.append(FalseNegativeGap(
            gap_type="suspicious_endpoint_unvalidated",
            description=f"{len(suspicious_eps)} sensitive endpoints never investigated",
            severity="medium",
            evidence=[e.id for e in suspicious_eps[:5]],
            suggested_investigation="Probe suspicious/privileged endpoints as each configured identity",
            specialist="AuthorizationAgent",
            candidate_tools=["http_probe", "authz_compare"],
        ))

    # 6. Blocked investigations
    try:
        from horcrux.intel.investigations import InvestigationState
        blocked_invs = [
            i for i in state.get_investigations()
            if i.state in (InvestigationState.BLOCKED, InvestigationState.SCOPE_BLOCKED,
                           InvestigationState.UNAVAILABLE, InvestigationState.FAILED)
        ]
        report.blocked_investigations = len(blocked_invs)
        if blocked_invs:
            obj = [i.objective[:60] for i in blocked_invs[:3]]
            report.gaps.append(FalseNegativeGap(
                gap_type="blocked_investigations",
                description=f"{len(blocked_invs)} investigations blocked/failed: {'; '.join(obj)}",
                severity="medium",
                evidence=[i.id for i in blocked_invs[:5]],
                suggested_investigation="Review blocked investigations for alternative approaches",
                specialist="WebAgent",
            ))
    except Exception:
        pass

    # 7. Identity gap: no multi-identity testing despite auth surface
    has_auth = bool(
        app.authentication
        or any("login" in e.path.lower() for e in app.endpoints)
    )
    if has_auth and len(app.identities) < 2:
        report.identity_gap = True
        report.gaps.append(FalseNegativeGap(
            gap_type="insufficient_identities",
            description="Authentication surface exists but fewer than 2 identities configured",
            severity="high",
            evidence=["No multi-identity comparison possible without at least 2 test identities"],
            suggested_investigation="Configure operator test identities for cross-identity authorization testing",
            specialist="AuthenticationAgent",
            candidate_tools=["identity_switch"],
        ))

    # 8. Session gap: auth surface but no sessions established
    if has_auth and not app.sessions:
        report.session_gap = True
        report.gaps.append(FalseNegativeGap(
            gap_type="no_sessions_established",
            description="Authentication surface exists but no sessions were established",
            severity="high",
            evidence=["Session establishment not observed in any identity"],
            suggested_investigation="Establish authenticated sessions to observe authenticated attack surface",
            specialist="AuthenticationAgent",
            candidate_tools=["browser_automate", "identity_switch"],
        ))

    # 9. Service versions unknown
    unknown_version_services = [
        s for s in app.services
        if not s.version and s.service_name not in ("http", "https")
    ]
    if unknown_version_services:
        report.gaps.append(FalseNegativeGap(
            gap_type="unknown_service_versions",
            description=f"{len(unknown_version_services)} services with unknown versions (no CVE analysis possible)",
            severity="low",
            evidence=[s.id for s in unknown_version_services[:3]],
            suggested_investigation="Fingerprint service versions for vulnerability intelligence",
            specialist="WebAgent",
            candidate_tools=["nmap_discovery", "http_probe"],
        ))

    # 10. Conflicting evidence (from contradictions module)
    try:
        from horcrux.intel.contradictions import detect_contradictions
        contradictions = detect_contradictions(state)
        if contradictions:
            report.gaps.append(FalseNegativeGap(
                gap_type="contradictory_evidence",
                description=f"{len(contradictions)} contradictions in evidence require investigation",
                severity="medium",
                evidence=[str(c)[:60] for c in contradictions[:3]],
                suggested_investigation="Resolve tool disagreements through targeted validation",
                specialist="WebAgent",
                candidate_tools=["endpoint_validate", "http_probe"],
            ))
    except Exception:
        pass

    # Calculate gap score
    severity_weights = {"high": 3.0, "medium": 1.5, "low": 0.5}
    report.total_gap_score = sum(
        severity_weights.get(g.severity, 1.0) for g in report.gaps
    )

    return report


def _infer_expected_workflows(app: "ApplicationModel") -> list[str]:
    """Infer which workflows should exist based on endpoint patterns."""
    expected = []
    ep_paths = " ".join(e.path.lower() for e in app.endpoints)

    if "login" in ep_paths or "signin" in ep_paths:
        expected.append("authentication flow")
    if "register" in ep_paths or "signup" in ep_paths:
        expected.append("registration flow")
    if "checkout" in ep_paths or "cart" in ep_paths:
        expected.append("checkout flow")
    if "upload" in ep_paths or "file" in ep_paths:
        expected.append("file upload flow")
    if "password" in ep_paths and "reset" in ep_paths:
        expected.append("password reset flow")
    if "admin" in ep_paths:
        expected.append("admin workflow")
    if "order" in ep_paths or "purchase" in ep_paths:
        expected.append("order flow")

    return expected


def generate_gap_investigations_from_audit(
    report: FalseNegativeReport,
    app: "ApplicationModel",
) -> list["Investigation"]:
    """Convert false-negative gaps into Investigation objects."""
    from horcrux.intel.investigations import Investigation, InvestigationState, InvestigationScore
    from horcrux.intel.application_model import fingerprint

    investigations = []
    for gap in report.gaps:
        if gap.severity not in ("high", "medium"):
            continue
        inv = Investigation(
            objective=f"[GAP] {gap.description[:120]}",
            reason=f"False-negative audit: {gap.gap_type}",
            evidence_refs=list(gap.evidence[:5]),
            vulnerability_classes=["information_disclosure"],
            required_capabilities=["http"],
            candidate_tools=gap.candidate_tools or ["http_probe"],
            expected_information_gain="high" if gap.severity == "high" else "medium",
            specialist=gap.specialist or "WebAgent",
            state=InvestigationState.READY,
            score=InvestigationScore(
                evidence_relevance=0.6,
                expected_information_gain=0.85 if gap.severity == "high" else 0.65,
                impact_potential=0.7,
                coverage_gap=0.9,
                prerequisites_satisfied=1.0,
                execution_cost=0.3,
            ),
        )
        inv.id = fingerprint("inv", "fn_audit", gap.gap_type, gap.description[:40])
        inv.priority = inv.score.total
        investigations.append(inv)

    return investigations
