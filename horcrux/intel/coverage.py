"""Semantic security coverage model."""

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from horcrux.intel.application_model import ApplicationModel
    from horcrux.intel.hypotheses import Hypothesis
    from horcrux.intel.investigations import Investigation
    from horcrux.models import WorkspaceState


class CoverageStatus(str, Enum):
    NOT_RELEVANT = "NOT_RELEVANT"
    NOT_REVIEWED = "NOT_REVIEWED"
    IN_PROGRESS = "IN_PROGRESS"
    REVIEWED = "REVIEWED"
    SUPPORTED = "SUPPORTED"
    CONFIRMED = "CONFIRMED"
    REFUTED = "REFUTED"
    BLOCKED = "BLOCKED"


SECURITY_DOMAINS = [
    "authentication",
    "session_security",
    "authorization",
    "object_level_authorization",
    "function_level_authorization",
    "input_validation",
    "injection",
    "client_side_security",
    "file_handling",
    "ssrf",
    "business_logic",
    "api_security",
    "information_disclosure",
    "configuration",
    "infrastructure",
    "web_discovery",
]


class DomainCoverage(BaseModel):
    domain: str
    status: CoverageStatus = CoverageStatus.NOT_REVIEWED
    notes: str = ""
    investigation_ids: list[str] = Field(default_factory=list)
    hypothesis_ids: list[str] = Field(default_factory=list)
    # --- Phase 7 security-property detail (Part 11) ---
    applicable: bool = True
    observed: bool = False
    investigated: bool = False
    validated: bool = False
    confirmed_issue: bool = False
    blocked: bool = False
    not_applicable: bool = False
    unknown: bool = True


class SecurityCoverageModel(BaseModel):
    domains: dict[str, DomainCoverage] = Field(default_factory=dict)

    def ensure_domains(self) -> None:
        for domain in SECURITY_DOMAINS:
            if domain not in self.domains:
                self.domains[domain] = DomainCoverage(domain=domain)

    def get(self, domain: str) -> CoverageStatus:
        self.ensure_domains()
        return self.domains.get(domain, DomainCoverage(domain=domain)).status

    def set_status(self, domain: str, status: CoverageStatus, notes: str = "") -> None:
        self.ensure_domains()
        dc = self.domains[domain]
        dc.status = status
        if notes:
            dc.notes = notes
        # Keep property detail consistent with status.
        if status == CoverageStatus.NOT_RELEVANT:
            dc.applicable = False
            dc.not_applicable = True
            dc.unknown = False
        elif status == CoverageStatus.NOT_REVIEWED:
            dc.unknown = True
        elif status == CoverageStatus.IN_PROGRESS:
            dc.observed = True
            dc.investigated = True
            dc.unknown = False
        elif status in {CoverageStatus.REVIEWED, CoverageStatus.REFUTED}:
            dc.observed = True
            dc.investigated = True
            dc.validated = True
            dc.unknown = False
        elif status in {CoverageStatus.SUPPORTED, CoverageStatus.CONFIRMED}:
            dc.observed = True
            dc.investigated = True
            dc.validated = True
            dc.confirmed_issue = status == CoverageStatus.CONFIRMED
            dc.unknown = False
        elif status == CoverageStatus.BLOCKED:
            dc.blocked = True
            dc.unknown = False

    def percentage_complete(self) -> dict[str, float]:
        """Return coverage percentages by category group."""
        self.ensure_domains()
        reviewed_statuses = {
            CoverageStatus.REVIEWED,
            CoverageStatus.SUPPORTED,
            CoverageStatus.CONFIRMED,
            CoverageStatus.REFUTED,
            CoverageStatus.NOT_RELEVANT,
        }
        groups = {
            "web": ["web_discovery", "client_side_security", "information_disclosure"],
            "authentication": ["authentication", "session_security"],
            "authorization": ["authorization", "object_level_authorization", "function_level_authorization"],
            "business_logic": ["business_logic"],
            "injection": ["injection", "input_validation", "ssrf"],
            "api": ["api_security"],
            "infrastructure": ["configuration", "infrastructure", "file_handling"],
        }
        result: dict[str, float] = {}
        for group, domains in groups.items():
            relevant = [
                d for d in domains
                if self.domains.get(d) and self.domains[d].status != CoverageStatus.NOT_RELEVANT
            ]
            if not relevant:
                result[group] = 0.0
                continue
            done = sum(
                1 for d in relevant
                if self.domains[d].status in reviewed_statuses
            )
            in_progress = sum(
                1 for d in relevant
                if self.domains[d].status == CoverageStatus.IN_PROGRESS
            )
            pct = (done + in_progress * 0.5) / len(relevant) * 100
            result[group] = round(pct, 1)
        return result


def calculate_coverage(
    app: ApplicationModel,
    hypotheses: list[Hypothesis],
    investigations: list[Investigation],
    coverage: SecurityCoverageModel,
) -> SecurityCoverageModel:
    """Update coverage based on application model and investigation progress."""
    coverage.ensure_domains()

    # Web discovery
    if app.endpoints or app.routes or app.pages:
        if any(i.state.value in {"RUNNING", "COMPLETE", "SUPPORTED"} for i in investigations if i.specialist == "WebAgent"):
            coverage.set_status("web_discovery", CoverageStatus.IN_PROGRESS)
        elif len(app.endpoints) >= 3:
            coverage.set_status("web_discovery", CoverageStatus.REVIEWED, f"{len(app.endpoints)} endpoints mapped")

    # Authentication relevance
    if app.authentication or any("login" in e.path.lower() for e in app.endpoints):
        auth_inv = [i for i in investigations if i.specialist == "AuthenticationAgent"]
        _update_domain_from_investigations(coverage, "authentication", auth_inv)
        if any(h.hypothesis_class.value in {"authentication", "session"} for h in hypotheses):
            coverage.set_status("session_security", CoverageStatus.NOT_REVIEWED)
    else:
        coverage.set_status("authentication", CoverageStatus.NOT_RELEVANT)
        coverage.set_status("session_security", CoverageStatus.NOT_RELEVANT)

    # Authorization
    object_eps = [e for e in app.endpoints if e.has_object_reference]
    if object_eps:
        authz_inv = [i for i in investigations if i.specialist == "AuthorizationAgent"]
        _update_domain_from_investigations(coverage, "object_level_authorization", authz_inv)
        _update_domain_from_investigations(coverage, "authorization", authz_inv)
    else:
        coverage.set_status("object_level_authorization", CoverageStatus.NOT_RELEVANT)

    admin_eps = [e for e in app.endpoints if "admin" in e.path.lower()]
    if admin_eps:
        _update_domain_from_investigations(
            coverage,
            "function_level_authorization",
            [i for i in investigations if i.specialist == "AuthorizationAgent"],
        )

    # SSRF
    ssrf_hyps = [h for h in hypotheses if h.hypothesis_class.value == "ssrf"]
    if ssrf_hyps:
        _update_domain_from_hypotheses(coverage, "ssrf", ssrf_hyps, investigations)
    else:
        coverage.set_status("ssrf", CoverageStatus.NOT_RELEVANT)

    # Business logic
    if app.workflows or len(app.endpoints) >= 5:
        bl_inv = [i for i in investigations if i.specialist == "BusinessLogicAgent"]
        _update_domain_from_investigations(coverage, "business_logic", bl_inv)
    else:
        coverage.set_status("business_logic", CoverageStatus.NOT_RELEVANT)

    # GraphQL / API
    if any("graphql" in e.path.lower() or e.path.startswith(("/api", "/rest")) for e in app.endpoints):
        api_inv = [i for i in investigations if i.specialist == "APIAgent"]
        _update_domain_from_investigations(coverage, "api_security", api_inv)
    else:
        coverage.set_status("api_security", CoverageStatus.NOT_RELEVANT)

    # Injection
    if len(app.parameters) >= 2:
        _update_domain_from_hypotheses(
            coverage,
            "injection",
            [h for h in hypotheses if h.hypothesis_class.value == "injection"],
            investigations,
        )
        coverage.set_status("input_validation", CoverageStatus.NOT_REVIEWED)

    # Infrastructure from services
    if app.services:
        coverage.set_status("infrastructure", CoverageStatus.REVIEWED, f"{len(app.services)} services mapped")

    return coverage


def _update_domain_from_investigations(
    coverage: SecurityCoverageModel,
    domain: str,
    investigations: list[Investigation],
) -> None:
    from horcrux.intel.investigations import InvestigationState

    if not investigations:
        coverage.set_status(domain, CoverageStatus.NOT_REVIEWED)
        return
    dc = coverage.domains[domain]
    dc.investigation_ids = [i.id for i in investigations[:10]]
    if any(i.state == InvestigationState.SCOPE_BLOCKED for i in investigations):
        coverage.set_status(domain, CoverageStatus.BLOCKED, "Scope/policy blocked")
    elif any(i.state == InvestigationState.RUNNING for i in investigations):
        coverage.set_status(domain, CoverageStatus.IN_PROGRESS)
    elif any(i.state in {InvestigationState.SUPPORTED, InvestigationState.COMPLETE} for i in investigations):
        coverage.set_status(domain, CoverageStatus.REVIEWED)
    elif any(i.state == InvestigationState.REFUTED for i in investigations):
        coverage.set_status(domain, CoverageStatus.REFUTED)
    elif any(i.state in {InvestigationState.UNAVAILABLE, InvestigationState.FAILED} for i in investigations):
        coverage.set_status(domain, CoverageStatus.BLOCKED, "Capability unavailable or failed")


def _update_domain_from_hypotheses(
    coverage: SecurityCoverageModel,
    domain: str,
    hypotheses: list,
    investigations: list,
) -> None:
    from horcrux.intel.hypotheses import HypothesisStatus
    from horcrux.intel.investigations import InvestigationState

    if any(h.status == HypothesisStatus.CONFIRMED for h in hypotheses):
        coverage.set_status(domain, CoverageStatus.CONFIRMED)
    elif any(h.status == HypothesisStatus.REFUTED for h in hypotheses):
        coverage.set_status(domain, CoverageStatus.REFUTED)
    elif any(i.state == InvestigationState.RUNNING for i in investigations):
        coverage.set_status(domain, CoverageStatus.IN_PROGRESS)
    elif hypotheses:
        coverage.set_status(domain, CoverageStatus.NOT_REVIEWED)


def assessment_completeness(state: WorkspaceState) -> dict:
    """Evaluate whether assessment has meaningful coverage vs 'no findings'."""
    coverage = state.get_security_coverage()
    coverage.ensure_domains()
    pct = coverage.percentage_complete()

    app = state.get_application_model()
    high_value_surfaces = (
        len(app.endpoints)
        + len(app.authentication)
        + len(app.object_types)
    )
    open_hyps = [
        h for h in state.get_hypotheses()
        if h.status.value in {"OPEN", "INVESTIGATING"}
        and h.confidence >= 0.6
    ]
    pending_high = [
        i for i in state.get_investigations()
        if i.state.value in {"READY", "PENDING", "RUNNING"}
        and i.expected_information_gain == "high"
    ]

    auth_reviewed = coverage.get("authorization") not in {
        CoverageStatus.NOT_REVIEWED,
        CoverageStatus.NOT_RELEVANT,
    }
    authz_reviewed = coverage.get("object_level_authorization") not in {
        CoverageStatus.NOT_REVIEWED,
        CoverageStatus.NOT_RELEVANT,
    }

    sufficient = (
        high_value_surfaces >= 3
        and not pending_high
        and (auth_reviewed or authz_reviewed or not app.endpoints)
        and pct.get("web", 0) >= 50
    )

    return {
        "sufficient": sufficient,
        "coverage_percentages": pct,
        "high_value_surfaces": high_value_surfaces,
        "open_hypotheses": len(open_hyps),
        "pending_high_investigations": len(pending_high),
        "authorization_investigated": auth_reviewed or authz_reviewed,
        "business_logic_investigated": coverage.get("business_logic") not in {
            CoverageStatus.NOT_REVIEWED,
            CoverageStatus.NOT_RELEVANT,
        },
    }
