"""Semantic security coverage model — Phase 9 hardened.

Critical invariant: UNKNOWN != NO_ISSUE_EVIDENCE
Absence of evidence NEVER implies absence of vulnerability.
Coverage can only transition to NO_ISSUE_EVIDENCE with explicit negative evidence.
"""

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from horcrux.intel.application_model import ApplicationModel
    from horcrux.intel.hypotheses import Hypothesis
    from horcrux.intel.investigations import Investigation
    from horcrux.models import WorkspaceState


class PropertyStatus(str, Enum):
    UNKNOWN = "UNKNOWN"
    APPLICABLE = "APPLICABLE"
    OBSERVED = "OBSERVED"
    INVESTIGATING = "INVESTIGATING"
    VALIDATED = "VALIDATED"
    CONFIRMED_ISSUE = "CONFIRMED_ISSUE"
    NO_ISSUE_EVIDENCE = "NO_ISSUE_EVIDENCE"
    BLOCKED = "BLOCKED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class CoverageStatus(str, Enum):
    NOT_RELEVANT = "NOT_RELEVANT"
    NOT_REVIEWED = "NOT_REVIEWED"
    IN_PROGRESS = "IN_PROGRESS"
    REVIEWED = "REVIEWED"
    SUPPORTED = "SUPPORTED"
    CONFIRMED = "CONFIRMED"
    REFUTED = "REFUTED"
    BLOCKED = "BLOCKED"


_COMPAT_MAP: dict[str, PropertyStatus] = {
    "NOT_RELEVANT": PropertyStatus.NOT_APPLICABLE,
    "NOT_REVIEWED": PropertyStatus.UNKNOWN,
    "IN_PROGRESS": PropertyStatus.INVESTIGATING,
    "REVIEWED": PropertyStatus.VALIDATED,
    "SUPPORTED": PropertyStatus.CONFIRMED_ISSUE,
    "CONFIRMED": PropertyStatus.CONFIRMED_ISSUE,
    "REFUTED": PropertyStatus.NO_ISSUE_EVIDENCE,
    "BLOCKED": PropertyStatus.BLOCKED,
}


class SecurityProperty(BaseModel):
    property_id: str
    name: str
    group: str
    status: PropertyStatus = PropertyStatus.UNKNOWN
    notes: str = ""
    investigation_ids: list[str] = Field(default_factory=list)
    hypothesis_ids: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    critical: bool = False
    applicable: bool = True


SECURITY_PROPERTIES: list[dict[str, Any]] = [
    # attack_surface
    {"id": "surface.host_discovery", "name": "Host Discovery", "group": "attack_surface", "critical": True},
    {"id": "surface.port_discovery", "name": "Port Discovery", "group": "attack_surface", "critical": True},
    {"id": "surface.service_enumeration", "name": "Service Enumeration", "group": "attack_surface", "critical": False},
    {"id": "surface.web_discovery", "name": "Web Discovery", "group": "attack_surface", "critical": True},
    {"id": "surface.api_discovery", "name": "API Discovery", "group": "attack_surface", "critical": True},
    {"id": "surface.js_discovery", "name": "JavaScript Discovery", "group": "attack_surface", "critical": False},
    {"id": "surface.graphql_discovery", "name": "GraphQL Discovery", "group": "attack_surface", "critical": False},
    {"id": "surface.hidden_functionality", "name": "Hidden Functionality", "group": "attack_surface", "critical": False},
    {"id": "surface.spec_discovery", "name": "Documentation Discovery", "group": "attack_surface", "critical": False},
    # authentication
    {"id": "auth.login", "name": "Login Mechanism", "group": "authentication", "critical": True},
    {"id": "auth.logout", "name": "Logout", "group": "authentication", "critical": False},
    {"id": "auth.registration", "name": "Registration Flow", "group": "authentication", "critical": False},
    {"id": "auth.password_reset", "name": "Password Reset", "group": "authentication", "critical": False},
    {"id": "auth.session_establishment", "name": "Session Establishment", "group": "authentication", "critical": True},
    {"id": "auth.session_invalidation", "name": "Session Invalidation", "group": "authentication", "critical": False},
    {"id": "auth.session_persistence", "name": "Session Fixation", "group": "authentication", "critical": False},
    {"id": "auth.mfa", "name": "MFA", "group": "authentication", "critical": False},
    {"id": "auth.state_transitions", "name": "Auth State Transitions", "group": "authentication", "critical": False},
    # authorization
    {"id": "authz.horizontal", "name": "Horizontal Authorization (IDOR/BOLA)", "group": "authorization", "critical": True},
    {"id": "authz.vertical", "name": "Vertical Authorization (Privilege Escalation)", "group": "authorization", "critical": True},
    {"id": "authz.object_level", "name": "Object-Level Authorization", "group": "authorization", "critical": True},
    {"id": "authz.function_level", "name": "Function-Level Authorization", "group": "authorization", "critical": True},
    {"id": "authz.resource_ownership", "name": "Resource Ownership", "group": "authorization", "critical": True},
    {"id": "authz.admin_access", "name": "Administrative Access Control", "group": "authorization", "critical": True},
    # input_server_side
    {"id": "input.injection", "name": "Injection", "group": "input_server_side", "critical": False},
    {"id": "input.command_execution", "name": "Command Execution", "group": "input_server_side", "critical": False},
    {"id": "input.template_injection", "name": "Template Injection", "group": "input_server_side", "critical": False},
    {"id": "input.ssrf", "name": "SSRF", "group": "input_server_side", "critical": False},
    {"id": "input.file_handling", "name": "File Handling", "group": "input_server_side", "critical": False},
    {"id": "input.path_traversal", "name": "Path Traversal", "group": "input_server_side", "critical": False},
    {"id": "input.header_trust", "name": "Header-Based Trust", "group": "input_server_side", "critical": False},
    # client_side
    {"id": "client.xss_reflected", "name": "XSS Candidates", "group": "client_side", "critical": False},
    {"id": "client.dom_sinks", "name": "DOM Sink Analysis", "group": "client_side", "critical": False},
    {"id": "client.storage", "name": "Insecure Client-Side Storage", "group": "client_side", "critical": False},
    {"id": "client.token_exposure", "name": "Token Exposure in Client", "group": "client_side", "critical": False},
    {"id": "client.source_maps", "name": "Source Map Exposure", "group": "client_side", "critical": False},
    {"id": "client.config_exposure", "name": "Exposed Configuration", "group": "client_side", "critical": False},
    # api_security
    {"id": "api.undocumented", "name": "Undocumented Endpoints", "group": "api_security", "critical": False},
    {"id": "api.method_override", "name": "Alternate Methods", "group": "api_security", "critical": False},
    {"id": "api.parameter_manipulation", "name": "Parameter Manipulation", "group": "api_security", "critical": False},
    {"id": "api.object_ids", "name": "Object Identifier Exposure", "group": "api_security", "critical": True},
    {"id": "api.graphql_fields", "name": "GraphQL Fields", "group": "api_security", "critical": False},
    {"id": "api.authorization", "name": "API Authorization", "group": "api_security", "critical": True},
    # business_logic
    {"id": "biz.workflow_sequencing", "name": "Workflow Sequencing", "group": "business_logic", "critical": False},
    {"id": "biz.state_transitions", "name": "State Transitions", "group": "business_logic", "critical": False},
    {"id": "biz.prerequisite_enforcement", "name": "Prerequisite Enforcement", "group": "business_logic", "critical": False},
    {"id": "biz.price_manipulation", "name": "Price Manipulation", "group": "business_logic", "critical": False},
    {"id": "biz.duplicate_actions", "name": "Duplicate Actions", "group": "business_logic", "critical": False},
    {"id": "biz.race_conditions", "name": "Race Conditions", "group": "business_logic", "critical": False},
    {"id": "biz.privilege_flows", "name": "Privilege-Changing Flows", "group": "business_logic", "critical": True},
    # data_exposure
    {"id": "data.sensitive_info", "name": "Sensitive Information Exposure", "group": "data_exposure", "critical": False},
    {"id": "data.secrets", "name": "Secret/Credential Exposure", "group": "data_exposure", "critical": True},
    {"id": "data.debug_output", "name": "Debug Output", "group": "data_exposure", "critical": False},
    {"id": "data.internal_ids", "name": "Internal ID Exposure", "group": "data_exposure", "critical": False},
    {"id": "data.excessive_fields", "name": "Excessive API Fields", "group": "data_exposure", "critical": False},
    # infrastructure
    {"id": "infra.tls", "name": "TLS Configuration", "group": "infrastructure", "critical": False},
    {"id": "infra.ssh", "name": "SSH Exposure", "group": "infrastructure", "critical": False},
    {"id": "infra.smb", "name": "SMB Exposure", "group": "infrastructure", "critical": False},
    {"id": "infra.database_exposure", "name": "Database Exposure", "group": "infrastructure", "critical": False},
    {"id": "infra.remote_admin", "name": "Remote Administration", "group": "infrastructure", "critical": False},
    # external_vulnerability — external engine fabric dimensions (non-critical by
    # design: missing engines yield LIMITED/INCOMPLETE engine verdicts, while the
    # core verdict math for native properties is unchanged).
    {"id": "vuln.external_intel", "name": "External Vulnerability Intelligence", "group": "external_vulnerability", "critical": False},
    {"id": "vuln.network_scanning", "name": "Network Vulnerability Scanning", "group": "external_vulnerability", "critical": False},
    {"id": "vuln.host_assessment", "name": "Host Vulnerability Assessment", "group": "external_vulnerability", "critical": False},
    {"id": "vuln.config_assessment", "name": "Configuration Assessment", "group": "external_vulnerability", "critical": False},
    {"id": "vuln.credentialed_assessment", "name": "Credentialed Assessment", "group": "external_vulnerability", "critical": False},
    {"id": "vuln.web_scanning", "name": "External Web Vulnerability Scanning", "group": "external_vulnerability", "critical": False},
]

SECURITY_DOMAINS = [
    "authentication", "session_security", "authorization",
    "object_level_authorization", "function_level_authorization",
    "input_validation", "injection", "client_side_security",
    "file_handling", "ssrf", "business_logic", "api_security",
    "information_disclosure", "configuration", "infrastructure", "web_discovery",
]

_DOMAIN_TO_PROPERTIES: dict[str, list[str]] = {
    "authentication": ["auth.login", "auth.session_establishment", "auth.state_transitions"],
    "session_security": ["auth.session_invalidation", "auth.session_persistence"],
    "authorization": ["authz.horizontal", "authz.vertical", "authz.function_level"],
    "object_level_authorization": ["authz.object_level", "authz.resource_ownership"],
    "function_level_authorization": ["authz.function_level", "authz.admin_access"],
    "input_validation": ["input.injection", "input.template_injection", "input.path_traversal"],
    "injection": ["input.injection", "input.command_execution"],
    "client_side_security": ["client.xss_reflected", "client.dom_sinks", "client.token_exposure"],
    "file_handling": ["input.file_handling"],
    "ssrf": ["input.ssrf"],
    "business_logic": ["biz.workflow_sequencing", "biz.state_transitions", "biz.privilege_flows"],
    "api_security": ["api.object_ids", "api.authorization", "api.undocumented"],
    "information_disclosure": ["data.sensitive_info", "data.debug_output", "data.secrets"],
    "configuration": ["data.debug_output", "infra.tls"],
    "infrastructure": ["infra.tls", "infra.ssh", "infra.smb"],
    "web_discovery": ["surface.web_discovery", "surface.api_discovery", "surface.js_discovery"],
}


class DomainCoverage(BaseModel):
    domain: str
    status: CoverageStatus = CoverageStatus.NOT_REVIEWED
    notes: str = ""
    investigation_ids: list[str] = Field(default_factory=list)
    hypothesis_ids: list[str] = Field(default_factory=list)
    applicable: bool = True
    observed: bool = False
    investigated: bool = False
    validated: bool = False
    confirmed_issue: bool = False
    blocked: bool = False
    not_applicable: bool = False
    unknown: bool = True

    def value(self) -> CoverageStatus:
        return self.status


class SecurityCoverageModel(BaseModel):
    domains: dict[str, DomainCoverage] = Field(default_factory=dict)
    properties: dict[str, SecurityProperty] = Field(default_factory=dict)
    # External-engine availability per provider:
    # AVAILABLE | NOT_CONFIGURED | UNAVAILABLE | RUNNING | COMPLETE |
    # FAILED | PARTIAL | NOT_APPLICABLE | OPERATOR_EXCLUDED
    external_engines: dict[str, str] = Field(default_factory=dict)

    def set_engine_state(self, provider_id: str, state: str) -> None:
        self.external_engines[str(provider_id)] = str(state)

    def get_engine_state(self, provider_id: str, default: str = "NOT_CONFIGURED") -> str:
        return self.external_engines.get(str(provider_id), default)

    def engine_coverage_verdict(self) -> str:
        """LIMITED when applicable engine coverage is missing; never boolean."""
        if not self.external_engines:
            return "NOT_ASSESSED"
        states = set(self.external_engines.values())
        if states and all(s in ("NOT_CONFIGURED",) for s in states):
            return "LIMITED"
        if "COMPLETE" in states:
            # executed some, but other sources missing/failed → PARTIAL, never
            # full credit while vulnerability evidence sources are absent.
            remainder = states - {"COMPLETE"}
            if remainder:
                return "PARTIAL"
            return "COMPLETE"
        if "RUNNING" in states:
            return "RUNNING"
        if states & {"FAILED", "PARTIAL"}:
            return "PARTIAL"
        if states <= {"NOT_APPLICABLE"}:
            return "NOT_APPLICABLE"
        if states == {"OPERATOR_EXCLUDED"} or states <= {"OPERATOR_EXCLUDED", "NOT_APPLICABLE"}:
            return "OPERATOR_EXCLUDED"
        return "LIMITED"

    def engine_coverage_summary(self) -> dict[str, Any]:
        return {
            "verdict": self.engine_coverage_verdict(),
            "engines": dict(self.external_engines),
            "executed": sum(1 for s in self.external_engines.values() if s == "COMPLETE"),
            "failed": sum(1 for s in self.external_engines.values() if s == "FAILED"),
            "not_configured": sum(1 for s in self.external_engines.values() if s == "NOT_CONFIGURED"),
        }

    def ensure_domains(self) -> None:
        for domain in SECURITY_DOMAINS:
            if domain not in self.domains:
                self.domains[domain] = DomainCoverage(domain=domain)

    def ensure_properties(self) -> None:
        for prop_def in SECURITY_PROPERTIES:
            pid = prop_def["id"]
            if pid not in self.properties:
                self.properties[pid] = SecurityProperty(
                    property_id=pid,
                    name=prop_def["name"],
                    group=prop_def["group"],
                    critical=prop_def.get("critical", False),
                )

    def get_property(self, property_id: str) -> SecurityProperty | None:
        self.ensure_properties()
        return self.properties.get(property_id)

    def set_property_status(
        self,
        property_id: str,
        status: PropertyStatus,
        notes: str = "",
        evidence_refs: list[str] | None = None,
    ) -> None:
        self.ensure_properties()
        prop = self.properties.get(property_id)
        if prop is None:
            return
        # CRITICAL INVARIANT: UNKNOWN → NO_ISSUE_EVIDENCE requires explicit evidence
        if status == PropertyStatus.NO_ISSUE_EVIDENCE and not evidence_refs:
            status = PropertyStatus.VALIDATED
        prop.status = status
        if notes:
            prop.notes = notes
        if evidence_refs:
            prop.evidence_refs = list(set(prop.evidence_refs + evidence_refs))
        self._sync_domain_from_property(property_id, status)

    def _sync_domain_from_property(self, property_id: str, status: PropertyStatus) -> None:
        for domain, prop_ids in _DOMAIN_TO_PROPERTIES.items():
            if property_id not in prop_ids:
                continue
            if domain not in self.domains:
                self.domains[domain] = DomainCoverage(domain=domain)
            dc = self.domains[domain]
            if status in (PropertyStatus.APPLICABLE, PropertyStatus.OBSERVED):
                if dc.status in (CoverageStatus.NOT_REVIEWED, CoverageStatus.NOT_RELEVANT):
                    dc.status = CoverageStatus.IN_PROGRESS
                dc.unknown = False
                dc.observed = True
            elif status == PropertyStatus.INVESTIGATING:
                dc.status = CoverageStatus.IN_PROGRESS
                dc.investigated = True
                dc.unknown = False
            elif status in (PropertyStatus.VALIDATED, PropertyStatus.NO_ISSUE_EVIDENCE):
                if dc.status not in (CoverageStatus.CONFIRMED, CoverageStatus.SUPPORTED):
                    dc.status = CoverageStatus.REVIEWED
                dc.validated = True
                dc.investigated = True
                dc.unknown = False
            elif status == PropertyStatus.CONFIRMED_ISSUE:
                dc.status = CoverageStatus.CONFIRMED
                dc.confirmed_issue = True
                dc.unknown = False
            elif status == PropertyStatus.BLOCKED:
                dc.blocked = True
            elif status == PropertyStatus.NOT_APPLICABLE:
                pass  # do not mark domain n/a from a single property

    def get(self, domain: str) -> CoverageStatus:
        self.ensure_domains()
        return self.domains.get(domain, DomainCoverage(domain=domain)).status

    def set_status(self, domain: str, status: CoverageStatus, notes: str = "") -> None:
        self.ensure_domains()
        if domain not in self.domains:
            self.domains[domain] = DomainCoverage(domain=domain)
        dc = self.domains[domain]
        dc.status = status
        if notes:
            dc.notes = notes
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
        elif status in (CoverageStatus.REVIEWED, CoverageStatus.REFUTED):
            dc.observed = True
            dc.investigated = True
            dc.validated = True
            dc.unknown = False
        elif status in (CoverageStatus.SUPPORTED, CoverageStatus.CONFIRMED):
            dc.observed = True
            dc.investigated = True
            dc.validated = True
            dc.confirmed_issue = status == CoverageStatus.CONFIRMED
            dc.unknown = False
        elif status == CoverageStatus.BLOCKED:
            dc.blocked = True
            dc.unknown = False
        self.ensure_properties()
        new_status = _COMPAT_MAP.get(status.value, PropertyStatus.UNKNOWN)
        for prop_id in _DOMAIN_TO_PROPERTIES.get(domain, []):
            prop = self.properties.get(prop_id)
            if prop and prop.status == PropertyStatus.UNKNOWN:
                prop.status = new_status

    def percentage_complete(self) -> dict[str, float]:
        self.ensure_domains()
        reviewed_statuses = {
            CoverageStatus.REVIEWED, CoverageStatus.SUPPORTED,
            CoverageStatus.CONFIRMED, CoverageStatus.REFUTED,
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
            done = sum(1 for d in relevant if self.domains[d].status in reviewed_statuses)
            in_progress = sum(1 for d in relevant if self.domains[d].status == CoverageStatus.IN_PROGRESS)
            pct = (done + in_progress * 0.5) / len(relevant) * 100
            result[group] = round(pct, 1)
        return result

    def critical_unknown_properties(self) -> list[SecurityProperty]:
        self.ensure_properties()
        return [
            p for p in self.properties.values()
            if p.critical and p.applicable
            and p.status in (PropertyStatus.UNKNOWN, PropertyStatus.APPLICABLE)
        ]

    def unknown_properties(self) -> list[SecurityProperty]:
        self.ensure_properties()
        return [
            p for p in self.properties.values()
            if p.applicable and p.status in (PropertyStatus.UNKNOWN, PropertyStatus.APPLICABLE)
        ]

    def blocked_properties(self) -> list[SecurityProperty]:
        self.ensure_properties()
        return [p for p in self.properties.values() if p.status == PropertyStatus.BLOCKED]

    def confirmed_issues(self) -> list[SecurityProperty]:
        self.ensure_properties()
        return [p for p in self.properties.values() if p.status == PropertyStatus.CONFIRMED_ISSUE]

    def coverage_verdict(self) -> str:
        self.ensure_properties()
        critical_unknown = self.critical_unknown_properties()
        blocked = self.blocked_properties()
        all_unknown = self.unknown_properties()
        if critical_unknown:
            return "INCOMPLETE"
        if blocked and len(blocked) > max(1, len(self.properties) * 0.3):
            return "BLOCKED"
        if all_unknown and len(all_unknown) > 5:
            return "LIMITED"
        if blocked:
            return "LIMITED"
        return "COMPLETE"

    def completeness_blocking_reasons(self) -> list[str]:
        self.ensure_properties()
        reasons: list[str] = []
        critical_unknown = self.critical_unknown_properties()
        if critical_unknown:
            names = ", ".join(p.name for p in critical_unknown[:5])
            if len(critical_unknown) > 5:
                names += f" (+{len(critical_unknown) - 5} more)"
            reasons.append(f"{len(critical_unknown)} critical security properties UNKNOWN: {names}")
        blocked = self.blocked_properties()
        if blocked:
            names = ", ".join(p.name for p in blocked[:3])
            reasons.append(f"{len(blocked)} properties BLOCKED: {names}")
        non_critical_unknown = [p for p in self.unknown_properties() if not p.critical]
        if non_critical_unknown:
            groups: dict[str, list[str]] = {}
            for p in non_critical_unknown:
                groups.setdefault(p.group, []).append(p.name)
            for group, names_list in list(groups.items())[:3]:
                reasons.append(
                    f"{len(names_list)} '{group}' properties UNKNOWN: "
                    f"{', '.join(names_list[:2])}{'...' if len(names_list) > 2 else ''}"
                )
        return reasons

    def property_summary(self) -> dict[str, Any]:
        self.ensure_properties()
        by_status: dict[str, int] = {}
        by_group: dict[str, dict[str, int]] = {}
        for p in self.properties.values():
            s = p.status.value
            by_status[s] = by_status.get(s, 0) + 1
            if p.group not in by_group:
                by_group[p.group] = {}
            by_group[p.group][s] = by_group[p.group].get(s, 0) + 1
        return {
            "total": len(self.properties),
            "by_status": by_status,
            "by_group": by_group,
            "critical_unknown": len(self.critical_unknown_properties()),
            "blocked": len(self.blocked_properties()),
            "confirmed_issues": len(self.confirmed_issues()),
            "verdict": self.coverage_verdict(),
        }


def calculate_coverage(
    app: "ApplicationModel",
    hypotheses: list,
    investigations: list,
    coverage: SecurityCoverageModel,
) -> SecurityCoverageModel:
    coverage.ensure_domains()
    coverage.ensure_properties()

    if app.services:
        coverage.set_property_status("surface.host_discovery", PropertyStatus.OBSERVED,
                                     evidence_refs=[s.id for s in app.services[:3]])
        coverage.set_property_status("surface.port_discovery", PropertyStatus.OBSERVED,
                                     evidence_refs=[s.id for s in app.services[:3]])
        coverage.set_property_status("surface.service_enumeration", PropertyStatus.OBSERVED,
                                     evidence_refs=[s.id for s in app.services[:3]])

    if app.web_targets:
        coverage.set_property_status("surface.web_discovery", PropertyStatus.APPLICABLE)
    if app.endpoints:
        ev = [e.id for e in app.endpoints[:5]]
        coverage.set_property_status("surface.web_discovery", PropertyStatus.OBSERVED, evidence_refs=ev)

    js_eps = [e for e in app.endpoints if "javascript" in (e.sources or [])]
    if js_eps:
        coverage.set_property_status("surface.js_discovery", PropertyStatus.OBSERVED,
                                     evidence_refs=[e.id for e in js_eps[:3]])

    graphql_eps = [e for e in app.endpoints if "graphql" in e.path.lower()]
    if graphql_eps:
        coverage.set_property_status("surface.graphql_discovery", PropertyStatus.APPLICABLE,
                                     evidence_refs=[e.id for e in graphql_eps[:3]])
    else:
        coverage.set_property_status("surface.graphql_discovery", PropertyStatus.NOT_APPLICABLE)

    if app.api_operations:
        coverage.set_property_status("surface.api_discovery", PropertyStatus.OBSERVED,
                                     evidence_refs=[o.id for o in app.api_operations[:3]])

    login_eps = [e for e in app.endpoints if "login" in e.path.lower() or "signin" in e.path.lower()]
    register_eps = [e for e in app.endpoints if "register" in e.path.lower() or "signup" in e.path.lower()]
    reset_eps = [e for e in app.endpoints if "reset" in e.path.lower()]
    has_auth = bool(app.authentication or login_eps)

    if has_auth:
        coverage.set_property_status("auth.login", PropertyStatus.APPLICABLE,
                                     evidence_refs=[e.id for e in login_eps[:2]])
        if register_eps:
            coverage.set_property_status("auth.registration", PropertyStatus.APPLICABLE,
                                         evidence_refs=[e.id for e in register_eps[:2]])
        if reset_eps:
            coverage.set_property_status("auth.password_reset", PropertyStatus.APPLICABLE,
                                         evidence_refs=[e.id for e in reset_eps[:2]])
    else:
        for pid in ["auth.login", "auth.logout", "auth.registration", "auth.password_reset",
                    "auth.session_establishment", "auth.session_invalidation",
                    "auth.session_persistence", "auth.mfa", "auth.state_transitions"]:
            coverage.set_property_status(pid, PropertyStatus.NOT_APPLICABLE)

    if app.sessions:
        coverage.set_property_status("auth.session_establishment", PropertyStatus.OBSERVED,
                                     evidence_refs=[s.id for s in app.sessions[:3]])
    elif has_auth:
        coverage.set_property_status("auth.session_establishment", PropertyStatus.APPLICABLE)

    object_eps = [e for e in app.endpoints if e.has_object_reference]
    admin_eps = [e for e in app.endpoints if "admin" in e.path.lower()]
    multiple_identities = len(app.identities) > 1

    if object_eps:
        coverage.set_property_status("authz.object_level", PropertyStatus.APPLICABLE,
                                     evidence_refs=[e.id for e in object_eps[:3]])
        coverage.set_property_status("authz.horizontal", PropertyStatus.APPLICABLE,
                                     evidence_refs=[e.id for e in object_eps[:3]])
        coverage.set_property_status("authz.resource_ownership", PropertyStatus.APPLICABLE,
                                     evidence_refs=[e.id for e in object_eps[:3]])
        if multiple_identities:
            coverage.set_property_status("api.object_ids", PropertyStatus.OBSERVED,
                                         evidence_refs=[e.id for e in object_eps[:3]])
    else:
        for pid in ["authz.object_level", "authz.horizontal", "authz.resource_ownership"]:
            coverage.set_property_status(pid, PropertyStatus.NOT_APPLICABLE)

    if admin_eps:
        coverage.set_property_status("authz.function_level", PropertyStatus.APPLICABLE,
                                     evidence_refs=[e.id for e in admin_eps[:3]])
        coverage.set_property_status("authz.admin_access", PropertyStatus.APPLICABLE,
                                     evidence_refs=[e.id for e in admin_eps[:3]])
        coverage.set_property_status("authz.vertical", PropertyStatus.APPLICABLE,
                                     evidence_refs=[e.id for e in admin_eps[:3]])
    elif has_auth:
        coverage.set_property_status("authz.function_level", PropertyStatus.APPLICABLE)
        coverage.set_property_status("authz.vertical", PropertyStatus.APPLICABLE)
    else:
        for pid in ["authz.function_level", "authz.admin_access", "authz.vertical"]:
            coverage.set_property_status(pid, PropertyStatus.NOT_APPLICABLE)

    try:
        from horcrux.intel.investigations import InvestigationState
        authz_invs = [i for i in investigations if i.specialist == "AuthorizationAgent"]
        for inv in authz_invs:
            if inv.state in (InvestigationState.SUPPORTED, InvestigationState.COMPLETE):
                for pid in ["authz.object_level", "authz.horizontal"]:
                    if coverage.properties.get(pid) and coverage.properties[pid].status in (
                            PropertyStatus.APPLICABLE, PropertyStatus.OBSERVED):
                        coverage.set_property_status(pid, PropertyStatus.VALIDATED)
            elif inv.state == InvestigationState.SCOPE_BLOCKED:
                for pid in ["authz.object_level", "authz.horizontal"]:
                    coverage.set_property_status(pid, PropertyStatus.BLOCKED, notes="scope blocked")
    except Exception:
        pass

    ssrf_hyps = [h for h in hypotheses if getattr(h, 'hypothesis_class', None) and h.hypothesis_class.value == "ssrf"]
    if ssrf_hyps:
        coverage.set_property_status("input.ssrf", PropertyStatus.APPLICABLE,
                                     evidence_refs=[r for h in ssrf_hyps for r in h.evidence_refs[:3]])
    else:
        coverage.set_property_status("input.ssrf", PropertyStatus.NOT_APPLICABLE)

    upload_eps = [e for e in app.endpoints if "upload" in e.path.lower()]
    if upload_eps or any(getattr(h, 'hypothesis_class', None) and h.hypothesis_class.value == "file_upload" for h in hypotheses):
        coverage.set_property_status("input.file_handling", PropertyStatus.APPLICABLE,
                                     evidence_refs=[e.id for e in upload_eps[:2]])
    else:
        coverage.set_property_status("input.file_handling", PropertyStatus.NOT_APPLICABLE)

    if app.workflows or len(app.endpoints) >= 5:
        coverage.set_property_status("biz.workflow_sequencing", PropertyStatus.APPLICABLE)
        if len(app.workflow_transitions) > 2:
            coverage.set_property_status("biz.state_transitions", PropertyStatus.OBSERVED,
                                         evidence_refs=[t.id for t in app.workflow_transitions[:3]])
    else:
        for pid in ["biz.workflow_sequencing", "biz.state_transitions", "biz.prerequisite_enforcement",
                    "biz.price_manipulation", "biz.duplicate_actions", "biz.race_conditions",
                    "biz.privilege_flows"]:
            coverage.set_property_status(pid, PropertyStatus.NOT_APPLICABLE)

    if has_auth and (admin_eps or any("role" in e.path.lower() for e in app.endpoints)):
        coverage.set_property_status("biz.privilege_flows", PropertyStatus.APPLICABLE)

    api_eps = [e for e in app.endpoints if e.path.startswith(("/api", "/rest", "/v"))]
    if api_eps:
        coverage.set_property_status("api.authorization", PropertyStatus.APPLICABLE,
                                     evidence_refs=[e.id for e in api_eps[:3]])
    else:
        coverage.set_property_status("api.authorization", PropertyStatus.NOT_APPLICABLE)
        coverage.set_property_status("api.object_ids", PropertyStatus.NOT_APPLICABLE)

    if app.endpoints:
        coverage.set_property_status("data.sensitive_info", PropertyStatus.APPLICABLE)

    if any(s.port == 22 or "ssh" in (s.service_name or "").lower() for s in app.services):
        coverage.set_property_status("infra.ssh", PropertyStatus.APPLICABLE)
    else:
        coverage.set_property_status("infra.ssh", PropertyStatus.NOT_APPLICABLE)
    if any(s.port in (139, 445) for s in app.services):
        coverage.set_property_status("infra.smb", PropertyStatus.APPLICABLE)
    else:
        coverage.set_property_status("infra.smb", PropertyStatus.NOT_APPLICABLE)
    if any(s.port in (3306, 5432, 1433, 27017, 6379) for s in app.services):
        coverage.set_property_status("infra.database_exposure", PropertyStatus.APPLICABLE)
    else:
        coverage.set_property_status("infra.database_exposure", PropertyStatus.NOT_APPLICABLE)

    try:
        from horcrux.intel.investigations import InvestigationState
        _update_domain_from_investigations(coverage, "authentication",
            [i for i in investigations if i.specialist == "AuthenticationAgent"])
        _update_domain_from_investigations(coverage, "business_logic",
            [i for i in investigations if i.specialist == "BusinessLogicAgent"])
        _update_domain_from_investigations(coverage, "api_security",
            [i for i in investigations if i.specialist == "APIAgent"])
    except Exception:
        pass

    if app.services:
        coverage.set_status("infrastructure", CoverageStatus.REVIEWED,
                            f"{len(app.services)} services mapped")

    return coverage


def _update_domain_from_investigations(
    coverage: SecurityCoverageModel,
    domain: str,
    investigations: list,
) -> None:
    from horcrux.intel.investigations import InvestigationState
    if not investigations:
        return
    coverage.ensure_domains()
    if domain not in coverage.domains:
        coverage.domains[domain] = DomainCoverage(domain=domain)
    dc = coverage.domains[domain]
    dc.investigation_ids = [i.id for i in investigations[:10]]
    if any(i.state == InvestigationState.SCOPE_BLOCKED for i in investigations):
        coverage.set_status(domain, CoverageStatus.BLOCKED, "Scope/policy blocked")
    elif any(i.state == InvestigationState.RUNNING for i in investigations):
        coverage.set_status(domain, CoverageStatus.IN_PROGRESS)
    elif any(i.state in (InvestigationState.SUPPORTED, InvestigationState.COMPLETE) for i in investigations):
        coverage.set_status(domain, CoverageStatus.REVIEWED)
    elif any(i.state == InvestigationState.REFUTED for i in investigations):
        coverage.set_status(domain, CoverageStatus.REFUTED)
    elif any(i.state in (InvestigationState.UNAVAILABLE, InvestigationState.FAILED) for i in investigations):
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


def assessment_completeness(state: "WorkspaceState") -> dict:
    """Evaluate assessment completeness. NEVER collapses UNKNOWN to clean."""
    coverage = state.get_security_coverage()
    coverage.ensure_domains()
    coverage.ensure_properties()
    pct = coverage.percentage_complete()
    verdict = coverage.coverage_verdict()
    blocking = coverage.completeness_blocking_reasons()

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

    auth_reviewed = coverage.get("authorization") not in (
        CoverageStatus.NOT_REVIEWED, CoverageStatus.NOT_RELEVANT,
    )
    authz_reviewed = coverage.get("object_level_authorization") not in (
        CoverageStatus.NOT_REVIEWED, CoverageStatus.NOT_RELEVANT,
    )

    # CRITICAL: sufficient requires coverage verdict COMPLETE
    sufficient = (
        verdict == "COMPLETE"
        and high_value_surfaces >= 3
        and not pending_high
        and (auth_reviewed or authz_reviewed or not app.endpoints)
        and pct.get("web", 0) >= 50
    )

    # Never sufficient if auth surface present but no auth testing
    if sufficient and _has_auth_surface(app) and not _has_auth_testing(state, coverage):
        sufficient = False
        blocking.append("Authentication properties UNKNOWN despite auth surface discovered")

    # External-engine fabric: report which intelligence participated (additive —
    # never silently implies comprehensive coverage when engines are missing).
    engine_runs = dict(getattr(state, "external_engine_runs", {}) or {})
    engine_summary = coverage.engine_coverage_summary() if hasattr(coverage, "engine_coverage_summary") else {}
    external_verdict = engine_summary.get("verdict", "NOT_ASSESSED") if engine_summary else "NOT_ASSESSED"
    executed = [pid for pid, run in engine_runs.items()
                if str((run or {}).get("status", "")).upper() == "COMPLETE"]
    failed = [pid for pid, run in engine_runs.items()
              if str((run or {}).get("status", "")).upper() in (
                  "FAILED", "AUTH_FAILED", "RESULT_RETRIEVAL_FAILED", "SCAN_FAILED",
                  "UNAVAILABLE", "RATE_LIMITED")]
    not_configured = [pid for pid in ("tenable", "qualys", "rapid7", "greenbone", "msdefender")
                      if pid not in engine_runs
                      or str((engine_runs[pid] or {}).get("status", "")).upper() == "NOT_CONFIGURED"]
    if failed:
        blocking.append(f"External vulnerability engines failed: {', '.join(sorted(failed))} "
                        "— relevant vulnerability evidence incomplete (PARTIAL)")
    if executed and (failed or not_configured):
        blocking.append("External vulnerability coverage PARTIAL: only "
                        f"{', '.join(sorted(executed))} contributed results; "
                        "results from unavailable engines are not negative evidence")

    return {
        "sufficient": sufficient,
        "verdict": verdict,
        "blocking_reasons": blocking,
        "coverage_percentages": pct,
        "high_value_surfaces": high_value_surfaces,
        "open_hypotheses": len(open_hyps),
        "pending_high_investigations": len(pending_high),
        "authorization_investigated": auth_reviewed or authz_reviewed,
        "business_logic_investigated": coverage.get("business_logic") not in (
            CoverageStatus.NOT_REVIEWED, CoverageStatus.NOT_RELEVANT,
        ),
        "property_summary": coverage.property_summary(),
        "external_engine_verdict": external_verdict,
        "external_engine_summary": engine_summary,
        "external_engines_executed": sorted(executed),
        "external_engines_failed": sorted(failed),
        "external_engines_not_configured": sorted(not_configured),
    }


def _has_auth_surface(app: "ApplicationModel") -> bool:
    return bool(
        app.authentication
        or any(k in e.path.lower() for e in app.endpoints
               for k in ("login", "register", "signin", "auth"))
    )


def _has_auth_testing(state: "WorkspaceState", coverage: SecurityCoverageModel) -> bool:
    app = state.get_application_model()
    if app.sessions:
        return True
    auth_status = coverage.get("authentication")
    return auth_status not in (CoverageStatus.NOT_REVIEWED, CoverageStatus.NOT_RELEVANT)


# Public aliases for backward compatibility
has_auth_surface = _has_auth_surface
has_auth_testing = _has_auth_testing
