"""Specialist agent registry — task-specific roles activated by evidence."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class SpecialistSpec:
    agent_id: str
    name: str
    objective: str
    relevant_skills: list[str] = field(default_factory=list)
    relevant_tools: list[str] = field(default_factory=list)
    evidence_requirements: list[str] = field(default_factory=list)
    output_schema: dict[str, str] = field(default_factory=dict)
    stopping_conditions: list[str] = field(default_factory=list)
    activation_fn: Callable[[Any], bool] | None = None
    # --- Phase 7 task-specific role metadata ---
    role_id: str = ""
    task_description: str = ""
    allowed_input_context: list[str] = field(default_factory=list)
    evidence_types: list[str] = field(default_factory=list)
    hypothesis_classes: list[str] = field(default_factory=list)
    safety_boundary: str = "Non-destructive investigation only; exploitation stops at operator handoff."


SPECIALIST_REGISTRY: dict[str, SpecialistSpec] = {
    "ReconAgent": SpecialistSpec(
        agent_id="ReconAgent",
        name="Recon Agent",
        objective="Map network services and initial attack surface",
        relevant_tools=["nmap_discovery"],
        evidence_requirements=["target reachable"],
        output_schema={"services": "list", "web_targets": "list"},
        stopping_conditions=["All open ports mapped"],
        role_id="ReconAnalyst",
        task_description="Map network services and initial attack surface from service inventory.",
        allowed_input_context=["services", "ports", "software"],
        evidence_types=["service_observation"],
        hypothesis_classes=[],
    ),
    "WebAgent": SpecialistSpec(
        agent_id="WebAgent",
        name="Web Agent",
        objective="Understand web application structure, routes, forms, and client-side behavior",
        relevant_skills=["xss", "file_upload"],
        relevant_tools=["js_analyze", "http_probe", "browser_navigate", "endpoint_validate", "content_discovery"],
        evidence_requirements=["HTTP service discovered"],
        output_schema={"endpoints": "list", "routes": "list", "forms": "list"},
        stopping_conditions=["Application structure mapped", "No new routes from JS analysis"],
        activation_fn=lambda state: bool(state.get_application_model().web_targets),
        role_id="WebAnalyst",
        task_description="Understand web structure, routes, forms, client-side behavior.",
        allowed_input_context=["endpoints", "routes", "forms", "technologies", "parameters"],
        evidence_types=["endpoint_observation", "route_discovery", "parameter_observation"],
        hypothesis_classes=["information_disclosure", "injection"],
    ),
    "APIAgent": SpecialistSpec(
        agent_id="APIAgent",
        name="API Agent",
        objective="Map and analyze API endpoints, schemas, and authorization",
        relevant_skills=["graphql", "idor"],
        relevant_tools=["http_probe", "graphql_probe", "param_fuzz"],
        evidence_requirements=["API or REST endpoints discovered"],
        output_schema={"endpoints": "list", "schemas": "list"},
        stopping_conditions=["API structure documented"],
        activation_fn=lambda state: any(
            e.path.startswith(("/api", "/rest", "/v1", "/graphql"))
            for e in state.get_application_model().endpoints
        ),
        role_id="APIAnalyst",
        task_description="Map API endpoints, schemas, authorization boundaries.",
        allowed_input_context=["endpoints", "parameters", "object_types"],
        evidence_types=["endpoint_observation", "graphql_observation"],
        hypothesis_classes=["graphql", "api_security"],
    ),
    "AuthenticationAgent": SpecialistSpec(
        agent_id="AuthenticationAgent",
        name="Authentication Agent",
        objective="Map authentication workflow and test session security",
        relevant_skills=["authentication", "jwt"],
        relevant_tools=["http_probe", "browser_navigate", "identity_switch", "jwt_analyze"],
        evidence_requirements=["Login or registration surface discovered"],
        output_schema={"auth_mechanisms": "list", "workflows": "list"},
        stopping_conditions=["Auth workflow mapped"],
        activation_fn=lambda state: bool(state.get_application_model().authentication),
        role_id="AuthenticationAnalyst",
        task_description="Map authentication workflow and session security.",
        allowed_input_context=["authentication", "workflows", "identities"],
        evidence_types=["auth_observation", "identity_context"],
        hypothesis_classes=["authentication", "session"],
    ),
    "AuthorizationAgent": SpecialistSpec(
        agent_id="AuthorizationAgent",
        name="Authorization Agent",
        objective="Determine whether authorization boundaries are correctly enforced",
        relevant_skills=["authorization", "idor"],
        relevant_tools=["http_probe", "identity_switch", "authz_compare"],
        evidence_requirements=["Object references or privileged endpoints"],
        output_schema={"authorization_tests": "list", "findings": "list"},
        stopping_conditions=["Object and function-level auth tested"],
        activation_fn=lambda state: any(
            e.has_object_reference or "admin" in e.path.lower()
            for e in state.get_application_model().endpoints
        ),
        role_id="AuthorizationAnalyst",
        task_description="Determine whether authorization boundaries are enforced (object + function level).",
        allowed_input_context=["endpoints", "object_types", "identities", "parameters"],
        evidence_types=["authorization_observation", "endpoint_observation"],
        hypothesis_classes=["idor_bola", "privilege_escalation"],
    ),
    "BusinessLogicAgent": SpecialistSpec(
        agent_id="BusinessLogicAgent",
        name="Business Logic Agent",
        objective="Understand workflows and test for state manipulation flaws",
        relevant_skills=["business_logic"],
        relevant_tools=["http_probe", "browser_navigate"],
        evidence_requirements=["Multi-step workflow discovered"],
        output_schema={"workflow_tests": "list", "findings": "list"},
        stopping_conditions=["Workflow steps tested for state skipping"],
        activation_fn=lambda state: len(state.get_application_model().workflows) >= 1,
        role_id="BusinessLogicAnalyst",
        task_description="Understand workflows and test state-manipulation flaws.",
        allowed_input_context=["workflows", "endpoints", "forms"],
        evidence_types=["endpoint_observation", "form_observation"],
        hypothesis_classes=["business_logic"],
    ),
    "NetworkAgent": SpecialistSpec(
        agent_id="NetworkAgent",
        name="Network Agent",
        objective="Analyze non-web network services",
        relevant_tools=["smb_enum", "ldap_enum", "kerberos_enum", "ssh_enum", "ftp_enum", "smtp_enum", "dns_enum", "snmp_enum", "database_enum", "remote_enum"],
        evidence_requirements=["Non-HTTP services discovered"],
        activation_fn=lambda state: any(not s.is_web for s in state.get_application_model().services),
        role_id="ReconAnalyst",
        task_description="Analyze non-web network services with protocol-specific enumeration.",
        allowed_input_context=["services", "service_facts"],
        evidence_types=["service_observation"],
        hypothesis_classes=[],
    ),
    "EvidenceAgent": SpecialistSpec(
        agent_id="EvidenceAgent",
        name="Evidence Agent",
        objective="Validate whether observations support security claims",
        relevant_tools=["endpoint_validate", "http_probe"],
        evidence_requirements=["Candidate finding or hypothesis"],
        output_schema={"validation_result": "str", "confidence": "float"},
        role_id="EvidenceAnalyst",
        task_description="Validate whether observations support security claims; normalize evidence.",
        allowed_input_context=["evidence", "findings", "hypotheses"],
        evidence_types=["validation_result"],
        hypothesis_classes=[],
    ),
    "VulnerabilityValidationAgent": SpecialistSpec(
        agent_id="VulnerabilityValidationAgent",
        name="Vulnerability Validation Agent",
        objective="Confirm or refute hypotheses with targeted validation",
        relevant_tools=["http_probe", "endpoint_validate", "authz_compare", "param_fuzz"],
        evidence_requirements=["Open hypothesis with validation requirements"],
        role_id="ValidationAnalyst",
        task_description="Confirm or refute hypotheses with targeted, safe validation.",
        allowed_input_context=["hypotheses", "investigations", "coverage"],
        evidence_types=["validation_result", "authorization_observation"],
        hypothesis_classes=["injection", "ssrf", "file_upload"],
    ),
    "ClientSideAgent": SpecialistSpec(
        agent_id="ClientSideAgent",
        name="Client-Side Agent",
        objective="Analyze JS bundles and client-side trust boundaries",
        relevant_skills=["xss"],
        relevant_tools=["js_analyze", "browser_navigate"],
        evidence_requirements=["SPA framework or JS-derived routes"],
        output_schema={"routes": "list", "parameters": "list", "risks": "list"},
        stopping_conditions=["Client-side routes and parameters mapped"],
        activation_fn=lambda state: any(
            "javascript" in (e.sources or [])
            for e in state.get_application_model().endpoints),
        role_id="ClientSideAnalyst",
        task_description="Analyze JS bundles, DOM-derived routes, client-side trust boundaries.",
        allowed_input_context=["routes", "parameters", "technologies"],
        evidence_types=["route_discovery", "parameter_observation"],
        hypothesis_classes=["client_side"],
    ),
    "AttackPathAgent": SpecialistSpec(
        agent_id="AttackPathAgent",
        name="Attack Path Agent",
        objective="Correlate findings and hypotheses into attack paths",
        relevant_tools=[],
        evidence_requirements=["Supported hypotheses or confirmed findings"],
        output_schema={"attack_paths": "list", "prerequisites": "list"},
        stopping_conditions=["Attack paths rebuilt"],
        activation_fn=lambda state: bool(
            [h for h in state.get_hypotheses() if h.status.value in {"SUPPORTED", "CONFIRMED"}]
            or state.findings),
        role_id="AttackPathAnalyst",
        task_description="Correlate findings/hypotheses into evidence-backed attack paths.",
        allowed_input_context=["findings", "hypotheses", "attack_paths"],
        evidence_types=["authorization_observation"],
        hypothesis_classes=["privilege_escalation", "idor_bola"],
    ),
    "ExploitIntelAgent": SpecialistSpec(
        agent_id="ExploitIntelAgent",
        name="Exploit Intelligence Agent",
        objective="Correlate versioned software with exploit intelligence; prepare handoffs",
        relevant_tools=["searchsploit_intel", "nuclei_scan"],
        evidence_requirements=["Reliable versioned software evidence"],
        output_schema={"candidates": "list", "handoff": "dict"},
        stopping_conditions=["Intelligence correlated; handoffs prepared"],
        activation_fn=lambda state: bool(state.software),
        role_id="ExploitIntelligenceAnalyst",
        task_description="Correlate versioned software with exploit intelligence; prepare handoffs.",
        allowed_input_context=["software", "exploits"],
        evidence_types=["exploit_intelligence", "nuclei_finding"],
        hypothesis_classes=[],
        safety_boundary="Intelligence only; exploitation stops at operator handoff.",
    ),
}


def select_specialists(state) -> list[SpecialistSpec]:
    """Select specialists justified by current evidence."""
    selected: list[SpecialistSpec] = []
    for spec in SPECIALIST_REGISTRY.values():
        if spec.activation_fn is None:
            continue
        try:
            if spec.activation_fn(state):
                selected.append(spec)
        except Exception:
            continue
    if not selected and state.get_application_model().services:
        selected.append(SPECIALIST_REGISTRY["ReconAgent"])
    return selected
