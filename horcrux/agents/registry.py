"""Specialist agent registry."""

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


SPECIALIST_REGISTRY: dict[str, SpecialistSpec] = {
    "ReconAgent": SpecialistSpec(
        agent_id="ReconAgent",
        name="Recon Agent",
        objective="Map network services and initial attack surface",
        relevant_tools=["nmap"],
        evidence_requirements=["target reachable"],
        output_schema={"services": "list", "web_targets": "list"},
        stopping_conditions=["All open ports mapped"],
    ),
    "WebAgent": SpecialistSpec(
        agent_id="WebAgent",
        name="Web Agent",
        objective="Understand web application structure, routes, forms, and client-side behavior",
        relevant_skills=["xss", "file_upload"],
        relevant_tools=["js_analyzer", "http_probe", "browser_navigate", "validator"],
        evidence_requirements=["HTTP service discovered"],
        output_schema={"endpoints": "list", "routes": "list", "forms": "list"},
        stopping_conditions=["Application structure mapped", "No new routes from JS analysis"],
        activation_fn=lambda state: bool(state.get_application_model().web_targets),
    ),
    "APIAgent": SpecialistSpec(
        agent_id="APIAgent",
        name="API Agent",
        objective="Map and analyze API endpoints, schemas, and authorization",
        relevant_skills=["graphql", "idor"],
        relevant_tools=["http_probe", "graphql_probe"],
        evidence_requirements=["API or REST endpoints discovered"],
        output_schema={"endpoints": "list", "schemas": "list"},
        stopping_conditions=["API structure documented"],
        activation_fn=lambda state: any(
            e.path.startswith(("/api", "/rest", "/v1", "/graphql"))
            for e in state.get_application_model().endpoints
        ),
    ),
    "AuthenticationAgent": SpecialistSpec(
        agent_id="AuthenticationAgent",
        name="Authentication Agent",
        objective="Map authentication workflow and test session security",
        relevant_skills=["authentication", "jwt"],
        relevant_tools=["http_probe", "browser_navigate", "identity_switch"],
        evidence_requirements=["Login or registration surface discovered"],
        output_schema={"auth_mechanisms": "list", "workflows": "list"},
        stopping_conditions=["Auth workflow mapped"],
        activation_fn=lambda state: bool(state.get_application_model().authentication),
    ),
    "AuthorizationAgent": SpecialistSpec(
        agent_id="AuthorizationAgent",
        name="Authorization Agent",
        objective="Determine whether authorization boundaries are correctly enforced",
        relevant_skills=["authorization", "idor"],
        relevant_tools=["http_probe", "identity_switch"],
        evidence_requirements=["Object references or privileged endpoints"],
        output_schema={"authorization_tests": "list", "findings": "list"},
        stopping_conditions=["Object and function-level auth tested"],
        activation_fn=lambda state: any(
            e.has_object_reference or "admin" in e.path.lower()
            for e in state.get_application_model().endpoints
        ),
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
    ),
    "NetworkAgent": SpecialistSpec(
        agent_id="NetworkAgent",
        name="Network Agent",
        objective="Analyze non-web network services",
        relevant_tools=["service_enum"],
        evidence_requirements=["Non-HTTP services discovered"],
        activation_fn=lambda state: any(not s.is_web for s in state.get_application_model().services),
    ),
    "EvidenceAgent": SpecialistSpec(
        agent_id="EvidenceAgent",
        name="Evidence Agent",
        objective="Validate whether observations support security claims",
        relevant_tools=["validator", "http_probe"],
        evidence_requirements=["Candidate finding or hypothesis"],
        output_schema={"validation_result": "str", "confidence": "float"},
    ),
    "VulnerabilityValidationAgent": SpecialistSpec(
        agent_id="VulnerabilityValidationAgent",
        name="Vulnerability Validation Agent",
        objective="Confirm or refute hypotheses with targeted validation",
        relevant_tools=["http_probe", "validator"],
        evidence_requirements=["Open hypothesis with validation requirements"],
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
