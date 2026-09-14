"""Task-specific AI reasoning roles (Phase 7, Part 5).

One generic "security AI" prompt is not used. Each role defines:
- task description
- allowed input context
- output schema
- relevant capabilities
- evidence types it cares about
- hypotheses it can generate
- investigations it can recommend
- safety boundary

Roles activate from ApplicationModel/evidence — never randomly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AnalystRole:
    role_id: str
    name: str
    task: str
    allowed_context: list[str] = field(default_factory=list)
    output_schema: dict[str, str] = field(default_factory=dict)
    relevant_capabilities: list[str] = field(default_factory=list)
    evidence_types: list[str] = field(default_factory=list)
    hypothesis_classes: list[str] = field(default_factory=list)
    investigations: list[str] = field(default_factory=list)
    safety_boundary: str = "Non-destructive analysis only; no exploitation."
    activation_hint: str = ""


ROLE_REGISTRY: dict[str, AnalystRole] = {
    "ReconAnalyst": AnalystRole(
        role_id="ReconAnalyst", name="Recon Analyst",
        task="Map network services and initial attack surface from service inventory.",
        allowed_context=["services", "ports", "software"],
        output_schema={"services": "list", "web_targets": "list", "next": "str"},
        relevant_capabilities=["nmap_discovery"],
        evidence_types=["service_observation"],
        hypothesis_classes=[], investigations=["Map API structure and authentication requirements"],
        activation_hint="Always eligible when services exist but model is empty."),
    "WebAnalyst": AnalystRole(
        role_id="WebAnalyst", name="Web Analyst",
        task="Understand web structure, routes, forms, client-side behavior.",
        allowed_context=["endpoints", "routes", "forms", "technologies", "parameters"],
        output_schema={"endpoints": "list", "routes": "list", "forms": "list"},
        relevant_capabilities=["http_probe", "js_analyze", "content_discovery", "endpoint_validate", "browser_navigate"],
        evidence_types=["endpoint_observation", "route_discovery", "parameter_observation"],
        hypothesis_classes=["information_disclosure", "injection"],
        investigations=["Complete functional application structure discovery"],
        activation_hint="Web targets present."),
    "APIAnalyst": AnalystRole(
        role_id="APIAnalyst", name="API Analyst",
        task="Map API endpoints, schemas, authorization boundaries.",
        allowed_context=["endpoints", "parameters", "object_types"],
        output_schema={"endpoints": "list", "schemas": "list"},
        relevant_capabilities=["http_probe", "graphql_probe", "param_fuzz"],
        evidence_types=["endpoint_observation", "graphql_observation"],
        hypothesis_classes=["graphql", "api_security"],
        investigations=["Test GraphQL introspection and authorization boundaries"],
        activation_hint="/api, /rest, /v1, /graphql endpoints."),
    "AuthenticationAnalyst": AnalystRole(
        role_id="AuthenticationAnalyst", name="Authentication Analyst",
        task="Map authentication workflow and session security.",
        allowed_context=["authentication", "workflows", "identities"],
        output_schema={"auth_mechanisms": "list", "workflows": "list"},
        relevant_capabilities=["http_probe", "browser_navigate", "identity_switch", "jwt_analyze"],
        evidence_types=["auth_observation", "identity_context"],
        hypothesis_classes=["authentication", "session"],
        investigations=["Map authentication workflow and session lifecycle"],
        activation_hint="Login/register surfaces or auth mechanisms."),
    "AuthorizationAnalyst": AnalystRole(
        role_id="AuthorizationAnalyst", name="Authorization Analyst",
        task="Determine whether authorization boundaries are enforced (object + function level).",
        allowed_context=["endpoints", "object_types", "identities", "parameters"],
        output_schema={"authorization_tests": "list", "findings": "list"},
        relevant_capabilities=["http_probe", "identity_switch", "authz_compare"],
        evidence_types=["authorization_observation", "endpoint_observation"],
        hypothesis_classes=["idor_bola", "privilege_escalation"],
        investigations=["Determine whether object IDs are authorization-bound",
                        "Test privileged endpoints as anonymous and authenticated user"],
        activation_hint="Object IDs + multiple identities + object endpoints, or admin paths."),
    "BusinessLogicAnalyst": AnalystRole(
        role_id="BusinessLogicAnalyst", name="Business Logic Analyst",
        task="Understand workflows and test state-manipulation flaws.",
        allowed_context=["workflows", "endpoints", "forms"],
        output_schema={"workflow_tests": "list", "findings": "list"},
        relevant_capabilities=["http_probe", "browser_navigate"],
        evidence_types=["endpoint_observation", "form_observation"],
        hypothesis_classes=["business_logic"],
        investigations=["Test workflow state skipping and inconsistent authorization"],
        activation_hint="Multi-step workflows or state-changing endpoints."),
    "ClientSideAnalyst": AnalystRole(
        role_id="ClientSideAnalyst", name="Client-Side Analyst",
        task="Analyze JS bundles, DOM-derived routes, client-side trust boundaries.",
        allowed_context=["routes", "parameters", "technologies"],
        output_schema={"routes": "list", "parameters": "list", "risks": "list"},
        relevant_capabilities=["js_analyze", "browser_navigate"],
        evidence_types=["route_discovery", "parameter_observation"],
        hypothesis_classes=["client_side", "information_disclosure"],
        investigations=["Complete functional application structure discovery"],
        activation_hint="SPA framework or JS-derived routes."),
    "EvidenceAnalyst": AnalystRole(
        role_id="EvidenceAnalyst", name="Evidence Analyst",
        task="Validate whether observations support security claims; normalize evidence.",
        allowed_context=["evidence", "findings", "hypotheses"],
        output_schema={"validation_result": "str", "confidence": "float"},
        relevant_capabilities=["endpoint_validate"],
        evidence_types=["validation_result"],
        hypothesis_classes=[],
        investigations=["Review exposed endpoints for sensitive data leakage"],
        activation_hint="Candidate finding or open hypothesis."),
    "ValidationAnalyst": AnalystRole(
        role_id="ValidationAnalyst", name="Validation Analyst",
        task="Confirm or refute hypotheses with targeted, safe validation.",
        allowed_context=["hypotheses", "investigations", "coverage"],
        output_schema={"hypothesis_id": "str", "verdict": "str", "evidence": "list"},
        relevant_capabilities=["http_probe", "endpoint_validate", "authz_compare"],
        evidence_types=["validation_result", "authorization_observation"],
        hypothesis_classes=["injection", "ssrf", "file_upload"],
        investigations=["Test input validation on search and filter parameters",
                        "Test server-side URL fetch behavior on URL parameters"],
        activation_hint="Open hypothesis with validation requirements."),
    "AttackPathAnalyst": AnalystRole(
        role_id="AttackPathAnalyst", name="Attack Path Analyst",
        task="Correlate findings/hypotheses into evidence-backed attack paths.",
        allowed_context=["findings", "hypotheses", "attack_paths", "identities"],
        output_schema={"attack_paths": "list", "prerequisites": "list"},
        relevant_capabilities=[],
        evidence_types=["authorization_observation", "endpoint_observation"],
        hypothesis_classes=["privilege_escalation", "idor_bola"],
        investigations=[],
        activation_hint="Supported hypotheses or confirmed findings."),
    "ExploitIntelligenceAnalyst": AnalystRole(
        role_id="ExploitIntelligenceAnalyst", name="Exploit Intelligence Analyst",
        task="Correlate versioned software with exploit intelligence; prepare handoffs.",
        allowed_context=["software", "exploits"],
        output_schema={"candidates": "list", "handoff": "dict"},
        relevant_capabilities=["searchsploit_intel", "nuclei_scan"],
        evidence_types=["exploit_intelligence", "nuclei_finding"],
        hypothesis_classes=[],
        investigations=[],
        safety_boundary="Intelligence only; exploitation stops at operator handoff.",
        activation_hint="Reliable versioned software evidence."),
}


def activate_roles(state: Any) -> list[AnalystRole]:
    """Activate roles justified by current ApplicationModel/evidence."""
    try:
        app = state.get_application_model()
    except Exception:
        return [ROLE_REGISTRY["ReconAnalyst"]]
    active: list[AnalystRole] = []
    endpoints = getattr(app, "endpoints", [])
    has_api = any(e.path.startswith(("/api", "/rest", "/v1", "/graphql")) for e in endpoints)
    has_object = any(getattr(e, "has_object_reference", False) for e in endpoints)
    has_admin = any("admin" in e.path.lower() for e in endpoints)
    has_auth = bool(getattr(app, "authentication", []))
    has_workflow = bool(getattr(app, "workflows", []))
    has_graphql = any("graphql" in e.path.lower() for e in endpoints)
    has_upload = any("upload" in e.path.lower() for e in endpoints) or any(
        "file" in " ".join(getattr(f, "inputs", [])) for f in getattr(app, "forms", []))
    has_js = any("javascript" in (e.sources or []) for e in endpoints)
    has_sw = bool(getattr(state, "software", []))
    has_hyp = bool(state.get_hypotheses()) if hasattr(state, "get_hypotheses") else False

    if getattr(app, "services", []):
        active.append(ROLE_REGISTRY["ReconAnalyst"])
    if getattr(app, "web_targets", []):
        active.append(ROLE_REGISTRY["WebAnalyst"])
    if has_api or has_graphql:
        active.append(ROLE_REGISTRY["APIAnalyst"])
    if has_auth:
        active.append(ROLE_REGISTRY["AuthenticationAnalyst"])
    if has_object or has_admin:
        active.append(ROLE_REGISTRY["AuthorizationAnalyst"])
    if has_workflow or len(endpoints) >= 8:
        active.append(ROLE_REGISTRY["BusinessLogicAnalyst"])
    if has_js or (getattr(app, "profile", None) and getattr(app.profile, "app_type", "") == "SPA"):
        active.append(ROLE_REGISTRY["ClientSideAnalyst"])
    if has_hyp or getattr(state, "findings", []):
        active.append(ROLE_REGISTRY["EvidenceAnalyst"])
        active.append(ROLE_REGISTRY["ValidationAnalyst"])
    if has_hyp or getattr(state, "findings", []):
        active.append(ROLE_REGISTRY["AttackPathAnalyst"])
    if has_sw:
        active.append(ROLE_REGISTRY["ExploitIntelligenceAnalyst"])
    # Deduplicate preserving order.
    seen: set[str] = set()
    out: list[AnalystRole] = []
    for r in active:
        if r.role_id not in seen:
            seen.add(r.role_id)
            out.append(r)
    return out


def role_prompt(role: AnalystRole, context: str) -> str:
    caps = ", ".join(role.relevant_capabilities) or "none (analysis only)"
    return (
        f"You are HORCRUX {role.name}. {role.task}\n"
        f"Allowed context: {', '.join(role.allowed_context)}.\n"
        f"Relevant capabilities: {caps}.\n"
        f"Output JSON with keys: {', '.join(f'{k}: {v}' for k, v in role.output_schema.items())}.\n"
        f"Safety boundary: {role.safety_boundary} Do NOT invent vulnerabilities.\n"
        f"Workspace context:\n{context}"
    )
