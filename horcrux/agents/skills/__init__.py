"""Dynamic skill loading — contextual security expertise."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Skill:
    id: str
    name: str
    description: str
    hypothesis_classes: list[str] = field(default_factory=list)
    evidence_requirements: list[str] = field(default_factory=list)
    investigation_hints: list[str] = field(default_factory=list)
    false_positive_checks: list[str] = field(default_factory=list)
    relevant_tools: list[str] = field(default_factory=list)


SKILL_REGISTRY: dict[str, Skill] = {
    "idor": Skill(
        id="idor",
        name="IDOR / BOLA",
        description="Object-level authorization testing",
        hypothesis_classes=["idor_bola"],
        evidence_requirements=[
            "Object identifiers in URLs or parameters",
            "Multiple user identities available",
        ],
        investigation_hints=[
            "Swap object IDs between authenticated users",
            "Test sequential/predictable identifiers",
        ],
        false_positive_checks=["Verify object belongs to different user before claiming IDOR"],
        relevant_tools=["http_probe", "identity_switch"],
    ),
    "authentication": Skill(
        id="authentication",
        name="Authentication Security",
        description="Login, registration, and session lifecycle testing",
        hypothesis_classes=["authentication", "session"],
        evidence_requirements=["Login/register endpoints", "Session or JWT mechanism"],
        investigation_hints=["Map full auth workflow", "Test bypass and weak session handling"],
        relevant_tools=["http_probe", "browser_navigate"],
    ),
    "authorization": Skill(
        id="authorization",
        name="Authorization",
        description="Role and function-level access control testing",
        hypothesis_classes=["privilege_escalation"],
        evidence_requirements=["Privileged endpoints", "Multiple identity contexts"],
        investigation_hints=["Test admin endpoints as anonymous and user roles"],
        relevant_tools=["http_probe", "identity_switch"],
    ),
    "business_logic": Skill(
        id="business_logic",
        name="Business Logic",
        description="Workflow and state transition flaw testing",
        hypothesis_classes=["business_logic"],
        evidence_requirements=["Multi-step workflows", "State-changing operations"],
        investigation_hints=["Skip workflow steps", "Replay state-changing requests"],
        relevant_tools=["http_probe", "browser_navigate"],
    ),
    "ssrf": Skill(
        id="ssrf",
        name="SSRF",
        description="Server-side request forgery testing",
        hypothesis_classes=["ssrf"],
        evidence_requirements=["URL-fetching parameters"],
        investigation_hints=["Test callback URL parameters with controlled endpoints"],
        relevant_tools=["http_probe"],
    ),
    "graphql": Skill(
        id="graphql",
        name="GraphQL Security",
        description="GraphQL schema and authorization testing",
        hypothesis_classes=["graphql"],
        evidence_requirements=["GraphQL endpoint discovered"],
        investigation_hints=["Test introspection", "Authorization on mutations"],
        relevant_tools=["http_probe"],
    ),
    "jwt": Skill(
        id="jwt",
        name="JWT Security",
        description="JWT token validation and algorithm testing",
        hypothesis_classes=["session"],
        evidence_requirements=["JWT authentication mechanism"],
        investigation_hints=["Inspect alg header", "Test signature validation"],
        relevant_tools=["http_probe"],
    ),
    "file_upload": Skill(
        id="file_upload",
        name="File Upload",
        description="Unsafe file upload testing",
        hypothesis_classes=["file_upload"],
        evidence_requirements=["Upload forms or endpoints"],
        relevant_tools=["http_probe"],
    ),
    "sql_injection": Skill(
        id="sql_injection",
        name="SQL Injection",
        description="SQL injection testing on input parameters",
        hypothesis_classes=["injection"],
        evidence_requirements=["Database-backed parameters"],
        relevant_tools=["http_probe", "param_fuzz"],
    ),
    "xss": Skill(
        id="xss",
        name="Cross-Site Scripting",
        description="Reflected and stored XSS testing",
        hypothesis_classes=["injection", "client_side"],
        relevant_tools=["http_probe", "browser_navigate"],
    ),
}


def select_skills(hypothesis_classes: list[str], app_summary: dict) -> list[Skill]:
    """Load only relevant skills for current context."""
    selected: list[Skill] = []
    for skill in SKILL_REGISTRY.values():
        if any(hc in hypothesis_classes for hc in skill.hypothesis_classes):
            selected.append(skill)
    # Context-based additions
    if app_summary.get("authentication_surfaces", 0) > 0 and not any(s.id == "authentication" for s in selected):
        selected.append(SKILL_REGISTRY["authentication"])
    if app_summary.get("object_bearing_endpoints", 0) > 0 and not any(s.id == "idor" for s in selected):
        selected.append(SKILL_REGISTRY["idor"])
    return selected
