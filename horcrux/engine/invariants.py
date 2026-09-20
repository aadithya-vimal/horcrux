"""Security invariants — exist independently of how they were tested.

Multiple engines contribute evidence toward the same invariant; the
invariant evaluation decides PASS/FAIL/INCONCLUSIVE deterministically.
"""

from __future__ import annotations

from pydantic import BaseModel


class InvariantResult(BaseModel):
    invariant_id: str
    status: str = "INCONCLUSIVE"  # HOLD|VIOLATED|INCONCLUSIVE
    evidence: list[str] = []


INVARIANTS = {
    "INV-AUTH-001": "Protected resource must reject unauthenticated caller.",
    "INV-AUTHZ-001": "Identity A must not access object owned by identity B.",
    "INV-AUTHZ-002": "Low-privilege identity must not invoke privileged operation.",
    "INV-API-001": "Public API must not expose unauthorized sensitive fields.",
    "INV-API-002": "Writable fields must not permit unauthorized privilege/property changes.",
    "INV-INJECT-001": "Untrusted input must not alter server-side query semantics.",
    "INV-FILE-001": "User-controlled path must not escape intended filesystem boundary.",
    "INV-SSRF-001": "User-controlled URL must not cause unauthorized server-side network access.",
    "INV-WORKFLOW-001": "Workflow state transition must preserve authorization and business invariants.",
}

# property -> invariants it can violate
PROPERTY_INVARIANTS: dict[str, list[str]] = {
    "AUTHN_UNAUTH_PROTECTED_ACCESS": ["INV-AUTH-001"],
    "AUTHN_BYPASS": ["INV-AUTH-001"],
    "AUTHZ_BOLA_IDOR": ["INV-AUTHZ-001"],
    "AUTHZ_HORIZONTAL": ["INV-AUTHZ-001"],
    "AUTHZ_TENANT_ISOLATION": ["INV-AUTHZ-001"],
    "AUTHZ_VERTICAL_PRIVESC": ["INV-AUTHZ-002"],
    "AUTHZ_FUNCTION_LEVEL": ["INV-AUTHZ-002"],
    "API_EXCESSIVE_DATA": ["INV-API-001"],
    "API_MASS_ASSIGNMENT": ["INV-API-002"],
    "INJECT_SQL": ["INV-INJECT-001"],
    "INJECT_NOSQL": ["INV-INJECT-001"],
    "INJECT_COMMAND": ["INV-INJECT-001"],
    "INJECT_TEMPLATE": ["INV-INJECT-001"],
    "INJECT_LDAP": ["INV-INJECT-001"],
    "INJECT_XPATH": ["INV-INJECT-001"],
    "PATH_TRAVERSAL": ["INV-FILE-001"],
    "SSRF_BASIC": ["INV-SSRF-001"],
    "SSRF_INTERNAL": ["INV-SSRF-001"],
    "BIZ_WORKFLOW_BYPASS": ["INV-WORKFLOW-001"],
    "BIZ_QUANTITY_MANIPULATION": ["INV-WORKFLOW-001"],
    "BIZ_PRICE_MANIPULATION": ["INV-WORKFLOW-001"],
    "API_STATE_TRANSITION": ["INV-WORKFLOW-001"],
}


def evaluate_invariant(invariant_id: str, oracle_results: list) -> InvariantResult:
    """VIOLATED if any linked property CONFIRMED; HOLD if all linked
    evaluated properties REFUTED; else INCONCLUSIVE."""
    linked = [r for r in oracle_results
              if invariant_id in PROPERTY_INVARIANTS.get(r.property_id, [])]
    if any(r.verdict == "CONFIRMED" for r in linked):
        return InvariantResult(invariant_id=invariant_id, status="VIOLATED",
                               evidence=[r.property_id for r in linked if r.verdict == "CONFIRMED"])
    if linked and all(r.verdict == "REFUTED" for r in linked):
        return InvariantResult(invariant_id=invariant_id, status="HOLD",
                               evidence=[r.property_id for r in linked])
    return InvariantResult(invariant_id=invariant_id, status="INCONCLUSIVE",
                           evidence=[r.property_id for r in linked])
