"""Hypothesis -> concrete work mapping (Part 17).

Every open hypothesis must be able to produce a concrete investigation:
hypothesis -> prerequisite -> executable test -> evidence oracle ->
adjudication. No endless hypotheses that never become tests.
"""

from __future__ import annotations

HYPOTHESIS_WORK: dict[str, dict] = {
    "idor_bola": {
        "steps": ["identify object type", "obtain object instance",
                  "identify owner", "obtain second identity",
                  "replay request", "compare response",
                  "evaluate INV-AUTHZ-001", "promote/refute/block"],
        "prerequisites": ["object_instance", "two_identities"],
        "oracle": "bola_oracle",
        "properties": ["AUTHZ_BOLA_IDOR", "AUTHZ_HORIZONTAL"],
    },
    "privilege_escalation": {
        "steps": ["identify privileged endpoint", "obtain low-priv identity",
                  "replay as low-priv", "compare with anon",
                  "evaluate INV-AUTHZ-002", "promote/refute/block"],
        "prerequisites": ["privileged_endpoint", "low_priv_identity"],
        "oracle": "vertical_oracle",
        "properties": ["AUTHZ_VERTICAL_PRIVESC", "AUTHZ_FUNCTION_LEVEL"],
    },
    "authentication": {
        "steps": ["identify auth surface", "probe anonymous access",
                  "evaluate INV-AUTH-001", "promote/refute/block"],
        "prerequisites": ["web_target"],
        "oracle": "authn_unauth_oracle",
        "properties": ["AUTHN_UNAUTH_PROTECTED_ACCESS", "AUTHN_BYPASS"],
    },
    "session": {
        "steps": ["identify session mechanism", "capture session",
                  "test rotation/invalidation", "promote/refute/block"],
        "prerequisites": ["session"],
        "oracle": "session_fixation_oracle",
        "properties": ["AUTHN_SESSION_FIXATION", "SESSION_INVALIDATION"],
    },
    "injection": {
        "steps": ["bind owned parameter", "capture baseline",
                  "controlled mutation", "differential analysis",
                  "repeatability check", "evaluate INV-INJECT-001",
                  "promote/refute/block"],
        "prerequisites": ["owned_parameter"],
        "oracle": "sqli_oracle",
        "properties": ["INJECT_SQL", "INJECT_NOSQL", "INJECT_COMMAND",
                       "INJECT_TEMPLATE", "INJECT_LDAP", "INJECT_XPATH"],
    },
    "ssrf": {
        "steps": ["bind URL parameter", "controlled URL probe",
                  "distinguish reflection from fetch", "network-side evidence",
                  "evaluate INV-SSRF-001", "promote/refute/block"],
        "prerequisites": ["owned_parameter"],
        "oracle": "ssrf_oracle",
        "properties": ["SSRF_BASIC", "SSRF_INTERNAL"],
    },
    "file_upload": {
        "steps": ["identify upload surface", "upload benign marker",
                  "verify storage", "verify retrievability",
                  "promote/refute/block"],
        "prerequisites": ["upload_surface"],
        "oracle": "upload_oracle",
        "properties": ["FILE_UPLOAD_WEAKNESS", "PATH_TRAVERSAL"],
    },
    "graphql": {
        "steps": ["confirm graphql endpoint", "introspection probe",
                  "enumerate operations", "cross-identity field probe",
                  "promote/refute/block"],
        "prerequisites": ["graphql_endpoint"],
        "oracle": "graphql_intro_oracle",
        "properties": ["GRAPHQL_INTROSPECTION", "GRAPHQL_AUTHZ"],
    },
    "business_logic": {
        "steps": ["model workflow states", "valid baseline flow",
                  "controlled mutation", "invariant check",
                  "repeatability", "evaluate INV-WORKFLOW-001",
                  "promote/refute/block"],
        "prerequisites": ["workflow_model"],
        "oracle": "workflow_oracle",
        "properties": ["BIZ_WORKFLOW_BYPASS", "BIZ_QUANTITY_MANIPULATION",
                       "BIZ_PRICE_MANIPULATION", "API_STATE_TRANSITION"],
    },
    "information_disclosure": {
        "steps": ["identify artifact surface", "live probe",
                  "format-specific validation", "promote/refute/block"],
        "prerequisites": ["web_target"],
        "oracle": "backup_oracle",
        "properties": ["CONFIG_BACKUP_EXPOSURE", "CONFIG_DEBUG_EXPOSURE",
                       "API_EXCESSIVE_DATA", "CONFIG_DIR_LISTING"],
    },
    "configuration": {
        "steps": ["probe headers/cors/methods", "compare against policy",
                  "promote/refute/block"],
        "prerequisites": ["web_target"],
        "oracle": "headers_oracle",
        "properties": ["CONFIG_HEADERS", "CONFIG_CORS", "CONFIG_ADMIN_EXPOSURE"],
    },
    "api_security": {
        "steps": ["map response schema", "check sensitive fields",
                  "test writable fields", "method matrix",
                  "promote/refute/block"],
        "prerequisites": ["web_target"],
        "oracle": "excessive_data_oracle",
        "properties": ["API_EXCESSIVE_DATA", "API_MASS_ASSIGNMENT", "API_METHOD_AUTH"],
    },
}


def concrete_work_for(hypothesis_class: str) -> dict:
    """Return the executable work plan for a hypothesis class.

    Unknown classes yield a generic evidence-gathering plan, never an
    autonomous conclusion."""
    return HYPOTHESIS_WORK.get((hypothesis_class or "").lower(), {
        "steps": ["gather endpoint evidence", "determine applicability",
                  "promote/refute/block"],
        "prerequisites": ["web_target"],
        "oracle": "",
        "properties": [],
    })
