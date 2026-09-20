"""Investigation model and queue — targeted security investigations."""

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

from horcrux.intel.application_model import ApplicationModel, fingerprint
from horcrux.intel.hypotheses import Hypothesis, HypothesisClass, HypothesisStatus

if TYPE_CHECKING:
    from horcrux.models import WorkspaceState


class InvestigationState(str, Enum):
    PENDING = "PENDING"
    READY = "READY"
    RUNNING = "RUNNING"
    BLOCKED = "BLOCKED"
    SUPPORTED = "SUPPORTED"
    REFUTED = "REFUTED"
    COMPLETE = "COMPLETE"
    # --- Phase 7 execution outcomes (never COMPLETE on process-exit alone) ---
    FAILED = "FAILED"  # execution failed
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"  # ran but no useful evidence
    UNAVAILABLE = "UNAVAILABLE"  # capability unavailable
    SCOPE_BLOCKED = "SCOPE_BLOCKED"  # scope/policy blocked
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"  # operator approval required
    REQUIRES_AUTH = "REQUIRES_AUTH"  # requires authenticated session
    REQUIRES_SECOND_IDENTITY = "REQUIRES_SECOND_IDENTITY"  # requires distinct 2nd identity
    REQUIRES_TOOL = "REQUIRES_TOOL"  # required tool binary unavailable
    REQUIRES_OPERATOR = "REQUIRES_OPERATOR"  # manual operator action required
    NOT_APPLICABLE = "NOT_APPLICABLE"  # surface retired; test no longer applicable
    OUT_OF_SCOPE = "OUT_OF_SCOPE"  # explicitly out of engagement scope


ACTIONABLE_STATES = {InvestigationState.READY, InvestigationState.PENDING}
TERMINAL_EVIDENCE_STATES = {
    InvestigationState.SUPPORTED, InvestigationState.REFUTED,
    InvestigationState.COMPLETE, InvestigationState.INSUFFICIENT_EVIDENCE,
}
ALL_DONE_STATES = TERMINAL_EVIDENCE_STATES | {
    InvestigationState.FAILED, InvestigationState.REQUIRES_AUTH,
    InvestigationState.REQUIRES_SECOND_IDENTITY, InvestigationState.REQUIRES_TOOL,
    InvestigationState.REQUIRES_OPERATOR, InvestigationState.NOT_APPLICABLE,
    InvestigationState.OUT_OF_SCOPE, InvestigationState.BLOCKED,
    InvestigationState.UNAVAILABLE, InvestigationState.SCOPE_BLOCKED,
    InvestigationState.APPROVAL_REQUIRED,
}


#Cosmetic/low-value observations must never dominate scheduling.
LOW_VALUE_OBJECTIVE_PATTERNS = (
    "robots.txt", "sitemap.xml", "favicon", "banner grab",
    "server header", "generic header",
)


class InvestigationScore(BaseModel):
    evidence_relevance: float = 0.5
    expected_information_gain: float = 0.5
    impact_potential: float = 0.5
    coverage_gap: float = 0.5
    prerequisites_satisfied: float = 1.0
    execution_cost: float = 0.3
    redundancy_penalty: float = 0.0
    blast_radius: float = 0.5

    @property
    def total(self) -> float:
        return (
            self.evidence_relevance * 0.15
            + self.expected_information_gain * 0.20
            + self.impact_potential * 0.20
            + self.blast_radius * 0.15
            + self.coverage_gap * 0.15
            + self.prerequisites_satisfied * 0.10
            - self.execution_cost * 0.05
            - self.redundancy_penalty * 0.05
        )


class Investigation(BaseModel):
    id: str = ""
    objective: str = ""
    reason: str = ""
    evidence_refs: list[str] = Field(default_factory=list)
    vulnerability_classes: list[str] = Field(default_factory=list)
    required_capabilities: list[str] = Field(default_factory=list)
    candidate_tools: list[str] = Field(default_factory=list)
    prerequisites: list[str] = Field(default_factory=list)
    expected_information_gain: str = "medium"  # low, medium, high
    priority: float = 0.5
    state: InvestigationState = InvestigationState.PENDING
    hypothesis_id: str = ""
    specialist: str = ""
    score: InvestigationScore = Field(default_factory=InvestigationScore)
    result_summary: str = ""
    # --- Autonomous & Multi-Perspective Enhancements ---
    blast_radius: str = "medium"  # low, medium, high, critical
    identity_requirement: str = ""
    attempts: int = 0
    confidence: float = 0.5
    observations: list[str] = Field(default_factory=list)
    next_actions: list[str] = Field(default_factory=list)

    def ensure_id(self) -> str:
        if not self.id:
            self.id = fingerprint("inv", self.objective[:80], self.hypothesis_id)
        return self.id


HYPOTHESIS_TO_INVESTIGATIONS: dict[HypothesisClass, list[dict[str, Any]]] = {
    HypothesisClass.IDOR_BOLA: [
        {
            "objective": "Determine whether object IDs are authorization-bound",
            "capabilities": ["http", "proxy"],
            "tools": ["authz_compare", "identity_switch", "http_probe"],
            "gain": "high",
            "specialist": "AuthorizationAgent",
            "impact": 0.9,
        },
        {
            "objective": "Map object ownership relationships across endpoints",
            "capabilities": ["http", "browser"],
            "tools": ["authz_compare", "http_probe", "browser_navigate"],
            "gain": "high",
            "specialist": "AuthorizationAgent",
            "impact": 0.85,
        },
        {
            "objective": "Compare object access across identities (horizontal/vertical)",
            "capabilities": ["http"],
            "tools": ["authz_compare", "identity_compare"],
            "gain": "high",
            "specialist": "AuthorizationAgent",
            "impact": 0.9,
            "prerequisites": ["two_identities"],
        },
    ],
    HypothesisClass.PRIVILEGE_ESCALATION: [
        {
            "objective": "Test privileged endpoints as anonymous and authenticated user",
            "capabilities": ["http"],
            "tools": ["authz_compare", "identity_switch", "http_probe"],
            "gain": "high",
            "specialist": "AuthorizationAgent",
            "impact": 0.9,
        },
    ],
    HypothesisClass.AUTHENTICATION: [
        {
            "objective": "Map authentication workflow and session lifecycle",
            "capabilities": ["http", "browser"],
            "tools": ["http_probe", "browser_navigate"],
            "gain": "high",
            "specialist": "AuthenticationAgent",
            "impact": 0.8,
        },
        {
            "objective": "Test authentication bypass and weak credential handling",
            "capabilities": ["http"],
            "tools": ["http_probe"],
            "gain": "medium",
            "specialist": "AuthenticationAgent",
            "impact": 0.75,
        },
    ],
    HypothesisClass.SESSION: [
        {
            "objective": "Analyze JWT/session token structure and validation",
            "capabilities": ["http"],
            "tools": ["jwt_analyze", "http_probe"],
            "gain": "high",
            "specialist": "AuthenticationAgent",
            "impact": 0.85,
        },
    ],
    HypothesisClass.SSRF: [
        {
            "objective": "Test server-side URL fetch behavior on URL parameters",
            "capabilities": ["http"],
            "tools": ["http_probe"],
            "gain": "high",
            "specialist": "WebAgent",
            "impact": 0.85,
        },
    ],
    HypothesisClass.INJECTION: [
        {
            "objective": "Test input validation on search and filter parameters",
            "capabilities": ["http"],
            "tools": ["param_fuzz", "http_probe"],
            "gain": "medium",
            "specialist": "WebAgent",
            "impact": 0.7,
        },
    ],
    HypothesisClass.GRAPHQL: [
        {
            "objective": "Test GraphQL introspection and authorization boundaries",
            "capabilities": ["http"],
            "tools": ["graphql_probe", "http_probe"],
            "gain": "high",
            "specialist": "APIAgent",
            "impact": 0.85,
        },
    ],
    HypothesisClass.FILE_UPLOAD: [
        {
            "objective": "Test file upload validation and storage constraints",
            "capabilities": ["http"],
            "tools": ["http_probe"],
            "gain": "high",
            "specialist": "WebAgent",
            "impact": 0.8,
        },
    ],
    HypothesisClass.BUSINESS_LOGIC: [
        {
            "objective": "Test workflow state skipping and inconsistent authorization",
            "capabilities": ["http", "browser"],
            "tools": ["http_probe", "browser_navigate"],
            "gain": "high",
            "specialist": "BusinessLogicAgent",
            "impact": 0.9,
        },
    ],
    HypothesisClass.INFORMATION_DISCLOSURE: [
        {
            "objective": "Review exposed endpoints for sensitive data leakage",
            "capabilities": ["http"],
            "tools": ["http_probe", "endpoint_validate"],
            "gain": "medium",
            "specialist": "WebAgent",
            "impact": 0.6,
        },
    ],
}


def _gap_open(coverage_gaps: dict[str, str], *domains: str) -> bool:
    """True when a coverage property still needs investigation.

    Unknown/absent domains count as open (NOT_REVIEWED default); only an
    explicitly reviewed/blocked domain suppresses regeneration, which keeps
    Nikto-style coverage from being scheduled repeatedly.
    """
    if not domains:
        return True
    return any(coverage_gaps.get(d, "NOT_REVIEWED") == "NOT_REVIEWED"
               for d in domains)


def _gap_score(coverage_gaps: dict[str, str], *domains: str) -> float:
    return 1.0 if _gap_open(coverage_gaps, *domains) else 0.4


# Service inventory → enumeration capability (PART 10).
# Matched on port first, then service name. HTTP is skipped: web
# capabilities own that surface.
SERVICE_CAPABILITY_MAP: list[dict[str, Any]] = [
    {"ports": {139, 445}, "names": {"microsoft-ds", "netbios-ssn", "smb"},
     "capability": "smb_enum", "label": "SMB"},
    {"ports": {389, 636, 3268, 3269}, "names": {"ldap"},
     "capability": "ldap_enum", "label": "LDAP"},
    {"ports": {88}, "names": {"kerberos", "kdc"},
     "capability": "kerberos_enum", "label": "Kerberos"},
    {"ports": {22}, "names": {"ssh"},
     "capability": "ssh_enum", "label": "SSH"},
    {"ports": {21}, "names": {"ftp"},
     "capability": "ftp_enum", "label": "FTP"},
    {"ports": {25, 465, 587}, "names": {"smtp"},
     "capability": "smtp_enum", "label": "SMTP"},
    {"ports": {53}, "names": {"dns", "domain"},
     "capability": "dns_enum", "label": "DNS"},
    {"ports": {161}, "names": {"snmp"},
     "capability": "snmp_enum", "label": "SNMP"},
    {"ports": {3306, 5432, 1433, 6379, 27017},
     "names": {"mysql", "postgresql", "postgres", "redis", "mongodb",
               "mongo", "ms-sql-s", "mssql", "database"},
     "capability": "database_enum", "label": "database"},
    {"ports": {23, 111, 2049, 3389, 5900, 5985, 5986},
     "names": {"telnet", "nfs", "rdp", "ms-wbt-server", "winrm", "vnc"},
     "capability": "remote_enum", "label": "remote service"},
]


def _service_capability(service: Any) -> dict[str, Any] | None:
    name = (service.service_name or service.service or "").lower()
    for entry in SERVICE_CAPABILITY_MAP:
        if service.port in entry["ports"] or \
                any(n in name for n in entry["names"]):
            return entry
    return None


_SUSPICIOUS_PATH_KEYWORDS = (
    "admin", ".env", ".git", "phpinfo", "actuator", "swagger",
    "console", "manager", "config", "backup", "debug",
)


def generate_gap_investigations(
    app: ApplicationModel,
    coverage_gaps: dict[str, str] | None = None,
) -> list[Investigation]:
    """Coverage-gap and service-driven investigations (PARTs 4-11).

    Every entry defines prerequisites, target type, capability, required
    inputs (via build_capability_inputs), expected evidence, coverage
    property, and score factors. IDs are stable (objective-derived), so
    reassessment never regenerates identical investigations (PART 12).
    """
    from horcrux.agents.tools.capabilities import canonical_tool_id
    coverage_gaps = coverage_gaps or {}
    investigations: list[Investigation] = []

    def _make(objective: str, reason: str, specialist: str,
              capabilities: list[str], tools: list[str],
              gain: str, impact: float, cost: float,
              prerequisites: list[str] | None = None,
              vulnerability_classes: list[str] | None = None,
              evidence_refs: list[str] | None = None,
              gap_domains: tuple[str, ...] = ()) -> Investigation:
        inv = Investigation(
            objective=objective,
            reason=reason,
            evidence_refs=list(evidence_refs or []),
            vulnerability_classes=list(vulnerability_classes or []),
            required_capabilities=list(capabilities),
            candidate_tools=[canonical_tool_id(t) for t in tools],
            prerequisites=list(prerequisites or []),
            expected_information_gain=gain,
            hypothesis_id="",
            specialist=specialist,
            state=InvestigationState.READY,
            score=InvestigationScore(
                evidence_relevance=0.6,
                expected_information_gain=0.9 if gain == "high" else 0.6,
                impact_potential=impact,
                coverage_gap=_gap_score(coverage_gaps, *gap_domains),
                prerequisites_satisfied=1.0,
                execution_cost=cost,
            ),
        )
        inv.priority = inv.score.total
        inv.ensure_id()
        return inv

    has_web = bool(app.web_targets)
    open_surface = has_web and (len(app.endpoints) < 5 or
                                _gap_open(coverage_gaps, "web_discovery"))

    # WEB SURFACE INCOMPLETE → content discovery → content_discovery.
    if open_surface:
        investigations.append(_make(
            "Discover web content and enumerate hidden routes via fuzzing",
            "Application surface looks incomplete; wordlist-guided discovery "
            "with baseline suppression may reveal hidden routes.",
            "WebAgent", ["http"], ["content_discovery"], "high", 0.75, 0.5,
            prerequisites=["web_target"],
            vulnerability_classes=["information_disclosure"],
            evidence_refs=[e.id for e in app.endpoints[:3]],
            gap_domains=("web_discovery",),
        ))

    # WEB TECHNOLOGY UNKNOWN → fingerprint → web_fingerprint.
    if has_web and not app.technologies and _gap_open(coverage_gaps, "web_discovery"):
        investigations.append(_make(
            "Fingerprint web technologies and framework stack",
            "No technology evidence; fingerprinting enriches the model and "
            "drives framework-specific hypotheses and capability selection.",
            "WebAgent", ["http"], ["web_fingerprint"], "high", 0.6, 0.2,
            prerequisites=["web_target"],
            vulnerability_classes=["information_disclosure"],
            gap_domains=("web_discovery",),
        ))

    # SUSPICIOUS ENDPOINT → endpoint validation → endpoint_validate.
    if _gap_open(coverage_gaps, "information_disclosure", "configuration"):
        for ep in app.endpoints:
            path_lower = ep.path.lower()
            if not any(k in path_lower for k in _SUSPICIOUS_PATH_KEYWORDS):
                continue
            if any("validator" in (s or "") for s in ep.sources):
                continue
            investigations.append(_make(
                f"Validate suspicious endpoint {ep.path}",
                f"Path matches a sensitive-surface pattern; baseline-aware "
                f"validation produces structured evidence.",
                "WebAgent", ["http"], ["endpoint_validate"], "high", 0.75, 0.2,
                prerequisites=["web_target"],
                vulnerability_classes=["information_disclosure"],
                evidence_refs=[ep.id],
                gap_domains=("information_disclosure",),
            ))
            if len([i for i in investigations
                    if i.candidate_tools == ["endpoint_validate"]]) >= 5:
                break

    # WEB SERVER REVIEW REQUIRED → server audit → nikto_audit (once per gap).
    if has_web and len(app.endpoints) >= 3 and \
            _gap_open(coverage_gaps, "configuration", "client_side_security"):
        investigations.append(_make(
            "Audit web server configuration and legacy surfaces",
            "Server misconfiguration review; scheduled once per open "
            "configuration gap to avoid redundant rescans.",
            "WebAgent", ["http"], ["nikto_audit"], "medium", 0.6, 0.6,
            prerequisites=["web_target"],
            vulnerability_classes=["information_disclosure"],
            evidence_refs=[e.id for e in app.endpoints[:3]],
            gap_domains=("configuration",),
        ))

    # TARGETED TEMPLATE VALIDATION → nuclei validation → nuclei_scan.
    if has_web and (app.technologies or len(app.endpoints) >= 5) and \
            _gap_open(coverage_gaps, "api_security", "web_discovery",
                      "information_disclosure"):
        investigations.append(_make(
            "Validate web findings with targeted Nuclei templates",
            "Technology/endpoints mapped; template validation confirms or "
            "refutes candidate exposures with structured evidence.",
            "WebAgent", ["http"], ["nuclei_scan"], "high", 0.8, 0.5,
            prerequisites=["web_target"],
            vulnerability_classes=["information_disclosure"],
            evidence_refs=[e.id for e in app.endpoints[:5]],
            gap_domains=("api_security",),
        ))

    # JS ROUTES/PARAMETERS PRESENT → JS analysis → js_analyze.
    js_eps = [e for e in app.endpoints if "javascript" in (e.sources or [])]
    if js_eps and _gap_open(coverage_gaps, "api_security",
                            "information_disclosure", "client_side_security"):
        investigations.append(_make(
            "Analyze client-side routes, APIs, and parameters",
            "JavaScript-derived surface present; analysis feeds routes, "
            "APIs, parameters, auth surfaces, and workflow hints.",
            "WebAgent", ["http", "javascript"], ["js_analyze"], "high",
            0.7, 0.2,
            prerequisites=["web_target"],
            vulnerability_classes=["information_disclosure"],
            evidence_refs=[e.id for e in js_eps[:5]],
            gap_domains=("api_security",),
        ))

    # AUTHENTICATED SURFACE → browser walkthrough → browser_automate.
    login_eps = [e for e in app.endpoints if "login" in e.path.lower()]
    if login_eps and app.forms and _gap_open(coverage_gaps, "web_discovery",
                                             "authentication"):
        investigations.append(_make(
            "Walk authenticated surface via browser automation",
            "Login surface and forms discovered; automated walkthrough "
            "correlates browser traffic with APIs and workflows.",
            "WebAgent", ["http", "browser"], ["browser_automate"], "high",
            0.75, 0.5,
            prerequisites=["authenticated_api"],
            vulnerability_classes=["information_disclosure"],
            evidence_refs=[e.id for e in login_eps[:3]],
            gap_domains=("web_discovery",),
        ))

    # SERVICE-DRIVEN enumeration → protocol capabilities.
    for svc in app.services:
        if svc.is_web:
            continue
        entry = _service_capability(svc)
        if entry is None:
            continue
        investigations.append(_make(
            f"Enumerate {entry['label']} service on port {svc.port}",
            f"{entry['label']} service discovered; protocol enumeration "
            f"produces identities, shares, and configuration evidence.",
            "NetworkAgent", ["service"], [entry["capability"]], "high",
            0.8, 0.3,
            prerequisites=[],
            vulnerability_classes=["infrastructure"],
            evidence_refs=[svc.id],
            gap_domains=("infrastructure",),
        ))

    # EXPLOIT INTELLIGENCE → SearchSploit correlation → searchsploit_intel.
    # Gated on versioned product evidence at model level (mirrors the
    # reliability gate used by direct exploit-intelligence commands).
    versioned = [s for s in app.services
                 if (s.product or "").strip() and (s.version or "").strip()]
    if versioned:
        svc = versioned[0]
        investigations.append(_make(
            f"Correlate exploit intelligence for {svc.product} {svc.version}",
            "Reliable versioned software evidence exists; SearchSploit "
            "correlation produces candidate intelligence with relevance.",
            "ExploitIntelAgent", ["service"], ["searchsploit_intel"],
            "medium", 0.6, 0.2,
            prerequisites=[],
            vulnerability_classes=["infrastructure"],
            evidence_refs=[svc.id],
            gap_domains=("infrastructure",),
        ))

    return investigations


def generate_investigations(
    app: ApplicationModel,
    hypotheses: list[Hypothesis],
    coverage_gaps: dict[str, str] | None = None,
) -> list[Investigation]:
    """Generate candidate investigations from hypotheses and application state."""
    from horcrux.agents.tools.capabilities import canonical_tool_id
    coverage_gaps = coverage_gaps or {}
    investigations: list[Investigation] = []
    seen_objectives: set[str] = set()

    for hyp in hypotheses:
        if hyp.status in {HypothesisStatus.REFUTED, HypothesisStatus.CONFIRMED}:
            continue
        templates = HYPOTHESIS_TO_INVESTIGATIONS.get(hyp.hypothesis_class, [])
        for tmpl in templates:
            obj_key = tmpl["objective"].lower()
            if obj_key in seen_objectives:
                continue
            seen_objectives.add(obj_key)

            gap_key = _coverage_key_for_class(hyp.hypothesis_class)
            gap_score = 1.0 if coverage_gaps.get(gap_key, "NOT_REVIEWED") == "NOT_REVIEWED" else 0.4

            inv = Investigation(
                objective=tmpl["objective"],
                reason=f"Hypothesis: {hyp.title}",
                evidence_refs=hyp.evidence_refs[:8],
                vulnerability_classes=[hyp.hypothesis_class.value],
                required_capabilities=tmpl["capabilities"],
                candidate_tools=[canonical_tool_id(t) for t in tmpl["tools"]],
                prerequisites=list(tmpl.get("prerequisites", [])),
                expected_information_gain=tmpl["gain"],
                hypothesis_id=hyp.id,
                specialist=tmpl["specialist"],
                state=InvestigationState.READY,
                score=InvestigationScore(
                    evidence_relevance=min(1.0, 0.4 + len(hyp.evidence_refs) * 0.05),
                    expected_information_gain=0.9 if tmpl["gain"] == "high" else 0.6,
                    impact_potential=tmpl.get("impact", 0.7),
                    coverage_gap=gap_score,
                    prerequisites_satisfied=1.0,
                    execution_cost=0.2 if "browser" not in tmpl["capabilities"] else 0.5,
                ),
            )
            inv.priority = inv.score.total
            inv.ensure_id()
            investigations.append(inv)

    # Coverage-gap and service-driven investigations for orphaned capabilities.
    for inv in generate_gap_investigations(app, coverage_gaps):
        if inv.objective.lower() not in seen_objectives:
            seen_objectives.add(inv.objective.lower())
            investigations.append(inv)

    # Baseline investigations when app has structure but no hypotheses yet
    if app.endpoints and not investigations:
        investigations.append(
            Investigation(
                objective="Map API structure and authentication requirements",
                reason="Endpoints discovered but no targeted investigations generated yet",
                evidence_refs=[e.id for e in app.endpoints[:5]],
                vulnerability_classes=["api_security"],
                required_capabilities=["http"],
                candidate_tools=["http_probe"],
                expected_information_gain="high",
                specialist="APIAgent",
                state=InvestigationState.READY,
                score=InvestigationScore(
                    evidence_relevance=0.7,
                    expected_information_gain=0.85,
                    coverage_gap=0.9,
                ),
            )
        )

    if app.endpoints and not any(i.specialist == "WebAgent" for i in investigations):
        investigations.append(
            Investigation(
                objective="Complete functional application structure discovery",
                reason="Web endpoints exist; ensure routes, forms, and JS APIs are mapped",
                evidence_refs=[e.id for e in app.endpoints[:5]],
                vulnerability_classes=["information_disclosure"],
                required_capabilities=["http", "javascript"],
                candidate_tools=["js_analyze", "http_probe"],
                expected_information_gain="high",
                specialist="WebAgent",
                state=InvestigationState.READY,
                score=InvestigationScore(
                    evidence_relevance=0.6,
                    expected_information_gain=0.8,
                    coverage_gap=0.85,
                ),
            )
        )

    # Deterministic test-matrix investigations derived from ApplicationModel assets (Phase B/C)
    try:
        from horcrux.intel.test_matrix import derive_applicable_tests, test_case_to_investigation
        matrix_tests = derive_applicable_tests(app)
        for tc in matrix_tests:
            inv = test_case_to_investigation(tc)
            if inv.objective.lower() not in seen_objectives:
                seen_objectives.add(inv.objective.lower())
                investigations.append(inv)
    except Exception:
        pass

    return investigations


def _coverage_key_for_class(hyp_class: HypothesisClass) -> str:
    mapping = {
        HypothesisClass.IDOR_BOLA: "object_level_authorization",
        HypothesisClass.PRIVILEGE_ESCALATION: "function_level_authorization",
        HypothesisClass.AUTHENTICATION: "authentication",
        HypothesisClass.SESSION: "session_security",
        HypothesisClass.INJECTION: "injection",
        HypothesisClass.SSRF: "ssrf",
        HypothesisClass.FILE_UPLOAD: "file_handling",
        HypothesisClass.GRAPHQL: "api_security",
        HypothesisClass.BUSINESS_LOGIC: "business_logic",
        HypothesisClass.INFORMATION_DISCLOSURE: "information_disclosure",
    }
    return mapping.get(hyp_class, "input_validation")


def rank_investigations(investigations: list[Investigation]) -> list[Investigation]:
    """Rank investigations by information gain score.

    Low-value cosmetic observations (robots.txt, favicon, ...) are demoted so
    information-dense security investigations dominate. Matrix-derived
    security tests are data-driven work items and are exempt from cosmetic
    demotion — they must never starve behind heuristics.
    """
    for inv in investigations:
        inv.priority = inv.score.total
        obs = getattr(inv, "observations", []) or []
        is_matrix = any(str(o).startswith("matrix_tc_id:") for o in obs)
        if is_matrix:
            continue
        objective = (inv.objective or "").lower()
        if any(pat in objective for pat in LOW_VALUE_OBJECTIVE_PATTERNS):
            inv.priority = max(0.0, inv.priority - 0.35)
        # Hypothesis-less cosmetic parameter work must not outrank semantic
        # investigations: a bare parameter observation with no linked
        # hypothesis and no high-value class is demoted.
        if not inv.hypothesis_id and "parameter" in objective:
            inv.priority = max(0.0, inv.priority - 0.25)
        # High-impact classes dominate.
        high_value = {"idor_bola", "privilege_escalation", "authentication",
                      "business_logic", "ssrf", "graphql", "file_upload"}
        if any(vc in high_value for vc in (inv.vulnerability_classes or [])):
            inv.priority = min(1.0, inv.priority + 0.05)
        # Blast radius prioritization
        if getattr(inv, "blast_radius", "") == "critical":
            inv.priority = min(1.0, inv.priority + 0.10)
        elif getattr(inv, "blast_radius", "") == "high":
            inv.priority = min(1.0, inv.priority + 0.05)
    return sorted(investigations, key=lambda i: -i.priority)


def merge_investigations(
    existing: list[Investigation],
    candidates: list[Investigation],
) -> list[Investigation]:
    """Deduplicate and preserve state of in-progress investigations.

    Terminal and parked states (COMPLETE/SUPPORTED/REFUTED/FAILED/UNAVAILABLE/
    SCOPE_BLOCKED/APPROVAL_REQUIRED/BLOCKED/INSUFFICIENT_EVIDENCE) are never
    regenerated — preventing repeated impossible investigations (Part 43).
    """
    _PARKED = {
        InvestigationState.RUNNING,
        InvestigationState.COMPLETE,
        InvestigationState.SUPPORTED,
        InvestigationState.REFUTED,
        InvestigationState.INSUFFICIENT_EVIDENCE,
        InvestigationState.FAILED,
        InvestigationState.UNAVAILABLE,
        InvestigationState.SCOPE_BLOCKED,
        InvestigationState.APPROVAL_REQUIRED,
        InvestigationState.BLOCKED,
        InvestigationState.REQUIRES_AUTH,
        InvestigationState.REQUIRES_SECOND_IDENTITY,
        InvestigationState.REQUIRES_TOOL,
        InvestigationState.REQUIRES_OPERATOR,
        InvestigationState.NOT_APPLICABLE,
        InvestigationState.OUT_OF_SCOPE,
    }
    lookup = {i.id: i for i in existing}
    merged: list[Investigation] = []
    for cand in candidates:
        if cand.id in lookup:
            old = lookup[cand.id]
            if old.state in _PARKED:
                # Refresh evidence refs but keep the parked outcome.
                if cand.evidence_refs:
                    old.evidence_refs = list(set(old.evidence_refs + cand.evidence_refs))
                merged.append(old)
            else:
                cand.state = old.state
                merged.append(cand)
        else:
            merged.append(cand)
    done_ids = {i.id for i in merged}
    for old in existing:
        if old.id not in done_ids:
            merged.append(old)
    return merged


def choose_highest_value_task(ranked: list[Investigation]) -> Investigation | None:
    """Select the highest-value actionable investigation."""
    for inv in ranked:
        if inv.state in {InvestigationState.READY, InvestigationState.PENDING}:
            return inv
    return None


def prune_stale_matrix_investigations(
    existing: list[Investigation],
    applicable_tc_ids: set[str],
) -> list[Investigation]:
    """Terminalize matrix investigations whose test no longer derives.

    Continuous replenishment cuts both ways: new surface enqueues new tests,
    and retired surface (e.g. static JS bundle pseudo-params that are now
    excluded) must leave an explicit terminal state instead of lingering as
    stale INSUFFICIENT/READY work. Only non-terminal matrix items are touched;
    executed evidence is never rewritten.
    """
    for inv in existing:
        tc_id = ""
        for obs in getattr(inv, "observations", []) or []:
            if str(obs).startswith("matrix_tc_id:"):
                tc_id = str(obs).split(":", 1)[1]
                break
        if not tc_id or tc_id in applicable_tc_ids:
            continue
        if inv.state in (InvestigationState.READY, InvestigationState.PENDING,
                         InvestigationState.RUNNING):
            inv.state = InvestigationState.NOT_APPLICABLE
            inv.result_summary = (
                "Retired: matrix test no longer applicable to current attack "
                "surface (e.g. static-asset or collection reclassification)."
            )
    return existing
