from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, List, Optional

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class ValidationState(str, Enum):
    confirmed = "CONFIRMED"
    likely = "LIKELY"
    potential = "POTENTIAL"
    unverified = "UNVERIFIED"
    false_positive = "FALSE_POSITIVE"


class AuditStatus(str, Enum):
    hardened = "HARDENED"
    audited = "AUDITED"
    suspicious = "SUSPICIOUS"
    dismissed = "DISMISSED"


class SubsystemState(str, Enum):
    NOT_RUN = "NOT_RUN"
    RUNNING = "RUNNING"
    COMPLETE = "COMPLETE"
    COMPLETE_WITH_CANDIDATES = "COMPLETE_WITH_CANDIDATES"
    COMPLETE_NO_CANDIDATES = "COMPLETE_NO_CANDIDATES"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


class EvidenceClassification(str, Enum):
    VALIDATED = "VALIDATED"
    DISTINCT = "DISTINCT"
    CANDIDATE = "CANDIDATE"
    SUPPRESSED_FALLBACK = "SUPPRESSED_FALLBACK"
    DUPLICATE = "DUPLICATE"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class BaselineClassification(str, Enum):
    NORMAL_404 = "NORMAL_404"
    SOFT_404 = "SOFT_404"
    SPA_FALLBACK = "SPA_FALLBACK"
    GENERIC_ERROR_TEMPLATE = "GENERIC_ERROR_TEMPLATE"
    REDIRECT_CATCH_ALL = "REDIRECT_CATCH_ALL"
    UNKNOWN = "UNKNOWN"


class WebApplicationType(str, Enum):
    STATIC_SITE = "STATIC_SITE"
    TRADITIONAL_WEB_APP = "TRADITIONAL_WEB_APP"
    SPA = "SPA"
    API = "API"
    HYBRID = "HYBRID"
    UNKNOWN = "UNKNOWN"


class TechCategory(str, Enum):
    FRAMEWORK = "FRAMEWORK"
    RUNTIME = "RUNTIME"
    LANGUAGE = "LANGUAGE"
    WEBSERVER = "WEBSERVER"
    REVERSE_PROXY = "REVERSE_PROXY"
    CMS = "CMS"
    LIBRARY = "LIBRARY"
    ANALYTICS = "ANALYTICS"
    SECURITY_CONTROL = "SECURITY_CONTROL"
    DATABASE = "DATABASE"
    BUILD_TOOL = "BUILD_TOOL"
    UNKNOWN = "UNKNOWN"


class RawObservation(BaseModel):
    source_tool: str
    target: str
    timestamp: datetime = Field(default_factory=utcnow)
    observation_type: str
    data: dict[str, Any] = Field(default_factory=dict)
    artifact_path: str = ""


class ResponseFingerprint(BaseModel):
    status_code: int = 0
    content_type: str = ""
    normalized_body_length: int = 0
    title: str = ""
    normalized_body_hash: str = ""
    similarity_hash: str = ""
    structural_signature: str = ""
    redirect_chain: list[str] = Field(default_factory=list)
    final_url: str = ""
    is_html: bool = False
    is_json: bool = False
    is_spa_fallback: bool = False


class ResponseFamily(BaseModel):
    family_id: str
    representative_fingerprint: ResponseFingerprint
    member_count: int = 1
    representative_paths: list[str] = Field(default_factory=list)
    classification: EvidenceClassification = EvidenceClassification.DISTINCT
    confidence: float = 0.90
    evidence_references: list[str] = Field(default_factory=list)


class Parameter(BaseModel):
    name: str
    location: str = "query"  # query, path, body, header, cookie
    source: str = "url"      # form, javascript, url, openapi, graphql, json_schema
    endpoint: str = ""
    confidence: float = Field(default=0.8, ge=0, le=1)


class NormalizedTechnology(BaseModel):
    name: str
    category: TechCategory = TechCategory.UNKNOWN
    version: str = ""
    confidence: float = Field(default=0.8, ge=0, le=1)
    evidence_sources: list[str] = Field(default_factory=list)


class ModuleDecision(BaseModel):
    module: str
    status: str = "EXECUTED"  # EXECUTED, SKIPPED, DEFERRED, FAILED, COMPLETE
    reason: str = ""


class DiscoveredPath(BaseModel):
    url: str
    path: str
    status: int
    size: int = 0
    redirect: str = ""
    content_type: str = ""
    source: str = "horcrux-fuzzer"
    wordlist: str = ""
    confidence: float = 0.90
    validated: bool = False
    validation_state: ValidationState = ValidationState.unverified
    evidence_classification: EvidenceClassification = EvidenceClassification.CANDIDATE
    response_family_id: str = ""
    fingerprint: Optional[ResponseFingerprint] = None
    timestamp: datetime = Field(default_factory=utcnow)


class WebTarget(BaseModel):
    scheme: str = "http"
    host: str = ""
    port: int = 80
    base_url: str = ""
    service_identifier: str = ""
    application_type: WebApplicationType = WebApplicationType.UNKNOWN
    baseline_classification: BaselineClassification = BaselineClassification.UNKNOWN
    baseline_fingerprints: list[ResponseFingerprint] = Field(default_factory=list)
    endpoints: list[DiscoveredPath] = Field(default_factory=list)
    technologies: list[NormalizedTechnology] = Field(default_factory=list)
    response_families: list[ResponseFamily] = Field(default_factory=list)
    parameters: list[Parameter] = Field(default_factory=list)
    module_decisions: list[ModuleDecision] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)



class ArtifactRecord(BaseModel):
    module: str
    tool: str
    command: str
    target: str
    start_time: datetime = Field(default_factory=utcnow)
    end_time: Optional[datetime] = None
    duration_seconds: float = 0.0
    returncode: int = 0
    stdout_path: str = ""
    stderr_path: str = ""
    status: str = "completed"


# Backward-compatible alias for existing tests and code
class FindingStatus(str, Enum):
    suspected = "suspected"
    verified = "verified"
    exploited = "exploited"
    irrelevant = "irrelevant"



class AuditEntry(BaseModel):
    id: str
    category: str
    asset: str
    check_name: str
    status: AuditStatus = AuditStatus.audited
    evidence: list[str] = Field(default_factory=list)
    reason: str = ""
    timestamp: datetime = Field(default_factory=utcnow)


class Service(BaseModel):
    host: str
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    cpe: str = ""


class Software(BaseModel):
    product: str
    version: str = ""
    service: str = ""
    source: str = ""
    cpe: str = ""
    confidence: float = Field(default=0.5, ge=0, le=1)
    evidence: list[str] = Field(default_factory=list)


class Credential(BaseModel):
    username: str = ""
    secret: str = ""
    kind: str = "credential"
    source: str = ""
    confidence: float = Field(default=0.5, ge=0, le=1)


class Finding(BaseModel):
    id: str
    title: str
    category: str
    severity: Severity = Severity.info
    confidence: float = Field(ge=0, le=1)
    status: FindingStatus = FindingStatus.suspected
    validation_state: ValidationState = ValidationState.unverified
    target: str
    affected_asset: str = ""
    protocol: str = "tcp"
    port: Optional[int] = None
    source_tool: str = "horcrux"
    evidence: list[str] = Field(default_factory=list)
    artifacts: list[str] = Field(default_factory=list)
    reproduction: list[str] = Field(default_factory=list)
    why_it_matters: str = ""
    recommended_next_action: str = ""
    next_action: str = ""
    timestamp: datetime = Field(default_factory=utcnow)


class Action(BaseModel):
    id: str
    title: str
    reason: str
    score: float
    command: str = ""
    status: str = "pending"


class ExploitCandidate(BaseModel):
    title: str
    product: str = ""
    version: str = ""
    cve: str = ""
    source: str = ""
    confidence: float = Field(default=0.0, ge=0, le=1)
    notes: str = ""
    exploitability: str = "MANUAL REVIEW"
    relevance: str = "CANDIDATE"
    query: str = ""
    relevance_reasoning: str = ""
    attack_type: str = "remote"
    missing_prerequisites: list[str] = Field(default_factory=list)
    ai_triaged: bool = False
    ai_decision: str = ""


class ScanProfile(BaseModel):
    name: str = "standard"
    description: str = "Normal comprehensive recon"
    port_spec: str = "top1000"
    include_udp: bool = True
    udp_port_count: int = 50
    enabled_modules: list[str] = Field(
        default_factory=lambda: ["network", "web_probe", "service_enum"]
    )
    expensive_checks: bool = False
    cve_correlation: bool = False
    wordlist_strategy: str = "common"
    command_timeout: int = 300
    global_timeout: int = 1800


PROFILES: dict[str, ScanProfile] = {
    "quick": ScanProfile(
        name="quick",
        description="Fast attack-surface mapping with minimal footprint",
        port_spec="top100",
        include_udp=False,
        enabled_modules=["network", "web_probe"],
        expensive_checks=False,
        cve_correlation=False,
        wordlist_strategy="quickhits",
        command_timeout=120,
    ),
    "standard": ScanProfile(
        name="standard",
        description="Normal comprehensive reconnaissance and validated surface mapping",
        port_spec="top1000",
        include_udp=True,
        udp_port_count=50,
        enabled_modules=["network", "web_probe", "service_enum"],
        expensive_checks=False,
        cve_correlation=False,
        wordlist_strategy="common",
        command_timeout=300,
    ),
    "deep": ScanProfile(
        name="deep",
        description="Full TCP and deeper service enumeration with expensive checks",
        port_spec="full",
        include_udp=True,
        udp_port_count=100,
        enabled_modules=["network", "web_probe", "web_discovery", "service_enum"],
        expensive_checks=True,
        cve_correlation=False,
        wordlist_strategy="medium",
        command_timeout=900,
    ),
    "network": ScanProfile(
        name="network",
        description="Network and port discovery focused without application fuzzing",
        port_spec="top1000",
        include_udp=True,
        udp_port_count=100,
        enabled_modules=["network"],
        expensive_checks=False,
        cve_correlation=False,
        command_timeout=300,
    ),
    "web": ScanProfile(
        name="web",
        description="Web application focused probing, validated endpoints, and discovery",
        port_spec="top1000",
        include_udp=False,
        enabled_modules=["network", "web_probe", "web_discovery"],
        expensive_checks=True,
        cve_correlation=False,
        wordlist_strategy="common",
        command_timeout=450,
    ),
    "service": ScanProfile(
        name="service",
        description="Service-specific reconnaissance and protocol inspection",
        port_spec="top1000",
        include_udp=True,
        udp_port_count=50,
        enabled_modules=["network", "service_enum"],
        expensive_checks=False,
        cve_correlation=False,
        command_timeout=300,
    ),
    "intel": ScanProfile(
        name="intel",
        description="Vulnerability and exploit intelligence for confirmed software evidence",
        port_spec="top1000",
        include_udp=False,
        enabled_modules=["network", "web_probe", "service_enum"],
        expensive_checks=False,
        cve_correlation=True,
        command_timeout=300,
    ),
    "local": ScanProfile(
        name="local",
        description="Post-compromise target-agnostic local host enumeration",
        port_spec="none",
        include_udp=False,
        enabled_modules=["local"],
        expensive_checks=False,
        cve_correlation=False,
        command_timeout=180,
    ),
}


def get_profile(name_or_profile: str | ScanProfile | None) -> ScanProfile:
    if isinstance(name_or_profile, ScanProfile):
        return name_or_profile
    if not name_or_profile:
        return PROFILES["standard"]
    return PROFILES.get(name_or_profile.lower(), PROFILES["standard"])


class WorkspaceState(BaseModel):
    target: str
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    services: list[Service] = Field(default_factory=list)
    software: list[Software] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    normalized_technologies: list[NormalizedTechnology] = Field(default_factory=list)
    credentials: list[Credential] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    audit: list[AuditEntry] = Field(default_factory=list)
    actions: list[Action] = Field(default_factory=list)
    exploits: list[ExploitCandidate] = Field(default_factory=list)
    attack_paths: list[dict] = Field(default_factory=list)
    executive_summary: str = ""
    subsystem_states: dict[str, str] = Field(default_factory=dict)
    discovered_paths: list[DiscoveredPath] = Field(default_factory=list)
    artifacts: list[ArtifactRecord] = Field(default_factory=list)
    raw_observations: list[RawObservation] = Field(default_factory=list)
    web_targets: list[WebTarget] = Field(default_factory=list)
    parameters: list[Parameter] = Field(default_factory=list)
    response_families: list[ResponseFamily] = Field(default_factory=list)

    def get_web_target(self, port: int) -> WebTarget | None:
        for wt in self.web_targets:
            if wt.port == port:
                return wt
        return None

    def upsert_web_target(self, target: WebTarget) -> None:
        for idx, wt in enumerate(self.web_targets):
            if wt.port == target.port and wt.host == target.host:
                self.web_targets[idx] = target
                return
        self.web_targets.append(target)

    def get_subsystem_state(self, name: str) -> SubsystemState:

        val = self.subsystem_states.get(name, SubsystemState.NOT_RUN.value)
        try:
            return SubsystemState(val)
        except ValueError:
            return SubsystemState.NOT_RUN

    def set_subsystem_state(self, name: str, state: SubsystemState | str) -> None:
        val = state.value if isinstance(state, SubsystemState) else str(state)
        self.subsystem_states[name] = val

