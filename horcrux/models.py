from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional

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
    credentials: list[Credential] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    audit: list[AuditEntry] = Field(default_factory=list)
    actions: list[Action] = Field(default_factory=list)
    exploits: list[ExploitCandidate] = Field(default_factory=list)
    attack_paths: list[dict] = Field(default_factory=list)
    executive_summary: str = ""
