from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class FindingStatus(str, Enum):
    suspected = "suspected"
    verified = "verified"
    exploited = "exploited"
    irrelevant = "irrelevant"


class Service(BaseModel):
    host: str
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""


class Software(BaseModel):
    product: str
    version: str = ""
    service: str = ""
    source: str = ""
    confidence: float = Field(default=0.5, ge=0, le=1)


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
    target: str
    evidence: list[str] = Field(default_factory=list)
    artifacts: list[str] = Field(default_factory=list)
    reproduction: list[str] = Field(default_factory=list)
    next_action: str = ""


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


class WorkspaceState(BaseModel):
    target: str
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    services: list[Service] = Field(default_factory=list)
    software: list[Software] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    credentials: list[Credential] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    actions: list[Action] = Field(default_factory=list)
    exploits: list[ExploitCandidate] = Field(default_factory=list)
