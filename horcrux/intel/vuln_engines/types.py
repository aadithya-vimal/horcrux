"""Provider-neutral types for the external vulnerability engine fabric."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class DeploymentType(str, Enum):
    CLOUD = "CLOUD"
    LOCAL_SERVICE = "LOCAL_SERVICE"
    REMOTE_SERVICE = "REMOTE_SERVICE"
    IMPORTED_RESULT = "IMPORTED_RESULT"


class EngineHealth(str, Enum):
    NOT_CONFIGURED = "NOT_CONFIGURED"
    CONFIGURED = "CONFIGURED"
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    AUTH_FAILED = "AUTH_FAILED"
    RATE_LIMITED = "RATE_LIMITED"
    UNAVAILABLE = "UNAVAILABLE"
    UNSUPPORTED = "UNSUPPORTED"
    BROKEN = "BROKEN"


class ScanLifecycle(str, Enum):
    NOT_CONFIGURED = "NOT_CONFIGURED"
    READY = "READY"
    PREPARING = "PREPARING"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    PROCESSING = "PROCESSING"
    RESULTS_AVAILABLE = "RESULTS_AVAILABLE"
    IMPORTING = "IMPORTING"
    CORRELATING = "CORRELATING"
    COMPLETE = "COMPLETE"
    # failure branches — assessment must continue where possible
    AUTH_FAILED = "AUTH_FAILED"
    CONFIGURATION_ERROR = "CONFIGURATION_ERROR"
    RATE_LIMITED = "RATE_LIMITED"
    UNAVAILABLE = "UNAVAILABLE"
    SCAN_FAILED = "SCAN_FAILED"
    RESULT_RETRIEVAL_FAILED = "RESULT_RETRIEVAL_FAILED"
    PARTIAL_RESULTS = "PARTIAL_RESULTS"
    OPERATOR_EXCLUDED = "OPERATOR_EXCLUDED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class CoverageState(str, Enum):
    AVAILABLE = "AVAILABLE"
    NOT_CONFIGURED = "NOT_CONFIGURED"
    UNAVAILABLE = "UNAVAILABLE"
    RUNNING = "RUNNING"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    OPERATOR_EXCLUDED = "OPERATOR_EXCLUDED"


class CorrelationDisposition(str, Enum):
    CORROBORATED = "CORROBORATED"
    CONTRADICTED = "CONTRADICTED"
    APPLICABLE = "APPLICABLE"
    LIKELY_APPLICABLE = "LIKELY_APPLICABLE"
    UNVERIFIED = "UNVERIFIED"
    STALE = "STALE"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class ProviderMetadata(BaseModel):
    provider_id: str
    product: str
    api_version: str = ""
    docs_verified: str = ""
    docs_url: str = ""
    deployment_type: DeploymentType = DeploymentType.CLOUD
    endpoint: str = ""
    authentication_type: str = ""
    supported_asset_types: list[str] = Field(default_factory=list)
    supported_scan_types: list[str] = Field(default_factory=list)
    supported_result_formats: list[str] = Field(default_factory=list)
    known_limitations: list[str] = Field(default_factory=list)
    supported_operations: list[str] = Field(default_factory=list)


class EngineCapability(BaseModel):
    capability_id: str
    label: str = ""
    description: str = ""


class EngineReadiness(BaseModel):
    provider_id: str
    product: str = ""
    configured: bool = False
    enabled: bool = True
    health: EngineHealth = EngineHealth.NOT_CONFIGURED
    capabilities: list[str] = Field(default_factory=list)
    deployment_type: str = ""
    endpoint: str = ""
    last_test: str = ""
    last_status: str = ""
    detail: str = ""
    excluded_by_operator: bool = False


class SelectedEngine(BaseModel):
    provider_id: str
    reason: str = ""
    mode: str = "selected"  # selected | skipped
    skip_reason: str = ""


class NormalizedExternalFinding(BaseModel):
    """Provider-neutral normalized external observation. Evidence, NOT truth."""

    finding_id: str = ""
    provider: str = ""
    source_product: str = ""
    source_finding_id: str = ""
    asset: str = ""
    hostname: str = ""
    port: Optional[int] = None
    service: str = ""
    protocol: str = "tcp"
    product: str = ""
    version: str = ""
    cpe: str = ""
    cves: list[str] = Field(default_factory=list)
    cwes: list[str] = Field(default_factory=list)
    severity: str = "info"
    cvss: Optional[float] = None
    cvss_vector: str = ""
    risk: str = ""
    title: str = ""
    description: str = ""
    evidence: list[str] = Field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    scan_timestamp: Optional[datetime] = None
    scanner_state: str = ""
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    source_artifacts: list[str] = Field(default_factory=list)
    deployment_type: str = DeploymentType.CLOUD.value
    imported: bool = False
    provenance: str = ""
    raw: dict[str, Any] = Field(default_factory=dict)
    disposition: str = CorrelationDisposition.UNVERIFIED.value
    disposition_reason: str = ""
    stale: bool = False


class CorrelatedVulnerability(BaseModel):
    """HORCRUX vulnerability entity — deduplicated across engines."""

    vuln_id: str = ""
    primary_cve: str = ""
    cves: list[str] = Field(default_factory=list)
    cwes: list[str] = Field(default_factory=list)
    asset: str = ""
    port: Optional[int] = None
    service: str = ""
    product: str = ""
    version: str = ""
    title: str = ""
    severity: str = "info"
    max_cvss: Optional[float] = None
    sources: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    disposition: str = CorrelationDisposition.UNVERIFIED.value
    disposition_reason: str = ""
    corroborated_by_native: bool = False
    native_evidence: list[str] = Field(default_factory=list)
    stale: bool = False
    description: str = ""
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
