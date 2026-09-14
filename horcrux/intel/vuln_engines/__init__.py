"""External vulnerability engine fabric — HORCRUX assessment orchestrator plugin layer.

The researcher uses HORCRUX. HORCRUX orchestrates the engines.
Every external engine is an evidence-producing capability, never a
second operator workflow.
"""

from horcrux.intel.vuln_engines.types import (
    CorrelationDisposition,
    CorrelatedVulnerability,
    CoverageState,
    DeploymentType,
    EngineCapability,
    EngineHealth,
    EngineReadiness,
    NormalizedExternalFinding,
    ProviderMetadata,
    ScanLifecycle,
    SelectedEngine,
)

__all__ = [
    "CorrelationDisposition",
    "CorrelatedVulnerability",
    "CoverageState",
    "DeploymentType",
    "EngineCapability",
    "EngineHealth",
    "EngineReadiness",
    "NormalizedExternalFinding",
    "ProviderMetadata",
    "ScanLifecycle",
    "SelectedEngine",
]
