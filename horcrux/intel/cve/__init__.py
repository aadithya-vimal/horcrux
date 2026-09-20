"""CVE and component vulnerability intelligence module."""

from horcrux.intel.cve.resolver import (
    ComponentVulnerability,
    correlate_software_vulnerabilities,
    match_vulnerabilities,
    synthesize_cpe,
)

__all__ = [
    "ComponentVulnerability",
    "correlate_software_vulnerabilities",
    "match_vulnerabilities",
    "synthesize_cpe",
]
