"""First-class authorization matrix (Phase 9, Part 11).

The authorization matrix tracks access outcomes for every (identity, endpoint, method) triple.
Unknown cells are explicitly tracked — never inferred as secure.
UNKNOWN != DENIED — absence of testing is not evidence of access control.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, TYPE_CHECKING

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from horcrux.intel.application_model import ApplicationModel


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class AuthzCellStatus(str, Enum):
    UNKNOWN = "UNKNOWN"            # not yet tested
    ALLOWED = "ALLOWED"            # access permitted (2xx)
    DENIED = "DENIED"              # access denied (401/403)
    INCONCLUSIVE = "INCONCLUSIVE"  # response ambiguous
    ERROR = "ERROR"                # request failed


class AuthzCell(BaseModel):
    """One cell of the authorization matrix: (identity, endpoint, method) → outcome."""
    identity: str
    endpoint: str
    method: str = "GET"
    status: AuthzCellStatus = AuthzCellStatus.UNKNOWN
    status_code: int = 0
    response_size: int = 0
    evidence_refs: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.5, ge=0, le=1)
    tested_at: str = Field(default_factory=_utcnow)
    notes: str = ""


class AuthorizationMatrix(BaseModel):
    """Multi-identity authorization matrix.

    Tracks access outcomes for all (identity, endpoint, method) combinations.
    UNKNOWN cells are explicitly tracked — they are NOT inferred as secure.
    """
    cells: dict[str, AuthzCell] = Field(default_factory=dict)
    identities: list[str] = Field(default_factory=list)
    endpoints: list[str] = Field(default_factory=list)

    def cell_key(self, identity: str, endpoint: str, method: str = "GET") -> str:
        return f"{identity}:{method.upper()}:{endpoint}"

    def get_cell(self, identity: str, endpoint: str, method: str = "GET") -> AuthzCell:
        key = self.cell_key(identity, endpoint, method)
        return self.cells.get(key, AuthzCell(
            identity=identity, endpoint=endpoint, method=method.upper()))

    def record_observation(
        self,
        identity: str,
        endpoint: str,
        method: str,
        status_code: int,
        response_size: int = 0,
        evidence_refs: list[str] | None = None,
        confidence: float = 0.8,
        notes: str = "",
    ) -> AuthzCell:
        """Record an authorization observation."""
        if status_code in (401, 403):
            status = AuthzCellStatus.DENIED
        elif 200 <= status_code < 300:
            status = AuthzCellStatus.ALLOWED
        elif status_code == 0:
            status = AuthzCellStatus.ERROR
        else:
            status = AuthzCellStatus.INCONCLUSIVE

        cell = AuthzCell(
            identity=identity,
            endpoint=endpoint,
            method=method.upper(),
            status=status,
            status_code=status_code,
            response_size=response_size,
            evidence_refs=list(evidence_refs or []),
            confidence=confidence,
            notes=notes,
        )
        key = self.cell_key(identity, endpoint, method)
        self.cells[key] = cell

        if identity not in self.identities:
            self.identities.append(identity)
        if endpoint not in self.endpoints:
            self.endpoints.append(endpoint)

        return cell

    def unknown_cells(
        self,
        identities: list[str] | None = None,
        endpoints: list[str] | None = None,
    ) -> list[tuple[str, str, str]]:
        """Return (identity, endpoint, method) triples where status is UNKNOWN."""
        identities = identities or self.identities
        endpoints = endpoints or self.endpoints
        unknown = []
        for identity in identities:
            for endpoint in endpoints:
                for method in ("GET", "POST"):
                    cell = self.get_cell(identity, endpoint, method)
                    if cell.status == AuthzCellStatus.UNKNOWN:
                        unknown.append((identity, endpoint, method))
        return unknown

    def high_value_gaps(
        self,
        object_endpoints: list[str],
        admin_endpoints: list[str],
    ) -> list[tuple[str, str, str]]:
        """Return high-value unknown cells for investigation prioritization."""
        gaps = []
        high_value = set(object_endpoints + admin_endpoints)
        for identity in self.identities:
            for endpoint in high_value:
                cell = self.get_cell(identity, endpoint)
                if cell.status == AuthzCellStatus.UNKNOWN:
                    gaps.append((identity, endpoint, "GET"))
        return gaps

    def generate_investigations(self, app: "ApplicationModel") -> list:
        """Generate authorization investigations for important unknown cells."""
        from horcrux.intel.investigations import (
            Investigation, InvestigationState, InvestigationScore,
        )
        from horcrux.intel.application_model import fingerprint

        object_eps = [e.path for e in app.endpoints if e.has_object_reference]
        admin_eps = [e.path for e in app.endpoints if "admin" in e.path.lower()]
        gaps = self.high_value_gaps(object_eps, admin_eps)

        investigations = []
        for identity, endpoint, method in gaps[:10]:
            inv = Investigation(
                objective=f"Test {identity} access to {method} {endpoint}",
                reason=f"Authorization matrix cell UNKNOWN: {identity} → {method} {endpoint}",
                evidence_refs=[f"authz_matrix:{identity}:{endpoint}"],
                vulnerability_classes=["idor_bola" if endpoint in object_eps else "privilege_escalation"],
                required_capabilities=["http"],
                candidate_tools=["authz_compare", "http_probe"],
                expected_information_gain="high",
                specialist="AuthorizationAgent",
                state=InvestigationState.READY,
                score=InvestigationScore(
                    evidence_relevance=0.7,
                    expected_information_gain=0.9,
                    impact_potential=0.85,
                    coverage_gap=0.9,
                    prerequisites_satisfied=1.0,
                    execution_cost=0.2,
                ),
            )
            inv.id = fingerprint("inv", "authz_matrix", identity, endpoint, method)
            inv.priority = inv.score.total
            investigations.append(inv)

        return investigations

    def to_display_dict(self) -> dict[str, Any]:
        """Human-readable representation for reports and ask engine."""
        matrix: dict[str, dict[str, str]] = {}
        for cell in self.cells.values():
            ep_key = f"{cell.method} {cell.endpoint}"
            if ep_key not in matrix:
                matrix[ep_key] = {}
            matrix[ep_key][cell.identity] = cell.status.value
        return {
            "identities": self.identities,
            "endpoints_tested": len(self.endpoints),
            "cells_total": len(self.identities) * len(self.endpoints),
            "cells_tested": len(self.cells),
            "cells_unknown": sum(1 for c in self.cells.values() if c.status == AuthzCellStatus.UNKNOWN),
            "cells_denied": sum(1 for c in self.cells.values() if c.status == AuthzCellStatus.DENIED),
            "cells_allowed": sum(1 for c in self.cells.values() if c.status == AuthzCellStatus.ALLOWED),
            "matrix": matrix,
        }


def record_authz_observation(
    app: "ApplicationModel",
    identity: str,
    endpoint: str,
    method: str,
    status_code: int,
    response_size: int = 0,
    evidence_refs: list[str] | None = None,
) -> None:
    """Convenience: record in the matrix stored on ApplicationModel."""
    matrix = get_or_create_matrix(app)
    matrix.record_observation(
        identity=identity, endpoint=endpoint, method=method,
        status_code=status_code, response_size=response_size,
        evidence_refs=evidence_refs,
    )
    if hasattr(app, "authorization_matrix"):
        app.authorization_matrix = matrix.model_dump()


def get_or_create_matrix(app: "ApplicationModel") -> AuthorizationMatrix:
    """Get or create the authorization matrix from ApplicationModel."""
    raw = getattr(app, "authorization_matrix", None)
    if raw:
        if isinstance(raw, dict):
            try:
                return AuthorizationMatrix.model_validate(raw)
            except Exception:
                pass
        if isinstance(raw, AuthorizationMatrix):
            return raw
    return AuthorizationMatrix()


def generate_authz_matrix_investigations(app: "ApplicationModel") -> list:
    """Generate investigations for authorization matrix gaps."""
    matrix = get_or_create_matrix(app)
    # Need multiple identities for meaningful authz comparison
    if not matrix.identities and len(app.identities) < 2:
        return []
    return matrix.generate_investigations(app)
