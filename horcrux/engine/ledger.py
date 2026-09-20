"""Property ledger — coverage measured in security properties.

Applicable / Executable / Executed / Confirmed / Refuted / Insufficient /
Blocked / NotApplicable per property. The denominator is semantically
valid tests only.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class PropertyLedgerEntry(BaseModel):
    property_id: str
    applicable: int = 0
    executable: int = 0
    executed: int = 0
    confirmed: int = 0
    refuted: int = 0
    insufficient: int = 0
    blocked: int = 0
    not_applicable: int = 0


class PropertyLedger(BaseModel):
    entries: dict[str, PropertyLedgerEntry] = Field(default_factory=dict)

    def record(self, property_id: str, **counts) -> None:
        e = self.entries.setdefault(property_id, PropertyLedgerEntry(property_id=property_id))
        for k, v in counts.items():
            if hasattr(e, k):
                setattr(e, k, getattr(e, k) + int(v))

    def summary(self) -> dict[str, int]:
        tot = {"applicable": 0, "executable": 0, "executed": 0, "confirmed": 0,
               "refuted": 0, "insufficient": 0, "blocked": 0, "not_applicable": 0}
        for e in self.entries.values():
            for k in tot:
                tot[k] += getattr(e, k)
        return tot

    def gap_lines(self) -> list[str]:
        lines = []
        for pid in sorted(self.entries):
            e = self.entries[pid]
            lines.append(f"{pid}: applicable={e.applicable} executable={e.executable} "
                         f"executed={e.executed} confirmed={e.confirmed} refuted={e.refuted} "
                         f"insufficient={e.insufficient} blocked={e.blocked}")
        return lines


# TestFamily -> property_ids mapping (semantic heart wiring into matrix).
FAMILY_PROPERTIES: dict[str, list[str]] = {
    "bola_idor": ["AUTHZ_BOLA_IDOR"],
    "authz_horizontal": ["AUTHZ_HORIZONTAL"],
    "authz_vertical": ["AUTHZ_VERTICAL_PRIVESC", "AUTHZ_FUNCTION_LEVEL"],
    "auth_enforcement": ["AUTHN_UNAUTH_PROTECTED_ACCESS", "AUTHN_BYPASS"],
    "api_security": ["API_EXCESSIVE_DATA", "API_MASS_ASSIGNMENT", "API_METHOD_AUTH"],
    "param_sqli": ["INJECT_SQL", "INJECT_NOSQL"],
    "param_cmdi": ["INJECT_COMMAND"],
    "param_traversal": ["PATH_TRAVERSAL"],
    "param_ssrf": ["SSRF_BASIC", "SSRF_INTERNAL"],
    "param_xss": ["XSS_REFLECTED", "XSS_STORED"],
    "file_upload": ["FILE_UPLOAD_WEAKNESS"],
    "graphql_introspection": ["GRAPHQL_INTROSPECTION"],
    "graphql_authz": ["GRAPHQL_AUTHZ"],
    "workflow_state": ["BIZ_WORKFLOW_BYPASS", "API_STATE_TRANSITION"],
    "workflow_tampering": ["BIZ_QUANTITY_MANIPULATION", "BIZ_PRICE_MANIPULATION"],
    "config_exposure": ["CONFIG_DIR_LISTING", "CONFIG_BACKUP_EXPOSURE",
                        "CONFIG_ADMIN_EXPOSURE", "CONFIG_DEBUG_EXPOSURE",
                        "CONFIG_CORS", "CONFIG_HEADERS"],
    "service_exploit_intel": ["INFRA_EXPOSED_SERVICE", "INFRA_KNOWN_VULN_COMPONENT"],
}


def ledger_from_matrix_tests(tests: list, executed_ids: set[str] | None = None,
                             verdicts: dict[str, str] | None = None) -> PropertyLedger:
    ledger = PropertyLedger()
    executed_ids = executed_ids or set()
    verdicts = verdicts or {}
    for t in tests:
        fam = t.family.value if hasattr(t.family, "value") else str(t.family)
        for pid in FAMILY_PROPERTIES.get(fam, [fam]):
            ledger.record(pid, applicable=1, executable=1)
            tid = getattr(t, "id", "")
            if tid and tid in executed_ids:
                ledger.record(pid, executed=1)
                v = verdicts.get(tid, "")
                if v == "CONFIRMED":
                    ledger.record(pid, confirmed=1)
                elif v == "REFUTED":
                    ledger.record(pid, refuted=1)
                elif v == "INSUFFICIENT":
                    ledger.record(pid, insufficient=1)
                elif v == "BLOCKED":
                    ledger.record(pid, blocked=1)
    return ledger
