"""Deterministic security-property benchmark.

KNOWN_PROPERTY {property_id, asset, prerequisites, expected, evidence}.
For each property: vulnerable fixture -> CONFIRMED, hardened -> REFUTED,
ambiguous -> INSUFFICIENT (never CONFIRMED). Distinguishes NOT_IMPLEMENTED
from IMPLEMENTED_BUT_FAILED. Produces the detection gap report.

Fully offline. No AI. `horcrux benchmark --properties` runs this.
"""

from __future__ import annotations

from pydantic import BaseModel

from horcrux.engine.oracles import ORACLES, evaluate


class BenchmarkCase(BaseModel):
    property_id: str
    asset: str = ""
    prerequisites: list[str] = []
    vulnerable_evidence: dict = {}
    hardened_evidence: dict = {}
    ambiguous_evidence: dict = {}


def _e(**kw) -> dict:
    return dict(kw)


BENCHMARK_MANIFEST: list[BenchmarkCase] = [
    BenchmarkCase(property_id="INJECT_SQL", asset="/search?q",
                  prerequisites=["owned_parameter"],
                  vulnerable_evidence=_e(baseline_body='{"data":[]}', mutated_body='sqlite3 syntax error near "x"',
                                         repeatable=True),
                  hardened_evidence=_e(baseline_body='{"data":[]}', mutated_body='{"data":[]}'),
                  ambiguous_evidence=_e(baseline_body='{"data":[]}', mutated_body="error 500",
                                        generic_error_only=True)),
    BenchmarkCase(property_id="INJECT_COMMAND", asset="/run?cmd",
                  prerequisites=["owned_parameter"],
                  vulnerable_evidence=_e(baseline_body="cmd ok", mutated_body="uid=0(root) gid=0(root)"),
                  hardened_evidence=_e(baseline_body="cmd ok", mutated_body="cmd ok"),
                  ambiguous_evidence=_e(baseline_body="cmd ok", mutated_body="")),
    BenchmarkCase(property_id="XSS_REFLECTED", asset="/reflect?q",
                  prerequisites=["owned_parameter"],
                  vulnerable_evidence=_e(mutated_body='<div><script>alert(1)</script></div>', payload="<script>alert(1)</script>",
                                         reflected=True, unescaped=True, context="script-context"),
                  hardened_evidence=_e(mutated_body="<p>&lt;script&gt;</p>", payload="<script>",
                                        reflected=True, unescaped=False),
                  ambiguous_evidence=_e(mutated_body="<!-- <script> -->", payload="<script>",
                                        reflected=True, unescaped=False, context="comment")),
    BenchmarkCase(property_id="XSS_STORED", asset="/api/Feedbacks?comment",
                  prerequisites=["owned_parameter", "read_endpoint"],
                  vulnerable_evidence=_e(persisted=True, mutated_body="<img src=x onerror=alert(1)>",
                                         payload="<img src=x onerror=alert(1)>", reflected=True,
                                         unescaped=True, context="tag-attribute"),
                  hardened_evidence=_e(persisted=False, write_rejected=True),
                  ambiguous_evidence=_e(persisted=False)),
    BenchmarkCase(property_id="PATH_TRAVERSAL", asset="/files?file",
                  prerequisites=["owned_parameter"],
                  vulnerable_evidence=_e(baseline_body="file ok", mutated_body="root:x:0:0:root:/root:/bin/bash",
                                         repeatable=True),
                  hardened_evidence=_e(baseline_body="file ok", mutated_body="file ok"),
                  ambiguous_evidence=_e(baseline_body="file ok", mutated_body="")),
    BenchmarkCase(property_id="SSRF_BASIC", asset="/fetch?url",
                  prerequisites=["owned_parameter"],
                  vulnerable_evidence=_e(baseline_body="fetched ok", mutated_body="internal meta-data hostname",
                                         network_interaction=True),
                  hardened_evidence=_e(baseline_body="fetched ok", mutated_body="fetched ok"),
                  ambiguous_evidence=_e(baseline_body="fetched ok", mutated_body="url=http://x",
                                        reflected_only=True)),
    BenchmarkCase(property_id="AUTHZ_BOLA_IDOR", asset="/api/orders/2",
                  prerequisites=["two_identities", "object_instance"],
                  vulnerable_evidence=_e(ownership_proven=True, status_owner=200, status_other=200,
                                         private_fields=True),
                  hardened_evidence=_e(ownership_proven=True, status_owner=200, status_other=403),
                  ambiguous_evidence=_e(ownership_proven=True, status_owner=200, status_other=0)),
    BenchmarkCase(property_id="AUTHZ_VERTICAL_PRIVESC", asset="/rest/admin/version",
                  prerequisites=["web_target"],
                  vulnerable_evidence=_e(lowpriv_status=200, privileged_content=True),
                  hardened_evidence=_e(lowpriv_status=403),
                  ambiguous_evidence=_e(lowpriv_status=0)),
    BenchmarkCase(property_id="AUTHN_UNAUTH_PROTECTED_ACCESS", asset="/rest/basket/1",
                  prerequisites=["web_target"],
                  vulnerable_evidence=_e(anon_status=200, anon_body='{"items":[]}', protected_content=True),
                  hardened_evidence=_e(anon_status=401, anon_body="login"),
                  ambiguous_evidence=_e(anon_status=0, anon_body="")),
    BenchmarkCase(property_id="API_EXCESSIVE_DATA", asset="GET /api/Users",
                  prerequisites=["web_target"],
                  vulnerable_evidence=_e(actor="anonymous", fields=["id", "email", "passwordHash", "role"]),
                  hardened_evidence=_e(actor="anonymous", fields=["id", "name"]),
                  ambiguous_evidence=_e(actor="anonymous", fields=[])),
    BenchmarkCase(property_id="API_MASS_ASSIGNMENT", asset="POST /api/users",
                  prerequisites=["mutation_endpoint"],
                  vulnerable_evidence=_e(privileged_field_accepted=True, persisted=True, field="role"),
                  hardened_evidence=_e(ignored_or_rejected=True),
                  ambiguous_evidence=_e()),
    BenchmarkCase(property_id="FILE_UPLOAD_WEAKNESS", asset="/upload",
                  prerequisites=["upload_surface"],
                  vulnerable_evidence=_e(stored=True, retrievable=True, executable=True),
                  hardened_evidence=_e(rejected=True),
                  ambiguous_evidence=_e(stored=True)),
    BenchmarkCase(property_id="CONFIG_DIR_LISTING", asset="/ftp",
                  prerequisites=["web_target"],
                  vulnerable_evidence=_e(status=200, body="<title>Index of /ftp</title>parent directory file.bak",
                                         files=["file.bak"]),
                  hardened_evidence=_e(status=200, body="<h1>ftp ready</h1>", files=[]),
                  ambiguous_evidence=_e(status=200, body="<title>Index of /ftp</title>parent directory",
                                        files=[])),
    BenchmarkCase(property_id="CONFIG_BACKUP_EXPOSURE", asset="/.env",
                  prerequisites=["web_target"],
                  vulnerable_evidence=_e(status=200, body="DB_USER=root\nDB_PASS=x\n", content_type="text/plain",
                                         format_markers=True),
                  hardened_evidence=_e(status=200, body="<html>not found</html>", content_type="text/html"),
                  ambiguous_evidence=_e(status=0, body="")),
    BenchmarkCase(property_id="BIZ_PRICE_MANIPULATION", asset="checkout",
                  prerequisites=["workflow_model"],
                  vulnerable_evidence=_e(client_price_accepted=True),
                  hardened_evidence=_e(server_pricing=True),
                  ambiguous_evidence=_e()),
    BenchmarkCase(property_id="BIZ_WORKFLOW_BYPASS", asset="checkout",
                  prerequisites=["workflow_model"],
                  vulnerable_evidence=_e(bypass_accepted=True),
                  hardened_evidence=_e(rejected=True),
                  ambiguous_evidence=_e()),
    BenchmarkCase(property_id="GRAPHQL_INTROSPECTION", asset="/graphql",
                  prerequisites=["graphql_endpoint"],
                  vulnerable_evidence=_e(schema_disclosed=True),
                  hardened_evidence=_e(disabled=True),
                  ambiguous_evidence=_e()),
    BenchmarkCase(property_id="GRAPHQL_AUTHZ", asset="/graphql User(id:2)",
                  prerequisites=["graphql_endpoint", "two_identities"],
                  vulnerable_evidence=_e(ownership_proven=True, status_owner=200, status_other=200,
                                         private_fields=True),
                  hardened_evidence=_e(ownership_proven=True, status_owner=200, status_other=403),
                  ambiguous_evidence=_e(ownership_proven=True, status_owner=200, status_other=0)),
    BenchmarkCase(property_id="CONFIG_ADMIN_EXPOSURE", asset="/admin",
                  prerequisites=["web_target"],
                  vulnerable_evidence=_e(status=200, admin_markers=True),
                  hardened_evidence=_e(status=403),
                  ambiguous_evidence=_e(status=0)),
    BenchmarkCase(property_id="INJECT_NOSQL", asset="/api/users?filter",
                  prerequisites=["owned_parameter"],
                  vulnerable_evidence=_e(baseline_count=1, mutated_count=57, operator_payload=True),
                  hardened_evidence=_e(baseline_count=1, mutated_count=1, operator_payload=True),
                  ambiguous_evidence=_e(baseline_count=-1, mutated_count=-1,
                                        baseline_body="n/a", mutated_body="n/a?")),
    BenchmarkCase(property_id="SESSION_INVALIDATION", asset="/logout",
                  prerequisites=["session"],
                  vulnerable_evidence=_e(usable_after_logout=True),
                  hardened_evidence=_e(invalidated=True),
                  ambiguous_evidence=_e()),
]


class BenchmarkResult(BaseModel):
    property_id: str
    implemented: bool = True
    vulnerable_verdict: str = ""
    hardened_verdict: str = ""
    ambiguous_verdict: str = ""
    vulnerable_pass: bool = False
    hardened_pass: bool = False
    ambiguous_pass: bool = False
    overall: str = ""  # PASS|FAIL|NOT_IMPLEMENTED|BLOCKED


def run_benchmark(manifest: list[BenchmarkCase] | None = None) -> dict:
    manifest = manifest if manifest is not None else BENCHMARK_MANIFEST
    results: list[BenchmarkResult] = []
    for case in manifest:
        from horcrux.engine.properties import get_property
        prop = get_property(case.property_id)
        if prop is None or prop.oracle not in ORACLES:
            results.append(BenchmarkResult(property_id=case.property_id,
                                           implemented=False, overall="NOT_IMPLEMENTED"))
            continue
        v = evaluate(case.property_id, dict(case.vulnerable_evidence))
        h = evaluate(case.property_id, dict(case.hardened_evidence))
        a = evaluate(case.property_id, dict(case.ambiguous_evidence))
        vp = v.verdict == "CONFIRMED"
        hp = h.verdict == "REFUTED"
        ap = a.verdict == "INSUFFICIENT"
        blocked = v.verdict == "BLOCKED" or h.verdict == "BLOCKED"
        overall = "PASS" if (vp and hp and ap) else ("BLOCKED" if blocked else "FAIL")
        results.append(BenchmarkResult(
            property_id=case.property_id, implemented=True,
            vulnerable_verdict=v.verdict, hardened_verdict=h.verdict,
            ambiguous_verdict=a.verdict, vulnerable_pass=vp,
            hardened_pass=hp, ambiguous_pass=ap, overall=overall))
    tp = sum(1 for r in results if r.vulnerable_pass)
    # FP = hardened fixture confirmed (must never happen).
    fp = sum(1 for r in results if r.implemented and r.hardened_verdict == "CONFIRMED")
    fn = sum(1 for r in results if r.implemented and not r.vulnerable_pass)
    blocked = sum(1 for r in results if r.overall == "BLOCKED")
    not_impl = sum(1 for r in results if not r.implemented)
    passed = sum(1 for r in results if r.overall == "PASS")
    return {
        "results": [r.model_dump() for r in results],
        "total": len(results),
        "passed": passed,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "blocked": blocked,
        "not_implemented": not_impl,
    }


def gap_report_text(report: dict) -> str:
    lines = ["PROPERTY | EXPECTED | TESTED | RESULT | MATCH | EVIDENCE"]
    for r in report["results"]:
        if not r["implemented"]:
            lines.append(f"{r['property_id']}: expected=vulnerable tested=no result=n/a match=NOT_IMPLEMENTED")
            continue
        lines.append(f"{r['property_id']}: expected=vulnerable tested=yes "
                     f"result={r['vulnerable_verdict'].lower()} match={'PASS' if r['vulnerable_pass'] else 'FAIL'} "
                     f"[hardened={r['hardened_verdict'].lower()}{'PASS' if r['hardened_pass'] else 'FAIL'} "
                     f"ambiguous={r['ambiguous_verdict'].lower()}{'PASS' if r['ambiguous_pass'] else 'FAIL'}]")
    lines.append(f"TP={report['tp']} FP={report['fp']} FN={report['fn']} "
                 f"BLOCKED={report['blocked']} NOT_IMPLEMENTED={report['not_implemented']}")
    return "\n".join(lines)
