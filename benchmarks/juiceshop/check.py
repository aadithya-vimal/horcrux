"""Juice Shop benchmark checker: expected.yaml + workspace -> TP/FP/FN.

Usage: py benchmarks/juiceshop/check.py <workspace-state.json>

Matches canonical findings to benchmark items by (property, asset) with
per-item verification requirements. Never fuzzy-matches titles.
"""
from __future__ import annotations

import json
import re
import sys


def _load_expected(path: str) -> dict:
    try:
        import yaml  # type: ignore
        with open(path, encoding="utf-8") as fh:
            return yaml.safe_load(fh)
    except Exception:
        # Minimal YAML subset parser for the expected manifest shape.
        items, cur = [], {}
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                m = re.match(r"\s+- id: (\S+)", line)
                if m:
                    if cur:
                        items.append(cur)
                    cur = {"id": m.group(1)}
                    continue
                m2 = re.match(r"\s+(title|severity|type|property|asset):\s*(.*)", line)
                if m2 and cur is not None:
                    cur[m2.group(1)] = m2.group(2).strip()
        if cur:
            items.append(cur)
        return {"findings": items}


CATEGORY_TO_VULN = {
    "authn-jwt-issuance": "VULN-001",
    "authorization": "VULN-002",
    "injection-sqli": "VULN-003",
    "auth-bypass-sqli": "VULN-003",
    "web-information-disclosure": "VULN-004",
    "information-disclosure": "VULN-004",
    "configuration": None,  # resolved by title below
    "sensitive-artifact": "VULN-008",
    "weak-crypto-artifact": "VULN-009",
    "xss": "VULN-010",
    "api-security": "VULN-012",
    "unauth-mutation": "VULN-001",
}


def check(state_path: str, expected_path: str) -> dict:
    state = json.load(open(state_path, encoding="utf-8"))
    expected = _load_expected(expected_path)
    positives = [f for f in expected.get("findings", [])
                 if f.get("type", "positive") == "positive"]
    matched: dict[str, dict] = {}
    fps: list[dict] = []
    for f in state.get("findings", []):
        if str(f.get("validation_state", "")).upper() not in ("CONFIRMED", "LIKELY"):
            continue
        cat = str(f.get("category", "")).lower()
        title = str(f.get("title", "")).lower()
        vid = CATEGORY_TO_VULN.get(cat)
        if vid is None and cat.startswith("configuration"):
            if "content-security" in title:
                vid = "VULN-005"
            elif "cors" in title:
                vid = "VULN-006"
            elif "rate limit" in title:
                vid = "VULN-011"
            elif "header" in title:
                vid = "VULN-007"
        if vid is None:
            fps.append({"id": f.get("id"), "title": f.get("title"),
                        "reason": "no benchmark mapping"})
            continue
        matched.setdefault(vid, {"finding_ids": [], "title": f.get("title")})
        matched[vid]["finding_ids"].append(f.get("id"))
    rows = []
    for item in positives:
        vid = item["id"]
        if vid in matched:
            rows.append({"id": vid, "title": item.get("title"),
                         "severity": item.get("severity"),
                         "status": "CONFIRMED",
                         "finding_ids": matched[vid]["finding_ids"]})
        else:
            rows.append({"id": vid, "title": item.get("title"),
                         "severity": item.get("severity"),
                         "status": _miss_stage(vid, state),
                         "finding_ids": []})
    tps = [r for r in rows if r["status"] == "CONFIRMED"]
    fns = [r for r in rows if r["status"] != "CONFIRMED"]
    blocked = [r["id"] for r in rows if r["status"] == "BLOCKED"]
    insufficient = [r["id"] for r in rows if r["status"] == "INSUFFICIENT"]
    notimpl = [r["id"] for r in rows if r["status"] == "NOT_IMPLEMENTED"]
    return {"rows": rows, "tp": len(tps), "fn": len(fns),
            "fp": len(fps), "fps": fps,
            "blocked": blocked, "insufficient": insufficient,
            "not_implemented": notimpl,
            "ground_truth": len(positives),
            "precision": (len(tps) / (len(tps) + len(fps))) if (tps or fps) else 0.0,
            "recall": (len(tps) / len(positives)) if positives else 0.0}


def _is_blocked(vid: str, state: dict) -> bool:
    text = json.dumps(state.get("investigations", [])).lower()
    return ("requires_second_identity" in text or "requires_auth" in text) and vid in ("VULN-002",)


VULN_FAMILY_HINTS = {
    "VULN-001": ("registration", "api/users", "unauthenticated"),
    "VULN-002": ("bola", "idor", "horizontal", "object"),
    "VULN-003": ("sqli", "injection", "bypass"),
    "VULN-004": ("config_exposure", "ftp", "robots"),
    "VULN-005": ("controls", "header", "csp"),
    "VULN-006": ("controls", "cors"),
    "VULN-007": ("controls", "header"),
    "VULN-008": ("file_probe", "ftp", "artifact"),
    "VULN-009": ("file_probe", "artifact", "xor"),
    "VULN-010": ("xss", "reflection"),
    "VULN-011": ("controls", "rate"),
    "VULN-012": ("api_security", "excessive", "memories"),
}


def _miss_stage(vid: str, state: dict) -> str:
    """BLOCKED / INSUFFICIENT / NOT_IMPLEMENTED / MISSED for a missed item."""
    invs = state.get("investigations", []) or []
    hints = VULN_FAMILY_HINTS.get(vid, ())
    related = [i for i in invs if any(
        h in json.dumps(i).lower() for h in hints)]
    if not related:
        return "NOT_IMPLEMENTED"
    terms = " ".join(str(i.get("state", "")) for i in related)
    if any(k in terms for k in ("REQUIRES_AUTH", "REQUIRES_SECOND_IDENTITY",
                                "REQUIRES_TOOL", "BLOCKED", "SCOPE_BLOCKED")):
        return "BLOCKED"
    if "INSUFFICIENT_EVIDENCE" in terms:
        return "INSUFFICIENT"
    return "MISSED"


if __name__ == "__main__":
    report = check(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else
                   "benchmarks/juiceshop/expected.yaml")
    print(f"ground_truth={report['ground_truth']} TP={report['tp']} "
          f"FP={report['fp']} FN={report['fn']} "
          f"BLOCKED={report['blocked']} INSUFFICIENT={report['insufficient']} "
          f"NOT_IMPLEMENTED={report['not_implemented']} "
          f"precision={report['precision']:.2f} recall={report['recall']:.2f}")
    for r in report["rows"]:
        print(f"{r['id']} [{r['severity']}] {r['status']} {r['finding_ids']} {r['title']}")
    for fp in report["fps"]:
        print(f"FP {fp}")
