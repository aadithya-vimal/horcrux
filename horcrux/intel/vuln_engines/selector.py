"""Engine strategy — never run every engine by default.

Selects best-available engine set from profile, target type, health,
capabilities, previous runs, cost and expected incremental coverage.
"""

from __future__ import annotations

from typing import Any

from horcrux.intel.vuln_engines.types import EngineHealth, SelectedEngine

# profile → engine participation
PROFILE_ENGINE_MODE: dict[str, str] = {
    "quick": "none",       # native HORCRUX engines only
    "standard": "intel",   # native + available vulnerability intelligence (no full scans)
    "deep": "configured",  # native + configured external engines
    "full": "all",         # all applicable configured engines
    "network": "configured",
    "web": "configured",
    "service": "configured",
    "intel": "configured",
    "local": "none",
}

# relative scan cost (higher = slower / more expensive); used for redundancy
_ENGINE_COST: dict[str, int] = {
    "tenable": 3, "qualys": 3, "rapid7": 2, "greenbone": 1, "msdefender": 1,
}

# capability overlap group — engines in the same group are redundant
_REDUNDANCY_GROUP: dict[str, str] = {
    "tenable": "network-vm", "qualys": "network-vm",
    "rapid7": "network-vm", "greenbone": "network-vm",
    "msdefender": "intel",
}

_HEALTHY = {EngineHealth.HEALTHY, EngineHealth.CONFIGURED, EngineHealth.DEGRADED}


def engine_mode_for_profile(profile: str) -> str:
    return PROFILE_ENGINE_MODE.get((profile or "").lower(), "configured")


def select_engines(
    readiness: list[Any],
    profile: str = "standard",
    target: str = "",
    operator_include: list[str] | None = None,
    operator_exclude: list[str] | None = None,
    engine_mode: str = "best",
    previous_runs: dict[str, Any] | None = None,
) -> list[SelectedEngine]:
    """Return selected engines with rationale. Deterministic, no network.

    engine_mode: 'best' (dedupe redundant) | 'all' (every healthy configured).
    operator_include forces inclusion; operator_exclude forces OPERATOR_EXCLUDED.
    """
    _ = target
    include = {(i or "").lower() for i in (operator_include or [])}
    exclude = {(e or "").lower() for e in (operator_exclude or [])}
    previous_runs = previous_runs or {}
    mode = engine_mode_for_profile(profile)
    if engine_mode == "all":
        dedupe = False
    else:
        dedupe = True

    selected: list[SelectedEngine] = []
    if mode == "none":
        for r in readiness:
            pid = _pid(r)
            if pid in include:
                selected.append(SelectedEngine(provider_id=pid, reason="operator forced inclusion"))
            else:
                selected.append(SelectedEngine(provider_id=pid, mode="skipped",
                                               skip_reason=f"profile '{profile}' uses native engines only"))
        return selected

    # rank healthy configured engines: intel first in intel mode, else by cost/coverage
    candidates: list[tuple[int, Any]] = []
    for r in readiness:
        pid = _pid(r)
        healthy = _health(r) in _HEALTHY and _configured(r) and _enabled(r)
        if pid in exclude:
            selected.append(SelectedEngine(provider_id=pid, mode="skipped",
                                           skip_reason="operator excluded"))
            continue
        if pid in include:
            selected.append(SelectedEngine(provider_id=pid,
                                           reason="operator explicitly requested this engine"))
            continue
        if not healthy:
            selected.append(SelectedEngine(provider_id=pid, mode="skipped",
                                           skip_reason=_unhealthy_reason(r)))
            continue
        if mode == "intel" and pid != "msdefender":
            # standard profile: intelligence only, no full network scans
            selected.append(SelectedEngine(provider_id=pid, mode="skipped",
                                           skip_reason=f"profile '{profile}' uses vulnerability intelligence only; "
                                                       "full engine scans run on deep/full"))
            continue
        prev = previous_runs.get(pid, {})
        penalty = 5 if str(prev.get("status", "")).upper() == "COMPLETE" else 0
        cost = _ENGINE_COST.get(pid, 2) + penalty
        candidates.append((cost, r))

    candidates.sort(key=lambda c: c[0])
    seen_groups: set[str] = set()
    already = {s.provider_id for s in selected if s.mode == "selected"}
    for _cost, r in candidates:
        pid = _pid(r)
        if pid in already:
            continue
        group = _REDUNDANCY_GROUP.get(pid, pid)
        if dedupe and group in seen_groups and group == "network-vm":
            selected.append(SelectedEngine(
                provider_id=pid, mode="skipped",
                skip_reason=f"redundant network-VM coverage (group '{group}'); "
                            "lower expected incremental value — use --engine-mode all to force"))
            continue
        seen_groups.add(group)
        selected.append(SelectedEngine(
            provider_id=pid,
            reason=f"{_label(r)} selected: {_coverage_phrase(pid)}"))
    return selected


def _pid(r: Any) -> str:
    return str(getattr(r, "provider_id", "") or (r.get("provider_id", "") if isinstance(r, dict) else ""))


def _health(r: Any) -> EngineHealth:
    raw = getattr(r, "health", "") if not isinstance(r, dict) else r.get("health", "")
    if isinstance(raw, EngineHealth):
        return raw
    try:
        return EngineHealth(str(raw))
    except ValueError:
        return EngineHealth.UNAVAILABLE


def _configured(r: Any) -> bool:
    return bool(getattr(r, "configured", False) if not isinstance(r, dict) else r.get("configured", False))


def _enabled(r: Any) -> bool:
    return bool(getattr(r, "enabled", True) if not isinstance(r, dict) else r.get("enabled", True))


def _label(r: Any) -> str:
    label = getattr(r, "product", "") if not isinstance(r, dict) else r.get("product", "")
    return str(label or _pid(r)).title()


def _coverage_phrase(pid: str) -> str:
    return {
        "tenable": "network vulnerability coverage",
        "qualys": "network vulnerability coverage",
        "rapid7": "network/host vulnerability coverage",
        "greenbone": "network vulnerability coverage",
        "msdefender": "enterprise vulnerability-intelligence coverage",
    }.get(pid, "vulnerability coverage")


def _unhealthy_reason(r: Any) -> str:
    if not _configured(r):
        return "not configured"
    if not _enabled(r):
        return "disabled in settings"
    return f"health={_health(r).value.lower()}"
