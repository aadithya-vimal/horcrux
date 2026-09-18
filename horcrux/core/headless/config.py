"""Engagement configuration loader and parser for headless missions."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, List, Optional, Tuple

from horcrux.core.mission import (
    AssessmentMission,
    HeadlessExecutionPolicy,
    IdentityProfile,
    MissionStage,
    MissionStatus,
)
from horcrux.models import EngagementConfig, EngagementMode, RateLimitProfile


def _parse_yaml_or_json(content: str) -> dict[str, Any]:
    """Parse YAML if pyyaml is installed, otherwise parse JSON."""
    try:
        import yaml
        return yaml.safe_load(content) or {}
    except ImportError:
        try:
            return json.loads(content)
        except Exception as exc:
            raise ValueError(f"Could not parse configuration file as JSON (pyyaml not installed): {exc}")


def load_engagement_config(path_or_str: str | Path) -> dict[str, Any]:
    """Load configuration from a file path."""
    path = Path(path_or_str)
    if not path.exists():
        raise FileNotFoundError(f"Configuration file not found: {path}")
    raw = path.read_text(encoding="utf-8")
    return _parse_yaml_or_json(raw)


def build_mission_from_config(
    target: str,
    profile: str = "standard",
    config_data: dict[str, Any] | None = None,
    execution_overrides: dict[str, Any] | None = None,
) -> AssessmentMission:
    """Construct an AssessmentMission normalized from input parameters and optional config file."""
    config = config_data or {}
    exec_overrides = execution_overrides or {}

    # 1. Resolve Target
    effective_target = target.strip()
    if not effective_target:
        target_cfg = config.get("target", {})
        if isinstance(target_cfg, dict):
            urls = target_cfg.get("urls", [])
            hosts = target_cfg.get("hosts", [])
            if urls:
                effective_target = urls[0]
            elif hosts:
                effective_target = hosts[0]
        elif isinstance(target_cfg, str):
            effective_target = target_cfg
    if not effective_target:
        raise ValueError("Target must be specified via argument or config file")

    # 2. Resolve Scope
    scope_list: list[str] = []
    scope_cfg = config.get("scope", {})
    if isinstance(scope_cfg, dict):
        allowed_hosts = scope_cfg.get("allowed_hosts", [])
        allowed_targets = scope_cfg.get("allowed_targets", [])
        scope_list.extend(allowed_hosts or allowed_targets or [])
    elif isinstance(scope_cfg, list):
        scope_list.extend(scope_cfg)
    if effective_target not in scope_list:
        scope_list.append(effective_target)

    # 3. Resolve Identities
    identities: list[IdentityProfile] = []
    ids_cfg = config.get("identities", []) or []
    for id_item in ids_cfg:
        if isinstance(id_item, dict) and (id_item.get("id") or id_item.get("identity_id") or id_item.get("label")):
            iid = id_item.get("id") or id_item.get("identity_id") or id_item.get("label")
            identities.append(
                IdentityProfile(
                    identity_id=str(iid),
                    display_name=id_item.get("display_name", str(iid)),
                    role=id_item.get("role", "user"),
                    credentials_ref=id_item.get("credentials_ref", id_item.get("credential_reference", "")),
                    auth_workflow=id_item.get("auth_workflow", "login_form"),
                    login_url=id_item.get("login_url", id_item.get("login_path", "")),
                    username=id_item.get("username", ""),
                    password_env=id_item.get("password_env", ""),
                    headers=id_item.get("headers", {}),
                    permissions=id_item.get("permissions", []),
                    scope=id_item.get("scope", []),
                )
            )

    # 4. Resolve Execution Policy
    policy_cfg = config.get("execution", {})
    safety_cfg = config.get("safety", {})
    
    # Merge execution overrides
    max_runtime = exec_overrides.get("max_runtime") or policy_cfg.get("max_runtime") or 1800
    max_iterations = exec_overrides.get("max_iterations") or policy_cfg.get("max_iterations") or 25
    max_requests = exec_overrides.get("max_requests") or policy_cfg.get("max_requests") or 2500
    concurrency = exec_overrides.get("concurrency") or policy_cfg.get("concurrency") or 2
    browser_enabled = policy_cfg.get("browser", True)
    ext_engines_enabled = policy_cfg.get("external_engines", True)
    narrative_mode = exec_overrides.get("narrative", policy_cfg.get("narrative", True))

    destructive = safety_cfg.get("destructive_actions", False)
    exploit_execution = safety_cfg.get("exploit_execution", False)

    policy = HeadlessExecutionPolicy(
        max_runtime_seconds=int(max_runtime),
        max_requests=int(max_requests),
        max_iterations=int(max_iterations),
        max_concurrency=int(concurrency),
        destructive_actions_allowed=bool(destructive),
        exploit_execution_allowed=bool(exploit_execution),
        browser_enabled=bool(browser_enabled),
        external_engines_enabled=bool(ext_engines_enabled),
        narrative_mode=bool(narrative_mode),
    )

    selected_profile = exec_overrides.get("profile") or policy_cfg.get("profile") or profile or "standard"

    mission = AssessmentMission(
        target=effective_target,
        scope=scope_list,
        profile=selected_profile,
        policy=policy,
        identities=identities,
        current_stage=MissionStage.MISSION,
        status=MissionStatus.INITIALIZED,
    )

    return mission
