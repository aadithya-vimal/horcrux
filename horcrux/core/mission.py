"""Domain models for autonomous headless VAPT missions.

Defines the mission lifecycle, stages, identities, execution policies, budgets,
and briefs for autonomous operation.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, List, Optional

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class MissionStage(str, Enum):
    PLANNING = "PLANNING"
    MISSION = "MISSION"
    SCOPE = "SCOPE"
    RECONNAISSANCE = "RECONNAISSANCE"
    MODELING = "MODELING"
    DISCOVERY = "DISCOVERY"
    HYPOTHESIS = "HYPOTHESIS"
    INVESTIGATION = "INVESTIGATION"
    CORRELATION = "CORRELATION"
    HANDOFF = "HANDOFF"
    COMPLETION = "COMPLETION"
    PAUSED = "PAUSED"
    ABORTED = "ABORTED"


class MissionStatus(str, Enum):
    INITIALIZED = "INITIALIZED"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    INTERRUPTED = "INTERRUPTED"
    ABORTED = "ABORTED"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"
    COMPLETE = "COMPLETE"
    COMPLETE_WITH_LIMITATIONS = "COMPLETE_WITH_LIMITATIONS"


class AccessContextStatus(str, Enum):
    CONFIGURED = "CONFIGURED"
    VALID = "VALID"
    EXPIRED = "EXPIRED"
    UNAVAILABLE = "UNAVAILABLE"


class AccessContext(BaseModel):
    """Pre-established access context supplied by the tester.
    
    Authentication is an assessment INPUT, never a mission phase.
    HORCRUX consumes pre-established sessions/tokens and does NOT attempt
    login workflows or wait for credentials. Secrets are never logged.
    """

    context_id: str
    display_name: str = ""
    role_label: str = "user"  # anonymous, user, admin, privileged, org_owner, api_client
    source: str = "provided"  # provided, browser_session, cookie_session, api_token, bearer_token
    cookies: dict[str, str] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    bearer_token_ref: str = ""  # Env var name or key reference holding secret
    session_reference: str = ""
    api_credential_reference: str = ""
    scope: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    status: AccessContextStatus = AccessContextStatus.CONFIGURED
    last_validated_at: Optional[datetime] = None
    validation_endpoint: str = ""
    failure_reason: str = ""

    # Compatibility attributes for earlier identity profile usage
    username: str = ""
    password_env: str = ""
    credentials_ref: str = ""
    login_url: str = ""
    auth_workflow: str = "provided"
    is_authenticated: bool = False

    @property
    def identity_id(self) -> str:
        return self.context_id

    @identity_id.setter
    def identity_id(self, val: str) -> None:
        self.context_id = val

    @property
    def role(self) -> str:
        return self.role_label

    @role.setter
    def role(self, val: str) -> None:
        self.role_label = val

    def resolve_credential(self) -> str:
        env_var = self.credentials_ref or self.password_env or self.bearer_token_ref or self.api_credential_reference
        if env_var and os.environ.get(env_var):
            return os.environ[env_var]
        return ""


# Compatibility alias
IdentityProfile = AccessContext


class HeadlessExecutionPolicy(BaseModel):
    """Safety and execution constraints governing autonomous operation."""

    max_runtime_seconds: int = 1800  # 30 min default
    max_requests: int = 2500
    max_iterations: int = 25
    max_concurrency: int = 2
    rate_limit_profile: str = "normal"  # conservative, normal, aggressive
    requests_per_second: float = 5.0
    aggressive_scanning_allowed: bool = False
    destructive_actions_allowed: bool = False
    exploit_execution_allowed: bool = False  # strictly stops at handoff-ready
    browser_enabled: bool = True
    external_engines_enabled: bool = True
    max_ai_calls: int = 50
    max_tool_executions: int = 100
    narrative_mode: bool = True


class BudgetTracker(BaseModel):
    """Tracks resource consumption against execution policy budgets."""

    start_time: datetime = Field(default_factory=utcnow)
    runtime_seconds: float = 0.0
    requests_count: int = 0
    tool_executions_count: int = 0
    ai_calls_count: int = 0
    provider_queries_count: int = 0
    is_exhausted: bool = False
    exhaustion_reasons: list[str] = Field(default_factory=list)

    def update_runtime(self) -> float:
        delta = (utcnow() - self.start_time).total_seconds()
        self.runtime_seconds = delta
        return delta

    def check_limits(self, policy: HeadlessExecutionPolicy) -> bool:
        self.update_runtime()
        reasons = []
        if self.runtime_seconds >= policy.max_runtime_seconds:
            reasons.append(f"Runtime exceeded ({int(self.runtime_seconds)}s >= {policy.max_runtime_seconds}s)")
        if self.requests_count >= policy.max_requests:
            reasons.append(f"Request count exceeded ({self.requests_count} >= {policy.max_requests})")
        if self.tool_executions_count >= policy.max_tool_executions:
            reasons.append(f"Tool executions exceeded ({self.tool_executions_count} >= {policy.max_tool_executions})")
        if self.ai_calls_count >= policy.max_ai_calls:
            reasons.append(f"AI calls exceeded ({self.ai_calls_count} >= {policy.max_ai_calls})")

        if reasons:
            self.is_exhausted = True
            for r in reasons:
                if r not in self.exhaustion_reasons:
                    self.exhaustion_reasons.append(r)
            return True
        return False


class MissionBrief(BaseModel):
    """Normalized pre-flight brief persisted to raw/mission-brief.json."""

    mission_id: str
    target: str
    scope: list[str] = Field(default_factory=list)
    profile: str = "standard"
    objectives: list[str] = Field(default_factory=list)
    available_access_contexts: list[str] = Field(default_factory=list)
    available_identities: list[str] = Field(default_factory=list)
    available_capabilities: list[str] = Field(default_factory=list)
    external_integrations: dict[str, str] = Field(default_factory=dict)
    safety_limits: dict[str, Any] = Field(default_factory=dict)
    execution_budget: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utcnow)


class AssessmentMission(BaseModel):
    """Authoritative persistent representation of an autonomous assessment mission."""

    mission_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    target: str
    scope: list[str] = Field(default_factory=list)
    profile: str = "standard"
    current_stage: MissionStage = MissionStage.MISSION
    status: MissionStatus = MissionStatus.INITIALIZED
    policy: HeadlessExecutionPolicy = Field(default_factory=HeadlessExecutionPolicy)
    budget: BudgetTracker = Field(default_factory=BudgetTracker)
    access_contexts: list[AccessContext] = Field(default_factory=list)
    identities: list[IdentityProfile] = Field(default_factory=list)
    current_investigation_id: str = ""
    current_objective: str = ""
    start_time: datetime = Field(default_factory=utcnow)
    last_checkpoint_at: datetime = Field(default_factory=utcnow)
    termination_reason: str = ""
    completion_verdict: str = "INCOMPLETE"  # COMPLETE, COMPLETE_WITH_LIMITATIONS, BLOCKED, etc.
    active_capabilities: list[str] = Field(default_factory=list)
    enabled_integrations: list[str] = Field(default_factory=list)
    narrative_timeline: list[dict[str, Any]] = Field(default_factory=list)
    checkpoints_count: int = 0

    def get_all_contexts(self) -> list[AccessContext]:
        """Returns consolidated list of access contexts and legacy identities."""
        results: list[AccessContext] = list(self.access_contexts)
        known_ids = {c.context_id for c in results}
        for ident in self.identities:
            if ident.context_id not in known_ids:
                results.append(ident)
                known_ids.add(ident.context_id)
        return results

    def get_context(self, context_id: str) -> Optional[AccessContext]:
        for ctx in self.get_all_contexts():
            if ctx.context_id == context_id or ctx.role_label == context_id:
                return ctx
        return None

    def available_context_ids(self) -> list[str]:
        return [
            c.context_id for c in self.get_all_contexts()
            if c.status in (AccessContextStatus.VALID, AccessContextStatus.CONFIGURED)
        ] or ["anonymous"]

    def add_narrative(self, stage: str, header: str, detail: str, evidence_ref: str = "") -> None:
        self.narrative_timeline.append({
            "timestamp": utcnow().isoformat(),
            "stage": stage,
            "header": header,
            "detail": detail,
            "evidence_ref": evidence_ref,
        })
        if len(self.narrative_timeline) > 200:
            self.narrative_timeline = self.narrative_timeline[-200:]
