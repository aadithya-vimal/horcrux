"""Normalized tool registry for agent execution.

Production capabilities are bound to existing HORCRUX modules via
:mod:`horcrux.agents.tools.capabilities`. This module preserves the legacy
``ToolSpec``/``ToolRegistry`` surface for backward compatibility while
exposing full capability metadata (capability_id, category, target types,
inputs, evidence types, safety, availability, failure classification,
timeout, provenance) through the same registry.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable


class ToolCategory(str, Enum):
    RECON = "recon"
    WEB = "web"
    HTTP = "http"
    BROWSER = "browser"
    VALIDATION = "validation"
    SERVICE = "service"
    INTELLIGENCE = "intelligence"


class ToolRiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class ToolResult:
    tool: str
    request_id: str
    success: bool
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    structured_data: dict[str, Any] = field(default_factory=dict)
    artifact_refs: list[str] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    duration_ms: int = 0


@dataclass
class ToolSpec:
    name: str
    category: ToolCategory
    schema: dict[str, Any]
    handler: Callable[..., ToolResult] | None = None
    prerequisites: list[str] = field(default_factory=list)
    evidence_mapping: str = ""
    timeout: int = 300
    risk_level: ToolRiskLevel = ToolRiskLevel.LOW
    # --- Phase 7 capability metadata (defaults keep legacy specs valid) ---
    capability_id: str = ""
    supported_target_types: list[str] = field(default_factory=list)
    required_inputs: list[str] = field(default_factory=list)
    produced_evidence_types: list[str] = field(default_factory=list)
    safety_classification: str = "low"
    availability_check: Callable[[Any], bool] | None = None
    failure_classification: str = "tool_failed"
    provenance: str = ""

    def __post_init__(self) -> None:
        if not self.capability_id:
            self.capability_id = self.name


class ToolRegistry:
    """Central execution boundary — specialists must execute through here.

    The registry reuses the single production :class:`CapabilityRegistry`
    (which itself reuses the existing ``CommandRunner``) and exposes legacy
    mock handlers only as an offline fallback.
    """

    def __init__(self, workspace: Any = None, runner: Any = None,
                 state: Any = None) -> None:
        self._tools: dict[str, ToolSpec] = {}
        self.workspace = workspace
        self.runner = runner
        self.state = state
        self._capabilities = None

    def bind_context(self, workspace: Any = None, runner: Any = None,
                     state: Any = None) -> None:
        if workspace is not None:
            self.workspace = workspace
        if runner is not None:
            self.runner = runner
        if state is not None:
            self.state = state
        self._capabilities = None

    @property
    def capabilities(self):  # lazy production registry reusing CommandRunner
        if self._capabilities is None:
            from horcrux.agents.tools.capabilities import CapabilityRegistry
            scope_check = None
            if self.state is not None:
                try:
                    policy = self.state.get_policy()
                    scope_check = lambda t: policy.is_target_allowed(t)[0]  # noqa: E731
                except Exception:
                    scope_check = None
            self._capabilities = CapabilityRegistry(
                workspace=self.workspace, runner=self.runner,
                state=self.state, scope_check=scope_check)
        return self._capabilities

    def register(self, spec: ToolSpec) -> None:
        if not spec.capability_id:
            spec.capability_id = spec.name
        self._tools[spec.name] = spec

    def get(self, name: str) -> ToolSpec | None:
        spec = self._tools.get(name)
        if spec is not None:
            return spec
        # Fall back to production capability metadata.
        try:
            cap = self.capabilities.get(name)
        except Exception:
            cap = None
        if cap is None:
            return None
        return ToolSpec(
            name=cap.capability_id, category=ToolCategory(cap.category.value),
            schema={k: "str" for k in cap.required_inputs},
            handler=None, prerequisites=list(cap.required_inputs),
            evidence_mapping=",".join(cap.produced_evidence_types),
            timeout=cap.timeout,
            risk_level=ToolRiskLevel(cap.safety.value) if cap.safety.value in
            {"low", "medium", "high"} else ToolRiskLevel.LOW,
            capability_id=cap.capability_id,
            supported_target_types=list(cap.supported_target_types),
            required_inputs=list(cap.required_inputs),
            produced_evidence_types=list(cap.produced_evidence_types),
            safety_classification=cap.safety.value,
            provenance=cap.provenance,
        )

    def availability(self, name: str) -> dict[str, Any]:
        """Availability + failure-classification report for one capability."""
        spec = self.get(name)
        if spec is None:
            return {"available": False, "reason": "capability_unavailable"}
        available = True
        if spec.availability_check is not None:
            try:
                available = bool(spec.availability_check(self.runner))
            except Exception:
                available = False
        else:
            try:
                report = self.capabilities.availability_report()
                available = bool(report.get(name, {}).get("available", True))
            except Exception:
                available = True
        return {"available": available, "timeout": spec.timeout,
                "safety": spec.safety_classification, "provenance": spec.provenance}

    def list_tools(self, category: ToolCategory | None = None) -> list[ToolSpec]:
        specs = list(self._tools.values())
        # Merge production capabilities not already registered.
        try:
            for cap in self.capabilities.list():
                if cap.capability_id not in self._tools:
                    specs.append(self.get(cap.capability_id))
        except Exception:
            pass
        if category:
            return [t for t in specs if t and t.category == category]
        return [t for t in specs if t]

    def execute(self, name: str, **kwargs: Any) -> ToolResult:
        # Canonicalize legacy IDs first so production handlers win over
        # test-only mock handlers (js_analyzer → js_analyze, etc.).
        from horcrux.agents.tools.capabilities import canonical_tool_id
        name = canonical_tool_id(name)
        # Prefer production capability path (existing modules + CommandRunner).
        try:
            cap = self.capabilities.get(name)
        except Exception:
            cap = None
        if cap is not None and cap.execute_fn is not None and (
            self.workspace is not None or self.state is not None or self.runner is not None
        ):
            try:
                result = self.capabilities.execute(name, dict(kwargs),
                                                   request_id=str(kwargs.get("request_id", "")))
                return ToolResult(
                    tool=name,
                    request_id=str(kwargs.get("request_id", "")),
                    success=result.success,
                    exit_code=0 if result.success else 1,
                    stdout=result.stdout,
                    stderr=result.stderr,
                    structured_data=result.structured_data,
                    artifact_refs=list(result.artifacts),
                    evidence_refs=[e.get("source", name) + ":" + str(
                        e.get("data", {}).get("path", e.get("data", {}).get("endpoint", "")))
                        for e in result.evidence],
                    duration_ms=result.duration_ms,
                )
            except Exception:
                pass
        spec = self._tools.get(name)
        if not spec or not spec.handler:
            # Capability exists but no legacy handler: surface as unavailable
            # rather than crashing callers.
            if cap is not None:
                try:
                    result = self.capabilities.execute(name, dict(kwargs),
                                                       request_id=str(kwargs.get("request_id", "")))
                    return ToolResult(
                        tool=name,
                        request_id=str(kwargs.get("request_id", "")),
                        success=result.success,
                        exit_code=0 if result.success else 1,
                        stdout=result.stdout,
                        stderr=result.stderr,
                        structured_data=result.structured_data,
                        artifact_refs=list(result.artifacts),
                        evidence_refs=[e.get("source", name) for e in result.evidence],
                        duration_ms=result.duration_ms,
                    )
                except Exception as exc:
                    return ToolResult(tool=name, request_id=kwargs.get("request_id", ""),
                                      success=False, stderr=str(exc))
            return ToolResult(
                tool=name,
                request_id=kwargs.get("request_id", ""),
                success=False,
                stderr=f"Tool '{name}' not registered or has no handler",
            )
        return spec.handler(**kwargs)


def _mock_http_probe(**kwargs: Any) -> ToolResult:
    endpoint = kwargs.get("endpoint", "")
    identity = kwargs.get("identity", "anonymous")
    return ToolResult(
        tool="http_probe",
        request_id=kwargs.get("request_id", "mock"),
        success=True,
        structured_data={
            "endpoint": endpoint,
            "identity": identity,
            "status_code": 200 if identity != "anonymous" else 401,
            "authorization_enforced": identity == "anonymous",
        },
        evidence_refs=[f"http_probe:{endpoint}:{identity}"],
    )


def _mock_js_analyzer(**kwargs: Any) -> ToolResult:
    routes = kwargs.get("routes", [])
    return ToolResult(
        tool="js_analyzer",
        request_id=kwargs.get("request_id", "mock"),
        success=True,
        structured_data={"routes": routes, "parameters": kwargs.get("parameters", [])},
        evidence_refs=[f"js_analyzer:{r}" for r in routes[:5]],
    )


def _mock_identity_switch(**kwargs: Any) -> ToolResult:
    return ToolResult(
        tool="identity_switch",
        request_id=kwargs.get("request_id", "mock"),
        success=True,
        structured_data={
            "from_identity": kwargs.get("from_identity", "anonymous"),
            "to_identity": kwargs.get("to_identity", "user"),
            "session_established": True,
        },
        evidence_refs=["identity_switch:session"],
    )


def _mock_validator(**kwargs: Any) -> ToolResult:
    path = kwargs.get("path", "")
    return ToolResult(
        tool="validator",
        request_id=kwargs.get("request_id", "mock"),
        success=True,
        structured_data={"path": path, "validated": True, "classification": "DISTINCT"},
        evidence_refs=[f"validator:{path}"],
    )


def create_default_registry() -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="http_probe",
            category=ToolCategory.HTTP,
            schema={"endpoint": "str", "identity": "str", "method": "str"},
            handler=_mock_http_probe,
            prerequisites=["web_target"],
            evidence_mapping="endpoint_observation",
            timeout=30,
        )
    )
    registry.register(
        ToolSpec(
            name="js_analyzer",
            category=ToolCategory.WEB,
            schema={"base_url": "str", "routes": "list", "parameters": "list"},
            handler=_mock_js_analyzer,
            prerequisites=["web_target"],
            evidence_mapping="route_discovery",
            timeout=120,
        )
    )
    registry.register(
        ToolSpec(
            name="identity_switch",
            category=ToolCategory.HTTP,
            schema={"from_identity": "str", "to_identity": "str"},
            handler=_mock_identity_switch,
            prerequisites=["authentication_surface"],
            evidence_mapping="identity_context",
            timeout=15,
        )
    )
    registry.register(
        ToolSpec(
            name="validator",
            category=ToolCategory.VALIDATION,
            schema={"path": "str", "port": "int"},
            handler=_mock_validator,
            prerequisites=["discovered_path"],
            evidence_mapping="validation_result",
            timeout=30,
        )
    )
    registry.register(
        ToolSpec(
            name="browser_navigate",
            category=ToolCategory.BROWSER,
            schema={"url": "str", "actions": "list"},
            handler=lambda **kw: ToolResult(
                tool="browser_navigate",
                request_id=kw.get("request_id", "mock"),
                success=True,
                structured_data={"url": kw.get("url", ""), "forms": [], "links": [], "network_requests": []},
                evidence_refs=[f"browser:{kw.get('url', '')}"],
            ),
            prerequisites=["web_target"],
            evidence_mapping="browser_observation",
            timeout=60,
            risk_level=ToolRiskLevel.MEDIUM,
        )
    )
    return registry
