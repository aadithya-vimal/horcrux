"""Normalized tool registry for agent execution."""

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


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(self, spec: ToolSpec) -> None:
        self._tools[spec.name] = spec

    def get(self, name: str) -> ToolSpec | None:
        return self._tools.get(name)

    def list_tools(self, category: ToolCategory | None = None) -> list[ToolSpec]:
        if category:
            return [t for t in self._tools.values() if t.category == category]
        return list(self._tools.values())

    def execute(self, name: str, **kwargs: Any) -> ToolResult:
        spec = self._tools.get(name)
        if not spec or not spec.handler:
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
