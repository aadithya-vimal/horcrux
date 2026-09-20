"""Common normalized observation representation.

Every evidence-producing engine (nmap, ffuf, nuclei, httpx, browser,
native probes, external engines, custom validators) enters the pipeline
as an Observation. No scanner invents its own notion of vulnerability.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class HttpRequest(BaseModel):
    method: str = "GET"
    path: str = "/"
    query: dict[str, str] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = ""
    content_type: str = ""
    identity: str = "anonymous"


class HttpResponse(BaseModel):
    status: int = 0
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = ""
    content_type: str = ""
    length: int = 0


class Observation(BaseModel):
    """Normalized evidence-producer output. Never a verdict."""

    source: str = "unknown"
    timestamp: datetime = Field(default_factory=_utcnow)
    target: str = ""
    asset: str = ""
    endpoint: str = ""
    method: str = "GET"
    parameter: str = ""
    identity: str = "anonymous"
    request: HttpRequest = Field(default_factory=HttpRequest)
    response: HttpResponse = Field(default_factory=HttpResponse)
    protocol: str = "http"
    status: int = 0
    body_artifacts: list[str] = Field(default_factory=list)
    extracted_entities: dict[str, Any] = Field(default_factory=dict)
    parameters: list[dict[str, str]] = Field(default_factory=list)
    identities: list[str] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    versions: dict[str, str] = Field(default_factory=dict)
    confidence: float = Field(default=0.5, ge=0, le=1)
    provenance: str = "unknown"
    live: bool = False  # True only with real HTTP status (>0)

    @property
    def is_live(self) -> bool:
        return bool(self.live and self.status > 0)


def observe_http(source: str, target: str, endpoint: str, method: str,
                 status: int, body: str = "", headers: dict | None = None,
                 identity: str = "anonymous", parameter: str = "",
                 confidence: float = 0.8) -> Observation:
    hdrs = dict(headers or {})
    ctype = hdrs.get("content-type", hdrs.get("Content-Type", ""))
    return Observation(
        source=source, target=target, asset=endpoint, endpoint=endpoint,
        method=method.upper(), parameter=parameter, identity=identity,
        request=HttpRequest(method=method.upper(), path=endpoint, identity=identity),
        response=HttpResponse(status=status, headers=hdrs, body=body,
                              content_type=ctype, length=len(body)),
        status=status, confidence=confidence, provenance=source,
        live=status > 0,
    )


def observe_source_only(source: str, target: str, route: str,
                        artifacts: list[str] | None = None) -> Observation:
    """Source-derived clue (JS string, robots line). Never live evidence."""
    return Observation(
        source=source, target=target, asset=route, endpoint=route,
        status=0, confidence=0.6, provenance=source, live=False,
        body_artifacts=list(artifacts or []),
    )


def observation_from_capability_data(source: str, target: str,
                                     data: dict[str, Any]) -> Observation:
    """Normalize a capability result data dict into an Observation."""
    endpoint = str(data.get("path", data.get("endpoint", "/")) or "/")
    method = str(data.get("method", "GET") or "GET").upper()
    status = int(data.get("status_code", data.get("status", 0)) or 0)
    body = str(data.get("response_body", data.get("body", "")) or "")
    headers = data.get("headers", {}) or {}
    if not isinstance(headers, dict):
        headers = {}
    return observe_http(
        source=source, target=target, endpoint=endpoint, method=method,
        status=status, body=body, headers=headers,
        identity=str(data.get("identity", "anonymous") or "anonymous"),
        parameter=str(data.get("parameter", data.get("param", "")) or ""),
        confidence=float(data.get("confidence", 0.8) or 0.8),
    )
