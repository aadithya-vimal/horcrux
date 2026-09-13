"""Synthetic vulnerable application fixture — no real network testing."""

from __future__ import annotations

from horcrux.models import (
    DiscoveredPath,
    NormalizedTechnology,
    Parameter,
    Service,
    TechCategory,
    WebApplicationType,
    WebTarget,
    WorkspaceState,
)


def build_synthetic_workspace() -> WorkspaceState:
    """Rich SPA-like application with security-relevant surfaces."""
    target = "synthetic-vuln-app.local"
    state = WorkspaceState(target=target)

    state.services = [
        Service(host=target, port=3000, service="http", product="Node.js", version="18.x"),
    ]

    state.normalized_technologies = [
        NormalizedTechnology(name="Angular", category=TechCategory.FRAMEWORK, confidence=0.94),
        NormalizedTechnology(name="Node.js", category=TechCategory.RUNTIME, confidence=0.90),
        NormalizedTechnology(name="Express", category=TechCategory.FRAMEWORK, confidence=0.85),
    ]

    js_routes = [
        "/rest/user/login",
        "/rest/user/register",
        "/rest/users/{id}",
        "/rest/basket/{id}",
        "/rest/products/{id}",
        "/rest/admin",
        "/rest/admin/users",
        "/api/feedbacks",
        "/api/challenges",
    ]

    state.discovered_paths = [
        DiscoveredPath(
            url=f"http://{target}:3000{path.replace('{id}', '1')}",
            path=path.replace("{id}", "1") if "{" not in path else path,
            status=200,
            source="javascript",
            validated=True,
        )
        for path in js_routes
    ]

    state.parameters = [
        Parameter(name="id", location="path", source="javascript", endpoint="/rest/users/{id}"),
        Parameter(name="basketId", location="path", source="javascript", endpoint="/rest/basket/{id}"),
        Parameter(name="productId", location="path", source="javascript", endpoint="/rest/products/{id}"),
        Parameter(name="email", location="body", source="form", endpoint="/rest/user/login"),
        Parameter(name="password", location="body", source="form", endpoint="/rest/user/login"),
        Parameter(name="q", location="query", source="url", endpoint="/api/feedbacks"),
    ]

    state.web_targets = [
        WebTarget(
            scheme="http",
            host=target,
            port=3000,
            base_url=f"http://{target}:3000",
            application_type=WebApplicationType.SPA,
            endpoints=state.discovered_paths,
            technologies=state.normalized_technologies,
            parameters=state.parameters,
        )
    ]

    return state


def build_robots_txt_only_workspace() -> WorkspaceState:
    """Regression fixture — minimal surface that must NOT appear 'clean'."""
    target = "minimal-app.local"
    state = WorkspaceState(target=target)
    state.services = [Service(host=target, port=80, service="http")]
    state.discovered_paths = [
        DiscoveredPath(
            url=f"http://{target}/robots.txt",
            path="/robots.txt",
            status=200,
            source="validator",
            validated=True,
        )
    ]
    return state
