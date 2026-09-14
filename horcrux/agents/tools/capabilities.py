"""Production capability adapters — binds ToolRegistry to existing HORCRUX modules.

Boundary:
    Investigation -> Capability -> CapabilityRegistry -> existing module / CommandRunner
    -> raw output -> normalized Evidence -> ingestion

No specialist may execute shell directly; all execution flows through this registry.
Real network is only attempted against in-scope targets when the backing tool
exists; synthetic/offline targets (``*.local``, ``example.*``, loopback fixtures)
use deterministic synthesis derived from the ApplicationModel so tests never
require external network.
"""

from __future__ import annotations

import base64
import json
import os
import re
import secrets
import shutil
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional


class FailureClass(str, Enum):
    SUCCESS = "success"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    TOOL_FAILED = "tool_failed"
    UNAVAILABLE = "capability_unavailable"
    SCOPE_BLOCKED = "scope_blocked"
    APPROVAL_REQUIRED = "operator_approval_required"
    TIMEOUT = "timeout"
    POLICY_BLOCKED = "policy_blocked"


class SafetyClass(str, Enum):
    SAFE = "safe"  # passive read / local parse, no packets beyond normal HTTP
    LOW = "low"  # normal HTTP requests, banner grabs
    MEDIUM = "medium"  # fuzzing / active probing, still non-destructive
    HIGH = "high"  # intrusive; requires operator approval
    FORBIDDEN = "forbidden"  # never auto-executed (exploitation)


class CapabilityCategory(str, Enum):
    RECON = "recon"
    WEB = "web"
    HTTP = "http"
    BROWSER = "browser"
    VALIDATION = "validation"
    SERVICE = "service"
    INTELLIGENCE = "intelligence"


@dataclass
class CapabilityResult:
    capability_id: str
    success: bool
    failure: FailureClass = FailureClass.SUCCESS
    stdout: str = ""
    stderr: str = ""
    structured_data: dict[str, Any] = field(default_factory=dict)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    duration_ms: int = 0
    provenance: str = ""
    tool: str = ""


class ExecutionMode(str, Enum):
    LIVE = "live"  # real tool/network execution in this environment
    SYNTHETIC = "synthetic"  # model-derived offline synthesis (fixtures/tests)
    NONE = "none"  # cannot execute here


class Availability(str, Enum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    DISABLED = "disabled"
    BROKEN = "broken"


@dataclass
class CapabilityHealth:
    """Canonical capability health contract (single source of truth).

    Consumed by status UI, reports, ToolRegistry, and the scheduler.
    ``availability`` answers "can this produce evidence at all here";
    ``execution_mode`` answers "how would it execute" — never conflated.
    """

    capability_id: str
    availability: Availability = Availability.AVAILABLE
    execution_mode: ExecutionMode = ExecutionMode.SYNTHETIC
    reason: str = ""
    dependency: str = ""  # binary / package / runtime this verdict rests on
    provenance: str = ""
    target_support: bool | None = None  # None = not evaluated for a target
    diagnostic: str = ""

    def to_status_dict(self) -> dict[str, Any]:
        # Human-facing status vocabulary (no misleading "synthesis" synonym
        # for missing tooling; SYNTHETIC is an honest execution mode).
        status = {
            Availability.AVAILABLE: "AVAILABLE",
            Availability.UNAVAILABLE: "MISSING",
            Availability.DISABLED: "DISABLED",
            Availability.BROKEN: "BROKEN",
        }[self.availability]
        return {
            "status": status,
            "mode": self.execution_mode.value,
            "available": self.availability == Availability.AVAILABLE,
            "reason": self.reason,
            "dependency": self.dependency,
            "diagnostic": self.diagnostic,
        }


# Legacy capability IDs mapped to canonical production IDs.
# Backwards compatibility is explicit (never accidental family-map rescue).
TOOL_ALIASES: dict[str, str] = {
    "js_analyzer": "js_analyze",
    "validator": "endpoint_validate",
}


def canonical_tool_id(tool_id: str) -> str:
    """Resolve a legacy tool alias to its canonical capability ID."""
    return TOOL_ALIASES.get(str(tool_id or ""), str(tool_id or ""))


# Capabilities with an offline synthesis branch (fixture-grade fallback when
# the backing binary is absent). Used only to label execution_mode honestly.
_SYNTHETIC_FALLBACK_CAPS = frozenset({
    "http_probe", "web_fingerprint", "content_discovery", "js_analyze",
    "endpoint_validate", "graphql_probe", "param_fuzz", "jwt_analyze",
    "identity_switch", "authz_compare", "browser_navigate", "browser_automate",
    "identity_compare", "ssh_enum", "ftp_enum", "smtp_enum", "database_enum",
    "remote_enum", "nuclei_scan", "nikto_audit", "smb_enum", "ldap_enum",
    "kerberos_enum", "dns_enum", "snmp_enum", "searchsploit_intel", "nmap_discovery",
})

# Deterministic local analyzers: no external dependency, operate on real
# workspace data, and execute live wherever that data exists.
_LOCAL_LIVE_CAPS = frozenset({
    "http_probe", "graphql_probe", "authz_compare", "jwt_analyze",
    "identity_compare", "param_fuzz", "endpoint_validate", "js_analyze",
})

# Local-live capabilities that still require the httpx runtime library.
_HTTPX_DEPENDENT_CAPS = frozenset({"http_probe", "graphql_probe", "authz_compare"})


@dataclass
class Capability:
    capability_id: str
    name: str
    category: CapabilityCategory
    supported_target_types: list[str] = field(default_factory=list)
    required_inputs: list[str] = field(default_factory=list)
    produced_evidence_types: list[str] = field(default_factory=list)
    safety: SafetyClass = SafetyClass.LOW
    execute_fn: Optional[Callable[..., CapabilityResult]] = None
    availability_check: Optional[Callable[[Any], bool]] = None
    timeout: int = 300
    provenance: str = ""
    module_path: str = ""
    description: str = ""

    @property
    def name_alias(self) -> str:  # compatibility with legacy ToolSpec.name
        return self.capability_id


_SYNTHETIC_SUFFIXES = (".local", ".test", ".example", "example.", "synthetic")


def is_synthetic_target(target: str) -> bool:
    t = (target or "").lower()
    return (
        not t
        or t in {"localhost", "127.0.0.1", "::1"}
        or t.endswith(_SYNTHETIC_SUFFIXES)
        or t.startswith("synthetic")
        or t.startswith("minimal-app")
        or t.startswith("192.0.2.")
        or t.startswith("198.51.100.")
        or t.startswith("203.0.113.")
    )


_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


def _target_host(target: str) -> str:
    text = (target or "").strip().lower()
    if "://" in text:
        try:
            from urllib.parse import urlparse
            return (urlparse(text).hostname or "").lower()
        except Exception:
            return text
    return text.split(":")[0].split("/")[0]


def _live_local_enabled(ctx: dict | None = None) -> bool:
    """Explicit opt-in for live execution against loopback (local validation).

    Default off, so automated tests can never touch the network. Enabled via
    ``ctx["live_local"]`` (registry ``live_local=True``) or the
    ``HORCRUX_LIVE_LOCAL=1`` environment variable for operator-run checks.
    """
    if ctx and ctx.get("live_local"):
        return True
    return os.environ.get("HORCRUX_LIVE_LOCAL") == "1"


def _use_offline(target: str, ctx: dict | None = None) -> bool:
    """True when the adapter must take the offline synthesis branch.

    Non-synthetic targets always execute live. Synthetic fixtures always
    synthesize. Loopback synthesizes too — unless live-local execution was
    explicitly opted in (local validation only).
    """
    if not is_synthetic_target(target):
        return False
    if _target_host(target) in _LOOPBACK_HOSTS and _live_local_enabled(ctx):
        return False
    return True


class _EnvProbe:
    """Display-only PATH probe: answers 'does this tool exist' with no
    workspace, no runner, and no tool invocation."""

    @staticmethod
    def which(binary: str) -> str | None:
        try:
            return shutil.which(binary)
        except Exception:
            return None


def _playwright_probe() -> dict[str, Any]:
    """Real browser dependency check (import + executable + adapter init).

    Never launches a browser; safe for status rendering.
    """
    try:
        __import__("playwright")
    except ImportError:
        return {"ok": False, "reason": "playwright package not installed",
                "chromium": None}
    chromium = None
    for candidate in ("chromium", "chromium-browser", "google-chrome",
                      "google-chrome-stable", "chrome", "msedge"):
        found = shutil.which(candidate)
        if found:
            chromium = found
            break
    if chromium is None:
        try:
            from pathlib import Path
            pw_dir = Path.home() / ".cache" / "ms-playwright"
            if pw_dir.is_dir():
                for child in sorted(pw_dir.iterdir()):
                    exe = child / "chrome-linux" / "chrome"
                    if exe.exists():
                        chromium = str(exe)
                        break
                    exe = child / "chrome-linux" / "headless_shell"
                    if exe.exists():
                        chromium = str(exe)
                        break
        except Exception:
            pass
    if chromium is None:
        return {"ok": False, "reason": "no supported browser executable found",
                "chromium": None}
    try:
        from horcrux.intel.browser import PlaywrightBrowserAdapter
        PlaywrightBrowserAdapter()  # init must not raise; no launch here
    except Exception as exc:
        return {"ok": False, "reason": f"adapter init failed: {exc}",
                "chromium": chromium}
    return {"ok": True, "reason": "Playwright + browser executable available",
            "chromium": chromium}


def _playwright_availability() -> Callable[[Any], bool]:
    """Availability check for browser automation (dependency, not shell binary)."""
    def _check(runner: Any) -> bool:
        return _playwright_probe()["ok"]
    _check._binary = "playwright"  # type: ignore[attr-defined]
    _check._kind = "python"  # type: ignore[attr-defined]
    return _check


def _runner_available(runner: Any, binary: str) -> bool:
    try:
        if runner is None:
            return False
        which = getattr(runner, "which", None)
        if callable(which):
            return bool(which(binary))
    except Exception:
        return False
    return False


def _ok(cap_id: str, structured: dict, evidence: list[dict] | None = None,
        provenance: str = "", duration_ms: int = 0, tool: str = "") -> CapabilityResult:
    return CapabilityResult(
        capability_id=cap_id, success=True, failure=FailureClass.SUCCESS,
        structured_data=structured, evidence=evidence or [],
        provenance=provenance or cap_id, duration_ms=duration_ms, tool=tool or cap_id,
    )


def _fail(cap_id: str, failure: FailureClass, stderr: str,
          structured: dict | None = None) -> CapabilityResult:
    return CapabilityResult(
        capability_id=cap_id, success=False, failure=failure, stderr=stderr,
        structured_data=structured or {}, tool=cap_id,
    )


def _ev(evidence_type: str, data: dict, source: str, confidence: float = 0.8) -> dict:
    return {
        "evidence_type": evidence_type,
        "data": data,
        "source": source,
        "confidence": confidence,
    }


# ---------------------------------------------------------------------------
# Adapters — each reuses an existing HORCRUX module; synthetic targets are
# handled deterministically without network.
# ---------------------------------------------------------------------------

def _adapter_http_probe(ctx: dict) -> CapabilityResult:
    """Existing capability: horcrux.modules.web.scanner.scan_http (single probe)."""
    t0 = time.monotonic()
    target = ctx.get("target", "")
    path = ctx.get("path", ctx.get("endpoint", "/"))
    method = ctx.get("method", "GET").upper()
    identity = ctx.get("identity", "anonymous")
    app = ctx.get("application_model")
    if not path.startswith("/"):
        path = "/" + path
    # Deterministic offline synthesis from semantic model.
    known = None
    privileged = "admin" in path.lower() or "management" in path.lower()
    object_bearing = bool(re.search(r"/\d+|/\{", path))
    if app is not None:
        for e in getattr(app, "endpoints", []):
            if e.path == path or e.path.replace("{id}", "1") == path.replace("{id}", "1"):
                known = e
                break
    if _use_offline(target, ctx):
        if identity == "anonymous" and (privileged or (known and known.authentication == "required")):
            status = 401
        elif identity == "anonymous" and object_bearing:
            status = 200  # anonymously reachable object -> interesting
        else:
            status = 200
        ms = int((time.monotonic() - t0) * 1000)
        return _ok("http_probe", {
            "method": method, "path": path, "identity": identity,
            "status_code": status, "authorization_enforced": status in (401, 403),
            "privileged": privileged, "object_bearing": object_bearing,
            "synthetic": True,
        }, evidence=[_ev("endpoint_observation", {
            "method": method, "path": path, "identity": identity,
            "status_code": status,
        }, source="http_probe", confidence=0.9)], provenance="horcrux.modules.web.scanner:synthetic",
            duration_ms=ms)
    # Real path: single httpx GET via existing scanner primitives (bounded).
    try:
        import httpx  # local import; already a dependency
        runner = ctx.get("runner")
        port = int(ctx.get("port", 443 if str(ctx.get("scheme", "http")) == "https" else 80))
        scheme = ctx.get("scheme", "https" if port in (443, 8443) else "http")
        url = f"{scheme}://{target}:{port}{path}"
        timeout = min(int(ctx.get("timeout", 10)), 15)
        if runner is not None:
            try:
                runner.run(["httpx", "-u", url, "-silent"], f"http-probe-{port}", timeout=timeout)
            except Exception:
                pass
        with httpx.Client(verify=False, timeout=float(timeout),
                          headers={"User-Agent": "Horcrux/1.0"}) as client:
            resp = client.request(method, url, timeout=float(timeout))
            ms = int((time.monotonic() - t0) * 1000)
            return _ok("http_probe", {
                "method": method, "path": path, "url": url, "identity": identity,
                "status_code": resp.status_code,
                "authorization_enforced": resp.status_code in (401, 403),
                "content_length": len(resp.content),
            }, evidence=[_ev("endpoint_observation", {
                "method": method, "path": path, "url": url,
                "status_code": resp.status_code,
            }, source="http_probe", confidence=0.95)],
                provenance="horcrux.modules.web.scanner:httpx", duration_ms=ms)
    except Exception as exc:
        return _fail("http_probe", FailureClass.TOOL_FAILED, f"http_probe failed: {exc}")


def _adapter_js_analyze(ctx: dict) -> CapabilityResult:
    """Existing capability: horcrux.modules.web.js_analyzer.analyze_javascript_content."""
    from horcrux.modules.web.js_analyzer import analyze_javascript_content
    t0 = time.monotonic()
    js_text = ctx.get("js_text", "") or ""
    base_url = ctx.get("base_url", "")
    # If raw JS supplied, parse with the real parser.
    if js_text:
        parsed = analyze_javascript_content(js_text, source_name=ctx.get("source", "operator"))
        ms = int((time.monotonic() - t0) * 1000)
        ev = [_ev("route_discovery", {"path": r}, source="js_analyzer", confidence=0.85)
              for r in parsed.get("routes", [])]
        ev += [_ev("parameter_observation", p, source="js_analyzer", confidence=0.75)
               for p in parsed.get("parameters", [])]
        return _ok("js_analyze", {
            "base_url": base_url, "routes": parsed.get("routes", []),
            "parameters": parsed.get("parameters", []),
        }, evidence=ev, provenance="horcrux.modules.web.js_analyzer:content",
            duration_ms=ms)
    # Otherwise derive routes/params from the ApplicationModel (offline-safe).
    app = ctx.get("application_model")
    routes: list[str] = []
    params: list[dict] = []
    if app is not None:
        routes = [e.path for e in getattr(app, "endpoints", [])
                  if "javascript" in (e.sources or []) or e.path.startswith(("/rest", "/api"))]
        for p in getattr(app, "parameters", [])[:20]:
            params.append({"name": p.name, "endpoint": p.endpoint, "location": p.location})
    ms = int((time.monotonic() - t0) * 1000)
    return _ok("js_analyze", {"base_url": base_url, "routes": routes, "parameters": params},
               evidence=[_ev("route_discovery", {"path": r}, source="js_analyzer")
                         for r in routes[:20]],
               provenance="horcrux.modules.web.js_analyzer:model", duration_ms=ms)


def _adapter_content_discovery(ctx: dict) -> CapabilityResult:
    """Existing capability: horcrux.modules.web.fuzzer (ffuf/gobuster/ferox/native)."""
    t0 = time.monotonic()
    runner = ctx.get("runner")
    workspace = ctx.get("workspace")
    target = ctx.get("target", "")
    port = int(ctx.get("port", 80))
    # Prefer the real fuzzer only for non-synthetic targets with a runner.
    if workspace is not None and runner is not None and not _use_offline(target, ctx):
        try:
            from horcrux.modules.web.fuzzer import run_fuzzer
            paths = run_fuzzer(workspace, runner, target, port,
                               strategy=ctx.get("strategy", "common"))
            ms = int((time.monotonic() - t0) * 1000)
            return _ok("content_discovery",
                       {"port": port, "paths": [p.path for p in paths],
                        "statuses": {p.path: p.status for p in paths}},
                       evidence=[_ev("route_discovery", {"path": p.path, "status": p.status},
                                     source=p.source or "fuzzer") for p in paths[:30]],
                       provenance="horcrux.modules.web.fuzzer", duration_ms=ms)
        except Exception as exc:
            return _fail("content_discovery", FailureClass.TOOL_FAILED, str(exc))
    # Offline: enumerate candidate wordlist paths against the model (no network).
    app = ctx.get("application_model")
    known_paths = {e.path for e in getattr(app, [])} if isinstance(app, list) else set()
    if app is not None and not isinstance(app, list):
        known_paths = {e.path for e in getattr(app, "endpoints", [])}
    candidates = ctx.get("wordlist", []) or ["admin", "login", "api", "graphql", "upload", ".env"]
    found = [c if c.startswith("/") else "/" + c for c in candidates if (c if c.startswith("/") else "/" + c) in known_paths]
    ms = int((time.monotonic() - t0) * 1000)
    tool = "none"
    if runner is not None:
        for binary in ("ffuf", "gobuster", "feroxbuster"):
            if _runner_available(runner, binary):
                tool = binary
                break
    return _ok("content_discovery", {
        "port": port, "paths": sorted(found), "tool": tool, "synthetic": True,
    }, evidence=[_ev("route_discovery", {"path": p}, source="content_discovery")
                 for p in sorted(found)],
        provenance="horcrux.modules.web.fuzzer:offline", duration_ms=ms)


def _adapter_endpoint_validate(ctx: dict) -> CapabilityResult:
    """Existing capability: horcrux.modules.web.validator (pluggable validators)."""
    from horcrux.modules.web.validator import BaselineFingerprint, validate_generic_candidate
    t0 = time.monotonic()
    path = ctx.get("path", "/")
    status = int(ctx.get("status_code", 200))
    body = ctx.get("body", f"synthetic body for {path}")
    headers = ctx.get("headers", {"content-type": "text/html"})

    class _Resp:
        def __init__(self, status_code: int, text: str, headers: dict):
            self.status_code = status_code
            self.text = text
            self.headers = headers

    baseline = BaselineFingerprint(status_code=404, content_length=128,
                                   content_type="text/html", title="Not Found",
                                   body_hash="baseline")
    try:
        res = validate_generic_candidate(path, _Resp(status, body, headers), baseline)
        ms = int((time.monotonic() - t0) * 1000)
        failure = FailureClass.SUCCESS if res.is_valid else FailureClass.INSUFFICIENT_EVIDENCE
        out = CapabilityResult(
            capability_id="endpoint_validate", success=True, failure=failure,
            structured_data={"path": path, "is_valid": res.is_valid,
                             "validation_state": res.validation_state.value,
                             "confidence": res.confidence, "evidence": res.evidence},
            evidence=[_ev("validation_result", {"path": path, "state": res.validation_state.value},
                          source="validator", confidence=res.confidence)],
            provenance="horcrux.modules.web.validator", duration_ms=ms,
            tool="validator")
        return out
    except Exception as exc:
        return _fail("endpoint_validate", FailureClass.TOOL_FAILED, str(exc))


def _adapter_fingerprint(ctx: dict) -> CapabilityResult:
    """Existing capability: horcrux.modules.web.fingerprint + tech_normalizer."""
    t0 = time.monotonic()
    runner = ctx.get("runner")
    workspace = ctx.get("workspace")
    target = ctx.get("target", "")
    port = int(ctx.get("port", 80))
    if workspace is not None and runner is not None and not _use_offline(target, ctx):
        try:
            from horcrux.modules.web.fingerprint import run_fingerprinting
            techs, _sw = run_fingerprinting(workspace, runner, target, port)
            ms = int((time.monotonic() - t0) * 1000)
            return _ok("web_fingerprint", {"technologies": techs},
                       evidence=[_ev("technology_observation", {"name": t}, source="fingerprint")
                                 for t in techs],
                       provenance="horcrux.modules.web.fingerprint", duration_ms=ms)
        except Exception as exc:
            return _fail("web_fingerprint", FailureClass.TOOL_FAILED, str(exc))
    # Offline: read normalized technologies from state/model.
    techs: list[str] = []
    state = ctx.get("state")
    if state is not None:
        try:
            techs = [t.name for t in getattr(state, "normalized_technologies", [])]
        except Exception:
            techs = list(getattr(state, "technologies", []) or [])
    app = ctx.get("application_model")
    if not techs and app is not None:
        techs = [t.name for t in getattr(app, "technologies", [])]
    ms = int((time.monotonic() - t0) * 1000)
    return _ok("web_fingerprint", {"technologies": techs, "synthetic": True},
               evidence=[_ev("technology_observation", {"name": t}, source="fingerprint")
                         for t in techs],
               provenance="horcrux.modules.web.fingerprint:offline", duration_ms=ms)


def _adapter_nuclei(ctx: dict) -> CapabilityResult:
    """Existing capability: horcrux.core.intel.run_nuclei."""
    runner = ctx.get("runner")
    workspace = ctx.get("workspace")
    url = ctx.get("url", ctx.get("base_url", ""))
    if workspace is not None and runner is not None and url and not _use_offline(ctx.get("target", ""), ctx):
        if not _runner_available(runner, "nuclei"):
            return _fail("nuclei_scan", FailureClass.UNAVAILABLE, "nuclei binary not installed")
        try:
            from horcrux.core.intel import run_nuclei
            findings = run_nuclei(workspace, runner, url)
            return _ok("nuclei_scan", {"url": url, "findings": len(findings or [])},
                       evidence=[_ev("nuclei_finding", {"title": f.title}, source="nuclei")
                                 for f in (findings or [])[:20]],
                       provenance="horcrux.core.intel:run_nuclei")
        except Exception as exc:
            return _fail("nuclei_scan", FailureClass.TOOL_FAILED, str(exc))
    # Offline: surface nuclei-relevant hints from model (no live scan).
    app = ctx.get("application_model")
    hints: list[str] = []
    if app is not None:
        for e in getattr(app, "endpoints", []):
            if any(k in e.path for k in (".env", ".git", "phpinfo", "actuator", "swagger")):
                hints.append(e.path)
    return _ok("nuclei_scan", {"url": url, "synthetic": True, "hints": hints},
               evidence=[_ev("nuclei_finding", {"path": h}, source="nuclei", confidence=0.5)
                         for h in hints],
               provenance="horcrux.core.intel:offline")


def _adapter_nikto(ctx: dict) -> CapabilityResult:
    runner = ctx.get("runner")
    workspace = ctx.get("workspace")
    target = ctx.get("target", "")
    port = int(ctx.get("port", 80))
    if workspace is not None and runner is not None and not _use_offline(target, ctx):
        if not _runner_available(runner, "nikto"):
            return _fail("nikto_audit", FailureClass.UNAVAILABLE, "nikto binary not installed")
        try:
            from horcrux.modules.web.nikto import run_nikto
            findings, _audits = run_nikto(workspace, runner, target, port)
            return _ok("nikto_audit", {"findings": len(findings or [])},
                       evidence=[_ev("nikto_observation", {"title": f.title}, source="nikto")
                                 for f in (findings or [])[:20]],
                       provenance="horcrux.modules.web.nikto")
        except Exception as exc:
            return _fail("nikto_audit", FailureClass.TOOL_FAILED, str(exc))
    return _ok("nikto_audit", {"synthetic": True, "findings": 0},
               evidence=[], provenance="horcrux.modules.web.nikto:offline")


def _adapter_graphql_probe(ctx: dict) -> CapabilityResult:
    """Existing validators: validate_graphql_content + introspection reasoning."""
    target = ctx.get("target", "")
    path = ctx.get("path", "/graphql")
    app = ctx.get("application_model")
    has_graphql = any("graphql" in e.path.lower() for e in getattr(app, "endpoints", [])) if app else False
    if _use_offline(target, ctx):
        introspection = has_graphql and bool(ctx.get("assume_introspection", has_graphql))
        return _ok("graphql_probe", {
            "path": path, "graphql_present": has_graphql,
            "introspection": introspection, "synthetic": True,
        }, evidence=[_ev("graphql_observation", {"path": path, "introspection": introspection},
                          source="graphql_probe", confidence=0.7)] if has_graphql else [],
            provenance="horcrux.modules.web.validator:graphql")
    # Real (bounded): single POST introspection probe.
    try:
        import httpx
        port = int(ctx.get("port", 80))
        scheme = ctx.get("scheme", "http")
        url = f"{scheme}://{target}:{port}{path}"
        query = {"query": "{__typename}"}
        with httpx.Client(verify=False, timeout=8.0) as client:
            resp = client.post(url, json=query)
            is_gql = resp.status_code in (200, 400) and ("graphql" in resp.text.lower() or "__typename" in resp.text)
            return _ok("graphql_probe", {"path": path, "url": url, "graphql_present": is_gql,
                                         "status_code": resp.status_code},
                       evidence=[_ev("graphql_observation", {"path": path}, source="graphql_probe")]
                       if is_gql else [],
                       provenance="horcrux.modules.web.validator:graphql-live")
    except Exception as exc:
        return _fail("graphql_probe", FailureClass.TOOL_FAILED, str(exc))


def _adapter_param_fuzz(ctx: dict) -> CapabilityResult:
    params = ctx.get("parameters", ctx.get("params", [])) or []
    endpoint = ctx.get("endpoint", ctx.get("path", "/"))
    interesting = [p for p in params if str(p).lower() in
                   {"q", "query", "search", "filter", "sort", "id", "name", "email",
                    "url", "target", "callback", "redirect", "fetch", "file", "path"}]
    return _ok("param_fuzz", {"endpoint": endpoint, "tested": params,
                              "interesting": interesting, "synthetic": True},
               evidence=[_ev("parameter_observation", {"endpoint": endpoint, "parameter": p},
                             source="param_fuzz", confidence=0.6) for p in interesting],
               provenance="horcrux.modules.web.scanner:param")


def _adapter_jwt_analyze(ctx: dict) -> CapabilityResult:
    token = ctx.get("token", "") or ""
    parts = token.split(".")
    findings: dict[str, Any] = {"token_present": bool(token)}
    if len(parts) == 3:
        try:
            padded = parts[0] + "=" * (-len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8", errors="replace"))
            findings.update({"alg": header.get("alg", ""), "typ": header.get("typ", ""),
                             "none_alg": header.get("alg", "") == "none",
                             "header": header})
        except Exception as exc:
            return _fail("jwt_analyze", FailureClass.TOOL_FAILED, f"JWT decode failed: {exc}")
    else:
        # Model-driven: report auth mechanism facts.
        app = ctx.get("application_model")
        mechs = [a.mechanism_type for a in getattr(app, "authentication", [])] if app else []
        findings.update({"mechanisms": mechs, "synthetic": True})
    conf = 0.8 if findings.get("none_alg") else 0.6
    return _ok("jwt_analyze", findings,
               evidence=[_ev("auth_observation", findings, source="jwt_analyze", confidence=conf)]
               if findings.get("token_present") or findings.get("mechanisms") else [],
               provenance="horcrux.intel.tasks:jwt")


def _adapter_identity_switch(ctx: dict) -> CapabilityResult:
    frm = ctx.get("from_identity", "anonymous")
    to = ctx.get("to_identity", "user")
    creds = ctx.get("credentials_available", True)
    if to != "anonymous" and not creds:
        return _fail("identity_switch", FailureClass.APPROVAL_REQUIRED,
                     f"Switch to '{to}' requires operator-supplied credentials/session")
    return _ok("identity_switch", {"from_identity": frm, "to_identity": to,
                                   "session_established": True, "synthetic": True},
               evidence=[_ev("identity_context", {"from": frm, "to": to}, source="identity_switch")],
               provenance="horcrux.intel.browser_session")


def _adapter_authz_compare(ctx: dict) -> CapabilityResult:
    """Cross-identity object-access comparison (deterministic, non-destructive)."""
    endpoint = ctx.get("endpoint", ctx.get("path", "/"))
    code_a = ctx.get("status_anonymous", ctx.get("status_a"))
    code_b = ctx.get("status_user", ctx.get("status_b"))
    if code_a is None or code_b is None:
        # Derive from http_probe-style synthesis when explicit codes absent.
        r_anon = _adapter_http_probe({**ctx, "identity": "anonymous", "path": endpoint})
        r_user = _adapter_http_probe({**ctx, "identity": "user", "path": endpoint})
        code_a = r_anon.structured_data.get("status_code")
        code_b = r_user.structured_data.get("status_code")
    enforced = (code_a in (401, 403)) and (code_b == 200)
    gap = (code_a == 200) or (code_b == 200 and code_a == 200)
    return _ok("authz_compare", {"endpoint": endpoint, "status_anonymous": code_a,
                                 "status_user": code_b, "authorization_enforced": enforced,
                                 "potential_gap": gap, "synthetic": True},
               evidence=[_ev("authorization_observation", {
                   "endpoint": endpoint, "anonymous": code_a, "user": code_b,
                   "enforced": enforced}, source="authz_compare", confidence=0.75)],
               provenance="horcrux.agents.specialists:authz")


def _make_service_adapter(module_name: str, fn_name: str, cap_id: str,
                           evidence_type: str):
    def _fn(ctx: dict) -> CapabilityResult:
        runner = ctx.get("runner")
        workspace = ctx.get("workspace")
        target = ctx.get("target", "")
        port = int(ctx.get("port", 0))
        if workspace is not None and runner is not None and not _use_offline(target, ctx):
            try:
                mod = __import__(f"horcrux.modules.services.{module_name}",
                                 fromlist=[fn_name])
                fn = getattr(mod, fn_name)
                import inspect
                kwargs: dict[str, Any] = {}
                try:
                    sig = inspect.signature(fn)
                    if "port" in sig.parameters:
                        kwargs["port"] = port
                    if "service" in sig.parameters:
                        kwargs["service"] = ctx.get("service", "")
                except Exception:
                    kwargs = {"port": port}
                out = fn(workspace, runner, target, **kwargs)
                findings = out[0] if isinstance(out, tuple) else (out or [])
                return _ok(cap_id, {"port": port, "findings": len(findings or [])},
                           evidence=[_ev(evidence_type, {"title": f.title}, source=cap_id)
                                     for f in (findings or [])[:20]],
                           provenance=f"horcrux.modules.services.{module_name}:{fn_name}")
            except Exception as exc:
                return _fail(cap_id, FailureClass.TOOL_FAILED, str(exc))
        # Offline: synthesize protocol facts from service inventory.
        state = ctx.get("state")
        facts: list[dict] = []
        if state is not None:
            for s in getattr(state, "services", []):
                if port and s.port != port:
                    continue
                facts.append({"port": s.port, "service": s.service,
                              "product": s.product, "version": s.version})
        return _ok(cap_id, {"port": port, "synthetic": True, "services": facts},
                   evidence=[_ev(evidence_type, f, source=cap_id, confidence=0.7)
                             for f in facts[:10]],
                   provenance=f"horcrux.modules.services.{module_name}:offline")
    _fn.__name__ = f"adapter_{cap_id}"
    return _fn


def _adapter_searchsploit(ctx: dict) -> CapabilityResult:
    runner = ctx.get("runner")
    workspace = ctx.get("workspace")
    if workspace is not None and runner is not None and _runner_available(runner, "searchsploit"):
        try:
            from horcrux.intel.search import searchsploit_workspace
            cands = searchsploit_workspace(workspace, runner)
            return _ok("searchsploit_intel", {"candidates": len(cands or [])},
                       evidence=[_ev("exploit_intelligence",
                                     {"title": c.title, "cve": c.cve}, source="searchsploit",
                                     confidence=c.confidence) for c in (cands or [])[:15]],
                       provenance="horcrux.intel.search")
        except Exception as exc:
            return _fail("searchsploit_intel", FailureClass.TOOL_FAILED, str(exc))
    # Offline: evaluate relevance heuristically from software inventory.
    state = ctx.get("state")
    cands: list[dict] = []
    if state is not None:
        try:
            from horcrux.intel.search import is_reliable_software_evidence
            for sw in getattr(state, "software", [])[:10]:
                if is_reliable_software_evidence(sw):
                    cands.append({"product": sw.product, "version": sw.version})
        except Exception:
            pass
    return _ok("searchsploit_intel", {"synthetic": True, "reliable_software": cands},
               evidence=[_ev("exploit_intelligence", c, source="searchsploit", confidence=0.5)
                         for c in cands],
               provenance="horcrux.intel.search:offline")


def _adapter_browser_navigate(ctx: dict) -> CapabilityResult:
    """Pluggable browser boundary — stub records session evidence into the model."""
    try:
        from horcrux.intel.browser_session import record_browser_navigation
        out = record_browser_navigation(ctx)
        return _ok("browser_navigate", out,
                   evidence=out.get("evidence", []),
                   provenance="horcrux.intel.browser_session:stub")
    except Exception as exc:
        return _fail("browser_navigate", FailureClass.TOOL_FAILED, str(exc))


def _adapter_browser_automate(ctx: dict) -> CapabilityResult:
    """Real browser automation via replaceable BrowserAdapter (Part 1).

    ``script`` is a list of steps: navigate/click/fill/submit/select/wait.
    ``pages`` (scripted backend) or a live Playwright backend may be used.
    All observations converge into the ApplicationModel; scope is enforced
    per navigation.
    """
    t0 = time.monotonic()
    target = ctx.get("target", "")
    base_url = ctx.get("base_url", f"http://{target}")
    script = ctx.get("script", []) or [{"op": "navigate", "url": ctx.get("url", base_url)}]
    identity = ctx.get("identity", "anonymous")
    try:
        from horcrux.intel.browser import get_browser_adapter
        from horcrux.intel.browser_session import record_browser_session
    except Exception as exc:
        return _fail("browser_automate", FailureClass.UNAVAILABLE, str(exc))
    scope_check = None
    state = ctx.get("state")
    if state is not None:
        try:
            policy = state.get_policy()
            scope_check = lambda u: _url_in_scope(policy, u)  # noqa: E731
        except Exception:
            scope_check = None
    backend = ctx.get("backend", "auto")
    if _use_offline(target, ctx) and backend == "auto":
        backend = "scripted"
    try:
        adapter = get_browser_adapter(backend, pages=ctx.get("pages"),
                                      scope_check=scope_check)
    except Exception as exc:
        return _fail("browser_automate", FailureClass.TOOL_FAILED, str(exc))
    ok, reason = adapter.is_available()
    if not ok and backend == "playwright":
        return _fail("browser_automate", FailureClass.UNAVAILABLE, reason)
    observations: list[dict] = []
    errors: list[str] = []
    app = ctx.get("application_model")
    try:
        launched = adapter.launch()
        if not launched.get("launched"):
            return _fail("browser_automate", FailureClass.UNAVAILABLE,
                         str(launched.get("reason", "launch failed")))
        adapter.create_context(identity=identity)
        for step in script[:25]:
            op = str(step.get("op", "navigate")).lower()
            try:
                if op == "navigate":
                    obs = adapter.navigate(step.get("url", base_url))
                elif op == "click":
                    obs = adapter.click(step.get("selector", ""))
                elif op == "fill":
                    obs = adapter.fill(step.get("selector", ""), "***")
                elif op == "submit":
                    obs = adapter.submit(step.get("selector", ""))
                elif op == "select":
                    obs = adapter.select(step.get("selector", ""), step.get("value", ""))
                elif op == "wait":
                    adapter.wait(int(step.get("ms", 500)))
                    continue
                elif op == "reload":
                    obs = adapter.reload()
                else:
                    errors.append(f"unknown op: {op}")
                    continue
                obs.identity = identity
                if app is not None:
                    out = record_browser_session(obs, app, identity=identity)
                    observations.extend(out.get("evidence", []))
            except PermissionError as exc:
                return _fail("browser_automate", FailureClass.SCOPE_BLOCKED, str(exc))
            except Exception as exc:
                errors.append(f"{op}: {exc}")
    finally:
        try:
            adapter.close()
        except Exception:
            pass
    ms = int((time.monotonic() - t0) * 1000)
    if not observations and errors:
        return _fail("browser_automate", FailureClass.TOOL_FAILED, "; ".join(errors[:3]))
    return _ok("browser_automate", {"steps": len(script), "evidence_items": len(observations),
                                    "errors": errors[:5], "synthetic": backend == "scripted"},
               evidence=observations,
               provenance=f"horcrux.intel.browser:{backend}", duration_ms=ms)


def _url_in_scope(policy: Any, url: str) -> bool:
    from urllib.parse import urlparse
    try:
        host = urlparse(url).hostname or ""
    except Exception:
        return False
    try:
        ok, _ = policy.is_target_allowed(host)
        return ok
    except Exception:
        return True


def _adapter_identity_compare(ctx: dict) -> CapabilityResult:
    """Multi-identity comparison primitive (Part 12)."""
    t0 = time.monotonic()
    state = ctx.get("state")
    label_a = ctx.get("identity_a", ctx.get("from_identity", "anonymous"))
    label_b = ctx.get("identity_b", ctx.get("to_identity", "user"))
    if state is None:
        return _fail("identity_compare", FailureClass.INSUFFICIENT_EVIDENCE,
                     "no workspace state for comparison")
    try:
        from horcrux.intel.sessions import compare_identities
        out = compare_identities(state, label_a, label_b,
                                 endpoint_filter=ctx.get("endpoint_filter", ""))
        ms = int((time.monotonic() - t0) * 1000)
        ev = [_ev("comparison", {"verdict": out["verdict"], "detail": e},
                  source="identity_compare", confidence=0.75)
              for e in out.get("evidence", [])]
        failure = (FailureClass.SUCCESS if out["verdict"] in ("gap_suspected", "enforced")
                   else FailureClass.INSUFFICIENT_EVIDENCE)
        res = _ok("identity_compare", out, evidence=ev,
                  provenance="horcrux.intel.sessions:compare", duration_ms=ms)
        res.failure = failure
        return res
    except Exception as exc:
        return _fail("identity_compare", FailureClass.TOOL_FAILED, str(exc))


def _adapter_nmap(ctx: dict) -> CapabilityResult:
    runner = ctx.get("runner")
    workspace = ctx.get("workspace")
    target = ctx.get("target", "")
    if workspace is not None and runner is not None and not _use_offline(target, ctx):
        if not _runner_available(runner, "nmap"):
            return _fail("nmap_discovery", FailureClass.UNAVAILABLE, "nmap binary not installed")
        try:
            from horcrux.modules.network import run_network
            from horcrux.models import get_profile
            _svcs, _findings = run_network(workspace, runner, target,
                                           profile=get_profile("quick"))
            state = workspace.load()
            return _ok("nmap_discovery", {"services": len(state.services)},
                       evidence=[_ev("service_observation",
                                     {"port": s.port, "service": s.service}, source="nmap")
                                 for s in state.services[:25]],
                       provenance="horcrux.modules.network")
        except Exception as exc:
            return _fail("nmap_discovery", FailureClass.TOOL_FAILED, str(exc))
    state = ctx.get("state")
    svcs = [{"port": s.port, "service": s.service} for s in getattr(state, "services", [])] if state else []
    return _ok("nmap_discovery", {"synthetic": True, "services": svcs},
               evidence=[_ev("service_observation", s, source="nmap") for s in svcs],
               provenance="horcrux.modules.network:offline")


def _availability(binary: str) -> Callable[[Any], bool]:
    def _check(runner: Any) -> bool:
        # Offline-capable adapters are always "available" (synthesis path).
        return True
    _check._binary = binary  # type: ignore[attr-defined]
    return _check


def _binary_availability(binary: str) -> Callable[[Any], bool]:
    def _check(runner: Any) -> bool:
        return _runner_available(runner, binary)
    _check._binary = binary  # type: ignore[attr-defined]
    return _check


def build_production_capabilities() -> list[Capability]:
    """All production capabilities bound to existing HORCRUX modules."""
    return [
        Capability("nmap_discovery", "Network service discovery (Nmap)", CapabilityCategory.RECON,
                   ["host", "network"], ["target"], ["service_observation"],
                   SafetyClass.LOW, _adapter_nmap, _binary_availability("nmap"),
                   600, "horcrux.modules.network", "horcrux.modules.network",
                   "TCP service discovery via existing network module"),
        Capability("http_probe", "HTTP endpoint probe", CapabilityCategory.HTTP,
                   ["url", "endpoint"], ["target", "path"], ["endpoint_observation"],
                   SafetyClass.LOW, _adapter_http_probe, _availability("httpx"),
                   30, "horcrux.modules.web.scanner", "horcrux.modules.web.scanner",
                   "Single-endpoint HTTP probe with auth/identity context"),
        Capability("web_fingerprint", "Technology fingerprint (WhatWeb/httpx/wafw00f)",
                   CapabilityCategory.WEB, ["web_service"], ["target", "port"],
                   ["technology_observation"], SafetyClass.SAFE, _adapter_fingerprint,
                   _availability("whatweb"), 120, "horcrux.modules.web.fingerprint",
                   "horcrux.modules.web.fingerprint", "WhatWeb/httpx/wafw00f normalization"),
        Capability("content_discovery", "Content discovery (FFUF/Gobuster/Ferox/native)",
                   CapabilityCategory.WEB, ["web_service"], ["target", "port"],
                   ["route_discovery"], SafetyClass.MEDIUM, _adapter_content_discovery,
                   _availability("ffuf"), 600, "horcrux.modules.web.fuzzer",
                   "horcrux.modules.web.fuzzer", "Wordlist discovery with baseline suppression"),
        Capability("js_analyze", "JavaScript route/parameter analysis", CapabilityCategory.WEB,
                   ["web_service", "js_bundle"], ["base_url"], ["route_discovery", "parameter_observation"],
                   SafetyClass.SAFE, _adapter_js_analyze, _availability("none"),
                   120, "horcrux.modules.web.js_analyzer", "horcrux.modules.web.js_analyzer",
                   "Client-side route and parameter extraction"),
        Capability("endpoint_validate", "Endpoint validation (baseline-aware)", CapabilityCategory.VALIDATION,
                   ["url", "endpoint"], ["path"], ["validation_result"],
                   SafetyClass.LOW, _adapter_endpoint_validate, _availability("none"),
                   30, "horcrux.modules.web.validator", "horcrux.modules.web.validator",
                   "Baseline-aware content validation"),
        Capability("nuclei_scan", "Nuclei template scan", CapabilityCategory.VALIDATION,
                   ["web_service"], ["url"], ["nuclei_finding"],
                   SafetyClass.MEDIUM, _adapter_nuclei, _binary_availability("nuclei"),
                   1200, "horcrux.core.intel", "horcrux.core.intel",
                   "Targeted Nuclei templates (critical/high/medium/low)"),
        Capability("nikto_audit", "Nikto server audit", CapabilityCategory.VALIDATION,
                   ["web_service"], ["target", "port"], ["nikto_observation"],
                   SafetyClass.MEDIUM, _adapter_nikto, _binary_availability("nikto"),
                   600, "horcrux.modules.web.nikto", "horcrux.modules.web.nikto",
                   "Legacy CGI/misconfiguration audit"),
        Capability("graphql_probe", "GraphQL introspection probe", CapabilityCategory.HTTP,
                   ["graphql_endpoint"], ["target", "path"], ["graphql_observation"],
                   SafetyClass.LOW, _adapter_graphql_probe, _availability("httpx"),
                   30, "horcrux.modules.web.validator", "horcrux.modules.web.validator",
                   "GraphQL presence + introspection check"),
        Capability("param_fuzz", "Parameter surface analysis", CapabilityCategory.WEB,
                   ["endpoint"], ["endpoint", "parameters"], ["parameter_observation"],
                   SafetyClass.LOW, _adapter_param_fuzz, _availability("none"),
                   60, "horcrux.modules.web.scanner", "horcrux.modules.web.scanner",
                   "Input surface triage (SSRF/injection candidates)"),
        Capability("jwt_analyze", "JWT/session analysis", CapabilityCategory.VALIDATION,
                   ["auth_surface"], ["token"], ["auth_observation"],
                   SafetyClass.SAFE, _adapter_jwt_analyze, _availability("none"),
                   15, "horcrux.intel.tasks", "horcrux.intel.tasks",
                   "Local JWT structure validation"),
        Capability("identity_switch", "Identity/session switch", CapabilityCategory.HTTP,
                   ["auth_surface"], ["from_identity", "to_identity"], ["identity_context"],
                   SafetyClass.LOW, _adapter_identity_switch, _availability("none"),
                   15, "horcrux.intel.browser_session", "horcrux.intel.browser_session",
                   "Establish second identity context for comparison"),
        Capability("authz_compare", "Cross-identity authorization comparison", CapabilityCategory.VALIDATION,
                   ["object_endpoint"], ["endpoint"], ["authorization_observation"],
                   SafetyClass.LOW, _adapter_authz_compare, _availability("none"),
                   30, "horcrux.agents.specialists", "horcrux.agents.specialists",
                   "Deterministic anonymous-vs-user comparison (non-destructive)"),
        Capability("browser_navigate", "Browser navigation (pluggable)", CapabilityCategory.BROWSER,
                   ["web_service"], ["url"], ["browser_observation", "endpoint_observation"],
                   SafetyClass.MEDIUM, _adapter_browser_navigate, _availability("none"),
                   60, "horcrux.intel.browser_session", "horcrux.intel.browser_session",
                   "Pluggable browser adapter; stub records session evidence"),
        Capability("browser_automate", "Browser automation session (Playwright/scripted)",
                   CapabilityCategory.BROWSER,
                   ["web_service"], ["target"], ["endpoint_observation", "route_discovery",
                                                 "identity_context", "form_observation"],
                   SafetyClass.MEDIUM, _adapter_browser_automate, _playwright_availability(),
                   300, "horcrux.intel.browser", "horcrux.intel.browser",
                   "Replaceable Playwright/scripted automation; scope-gated"),
        Capability("identity_compare", "Multi-identity access comparison", CapabilityCategory.VALIDATION,
                   ["object_endpoint"], ["target"], ["comparison"],
                   SafetyClass.SAFE, _adapter_identity_compare, _availability("none"),
                   30, "horcrux.intel.sessions", "horcrux.intel.sessions",
                   "Cross-identity endpoint/object/response comparison primitive"),
        Capability("smb_enum", "SMB enumeration", CapabilityCategory.SERVICE,
                   ["smb_service"], ["target", "port"], ["service_observation", "smb_share"],
                   SafetyClass.LOW, _make_service_adapter("smb", "enumerate_smb", "smb_enum", "smb_share"),
                   _binary_availability("smbclient"), 180, "horcrux.modules.services.smb",
                   "horcrux.modules.services.smb", "Shares, null sessions, signing"),
        Capability("ldap_enum", "LDAP enumeration", CapabilityCategory.SERVICE,
                   ["ldap_service"], ["target", "port"], ["service_observation", "directory_fact"],
                   SafetyClass.LOW, _make_service_adapter("ldap", "enumerate_ldap", "ldap_enum", "directory_fact"),
                   _binary_availability("ldapsearch"), 90, "horcrux.modules.services.ldap",
                   "horcrux.modules.services.ldap", "RootDSE + naming contexts"),
        Capability("kerberos_enum", "Kerberos enumeration", CapabilityCategory.SERVICE,
                   ["kerberos_service"], ["target", "port"], ["service_observation", "identity_observation"],
                   SafetyClass.LOW, _make_service_adapter("kerberos", "enumerate_kerberos", "kerberos_enum", "identity_observation"),
                   _binary_availability("nmap"), 90, "horcrux.modules.services.kerberos",
                   "horcrux.modules.services.kerberos", "KDC presence + principals"),
        Capability("ssh_enum", "SSH enumeration", CapabilityCategory.SERVICE,
                   ["ssh_service"], ["target", "port"], ["service_observation", "auth_observation"],
                   SafetyClass.LOW, _make_service_adapter("ssh", "enumerate_ssh", "ssh_enum", "auth_observation"),
                   _availability("ssh"), 60, "horcrux.modules.services.ssh",
                   "horcrux.modules.services.ssh", "Banner + auth methods"),
        Capability("ftp_enum", "FTP enumeration", CapabilityCategory.SERVICE,
                   ["ftp_service"], ["target", "port"], ["service_observation", "auth_observation"],
                   SafetyClass.LOW, _make_service_adapter("ftp", "enumerate_ftp", "ftp_enum", "auth_observation"),
                   _availability("none"), 60, "horcrux.modules.services.ftp",
                   "horcrux.modules.services.ftp", "Banner + anonymous access"),
        Capability("smtp_enum", "SMTP enumeration", CapabilityCategory.SERVICE,
                   ["smtp_service"], ["target", "port"], ["service_observation", "mail_capability"],
                   SafetyClass.LOW, _make_service_adapter("smtp", "enumerate_smtp", "smtp_enum", "mail_capability"),
                   _availability("none"), 60, "horcrux.modules.services.smtp",
                   "horcrux.modules.services.smtp", "Banner + EHLO caps + relay"),
        Capability("dns_enum", "DNS enumeration", CapabilityCategory.SERVICE,
                   ["dns_service"], ["target", "port"], ["service_observation", "dns_record"],
                   SafetyClass.SAFE, _make_service_adapter("dns", "enumerate_dns", "dns_enum", "dns_record"),
                   _binary_availability("dig"), 60, "horcrux.modules.services.dns",
                   "horcrux.modules.services.dns", "Records + AXFR test"),
        Capability("snmp_enum", "SNMP enumeration", CapabilityCategory.SERVICE,
                   ["snmp_service"], ["target", "port"], ["service_observation", "snmp_fact"],
                   SafetyClass.LOW, _make_service_adapter("snmp", "enumerate_snmp", "snmp_enum", "snmp_fact"),
                   _binary_availability("snmpwalk"), 60, "horcrux.modules.services.snmp",
                   "horcrux.modules.services.snmp", "Community + MIB inspection"),
        Capability("database_enum", "Database enumeration", CapabilityCategory.SERVICE,
                   ["db_service"], ["target", "port"], ["service_observation", "auth_observation"],
                   SafetyClass.LOW, _make_service_adapter("databases", "enumerate_databases", "database_enum", "auth_observation"),
                   _availability("none"), 120, "horcrux.modules.services.databases",
                   "horcrux.modules.services.databases", "Redis/MySQL/Postgres auth audit"),
        Capability("remote_enum", "Remote-service enumeration (RDP/WinRM/NFS/VNC)", CapabilityCategory.SERVICE,
                   ["remote_service"], ["target", "port"], ["service_observation"],
                   SafetyClass.LOW, _make_service_adapter("remote", "enumerate_remote_services", "remote_enum", "service_observation"),
                   _availability("showmount"), 120, "horcrux.modules.services.remote",
                   "horcrux.modules.services.remote", "RDP/WinRM/NFS/VNC surface"),
        Capability("searchsploit_intel", "Exploit intelligence (SearchSploit)", CapabilityCategory.INTELLIGENCE,
                   ["software"], ["product"], ["exploit_intelligence"],
                   SafetyClass.SAFE, _adapter_searchsploit, _binary_availability("searchsploit"),
                   180, "horcrux.intel.search", "horcrux.intel.search",
                   "CVE/exploit correlation (evidence-gated)"),
    ]


class CapabilityRegistry:
    """Central execution boundary. Specialists must execute through here."""

    # Destructive/final-exploitation markers — never auto-executed (Part 26).
    DESTRUCTIVE_MARKERS = ("exploit", "payload-exec", "reverse-shell", "rm -rf",
                           "drop table", "delete from", "ransom", "wipe")

    # Consecutive failures before a capability is reported BROKEN.
    BROKEN_THRESHOLD = 3

    def __init__(self, workspace: Any = None, runner: Any = None,
                 state: Any = None, scope_check: Callable[[str], bool] | None = None,
                 live_local: bool = False):
        self.workspace = workspace
        self.runner = runner
        self.state = state
        self.scope_check = scope_check
        self.live_local = live_local
        self._caps: dict[str, Capability] = {}
        for cap in build_production_capabilities():
            self._caps[cap.capability_id] = cap
        self._disabled: set[str] = set()
        self._failures: dict[str, int] = {}

    @classmethod
    def for_display(cls) -> CapabilityRegistry:
        """Display-only registry: truthful PATH/dependency checks with no
        workspace, no CommandRunner, and no tool invocation."""
        return cls(workspace=None, runner=_EnvProbe(), state=None,
                   scope_check=None)

    def get(self, capability_id: str) -> Capability | None:
        # Explicit legacy-alias resolution (backward compatible).
        return self._caps.get(canonical_tool_id(capability_id))

    def list(self, category: CapabilityCategory | None = None) -> list[Capability]:
        if category:
            return [c for c in self._caps.values() if c.category == category]
        return list(self._caps.values())

    def disable(self, capability_id: str) -> None:
        self._disabled.add(capability_id)

    def enable(self, capability_id: str) -> None:
        self._disabled.discard(capability_id)
        self._failures.pop(capability_id, None)

    def health(self, capability_id: str) -> CapabilityHealth:
        """Canonical health evaluation (shared by status UI, reports, scheduler)."""
        cap = self._caps.get(canonical_tool_id(capability_id))
        if cap is None:
            return CapabilityHealth(
                capability_id=capability_id, availability=Availability.UNAVAILABLE,
                execution_mode=ExecutionMode.NONE, reason="not registered",
                diagnostic=f"unknown capability '{capability_id}'")
        if capability_id in self._disabled or cap.capability_id in self._disabled:
            return CapabilityHealth(
                capability_id=cap.capability_id, availability=Availability.DISABLED,
                execution_mode=ExecutionMode.NONE, reason="disabled by operator/policy",
                provenance=cap.provenance)
        if self._failures.get(cap.capability_id, 0) >= self.BROKEN_THRESHOLD:
            return CapabilityHealth(
                capability_id=cap.capability_id, availability=Availability.BROKEN,
                execution_mode=ExecutionMode.NONE,
                reason=f"{self._failures[cap.capability_id]} consecutive failures",
                provenance=cap.provenance,
                diagnostic="re-enable explicitly after fixing the underlying tool")
        check = cap.availability_check
        kind = getattr(check, "_kind", "binary")
        binary = getattr(check, "_binary", "") or ""
        # Deterministic local analyzers first: they do not need a shell
        # binary, so the binary branch below must not shadow them.
        if cap.capability_id in _LOCAL_LIVE_CAPS:
            if cap.capability_id in _HTTPX_DEPENDENT_CAPS:
                try:
                    __import__("httpx")
                except ImportError:
                    return CapabilityHealth(
                        capability_id=cap.capability_id,
                        availability=Availability.UNAVAILABLE,
                        execution_mode=ExecutionMode.NONE,
                        reason="httpx library not installed",
                        dependency="httpx", provenance=cap.provenance,
                        diagnostic="pip install httpx for live HTTP probing")
            return CapabilityHealth(
                capability_id=cap.capability_id, availability=Availability.AVAILABLE,
                execution_mode=ExecutionMode.LIVE,
                reason="deterministic local analysis; no external dependency",
                dependency="none", provenance=cap.provenance)
        if kind == "python" and cap.capability_id == "browser_automate":
            probe = _playwright_probe()
            if probe["ok"]:
                return CapabilityHealth(
                    capability_id=cap.capability_id, availability=Availability.AVAILABLE,
                    execution_mode=ExecutionMode.LIVE,
                    reason="Playwright + browser executable available",
                    dependency=f"playwright ({probe['chromium']})",
                    provenance=cap.provenance)
            return CapabilityHealth(
                capability_id=cap.capability_id, availability=Availability.AVAILABLE,
                execution_mode=ExecutionMode.SYNTHETIC,
                reason=f"{probe['reason']}; scripted fallback",
                dependency="playwright", provenance=cap.provenance,
                diagnostic=probe["reason"])
        if binary and binary != "none":
            if _runner_available(self.runner, binary):
                return CapabilityHealth(
                    capability_id=cap.capability_id, availability=Availability.AVAILABLE,
                    execution_mode=ExecutionMode.LIVE,
                    reason=f"'{binary}' found on PATH",
                    dependency=binary, provenance=cap.provenance)
            if cap.capability_id in _SYNTHETIC_FALLBACK_CAPS:
                return CapabilityHealth(
                    capability_id=cap.capability_id, availability=Availability.AVAILABLE,
                    execution_mode=ExecutionMode.SYNTHETIC,
                    reason=f"'{binary}' not found; offline synthesis fallback",
                    dependency=binary, provenance=cap.provenance,
                    diagnostic=f"install '{binary}' for live execution")
            return CapabilityHealth(
                capability_id=cap.capability_id, availability=Availability.UNAVAILABLE,
                execution_mode=ExecutionMode.NONE,
                reason=f"'{binary}' not found and no fallback",
                dependency=binary, provenance=cap.provenance)
        return CapabilityHealth(
            capability_id=cap.capability_id, availability=Availability.AVAILABLE,
            execution_mode=ExecutionMode.SYNTHETIC,
            reason="offline synthesis path",
            dependency="none", provenance=cap.provenance)

    def capability_status(self, capability_id: str) -> dict[str, Any]:
        """Human-facing status derived from the canonical health contract."""
        health = self.health(capability_id)
        out = health.to_status_dict()
        cap = self._caps.get(canonical_tool_id(capability_id))
        if cap is not None:
            out["safety"] = cap.safety.value
            out["timeout"] = cap.timeout
        return out

    def _scope_gate(self, capability_id: str, inputs: dict[str, Any],
                    target: str) -> CapabilityResult | None:
        """Deterministic scope checks over target/hostname/URL/port/redirects."""
        # Legacy callable gate (policy-derived).
        if self.scope_check is not None:
            try:
                if target and not self.scope_check(target):
                    return _fail(capability_id, FailureClass.SCOPE_BLOCKED,
                                 f"Target '{target}' outside engagement scope")
            except Exception:
                pass
        # URL-level gate via engagement policy when state is bound.
        policy = None
        if self.state is not None:
            try:
                policy = self.state.get_policy()
            except Exception:
                policy = None
        if policy is not None:
            from horcrux.core.policy import is_url_allowed
            for key in ("url", "base_url", "redirect_destination"):
                url = inputs.get(key)
                if url:
                    ok, reason = is_url_allowed(policy, str(url))
                    if not ok:
                        return _fail(capability_id, FailureClass.SCOPE_BLOCKED,
                                     f"URL scope blocked ({key}): {reason}")
            port = inputs.get("port")
            try:
                if port is not None and not (1 <= int(port) <= 65535):
                    return _fail(capability_id, FailureClass.POLICY_BLOCKED,
                                 f"Port '{port}' outside valid range")
            except (TypeError, ValueError):
                return _fail(capability_id, FailureClass.POLICY_BLOCKED,
                             f"Port '{port}' is not a valid port number")
        return None

    def availability_report(self) -> dict[str, dict[str, Any]]:
        report: dict[str, dict[str, Any]] = {}
        for cap_id, cap in self._caps.items():
            st = self.capability_status(cap_id)
            report[cap_id] = {
                "available": st["status"] == "AVAILABLE",
                "status": st["status"],
                "mode": st.get("mode", "none"),
                "category": cap.category.value,
                "safety": cap.safety.value,
                "timeout": cap.timeout,
                "module": cap.module_path,
                "required_binary": getattr(cap.availability_check, "_binary", ""),
                "reason": st.get("reason", ""),
            }
        return report

    def execute(self, capability_id: str, inputs: dict[str, Any] | None = None,
                request_id: str | None = None) -> CapabilityResult:
        inputs = dict(inputs or {})
        capability_id = canonical_tool_id(capability_id)
        cap = self._caps.get(capability_id)
        if cap is None or cap.execute_fn is None:
            return _fail(capability_id, FailureClass.UNAVAILABLE,
                         f"Capability '{capability_id}' not registered")
        # Disabled / broken gates (Part 27).
        if capability_id in self._disabled:
            return _fail(capability_id, FailureClass.UNAVAILABLE,
                         f"Capability '{capability_id}' is DISABLED")
        if self._failures.get(capability_id, 0) >= self.BROKEN_THRESHOLD:
            return _fail(capability_id, FailureClass.UNAVAILABLE,
                         f"Capability '{capability_id}' is BROKEN "
                         f"({self._failures[capability_id]} consecutive failures)")
        # Destructive-action deny-list: LLM can never bypass safety (Part 26).
        blob = " ".join(str(v).lower() for v in inputs.values() if isinstance(v, str))
        if any(m in blob for m in self.DESTRUCTIVE_MARKERS):
            return _fail(capability_id, FailureClass.APPROVAL_REQUIRED,
                         "Input matches destructive-action deny-list; operator approval required")
        target = str(inputs.get("target", getattr(self.state, "target", "") or ""))
        # Deterministic scope enforcement on target + URL + port (Part 25).
        scope_fail = self._scope_gate(capability_id, inputs, target)
        if scope_fail is not None:
            return scope_fail
        # Approval gate for HIGH/FORBIDDEN.
        if cap.safety in (SafetyClass.HIGH, SafetyClass.FORBIDDEN) and not inputs.get("operator_approved"):
            return _fail(capability_id, FailureClass.APPROVAL_REQUIRED,
                         f"Capability '{capability_id}' requires operator approval")
        # Required-input validation.
        missing = [k for k in cap.required_inputs
                   if k not in inputs and k not in ("target",)]
        # 'target' may come from state; only enforce when truly absent.
        if "target" in cap.required_inputs and not target:
            missing.append("target")
        # Allow model-derived defaults: drop missing keys that the adapter can synthesize.
        missing = [m for m in missing if m not in ("path", "endpoint", "url", "port", "base_url")]
        if missing:
            return _fail(capability_id, FailureClass.INSUFFICIENT_EVIDENCE,
                         f"Missing required inputs: {', '.join(missing)}",
                         {"missing": missing})
        ctx = dict(inputs)
        ctx.setdefault("target", target)
        ctx.setdefault("request_id", request_id or secrets.token_hex(8))
        ctx["workspace"] = self.workspace
        ctx["runner"] = self.runner
        ctx["state"] = self.state
        ctx["live_local"] = self.live_local
        if self.state is not None:
            try:
                ctx.setdefault("application_model", self.state.get_application_model())
            except Exception:
                pass
        t0 = time.monotonic()
        try:
            result = cap.execute_fn(ctx)
            result.duration_ms = result.duration_ms or int((time.monotonic() - t0) * 1000)
            result.provenance = result.provenance or cap.provenance
            result.tool = result.tool or capability_id
            # Failure accounting for BROKEN reporting (Part 27).
            if result.success:
                self._failures.pop(capability_id, None)
            elif result.failure in (FailureClass.TOOL_FAILED, FailureClass.TIMEOUT):
                self._failures[capability_id] = self._failures.get(capability_id, 0) + 1
            # Persist raw artifact for forensics.
            if self.workspace is not None:
                try:
                    rid = ctx.get("request_id", "noid")
                    self.workspace.write(f"raw/cap-{capability_id}-{rid}.json",
                                         json.dumps({"inputs": {k: v for k, v in inputs.items()
                                                                 if k != 'application_model'},
                                                     "structured": result.structured_data,
                                                     "failure": result.failure.value,
                                                     "provenance": result.provenance}, indent=2, default=str))
                    result.artifacts.append(f"raw/cap-{capability_id}-{rid}.json")
                except Exception:
                    pass
            # Timeout classification.
            if result.duration_ms >= cap.timeout * 1000:
                result.failure = FailureClass.TIMEOUT
                result.success = False
            return result
        except TimeoutError as exc:
            return _fail(capability_id, FailureClass.TIMEOUT, str(exc))
        except Exception as exc:
            return _fail(capability_id, FailureClass.TOOL_FAILED, f"{capability_id} failed: {exc}")


def environment_availability_report() -> dict[str, dict[str, Any]]:
    """Shared display/diagnostic report: truthful PATH + dependency checks.

    Uses an environment probe — no workspace, no CommandRunner, no tool
    invocation. Consumed by status UI, reports, and explainers so doctor,
    status, and the registry share one availability semantic.
    """
    return CapabilityRegistry.for_display().availability_report()


def capability_binaries() -> dict[str, str]:
    """Canonical capability → dependency map shared with doctor-style checks.

    Values are shell binaries, except ``playwright`` (Python package +
    browser executable) and ``""`` (no external dependency).
    """
    out: dict[str, str] = {}
    for cap in build_production_capabilities():
        out[cap.capability_id] = getattr(cap.availability_check, "_binary", "") or ""
    return out
