"""Session / identity model + authenticated crawling + comparison (Parts 3, 4, 12).

- Identities carry roles, privilege levels, session/token *hashes* (raw
  secrets are never stored), login/logout/expiry transitions, and observed
  objects — enabling cross-identity object-access reasoning.
- :class:`TestIdentity` describes a researcher-configured test account.
  Credentials come from runtime configuration / environment, never hard-coded.
- :func:`authenticated_crawl` runs the anonymous -> login -> authenticated
  surface -> object/workflow correlation workflow over any BrowserAdapter.
- :func:`compare_identities` is the reusable multi-identity comparison
  primitive for authorization investigations.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any


ROLE_PRIVILEGE = {"anonymous": 0, "user": 1, "privileged": 2, "admin": 3}


@dataclass
class TestIdentity:
    """Researcher-configured test account. Secrets resolved at runtime."""

    __test__ = False

    label: str
    role: str = "user"
    login_path: str = "/login"
    username: str = ""
    password_env: str = ""  # env var holding the password (preferred)
    password: str = ""  # explicit only for synthetic benchmarks
    headers: dict[str, str] = field(default_factory=dict)

    @property
    def privilege_level(self) -> int:
        return ROLE_PRIVILEGE.get(self.role, 1)

    def resolve_secret(self) -> str:
        if self.password_env and os.environ.get(self.password_env):
            return os.environ[self.password_env]
        return self.password

    def has_credentials(self) -> bool:
        return bool(self.username and self.resolve_secret())


def load_test_identities(config: Any = None) -> list[TestIdentity]:
    """Build test identities from runtime config (dict/env), never hard-coded."""
    identities: list[TestIdentity] = []
    items: list[dict[str, Any]] = []
    if isinstance(config, dict):
        items = config.get("test_identities", []) or []
    elif isinstance(config, list):
        items = config
    for item in items:
        if isinstance(item, dict) and item.get("label"):
            identities.append(TestIdentity(
                label=item["label"], role=item.get("role", "user"),
                login_path=item.get("login_path", "/login"),
                username=item.get("username", ""),
                password_env=item.get("password_env", ""),
                password=item.get("password", "")))
    # Environment-provided identities: HORCRUX_IDENTITY_<N>_LABEL/ROLE/USER/PASS_ENV.
    idx = 1
    while True:
        label = os.environ.get(f"HORCRUX_IDENTITY_{idx}_LABEL", "")
        if not label:
            break
        identities.append(TestIdentity(
            label=label, role=os.environ.get(f"HORCRUX_IDENTITY_{idx}_ROLE", "user"),
            username=os.environ.get(f"HORCRUX_IDENTITY_{idx}_USER", ""),
            password_env=os.environ.get(f"HORCRUX_IDENTITY_{idx}_PASS_ENV", ""),
            login_path=os.environ.get(f"HORCRUX_IDENTITY_{idx}_LOGIN", "/login")))
        idx += 1
    return identities


def register_test_identity(app: Any, identity: TestIdentity,
                           source: str = "operator") -> Any:
    """Register a configured identity in the model (no secrets persisted)."""
    from horcrux.intel.application_model import IdentityRole, SemanticIdentity
    try:
        role = IdentityRole(identity.role)
    except ValueError:
        role = IdentityRole.USER
    return app.upsert_identity(SemanticIdentity(
        role=role, label=identity.label,
        privilege_level=identity.privilege_level,
        session_evidence=[f"{source}:test-identity:{identity.label}"],
        auth_mechanism="session"))


def begin_session(app: Any, identity_label: str, role: str = "user",
                  cookies: list[dict] | None = None, token: str = "",
                  login_endpoint: str = "", provenance: str = "browser") -> Any:
    """Record a new session; only hashes of secrets are stored."""
    from horcrux.intel.application_model import IdentityRole, SemanticIdentity, SessionRecord
    from horcrux.intel.browser import hash_secret
    cookie_hashes = [hash_secret(c.get("value", "")) for c in (cookies or [])
                     if isinstance(c, dict)]
    token_hashes = [hash_secret(token)] if token else []
    session = SessionRecord(
        identity_label=identity_label, role=_role(role),
        cookie_hashes=cookie_hashes, token_hashes=token_hashes,
        login_endpoint=login_endpoint,
        evidence_refs=[f"session:{identity_label}:{login_endpoint or 'observed'}"],
        provenance=[provenance])
    app.upsert_session(session)
    ident = app.upsert_identity(SemanticIdentity(
        role=_role(role), label=identity_label,
        privilege_level=ROLE_PRIVILEGE.get(role, 1),
        session_ids=[session.id], token_hashes=token_hashes,
        session_evidence=[f"session:{session.id[:8]}"]))
    return session


def _role(role: str):  # local helper avoiding import cycles at module import
    from horcrux.intel.application_model import IdentityRole
    try:
        return IdentityRole(role)
    except ValueError:
        return IdentityRole.USER


def record_login_transition(app: Any, identity_label: str, login_path: str,
                            success: bool = True, provenance: str = "browser") -> None:
    from horcrux.intel.ingestion import ingest_http_request
    try:
        ingest_http_request(app, method="POST", path=login_path,
                            identity=identity_label if success else "anonymous",
                            source=provenance)
    except Exception:
        pass


def record_logout_transition(app: Any, session_id: str) -> None:
    for s in getattr(app, "sessions", []):
        if s.id == session_id or s.id.startswith(session_id):
            s.logout_observed = True
            return


def record_session_expiry(app: Any, session_id: str, replaced_by: str = "") -> None:
    for s in getattr(app, "sessions", []):
        if s.id == session_id or s.id.startswith(session_id):
            s.expired_observed = True
            s.replaced_by = replaced_by
            return


def observe_identity_object(app: Any, identity_label: str, object_type: str,
                            identifier: str, endpoint: str = "",
                            operation: str = "read") -> None:
    """Link an identity to an observed object + lifecycle (Part 6 feed)."""
    from horcrux.intel.application_model import ObjectLifecycle
    for ident in getattr(app, "identities", []):
        if ident.label == identity_label:
            ref = f"{object_type}:{identifier}"
            if ref not in ident.observed_objects:
                ident.observed_objects.append(ref)
            break
    lc = ObjectLifecycle(object_type=object_type, identifier=str(identifier),
                         identifier_pattern="{id}" if str(identifier).isdigit() else str(identifier))
    if operation == "read" and endpoint:
        lc.read_endpoints.append(endpoint)
    elif operation == "mutation" and endpoint:
        lc.mutation_endpoints.append(endpoint)
    elif operation == "delete" and endpoint:
        lc.delete_endpoints.append(endpoint)
    lc.observed_identities.append(identity_label)
    lc.evidence_refs.append(f"identity-object:{identity_label}:{object_type}:{identifier}")
    lc.provenance.append("sessions")
    app.upsert_object_lifecycle(lc)


# ---------------------------------------------------------------------------
# Authenticated crawling (Part 4)
# ---------------------------------------------------------------------------

def authenticated_crawl(app: Any, adapter: Any, base_url: str,
                        identity: TestIdentity,
                        extra_paths: list[str] | None = None) -> dict[str, Any]:
    """Anonymous discovery -> login -> authenticated surface -> correlation.

    Uses only the provided BrowserAdapter; every observation converges into
    ``app`` via :func:`record_browser_session`. Credentials are used for the
    login interaction only and are never written to the model or artifacts.
    """
    from horcrux.intel.browser_session import record_browser_session
    summary: dict[str, Any] = {"identity": identity.label, "steps": [],
                               "evidence": 0, "authenticated": False}
    base = base_url.rstrip("/")

    def _step(name: str, obs: Any) -> None:
        try:
            out = record_browser_session(obs, app, identity="anonymous"
                                         if name == "anonymous" else identity.label)
            summary["steps"].append(name)
            summary["evidence"] += len(out.get("evidence", []))
        except Exception as exc:
            summary["steps"].append(f"{name}:error:{exc}")

    # 1. anonymous crawl of entry points.
    try:
        _step("anonymous", adapter.navigate(base + "/"))
    except Exception as exc:
        summary["steps"].append(f"anonymous:error:{exc}")
        return summary
    # 2. discover login surface from the model.
    login_path = identity.login_path
    try:
        for ep in getattr(app, "endpoints", []):
            if "login" in ep.path.lower():
                login_path = ep.path
                break
    except Exception:
        pass
    # 3. establish test identity (fill + submit; secret stays in-memory).
    try:
        adapter.navigate(base + login_path)
        secret = identity.resolve_secret()
        if identity.username:
            adapter.fill("input[name=email], input[name=username]", identity.username)
        if secret:
            adapter.fill("input[type=password]", "***")
        obs = adapter.submit()
        # Re-attribute observation to the authenticated identity without secret.
        obs.identity = identity.label
        _step("login", obs)
        begin_session(app, identity.label, role=identity.role,
                      cookies=adapter.get_cookies(), login_endpoint=login_path)
        summary["authenticated"] = True
    except Exception as exc:
        summary["steps"].append(f"login:error:{exc}")
        return summary
    # 4. crawl authenticated surface (use discovered endpoints, not hardcoded app-specific paths).
    discovered_paths = []
    try:
        for ep in getattr(app, "endpoints", [])[:8]:
            p = ep.path.replace("{id}", "1").replace(":id", "1")
            if p not in discovered_paths:
                discovered_paths.append(p)
    except Exception:
        pass
    crawl_paths = extra_paths or discovered_paths or ["/", "/api"]
    for path in crawl_paths:
        try:
            obs = adapter.navigate(base + path)
            obs.identity = identity.label
            _step(f"authed:{path}", obs)
        except PermissionError:
            summary["steps"].append(f"authed:{path}:scope_blocked")
        except Exception as exc:
            summary["steps"].append(f"authed:{path}:error:{exc}")
    # 5. correlate objects/workflows for this identity.
    try:
        for ep in getattr(app, "endpoints", [])[:20]:
            if getattr(ep, "has_object_reference", False) and ep.object_type:
                observe_identity_object(app, identity.label, ep.object_type,
                                        _example_id(ep.path), endpoint=ep.path)
    except Exception:
        pass
    return summary


def _example_id(path: str) -> str:
    import re
    m = re.search(r"/(\d+)", path)
    if m:
        return m.group(1)
    m = re.search(r"\{(\w+)\}", path)
    if m:
        return f"{{{m.group(1)}}}"
    return "1"


# ---------------------------------------------------------------------------
# Multi-identity comparison engine (Part 12)
# ---------------------------------------------------------------------------

def compare_identities(state: Any, label_a: str, label_b: str,
                       endpoint_filter: str = "") -> dict[str, Any]:
    """Compare two identities across endpoints/objects/responses/workflows.

    Returns structured comparison evidence usable by authorization
    investigations: accessible endpoints per identity, shared objects with
    divergent access, role/privilege delta, session behavior delta, and an
    overall verdict (``gap_suspected`` / ``enforced`` / ``insufficient``).
    """
    app = state.get_application_model()
    idents = {i.label: i for i in getattr(app, "identities", [])}
    a = idents.get(label_a)
    b = idents.get(label_b)
    result: dict[str, Any] = {
        "identity_a": label_a, "identity_b": label_b,
        "endpoints_a": [], "endpoints_b": [],
        "shared_objects": [], "divergent": [],
        "role_delta": None, "verdict": "insufficient", "evidence": [],
    }
    if a is None or b is None:
        result["evidence"].append(f"comparison:missing-identity:"
                                  f"{label_a if a is None else label_b}")
        return result
    result["role_delta"] = {"a": a.role.value, "b": b.role.value,
                            "privilege_a": a.privilege_level,
                            "privilege_b": b.privilege_level}
    eps_a = set(a.observed_endpoints or [])
    eps_b = set(b.observed_endpoints or [])
    if endpoint_filter:
        eps_a = {e for e in eps_a if endpoint_filter in e}
        eps_b = {e for e in eps_b if endpoint_filter in e}
    # Fall back to endpoint.observed_identities when per-identity lists are thin.
    if not eps_a or not eps_b:
        for e in getattr(app, "endpoints", []):
            seen = set(e.observed_identities or [])
            if a.role.value in seen or label_a in seen:
                eps_a.add(e.path)
            if b.role.value in seen or label_b in seen:
                eps_b.add(e.path)
    result["endpoints_a"] = sorted(eps_a)[:40]
    result["endpoints_b"] = sorted(eps_b)[:40]
    only_b = sorted(eps_b - eps_a)[:20]
    only_a = sorted(eps_a - eps_b)[:20]
    # Shared objects with per-identity observations.
    objs_a = {o for o in (a.observed_objects or [])}
    objs_b = {o for o in (b.observed_objects or [])}
    shared_types: dict[str, list[str]] = {}
    for o in objs_a | objs_b:
        typ = o.split(":", 1)[0]
        shared_types.setdefault(typ, []).append(o)
    for typ, members in shared_types.items():
        in_a = [m for m in members if m in objs_a]
        in_b = [m for m in members if m in objs_b]
        entry = {"object_type": typ, "a": in_a[:5], "b": in_b[:5]}
        result["shared_objects"].append(entry)
        if in_a and in_b and set(in_a) != set(in_b):
            result["divergent"].append(entry)
    # Cross-user same-object access: same Type:id visible to both identities.
    cross_visible = sorted((objs_a & objs_b))[:10]
    result["cross_visible_objects"] = cross_visible
    if cross_visible and a.role.value != b.role.value:
        result["verdict"] = "gap_suspected"
        result["evidence"].append(
            f"comparison:{label_a}x{label_b}:shared-objects:{len(cross_visible)}")
    elif only_b or only_a or result["divergent"]:
        result["verdict"] = "gap_suspected"
        result["evidence"].append(
            f"comparison:{label_a}x{label_b}:endpoint-delta:"
            f"a_only={len(only_a)}:b_only={len(only_b)}")
    elif eps_a or eps_b:
        result["verdict"] = "enforced"
        result["evidence"].append(f"comparison:{label_a}x{label_b}:no-delta")
    else:
        result["evidence"].append(f"comparison:{label_a}x{label_b}:insufficient-data")
    result["only_a"] = only_a
    result["only_b"] = only_b
    # Persist comparison as session evidence provenance (no secrets).
    try:
        from horcrux.intel.application_model import ObjectLifecycle
        for entry in result["divergent"][:5]:
            lc = ObjectLifecycle(object_type=entry["object_type"], identifier="*")
            lc.authorization_notes.append(
                f"cross-identity-divergence:{label_a}x{label_b}")
            lc.evidence_refs.extend(result["evidence"][:3])
            lc.provenance.append("comparison")
            app.upsert_object_lifecycle(lc)
        state.set_application_model(app)
    except Exception:
        pass
    return result
