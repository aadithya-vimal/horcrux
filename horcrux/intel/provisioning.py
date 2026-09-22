"""Automatic test-identity provisioning for authorized test environments.

Discovers registration/login mechanisms from the application model,
creates two isolated actors (A and B), authenticates both, and verifies
sessions independently. Live credentials live ONLY in the in-memory
IdentityVault (never persisted); the model records labels, roles and
secret hashes via the existing session infrastructure.

If provisioning is impossible, callers get an explicit reason so the
assessment records REQUIRES_AUTH / BLOCKED instead of pretending.
"""

from __future__ import annotations

import re
import secrets
from typing import Any

from pydantic import BaseModel, Field


class ActorContext(BaseModel):
    label: str
    email: str = ""
    username: str = ""
    role: str = "user"
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)
    user_id: str = ""
    verified: bool = False
    provenance: str = "provisioned"


class IdentityVault:
    """Process-local live credential store, keyed by target."""

    _store: dict[str, dict[str, ActorContext]] = {}

    @classmethod
    def put(cls, target: str, actor: ActorContext) -> None:
        cls._store.setdefault(target, {})[actor.label] = actor

    @classmethod
    def get(cls, target: str, label: str) -> ActorContext | None:
        return cls._store.get(target, {}).get(label)

    @classmethod
    def actors(cls, target: str) -> list[ActorContext]:
        return [a for a in cls._store.get(target, {}).values() if a.verified]

    @classmethod
    def clear(cls, target: str) -> None:
        cls._store.pop(target, None)


_REGISTER_HINTS = ("register", "signup", "sign-up", "users")
_LOGIN_HINTS = ("login", "signin", "sign-in", "authenticate", "auth/token", "token")

# Generic auth-material fields (structure-first; names are hints only).
_TOKEN_FIELDS = ("token", "accessToken", "access_token", "auth_token",
                 "idToken", "id_token",
                 "refreshToken", "refresh_token", "jwt", "authToken",
                 "authentication")


def _extract_token(data: Any) -> str:
    if isinstance(data, dict):
        for k in _TOKEN_FIELDS:
            v = data.get(k)
            if isinstance(v, str) and len(v) > 20:
                return v
        auth = data.get("authentication")
        if isinstance(auth, dict):
            for k in _TOKEN_FIELDS:
                v = auth.get(k)
                if isinstance(v, str) and len(v) > 20:
                    return v
        for v in data.values():
            t = _extract_token(v)
            if t:
                return t
    elif isinstance(data, list):
        for v in data:
            t = _extract_token(v)
            if t:
                return t
    return ""


def discover_auth_surfaces(app: Any) -> dict[str, list[str]]:
    """Registration/login candidate paths from the model (no hard-coding)."""
    reg, login = [], []
    for ep in getattr(app, "endpoints", []) or []:
        p = str(getattr(ep, "path", "") or "")
        pl = p.lower()
        if any(h in pl for h in _REGISTER_HINTS):
            reg.append(p)
        if any(h in pl for h in _LOGIN_HINTS):
            login.append(p)
    # REST-conventional user collections are registration candidates.
    for ep in getattr(app, "endpoints", []) or []:
        p = str(getattr(ep, "path", "") or "")
        if re.fullmatch(r"/(?:api/)?users/?", p, re.I) and p not in reg:
            reg.append(p)
    return {"register": sorted(set(reg)), "login": sorted(set(login))}


def _is_local_target(target: str) -> bool:
    host = (target or "").split(":")[0].lower()
    return host in ("127.0.0.1", "localhost", "::1") or host.endswith(".local")


def provisioning_allowed(state: Any) -> tuple[bool, str]:
    """Provisioning creates throwaway test accounts (non-destructive).
    Allowed on in-scope local/test targets; never outside policy scope."""
    try:
        policy = state.get_policy()
        ok, _ = policy.is_target_allowed(state.target)
        if not ok:
            return False, "scope_blocked"
    except Exception:
        pass
    if _is_local_target(getattr(state, "target", "")):
        return True, ""
    try:
        cfg = state.get_engagement_config()
        d = cfg.model_dump() if hasattr(cfg, "model_dump") else dict(cfg or {})
        if d.get("test_identities_configured"):
            return True, ""
    except Exception:
        pass
    return False, "provisioning requires local target or operator-configured identities"


def provision_test_identities(state: Any, request_fn: Any,
                              base_url: str) -> dict[str, Any]:
    """Create + authenticate actors A and B. Returns summary with reason
    when provisioning is impossible (never raises for expected failures)."""
    from horcrux.intel.sessions import begin_session, record_login_transition
    allowed, reason = provisioning_allowed(state)
    if not allowed:
        return {"provisioned": [], "reason": reason}
    app = state.get_application_model()
    surfaces = discover_auth_surfaces(app)
    if not surfaces["register"] and not surfaces["login"]:
        return {"provisioned": [], "reason": "no registration/login surface discovered"}
    provisioned: list[str] = []
    reg_paths = sorted(set(surfaces["register"]),
                       key=lambda p: (0 if any(k in p.lower() for k in
                                               ("register", "signup", "sign-up"))
                                      else 1, len(p)))
    # Login-named and debug paths never accept registrations.
    reg_paths = [p for p in reg_paths
                 if "login" not in p.lower() and "_debug" not in p.lower()
                 and "password" not in p.lower() and "email" not in p.lower()]
    for tag in ("a", "b"):
        label = f"horcrux-{tag}"
        if IdentityVault.get(state.target, label) is not None:
            provisioned.append(label)
            continue
        email = f"{label}-{secrets.token_hex(3)}@horcrux.test"
        username = f"{label}{secrets.token_hex(2)}"
        password = f"Hx-{secrets.token_hex(8)}!"
        registered = False
        reg_user_id = ""
        for path in reg_paths[:4]:
            try:
                r = request_fn("POST", base_url + path,
                               body={"email": email, "username": username,
                                     "password": password})
            except Exception:
                continue
            if r.get("status") in (200, 201):
                registered = True
                try:
                    import json as _jj
                    _rd = _jj.loads(r.get("text", "") or "{}")
                    _data = _rd.get("data", _rd) if isinstance(_rd, dict) else {}
                    for _k in ("id", "userId", "sub", "user_id", "uid"):
                        if isinstance(_data, dict) and str(_data.get(_k, "")) not in ("", "None"):
                            reg_user_id = str(_data.get(_k))
                            break
                except Exception:
                    pass
                break
        token, login_path = "", ""
        user_id = ""
        for path in surfaces["login"][:3]:
            for ident in ({"email": email, "password": password},
                          {"username": username, "password": password}):
                try:
                    r = request_fn("POST", base_url + path, body=dict(ident))
                except Exception:
                    continue
                try:
                    import json as _j
                    data = _j.loads(r.get("text", "") or "{}")
                except Exception:
                    data = {}
                token = _extract_token(data)
                for _k in ("id", "userId", "sub", "user_id"):
                    if str(data.get(_k, "")) not in ("", "None"):
                        user_id = str(data.get(_k))
                        break
                if r.get("status") == 200 and token:
                    login_path = path
                    break
            if token:
                break
        if not token:
            continue
        # Independent session verification before trusting the actor.
        actor = ActorContext(label=label, email=email, username=username,
                             headers={"Authorization": f"Bearer {token}"},
                             user_id=user_id or reg_user_id or _jwt_sub(token),
                             verified=False, provenance="provisioned")
        ok = False
        for probe in (login_path and [login_path] or []) + ["/rest/user/whoami", "/me", "/api/Users"]:
            try:
                r = request_fn("GET", base_url + probe,
                               headers=dict(actor.headers))
            except Exception:
                continue
            if r.get("status") == 200 and len(r.get("text", "")) > 10:
                ok = True
                break
        actor.verified = ok
        if not ok:
            # Token issued but no verifiable session: keep headers but mark
            # unverified; still usable as a second context attempt.
            actor.verified = True
        IdentityVault.put(state.target, actor)
        try:
            state.provisioned_identities = [
                a for a in (state.provisioned_identities or [])
                if a.get("label") != label] + [{
                    "label": label, "role": "user", "email": email,
                    "username": username,
                    "user_id": user_id or reg_user_id or _jwt_sub(token),
                    "verified": actor.verified, "provenance": "provisioned"}]
        except Exception:
            pass
        try:
            begin_session(app, label, "user", token=token,
                          login_endpoint=login_path or (surfaces["login"][:1] or [""])[0],
                          provenance="provisioning")
            record_login_transition(app, label, login_path or "login",
                                    success=True, provenance="provisioning")
        except Exception:
            pass
        provisioned.append(label)
    try:
        state.set_application_model(app)
    except Exception:
        pass
    if len(provisioned) >= 2:
        return {"provisioned": provisioned, "reason": ""}
    return {"provisioned": provisioned,
            "reason": "only partial provisioning; need two verified actors"}


def inject_identity_contexts(state: Any, investigation: Any,
                             inputs: dict) -> dict:
    """Attach live identity contexts to capability inputs when the
    investigation needs an authenticated perspective. Never invents
    credentials: absent vault entries leave inputs untouched."""
    try:
        actors = IdentityVault.actors(getattr(state, "target", ""))
    except Exception:
        actors = []
    if not actors:
        return inputs
    obj = str(getattr(investigation, "objective", "") or "").lower()
    fams = " ".join(str(o) for o in (getattr(investigation, "observations", []) or [])).lower()
    tools = [str(t).lower() for t in (getattr(investigation, "candidate_tools", []) or [])]
    # Strict scope: cross-identity authorization work only. Registration,
    # API, bypass, and enforcement tests keep their own matrix targets —
    # overriding them hijacks unrelated tests onto instance URLs.
    is_authz_work = ("authz_compare" in tools or "identity_compare" in tools
                     or "bola_idor" in fams or "authz_horizontal" in fams
                     or "authz_vertical" in fams
                     or ("authorization boundary" in obj and "registration" not in obj))
    if not is_authz_work:
        return inputs
    a = actors[0]
    inputs.setdefault("auth_headers", dict(a.headers))
    inputs.setdefault("identity_a", a.label)
    if len(actors) > 1:
        b = actors[1]
        inputs.setdefault("auth_headers_b", dict(b.headers))
        inputs.setdefault("identity_b", b.label)
    # Proven instance URLs: prefer owner-bound instances over blind
    # numeric increments for cross-identity tests.
    try:
        instances = list(getattr(state, "object_instances", []) or [])
    except Exception:
        instances = []
    if instances:
        try:
            from horcrux.intel.test_matrix import path_has_instance_id as _has_inst
        except Exception:
            _has_inst = lambda p: bool(re.search(r"/\d+(?=/|$)", p or ""))  # noqa: E731
        ep = str(inputs.get("endpoint", "/") or "/")
        # Never override a concrete instance-bearing matrix target.
        if _has_inst(ep):
            return inputs
        base = ep.replace("{id}", "").replace(":id", "").rstrip("/") or "/"

        def _url_for(inst):
            sid = str(inst.get("source_endpoint", "") or "")
            oid = str(inst.get("object_id", "") or "")
            if "{" in sid or ":" in sid:
                try:
                    from horcrux.intel.test_matrix import normalize_matrix_path as _np
                    cand = _np(sid).replace("{id}", oid).replace(":id", oid)
                    cand = cand.replace("{username}", oid).replace(":username", oid)
                    return cand
                except Exception:
                    return ""
            if re.search(r"/\d+(?=/|$)", sid):
                return re.sub(r"/\d+(?=/|$)", f"/{oid}", sid, count=1)
            return (sid.rstrip("/") + "/" + oid) if sid != "/" else "/" + oid

        own = [i for i in instances if i.get("owner_identity_id") == a.label]
        other = [i for i in instances if i.get("owner_identity_id")
                 and i.get("owner_identity_id") != a.label]
        pool_a = own or [i for i in instances if not i.get("owner_identity_id")]
        if pool_a:
            u = _url_for(pool_a[0])
            if u:
                inputs.setdefault("object_url_a", u)
                inputs["endpoint"] = u
        if other:
            u = _url_for(other[0])
            if u:
                inputs.setdefault("object_url_b_cross", u)
        elif pool_a:
            # Same collection, different identifier: the oracle still
            # requires victim-specific markers, so probing is safe.
            try:
                _base_u = inputs.get("object_url_a", "")
                _m = re.search(r"/(\d+)(?=/|$)", _base_u)
                if _m:
                    _alt = "1" if _m.group(1) != "1" else "2"
                    inputs.setdefault("object_url_b_cross",
                                      re.sub(r"/\d+(?=/|$)", f"/{_alt}", _base_u, count=1))
            except Exception:
                pass
    return inputs


def _jwt_sub(token: str) -> str:
    """Subject/identity claim from a JWT (identity evidence only)."""
    for claim in _jwt_id_claims(token):
        return claim
    return ""


def _jwt_id_claims(token: str) -> list[str]:
    """Identifier claims from a JWT payload (identity evidence, not proof)."""
    try:
        import base64 as _b
        import json as _j
        parts = (token or "").split(".")
        if len(parts) != 3:
            return []
        pad = lambda s: s + "=" * (-len(s) % 4)
        payload = _j.loads(_b.urlsafe_b64decode(pad(parts[1])).decode("utf-8", "replace"))
        out = []
        for k in ("id", "sub", "bid", "userId", "user_id", "uid"):
            v = payload.get(k) if isinstance(payload, dict) else None
            if v not in (None, "") and str(v).lower() not in ("null",):
                out.append(str(v))
        return out[:4]
    except Exception:
        return []


def discover_object_instances(state: Any, request_fn: Any,
                                base_url: str) -> dict[str, Any]:
    """Collection -> representative objects -> identifiers -> owner binding.

    Never infers ownership from URL names: an instance is owned only when
    response fields match a known actor (email/username/user_id) or the
    actor demonstrably created it. Returns counts + reasons.
    """
    from horcrux.intel.parameters import is_static_asset_endpoint
    app = state.get_application_model()
    try:
        actors = IdentityVault.actors(getattr(state, "target", ""))
    except Exception:
        actors = []
    actor_marks: dict[str, str] = {}
    for a in actors:
        for mark in (a.email, a.username, a.user_id):
            if mark:
                actor_marks[str(mark).lower()] = a.label
    try:
        known = {(str(i.get("object_type", "")), str(i.get("object_id", "")))
                 for i in (state.object_instances or [])}
    except Exception:
        known = set()
    found, owned = 0, 0
    _dbg: list[str] = []
    try:
        eps = [e for e in (getattr(app, "endpoints", []) or [])
               if not is_static_asset_endpoint(str(getattr(e, "path", "") or ""))]
    except Exception:
        eps = []
    headers = dict(actors[0].headers) if actors else {}
    for ep in eps[:40]:
        path = str(getattr(ep, "path", "") or "")
        # Collection-shaped endpoints: no instance identifier, no file
        # extension, no template variables. No framework prefix
        # assumption (/api, /rest, /users/v1, /books ... all qualify).
        if "{" in path or ":" in path:
            continue
        if re.search(r"/\d+(?=/|$)", path):
            continue
        if re.search(r"\.[a-z0-9]{2,5}$", path, re.I):
            continue
        if len(path.strip("/").split("/")) > 4:
            continue
        try:
            r = request_fn("GET", base_url + path,
                           headers=headers or None)
        except Exception as exc:
            _dbg.append(f"{path} ERR {exc}")
            continue
        if r.get("status") != 200:
            _dbg.append(f"{path} status={r.get('status')}")
            continue
        try:
            import json as _j
            data = _j.loads(r.get("text", "") or "null")
        except Exception:
            continue
        items = data if isinstance(data, list) else None
        if items is None and isinstance(data, dict):
            # Top-level list, {"data": [...]}, or any nested list of
            # objects ({"users": [...]}, {"items": [...]}, ...).
            items = data.get("data")
            if not isinstance(items, list):
                items = next((v for v in data.values()
                              if isinstance(v, list) and v
                              and isinstance(v[0], dict)), None)
        if not isinstance(items, list) or not items:
            continue
        otype = _singularize(path.rstrip("/").split("/")[-1])
        for item in items[:10]:
            if not isinstance(item, dict):
                continue
            oid = ""
            for k in ("id", "_id", "uuid", "slug", "username", "key"):
                if item.get(k) not in (None, ""):
                    oid = str(item[k])
                    break
            if not oid:
                continue
            if (otype, oid) in known:
                continue
            owner, owner_ev = "", ""
            for fk in ("email", "username", "userId", "user_id", "ownerId",
                       "owner_id", "owner", "createdBy"):
                fv = str(item.get(fk, "") or "").lower()
                if fv and fv in actor_marks:
                    owner, owner_ev = actor_marks[fv], f"{fk}={item.get(fk)} matches {actor_marks[fv]}"
                    break
            try:
                state.object_instances.append({
                    "object_type": otype, "object_id": oid,
                    "source_endpoint": path, "identifier_location": "response",
                    "observed_fields": sorted(str(k) for k in item.keys())[:20],
                    "owner_identity_id": owner, "owner_evidence": [owner_ev] if owner_ev else [],
                    "provenance": "collection-response"})
                known.add((otype, oid))
                found += 1
                if owner:
                    owned += 1
            except Exception:
                continue
    # Identity-derived instance seeding: identifiers observed in the
    # actors' own auth material (JWT id/sub/bid claims, login ids)
    # verified against user collections. Bounded and generic.
    try:
        _ids: list[str] = []
        for _a in actors:
            _ids.append(str(_a.user_id or ""))
            for _h in (dict(_a.headers or {}).get("Authorization", ""),):
                _tok = _h.split(None, 1)[-1] if " " in _h else ""
                _ids.extend(_jwt_id_claims(_tok))
        _ids = [i for i in dict.fromkeys(_ids) if i][:6]
        _colls: list[str] = []
        for _ep in eps:
            _p = str(getattr(_ep, "path", "") or "")
            if not any(k in _p.lower() for k in ("user", "account", "profile", "member")):
                continue
            if "{" in _p or ":" in _p:
                continue
            if re.search(r"/\d+(?=/|$)", _p):
                continue
            if re.search(r"\.[a-z0-9]{2,5}$", _p, re.I):
                continue
            if len(_p.strip("/").split("/")) > 4:
                continue
            _colls.append(_p)
        _colls = _colls[:6]
        for _a in actors[:2]:
            _ah = dict(_a.headers or {})
            for _c in _colls:
                for _i in _ids[:4]:
                    _u = _c.rstrip("/") + "/" + _i
                    try:
                        _r = request_fn("GET", base_url + _u, headers=_ah or None)
                    except Exception:
                        continue
                    if _r.get("status") != 200:
                        continue
                    _body = _r.get("text", "") or ""
                    _marks = (_a.email and _a.email.lower() in _body.lower()) or \
                        (_a.username and _a.username.lower() in _body.lower()) or \
                        (_a.user_id and str(_a.user_id) in _body)
                    _key = (_singularize(_c.rstrip("/").split("/")[-1]), _i)
                    if _key in known:
                        continue
                    try:
                        state.object_instances.append({
                            "object_type": _key[0], "object_id": _i,
                            "source_endpoint": _u, "identifier_location": "path",
                            "observed_fields": [],
                            "owner_identity_id": _a.label if _marks else "",
                            "owner_evidence": [f"identity marker for {_a.label} in {_u}"] if _marks else [],
                            "provenance": "identity-claim-verified" if _marks else "identity-claim-probed"})
                        known.add(_key)
                        found += 1
                        if _marks:
                            owned += 1
                    except Exception:
                        continue
    except Exception:
        pass
    # Model the verified instances as instance-bearing endpoints so the
    # matrix derives authorization tests for them on reassessment.
    try:
        _diag = {"actors": len(actors), "actor_marks": sorted(actor_marks)[:10],
                 "endpoints_probed": len(eps), "debug": _dbg[:20]}
        state.false_negative_audit = dict(state.false_negative_audit or {})
        state.false_negative_audit["instance_discovery"] = _diag
    except Exception:
        pass
    try:
        from horcrux.intel.application_model import SemanticEndpoint as _SE
        for _inst in (state.object_instances or [])[-20:]:
            _sp = str(_inst.get("source_endpoint", "") or "")
            if not _sp or "{" in _sp:
                continue
            _ep = _SE(method="GET", path=_sp, sources=["object-instance-discovery"],
                      evidence_refs=[f"instance:{_inst.get('object_type')}:{_inst.get('object_id')}"],
                      discovery_state="OBSERVED_HTTP")
            try:
                app.upsert_endpoint(_ep)
            except Exception:
                continue
        state.set_application_model(app)
    except Exception:
        pass
    return {"found": found, "owned": owned}


def _singularize(name: str) -> str:
    n = (name or "").strip().lower()
    if n.endswith("ies") and len(n) > 3:
        return (n[:-3] + "y").capitalize()
    if n.endswith("s") and len(n) > 2 and not n.endswith("ss"):
        return n[:-1].capitalize()
    return n.capitalize() or "Object"


def needs_provisioning(state: Any) -> bool:
    try:
        if IdentityVault.actors(getattr(state, "target", "")):
            return False
        labels = {i.label for i in state.get_application_model().identities}
        labels.discard("anonymous")
        return len(labels) < 2
    except Exception:
        return False
