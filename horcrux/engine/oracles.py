"""Deterministic security oracles — one per vulnerability family.

Property-specific evidence rules. Never `if suspicious_text: finding`.
Ambiguous input yields INSUFFICIENT, never CONFIRMED. No AI anywhere.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, Field


class OracleBlocked(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class OracleResult(BaseModel):
    verdict: str = "INSUFFICIENT"  # CONFIRMED|REFUTED|INSUFFICIENT
    confidence: float = Field(default=0.5, ge=0, le=1)
    evidence: list[str] = Field(default_factory=list)
    property_id: str = ""


def _conf(pid: str, conf: float, evidence: list[str]) -> OracleResult:
    return OracleResult(verdict="CONFIRMED", confidence=conf,
                        evidence=evidence, property_id=pid)


def _ref(pid: str, conf: float, evidence: list[str]) -> OracleResult:
    return OracleResult(verdict="REFUTED", confidence=conf,
                        evidence=evidence, property_id=pid)


def _ins(pid: str, evidence: list[str], conf: float = 0.4) -> OracleResult:
    return OracleResult(verdict="INSUFFICIENT", confidence=conf,
                        evidence=evidence, property_id=pid)


_SQLI_ERROR_RES = [
    re.compile(r"sqlite3?\s+(syntax\s+)?error", re.I),
    re.compile(r"mysql.*(error|syntax)", re.I),
    re.compile(r"psql|postgres.*error|pg_query", re.I),
    re.compile(r"ORA-\d{4,5}", re.I),
    re.compile(r"microsoft\s+(ole\s+db|sql\s+server)|unclosed\s+quotation", re.I),
    re.compile(r"jdbc.*exception|sql\s+exception", re.I),
]

_PASSWD_RE = re.compile(r"root:x:0:0:[^\n]*:/", re.M)
_WININI_RE = re.compile(r"\[boot loader\]|\[extensions\]", re.I)
_CMD_RE = re.compile(r"uid=\d+\(|whoami|root:.*:0:0", re.I)
_TEMPLATE_EVAL_RES = [re.compile(r"\b49\b"), re.compile(r"__proto__|constructor", re.I)]
_UNESCAPED_CTX = {"script-context", "event-handler-attribute", "tag-attribute", "html-body"}
_ESCAPED_MARKERS = ("&lt;", "&gt;", "&quot;", "&#x27;", "&#39;")


def _norm(e: dict) -> dict:
    return {k: e.get(k) for k in e} | {"_raw": e}


# ── SQLi ──────────────────────────────────────────────────────────
def sqli_oracle(evidence: dict, pid: str = "INJECT_SQL") -> OracleResult:
    baseline = str(evidence.get("baseline_body", ""))
    mutated = str(evidence.get("mutated_body", ""))
    time_base = float(evidence.get("baseline_time_ms", 0) or 0)
    time_mut = float(evidence.get("mutated_time_ms", 0) or 0)
    repeated = bool(evidence.get("repeatable", False))
    generic_only = bool(evidence.get("generic_error_only", False))
    if not mutated:
        return _ins(pid, ["no mutation response to evaluate"])
    if generic_only and not any(r.search(mutated) for r in _SQLI_ERROR_RES):
        return _ins(pid, ["single generic error string is never confirmation"])
    for rx in _SQLI_ERROR_RES:
        if rx.search(mutated) and not rx.search(baseline):
            if repeated:
                return _conf(pid, 0.92, [f"db-error differential: {rx.pattern[:40]}", "repeatable"])
            return _conf(pid, 0.80, [f"db-error differential: {rx.pattern[:40]}"])
    if time_base > 0 and time_mut >= max(4000, time_base * 5):
        if repeated:
            return _conf(pid, 0.85, [f"time differential {time_base:.0f}ms->{time_mut:.0f}ms", "repeatable"])
        return _ins(pid, [f"time differential single-sample {time_base:.0f}ms->{time_mut:.0f}ms; needs repeat"])
    if mutated == baseline:
        return _ref(pid, 0.75, ["mutation neutral vs baseline"])
    return _ins(pid, ["no db-specific fingerprint; ambiguous behavioral change"])


def nosql_oracle(evidence: dict, pid: str = "INJECT_NOSQL") -> OracleResult:
    base_n = int(evidence.get("baseline_count", -1))
    mut_n = int(evidence.get("mutated_count", -1))
    err = str(evidence.get("mutated_body", ""))
    if base_n >= 0 and mut_n >= 0 and mut_n != base_n and bool(evidence.get("operator_payload", False)):
        return _conf(pid, 0.82, [f"result-set change {base_n}->{mut_n} via operator injection"])
    if re.search(r"mongo|bson|cannot\s+apply|operator", err, re.I) and err != str(evidence.get("baseline_body", "")):
        return _conf(pid, 0.78, ["nosql error differential"])
    if err == str(evidence.get("baseline_body", "")):
        return _ref(pid, 0.7, ["neutral"])
    return _ins(pid, ["ambiguous nosql response"])


# ── Command / template / ldap / xpath ─────────────────────────────
def cmdi_oracle(evidence: dict, pid: str = "INJECT_COMMAND") -> OracleResult:
    body = str(evidence.get("mutated_body", ""))
    if _CMD_RE.search(body) and body != str(evidence.get("baseline_body", "")):
        return _conf(pid, 0.93, ["command output reflected"])
    if body == str(evidence.get("baseline_body", "")):
        return _ref(pid, 0.7, ["neutral"])
    return _ins(pid, ["no command-output reflection"])


def ssti_oracle(evidence: dict, pid: str = "INJECT_TEMPLATE") -> OracleResult:
    body = str(evidence.get("mutated_body", ""))
    marker = str(evidence.get("expected_marker", "49"))
    if marker and marker in body and str(evidence.get("payload", "")) not in body:
        return _conf(pid, 0.88, [f"template evaluated marker {marker}"])
    if body == str(evidence.get("baseline_body", "")):
        return _ref(pid, 0.7, ["neutral"])
    return _ins(pid, ["verbatim reflection or no evaluation"])


def ldap_oracle(evidence: dict, pid: str = "INJECT_LDAP") -> OracleResult:
    base = str(evidence.get("baseline_body", ""))
    mut = str(evidence.get("mutated_body", ""))
    if mut != base and re.search(r"ldap|invalid\s+dn|filter", mut, re.I):
        return _conf(pid, 0.78, ["ldap filter-semantics differential"])
    if mut == base:
        return _ref(pid, 0.7, ["neutral"])
    return _ins(pid, ["ambiguous ldap response"])


def xpath_oracle(evidence: dict, pid: str = "INJECT_XPATH") -> OracleResult:
    base = str(evidence.get("baseline_body", ""))
    mut = str(evidence.get("mutated_body", ""))
    if mut != base and re.search(r"xpath|invalid\s+expression", mut, re.I):
        return _conf(pid, 0.78, ["xpath differential"])
    if mut == base:
        return _ref(pid, 0.7, ["neutral"])
    return _ins(pid, ["ambiguous xpath response"])


# ── XSS ───────────────────────────────────────────────────────────
def xss_oracle(evidence: dict, pid: str = "XSS_REFLECTED") -> OracleResult:
    body = str(evidence.get("mutated_body", ""))
    payload = str(evidence.get("payload", ""))
    ctx = str(evidence.get("context", "html-body"))
    reflected = bool(evidence.get("reflected", payload and payload in body))
    if not reflected:
        return _ref(pid, 0.75, ["payload not reflected"])
    unescaped = bool(evidence.get("unescaped", False))
    if not unescaped:
        if any(m in body for m in _ESCAPED_MARKERS):
            return _ref(pid, 0.8, ["reflection escaped"])
        return _ins(pid, ["reflection present; encoding indeterminate"])
    if ctx in _UNESCAPED_CTX:
        return _conf(pid, 0.88, [f"unescaped reflection in {ctx}"])
    return _ins(pid, [f"unescaped reflection in non-executable context {ctx}"])


def xss_stored_oracle(evidence: dict, pid: str = "XSS_STORED") -> OracleResult:
    if not bool(evidence.get("persisted", False)):
        if bool(evidence.get("write_rejected", False)):
            return _ref(pid, 0.75, ["write rejected; nothing persisted"])
        return _ins(pid, ["persistence unproven"])
    sub = dict(evidence)
    return xss_oracle(sub, pid)


def dom_oracle(evidence: dict, pid: str = "XSS_DOM") -> OracleResult:
    if bool(evidence.get("dangerous_sink", False)) and bool(evidence.get("tainted_source", False)):
        return _conf(pid, 0.75, [f"sink {evidence.get('sink_kind', 'sink')} with tainted flow"])
    if bool(evidence.get("dangerous_sink", False)):
        return _ins(pid, ["sink present; flow unproven"])
    return _ref(pid, 0.7, ["no dangerous sink"])


def redirect_oracle(evidence: dict, pid: str = "OPEN_REDIRECT") -> OracleResult:
    loc = str(evidence.get("location", ""))
    if loc.startswith(("http://", "https://", "//")) and bool(evidence.get("external", True)):
        if bool(evidence.get("allowlisted", False)):
            return _ref(pid, 0.75, ["external target allowlisted"])
        return _conf(pid, 0.8, [f"external redirect honored: {loc[:60]}"])
    return _ref(pid, 0.7, ["no external redirect"])


# ── Traversal / upload ────────────────────────────────────────────
def traversal_oracle(evidence: dict, pid: str = "PATH_TRAVERSAL") -> OracleResult:
    body = str(evidence.get("mutated_body", ""))
    base = str(evidence.get("baseline_body", ""))
    hit = bool(_PASSWD_RE.search(body) or _WININI_RE.search(body) or bool(evidence.get("marker_hit", False)))
    if hit and body != base:
        if bool(evidence.get("repeatable", False)):
            return _conf(pid, 0.93, ["filesystem marker disclosed", "repeatable"])
        return _conf(pid, 0.82, ["filesystem marker disclosed"])
    if body == base:
        return _ref(pid, 0.7, ["neutral"])
    return _ins(pid, ["no filesystem marker"])


def upload_oracle(evidence: dict, pid: str = "FILE_UPLOAD_WEAKNESS") -> OracleResult:
    if bool(evidence.get("stored", False)) and bool(evidence.get("retrievable", False)) \
            and bool(evidence.get("executable", False)):
        return _conf(pid, 0.9, ["executable content stored and retrievable"])
    if bool(evidence.get("rejected", False)):
        return _ref(pid, 0.8, ["upload rejected/sanitized"])
    return _ins(pid, ["storage/execution unproven"])


# ── SSRF ──────────────────────────────────────────────────────────
def ssrf_oracle(evidence: dict, pid: str = "SSRF_BASIC") -> OracleResult:
    if bool(evidence.get("network_interaction", False)) or bool(evidence.get("internal_response", False)):
        return _conf(pid, 0.88, ["server-side fetch evidenced (network/interaction)"])
    if bool(evidence.get("reflected_only", False)) or (
            str(evidence.get("mutated_body", "")) == str(evidence.get("baseline_body", ""))):
        if "url" in str(evidence.get("mutated_body", "")).lower():
            return _ins(pid, ["URL echoed; fetch vs reflection indistinguishable"])
        return _ref(pid, 0.7, ["no fetch behavior"])
    return _ins(pid, ["fetch unproven; reflection only"])


# ── Authn ─────────────────────────────────────────────────────────
def authn_unauth_oracle(evidence: dict, pid: str = "AUTHN_UNAUTH_PROTECTED_ACCESS") -> OracleResult:
    status = int(evidence.get("anon_status", 0) or 0)
    body = str(evidence.get("anon_body", ""))
    if status in (401, 403) or "login" in body.lower()[:500]:
        return _ref(pid, 0.85, [f"anon challenged ({status})"])
    if status == 200 and bool(evidence.get("protected_content", False)):
        return _conf(pid, 0.88, ["protected content served anonymously"])
    return _ins(pid, [f"anon status {status} without content verdict"])


def authn_bypass_oracle(evidence: dict, pid: str = "AUTHN_BYPASS") -> OracleResult:
    if bool(evidence.get("restricted_content_without_credential", False)):
        return _conf(pid, 0.9, ["restricted content without credential"])
    return _ref(pid, 0.7, ["bypass rejected"]) if bool(evidence.get("tested", False)) \
        else _ins(pid, ["bypass untested"])


def session_fixation_oracle(evidence: dict, pid: str = "AUTHN_SESSION_FIXATION") -> OracleResult:
    if bool(evidence.get("pre_session_accepted_post_login", False)):
        return _conf(pid, 0.85, ["pre-login session accepted post-login"])
    if bool(evidence.get("rotated", False)):
        return _ref(pid, 0.8, ["session rotated"])
    return _ins(pid, ["rotation unproven"])


def authn_weak_oracle(evidence: dict, pid: str = "AUTHN_WEAK_BEHAVIOR") -> OracleResult:
    if bool(evidence.get("user_enumeration", False)) or bool(evidence.get("no_lockout", False)):
        return _conf(pid, 0.78, ["weak auth behavior proven"])
    if bool(evidence.get("uniform_responses", False)):
        return _ref(pid, 0.75, ["uniform responses + lockout"])
    return _ins(pid, ["behavior ambiguous"])


def secret_exposure_oracle(evidence: dict, pid: str = "AUTHN_CREDENTIAL_EXPOSURE") -> OracleResult:
    body = str(evidence.get("body", ""))
    ctype = str(evidence.get("content_type", "")).lower()
    if "html" in ctype and "<html" in body.lower()[:500]:
        return _ref(pid, 0.8, ["HTML error, not a secret artifact"])
    if bool(evidence.get("secret_pattern", False)) and int(evidence.get("status", 0)) == 200:
        return _conf(pid, 0.9, ["secret pattern in reachable non-HTML response"])
    return _ref(pid, 0.7, ["no secret pattern"]) if bool(evidence.get("tested", False)) \
        else _ins(pid, ["untested"])


# ── Authz ─────────────────────────────────────────────────────────
def bola_oracle(evidence: dict, pid: str = "AUTHZ_BOLA_IDOR") -> OracleResult:
    if bool(evidence.get("requires_second_identity", False)):
        raise OracleBlocked("second identity unavailable")
    if not bool(evidence.get("ownership_proven", False)):
        raise OracleBlocked("no object instance with proven ownership")
    status_a = int(evidence.get("status_owner", 0) or 0)
    status_b = int(evidence.get("status_other", 0) or 0)
    if status_b in (401, 403, 404) and status_a == 200:
        return _ref(pid, 0.85, ["cross-identity denied; owner allowed"])
    if status_b == 200 and bool(evidence.get("private_fields", False)):
        if bool(evidence.get("public_catalog", False)):
            return _ref(pid, 0.8, ["public catalog object; no boundary"])
        return _conf(pid, 0.9, ["peer object readable with private fields"])
    if status_b == 0:
        return _ins(pid, ["cross-identity probe never executed"])
    return _ins(pid, ["differential ambiguous"])


def vertical_oracle(evidence: dict, pid: str = "AUTHZ_VERTICAL_PRIVESC") -> OracleResult:
    status = int(evidence.get("lowpriv_status", evidence.get("anon_status", 0)) or 0)
    if status in (401, 403):
        return _ref(pid, 0.85, [f"privileged surface denied ({status})"])
    if status == 200 and bool(evidence.get("privileged_content", False)):
        return _conf(pid, 0.88, ["privileged content served to low-priv/anon"])
    return _ins(pid, [f"status {status} without content verdict"])


# ── API ───────────────────────────────────────────────────────────
_SENSITIVE_FIELDS = {"password", "passwordhash", "token", "ssn", "creditcard",
                     "role", "isadmin", "salary", "apikey", "secret"}


def excessive_data_oracle(evidence: dict, pid: str = "API_EXCESSIVE_DATA") -> OracleResult:
    fields = {str(f).lower() for f in (evidence.get("fields", []) or [])}
    actor = str(evidence.get("actor", "anonymous"))
    sensitive = sorted(fields & _SENSITIVE_FIELDS)
    if sensitive and actor in ("anonymous", "lowpriv", "user"):
        return _conf(pid, 0.85, [f"sensitive fields to {actor}: {','.join(sensitive[:5])}"])
    if not fields:
        return _ins(pid, ["no response schema extracted"])
    return _ref(pid, 0.75, ["minimal schema"])


def mass_assignment_oracle(evidence: dict, pid: str = "API_MASS_ASSIGNMENT") -> OracleResult:
    if bool(evidence.get("privileged_field_accepted", False)) and bool(evidence.get("persisted", False)):
        return _conf(pid, 0.88, [f"privileged field persisted: {evidence.get('field', 'role')}"])
    if bool(evidence.get("ignored_or_rejected", False)):
        return _ref(pid, 0.8, ["privileged field ignored/rejected"])
    return _ins(pid, ["persistence unproven"])


def method_auth_oracle(evidence: dict, pid: str = "API_METHOD_AUTH") -> OracleResult:
    matrix = evidence.get("method_matrix", {}) or {}
    for method, st in matrix.items():
        if int(st) == 200 and bool(evidence.get("privileged_method", False)):
            return _conf(pid, 0.8, [f"privileged method {method} accepted"])
    if matrix and all(int(s) in (401, 403, 405) for s in matrix.values()):
        return _ref(pid, 0.8, ["methods uniformly denied"])
    return _ins(pid, ["method matrix incomplete"])


def undoc_endpoint_oracle(evidence: dict, pid: str = "API_UNDOC_SENSITIVE") -> OracleResult:
    if bool(evidence.get("live", False)) and bool(evidence.get("sensitive", False)):
        return _conf(pid, 0.8, ["live sensitive endpoint outside documented surface"])
    if bool(evidence.get("live", False)):
        return _ref(pid, 0.7, ["live but non-sensitive"])
    return _ins(pid, ["liveness unproven"])


# ── Workflow / business logic ─────────────────────────────────────
def workflow_oracle(evidence: dict, pid: str = "BIZ_WORKFLOW_BYPASS") -> OracleResult:
    if bool(evidence.get("bypass_accepted", False)):
        return _conf(pid, 0.85, ["required step omitted yet flow completes"])
    if bool(evidence.get("rejected", False)):
        return _ref(pid, 0.8, ["transition enforced"])
    return _ins(pid, ["transition outcome unknown"])


def quantity_oracle(evidence: dict, pid: str = "BIZ_QUANTITY_MANIPULATION") -> OracleResult:
    if bool(evidence.get("total_altered", False)):
        return _conf(pid, 0.85, ["quantity alters total"])
    if bool(evidence.get("validated", False)):
        return _ref(pid, 0.8, ["quantity validated"])
    return _ins(pid, ["total effect unknown"])


def price_oracle(evidence: dict, pid: str = "BIZ_PRICE_MANIPULATION") -> OracleResult:
    if bool(evidence.get("client_price_accepted", False)):
        return _conf(pid, 0.9, ["client price accepted"])
    if bool(evidence.get("server_pricing", False)):
        return _ref(pid, 0.85, ["server-side pricing"])
    return _ins(pid, ["pricing source unknown"])


# ── Session ───────────────────────────────────────────────────────
def session_invalidation_oracle(evidence: dict, pid: str = "SESSION_INVALIDATION") -> OracleResult:
    if bool(evidence.get("usable_after_logout", False)):
        return _conf(pid, 0.85, ["session usable after logout"])
    if bool(evidence.get("invalidated", False)):
        return _ref(pid, 0.8, ["session invalidated"])
    return _ins(pid, ["logout effect unknown"])


# ── Config ────────────────────────────────────────────────────────
def dir_listing_oracle(evidence: dict, pid: str = "CONFIG_DIR_LISTING") -> OracleResult:
    body = str(evidence.get("body", "")).lower()
    has_markers = ("index of /" in body and ("parent directory" in body or "last modified" in body)) \
        or "directory listing" in body
    has_files = bool(evidence.get("files", []))
    if has_markers and has_files and int(evidence.get("status", 0)) == 200:
        return _conf(pid, 0.9, ["index markers + file entries"])
    if not has_markers:
        return _ref(pid, 0.8, ["no index markers"])
    return _ins(pid, ["markers without file entries"])


def admin_surface_oracle(evidence: dict, pid: str = "CONFIG_ADMIN_EXPOSURE") -> OracleResult:
    status = int(evidence.get("status", 0) or 0)
    if status in (401, 403):
        return _ref(pid, 0.85, [f"admin denied ({status})"])
    if status == 200 and bool(evidence.get("admin_markers", False)):
        return _conf(pid, 0.82, ["admin markers to unauthorized actor"])
    return _ins(pid, ["admin content unverified"])


def debug_oracle(evidence: dict, pid: str = "CONFIG_DEBUG_EXPOSURE") -> OracleResult:
    body = str(evidence.get("body", ""))
    if re.search(r"Traceback|NullPointerException|Fatal error|org\.springframework|at .*\(.*\.java:\d+\)", body):
        return _conf(pid, 0.85, ["diagnostic disclosure"])
    return _ref(pid, 0.75, ["generic error"]) if bool(evidence.get("tested", False)) \
        else _ins(pid, ["untested"])


def backup_oracle(evidence: dict, pid: str = "CONFIG_BACKUP_EXPOSURE") -> OracleResult:
    body = str(evidence.get("body", ""))
    ctype = str(evidence.get("content_type", "")).lower()
    if "<html" in body.lower()[:500] or "html" in ctype:
        return _ref(pid, 0.8, ["HTML, not an artifact"])
    if bool(evidence.get("format_markers", False)) and int(evidence.get("status", 0)) == 200:
        return _conf(pid, 0.9, ["valid artifact syntax"])
    return _ref(pid, 0.7, ["no artifact syntax"]) if bool(evidence.get("tested", False)) \
        else _ins(pid, ["untested"])


def cors_oracle(evidence: dict, pid: str = "CONFIG_CORS") -> OracleResult:
    if bool(evidence.get("origin_reflected", False)) and bool(evidence.get("credentials", False)):
        return _conf(pid, 0.85, ["arbitrary origin + credentials"])
    if bool(evidence.get("tested", False)):
        return _ref(pid, 0.75, ["CORS restricted"])
    return _ins(pid, ["untested"])


def headers_oracle(evidence: dict, pid: str = "CONFIG_HEADERS") -> OracleResult:
    missing = list(evidence.get("missing", []) or [])
    if len(missing) >= 3:
        return _conf(pid, 0.7, [f"missing: {','.join(missing[:5])}"])
    return _ref(pid, 0.7, ["headers present"]) if bool(evidence.get("tested", False)) \
        else _ins(pid, ["untested"])


# ── GraphQL ───────────────────────────────────────────────────────
def graphql_intro_oracle(evidence: dict, pid: str = "GRAPHQL_INTROSPECTION") -> OracleResult:
    if bool(evidence.get("schema_disclosed", False)):
        return _conf(pid, 0.85, ["full schema disclosed"])
    if bool(evidence.get("disabled", False)):
        return _ref(pid, 0.85, ["introspection disabled"])
    return _ins(pid, ["introspection untested"])


def graphql_authz_oracle(evidence: dict, pid: str = "GRAPHQL_AUTHZ") -> OracleResult:
    return bola_oracle(evidence, pid)


# ── Infra ─────────────────────────────────────────────────────────
def exposed_service_oracle(evidence: dict, pid: str = "INFRA_EXPOSED_SERVICE") -> OracleResult:
    if bool(evidence.get("anonymous_access", False)) and bool(evidence.get("sensitive", False)):
        return _conf(pid, 0.88, ["sensitive service reachable without auth"])
    if bool(evidence.get("auth_required", False)):
        return _ref(pid, 0.8, ["auth required"])
    return _ins(pid, ["access state unknown"])


def known_vuln_oracle(evidence: dict, pid: str = "INFRA_KNOWN_VULN_COMPONENT") -> OracleResult:
    if bool(evidence.get("version_match", False)) and bool(evidence.get("intel_match", False)) \
            and bool(evidence.get("service_confirmed", False)):
        return _conf(pid, 0.85, ["versioned product + intel match on confirmed service"])
    if bool(evidence.get("version_mismatch", False)):
        return _ref(pid, 0.8, ["version mismatch"])
    return _ins(pid, ["version/intel unproven"])


def registration_jwt_oracle(evidence: dict,
                              pid: str = "UNAUTHENTICATED_AUTHENTICATION_MATERIAL_ISSUANCE") -> OracleResult:
    if bool(evidence.get("registered_2xx", False)) and bool(evidence.get("jwt_valid", False)) \
            and bool(evidence.get("verified_use", False)):
        return _conf(pid, 0.93, ["anonymous registration 2xx", "structurally valid JWT",
                                 "token verified on protected resource"])
    if bool(evidence.get("registered_2xx", False)) and bool(evidence.get("jwt_valid", False)):
        return _ins(pid, ["JWT issued but protected-use unverified"])
    if bool(evidence.get("tested", False)):
        return _ref(pid, 0.7, ["no usable token issued"])
    return _ins(pid, ["registration flow untested"])


def rate_limit_oracle(evidence: dict, pid: str = "RATE_LIMIT_DEFICIENCY") -> OracleResult:
    if bool(evidence.get("throttled", False)):
        return _ref(pid, 0.8, ["throttle signal observed"])
    if int(evidence.get("attempts", 0) or 0) >= 10 and bool(evidence.get("all_accepted", False)):
        return _conf(pid, 0.8, [f"bounded burst of {evidence['attempts']} accepted without throttle"])
    if bool(evidence.get("tested", False)):
        return _ref(pid, 0.7, ["throttling present"])
    return _ins(pid, ["rate behavior untested"])


def keepass_oracle(evidence: dict, pid: str = "FILE_KEEPASS_EXPOSURE") -> OracleResult:
    if bool(evidence.get("reachable", False)) and str(evidence.get("magic", "")) == "keepass-kdbx":
        return _conf(pid, 0.9, ["KDBX magic bytes in anonymously downloadable artifact"])
    if bool(evidence.get("tested", False)) or bool(evidence.get("reachable", False)):
        return _ref(pid, 0.75, ["no magic signature"])
    return _ins(pid, ["artifact untested"])


def weak_crypto_oracle(evidence: dict, pid: str = "WEAK_CRYPTO_RECOVERY") -> OracleResult:
    if bool(evidence.get("recovered", False)):
        return _conf(pid, 0.82, ["opaque blob deterministically recovered"])
    if bool(evidence.get("tested", False)) or "recovered" in evidence:
        return _ref(pid, 0.7, ["recovery attempted, nothing recovered"])
    return _ins(pid, ["recovery untested"])


ORACLES = {
    "sqli_oracle": sqli_oracle,
    "nosql_oracle": nosql_oracle,
    "cmdi_oracle": cmdi_oracle,
    "ssti_oracle": ssti_oracle,
    "ldap_oracle": ldap_oracle,
    "xpath_oracle": xpath_oracle,
    "xss_oracle": xss_oracle,
    "xss_stored_oracle": xss_stored_oracle,
    "dom_oracle": dom_oracle,
    "redirect_oracle": redirect_oracle,
    "traversal_oracle": traversal_oracle,
    "upload_oracle": upload_oracle,
    "ssrf_oracle": ssrf_oracle,
    "authn_unauth_oracle": authn_unauth_oracle,
    "authn_bypass_oracle": authn_bypass_oracle,
    "session_fixation_oracle": session_fixation_oracle,
    "authn_weak_oracle": authn_weak_oracle,
    "secret_exposure_oracle": secret_exposure_oracle,
    "bola_oracle": bola_oracle,
    "vertical_oracle": vertical_oracle,
    "excessive_data_oracle": excessive_data_oracle,
    "mass_assignment_oracle": mass_assignment_oracle,
    "method_auth_oracle": method_auth_oracle,
    "undoc_endpoint_oracle": undoc_endpoint_oracle,
    "workflow_oracle": workflow_oracle,
    "quantity_oracle": quantity_oracle,
    "price_oracle": price_oracle,
    "session_invalidation_oracle": session_invalidation_oracle,
    "dir_listing_oracle": dir_listing_oracle,
    "admin_surface_oracle": admin_surface_oracle,
    "debug_oracle": debug_oracle,
    "backup_oracle": backup_oracle,
    "cors_oracle": cors_oracle,
    "headers_oracle": headers_oracle,
    "graphql_intro_oracle": graphql_intro_oracle,
    "graphql_authz_oracle": graphql_authz_oracle,
    "exposed_service_oracle": exposed_service_oracle,
    "known_vuln_oracle": known_vuln_oracle,
    "registration_jwt_oracle": registration_jwt_oracle,
    "rate_limit_oracle": rate_limit_oracle,
    "keepass_oracle": keepass_oracle,
    "weak_crypto_oracle": weak_crypto_oracle,
}


def evaluate(property_id: str, evidence: dict) -> OracleResult:
    """Evaluate evidence against the property's oracle. No AI."""
    from horcrux.engine.properties import get_property
    prop = get_property(property_id)
    if prop is None:
        return OracleResult(verdict="INSUFFICIENT", confidence=0.0,
                            evidence=[f"unknown property {property_id}"],
                            property_id=property_id)
    fn = ORACLES.get(prop.oracle)
    if fn is None:
        return OracleResult(verdict="INSUFFICIENT", confidence=0.0,
                            evidence=[f"oracle not implemented: {prop.oracle}"],
                            property_id=property_id)
    try:
        return fn(evidence, property_id)
    except OracleBlocked as blocked:
        return OracleResult(verdict="BLOCKED", confidence=0.5,
                            evidence=[f"blocked: {blocked.reason}"],
                            property_id=property_id)
