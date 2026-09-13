from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Callable, Optional, Sequence
from urllib.parse import urljoin

import httpx

from horcrux.models import AuditStatus, Finding, Severity, ValidationState


@dataclass
class BaselineFingerprint:
    status_code: int
    content_length: int
    content_type: str
    title: str
    body_hash: str
    is_spa: bool = False
    is_catchall_200: bool = False
    server_header: str = ""
    redirect_location: str = ""

    @classmethod
    def analyze(cls, response: httpx.Response) -> "BaselineFingerprint":
        text = response.text
        headers = response.headers
        content_type = headers.get("content-type", "").lower()
        title_match = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
        title = re.sub(r"\s+", " ", title_match.group(1)).strip() if title_match else ""

        body_hash = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
        is_catchall = response.status_code == 200

        # SPA detection heuristic
        is_spa = False
        if response.status_code == 200 and "html" in content_type:
            spa_indicators = [
                r'<div id=["\'](?:app|root|main)["\']',
                r'<noscript>.*?(?:enable javascript|requires javascript)',
                r'<script[^>]*src=["\'][^"\']*(?:main|app|bundle|chunk|runtime|vendor)[^"\']*\.js["\']',
                r'ng-app|data-reactroot|data-v-[a-f0-9]+',
            ]
            if any(re.search(pat, text, re.I | re.S) for pat in spa_indicators):
                is_spa = True

        return cls(
            status_code=response.status_code,
            content_length=len(text),
            content_type=content_type,
            title=title,
            body_hash=body_hash,
            is_spa=is_spa,
            is_catchall_200=is_catchall,
            server_header=headers.get("server", ""),
            redirect_location=headers.get("location", ""),
        )

    def is_similar(self, response: httpx.Response) -> bool:
        """Determines if a response is structurally identical to the baseline non-existent response."""
        if response.status_code != self.status_code:
            return False

        resp_text = response.text
        resp_hash = hashlib.sha256(resp_text.encode("utf-8", errors="replace")).hexdigest()
        if resp_hash == self.body_hash:
            return True

        # Check for matching title and length similarity within 15%
        title_match = re.search(r"<title[^>]*>(.*?)</title>", resp_text, re.I | re.S)
        resp_title = re.sub(r"\s+", " ", title_match.group(1)).strip() if title_match else ""
        if self.title and resp_title and self.title.lower() == resp_title.lower():
            diff = abs(len(resp_text) - self.content_length)
            if self.content_length > 0 and (diff / self.content_length) < 0.15:
                return True

        # Catchall 200 / SPA fallback matching
        if self.is_catchall_200 and ("html" in response.headers.get("content-type", "").lower()):
            diff = abs(len(resp_text) - self.content_length)
            if self.content_length > 0 and (diff / self.content_length) < 0.05:
                return True

        return False


@dataclass
class ValidationResult:
    is_valid: bool
    confidence: float
    validation_state: ValidationState
    evidence: list[str]
    why_it_matters: str = ""
    recommended_next_action: str = ""
    audit_status: AuditStatus = AuditStatus.audited
    reproduction: list[str] = field(default_factory=list)


# Pluggable content validator callback signature
ContentValidatorFn = Callable[[httpx.Response, BaselineFingerprint], ValidationResult]


@dataclass
class EndpointValidator:
    """Pluggable definition for arbitrary endpoint evaluation."""
    path: str
    category: str
    severity: Severity
    validator_fn: ContentValidatorFn
    title: str = ""
    description: str = ""


# ---------------------------------------------------------------------------
# BUILT-IN PLUGGABLE VALIDATORS
# ---------------------------------------------------------------------------

def validate_env_content(response: httpx.Response, baseline: BaselineFingerprint) -> ValidationResult:
    """Validates real .env syntax; strictly rejects HTML error or SPA pages."""
    if response.status_code != 200 or baseline.is_similar(response):
        return ValidationResult(
            is_valid=False,
            confidence=0.0,
            validation_state=ValidationState.false_positive,
            audit_status=AuditStatus.hardened,
            evidence=["Filtered out by baseline similarity or non-200."],
        )

    text = response.text
    content_type = response.headers.get("content-type", "").lower()

    if "html" in content_type or "<html" in text.lower() or "<body" in text.lower():
        return ValidationResult(
            is_valid=False,
            confidence=0.0,
            validation_state=ValidationState.false_positive,
            audit_status=AuditStatus.hardened,
            evidence=["Path returned HTML document instead of key-value configuration."],
        )

    # Must contain lines that look like KEY=VALUE or comments with variables
    env_lines = []
    lines = text.strip().splitlines()
    for line in lines[:50]:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if re.match(r"^[A-Za-z0-9_]{2,64}\s*=\s*.*$", line):
            # Check if key is a common config pattern
            env_lines.append(line.split("=")[0].strip())

    if len(env_lines) >= 2:
        return ValidationResult(
            is_valid=True,
            confidence=0.99,
            validation_state=ValidationState.confirmed,
            audit_status=AuditStatus.suspicious,
            evidence=[
                "Valid environment configuration file syntax confirmed.",
                f"Discovered configuration keys: {', '.join(env_lines[:5])}",
            ],
            why_it_matters="Exposes critical application secrets, database credentials, API tokens, and private keys.",
            recommended_next_action="Inspect variables for credentials without dumping the entire file to terminal.",
        )
    elif len(env_lines) == 1:
        return ValidationResult(
            is_valid=True,
            confidence=0.75,
            validation_state=ValidationState.likely,
            audit_status=AuditStatus.suspicious,
            evidence=[f"Potential single key-value environment line found: {env_lines[0]}"],
            why_it_matters="May expose application configuration or credential definitions.",
            recommended_next_action="Review endpoint manually to verify syntax.",
        )

    return ValidationResult(
        is_valid=False,
        confidence=0.1,
        validation_state=ValidationState.false_positive,
        audit_status=AuditStatus.hardened,
        evidence=["HTTP 200 returned but content does not match environment file structure."],
    )


def validate_git_head(response: httpx.Response, baseline: BaselineFingerprint) -> ValidationResult:
    """Validates real Git HEAD syntax (ref: refs/heads/... or 40-char SHA); rejects HTML/catch-all."""
    if response.status_code != 200 or baseline.is_similar(response):
        return ValidationResult(
            is_valid=False,
            confidence=0.0,
            validation_state=ValidationState.false_positive,
            audit_status=AuditStatus.hardened,
            evidence=["Filtered out by baseline similarity or non-200."],
        )

    text = response.text.strip()
    if re.match(r"^ref:\s*refs/heads/[A-Za-z0-9_.-]+", text) or re.match(r"^[0-9a-f]{40}$", text):
        return ValidationResult(
            is_valid=True,
            confidence=0.99,
            validation_state=ValidationState.confirmed,
            audit_status=AuditStatus.suspicious,
            evidence=[f"Valid Git repository HEAD structure verified: '{text[:40]}'"],
            why_it_matters="Exposes internal Git repository metadata, commit history, and source code.",
            recommended_next_action="Inspect Git tree objects and commit history for hardcoded secrets.",
        )

    return ValidationResult(
        is_valid=False,
        confidence=0.0,
        validation_state=ValidationState.false_positive,
        audit_status=AuditStatus.hardened,
        evidence=["HTTP 200 returned but content does not match Git HEAD record."],
    )


def validate_passwd_content(response: httpx.Response, baseline: BaselineFingerprint) -> ValidationResult:
    """Validates Unix /etc/passwd record structure."""
    if response.status_code != 200 or baseline.is_similar(response):
        return ValidationResult(
            is_valid=False,
            confidence=0.0,
            validation_state=ValidationState.false_positive,
            audit_status=AuditStatus.hardened,
            evidence=["Filtered out by baseline similarity or non-200."],
        )

    text = response.text
    # Expect root:x:0:0:... or bin:x:1:1:...
    passwd_matches = re.findall(r"^[a-zA-Z0-9_.-]+:[^:]*:\d+:\d+:[^:]*:[^:]*:[^:\r\n]*$", text, re.M)
    if passwd_matches:
        return ValidationResult(
            is_valid=True,
            confidence=0.99,
            validation_state=ValidationState.confirmed,
            audit_status=AuditStatus.suspicious,
            evidence=[
                f"Discovered {len(passwd_matches)} valid Unix passwd format user account records.",
                f"First entry: {passwd_matches[0]}",
            ],
            why_it_matters="Arbitrary local file disclosure exposes all local system user accounts and shell paths.",
            recommended_next_action="Map system users for credential testing and investigate /etc/shadow or SSH keys.",
        )

    return ValidationResult(
        is_valid=False,
        confidence=0.0,
        validation_state=ValidationState.false_positive,
        audit_status=AuditStatus.hardened,
        evidence=["HTTP 200 returned but content does not match /etc/passwd record format."],
    )


def validate_admin_surface(response: httpx.Response, baseline: BaselineFingerprint) -> ValidationResult:
    """Validates administrative interface; rejects generic 200/SPA catch-all."""
    if baseline.is_similar(response):
        return ValidationResult(
            is_valid=False,
            confidence=0.0,
            validation_state=ValidationState.false_positive,
            audit_status=AuditStatus.hardened,
            evidence=["Endpoint returned baseline catch-all error/SPA response."],
        )

    status = response.status_code
    text = response.text.lower()

    if status in {401, 403}:
        return ValidationResult(
            is_valid=False,
            confidence=0.85,
            validation_state=ValidationState.potential,
            audit_status=AuditStatus.audited,
            evidence=[f"Administrative path restricted with HTTP {status}."],
            why_it_matters="Identifies privileged administrative boundary requiring authentication.",
            recommended_next_action="Inspect authentication mechanism and check for authorization bypasses.",
        )

    if status == 200:
        admin_tokens = [
            r"\badmin(?:istrator)?\b",
            r"\bdashboard\b",
            r"\bcontrol panel\b",
            r"\bmanagement\b",
            r"\blogin\b",
            r'type=["\']password["\']',
            r"\bsign in\b",
        ]
        matches = [t for t in admin_tokens if re.search(t, text)]
        if len(matches) >= 2:
            return ValidationResult(
                is_valid=True,
                confidence=0.90,
                validation_state=ValidationState.confirmed,
                audit_status=AuditStatus.suspicious,
                evidence=[
                    "Administrative interface content verified.",
                    f"Matched administrative indicators: {', '.join(matches)}",
                ],
                why_it_matters="Exposed administrative control panel interface accessible without or before authorization.",
                recommended_next_action="Inspect authentication controls and default credential combinations.",
            )
        elif len(matches) == 1:
            return ValidationResult(
                is_valid=True,
                confidence=0.65,
                validation_state=ValidationState.potential,
                audit_status=AuditStatus.suspicious,
                evidence=[f"Weak administrative keyword match: {matches[0]}"],
                why_it_matters="Potential administrative surface; requires manual verification.",
                recommended_next_action="Manual operator review of administrative interface.",
            )

    return ValidationResult(
        is_valid=False,
        confidence=0.1,
        validation_state=ValidationState.false_positive,
        audit_status=AuditStatus.hardened,
        evidence=[f"HTTP {status} returned without administrative markers."],
    )


def validate_robots_content(response: httpx.Response, baseline: BaselineFingerprint) -> ValidationResult:
    """Validates robots.txt formatting."""
    if response.status_code != 200 or baseline.is_similar(response):
        return ValidationResult(
            is_valid=False,
            confidence=0.0,
            validation_state=ValidationState.false_positive,
            audit_status=AuditStatus.hardened,
            evidence=["Filtered out by baseline similarity or non-200."],
        )

    text = response.text
    if re.search(r"(?im)^\s*(?:user-agent|disallow|allow|sitemap)\s*:", text):
        disallows = re.findall(r"(?im)^\s*disallow\s*:\s*(\S+)", text)
        return ValidationResult(
            is_valid=True,
            confidence=0.99,
            validation_state=ValidationState.confirmed,
            audit_status=AuditStatus.audited,
            evidence=[
                "Valid robots.txt discovered.",
                f"Disallowed entries ({len(disallows)}): {', '.join(disallows[:5])}",
            ],
            why_it_matters="Discloses hidden paths, administrative consoles, or developer assets intended to be unindexed.",
            recommended_next_action="Investigate paths disclosed in Disallow directives.",
        )

    return ValidationResult(
        is_valid=False,
        confidence=0.0,
        validation_state=ValidationState.false_positive,
        audit_status=AuditStatus.hardened,
        evidence=["HTTP 200 returned but file does not contain robots directives."],
    )


def validate_sitemap_content(response: httpx.Response, baseline: BaselineFingerprint) -> ValidationResult:
    """Validates sitemap.xml structure."""
    if response.status_code != 200 or baseline.is_similar(response):
        return ValidationResult(
            is_valid=False,
            confidence=0.0,
            validation_state=ValidationState.false_positive,
            audit_status=AuditStatus.hardened,
            evidence=["Filtered out by baseline similarity or non-200."],
        )
    text = response.text
    if ("<urlset" in text or "<sitemapindex" in text) and "<loc>" in text:
        locs = re.findall(r"<loc>(.*?)</loc>", text, re.I)
        return ValidationResult(
            is_valid=True,
            confidence=0.95,
            validation_state=ValidationState.confirmed,
            audit_status=AuditStatus.audited,
            evidence=[f"Discovered sitemap XML with {len(locs)} declared URL endpoints."],
            why_it_matters="Exposes full list of indexable site routes and application endpoints.",
            recommended_next_action="Add extracted sitemap endpoints to discovery queue.",
        )
    return ValidationResult(
        is_valid=False,
        confidence=0.0,
        validation_state=ValidationState.false_positive,
        audit_status=AuditStatus.hardened,
        evidence=["Response does not match XML sitemap schema."],
    )


def validate_backup_content(response: httpx.Response, baseline: BaselineFingerprint) -> ValidationResult:
    """Validates database dump / backup file indicators; rejects HTML catchall."""
    if response.status_code != 200 or baseline.is_similar(response):
        return ValidationResult(
            is_valid=False,
            confidence=0.0,
            validation_state=ValidationState.false_positive,
            audit_status=AuditStatus.hardened,
            evidence=["Filtered out by baseline similarity or non-200."],
        )
    text = response.text
    if "<html" in text.lower():
        return ValidationResult(
            is_valid=False,
            confidence=0.0,
            validation_state=ValidationState.false_positive,
            audit_status=AuditStatus.hardened,
            evidence=["Path returned HTML error page."],
        )
    # Check for SQL statements
    if re.search(r"(?i)\b(?:CREATE\s+TABLE|INSERT\s+INTO|DROP\s+TABLE)\b", text):
        return ValidationResult(
            is_valid=True,
            confidence=0.98,
            validation_state=ValidationState.confirmed,
            audit_status=AuditStatus.suspicious,
            evidence=["Valid SQL dump syntax detected with table/insert statements."],
            why_it_matters="Database backup file exposed publicly; leaks database schema and table contents.",
            recommended_next_action="Remove public exposure immediately and audit disclosed data.",
        )
    return ValidationResult(
        is_valid=False,
        confidence=0.0,
        validation_state=ValidationState.false_positive,
        audit_status=AuditStatus.hardened,
        evidence=["Response does not contain backup or SQL structure."],
    )


def validate_phpinfo_content(response: httpx.Response, baseline: BaselineFingerprint) -> ValidationResult:
    """Validates phpinfo disclosure."""
    if response.status_code != 200 or baseline.is_similar(response):
        return ValidationResult(
            is_valid=False,
            confidence=0.0,
            validation_state=ValidationState.false_positive,
            audit_status=AuditStatus.hardened,
            evidence=["Filtered out by baseline similarity or non-200."],
        )
    text = response.text
    if "php version" in text.lower() and ("configuration file (php.ini)" in text.lower() or "zend extension build" in text.lower()):
        return ValidationResult(
            is_valid=True,
            confidence=0.99,
            validation_state=ValidationState.confirmed,
            audit_status=AuditStatus.suspicious,
            evidence=["PHP diagnostic phpinfo() output verified."],
            why_it_matters="Discloses complete PHP runtime configuration, modules, and server environment variables.",
            recommended_next_action="Disable or restrict phpinfo diagnostics.",
        )
    return ValidationResult(
        is_valid=False,
        confidence=0.0,
        validation_state=ValidationState.false_positive,
        audit_status=AuditStatus.hardened,
        evidence=["Response does not match phpinfo structure."],
    )


def validate_directory_listing(response: httpx.Response, baseline: BaselineFingerprint) -> ValidationResult:
    """Validates automatic directory listing / index exposure."""
    if response.status_code != 200 or baseline.is_similar(response):
        return ValidationResult(
            is_valid=False,
            confidence=0.0,
            validation_state=ValidationState.false_positive,
            audit_status=AuditStatus.hardened,
            evidence=["Filtered out by baseline similarity or non-200."],
        )
    text = response.text
    if re.search(r"<title>\s*Index of\s+[^<]+</title>", text, re.I) or (
        "index of /" in text.lower() and ("parent directory" in text.lower() or "last modified" in text.lower())
    ):
        return ValidationResult(
            is_valid=True,
            confidence=0.98,
            validation_state=ValidationState.confirmed,
            audit_status=AuditStatus.suspicious,
            evidence=["Directory indexing header ('Index of /') detected on live endpoint."],
            why_it_matters="Directory listing allows unauthenticated mapping of file trees, hidden scripts, and backup artifacts.",
            recommended_next_action="Disable Options -Indexes on web server configuration.",
        )
    return ValidationResult(
        is_valid=False,
        confidence=0.0,
        validation_state=ValidationState.false_positive,
        audit_status=AuditStatus.hardened,
        evidence=["Response is not a directory listing."],
    )


def validate_swagger_openapi(response: httpx.Response, baseline: BaselineFingerprint) -> ValidationResult:
    """Validates interactive Swagger UI or raw OpenAPI schema."""
    if response.status_code != 200 or baseline.is_similar(response):
        return ValidationResult(
            is_valid=False,
            confidence=0.0,
            validation_state=ValidationState.false_positive,
            audit_status=AuditStatus.hardened,
            evidence=["Filtered out by baseline similarity or non-200."],
        )
    text = response.text.lower()
    if "swagger-ui" in text or '"openapi":' in text or '"swagger":' in text or "swaggerui" in text:
        return ValidationResult(
            is_valid=True,
            confidence=0.95,
            validation_state=ValidationState.confirmed,
            audit_status=AuditStatus.suspicious,
            evidence=["Interactive API documentation interface (Swagger/OpenAPI) verified."],
            why_it_matters="Discloses complete internal API endpoint catalog, parameters, authentication schemes, and schemas.",
            recommended_next_action="Review disclosed API routes for authorization controls and restrict public access.",
        )
    return ValidationResult(
        is_valid=False,
        confidence=0.0,
        validation_state=ValidationState.false_positive,
        audit_status=AuditStatus.hardened,
        evidence=["Response does not match Swagger/OpenAPI documentation."],
    )


def validate_actuator_content(response: httpx.Response, baseline: BaselineFingerprint) -> ValidationResult:
    """Validates Spring Boot Actuator endpoint exposure."""
    if response.status_code != 200 or baseline.is_similar(response):
        return ValidationResult(
            is_valid=False,
            confidence=0.0,
            validation_state=ValidationState.false_positive,
            audit_status=AuditStatus.hardened,
            evidence=["Filtered out by baseline similarity or non-200."],
        )
    text = response.text.lower()
    if "_links" in text and ("actuator" in text or "health" in text or "beans" in text or "env" in text):
        return ValidationResult(
            is_valid=True,
            confidence=0.98,
            validation_state=ValidationState.confirmed,
            audit_status=AuditStatus.suspicious,
            evidence=["Spring Boot Actuator discovery JSON navigation links confirmed."],
            why_it_matters="Actuator endpoints frequently expose internal JVM state, heap dumps, environment secrets, and config properties.",
            recommended_next_action="Restrict management.endpoints.web.exposure.include to authenticated admin perimeters.",
        )
    return ValidationResult(
        is_valid=False,
        confidence=0.0,
        validation_state=ValidationState.false_positive,
        audit_status=AuditStatus.hardened,
        evidence=["Response does not match Spring Boot Actuator format."],
    )


def validate_graphql_content(response: httpx.Response, baseline: BaselineFingerprint) -> ValidationResult:
    """Validates GraphQL endpoint exposure."""
    if baseline.is_similar(response):
        return ValidationResult(
            is_valid=False,
            confidence=0.0,
            validation_state=ValidationState.false_positive,
            audit_status=AuditStatus.hardened,
            evidence=["Filtered out by baseline similarity."],
        )
    text = response.text.lower()
    if response.status_code in {200, 400} and ("graphql" in text or "must provide query string" in text or "graphiql" in text):
        return ValidationResult(
            is_valid=True,
            confidence=0.92,
            validation_state=ValidationState.confirmed,
            audit_status=AuditStatus.suspicious,
            evidence=["GraphQL service endpoint or interactive GraphiQL playground detected."],
            why_it_matters="Allows querying internal object graphs; introspection queries may disclose full data models.",
            recommended_next_action="Run introspection query check and ensure field authorization is strictly enforced.",
        )
    return ValidationResult(
        is_valid=False,
        confidence=0.0,
        validation_state=ValidationState.false_positive,
        audit_status=AuditStatus.hardened,
        evidence=["Endpoint does not behave as GraphQL interface."],
    )


def validate_generic_candidate(path: str, response: httpx.Response, baseline: BaselineFingerprint) -> ValidationResult:
    """
    Universal validator for arbitrary paths discovered by fuzzing/wordlist brute-forcing.
    Detects soft-404s, directory listings, credentials, backups, debug dumps, and normal surface items.
    """
    # 1. Soft-404 / baseline check
    if baseline.is_similar(response):
        return ValidationResult(
            is_valid=False,
            confidence=0.0,
            validation_state=ValidationState.false_positive,
            audit_status=AuditStatus.hardened,
            evidence=[f"Suppressed: response for '{path}' is structurally identical to baseline non-existent path."],
        )

    # 2. Status code classification
    if response.status_code in {401, 403}:
        return ValidationResult(
            is_valid=False,
            confidence=0.0,
            validation_state=ValidationState.false_positive,
            audit_status=AuditStatus.hardened,
            evidence=[f"HTTP {response.status_code} Access Denied on '{path}'; endpoint protected."],
        )

    if response.status_code >= 500:
        # Check for stack trace disclosure
        text = response.text
        if any(err in text for err in ["Traceback (most recent call last):", "NullPointerException", "Fatal error:", "org.springframework."]):
            return ValidationResult(
                is_valid=True,
                confidence=0.90,
                validation_state=ValidationState.confirmed,
                audit_status=AuditStatus.suspicious,
                evidence=[f"Stack trace or debug exception revealed on HTTP {response.status_code} error page."],
                why_it_matters="Application crash dumps disclose internal filenames, line numbers, frameworks, and backend configurations.",
                recommended_next_action="Implement custom error pages and disable display_errors / debug modes.",
            )
        return ValidationResult(
            is_valid=False,
            confidence=0.0,
            validation_state=ValidationState.false_positive,
            audit_status=AuditStatus.hardened,
            evidence=[f"HTTP {response.status_code} server error returned without diagnostic disclosure."],
        )

    # 3. Check for Directory Listing
    dir_res = validate_directory_listing(response, baseline)
    if dir_res.is_valid:
        return dir_res

    # 4. Check for SQL Dump or Database Backup
    if path.endswith((".sql", ".sql.gz", ".sql.bak")):
        return validate_backup_content(response, baseline)

    # 5. Check for Environment or Version Control file
    if path.endswith((".env", ".env.local", ".env.production", ".env.bak")):
        return validate_env_content(response, baseline)
    if ".git" in path:
        return validate_git_head(response, baseline)

    # 6. Check for Disclosed Secrets / Hardcoded Credentials in Response
    text = response.text
    cred_match = re.search(
        r'(?i)\b(?:api[_-]?key|secret[_-]?key|aws[_-]?secret|jwt[_-]?token|db[_-]?password)\s*[:=]\s*["\']?([A-Za-z0-9_\-./+=]{8,})',
        text,
    )
    if cred_match and "<html" not in text[:200].lower():
        return ValidationResult(
            is_valid=True,
            confidence=0.92,
            validation_state=ValidationState.confirmed,
            audit_status=AuditStatus.suspicious,
            evidence=[f"Sensitive key or credential pattern disclosed in '{path}': {cred_match.group(0)[:60]}..."],
            why_it_matters="Exposed secrets allow unauthorized privilege escalation, API access, or database hijacking.",
            recommended_next_action="Rotate disclosed secret immediately and restrict access to asset.",
        )

    # 7. Otherwise, legitimate live attack surface observation
    return ValidationResult(
        is_valid=False,
        confidence=0.0,
        validation_state=ValidationState.unverified,
        audit_status=AuditStatus.audited,
        evidence=[f"Live endpoint '{path}' (HTTP {response.status_code}, {len(response.text)} bytes) mapped to attack surface."],
    )


class ValidatorRegistry:
    """Universal, pluggable registry for endpoint validation."""

    def __init__(self):
        self._validators: dict[str, EndpointValidator] = {}
        self._register_defaults()

    def register(self, validator: EndpointValidator) -> None:
        self._validators[validator.path.lower()] = validator

    def get(self, path: str) -> Optional[EndpointValidator]:
        return self._validators.get(path.lower())

    def all_validators(self) -> list[EndpointValidator]:
        return list(self._validators.values())

    def _register_defaults(self):
        self.register(
            EndpointValidator(
                path="/.env",
                category="web-file-exposure",
                severity=Severity.high,
                validator_fn=validate_env_content,
                title="Exposed environment configuration file",
                description="Configuration file leaking sensitive environment variables",
            )
        )
        self.register(
            EndpointValidator(
                path="/.git/HEAD",
                category="web-file-exposure",
                severity=Severity.high,
                validator_fn=validate_git_head,
                title="Exposed Git repository metadata",
                description="Version control metadata allowing source code recovery",
            )
        )
        self.register(
            EndpointValidator(
                path="/etc/passwd",
                category="local-file-inclusion",
                severity=Severity.critical,
                validator_fn=validate_passwd_content,
                title="Arbitrary file disclosure (/etc/passwd)",
                description="Sensitive operating system user database exposed",
            )
        )
        self.register(
            EndpointValidator(
                path="/admin",
                category="web-discovery",
                severity=Severity.medium,
                validator_fn=validate_admin_surface,
                title="Administrative interface surface",
                description="Privileged administrative control surface discovered",
            )
        )
        self.register(
            EndpointValidator(
                path="/robots.txt",
                category="web-information-disclosure",
                severity=Severity.info,
                validator_fn=validate_robots_content,
                title="Web crawlers policy (robots.txt)",
                description="Information disclosure via crawler exclusions",
            )
        )
        self.register(
            EndpointValidator(
                path="/sitemap.xml",
                category="web-information-disclosure",
                severity=Severity.info,
                validator_fn=validate_sitemap_content,
                title="XML Sitemap discovery",
                description="Discloses application endpoint index",
            )
        )
        self.register(
            EndpointValidator(
                path="/backup.sql",
                category="web-file-exposure",
                severity=Severity.high,
                validator_fn=validate_backup_content,
                title="Database backup file exposure",
                description="Publicly exposed database backup file",
            )
        )
        self.register(
            EndpointValidator(
                path="/phpinfo.php",
                category="web-information-disclosure",
                severity=Severity.medium,
                validator_fn=validate_phpinfo_content,
                title="PHP configuration info disclosure",
                description="Diagnostic phpinfo script publicly accessible",
            )
        )
        self.register(
            EndpointValidator(
                path="/swagger-ui.html",
                category="web-information-disclosure",
                severity=Severity.low,
                validator_fn=validate_swagger_openapi,
                title="Interactive Swagger UI documentation",
                description="Public API schema interface exposed",
            )
        )
        self.register(
            EndpointValidator(
                path="/actuator",
                category="web-information-disclosure",
                severity=Severity.medium,
                validator_fn=validate_actuator_content,
                title="Spring Boot Actuator endpoints",
                description="Diagnostic framework endpoints exposed",
            )
        )
        self.register(
            EndpointValidator(
                path="/graphql",
                category="web-discovery",
                severity=Severity.low,
                validator_fn=validate_graphql_content,
                title="GraphQL service endpoint",
                description="GraphQL schema query interface discovered",
            )
        )


