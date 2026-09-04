from __future__ import annotations

import abc
import json
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Generator, Optional

from horcrux.core.sanitizer import redact_secrets
from horcrux.core.settings import CredentialInfo, DEFAULT_MODELS, ProviderConfig, SettingsManager


HORCRUX_EVIDENCE_POLICY = """You are HORCRUX AI, an expert senior offensive-security reasoning analyst.
STRICT EVIDENCE RULES:
1. Use ONLY supplied evidence from the operator's workspace.
2. Do NOT invent versions, services, credentials, CVEs, exploit success, or vulnerabilities.
3. Clearly distinguish direct observation from inference.
4. If evidence is insufficient or ambiguous, explicitly state that.
5. Never promote unverified evidence or hypothetical exploits to CONFIRMED status without deterministic evidence.
6. Present reasoning using the structure:
   OBSERVATION: <exact evidence from scan>
   REASONING: <technical impact or prerequisite check>
   RECOMMENDATION: <prioritized, actionable next step>
"""


class AIErrorType(str, Enum):
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    MODEL_NOT_FOUND = "MODEL_NOT_FOUND"
    MODEL_UNAVAILABLE = "MODEL_UNAVAILABLE"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    RATE_LIMITED = "RATE_LIMITED"
    QUOTA_EXCEEDED = "QUOTA_EXCEEDED"
    BAD_REQUEST = "BAD_REQUEST"
    INVALID_RESPONSE = "INVALID_RESPONSE"
    TIMEOUT = "TIMEOUT"
    NETWORK_ERROR = "NETWORK_ERROR"
    PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
    UNSUPPORTED_FEATURE = "UNSUPPORTED_FEATURE"
    SAFETY_BLOCK = "SAFETY_BLOCK"
    CONFIGURATION_ERROR = "CONFIGURATION_ERROR"


class AIError(Exception):
    def __init__(
        self,
        error_type: AIErrorType,
        message: str,
        suggested_action: str = "",
        provider: str = "",
        raw_status: int | None = None,
    ):
        clean_msg = redact_secrets(message)
        clean_hint = redact_secrets(suggested_action)
        super().__init__(clean_msg)
        self.error_type = error_type
        self.message = clean_msg
        self.suggested_action = clean_hint
        self.provider = provider
        self.raw_status = raw_status

    def __str__(self) -> str:
        prov = f"[{self.provider.upper()}] " if self.provider else ""
        return f"{prov}{self.error_type.value}: {self.message}"


@dataclass
class ModelInfo:
    id: str
    name: str = ""
    context_window: int = 0
    max_output_tokens: int = 0
    supports_structured: bool = True
    supports_streaming: bool = True
    description: str = ""

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, str):
            return self.id == other or self.name == other
        if isinstance(other, ModelInfo):
            return self.id == other.id
        return False

    def __str__(self) -> str:
        return self.id


@dataclass
class ProviderCapabilities:
    supports_model_listing: bool = True
    supports_streaming: bool = True
    supports_system_prompt: bool = True
    supports_usage_metadata: bool = True
    supports_reasoning_metadata: bool = False


@dataclass
class AIResponse:
    content: str
    structured: Any = None
    prompt_tokens: int = 0
    completion_tokens: int = 0
    reasoning_tokens: int = 0
    total_tokens: int = 0
    model: str = ""
    provider: str = ""
    latency: float = 0.0
    request_id: str = ""
    cached: bool = False
    finish_reason: str = ""
    raw_metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def text(self) -> str:
        """Standard property returning generated text content."""
        return self.content

    @text.setter
    def text(self, val: str) -> None:
        self.content = val

    @property
    def input_tokens(self) -> int:
        return self.prompt_tokens

    @input_tokens.setter
    def input_tokens(self, val: int) -> None:
        self.prompt_tokens = val

    @property
    def output_tokens(self) -> int:
        return self.completion_tokens

    @output_tokens.setter
    def output_tokens(self, val: int) -> None:
        self.completion_tokens = val

    @property
    def latency_ms(self) -> int:
        return int(round(self.latency * 1000))


def extract_json_payload(text: str) -> Any:
    """Robustly extracts JSON object or array from LLM response text."""
    if not text:
        return {}
    cleaned = text.strip()

    # Check for fenced code block ```json ... ```
    match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", cleaned, re.I)
    if match:
        candidate = match.group(1).strip()
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass

    # Find outermost { ... } or [ ... ]
    first_brace = cleaned.find("{")
    first_bracket = cleaned.find("[")

    start_pos = -1
    end_char = ""
    if first_brace != -1 and (first_bracket == -1 or first_brace < first_bracket):
        start_pos = first_brace
        end_char = "}"
    elif first_bracket != -1:
        start_pos = first_bracket
        end_char = "]"

    if start_pos != -1:
        end_pos = cleaned.rfind(end_char)
        if end_pos > start_pos:
            candidate = cleaned[start_pos : end_pos + 1]
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                pass

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        return {"raw": cleaned}


class AIProvider(abc.ABC):
    """
    Abstract base class defining the common provider interface for HORCRUX.
    All provider implementations (Groq, OpenAI, Anthropic, Google) conform to this interface.
    """

    def __init__(self, settings_manager: SettingsManager):
        self.settings = settings_manager

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Provider identifier, e.g. 'groq', 'openai', 'anthropic', 'google'."""
        pass

    @property
    def config(self) -> ProviderConfig:
        return self.settings.settings.providers.get(
            self.name,
            ProviderConfig(name=self.name, model=DEFAULT_MODELS.get(self.name, "")),
        )

    def get_api_key(self) -> str:
        return self.settings.get_api_key(self.name)

    def get_credential_info(self) -> CredentialInfo:
        return self.settings.get_credential_info(self.name)

    def get_active_model(self) -> str:
        return self.settings.get_model(self.name) or self.config.model or DEFAULT_MODELS.get(self.name, "")

    def is_configured(self) -> bool:
        return bool(self.get_api_key())

    def validate_configuration(self) -> tuple[bool, str]:
        """Check if provider has credential and active model."""
        if not self.is_configured():
            return False, f"Provider '{self.name}' has no API key configured."
        if not self.get_active_model():
            return False, f"Provider '{self.name}' has no model configured."
        return True, "Configuration valid."

    @property
    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities()

    @abc.abstractmethod
    def list_models(self) -> list[ModelInfo]:
        """
        Dynamically query provider for available text-generation models.
        Returns normalized ModelInfo list.
        """
        pass

    def get_model_info(self, model_id: str) -> ModelInfo | None:
        """Retrieve metadata for a specific model ID."""
        for m in self.list_models():
            if m.id.lower() == model_id.lower() or m.id.lower().endswith(model_id.lower()):
                return m
        return None

    def fetch_models(self) -> list[str]:
        """Backward-compatible helper returning list of model ID strings."""
        return [m.id for m in self.list_models()]

    @abc.abstractmethod
    def complete(
        self,
        prompt: str,
        system_prompt: str = "",
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> AIResponse:
        """Execute a text completion request."""
        pass

    def generate(
        self,
        prompt: str,
        system_prompt: str = "",
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> AIResponse:
        """Provider-agnostic text generation; invokes complete()."""
        return self.complete(prompt, system_prompt=system_prompt, temperature=temperature, max_tokens=max_tokens)

    def structured(
        self,
        prompt: str,
        system_prompt: str = "",
        schema: Any | None = None,
        temperature: float = 0.1,
        max_tokens: int | None = None,
    ) -> AIResponse:
        """
        Execute structured JSON completion.
        Uses provider-native JSON mode where available or structured prompt fallback.
        """
        sys = (system_prompt or HORCRUX_EVIDENCE_POLICY) + "\n\nRespond ONLY with valid JSON. Do not include introductory text or markdown formatting."
        resp = self.complete(prompt, system_prompt=sys, temperature=temperature, max_tokens=max_tokens)
        resp.structured = extract_json_payload(resp.content)
        return resp

    def stream(
        self,
        prompt: str,
        system_prompt: str = "",
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> Generator[str, None, None]:
        """Streaming completion generator; default implementation yields full content."""
        resp = self.complete(prompt, system_prompt=system_prompt, temperature=temperature, max_tokens=max_tokens)
        yield resp.content

    def test_connection(self) -> tuple[bool, str, AIErrorType | None, float]:
        """Alias for validate_credentials."""
        return self.validate_credentials()

    def validate_credentials(self) -> tuple[bool, str, AIErrorType | None, float]:
        """
        Test provider credentials and selected model with minimal low-cost request.
        Uses the exact same generate/complete request pathway as production requests.
        Returns: (success, message, error_type, latency_seconds)
        """
        if not self.is_configured():
            return False, "API key is not configured.", AIErrorType.AUTHENTICATION_FAILED, 0.0

        t0 = time.perf_counter()
        try:
            # Send enough tokens (100) so thinking/reasoning models don't exhaust completion budget
            resp = self.complete("Respond with OK.", max_tokens=100, temperature=0.0)
            latency = time.perf_counter() - t0
            if resp and resp.content and resp.content.strip():
                self.settings.set_provider_validation(self.name, True, "READY")
                return True, f"Connection verified successfully. Model: {resp.model}", None, round(latency, 2)

            self.settings.set_provider_validation(self.name, False, "EMPTY_RESPONSE")
            return (
                False,
                f"Provider {self.name.upper()} returned an empty response. Verify model availability or permissions.",
                AIErrorType.INVALID_RESPONSE,
                round(latency, 2),
            )
        except Exception as exc:
            latency = time.perf_counter() - t0
            if isinstance(exc, AIError):
                err_type, msg, hint = exc.error_type, exc.message, exc.suggested_action
            else:
                err_type, msg, hint = self.normalize_error(exc)
            self.settings.set_provider_validation(self.name, False, err_type.value)
            detail = f"{msg} {hint}".strip()
            return False, detail, err_type, round(latency, 2)

    def estimate_capabilities(self) -> dict[str, Any]:
        """Return provider capabilities (context size, streaming, json mode)."""
        return {
            "name": self.name,
            "configured": self.is_configured(),
            "selected_model": self.get_active_model(),
            "supports_streaming": True,
            "supports_structured": True,
        }

    def normalize_error(self, exc: Exception) -> tuple[AIErrorType, str, str]:
        """
        Normalizes provider-specific exception into (AIErrorType, human_message, suggested_action).
        Never exposes raw API keys in returned messages.
        """
        if isinstance(exc, AIError):
            return exc.error_type, exc.message, exc.suggested_action

        active_key = self.get_api_key()
        err_str = redact_secrets(str(exc), extra_secrets=[active_key] if active_key else None)

        status = getattr(exc, "status_code", None)
        if status is None and hasattr(exc, "response") and exc.response is not None:
            status = getattr(exc.response, "status_code", None)

        # 1. Authentication / Invalid Key (401)
        if status == 401 or any(k in err_str.lower() for k in ["invalid api key", "invalid_api_key", "unauthorized", "api_key_invalid", "authentication failed"]):
            return (
                AIErrorType.AUTHENTICATION_FAILED,
                f"{self.name.upper()} authentication failed. The configured API key was rejected.",
                f"Run: settings provider {self.name}",
            )

        # 2. Model Not Found or Model Unavailable (404 or deprecated model message)
        if status == 404 or any(k in err_str.lower() for k in ["model_not_found", "model not found", "not found for api version", "no longer available", "is not supported"]):
            curr_model = self.get_active_model()
            return (
                AIErrorType.MODEL_UNAVAILABLE,
                f"Model '{curr_model}' is unavailable or not accessible to this account.",
                f"Run: settings models {self.name}",
            )

        # 3. Permission Denied / Project Access (403)
        if status == 403 or "permission_denied" in err_str.lower() or "forbidden" in err_str.lower():
            return (
                AIErrorType.PERMISSION_DENIED,
                f"{self.name.upper()} access forbidden or insufficient permissions.",
                "Check account tier, project billing, and API enablement.",
            )

        # 4. Rate Limited (429)
        if status == 429:
            if "quota" in err_str.lower() or "insufficient_quota" in err_str.lower() or "resource_exhausted" in err_str.lower():
                return (
                    AIErrorType.QUOTA_EXCEEDED,
                    f"{self.name.upper()} quota or credits exhausted.",
                    "Check billing or account balance at provider console.",
                )
            return (
                AIErrorType.RATE_LIMITED,
                f"{self.name.upper()} rate limit reached.",
                "Wait a moment before retrying or switch default provider.",
            )

        # 5. Timeout
        if any(k in err_str.lower() for k in ["timeout", "timed out", "readtimeouterror"]):
            return (
                AIErrorType.TIMEOUT,
                f"{self.name.upper()} request timed out.",
                "Check network connection or increase timeout in settings.",
            )

        # 6. Network Error / Connect failure
        if any(k in err_str.lower() for k in ["connection refused", "nameresolutionerror", "connecterror", "gaierror"]):
            return (
                AIErrorType.NETWORK_ERROR,
                f"Unable to connect to {self.name.upper()} endpoint.",
                "Check internet connectivity and DNS resolution.",
            )

        # 7. Bad Request (400)
        if status == 400:
            return (
                AIErrorType.BAD_REQUEST,
                f"Invalid request parameters sent to {self.name.upper()}.",
                "Check model configuration or prompt parameters.",
            )

        # 8. Server error (500, 502, 503, 504)
        if status and status >= 500:
            return (
                AIErrorType.PROVIDER_UNAVAILABLE,
                f"Provider {self.name.upper()} is currently experiencing service disruption (HTTP {status}).",
                "Try again later or switch to a fallback provider.",
            )

        return (
            AIErrorType.INVALID_RESPONSE,
            f"Unexpected error: {err_str[:120]}",
            "Review error details and check provider status.",
        )
