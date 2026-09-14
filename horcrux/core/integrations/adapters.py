"""Concrete integration adapters bridging existing HORCRUX subsystems into the unified control plane."""

from __future__ import annotations

import logging
import shutil
import subprocess
import time
from typing import Any

from horcrux.core.integrations.base import (
    AIIntegration,
    AutomationIntegration,
    ExternalIntegration,
    ToolIntegration,
    VulnerabilityIntegration,
)
from horcrux.core.integrations.models import (
    ConfigField,
    CredentialField,
    IntegrationCategory,
    IntegrationErrorType,
    IntegrationHealth,
    IntegrationHealthResult,
    IntegrationMetadata,
    IntegrationTestResult,
)
from horcrux.core.settings import (
    AVAILABLE_MODELS,
    DEFAULT_MODELS,
    ENV_KEY_NAMES,
    VULN_CREDENTIAL_FIELDS,
    VULN_DEFAULT_ENDPOINTS,
    VULN_ENGINE_LABELS,
    VULN_ENV_VARS,
    SettingsManager,
    normalize_provider_name,
    normalize_vuln_engine_id,
)

logger = logging.getLogger("horcrux.integrations")

AI_DISPLAY_NAMES = {
    "groq": "Groq LLaMA Cloud",
    "openai": "OpenAI GPT Platform",
    "anthropic": "Anthropic Claude Platform",
    "google": "Google Gemini Platform",
}

AI_DESCRIPTIONS = {
    "groq": "Ultra-low-latency LLaMA inference engine for high-speed hypothesis generation and triage.",
    "openai": "OpenAI flagship models (GPT-4o, o3-mini) for complex reasoning and attack-chain synthesis.",
    "anthropic": "Anthropic Claude models (3.5 Sonnet, 3.7 Sonnet) with deep code analysis and artifact comprehension.",
    "google": "Google Gemini multimodal models (Gemini 2.5/3.6 Flash & Pro) with large context window reasoning.",
}

CORE_TOOLS_DEF = {
    "nmap": {
        "name": "Nmap Security Scanner",
        "description": "Network exploration tool and security / port scanner.",
        "binary": "nmap",
        "capabilities": ["network_discovery", "port_scanning", "service_fingerprinting", "os_detection"],
        "doc_url": "https://nmap.org",
    },
    "nuclei": {
        "name": "Nuclei Vulnerability Scanner",
        "description": "Fast and customizable vulnerability scanner based on simple YAML DSL.",
        "binary": "nuclei",
        "capabilities": ["template_scanning", "cve_detection", "misconfiguration_audit"],
        "doc_url": "https://projectdiscovery.io/nuclei",
    },
    "ffuf": {
        "name": "FFUF Web Fuzzer",
        "description": "Fast web fuzzer written in Go for parameter and endpoint discovery.",
        "binary": "ffuf",
        "capabilities": ["directory_fuzzing", "parameter_fuzzing", "virtual_host_discovery"],
        "doc_url": "https://github.com/ffuf/ffuf",
    },
    "whatweb": {
        "name": "WhatWeb Next Gen Web Scanner",
        "description": "Web scanner identifying technologies including CMS, blogging platforms, and JS libraries.",
        "binary": "whatweb",
        "capabilities": ["tech_stack_identification", "header_analysis", "cms_detection"],
        "doc_url": "https://github.com/urbanadventurer/WhatWeb",
    },
}


class AIProviderAdapter(AIIntegration):
    """Bridges existing AI Providers (Groq, OpenAI, Anthropic, Google) into ExternalIntegration."""

    def __init__(self, provider_name: str, settings_manager: SettingsManager | None = None) -> None:
        super().__init__(settings_manager)
        self.provider_name = normalize_provider_name(provider_name)

    def metadata(self) -> IntegrationMetadata:
        env_vars = ENV_KEY_NAMES.get(self.provider_name, [f"{self.provider_name.upper()}_API_KEY"])
        models = AVAILABLE_MODELS.get(self.provider_name, [])
        def_model = DEFAULT_MODELS.get(self.provider_name, "")

        return IntegrationMetadata(
            id=self.provider_name,
            name=AI_DISPLAY_NAMES.get(self.provider_name, f"{self.provider_name.title()} AI"),
            category=IntegrationCategory.AI,
            provider_type="cloud_api",
            description=AI_DESCRIPTIONS.get(self.provider_name, f"AI Provider: {self.provider_name}"),
            version="1.0",
            documentation_url=f"https://docs.{self.provider_name}.com" if self.provider_name in ("openai", "anthropic") else "https://ai.google.dev",
            capabilities=["reasoning", "hypothesis_generation", "code_analysis", "payload_synthesis", "remediation_advisory"],
            credential_fields=[
                CredentialField(
                    name="api_key",
                    label="API Key",
                    secret=True,
                    required=True,
                    env_vars=env_vars,
                    description=f"API key for {self.provider_name}",
                ),
            ],
            config_fields=[
                ConfigField(
                    name="model",
                    label="Model",
                    type="choice",
                    default=def_model,
                    choices=models,
                    description="Active model identifier",
                ),
                ConfigField(
                    name="temperature",
                    label="Temperature",
                    type="float",
                    default=0.2,
                    description="Sampling temperature (0.0 to 1.0)",
                ),
                ConfigField(
                    name="custom_endpoint",
                    label="Custom Endpoint",
                    type="string",
                    default="",
                    description="Custom base URL / proxy endpoint",
                ),
            ],
            requires_network=True,
            requires_binary=False,
            aliases=[self.provider_name],
        )

    def available_models(self) -> list[str]:
        return AVAILABLE_MODELS.get(self.provider_name, [])

    def default_model(self) -> str:
        return DEFAULT_MODELS.get(self.provider_name, "")

    def is_configured(self) -> bool:
        creds = self.get_credentials()
        return bool(creds.get("api_key"))

    def health_check(self, quick: bool = True) -> IntegrationHealthResult:
        if not self.is_configured():
            return IntegrationHealthResult(
                health=IntegrationHealth.NOT_CONFIGURED,
                message=f"{self.name} API key is not configured.",
                error_type=IntegrationErrorType.NOT_CONFIGURED,
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            )

        if not self.is_enabled():
            return IntegrationHealthResult(
                health=IntegrationHealth.DEGRADED,
                message=f"{self.name} is configured but disabled in settings.",
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            )

        return IntegrationHealthResult(
            health=IntegrationHealth.HEALTHY,
            message=f"{self.name} configured with model '{self.current_model()}'.",
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            details={"model": self.current_model()},
        )

    def test_connection(self) -> IntegrationTestResult:
        start = time.perf_counter()
        if not self.is_configured():
            return IntegrationTestResult(
                ok=False,
                status=IntegrationHealth.NOT_CONFIGURED,
                message=f"{self.name} API key not found in runtime, keyring, config, or env.",
                latency_ms=0.0,
                error_type=IntegrationErrorType.NOT_CONFIGURED,
            )

        try:
            from horcrux.intel.ai.manager import AIManager
            ai_mgr = AIManager(self.settings_manager)
            provider_inst = ai_mgr.providers.get(self.provider_name)
            if not provider_inst:
                return IntegrationTestResult(
                    ok=False,
                    status=IntegrationHealth.UNHEALTHY,
                    message=f"Provider implementation {self.provider_name} not found.",
                    latency_ms=round((time.perf_counter() - start) * 1000, 2),
                    error_type=IntegrationErrorType.INTERNAL_ERROR,
                )

            # Test prompt
            resp = provider_inst.complete("Echo test: Respond with 'HORCRUX_AI_OK'", max_tokens=10)
            latency = round((time.perf_counter() - start) * 1000, 2)
            if resp and resp.content:
                return IntegrationTestResult(
                    ok=True,
                    status=IntegrationHealth.OPERATIONAL,
                    message=f"Connection verified to {self.name} ({latency:.0f}ms).",
                    raw_output=resp.content.strip()[:100],
                    latency_ms=latency,
                    details={"model": resp.model, "tokens": resp.tokens_used},
                )
            else:
                return IntegrationTestResult(
                    ok=False,
                    status=IntegrationHealth.DEGRADED,
                    message=f"Received empty response from {self.name}.",
                    latency_ms=latency,
                    error_type=IntegrationErrorType.INVALID_RESPONSE,
                )
        except Exception as e:
            latency = round((time.perf_counter() - start) * 1000, 2)
            err_str = str(e)
            err_type = IntegrationErrorType.API_ERROR
            if "auth" in err_str.lower() or "401" in err_str or "api_key" in err_str.lower():
                err_type = IntegrationErrorType.AUTHENTICATION_FAILED
            elif "rate" in err_str.lower() or "429" in err_str:
                err_type = IntegrationErrorType.RATE_LIMITED
            elif "timeout" in err_str.lower():
                err_type = IntegrationErrorType.TIMEOUT

            return IntegrationTestResult(
                ok=False,
                status=IntegrationHealth.UNHEALTHY,
                message=f"Connection failed to {self.name}: {err_str}",
                latency_ms=latency,
                error_type=err_type,
            )


class VulnEngineAdapter(VulnerabilityIntegration):
    """Bridges ExternalVulnerabilityEngine implementations into ExternalIntegration."""

    def __init__(self, engine_id: str, settings_manager: SettingsManager | None = None) -> None:
        super().__init__(settings_manager)
        self.engine_id = normalize_vuln_engine_id(engine_id)

    def metadata(self) -> IntegrationMetadata:
        label = VULN_ENGINE_LABELS.get(self.engine_id, self.engine_id.title())
        req_fields = VULN_CREDENTIAL_FIELDS.get(self.engine_id, [])
        env_map = VULN_ENV_VARS.get(self.engine_id, {})
        def_endpoint = VULN_DEFAULT_ENDPOINTS.get(self.engine_id, "")

        cred_fields = []
        for fn in req_fields:
            cred_fields.append(
                CredentialField(
                    name=fn,
                    label=fn.replace("_", " ").title(),
                    secret=True,
                    required=True,
                    env_vars=env_map.get(fn, []),
                    description=f"{fn} for {label}",
                )
            )

        is_daemon = self.engine_id == "greenbone"
        return IntegrationMetadata(
            id=self.engine_id,
            name=label,
            category=IntegrationCategory.VULNERABILITY,
            provider_type="local_daemon" if is_daemon else "cloud_saas",
            description=f"Enterprise vulnerability engine integration for {label}.",
            version="1.0",
            capabilities=[
                "vulnerability_ingestion",
                "host_vulnerability_assessment",
                "cve_correlation",
                "cvss_scoring",
                "remediation_intelligence",
            ],
            credential_fields=cred_fields,
            config_fields=[
                ConfigField(
                    name="endpoint",
                    label="API Endpoint",
                    type="string",
                    default=def_endpoint,
                    description=f"Base API endpoint for {label}",
                ),
            ],
            requires_network=True,
            requires_binary=False,
            aliases=[self.engine_id],
        )

    def get_engine_instance(self) -> Any:
        from horcrux.intel.vuln_engines.registry import get_engine
        creds = self.get_credentials()
        cfg = self.get_config()
        return get_engine(self.engine_id, config=cfg, credentials=creds)

    def is_configured(self) -> bool:
        creds = self.get_credentials()
        req_fields = VULN_CREDENTIAL_FIELDS.get(self.engine_id, [])
        return all(bool(creds.get(f)) for f in req_fields)

    def health_check(self, quick: bool = True) -> IntegrationHealthResult:
        if not self.is_configured():
            return IntegrationHealthResult(
                health=IntegrationHealth.NOT_CONFIGURED,
                message=f"{self.name} credentials are not configured.",
                error_type=IntegrationErrorType.NOT_CONFIGURED,
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            )

        if not self.is_enabled():
            return IntegrationHealthResult(
                health=IntegrationHealth.DEGRADED,
                message=f"{self.name} is configured but disabled in settings.",
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            )

        cfg = self.get_config()
        last_status = cfg.get("last_status")
        last_test = cfg.get("last_test")

        if last_status == "ok":
            return IntegrationHealthResult(
                health=IntegrationHealth.HEALTHY,
                message=f"{self.name} connection verified ({last_test or 'recent'}).",
                timestamp=last_test or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            )

        return IntegrationHealthResult(
            health=IntegrationHealth.CONFIGURED,
            message=f"{self.name} is configured and ready for connection test.",
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )

    def test_connection(self) -> IntegrationTestResult:
        start = time.perf_counter()
        if not self.is_configured():
            return IntegrationTestResult(
                ok=False,
                status=IntegrationHealth.NOT_CONFIGURED,
                message=f"{self.name} credentials are not configured.",
                latency_ms=0.0,
                error_type=IntegrationErrorType.NOT_CONFIGURED,
            )

        try:
            engine = self.get_engine_instance()
            creds = self.get_credentials()
            result = engine.test_connection(creds)
            latency = round((time.perf_counter() - start) * 1000, 2)

            # Update settings with last test results
            cfg = self.get_config()
            cfg["last_test"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            cfg["last_status"] = "ok" if result.ok else "error"
            self.settings_manager.set_integration_config(self.id, cfg)

            health = IntegrationHealth.OPERATIONAL if result.ok else IntegrationHealth.UNHEALTHY
            err_type = None
            if not result.ok:
                err_type = IntegrationErrorType.AUTHENTICATION_FAILED if "auth" in result.message.lower() else IntegrationErrorType.API_ERROR

            return IntegrationTestResult(
                ok=result.ok,
                status=health,
                message=result.message,
                latency_ms=latency,
                error_type=err_type,
                details=result.details or {},
            )
        except Exception as e:
            latency = round((time.perf_counter() - start) * 1000, 2)
            return IntegrationTestResult(
                ok=False,
                status=IntegrationHealth.UNHEALTHY,
                message=f"Connection test failed for {self.name}: {e}",
                latency_ms=latency,
                error_type=IntegrationErrorType.API_ERROR,
            )


class PlaywrightAutomationAdapter(AutomationIntegration):
    """Bridges Playwright browser automation into ExternalIntegration."""

    def __init__(self, settings_manager: SettingsManager | None = None) -> None:
        super().__init__(settings_manager)

    def metadata(self) -> IntegrationMetadata:
        return IntegrationMetadata(
            id="playwright",
            name="Playwright Browser Automation",
            category=IntegrationCategory.AUTOMATION,
            provider_type="headless_browser",
            description="Browser automation runtime for interactive discovery, SPA crawling, and authenticated sessions.",
            version="1.0",
            documentation_url="https://playwright.dev/python/",
            capabilities=[
                "headless_browsing",
                "spa_exploration",
                "dom_snapshot",
                "session_recording",
                "dynamic_form_filling",
                "javascript_execution",
            ],
            credential_fields=[],
            config_fields=[
                ConfigField(
                    name="browser_type",
                    label="Browser Engine",
                    type="choice",
                    default="chromium",
                    choices=["chromium", "firefox", "webkit"],
                    description="Underlying browser engine to launch",
                ),
                ConfigField(
                    name="headless",
                    label="Headless Mode",
                    type="bool",
                    default=True,
                    description="Run browser in headless mode without window",
                ),
                ConfigField(
                    name="timeout_ms",
                    label="Page Timeout (ms)",
                    type="int",
                    default=30000,
                    description="Navigation and selector wait timeout",
                ),
            ],
            requires_network=False,
            requires_binary=False,
            aliases=["playwright", "browser", "automation"],
        )

    def is_browser_available(self) -> bool:
        try:
            import importlib.util
            return importlib.util.find_spec("playwright") is not None
        except Exception:
            return False

    def is_configured(self) -> bool:
        # Automation does not require secrets, only runtime presence
        return True

    def health_check(self, quick: bool = True) -> IntegrationHealthResult:
        if not self.is_browser_available():
            return IntegrationHealthResult(
                health=IntegrationHealth.UNAVAILABLE,
                message="Playwright package is not installed in the current environment.",
                error_type=IntegrationErrorType.NOT_CONFIGURED,
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            )

        if not self.is_enabled():
            return IntegrationHealthResult(
                health=IntegrationHealth.DEGRADED,
                message="Playwright automation is disabled in settings.",
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            )

        return IntegrationHealthResult(
            health=IntegrationHealth.HEALTHY,
            message="Playwright Python SDK available.",
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )

    def test_connection(self) -> IntegrationTestResult:
        start = time.perf_counter()
        if not self.is_browser_available():
            return IntegrationTestResult(
                ok=False,
                status=IntegrationHealth.UNAVAILABLE,
                message="Playwright package not installed (run 'pip install playwright && playwright install').",
                latency_ms=0.0,
                error_type=IntegrationErrorType.NOT_CONFIGURED,
            )

        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                page.set_content("<html><body><h1>HORCRUX_PLAYWRIGHT_OK</h1></body></html>")
                text = page.inner_text("h1")
                browser.close()

            latency = round((time.perf_counter() - start) * 1000, 2)
            return IntegrationTestResult(
                ok=True,
                status=IntegrationHealth.OPERATIONAL,
                message=f"Playwright Chromium browser launched successfully ({latency:.0f}ms).",
                raw_output=text,
                latency_ms=latency,
            )
        except Exception as e:
            latency = round((time.perf_counter() - start) * 1000, 2)
            return IntegrationTestResult(
                ok=False,
                status=IntegrationHealth.UNHEALTHY,
                message=f"Playwright launch failed: {e}",
                latency_ms=latency,
                error_type=IntegrationErrorType.INTERNAL_ERROR,
            )


class CoreToolAdapter(ToolIntegration):
    """Bridges CLI security tools (Nmap, Nuclei, FFUF, WhatWeb) into ExternalIntegration."""

    def __init__(self, tool_id: str, settings_manager: SettingsManager | None = None) -> None:
        super().__init__(settings_manager)
        self.tool_id = tool_id.lower()
        self.tool_def = CORE_TOOLS_DEF.get(self.tool_id, {
            "name": self.tool_id.title(),
            "description": f"Security tool {self.tool_id}",
            "binary": self.tool_id,
            "capabilities": ["generic_tool"],
            "doc_url": "",
        })

    def metadata(self) -> IntegrationMetadata:
        binary_name = self.tool_def.get("binary", self.tool_id)
        return IntegrationMetadata(
            id=self.tool_id,
            name=self.tool_def.get("name", self.tool_id.title()),
            category=IntegrationCategory.SECURITY_TOOLS,
            provider_type="cli_binary",
            description=self.tool_def.get("description", ""),
            documentation_url=self.tool_def.get("doc_url", ""),
            capabilities=self.tool_def.get("capabilities", []),
            credential_fields=[],
            config_fields=[
                ConfigField(
                    name="custom_path",
                    label="Custom Binary Path",
                    type="string",
                    default="",
                    description=f"Override path for {binary_name} binary",
                ),
            ],
            requires_network=False,
            requires_binary=True,
            binary_names=[binary_name],
            aliases=[self.tool_id],
        )

    def binary_path(self) -> str | None:
        cfg = self.get_config()
        custom = cfg.get("custom_path")
        if custom and shutil.which(custom):
            return custom
        binary_name = self.tool_def.get("binary", self.tool_id)
        return shutil.which(binary_name)

    def is_configured(self) -> bool:
        return self.binary_path() is not None

    def health_check(self, quick: bool = True) -> IntegrationHealthResult:
        path = self.binary_path()
        if not path:
            return IntegrationHealthResult(
                health=IntegrationHealth.UNAVAILABLE,
                message=f"Executable '{self.tool_def.get('binary', self.tool_id)}' not found in system PATH.",
                error_type=IntegrationErrorType.NOT_CONFIGURED,
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            )

        if not self.is_enabled():
            return IntegrationHealthResult(
                health=IntegrationHealth.DEGRADED,
                message=f"{self.name} is available but disabled in settings.",
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            )

        return IntegrationHealthResult(
            health=IntegrationHealth.HEALTHY,
            message=f"Binary located at: {path}",
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            details={"binary_path": path},
        )

    def test_connection(self) -> IntegrationTestResult:
        start = time.perf_counter()
        path = self.binary_path()
        if not path:
            return IntegrationTestResult(
                ok=False,
                status=IntegrationHealth.UNAVAILABLE,
                message=f"Binary '{self.tool_def.get('binary', self.tool_id)}' not found on PATH.",
                latency_ms=0.0,
                error_type=IntegrationErrorType.NOT_CONFIGURED,
            )

        try:
            # Run quick version check
            res = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=5)
            output = (res.stdout or res.stderr).strip().splitlines()
            first_line = output[0] if output else "Executed successfully"
            latency = round((time.perf_counter() - start) * 1000, 2)
            return IntegrationTestResult(
                ok=True,
                status=IntegrationHealth.OPERATIONAL,
                message=f"{self.name} executed successfully ({latency:.0f}ms).",
                raw_output=first_line,
                latency_ms=latency,
                details={"binary": path, "version_output": first_line},
            )
        except Exception as e:
            latency = round((time.perf_counter() - start) * 1000, 2)
            return IntegrationTestResult(
                ok=False,
                status=IntegrationHealth.UNHEALTHY,
                message=f"Execution error for {self.name}: {e}",
                latency_ms=latency,
                error_type=IntegrationErrorType.INTERNAL_ERROR,
            )
