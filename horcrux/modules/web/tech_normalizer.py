from __future__ import annotations

import re
from typing import Any
from horcrux.models import NormalizedTechnology, RawObservation, TechCategory


# Raw scanner metadata labels that must NEVER be promoted to primary technologies
BLACKLIST_SCANNER_LABELS = {
    "country",
    "html5",
    "ip",
    "script",
    "title",
    "uncommonheaders",
    "x-frame-options",
    "x-xss-protection",
    "strict-transport-security",
    "content-security-policy",
    "email",
    "https-certificate",
    "cookies",
    "frame",
    "meta-refresh-redirect",
    "open-search",
    "passwordfield",
    "string",
    "via-proxy",
    "x-ua-compatible",
    "x-content-type-options",
    "content-language",
    "access-control-allow-origin",
}

# Mapping of known technology signatures to categories and canonical names
KNOWN_TECH_MAP: dict[str, tuple[str, TechCategory]] = {
    # Webservers & Reverse Proxies
    "apache": ("Apache HTTP Server", TechCategory.WEBSERVER),
    "nginx": ("nginx", TechCategory.WEBSERVER),
    "iis": ("Microsoft IIS", TechCategory.WEBSERVER),
    "microsoft-iis": ("Microsoft IIS", TechCategory.WEBSERVER),
    "caddy": ("Caddy", TechCategory.WEBSERVER),
    "lighttpd": ("lighttpd", TechCategory.WEBSERVER),
    "cloudflare": ("Cloudflare", TechCategory.REVERSE_PROXY),
    "envoy": ("Envoy Proxy", TechCategory.REVERSE_PROXY),
    "traefik": ("Traefik", TechCategory.REVERSE_PROXY),
    "haproxy": ("HAProxy", TechCategory.REVERSE_PROXY),

    # Frameworks
    "react": ("React", TechCategory.FRAMEWORK),
    "angular": ("Angular", TechCategory.FRAMEWORK),
    "angularjs": ("AngularJS", TechCategory.FRAMEWORK),
    "vue": ("Vue.js", TechCategory.FRAMEWORK),
    "vue.js": ("Vue.js", TechCategory.FRAMEWORK),
    "next.js": ("Next.js", TechCategory.FRAMEWORK),
    "nuxt": ("Nuxt", TechCategory.FRAMEWORK),
    "express": ("Express", TechCategory.FRAMEWORK),
    "django": ("Django", TechCategory.FRAMEWORK),
    "flask": ("Flask", TechCategory.FRAMEWORK),
    "spring": ("Spring Framework", TechCategory.FRAMEWORK),
    "spring-boot": ("Spring Boot", TechCategory.FRAMEWORK),
    "rails": ("Ruby on Rails", TechCategory.FRAMEWORK),
    "ruby on rails": ("Ruby on Rails", TechCategory.FRAMEWORK),
    "laravel": ("Laravel", TechCategory.FRAMEWORK),
    "asp.net": ("ASP.NET", TechCategory.FRAMEWORK),
    "asp.net core": ("ASP.NET Core", TechCategory.FRAMEWORK),
    "fastapi": ("FastAPI", TechCategory.FRAMEWORK),

    # Runtimes & Languages
    "php": ("PHP", TechCategory.LANGUAGE),
    "python": ("Python", TechCategory.LANGUAGE),
    "ruby": ("Ruby", TechCategory.LANGUAGE),
    "node.js": ("Node.js", TechCategory.RUNTIME),
    "nodejs": ("Node.js", TechCategory.RUNTIME),
    "java": ("Java", TechCategory.RUNTIME),
    ".net": (".NET", TechCategory.RUNTIME),
    "golang": ("Go", TechCategory.LANGUAGE),

    # CMS
    "wordpress": ("WordPress", TechCategory.CMS),
    "drupal": ("Drupal", TechCategory.CMS),
    "joomla": ("Joomla", TechCategory.CMS),
    "ghost": ("Ghost", TechCategory.CMS),
    "magento": ("Magento", TechCategory.CMS),

    # Libraries & Analytics
    "jquery": ("jQuery", TechCategory.LIBRARY),
    "bootstrap": ("Bootstrap", TechCategory.LIBRARY),
    "font-awesome": ("Font Awesome", TechCategory.LIBRARY),
    "google-analytics": ("Google Analytics", TechCategory.ANALYTICS),

    # Security Controls
    "mod_security": ("ModSecurity", TechCategory.SECURITY_CONTROL),
    "incapsula": ("Imperva Incapsula", TechCategory.SECURITY_CONTROL),
    "aws waf": ("AWS WAF", TechCategory.SECURITY_CONTROL),
}


def normalize_technology_name(raw_name: str) -> tuple[str, TechCategory] | None:
    """Normalizes raw scanner label into canonical name and category, or None if blacklisted."""
    clean = raw_name.strip().lower()
    if clean in BLACKLIST_SCANNER_LABELS:
        return None
    for bl in BLACKLIST_SCANNER_LABELS:
        if clean == bl or clean.startswith(f"{bl}:"):
            return None

    if clean in KNOWN_TECH_MAP:
        return KNOWN_TECH_MAP[clean]

    # Partial substring matches for common prefixes
    for k, (c_name, cat) in KNOWN_TECH_MAP.items():
        if k in clean:
            return c_name, cat

    # If not specifically recognized but not in blacklist, categorize as UNKNOWN
    # Filter out pure numbers or short tokens (< 3 chars)
    if len(clean) >= 3 and not clean.isdigit():
        return raw_name.strip(), TechCategory.UNKNOWN

    return None


def extract_technologies_from_headers(headers: dict[str, str]) -> list[NormalizedTechnology]:
    """Extracts corroborated technologies from HTTP response headers."""
    results: list[NormalizedTechnology] = []
    h_lower = {k.lower(): v for k, v in headers.items()}

    # Server header
    server = h_lower.get("server", "")
    if server:
        # e.g. "Apache/2.4.49 (Unix) OpenSSL/1.1.1d" or "nginx/1.18.0"
        parts = server.split()
        for p in parts:
            p_clean = p.split("/")[0].strip()
            v_clean = p.split("/")[1].strip() if "/" in p else ""
            res = normalize_technology_name(p_clean)
            if res:
                c_name, cat = res
                results.append(
                    NormalizedTechnology(
                        name=c_name,
                        category=cat,
                        version=v_clean,
                        confidence=0.95,
                        evidence_sources=[f"Server header: '{server}'"],
                    )
                )

    # X-Powered-By header
    powered = h_lower.get("x-powered-by", "")
    if powered:
        # e.g. "PHP/8.1.2" or "Express"
        p_clean = powered.split("/")[0].strip()
        v_clean = powered.split("/")[1].strip() if "/" in powered else ""
        res = normalize_technology_name(p_clean)
        if res:
            c_name, cat = res
            results.append(
                NormalizedTechnology(
                    name=c_name,
                    category=cat,
                    version=v_clean,
                    confidence=0.95,
                    evidence_sources=[f"X-Powered-By header: '{powered}'"],
                )
            )

    return results


def normalize_scanner_technologies(
    whatweb_plugins: dict[str, Any] | list[str],
    headers: dict[str, str] | None = None,
    waf_detected: str = "",
) -> list[NormalizedTechnology]:
    """
    Merges and normalizes technology evidence from WhatWeb, headers, and WAF tools.
    Strictly eliminates scanner noise (ip, country, html5, script, title, uncommonheaders).
    """
    tech_map: dict[str, NormalizedTechnology] = {}

    # 1. Process header evidence
    if headers:
        header_techs = extract_technologies_from_headers(headers)
        for ht in header_techs:
            tech_map[ht.name.lower()] = ht

    # 2. Process WhatWeb plugins
    plugin_dict: dict[str, Any] = {}
    if isinstance(whatweb_plugins, dict):
        plugin_dict = whatweb_plugins
    elif isinstance(whatweb_plugins, list):
        plugin_dict = {p: {} for p in whatweb_plugins}

    for p_name, details in plugin_dict.items():
        norm_result = normalize_technology_name(p_name)
        if not norm_result:
            continue

        c_name, cat = norm_result
        version = ""
        if isinstance(details, dict):
            v_val = details.get("version")
            if isinstance(v_val, list) and v_val:
                version = str(v_val[0])
            elif isinstance(v_val, str):
                version = v_val.strip()

        key = c_name.lower()
        if key in tech_map:
            # Corroborate existing technology
            existing = tech_map[key]
            if version and not existing.version:
                existing.version = version
            existing.confidence = min(0.99, existing.confidence + 0.1)
            existing.evidence_sources.append(f"WhatWeb plugin: {p_name}")
        else:
            tech_map[key] = NormalizedTechnology(
                name=c_name,
                category=cat,
                version=version,
                confidence=0.88,
                evidence_sources=[f"WhatWeb plugin: {p_name}"],
            )

    # 3. Process WAF detection
    if waf_detected:
        c_name = f"WAF: {waf_detected}"
        tech_map[c_name.lower()] = NormalizedTechnology(
            name=c_name,
            category=TechCategory.SECURITY_CONTROL,
            version="",
            confidence=0.92,
            evidence_sources=[f"wafw00f detection: {waf_detected}"],
        )

    return sorted(tech_map.values(), key=lambda t: t.name)


def normalize_technologies(
    whatweb_plugins: dict[str, Any] | list[str] | list[RawObservation],
    headers: dict[str, str] | None = None,
    waf_detected: str = "",
) -> list[NormalizedTechnology]:
    """
    Normalizes technology observations (accepts dict, list of plugin names, or list of RawObservation).
    Strictly eliminates scanner noise (ip, country, html5, script, title, uncommonheaders).
    """
    if isinstance(whatweb_plugins, list) and whatweb_plugins and isinstance(whatweb_plugins[0], RawObservation):
        plugin_dict: dict[str, Any] = {}
        for obs in whatweb_plugins:
            p = obs.data.get("plugin")
            if p:
                plugin_dict[p] = obs.data
        return normalize_scanner_technologies(plugin_dict, headers=headers, waf_detected=waf_detected)
    return normalize_scanner_technologies(whatweb_plugins, headers=headers, waf_detected=waf_detected)
