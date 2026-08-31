from __future__ import annotations

import os
import sys
from pathlib import Path
from horcrux.core.doctor import BASES, find_wordlist

# Strategy priority lists mapped to relative SecLists / standard paths
STRATEGY_MAP = {
    "quickhits": [
        "seclists/Discovery/Web-Content/quickhits.txt",
        "Discovery/Web-Content/quickhits.txt",
        "seclists/Discovery/Web-Content/common.txt",
        "Discovery/Web-Content/common.txt",
        "dirb/common.txt",
    ],
    "common": [
        "seclists/Discovery/Web-Content/common.txt",
        "Discovery/Web-Content/common.txt",
        "dirb/common.txt",
        "seclists/Discovery/Web-Content/raft-small-words.txt",
        "Discovery/Web-Content/raft-small-words.txt",
        "dirbuster/directory-list-2.3-small.txt",
    ],
    "medium": [
        "seclists/Discovery/Web-Content/raft-medium-words.txt",
        "Discovery/Web-Content/raft-medium-words.txt",
        "dirbuster/directory-list-2.3-medium.txt",
        "seclists/Discovery/Web-Content/common.txt",
    ],
    "large": [
        "seclists/Discovery/Web-Content/raft-large-words.txt",
        "Discovery/Web-Content/raft-large-words.txt",
        "dirbuster/directory-list-2.3-big.txt",
        "seclists/Discovery/Web-Content/raft-medium-words.txt",
    ],
}

# High-priority built-in discovery list for zero-dependency environments
BUILTIN_COMMON_PATHS = [
    "admin", "administrator", "login", "auth", "api", "v1", "v2",
    "dashboard", "portal", "user", "users", "register", "signup",
    ".env", ".env.local", ".env.production", ".env.bak", ".git/HEAD",
    ".git/config", ".gitignore", "robots.txt", "sitemap.xml",
    "backup", "backup.sql", "backup.zip", "backup.tar.gz", "dump.sql",
    "database.sql", "db.sql", "wp-config.php.bak", "config.php.bak",
    "config.json", "settings.json", "web.config", "Dockerfile",
    "docker-compose.yml", "server-status", "phpinfo.php", "info.php",
    "test.php", "upload", "uploads", "files", "media", "static",
    "assets", "public", "private", "secret", "console", "terminal",
    "shell", "status", "health", "metrics", "actuator", "actuator/env",
    "_profiler", "swagger", "swagger-ui.html", "openapi.json", "graphql",
    "wp-login.php", "wp-admin", "xmlrpc.php", "cgi-bin", "manager/html",
    "debug", "trace", "source", "src", "include", "includes",
]


def get_embedded_wordlist_path() -> Path:
    """Ensure a built-in fallback wordlist exists on disk and return its path."""
    from horcrux.core.settings import get_config_dir
    wl_dir = get_config_dir() / "wordlists"
    wl_dir.mkdir(parents=True, exist_ok=True)
    embedded_file = wl_dir / "horcrux_builtin_common.txt"
    if not embedded_file.exists() or embedded_file.stat().st_size == 0:
        embedded_file.write_text("\n".join(BUILTIN_COMMON_PATHS) + "\n", encoding="utf-8")
    return embedded_file


def resolve_wordlist(
    strategy: str = "common",
    custom_path: str = "",
    ws = None,
) -> tuple[Path, bool, str]:
    """
    Resolves wordlist path based on strategy.
    Returns: (path, is_fallback, message)
    """
    if custom_path:
        cp = Path(custom_path)
        if cp.exists():
            return cp, False, f"Using custom wordlist: {cp}"

    strat_key = strategy.lower() if strategy.lower() in STRATEGY_MAP else "common"
    candidates = STRATEGY_MAP.get(strat_key, STRATEGY_MAP["common"])

    preferred = candidates[0]
    for rel_path in candidates:
        found = find_wordlist(rel_path)
        if found and found.exists():
            if rel_path == preferred:
                msg = f"Using preferred {strat_key} wordlist: {found}"
                if ws:
                    ws.write("raw/wordlist-resolution.txt", msg)
                return found, False, msg
            else:
                msg = f"[WARN] preferred wordlist '{preferred}' missing\n[FALLBACK] using '{found}'"
                if ws:
                    ws.write("raw/wordlist-resolution.txt", msg)
                return found, True, msg

    # If no SecLists or system wordlist was found on host, fall back to embedded wordlist
    fallback = get_embedded_wordlist_path()
    msg = f"[WARN] preferred wordlists for '{strat_key}' missing from system SecLists paths\n[FALLBACK] using embedded Horcrux triage list ({fallback})"
    if ws:
        ws.write("raw/wordlist-resolution.txt", msg)
    return fallback, True, msg
