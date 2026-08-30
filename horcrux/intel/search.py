from __future__ import annotations

import json
import re

from horcrux.models import ExploitCandidate


def is_reliable_software_evidence(software) -> bool:
    """Only correlate CVEs / SearchSploit when high-quality product + version / CPE evidence exists."""
    if not software.product or len(software.product.strip()) < 3:
        return False
    product = software.product.strip().lower()
    # Reject generic words or weak guesses
    blacklisted_products = {
        "unknown", "tcpwrapped", "ppp", "http", "https", "ssl", "generic",
        "linux", "windows", "unix", "embedded", "upnp", "router",
    }
    if product in blacklisted_products:
        return False
    # Confidence must be at least 0.70 and either version or CPE must be present
    if software.confidence < 0.70:
        return False
    if not software.version and not software.cpe:
        return False
    return True


def searchsploit_workspace(ws, runner):
    state = ws.load()
    candidates = []

    if not runner.which("searchsploit"):
        ws.set_exploits([])
        return candidates

    seen = set()
    for index, software in enumerate(state.software):
        if not is_reliable_software_evidence(software):
            continue

        # Build specific query using product and version
        parts = [software.product]
        if software.version:
            # Clean version string of extra build noise for query
            v_clean = software.version.split()[0].strip()
            parts.append(v_clean)
        query = " ".join(parts).strip()

        result = runner.run(
            ["searchsploit", "--json", query],
            f"searchsploit-{index}",
            timeout=180,
        )

        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            payload = {}

        rows = (
            payload.get("RESULTS_EXPLOIT", [])
            if isinstance(payload, dict)
            else []
        )

        for row in rows:
            title = row.get("Title", "SearchSploit result")
            path = row.get("Path", "")
            match = re.search(r"\bCVE-\d{4}-\d{4,7}\b", title, re.I)
            cve = match.group(0).upper() if match else ""

            key = (title, path, software.product, software.version)
            if key in seen:
                continue
            seen.add(key)

            # Separate Exploitability, Confidence, Relevance
            exact_version = bool(software.version and software.version.lower() in title.lower())
            is_remote = "remote" in title.lower()
            exploitability = "HIGH (REMOTE)" if is_remote else ("MODERATE (LOCAL)" if "local" in title.lower() else "MANUAL REVIEW")
            relevance = "CONFIRMED VERSION MATCH" if exact_version else "HIGH-CONFIDENCE CANDIDATE"
            confidence = 0.90 if exact_version else (0.75 if software.version else 0.55)

            candidates.append(
                ExploitCandidate(
                    title=title,
                    product=software.product,
                    version=software.version,
                    cve=cve,
                    source=path,
                    confidence=confidence,
                    notes=f"SearchSploit candidate for {query}; evidence source: {software.source}.",
                    exploitability=exploitability,
                    relevance=relevance,
                )
            )

    ws.set_exploits(candidates)
    return candidates
