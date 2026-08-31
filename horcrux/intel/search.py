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


def evaluate_candidate_relevance(
    title: str,
    product: str,
    version: str,
    target_os: str = "",
    has_shell: bool = False,
) -> tuple[str, str, float, str, list[str], str]:
    """
    Evaluates ExploitCandidate returning:
    (relevance, exploitability, confidence, attack_type, missing_prereqs, reasoning)
    """
    title_lower = title.lower()
    product_lower = product.lower()
    version_clean = version.split()[0].strip().lower() if version else ""

    exact_version = bool(version_clean and version_clean in title_lower)
    is_remote = "remote" in title_lower or "rce" in title_lower or "unauth" in title_lower
    is_local = "local" in title_lower or "privilege escalation" in title_lower or "lpe" in title_lower
    is_dos = "denial of service" in title_lower or " crash" in title_lower or "dos" in title_lower

    attack_type = "remote" if is_remote else ("local" if is_local else ("dos" if is_dos else "manual"))
    missing_prereqs: list[str] = []

    # Platform compatibility heuristic
    platform_mismatch = False
    if target_os == "linux" and ("windows" in title_lower or "win32" in title_lower or "win64" in title_lower):
        platform_mismatch = True
    elif target_os == "windows" and ("linux" in title_lower or "unix" in title_lower or "freebsd" in title_lower):
        platform_mismatch = True

    if is_local and not has_shell:
        missing_prereqs.append("Initial target shell/command execution prerequisite unmet")

    if platform_mismatch:
        relevance = "REJECTED"
        exploitability = "INCOMPATIBLE (PLATFORM MISMATCH)"
        confidence = 0.20
        reasoning = f"Exploit targets different OS architecture than observed host ({target_os})."
    elif is_dos:
        relevance = "BROAD REFERENCE"
        exploitability = "LOW (DENIAL OF SERVICE)"
        confidence = 0.40
        reasoning = "Denial-of-service / crash vector; does not provide code execution or access."
    elif exact_version and is_remote:
        relevance = "CONFIRMED VERSION MATCH"
        exploitability = "HIGH (REMOTE)"
        confidence = 0.92
        reasoning = f"Exact version match for {product} {version} with remote attack vector."
    elif exact_version and is_local:
        relevance = "POTENTIALLY RELEVANT"
        exploitability = "MODERATE (LOCAL)"
        confidence = 0.70
        reasoning = f"Exact version match for local component; requires active shell to execute."
    elif is_remote and (version_clean and any(char.isdigit() for char in version_clean)):
        relevance = "HIGH-CONFIDENCE CANDIDATE"
        exploitability = "HIGH (REMOTE)"
        confidence = 0.78
        reasoning = f"Product match ({product}) with remote vector; candidate for version {version}."
    elif is_local:
        relevance = "POTENTIALLY RELEVANT"
        exploitability = "MODERATE (LOCAL)"
        confidence = 0.55
        reasoning = f"Local exploit for {product}; requires operator foothold."
    else:
        relevance = "MANUAL REVIEW"
        exploitability = "MANUAL REVIEW"
        confidence = 0.45
        reasoning = f"Broad reference candidate for {product}; operator verification required."

    return relevance, exploitability, confidence, attack_type, missing_prereqs, reasoning


def searchsploit_workspace(ws, runner):
    state = ws.load()
    candidates = []

    if not runner.which("searchsploit"):
        ws.set_exploits([])
        return candidates

    # Infer OS if available from services/software
    target_os = ""
    for s in state.software:
        src = (s.product + " " + s.service + " " + s.source).lower()
        if "linux" in src or "ubuntu" in src or "debian" in src or "centos" in src:
            target_os = "linux"
            break
        elif "windows" in src or "microsoft" in src:
            target_os = "windows"
            break

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

            (
                relevance,
                exploitability,
                confidence,
                attack_type,
                missing_prereqs,
                reasoning,
            ) = evaluate_candidate_relevance(
                title=title,
                product=software.product,
                version=software.version,
                target_os=target_os,
            )

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
                    query=query,
                    relevance_reasoning=reasoning,
                    attack_type=attack_type,
                    missing_prerequisites=missing_prereqs,
                )
            )

    ws.set_exploits(candidates)
    return candidates

