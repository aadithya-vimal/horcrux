from __future__ import annotations

import json
import re

from horcrux.models import ExploitCandidate


def searchsploit_workspace(ws, runner):
    state = ws.load()
    candidates = []

    if not runner.which("searchsploit"):
        ws.set_exploits([])
        return candidates

    seen = set()
    for index, software in enumerate(state.software):
        if not software.product:
            continue

        query = " ".join(
            item for item in [software.product, software.version] if item
        ).strip()

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

            candidates.append(
                ExploitCandidate(
                    title=title,
                    product=software.product,
                    version=software.version,
                    cve=cve,
                    source=path,
                    confidence=.75 if software.version else .5,
                    notes=f"SearchSploit candidate for {query}; verify applicability.",
                )
            )

    ws.set_exploits(candidates)
    return candidates
