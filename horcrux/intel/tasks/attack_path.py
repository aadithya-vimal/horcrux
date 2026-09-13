from __future__ import annotations

import json
from horcrux.models import WorkspaceState
from horcrux.intel.tasks.triage import build_compact_state


def execute_attack_path_synthesis(
    ai_manager,
    state: WorkspaceState,
) -> list[dict]:
    """
    Synthesizes plausible multi-stage attack paths from confirmed evidence.
    Falls back to deterministic heuristic paths if AI is disabled.
    """
    compact_state = build_compact_state(state)
    payload = {
        "target": compact_state["target"],
        "services": compact_state["services"],
        "findings": compact_state["findings"],
        "credentials": [
            {"username": c.username, "source": c.source, "kind": c.kind}
            for c in state.credentials
        ],
    }

    prompt = f"""Synthesize plausible, multi-stage attack paths against the target using ONLY verified evidence.
Strictly adhere to the HORCRUX evidence policy. Do NOT hallucinate credentials or vulnerabilities.
Target state:
{json.dumps(payload, indent=2)}

Return a JSON list of attack paths:
[
  {{
    "name": "concise descriptive title",
    "probability": "HIGH" | "MEDIUM" | "LOW",
    "prerequisites": "required access, credentials, or network position",
    "steps": [
      "Step 1: exact initial recon or interaction",
      "Step 2: verification step",
      "Step 3: post-compromise or pivot step"
    ]
  }}
]
"""

    resp = ai_manager.call_task("attack_path_synthesis", prompt, payload=payload, max_tokens=1024)
    if resp and resp.structured and isinstance(resp.structured, list):
        return resp.structured

    # Deterministic fallback paths based on open services and verified findings
    fallback_paths = []
    has_web = any(s.service == "http" or s.port in (80, 443, 8080) for s in state.services)
    has_smb = any("smb" in s.service.lower() or s.port in (139, 445) for s in state.services)
    has_creds = len(state.credentials) > 0

    if has_web:
        fallback_paths.append({
            "name": "Web Application Foothold",
            "probability": "MEDIUM",
            "prerequisites": "HTTP/HTTPS service access",
            "steps": [
                "1. Enumerate exposed routes, backup artifacts, and API schema.",
                "2. Validate findings against HTTP response baseline.",
                "3. Exploit confirmed authentication bypass or injection.",
            ],
        })
    if has_smb:
        fallback_paths.append({
            "name": "SMB Share Access & Credential Harvesting",
            "probability": "MEDIUM",
            "prerequisites": "TCP 445 network reachability",
            "steps": [
                "1. Audit null sessions and guest permissions on accessible shares.",
                "2. Harvest readable files for cleartext credentials and scripts.",
                "3. Authenticate with recovered credentials for privilege escalation.",
            ],
        })
    if has_creds:
        fallback_paths.append({
            "name": "Credential Reuse & Service Authentication",
            "probability": "HIGH",
            "prerequisites": "Recovered valid credentials",
            "steps": [
                "1. Test recovered credentials against SSH, WinRM, or database services.",
                "2. Establish interactive shell session.",
                "3. Perform local security configuration audit.",
            ],
        })

    return fallback_paths
