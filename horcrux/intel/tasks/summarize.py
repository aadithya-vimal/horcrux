from __future__ import annotations

import json
from horcrux.models import ValidationState, WorkspaceState
from horcrux.intel.tasks.triage import build_compact_state


def execute_executive_summary(
    ai_manager,
    state: WorkspaceState,
) -> str:
    """
    Generates a concise executive risk summary grounded in discovered evidence.
    Falls back to deterministic template if AI is unavailable.
    """
    confirmed = [f for f in state.findings if f.validation_state == ValidationState.confirmed]
    likely = [f for f in state.findings if f.validation_state == ValidationState.likely]

    payload = {
        "target": state.target,
        "services_count": len(state.services),
        "confirmed_findings": [
            {"title": f.title, "severity": f.severity.value, "impact": f.why_it_matters}
            for f in confirmed[:5]
        ],
        "likely_findings_count": len(likely),
        "audited_controls_count": len(state.audit),
    }

    prompt = f"""Generate a concise, professional executive security assessment summary (2-3 paragraphs).
Focus on observed posture, critical exposures, and priority mitigations.
Strictly adhere to the HORCRUX evidence policy: do not exaggerate or invent facts.
Assessment data:
{json.dumps(payload, indent=2)}
"""

    resp = ai_manager.call_task("executive_summary", prompt, payload=payload, max_tokens=768)
    if resp and resp.content and len(resp.content.strip()) > 30:
        return resp.content.strip()

    # Deterministic fallback summary
    return (
        f"Automated security reconnaissance and validation completed for target {state.target}. "
        f"Discovered {len(state.services)} active network service(s), {len(confirmed)} confirmed "
        f"vulnerability finding(s), and {len(state.audit)} audited control check(s). "
        f"Review verified findings and execute prioritized next actions."
    )
