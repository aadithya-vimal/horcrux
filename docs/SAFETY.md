# Safety Boundary

HORCRUX automatically performs: reconnaissance, enumeration,
fingerprinting, safe validation, comparison, evidence collection,
correlation, hypothesis generation, attack-path analysis, exploit
intelligence, handoff preparation.

It never automatically performs destructive or final exploitation.
`ExploitHandoff` (target, vulnerability, evidence, confidence, affected
component, prerequisites, recommended operator action, tools, risks, why
manual approval is required) is the boundary; `operator_approval_required`
is always true.

Enforcement is deterministic, not prompt-based:

- `CapabilityRegistry` safety classes (`SAFE/LOW/MEDIUM/HIGH/FORBIDDEN`);
  `HIGH`/`FORBIDDEN` require explicit `operator_approved` input.
- Destructive-input deny-list rejects exploit/payload markers without
  approval.
- Scope enforcement (`horcrux/core/policy.py::is_url_allowed`,
  `validate_redirect_chain`) covers target, hostname, URL, port, protocol,
  and redirect destinations. Browser navigation is scope-gated per page.
- The LLM cannot bypass any of the above; violations surface as
  `SCOPE_BLOCKED` / `APPROVAL_REQUIRED` structured states.
