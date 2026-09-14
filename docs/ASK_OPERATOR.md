# Ask & Operator Controls

`ask` is an interface to HORCRUX state, not a generic chatbot
(`horcrux/intel/ask_engine.py`).

Intent router (deterministic-first, 11 classes): EXPLAIN, EVIDENCE,
GAP_ANALYSIS, HYPOTHESIS, FINDING, INVESTIGATE, PRIORITIZE, STEER, REPORT,
STATUS, MANUAL_GUIDANCE. The LLM is only consulted for ambiguous prose;
simple state queries never spend model calls.

Examples:

- `ask What remains untested?` → coverage + unresolved hypotheses + queue.
- `ask Why is this finding LIKELY?` → supporting vs missing evidence.
- `ask Explain this attack path.` → nodes, edges, evidence, assumptions.
- `ask Focus on authorization.` → validated `SET_OPERATOR_FOCUS` action.
- `ask Investigate authorization on these APIs.` → creates investigations.
- `ask What evidence would disprove this hypothesis?` → disproof criteria.
- `ask What changed since the last reassessment?` → state-delta analysis.

State changes happen only through typed `AskAction`s validated by
`validate_and_apply_action()`; the LLM never mutates state.

Operator controls (console + direct CLI where applicable):

- `focus web|api|auth|authz|business-logic|network|all`
- `pause` / `resume` (no new work while paused; subprocesses drain)
- `skip <id-or-keyword>`, `prioritize <id-or-keyword>`
- `why [investigation|finding <id>|not <ref>]` — structured rationale
- `assess [--iterations N] [--workers W]`, `status`, `report`, `replay`
