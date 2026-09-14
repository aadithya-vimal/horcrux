# HORCRUX Architecture

Deterministic execution/state engine is authoritative. The LLM reasons over
semantic state and never mutates it directly.

```
target → recon → ApplicationModel → hypotheses → investigations
  → CapabilityRegistry → CommandRunner / adapters → evidence
  → ingestion → model update → reassess → attack paths → ExploitHandoff
```

Source of truth (all persisted in `workspaces/<target>/state.json`):

- `ApplicationModel` (`horcrux/intel/application_model.py`) — endpoints,
  routes, parameters, identities, sessions, objects, lifecycles, workflows,
  transitions, API/GraphQL operations, technologies, service facts.
- `WorkspaceState` (`horcrux/models.py`) — services, findings, hypotheses,
  investigations, coverage, attack paths, handoffs, operator focus,
  scheduler state.
- `CapabilityRegistry` (`horcrux/agents/tools/capabilities.py`) — the only
  execution boundary. Specialists never run shell directly.
- Structured event log (`workspaces/<target>/raw/events.jsonl`).

Correct AI flow: LLM reasoning → structured result → schema validation →
scope/safety validation → orchestrator decision → deterministic mutation.
