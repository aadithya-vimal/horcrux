# Application Model

`horcrux/intel/application_model.py` + `horcrux/intel/ingestion.py`.

Beyond endpoint inventory the model represents behavior:

- **Endpoints** with mutation flags, API versions, response hints, provenance.
- **Parameters** with classes (`object_id`, `pagination`, `filtering`,
  `url_fetch`, `file`, `auth_credential`, `client_state`).
- **Sessions** (`SessionRecord`): identity, role, cookie/token *hashes* only,
  login/logout/expiry transitions. Raw secrets are never stored.
- **Object lifecycles** (`ObjectLifecycle`): read/mutation/delete endpoints,
  observed identities, relationships, authorization notes.
- **Workflows + transitions** (`WorkflowTransition`): trigger, endpoint,
  identity, preconditions, postconditions, state-changing flag, provenance.
- **API operations** (`APIOperation`): deduplicated `METHOD /path/{id}` view
  correlating browser + JS + HTTP + fuzzer + schema evidence.
- **GraphQL operations** (`GraphQLOperation`): queries/mutations, fields,
  object types, authorization notes.
- **Trust boundaries** (`SecurityBoundary`) and protocol `ServiceFact`s.

Ingestion is idempotent (stable fingerprint IDs, dedup) and every fact
carries `sources` / `evidence_refs` / `provenance` (`browser`, `http`,
`javascript`, `crawler`, `scanner`, `operator`, `inference`).
