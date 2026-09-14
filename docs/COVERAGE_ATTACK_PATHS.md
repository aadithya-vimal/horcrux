# Coverage & Attack Paths

Coverage (`horcrux/intel/coverage.py`) tracks security *properties*, not
scanner counts: authentication, session_security, authorization,
object/function-level authorization, input_validation, injection,
client_side_security, file_handling, ssrf, business_logic, api_security,
information_disclosure, configuration, infrastructure, web_discovery.
Each domain records applicable/observed/investigated/validated/
confirmed_issue/blocked/not_applicable/unknown plus status.

Attack paths (`horcrux/intel/attack_paths.py`) are graphs:

- Nodes: identity, endpoint, object, vulnerability, workflow_state,
  privilege, capability, trust_boundary, (asset/service/role/hypothesis/finding).
- Edges: enables, requires (depends_on), produces, grants, accesses,
  transitions_to, exposes, authenticates, escalates, reaches, references.
- Every edge carries evidence or is explicitly marked `inference` with a
  rationale. Unsupported paths never render as confirmed.
- `rank_attack_paths()` scores evidence strength, impact, exploitability,
  prerequisites, uncertain edges, and investigation cost, with `rank_why`.
