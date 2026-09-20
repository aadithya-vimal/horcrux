"""State-consistency regressions: one authoritative assessment state across
findings / graph / next / status.

Graph labels: HYPOTHESIS vs SUPPORTED vs REFUTED vs INSUFFICIENT_EVIDENCE
vs BLOCKED vs CONFIRMED. "evidenced" requires validator/adjudication
evidence — never mere endpoint observation.
"""

from __future__ import annotations

from horcrux.intel.application_model import ApplicationModel, SemanticEndpoint
from horcrux.intel.attack_paths import build_attack_paths
from horcrux.intel.hypotheses import Hypothesis, HypothesisClass, HypothesisStatus
from horcrux.intel.investigations import Investigation, InvestigationState
from horcrux.models import Finding, FindingStatus, Parameter, Severity, ValidationState, WorkspaceState


def _ep(path: str, refs: list[str] | None = None) -> SemanticEndpoint:
    ep = SemanticEndpoint(method="GET", path=path, sources=["fixture"],
                          evidence_refs=list(refs or [f"fixture:{path}"]))
    ep.ensure_id()
    return ep


def _hyp(cls: HypothesisClass, status: HypothesisStatus,
         asset_refs: list[str] | None = None) -> Hypothesis:
    h = Hypothesis(hypothesis_class=cls, title=f"{cls.value} hypothesis",
                   status=status, asset_refs=list(asset_refs or []),
                   evidence_refs=["hyp-evidence"] if status == HypothesisStatus.SUPPORTED else [])
    h.ensure_id()
    return h


def _inv(objective: str, terminal: InvestigationState, hyp_id: str = "",
         observations: list[str] | None = None) -> Investigation:
    inv = Investigation(id="", objective=objective, candidate_tools=["api_probe"],
                        required_capabilities=["http"], specialist="WebAgent",
                        state=terminal, hypothesis_id=hyp_id,
                        observations=list(observations or []))
    inv.ensure_id()
    return inv


def _state(endpoints, hyps, invs, findings=None) -> WorkspaceState:
    st = WorkspaceState(target="t.local")
    app = ApplicationModel(target="t.local")
    app.endpoints = endpoints
    st.set_application_model(app)
    st.set_hypotheses(hyps)
    st.set_investigations(invs)
    st.findings = list(findings or [])
    return st


def _finding(asset: str, inv_id: str = "", hyp_id: str = "") -> Finding:
    return Finding(id="find-1", title="API Security Weakness", category="api-security",
                   severity=Severity.medium, confidence=0.9, status=FindingStatus.verified,
                   validation_state=ValidationState.confirmed, target="t.local",
                   affected_asset=asset, evidence=["validator evidence"],
                   investigation_id=inv_id, hypothesis_id=hyp_id)


def _idor_path(paths, asset: str):
    return next(p for p in paths if p.name.startswith("Object reference"))


# A. hypothesis, no validator evidence -> HYPOTHESIS, no finding -----------
def test_a_hypothesis_without_evidence_is_labeled_hypothesis():
    ep = _ep("/api/widgets/1")
    h = _hyp(HypothesisClass.IDOR_BOLA, HypothesisStatus.OPEN, [ep.id])
    st = _state([ep], [h], [])
    paths = build_attack_paths(st)
    p = _idor_path(paths, "/api/widgets/1")
    assert p.status == "HYPOTHESIS"
    assert p.finding_ids == []
    assert p.probability != "HIGH"
    assert not any(e.security_evidence for e in p.edges)
    assert st.findings == []


# B. REFUTED -> graph REFUTED, no finding, next does not resurrect ---------
def test_b_refuted_stays_refuted_and_next_ignores_it():
    from horcrux.core.actions import compute_investigation_actions
    ep = _ep("/api/widgets/1")
    h = _hyp(HypothesisClass.IDOR_BOLA, HypothesisStatus.REFUTED, [ep.id])
    inv = _inv("BOLA check", InvestigationState.REFUTED, h.id,
               ["matrix_asset:/api/widgets/1"])
    st = _state([ep], [h], [inv])
    paths = build_attack_paths(st)
    p = _idor_path(paths, "/api/widgets/1")
    assert p.status == "REFUTED"
    assert p.finding_ids == []
    assert st.findings == []
    actions = compute_investigation_actions(st)
    assert len(actions) == 1 and actions[0].id == "queue_drained"
    assert inv.state == InvestigationState.REFUTED  # untouched


# C. INSUFFICIENT_EVIDENCE -> labeled, no finding; materialized follow-up --
def test_c_insufficient_labels_path_and_materialized_followup_is_next():
    from horcrux.core.actions import compute_investigation_actions
    ep = _ep("/api/widgets/1")
    h = _hyp(HypothesisClass.IDOR_BOLA, HypothesisStatus.INVESTIGATING, [ep.id])
    inv = _inv("BOLA check", InvestigationState.INSUFFICIENT_EVIDENCE, h.id,
               ["matrix_asset:/api/widgets/1"])
    st = _state([ep], [h], [inv])
    paths = build_attack_paths(st)
    assert _idor_path(paths, "/api/widgets/1").status == "INSUFFICIENT_EVIDENCE"
    assert st.findings == []
    # No materialized follow-up -> terminal message, no synthesis.
    assert compute_investigation_actions(st)[0].id == "queue_drained"
    # Materialized follow-up -> next returns exactly that investigation.
    follow = _inv("BOLA retest with corrected input", InvestigationState.READY, h.id,
                  ["matrix_asset:/api/widgets/1"])
    st.set_investigations([inv, follow])
    actions = compute_investigation_actions(st)
    assert follow.objective in actions[0].title


# D. SUPPORTED -> canonical finding, graph references it -------------------
def test_d_supported_creates_finding_and_graph_links_it():
    from horcrux.intel.attack_paths import attack_paths_to_dict
    from horcrux.intel.events import attack_path_lineage, finding_lineage
    ep = _ep("/api/widgets/1")
    h = _hyp(HypothesisClass.IDOR_BOLA, HypothesisStatus.SUPPORTED, [ep.id])
    inv = _inv("BOLA check", InvestigationState.SUPPORTED, h.id,
               ["matrix_asset:/api/widgets/1"])
    st = _state([ep], [h], [inv], [_finding("/api/widgets/1", inv.id, h.id)])
    paths = build_attack_paths(st)
    st.attack_paths = attack_paths_to_dict(paths)
    p = _idor_path(paths, "/api/widgets/1")
    assert p.status == "CONFIRMED"
    assert p.finding_ids == ["find-1"]
    assert len(st.findings) == 1
    lin = attack_path_lineage(st, p.id)
    assert lin["finding_ids"] == ["find-1"]
    assert lin["status"] == "CONFIRMED"
    flin = finding_lineage(st, "find-1")
    assert flin["validation_state"] == "CONFIRMED"


# E. queue=0 -> no synthetic actions ---------------------------------------
def test_e_drained_queue_returns_terminal_message():
    from horcrux.core.actions import compute_investigation_actions, compute_next_actions
    ep = _ep("/api/widgets/1")
    h = _hyp(HypothesisClass.IDOR_BOLA, HypothesisStatus.REFUTED, [ep.id])
    inv = _inv("BOLA check", InvestigationState.REFUTED, h.id)
    st = _state([ep], [h], [inv])
    st.parameters = [Parameter(name="isPeriodic", location="query",
                               endpoint="http://t.local/polyfills.js")]
    actions = compute_investigation_actions(st)
    assert [a.id for a in actions] == ["queue_drained"]
    assert "No executable investigations remain" in actions[0].title
    legacy = compute_next_actions(st)
    assert "param_audit" not in [a.id for a in legacy]


# F. static JS parameter cannot become executable input --------------------
def test_f_static_js_parameter_is_not_server_bound():
    from horcrux.intel.parameters import is_server_bound_parameter
    from horcrux.intel.test_matrix import derive_applicable_tests
    good = Parameter(name="q", location="query", endpoint="/search")
    bad = Parameter(name="isPeriodic", location="query",
                    endpoint="http://t.local/polyfills.js")
    known = {"/search", "/polyfills.js"}
    assert is_server_bound_parameter(good, known) is True
    assert is_server_bound_parameter(bad, known) is False
    assert is_server_bound_parameter(bad, set()) is False
    app = ApplicationModel(target="t.local")
    app.endpoints = [_ep("/search"), _ep("/polyfills.js")]
    from horcrux.intel.application_model import SemanticParameter
    app.parameters = [SemanticParameter(name="isPeriodic", location="query",
                                        endpoint="http://t.local/polyfills.js",
                                        source="javascript", evidence_refs=["js"])]
    tests = derive_applicable_tests(app, None)
    assert not any("isPeriodic" in (t.target_parameter or "") for t in tests)


# G. refuted Feedbacks-like path stays historical, never confirmed --------
def test_g_refuted_path_is_historical_not_confirmed():
    ep = _ep("/api/Feedbacks/1")
    h = _hyp(HypothesisClass.IDOR_BOLA, HypothesisStatus.REFUTED, [ep.id])
    inv = _inv("BOLA check", InvestigationState.REFUTED, h.id,
               ["matrix_asset:/api/Feedbacks/1"])
    st = _state([ep], [h], [inv])
    paths = build_attack_paths(st)
    statuses = {p.status for p in paths}
    assert "CONFIRMED" not in statuses
    assert "REFUTED" in statuses
    assert st.findings == []


# H. unvalidated /rest/admin hypothesis is HYPOTHESIS, never evidenced ----
def test_h_unvalidated_admin_hypothesis_is_not_evidenced():
    ep = _ep("/rest/admin")
    h = _hyp(HypothesisClass.PRIVILEGE_ESCALATION, HypothesisStatus.OPEN, [ep.id])
    st = _state([ep], [h], [])
    paths = build_attack_paths(st)
    admin = next(p for p in paths if p.name.startswith("Privileged function"))
    assert admin.status == "HYPOTHESIS"
    assert admin.finding_ids == []
    assert not any(e.security_evidence for e in admin.edges)
    from horcrux.ui.console import edge_display_kind, path_status_badge
    assert "HYPOTHESIS" in path_status_badge(admin.status)
    assert all(edge_display_kind(e.model_dump()) != "evidenced" for e in admin.edges)


# Invariants ---------------------------------------------------------------
def test_invariants_finding_evidence_and_next_ready():
    from horcrux.core.actions import compute_investigation_actions
    ep = _ep("/api/widgets/1")
    h = _hyp(HypothesisClass.IDOR_BOLA, HypothesisStatus.SUPPORTED, [ep.id])
    inv = _inv("BOLA check", InvestigationState.SUPPORTED, h.id,
               ["matrix_asset:/api/widgets/1"])
    st = _state([ep], [h], [inv], [_finding("/api/widgets/1", inv.id, h.id)])
    # Every CONFIRMED finding has evidence.
    for f in st.findings:
        assert f.validation_state == ValidationState.confirmed
        assert f.evidence
    # Every CONFIRMED graph item references a canonical finding.
    for p in build_attack_paths(st):
        if p.status == "CONFIRMED":
            assert p.finding_ids
            assert all(fid in {f.id for f in st.findings} for fid in p.finding_ids)
    # next() items map to real READY investigations.
    ready = _inv("Follow-up probe", InvestigationState.READY, h.id)
    st.set_investigations([inv, ready])
    actions = compute_investigation_actions(st)
    ready_ids = {i.id for i in st.get_investigations()
                 if i.state == InvestigationState.READY}
    assert ready.objective in actions[0].title
    assert ready.id in ready_ids
