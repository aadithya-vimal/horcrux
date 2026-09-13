"""Specialist agent execution."""

from __future__ import annotations

import secrets
from typing import TYPE_CHECKING, Any

from horcrux.agents.registry import SPECIALIST_REGISTRY
from horcrux.agents.skills import select_skills
from horcrux.agents.tools.registry import ToolRegistry, ToolResult, create_default_registry
from horcrux.intel.ingestion import ingest_http_request, ingest_javascript_routes
from horcrux.intel.investigations import Investigation, InvestigationState
from horcrux.models import AgentRuntimeState, Finding, FindingStatus, Severity, ValidationState

if TYPE_CHECKING:
    from horcrux.models import WorkspaceState


class SpecialistExecutor:
    def __init__(self, tool_registry: ToolRegistry | None = None):
        self.tools = tool_registry or create_default_registry()

    def execute_investigation(
        self,
        state: WorkspaceState,
        investigation: Investigation,
    ) -> dict[str, Any]:
        """Execute an investigation using appropriate specialist and tools."""
        spec = SPECIALIST_REGISTRY.get(investigation.specialist)
        if not spec:
            return {"success": False, "error": f"Unknown specialist: {investigation.specialist}"}

        app = state.get_application_model()
        skills = select_skills(
            investigation.vulnerability_classes,
            app.summary(),
        )

        investigation.state = InvestigationState.RUNNING
        results: list[ToolResult] = []

        for tool_name in investigation.candidate_tools:
            if tool_name not in self.tools._tools:
                continue
            tool_result = self._invoke_tool(tool_name, state, investigation)
            results.append(tool_result)
            self._apply_tool_result(state, tool_result, investigation)

        outcome = self._evaluate_outcome(investigation, results, skills)
        investigation.state = outcome["state"]
        investigation.result_summary = outcome["summary"]

        return {
            "success": True,
            "specialist": investigation.specialist,
            "tools_executed": [r.tool for r in results],
            "outcome": outcome,
            "skills_used": [s.id for s in skills],
        }

    def _invoke_tool(
        self,
        tool_name: str,
        state: WorkspaceState,
        investigation: Investigation,
    ) -> ToolResult:
        app = state.get_application_model()
        request_id = secrets.token_hex(8)
        kwargs: dict[str, Any] = {"request_id": request_id}

        if tool_name == "http_probe":
            ep = app.endpoints[0] if app.endpoints else None
            kwargs["endpoint"] = ep.path if ep else "/"
            kwargs["identity"] = "anonymous"
            if "authorization" in investigation.objective.lower():
                kwargs["identity"] = "user"
        elif tool_name == "js_analyzer":
            wt = app.web_targets[0] if app.web_targets else None
            kwargs["base_url"] = wt.base_url if wt else f"http://{state.target}"
            kwargs["routes"] = [e.path for e in app.endpoints if "javascript" in e.sources][:10]
            kwargs["parameters"] = [p.name for p in app.parameters[:10]]
        elif tool_name == "identity_switch":
            kwargs["from_identity"] = "anonymous"
            kwargs["to_identity"] = "user"
        elif tool_name == "validator":
            path = app.endpoints[0].path if app.endpoints else "/"
            kwargs["path"] = path
            kwargs["port"] = app.web_targets[0].port if app.web_targets else 80
        elif tool_name == "browser_navigate":
            wt = app.web_targets[0] if app.web_targets else None
            kwargs["url"] = wt.base_url if wt else f"http://{state.target}"

        return self.tools.execute(tool_name, **kwargs)

    def _apply_tool_result(
        self,
        state: WorkspaceState,
        result: ToolResult,
        investigation: Investigation,
    ) -> None:
        app = state.get_application_model()
        data = result.structured_data

        if result.tool == "js_analyzer" and data.get("routes"):
            ingest_javascript_routes(app, data["routes"], data.get("parameters", []))

        if result.tool == "http_probe" and data.get("endpoint"):
            identity = data.get("identity", "anonymous")
            ingest_http_request(
                app,
                method=data.get("method", "GET"),
                path=data["endpoint"],
                identity=identity,
                source="http_probe",
            )
            # Authorization investigation: detect potential IDOR
            if (
                "authorization" in investigation.objective.lower()
                and data.get("status_code") == 200
                and identity == "user"
            ):
                finding = Finding(
                    id=f"authz-potential-idor-{secrets.token_hex(4)}",
                    title="Potential object-level authorization weakness",
                    category="authorization",
                    severity=Severity.medium,
                    confidence=0.65,
                    status=FindingStatus.suspected,
                    validation_state=ValidationState.likely,
                    target=state.target,
                    affected_asset=data["endpoint"],
                    evidence=result.evidence_refs,
                    reproduction=[
                        f"Authenticate as user A",
                        f"Access {data['endpoint']} with user B's object ID",
                        "Compare response for unauthorized access",
                    ],
                    why_it_matters="Object access may not be bound to authenticated identity",
                    recommended_next_action="Manual validation with distinct user accounts",
                )
                state.findings.append(finding)

        if result.tool == "identity_switch" and data.get("session_established"):
            from horcrux.intel.application_model import IdentityRole, SemanticIdentity
            app.upsert_identity(SemanticIdentity(role=IdentityRole.USER, label="test_user"))

        state.set_application_model(app)

    def _evaluate_outcome(
        self,
        investigation: Investigation,
        results: list[ToolResult],
        skills: list,
    ) -> dict[str, Any]:
        if not results:
            return {"state": InvestigationState.BLOCKED, "summary": "No tools available"}

        success_count = sum(1 for r in results if r.success)
        if success_count == 0:
            return {"state": InvestigationState.BLOCKED, "summary": "All tool executions failed"}

        if "authorization" in investigation.objective.lower():
            auth_data = next((r.structured_data for r in results if r.tool == "http_probe"), {})
            if auth_data.get("status_code") == 200 and not auth_data.get("authorization_enforced"):
                return {
                    "state": InvestigationState.SUPPORTED,
                    "summary": "Evidence suggests authorization may not be enforced on object endpoint",
                }

        return {
            "state": InvestigationState.COMPLETE,
            "summary": f"Executed {success_count} tool(s); gathered structured evidence",
        }


def update_agent_states(state: WorkspaceState, active_specialist: str | None = None) -> None:
    """Sync agent runtime states from application evidence."""
    from horcrux.agents.registry import select_specialists

    specialists = select_specialists(state)
    states: list[AgentRuntimeState] = []
    for spec in SPECIALIST_REGISTRY.values():
        is_active = spec.agent_id == active_specialist
        is_ready = any(s.agent_id == spec.agent_id for s in specialists)
        status = "RUNNING" if is_active else ("READY" if is_ready else "WAITING")
        states.append(
            AgentRuntimeState(
                agent_id=spec.agent_id,
                name=spec.name,
                status=status,
                objective=spec.objective,
            )
        )
    state.agent_states = states
