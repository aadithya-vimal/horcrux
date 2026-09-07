from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class EngagementMode(str, Enum):
    LAB = "LAB"
    AUTHORIZED = "AUTHORIZED"
    READ_ONLY = "READ_ONLY"
    ANALYSIS_ONLY = "ANALYSIS_ONLY"


class OperatorMode(str, Enum):
    MAP = "MAP"
    OPERATOR = "OPERATOR"
    AUTOMATION = "AUTOMATION"


@dataclass
class ActionProposal:
    action_type: str
    target: str
    rationale: str = ""
    prerequisites: list[str] = field(default_factory=list)
    expected_evidence: str = ""
    risk_level: str = "SAFE"  # SAFE, LOW, MEDIUM, HIGH, AGGRESSIVE
    command: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_type": self.action_type,
            "target": self.target,
            "rationale": self.rationale,
            "prerequisites": self.prerequisites,
            "expected_evidence": self.expected_evidence,
            "risk_level": self.risk_level,
            "command": self.command,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ActionProposal:
        return cls(
            action_type=data.get("action_type", ""),
            target=data.get("target", ""),
            rationale=data.get("rationale", ""),
            prerequisites=data.get("prerequisites", []),
            expected_evidence=data.get("expected_evidence", ""),
            risk_level=data.get("risk_level", "SAFE"),
            command=data.get("command", ""),
        )


@dataclass
class EngagementScope:
    allowed_targets: list[str] = field(default_factory=list)
    allowed_networks: list[str] = field(default_factory=list)
    allowed_domains: list[str] = field(default_factory=list)
    excluded_targets: list[str] = field(default_factory=list)
    permitted_categories: list[str] = field(
        default_factory=lambda: [
            "reconnaissance",
            "discovery",
            "fingerprint",
            "web",
            "vuln_check",
            "service_audit",
        ]
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed_targets": self.allowed_targets,
            "allowed_networks": self.allowed_networks,
            "allowed_domains": self.allowed_domains,
            "excluded_targets": self.excluded_targets,
            "permitted_categories": self.permitted_categories,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EngagementScope:
        return cls(
            allowed_targets=data.get("allowed_targets", []),
            allowed_networks=data.get("allowed_networks", []),
            allowed_domains=data.get("allowed_domains", []),
            excluded_targets=data.get("excluded_targets", []),
            permitted_categories=data.get(
                "permitted_categories",
                ["reconnaissance", "discovery", "fingerprint", "web", "vuln_check", "service_audit"],
            ),
        )


@dataclass
class EngagementPolicy:
    mode: EngagementMode = EngagementMode.AUTHORIZED
    operator_mode: OperatorMode = OperatorMode.OPERATOR
    scope: EngagementScope = field(default_factory=EngagementScope)

    def is_target_allowed(self, target: str) -> tuple[bool, str]:
        tgt = target.strip().lower()
        if not tgt:
            return False, "Target is empty."

        for exc in self.scope.excluded_targets:
            if tgt == exc.strip().lower():
                return False, f"Target '{target}' is explicitly excluded by engagement scope."

        if self.scope.allowed_targets:
            allowed = {t.strip().lower() for t in self.scope.allowed_targets}
            if tgt in allowed:
                return True, f"Target '{target}' is in authorized target scope."

            try:
                tgt_ip = ipaddress.ip_address(tgt)
                for net_str in self.scope.allowed_networks:
                    try:
                        net = ipaddress.ip_network(net_str.strip(), strict=False)
                        if tgt_ip in net:
                            return True, f"Target '{target}' is within authorized network {net_str}."
                    except ValueError:
                        pass
            except ValueError:
                for domain in self.scope.allowed_domains:
                    d = domain.strip().lower()
                    if tgt == d or tgt.endswith("." + d):
                        return True, f"Target '{target}' matches authorized domain {domain}."

            return False, f"Target '{target}' is outside declared engagement scope."

        return True, f"Target '{target}' permitted under engagement policy."

    def is_action_allowed(self, proposal: ActionProposal) -> tuple[bool, str]:
        ok, reason = self.is_target_allowed(proposal.target)
        if not ok:
            return False, f"Target rejected by policy: {reason}"

        if self.mode == EngagementMode.READ_ONLY:
            if proposal.risk_level.upper() not in ("SAFE", "READ_ONLY"):
                return (
                    False,
                    f"Engagement mode is READ_ONLY. Action '{proposal.action_type}' (risk: {proposal.risk_level}) prohibited.",
                )

        if self.mode == EngagementMode.ANALYSIS_ONLY:
            return (
                False,
                f"Engagement mode is ANALYSIS_ONLY. Active tool execution is disabled; plan only.",
            )

        if proposal.risk_level.upper() == "AGGRESSIVE" and self.mode != EngagementMode.LAB:
            return (
                False,
                f"Action '{proposal.action_type}' has AGGRESSIVE risk level, which requires LAB mode.",
            )

        return True, "Action permitted under current engagement policy."

    def format_ai_context(self, current_target: str = "") -> str:
        targets_desc = ", ".join(self.scope.allowed_targets) if self.scope.allowed_targets else (current_target or "declared target")
        categories_desc = ", ".join(self.scope.permitted_categories[:4])
        return (
            f"ENGAGEMENT POLICY (HORCRUX SECURITY GOVERNANCE):\n"
            f"- Mode: {self.mode.value}\n"
            f"- Operator Mode: {self.operator_mode.value}\n"
            f"- Authorized Scope: {targets_desc}\n"
            f"- Permitted Operation Classes: {categories_desc}\n"
            f"- Policy Directives: All testing must strictly adhere to declared authorized scope. "
            f"Distinguish verified observations from hypotheses. Propose technical actions with rationale.\n"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode.value,
            "operator_mode": self.operator_mode.value,
            "scope": self.scope.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EngagementPolicy:
        mode_val = data.get("mode", EngagementMode.AUTHORIZED.value)
        op_mode_val = data.get("operator_mode", OperatorMode.OPERATOR.value)
        try:
            mode = EngagementMode(mode_val)
        except ValueError:
            mode = EngagementMode.AUTHORIZED
        try:
            op_mode = OperatorMode(op_mode_val)
        except ValueError:
            op_mode = OperatorMode.OPERATOR
        scope = EngagementScope.from_dict(data.get("scope", {}))
        return cls(mode=mode, operator_mode=op_mode, scope=scope)
