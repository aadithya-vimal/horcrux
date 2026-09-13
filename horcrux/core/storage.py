from __future__ import annotations

import json
import re
from pathlib import Path

from horcrux.models import (
    Action,
    ArtifactRecord,
    AuditEntry,
    Credential,
    DiscoveredPath,
    ExploitCandidate,
    Finding,
    Parameter,
    RawObservation,
    ResponseFamily,
    Service,
    Software,
    SubsystemState,
    WebTarget,
    WorkspaceState,
)


def safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value)


class Workspace:
    def __init__(self, target: str, base: str = "workspaces"):
        self.target = target
        self.root = Path(base) / safe_name(target)
        self.raw = self.root / "raw"
        self.responses = self.root / "responses"
        self.headers = self.root / "headers"
        self.reports = self.root / "reports"

        self.root.mkdir(parents=True, exist_ok=True)
        for directory in (self.raw, self.responses, self.headers, self.reports):
            directory.mkdir(exist_ok=True)

        self.state_file = self.root / "state.json"

    def load(self) -> WorkspaceState:
        if self.state_file.exists():
            return WorkspaceState.model_validate_json(
                self.state_file.read_text(encoding="utf-8")
            )
        state = WorkspaceState(target=self.target)
        self.save(state)
        return state

    def save(self, state: WorkspaceState) -> None:
        from datetime import datetime, timezone
        state.updated_at = datetime.now(timezone.utc)
        self.state_file.write_text(
            state.model_dump_json(indent=2),
            encoding="utf-8",
        )

    def write(self, relative: str, content: str) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", errors="replace")
        return path

    def write_json(self, relative: str, data) -> Path:
        return self.write(relative, json.dumps(data, indent=2, default=str))

    def upsert_services(self, items: list[Service]) -> None:
        state = self.load()
        current = {(x.port, x.protocol): x for x in state.services}
        for item in items:
            current[(item.port, item.protocol)] = item
        state.services = list(current.values())
        self.save(state)

    def upsert_software(self, items: list[Software]) -> None:
        state = self.load()
        seen = {(x.product, x.version, x.service, x.source) for x in state.software}
        for item in items:
            key = (item.product, item.version, item.service, item.source)
            if key not in seen:
                state.software.append(item)
                seen.add(key)
        self.save(state)

    def add_credentials(self, items: list[Credential]) -> None:
        if not items:
            return
        state = self.load()
        seen = {(x.username, x.secret, x.kind, x.source) for x in state.credentials}
        for item in items:
            key = (item.username, item.secret, item.kind, item.source)
            if key not in seen:
                state.credentials.append(item)
                seen.add(key)
        self.save(state)

    def upsert_finding(self, finding: Finding) -> None:
        state = self.load()
        for idx, old in enumerate(state.findings):
            if old.id == finding.id:
                state.findings[idx] = finding
                break
        else:
            state.findings.append(finding)
        self.save(state)

    def upsert_audit(self, entry: AuditEntry) -> None:
        state = self.load()
        for idx, old in enumerate(state.audit):
            if old.id == entry.id:
                state.audit[idx] = entry
                break
        else:
            state.audit.append(entry)
        self.save(state)

    def upsert_audits(self, items: list[AuditEntry]) -> None:
        if not items:
            return
        state = self.load()
        lookup = {a.id: idx for idx, a in enumerate(state.audit)}
        for entry in items:
            if entry.id in lookup:
                state.audit[lookup[entry.id]] = entry
            else:
                state.audit.append(entry)
                lookup[entry.id] = len(state.audit) - 1
        self.save(state)

    def set_actions(self, items: list[Action]) -> None:
        state = self.load()
        state.actions = sorted(items, key=lambda x: -x.score)
        self.save(state)

    def set_exploits(self, items: list[ExploitCandidate]) -> None:
        state = self.load()
        state.exploits = items
        self.save(state)

    def set_subsystem_state(self, name: str, sub_state: SubsystemState | str) -> None:
        state = self.load()
        state.set_subsystem_state(name, sub_state)
        self.save(state)

    def upsert_discovered_paths(self, items: list[DiscoveredPath]) -> None:
        if not items:
            return
        state = self.load()
        lookup = {p.url: idx for idx, p in enumerate(state.discovered_paths)}
        for p in items:
            if p.url in lookup:
                state.discovered_paths[lookup[p.url]] = p
            else:
                state.discovered_paths.append(p)
                lookup[p.url] = len(state.discovered_paths) - 1
        self.save(state)

    def add_artifact(self, record: ArtifactRecord) -> None:
        state = self.load()
        state.artifacts.append(record)
        self.save(state)

    def upsert_web_target(self, target: WebTarget) -> None:
        state = self.load()
        state.upsert_web_target(target)
        self.save(state)

    def add_raw_observations(self, items: list[RawObservation]) -> None:
        if not items:
            return
        state = self.load()
        state.raw_observations.extend(items)
        self.save(state)

    def add_parameters(self, items: list[Parameter]) -> None:
        if not items:
            return
        state = self.load()
        seen = {(p.name.lower(), p.endpoint) for p in state.parameters}
        for item in items:
            key = (item.name.lower(), item.endpoint)
            if key not in seen:
                state.parameters.append(item)
                seen.add(key)
        self.save(state)

    def upsert_response_families(self, items: list[ResponseFamily]) -> None:
        if not items:
            return
        state = self.load()
        lookup = {f.family_id: idx for idx, f in enumerate(state.response_families)}
        for item in items:
            if item.family_id in lookup:
                state.response_families[lookup[item.family_id]] = item
            else:
                state.response_families.append(item)
                lookup[item.family_id] = len(state.response_families) - 1
        self.save(state)


