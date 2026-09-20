"""Deterministic evidence graph.

Target -> Service -> Application -> Route -> Endpoint -> Request ->
Parameter -> Object -> ObjectInstance -> Identity -> Session -> Technology
-> Response -> ExtractedArtifact -> SecurityProperty -> Finding

Every conclusion is traceable through this graph. No conclusion exists
without an evidence chain.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from horcrux.engine.observations import Observation


class GraphNode(BaseModel):
    id: str
    kind: str  # target|service|route|endpoint|request|parameter|object|instance|identity|response|artifact|property|finding
    label: str
    refs: list[str] = Field(default_factory=list)


class GraphEdge(BaseModel):
    source_id: str
    target_id: str
    relation: str
    evidence: list[str] = Field(default_factory=list)


class EvidenceGraph(BaseModel):
    nodes: dict[str, GraphNode] = Field(default_factory=dict)
    edges: list[GraphEdge] = Field(default_factory=list)

    def add_node(self, node_id: str, kind: str, label: str,
                 refs: list[str] | None = None) -> GraphNode:
        if node_id not in self.nodes:
            self.nodes[node_id] = GraphNode(id=node_id, kind=kind, label=label,
                                            refs=list(refs or []))
        else:
            for r in (refs or []):
                if r not in self.nodes[node_id].refs:
                    self.nodes[node_id].refs.append(r)
        return self.nodes[node_id]

    def add_edge(self, src: str, dst: str, relation: str,
                 evidence: list[str] | None = None) -> None:
        self.edges.append(GraphEdge(source_id=src, target_id=dst,
                                    relation=relation,
                                    evidence=list(evidence or [])))

    def chain_to(self, node_id: str) -> list[str]:
        """Evidence chain: ordered edge descriptions leading to node."""
        chain: list[str] = []
        for e in self.edges:
            if e.target_id == node_id:
                chain.append(f"{e.source_id} -[{e.relation}]-> {e.target_id}"
                             + (f" ({'; '.join(e.evidence[:2])})" if e.evidence else ""))
        return chain


def build_graph_for_observations(target: str,
                                 observations: list[Observation]) -> EvidenceGraph:
    g = EvidenceGraph()
    g.add_node(f"target:{target}", "target", target)
    for idx, ob in enumerate(observations):
        base = f"ob{idx}"
        ep_id = f"endpoint:{ob.method}:{ob.endpoint}"
        g.add_node(ep_id, "endpoint", f"{ob.method} {ob.endpoint}",
                   [f"{ob.source}:status={ob.status}"])
        g.add_edge(f"target:{target}", ep_id, "serves",
                   [f"{ob.source}:{ob.status}"])
        if ob.parameter:
            p_id = f"param:{ob.endpoint}:{ob.parameter}"
            g.add_node(p_id, "parameter", ob.parameter, [ob.provenance])
            g.add_edge(ep_id, p_id, "accepts", [ob.provenance])
            _ = base
        for name in ob.extracted_entities.get("objects", []) or []:
            o_id = f"object:{name}"
            g.add_node(o_id, "object", str(name))
            g.add_edge(ep_id, o_id, "exposes")
        if ob.identity and ob.identity != "anonymous":
            i_id = f"identity:{ob.identity}"
            g.add_node(i_id, "identity", ob.identity)
            g.add_edge(i_id, ep_id, "accessed")
    return g
