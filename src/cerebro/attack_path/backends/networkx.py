"""
NetworkX backend implementation for the attack graph.

This is the default in-memory backend suitable for smaller deployments.
"""

import networkx as nx
from typing import Any, Dict, List, Optional
from ..graph_model import AttackNode, AttackEdge, NodeType
from .backend import GraphBackend

class NetworkXBackend(GraphBackend):
    """
    In-memory NetworkX implementation of the graph backend.
    """

    def __init__(self):
        self.graph = nx.DiGraph()
        self._nodes: Dict[str, AttackNode] = {}
        self._edges: Dict[str, AttackEdge] = {}

    async def clear(self) -> None:
        self.graph.clear()
        self._nodes.clear()
        self._edges.clear()

    async def add_node(self, node: AttackNode) -> None:
        self._nodes[node.node_id] = node
        self.graph.add_node(node.node_id, **node.__dict__)

    async def add_edge(self, edge: AttackEdge) -> None:
        self._edges[edge.edge_id] = edge
        self.graph.add_edge(
            edge.source_node,
            edge.target_node,
            edge_id=edge.edge_id,
            weight=edge.weight,
            permission=edge.permission,
            privilege_level=edge.privilege_level,
            edge_type=edge.edge_type.value,
            **edge.__dict__
        )

    async def get_node(self, node_id: str) -> Optional[AttackNode]:
        return self._nodes.get(node_id)

    async def get_edge(self, source_id: str, target_id: str) -> Optional[AttackEdge]:
        if self.graph.has_edge(source_id, target_id):
            edge_data = self.graph.edges[source_id, target_id]
            edge_id = edge_data.get("edge_id")
            if edge_id:
                return self._edges.get(edge_id)
        return None

    async def get_neighbors(
        self, node_id: str, direction: str = "outbound"
    ) -> List[AttackNode]:
        neighbors = []
        if direction == "outbound":
            successors = list(self.graph.successors(node_id))
            neighbors = [self._nodes[nid] for nid in successors if nid in self._nodes]
        elif direction == "inbound":
            predecessors = list(self.graph.predecessors(node_id))
            neighbors = [self._nodes[nid] for nid in predecessors if nid in self._nodes]
        return neighbors

    async def get_node_degree(self, node_id: str) -> Dict[str, int]:
        if node_id not in self.graph:
            return {"in_degree": 0, "out_degree": 0, "total_degree": 0}
        
        in_degree = self.graph.in_degree(node_id)
        out_degree = self.graph.out_degree(node_id)
        
        return {
            "in_degree": in_degree,
            "out_degree": out_degree,
            "total_degree": in_degree + out_degree,
        }

    async def shortest_path(
        self, source_id: str, target_id: str, weight_field: str = "weight"
    ) -> List[str]:
        return nx.shortest_path(
            self.graph, source_id, target_id, weight=weight_field
        )

    async def all_simple_paths(
        self, source_id: str, target_id: str, cutoff: int
    ) -> List[List[str]]:
        return list(
            nx.all_simple_paths(self.graph, source_id, target_id, cutoff=cutoff)
        )

    async def get_nodes_by_type(self, node_type: str) -> List[AttackNode]:
        # Convert string type back to Enum if needed or handle comparison
        try:
            enum_type = NodeType(node_type) if isinstance(node_type, str) else node_type
            return [
                node for node in self._nodes.values() 
                if node.node_type == enum_type
            ]
        except ValueError:
            return []

    async def get_metrics(self) -> Dict[str, Any]:
        if self.graph.number_of_nodes() > 0:
            density = nx.density(self.graph)
            avg_degree = sum(dict(self.graph.degree()).values()) / self.graph.number_of_nodes()
        else:
            density = 0.0
            avg_degree = 0.0
            
        return {
            "total_nodes": len(self._nodes),
            "total_edges": len(self._edges),
            "density": density,
            "average_degree": avg_degree
        }
