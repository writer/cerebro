"""
Graph backend abstraction for scalable attack path analysis.

Defines the interface for graph storage backends (NetworkX, Neptune, Neo4j, etc.)
to support scaling beyond in-memory limits.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Set, Tuple
from .graph_model import AttackNode, AttackEdge

class GraphBackend(ABC):
    """
    Abstract base class for attack graph storage backends.
    """

    @abstractmethod
    async def clear(self) -> None:
        """Clear all nodes and edges from the graph."""
        pass

    @abstractmethod
    async def add_node(self, node: AttackNode) -> None:
        """Add a node to the graph."""
        pass

    @abstractmethod
    async def add_edge(self, edge: AttackEdge) -> None:
        """Add an edge to the graph."""
        pass

    @abstractmethod
    async def get_node(self, node_id: str) -> Optional[AttackNode]:
        """Get a node by ID."""
        pass

    @abstractmethod
    async def get_edge(self, source_id: str, target_id: str) -> Optional[AttackEdge]:
        """Get an edge between two nodes."""
        pass

    @abstractmethod
    async def get_neighbors(
        self, node_id: str, direction: str = "outbound"
    ) -> List[AttackNode]:
        """Get neighboring nodes."""
        pass

    @abstractmethod
    async def get_node_degree(self, node_id: str) -> Dict[str, int]:
        """Get degree metrics for a node."""
        pass

    @abstractmethod
    async def shortest_path(
        self, source_id: str, target_id: str, weight_field: str = "weight"
    ) -> List[str]:
        """Find the shortest path between two nodes."""
        pass

    @abstractmethod
    async def all_simple_paths(
        self, source_id: str, target_id: str, cutoff: int
    ) -> List[List[str]]:
        """Find all simple paths between two nodes up to a cutoff length."""
        pass

    @abstractmethod
    async def get_nodes_by_type(self, node_type: str) -> List[AttackNode]:
        """Get all nodes of a specific type."""
        pass

    @abstractmethod
    async def get_metrics(self) -> Dict[str, Any]:
        """Get graph metrics (node count, edge count, density, etc.)."""
        pass
