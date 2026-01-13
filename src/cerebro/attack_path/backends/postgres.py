"""
PostgreSQL backend implementation for attack graph using Recursive CTEs.

This backend provides scalability beyond memory limits by leveraging 
PostgreSQL's recursive query capabilities for graph traversal.
"""

from typing import Any, Dict, List, Optional
import json

from sqlalchemy import select, and_, or_, func, text, literal_column
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.dialects.postgresql import insert

from ..core.database import async_session_factory
from ..core.models import Principal, Resource, IamEdge
from ..graph_model import AttackNode, AttackEdge, NodeType, EdgeType
from .backend import GraphBackend

class PostgresRecursiveCTEBackend(GraphBackend):
    """
    Graph backend using PostgreSQL with recursive CTEs for traversal.
    """
    
    def __init__(self, org_id: str):
        self.org_id = org_id
        
    async def clear(self) -> None:
        """
        No-op for Postgres backend as data is persistent in core tables.
        In a real graph database, this might clear a specific graph projection.
        """
        pass

    async def add_node(self, node: AttackNode) -> None:
        """
        Nodes are typically synced from Principal/Resource tables.
        This method might be used for ephemeral nodes if needed.
        """
        pass

    async def add_edge(self, edge: AttackEdge) -> None:
        """
        Edges are typically synced from IamEdge tables.
        """
        pass

    async def get_node(self, node_id: str) -> Optional[AttackNode]:
        """Fetch node details from Principal or Resource tables."""
        async with async_session_factory() as db:
            # Try Principal first
            stmt = select(Principal).where(
                and_(Principal.principal_id == node_id, Principal.org_id == self.org_id) # type: ignore
            )
            principal = await db.scalar(stmt)
            
            if principal:
                return AttackNode(
                    node_id=str(principal.principal_id),
                    node_type=NodeType.PRINCIPAL,
                    provider=principal.provider,
                    display_name=principal.display_name or "Unknown",
                    properties={
                        "principal_type": principal.principal_type,
                        "external_id": principal.external_id,
                    },
                    risk_score=0.0, # Would be calculated
                    criticality="low",
                    metadata=dict(principal.metadata or {}) # type: ignore
                )
                
            # Try Resource
            stmt = select(Resource).where(
                 and_(Resource.resource_id == node_id) # type: ignore
            )
            resource = await db.scalar(stmt)
            
            if resource:
                return AttackNode(
                    node_id=str(resource.resource_id),
                    node_type=NodeType.RESOURCE,
                    provider=resource.provider,
                    display_name=resource.external_id or "Unknown",
                    properties={
                        "resource_type": resource.resource_type,
                        "external_id": resource.external_id,
                    },
                    risk_score=0.0,
                    criticality="low",
                    metadata=dict(resource.metadata or {}) # type: ignore
                )
                
            return None

    async def get_edge(self, source_id: str, target_id: str) -> Optional[AttackEdge]:
        async with async_session_factory() as db:
            stmt = select(IamEdge).where(
                and_(
                    IamEdge.principal_id == source_id,
                    IamEdge.resource_id == target_id,
                    IamEdge.effective == True
                )
            ).limit(1)
            
            edge = await db.scalar(stmt)
            if edge:
                return AttackEdge(
                    edge_id=str(edge.edge_id),
                    source_node=str(edge.principal_id),
                    target_node=str(edge.resource_id),
                    edge_type=EdgeType.DIRECT_ACCESS,
                    permission=edge.permission,
                    weight=1.0,
                    privilege_level=1,
                    conditions=[],
                    metadata={}
                )
            return None

    async def get_neighbors(
        self, node_id: str, direction: str = "outbound"
    ) -> List[AttackNode]:
        async with async_session_factory() as db:
            nodes = []
            if direction == "outbound":
                # Find resources accessed by principal
                stmt = select(IamEdge).where(
                    and_(IamEdge.principal_id == node_id, IamEdge.effective == True)
                )
                edges = await db.scalars(stmt)
                # Then fetch resources... (simplified for brevity)
                
            elif direction == "inbound":
                # Find principals accessing resource
                stmt = select(IamEdge).where(
                    and_(IamEdge.resource_id == node_id, IamEdge.effective == True)
                )
                edges = await db.scalars(stmt)
                
            return nodes

    async def get_node_degree(self, node_id: str) -> Dict[str, int]:
        async with async_session_factory() as db:
            # Outbound degree
            out_stmt = select(func.count(IamEdge.edge_id)).where(
                and_(IamEdge.principal_id == node_id, IamEdge.effective == True)
            )
            out_degree = await db.scalar(out_stmt) or 0
            
            # Inbound degree
            in_stmt = select(func.count(IamEdge.edge_id)).where(
                and_(IamEdge.resource_id == node_id, IamEdge.effective == True)
            )
            in_degree = await db.scalar(in_stmt) or 0
            
            return {
                "in_degree": in_degree,
                "out_degree": out_degree,
                "total_degree": in_degree + out_degree
            }

    async def shortest_path(
        self, source_id: str, target_id: str, weight_field: str = "weight"
    ) -> List[str]:
        """
        Uses Recursive CTE to find shortest path.
        Note: This is a simplified implementation. Production would need loop detection and depth limits.
        """
        query = text("""
            WITH RECURSIVE attack_path AS (
                -- Base case: direct edges from source
                SELECT 
                    principal_id as source, 
                    resource_id as target, 
                    ARRAY[principal_id::text, resource_id::text] as path,
                    1 as depth
                FROM iam_edges
                WHERE principal_id = :source_id AND effective = true
                
                UNION ALL
                
                -- Recursive step
                SELECT 
                    e.principal_id, 
                    e.resource_id, 
                    p.path || e.resource_id::text,
                    p.depth + 1
                FROM iam_edges e
                JOIN attack_path p ON e.principal_id = p.target
                WHERE e.effective = true 
                AND NOT (e.resource_id::text = ANY(p.path)) -- Prevent loops
                AND p.depth < 10 -- Safety limit
            )
            SELECT path FROM attack_path 
            WHERE target = :target_id 
            ORDER BY depth ASC 
            LIMIT 1
        """)
        
        async with async_session_factory() as db:
            result = await db.execute(query, {"source_id": source_id, "target_id": target_id})
            row = result.fetchone()
            return row[0] if row else []

    async def all_simple_paths(
        self, source_id: str, target_id: str, cutoff: int
    ) -> List[List[str]]:
        # Similar CTE structure but without LIMIT 1 and with higher cost
        return []

    async def get_nodes_by_type(self, node_type: str) -> List[AttackNode]:
        # Maps to selecting from Principal or Resource tables
        return []

    async def get_metrics(self) -> Dict[str, Any]:
        async with async_session_factory() as db:
            p_count = await db.scalar(select(func.count(Principal.principal_id)))
            r_count = await db.scalar(select(func.count(Resource.resource_id)))
            e_count = await db.scalar(select(func.count(IamEdge.edge_id)))
            
            return {
                "total_nodes": (p_count or 0) + (r_count or 0),
                "total_edges": e_count or 0
            }
