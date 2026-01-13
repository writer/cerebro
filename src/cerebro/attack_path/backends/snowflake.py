"""
Snowflake backend implementation for the attack graph.

This backend leverages Snowflake's graph capabilities (CONNECT BY/Recursive CTEs)
to support massive-scale attack graphs without in-memory limitations.
"""

from typing import Any, Dict, List, Optional
import os
import json

from ..graph_model import AttackNode, AttackEdge, NodeType, EdgeType
from .backend import GraphBackend

# Check if snowflake connector is available
try:
    import snowflake.connector
    from snowflake.connector.errors import ProgrammingError
    SNOWFLAKE_AVAILABLE = True
except ImportError:
    SNOWFLAKE_AVAILABLE = False

class SnowflakeBackend(GraphBackend):
    """
    Snowflake implementation of the graph backend.
    
    Requires environment variables:
    - SNOWFLAKE_ACCOUNT
    - SNOWFLAKE_USER
    - SNOWFLAKE_PASSWORD
    - SNOWFLAKE_WAREHOUSE
    - SNOWFLAKE_DATABASE
    - SNOWFLAKE_SCHEMA
    """

    def __init__(self, org_id: str):
        if not SNOWFLAKE_AVAILABLE:
            raise ImportError("snowflake-connector-python is required for SnowflakeBackend")
            
        self.org_id = org_id
        self._conn = None
        self._connect()
        
    def _connect(self):
        """Establish connection to Snowflake."""
        try:
            self._conn = snowflake.connector.connect(
                user=os.environ.get("SNOWFLAKE_USER"),
                password=os.environ.get("SNOWFLAKE_PASSWORD"),
                account=os.environ.get("SNOWFLAKE_ACCOUNT"),
                warehouse=os.environ.get("SNOWFLAKE_WAREHOUSE"),
                database=os.environ.get("SNOWFLAKE_DATABASE"),
                schema=os.environ.get("SNOWFLAKE_SCHEMA")
            )
        except Exception as e:
            # Fallback or re-raise depending on strictness
            raise ConnectionError(f"Failed to connect to Snowflake: {e}")

    async def clear(self) -> None:
        """
        Clear graph data for this organization.
        Note: In a shared schema, we only delete rows for this org_id.
        """
        cursor = self._conn.cursor()
        try:
            cursor.execute("DELETE FROM attack_nodes WHERE org_id = %s", (self.org_id,))
            cursor.execute("DELETE FROM attack_edges WHERE org_id = %s", (self.org_id,))
        finally:
            cursor.close()

    async def add_node(self, node: AttackNode) -> None:
        """Add a node to the Snowflake attack_nodes table."""
        cursor = self._conn.cursor()
        try:
            query = """
            MERGE INTO attack_nodes AS target
            USING (SELECT %s AS org_id, %s AS node_id, %s AS node_type, %s AS provider, 
                          %s AS display_name, PARSE_JSON(%s) AS properties, 
                          %s AS risk_score, %s AS criticality, PARSE_JSON(%s) AS metadata) AS source
            ON target.org_id = source.org_id AND target.node_id = source.node_id
            WHEN MATCHED THEN UPDATE SET
                target.node_type = source.node_type,
                target.provider = source.provider,
                target.display_name = source.display_name,
                target.properties = source.properties,
                target.risk_score = source.risk_score,
                target.criticality = source.criticality,
                target.metadata = source.metadata
            WHEN NOT MATCHED THEN INSERT
                (org_id, node_id, node_type, provider, display_name, properties, risk_score, criticality, metadata)
            VALUES
                (source.org_id, source.node_id, source.node_type, source.provider, source.display_name, 
                 source.properties, source.risk_score, source.criticality, source.metadata)
            """
            cursor.execute(query, (
                self.org_id, node.node_id, node.node_type.value, node.provider,
                node.display_name, json.dumps(node.properties),
                node.risk_score, node.criticality, json.dumps(node.metadata)
            ))
        finally:
            cursor.close()

    async def add_edge(self, edge: AttackEdge) -> None:
        """Add an edge to the Snowflake attack_edges table."""
        cursor = self._conn.cursor()
        try:
            query = """
            MERGE INTO attack_edges AS target
            USING (SELECT %s AS org_id, %s AS edge_id, %s AS source_node, %s AS target_node, 
                          %s AS edge_type, %s AS permission, %s AS weight, 
                          %s AS privilege_level, PARSE_JSON(%s) AS conditions, 
                          PARSE_JSON(%s) AS metadata) AS source
            ON target.org_id = source.org_id AND target.edge_id = source.edge_id
            WHEN MATCHED THEN UPDATE SET
                target.source_node = source.source_node,
                target.target_node = source.target_node,
                target.edge_type = source.edge_type,
                target.permission = source.permission,
                target.weight = source.weight,
                target.privilege_level = source.privilege_level,
                target.conditions = source.conditions,
                target.metadata = source.metadata
            WHEN NOT MATCHED THEN INSERT
                (org_id, edge_id, source_node, target_node, edge_type, permission, weight, privilege_level, conditions, metadata)
            VALUES
                (source.org_id, source.edge_id, source.source_node, source.target_node, source.edge_type, 
                 source.permission, source.weight, source.privilege_level, source.conditions, source.metadata)
            """
            cursor.execute(query, (
                self.org_id, edge.edge_id, edge.source_node, edge.target_node,
                edge.edge_type.value, edge.permission, edge.weight,
                edge.privilege_level, json.dumps(edge.conditions), json.dumps(edge.metadata)
            ))
        finally:
            cursor.close()

    async def get_node(self, node_id: str) -> Optional[AttackNode]:
        cursor = self._conn.cursor()
        try:
            query = """
            SELECT node_id, node_type, provider, display_name, properties, risk_score, criticality, metadata
            FROM attack_nodes
            WHERE org_id = %s AND node_id = %s
            """
            cursor.execute(query, (self.org_id, node_id))
            row = cursor.fetchone()
            
            if row:
                return AttackNode(
                    node_id=row[0],
                    node_type=NodeType(row[1]),
                    provider=row[2],
                    display_name=row[3],
                    properties=json.loads(row[4]) if row[4] else {},
                    risk_score=row[5],
                    criticality=row[6],
                    metadata=json.loads(row[7]) if row[7] else {}
                )
            return None
        finally:
            cursor.close()

    async def get_edge(self, source_id: str, target_id: str) -> Optional[AttackEdge]:
        cursor = self._conn.cursor()
        try:
            query = """
            SELECT edge_id, source_node, target_node, edge_type, permission, weight, privilege_level, conditions, metadata
            FROM attack_edges
            WHERE org_id = %s AND source_node = %s AND target_node = %s
            LIMIT 1
            """
            cursor.execute(query, (self.org_id, source_id, target_id))
            row = cursor.fetchone()
            
            if row:
                return AttackEdge(
                    edge_id=row[0],
                    source_node=row[1],
                    target_node=row[2],
                    edge_type=EdgeType(row[3]),
                    permission=row[4],
                    weight=row[5],
                    privilege_level=row[6],
                    conditions=json.loads(row[7]) if row[7] else [],
                    metadata=json.loads(row[8]) if row[8] else {}
                )
            return None
        finally:
            cursor.close()

    async def get_neighbors(
        self, node_id: str, direction: str = "outbound"
    ) -> List[AttackNode]:
        cursor = self._conn.cursor()
        try:
            if direction == "outbound":
                query = """
                SELECT n.node_id, n.node_type, n.provider, n.display_name, n.properties, n.risk_score, n.criticality, n.metadata
                FROM attack_nodes n
                JOIN attack_edges e ON n.node_id = e.target_node
                WHERE e.org_id = %s AND e.source_node = %s
                """
            else:
                query = """
                SELECT n.node_id, n.node_type, n.provider, n.display_name, n.properties, n.risk_score, n.criticality, n.metadata
                FROM attack_nodes n
                JOIN attack_edges e ON n.node_id = e.source_node
                WHERE e.org_id = %s AND e.target_node = %s
                """
                
            cursor.execute(query, (self.org_id, node_id))
            rows = cursor.fetchall()
            
            return [
                AttackNode(
                    node_id=row[0],
                    node_type=NodeType(row[1]),
                    provider=row[2],
                    display_name=row[3],
                    properties=json.loads(row[4]) if row[4] else {},
                    risk_score=row[5],
                    criticality=row[6],
                    metadata=json.loads(row[7]) if row[7] else {}
                )
                for row in rows
            ]
        finally:
            cursor.close()

    async def get_node_degree(self, node_id: str) -> Dict[str, int]:
        cursor = self._conn.cursor()
        try:
            query_in = "SELECT COUNT(*) FROM attack_edges WHERE org_id = %s AND target_node = %s"
            cursor.execute(query_in, (self.org_id, node_id))
            in_degree = cursor.fetchone()[0]
            
            query_out = "SELECT COUNT(*) FROM attack_edges WHERE org_id = %s AND source_node = %s"
            cursor.execute(query_out, (self.org_id, node_id))
            out_degree = cursor.fetchone()[0]
            
            return {
                "in_degree": in_degree,
                "out_degree": out_degree,
                "total_degree": in_degree + out_degree
            }
        finally:
            cursor.close()

    async def shortest_path(
        self, source_id: str, target_id: str, weight_field: str = "weight"
    ) -> List[str]:
        """
        Uses Snowflake Recursive CTE to find shortest path.
        """
        cursor = self._conn.cursor()
        try:
            query = """
            WITH RECURSIVE bfs_path (source_node, target_node, path_array, depth) AS (
                -- Anchor member
                SELECT source_node, target_node, ARRAY_CONSTRUCT(source_node, target_node), 1
                FROM attack_edges
                WHERE org_id = %s AND source_node = %s
                
                UNION ALL
                
                -- Recursive member
                SELECT e.source_node, e.target_node, 
                       ARRAY_CAT(p.path_array, ARRAY_CONSTRUCT(e.target_node)), 
                       p.depth + 1
                FROM attack_edges e
                JOIN bfs_path p ON e.source_node = p.target_node
                WHERE e.org_id = %s
                AND ARRAY_CONTAINS(e.target_node::variant, p.path_array) = FALSE -- Prevent loops
                AND p.depth < 10 -- Safety limit
            )
            SELECT path_array
            FROM bfs_path
            WHERE target_node = %s
            ORDER BY depth ASC
            LIMIT 1
            """
            cursor.execute(query, (self.org_id, source_id, self.org_id, target_id))
            row = cursor.fetchone()
            
            if row:
                # Convert Snowflake array to Python list
                return json.loads(row[0]) if isinstance(row[0], str) else row[0]
            return []
        finally:
            cursor.close()

    async def all_simple_paths(
        self, source_id: str, target_id: str, cutoff: int
    ) -> List[List[str]]:
        """
        Find all simple paths using Recursive CTE with cutoff.
        """
        cursor = self._conn.cursor()
        try:
            query = """
            WITH RECURSIVE paths (source_node, target_node, path_array, depth) AS (
                SELECT source_node, target_node, ARRAY_CONSTRUCT(source_node, target_node), 1
                FROM attack_edges
                WHERE org_id = %s AND source_node = %s
                
                UNION ALL
                
                SELECT e.source_node, e.target_node, 
                       ARRAY_CAT(p.path_array, ARRAY_CONSTRUCT(e.target_node)), 
                       p.depth + 1
                FROM attack_edges e
                JOIN paths p ON e.source_node = p.target_node
                WHERE e.org_id = %s
                AND p.depth < %s
                AND ARRAY_CONTAINS(e.target_node::variant, p.path_array) = FALSE
            )
            SELECT path_array
            FROM paths
            WHERE target_node = %s
            """
            cursor.execute(query, (self.org_id, source_id, self.org_id, cutoff, target_id))
            rows = cursor.fetchall()
            
            return [
                json.loads(row[0]) if isinstance(row[0], str) else row[0]
                for row in rows
            ]
        finally:
            cursor.close()

    async def get_nodes_by_type(self, node_type: str) -> List[AttackNode]:
        cursor = self._conn.cursor()
        try:
            query = """
            SELECT node_id, node_type, provider, display_name, properties, risk_score, criticality, metadata
            FROM attack_nodes
            WHERE org_id = %s AND node_type = %s
            """
            # Handle enum if passed
            type_str = node_type.value if isinstance(node_type, NodeType) else node_type
            
            cursor.execute(query, (self.org_id, type_str))
            rows = cursor.fetchall()
            
            return [
                AttackNode(
                    node_id=row[0],
                    node_type=NodeType(row[1]),
                    provider=row[2],
                    display_name=row[3],
                    properties=json.loads(row[4]) if row[4] else {},
                    risk_score=row[5],
                    criticality=row[6],
                    metadata=json.loads(row[7]) if row[7] else {}
                )
                for row in rows
            ]
        finally:
            cursor.close()

    async def get_metrics(self) -> Dict[str, Any]:
        cursor = self._conn.cursor()
        try:
            cursor.execute("SELECT COUNT(*) FROM attack_nodes WHERE org_id = %s", (self.org_id,))
            node_count = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM attack_edges WHERE org_id = %s", (self.org_id,))
            edge_count = cursor.fetchone()[0]
            
            # Simple density calc
            density = 0.0
            if node_count > 1:
                density = edge_count / (node_count * (node_count - 1))
                
            return {
                "total_nodes": node_count,
                "total_edges": edge_count,
                "density": density,
                "backend": "snowflake"
            }
        finally:
            cursor.close()
