"""
Attack graph model for representing identity and resource relationships.

Models principals → roles → resources across providers with weighted edges
for attack path analysis and blast radius calculations.
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import networkx as nx

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

from ..core.database import async_session_factory
from ..core.models import Principal, Resource, IAMEdge

logger = logging.getLogger(__name__)


class NodeType(Enum):
    """Types of nodes in the attack graph."""
    PRINCIPAL = "principal"
    ROLE = "role"
    RESOURCE = "resource"
    SERVICE = "service"
    NETWORK = "network"


class EdgeType(Enum):
    """Types of edges in the attack graph."""
    DIRECT_ACCESS = "direct_access"
    ROLE_ASSIGNMENT = "role_assignment"
    ROLE_INHERITANCE = "role_inheritance"
    SERVICE_IDENTITY = "service_identity"
    NETWORK_ACCESS = "network_access"
    TRUST_RELATIONSHIP = "trust_relationship"
    OIDC_FEDERATION = "oidc_federation"


@dataclass
class AttackNode:
    """Node in the attack graph."""
    node_id: str
    node_type: NodeType
    provider: str
    display_name: str
    properties: Dict[str, Any]
    risk_score: float
    criticality: str  # "low", "medium", "high", "critical"
    metadata: Dict[str, Any]


@dataclass 
class AttackEdge:
    """Edge in the attack graph representing access relationships."""
    edge_id: str
    source_node: str
    target_node: str
    edge_type: EdgeType
    permission: str
    weight: float  # Cost/difficulty of traversing this edge
    privilege_level: int  # 0=read, 1=write, 2=admin, 3=owner
    conditions: List[str]  # Conditions required to traverse edge
    metadata: Dict[str, Any]


class AttackGraph:
    """
    Graph model representing attack paths across cloud providers.
    
    Models identity relationships and access patterns to enable
    attack path analysis and blast radius calculations.
    """
    
    def __init__(self, org_id: str):
        self.org_id = org_id
        self.graph = nx.DiGraph()
        self.nodes: Dict[str, AttackNode] = {}
        self.edges: Dict[str, AttackEdge] = {}
        self.last_built: Optional[datetime] = None
    
    async def build_graph(self) -> None:
        """
        Build attack graph from current IAM and resource data.
        
        Constructs comprehensive graph of all identity relationships.
        """
        logger.info(f"Building attack graph for organization {self.org_id}")
        
        # Clear existing graph
        self.graph.clear()
        self.nodes.clear()
        self.edges.clear()
        
        async with async_session_factory() as db:
            # Add principal nodes
            await self._add_principal_nodes(db)
            
            # Add resource nodes
            await self._add_resource_nodes(db)
            
            # Add IAM edges
            await self._add_iam_edges(db)
            
            # Add service identity edges
            await self._add_service_identity_edges(db)
            
            # Add cross-provider trust relationships
            await self._add_trust_relationships(db)
        
        self.last_built = datetime.now()
        
        logger.info(
            f"Attack graph built: {len(self.nodes)} nodes, {len(self.edges)} edges"
        )
    
    async def _add_principal_nodes(self, db: AsyncSession):
        """Add principal nodes to the graph."""
        stmt = select(Principal).where(Principal.org_id == self.org_id)
        principals = await db.scalars(stmt)
        
        for principal in principals:
            node = AttackNode(
                node_id=principal.principal_id,
                node_type=NodeType.PRINCIPAL,
                provider=principal.provider,
                display_name=principal.display_name,
                properties={
                    "principal_type": principal.principal_type,
                    "external_id": principal.external_id,
                    "is_active": principal.is_active
                },
                risk_score=self._calculate_principal_risk_score(principal),
                criticality=self._assess_principal_criticality(principal),
                metadata=principal.metadata or {}
            )
            
            self.nodes[node.node_id] = node
            self.graph.add_node(node.node_id, **node.__dict__)
    
    async def _add_resource_nodes(self, db: AsyncSession):
        """Add resource nodes to the graph."""
        # Get resources for all accounts in the organization
        from ..core.models import Account
        stmt = select(Account).where(Account.org_id == self.org_id)
        accounts = await db.scalars(stmt)
        
        for account in accounts:
            resource_stmt = select(Resource).where(Resource.account_id == account.account_id)
            resources = await db.scalars(resource_stmt)
            
            for resource in resources:
                node = AttackNode(
                    node_id=resource.resource_id,
                    node_type=NodeType.RESOURCE,
                    provider=resource.provider,
                    display_name=resource.external_id,
                    properties={
                        "resource_type": resource.resource_type,
                        "external_id": resource.external_id
                    },
                    risk_score=self._calculate_resource_risk_score(resource),
                    criticality=self._assess_resource_criticality(resource),
                    metadata=resource.metadata or {}
                )
                
                self.nodes[node.node_id] = node
                self.graph.add_node(node.node_id, **node.__dict__)
    
    async def _add_iam_edges(self, db: AsyncSession):
        """Add IAM permission edges to the graph."""
        stmt = select(IAMEdge).where(
            and_(
                IAMEdge.org_id == self.org_id,
                IAMEdge.effective == True
            )
        )
        edges = await db.scalars(stmt)
        
        for iam_edge in edges:
            # Determine edge type
            edge_type = EdgeType.DIRECT_ACCESS
            if iam_edge.edge_type == "role_assignment":
                edge_type = EdgeType.ROLE_ASSIGNMENT
            elif iam_edge.edge_type == "inheritance":
                edge_type = EdgeType.ROLE_INHERITANCE
            
            # Calculate edge weight (difficulty/cost of traversal)
            weight = self._calculate_edge_weight(iam_edge.permission, iam_edge.provider)
            
            # Determine privilege level
            privilege_level = self._get_privilege_level(iam_edge.permission)
            
            edge = AttackEdge(
                edge_id=iam_edge.edge_id,
                source_node=iam_edge.principal_id,
                target_node=iam_edge.resource_id,
                edge_type=edge_type,
                permission=iam_edge.permission,
                weight=weight,
                privilege_level=privilege_level,
                conditions=self._extract_edge_conditions(iam_edge),
                metadata=iam_edge.metadata or {}
            )
            
            self.edges[edge.edge_id] = edge
            
            # Add to NetworkX graph
            self.graph.add_edge(
                edge.source_node,
                edge.target_node,
                edge_id=edge.edge_id,
                weight=edge.weight,
                permission=edge.permission,
                privilege_level=edge.privilege_level,
                edge_type=edge.edge_type.value
            )
    
    async def _add_service_identity_edges(self, db: AsyncSession):
        """Add service-to-service identity edges."""
        # This would query for:
        # - GitHub OIDC → AWS STS roles
        # - GCP Workload Identity Federation
        # - Azure Entra federated identities
        # - CI/CD service accounts
        
        # Example: GitHub Actions → AWS role
        # (In production, would discover these from provider configurations)
        
        service_edges = [
            {
                "source": "github_actions_service",
                "target": "aws_deployment_role", 
                "provider": "aws",
                "permission": "sts:AssumeRoleWithWebIdentity",
                "trust_policy": "GitHub OIDC trust"
            },
            {
                "source": "gcp_compute_service_account",
                "target": "gcp_storage_bucket",
                "provider": "gcp",
                "permission": "storage.objects.create",
                "trust_policy": "Workload Identity"
            }
        ]
        
        for service_edge in service_edges:
            edge = AttackEdge(
                edge_id=f"service_{service_edge['source']}_{service_edge['target']}",
                source_node=service_edge["source"],
                target_node=service_edge["target"],
                edge_type=EdgeType.SERVICE_IDENTITY,
                permission=service_edge["permission"],
                weight=0.3,  # Service edges are often easier to exploit
                privilege_level=2,  # Service accounts often have elevated privileges
                conditions=[service_edge["trust_policy"]],
                metadata={
                    "provider": service_edge["provider"],
                    "trust_mechanism": service_edge["trust_policy"]
                }
            )
            
            self.edges[edge.edge_id] = edge
            self.graph.add_edge(
                edge.source_node,
                edge.target_node,
                **edge.__dict__
            )
    
    async def _add_trust_relationships(self, db: AsyncSession):
        """Add cross-provider trust relationships."""
        # Examples of trust relationships:
        # - AWS cross-account roles
        # - GCP organization policies
        # - Azure AD B2B trusts
        # - GitHub organization memberships
        
        # Mock trust relationships (would discover from provider configs)
        trust_relationships = [
            {
                "source_provider": "github",
                "target_provider": "aws",
                "trust_type": "oidc_federation",
                "source_resource": "github_repo_actions",
                "target_resource": "aws_deployment_role"
            }
        ]
        
        for trust in trust_relationships:
            edge = AttackEdge(
                edge_id=f"trust_{trust['source_provider']}_{trust['target_provider']}",
                source_node=trust["source_resource"],
                target_node=trust["target_resource"],
                edge_type=EdgeType.TRUST_RELATIONSHIP,
                permission=f"{trust['trust_type']}_trust",
                weight=0.4,
                privilege_level=2,
                conditions=[f"{trust['trust_type']} configured"],
                metadata=trust
            )
            
            self.edges[edge.edge_id] = edge
            self.graph.add_edge(
                edge.source_node,
                edge.target_node,
                **edge.__dict__
            )
    
    def _calculate_principal_risk_score(self, principal: Principal) -> float:
        """Calculate risk score for a principal."""
        base_score = 0.5
        
        # Higher risk for service accounts
        if principal.principal_type == "service_account":
            base_score += 0.2
        
        # Higher risk for external principals
        if principal.provider != "internal":
            base_score += 0.1
        
        # Higher risk for inactive principals (stale access)
        if not principal.is_active:
            base_score += 0.3
        
        return min(base_score, 1.0)
    
    def _assess_principal_criticality(self, principal: Principal) -> str:
        """Assess criticality level of principal."""
        if principal.principal_type == "service_account":
            return "high"
        elif not principal.is_active:
            return "medium"
        else:
            return "low"
    
    def _calculate_resource_risk_score(self, resource: Resource) -> float:
        """Calculate risk score for a resource."""
        base_score = 0.3
        
        # Higher risk for certain resource types
        high_risk_types = ["s3_bucket", "secret", "database", "key_vault"]
        if any(risk_type in resource.resource_type.lower() for risk_type in high_risk_types):
            base_score += 0.4
        
        # Higher risk for production resources
        if resource.metadata and "production" in str(resource.metadata).lower():
            base_score += 0.3
        
        return min(base_score, 1.0)
    
    def _assess_resource_criticality(self, resource: Resource) -> str:
        """Assess criticality level of resource."""
        critical_types = ["secret", "key", "database"]
        high_types = ["s3_bucket", "storage_account", "compute"]
        
        resource_type_lower = resource.resource_type.lower()
        
        if any(crit_type in resource_type_lower for crit_type in critical_types):
            return "critical"
        elif any(high_type in resource_type_lower for high_type in high_types):
            return "high"
        else:
            return "medium"
    
    def _calculate_edge_weight(self, permission: str, provider: str) -> float:
        """Calculate weight (difficulty) for edge traversal."""
        # Lower weight = easier to exploit
        base_weight = 0.5
        
        # Admin permissions are easier to exploit (lower weight)
        if any(term in permission.lower() for term in ["admin", "owner", "full", "*"]):
            base_weight = 0.2
        
        # Write permissions are medium difficulty
        elif any(term in permission.lower() for term in ["write", "create", "delete", "modify"]):
            base_weight = 0.4
        
        # Read permissions are harder to exploit for lateral movement
        elif "read" in permission.lower():
            base_weight = 0.7
        
        # Service-to-service edges are often easier
        if provider in ["github_actions", "ci_cd"]:
            base_weight *= 0.8
        
        return base_weight
    
    def _get_privilege_level(self, permission: str) -> int:
        """Get numerical privilege level for permission."""
        permission_lower = permission.lower()
        
        if any(term in permission_lower for term in ["owner", "admin", "root", "superuser"]):
            return 3  # Owner/Admin
        elif any(term in permission_lower for term in ["write", "create", "delete", "modify", "edit"]):
            return 2  # Write
        elif any(term in permission_lower for term in ["read", "list", "get", "describe"]):
            return 1  # Read
        else:
            return 0  # Minimal/Unknown
    
    def _extract_edge_conditions(self, iam_edge: IAMEdge) -> List[str]:
        """Extract conditions required to traverse an edge."""
        conditions = []
        
        # Extract conditions from metadata
        if iam_edge.metadata:
            if "mfa_required" in iam_edge.metadata:
                conditions.append("MFA required")
            
            if "time_restriction" in iam_edge.metadata:
                conditions.append("Time-based restriction")
            
            if "ip_restriction" in iam_edge.metadata:
                conditions.append("IP address restriction")
            
            if "conditional_access" in iam_edge.metadata:
                conditions.append("Conditional access policy")
        
        return conditions
    
    def get_neighbors(self, node_id: str, direction: str = "outbound") -> List[AttackNode]:
        """Get neighboring nodes (reachable resources or accessing principals)."""
        neighbors = []
        
        if direction == "outbound":
            # Get resources this node can access
            successors = list(self.graph.successors(node_id))
            neighbors = [self.nodes[nid] for nid in successors if nid in self.nodes]
        
        elif direction == "inbound":
            # Get principals that can access this node
            predecessors = list(self.graph.predecessors(node_id))
            neighbors = [self.nodes[nid] for nid in predecessors if nid in self.nodes]
        
        return neighbors
    
    def get_node_degree(self, node_id: str) -> Dict[str, int]:
        """Get degree centrality metrics for a node."""
        if node_id not in self.graph:
            return {"in_degree": 0, "out_degree": 0, "total_degree": 0}
        
        in_degree = self.graph.in_degree(node_id)
        out_degree = self.graph.out_degree(node_id)
        
        return {
            "in_degree": in_degree,
            "out_degree": out_degree, 
            "total_degree": in_degree + out_degree
        }
    
    def get_high_value_targets(self, limit: int = 20) -> List[AttackNode]:
        """
        Get high-value target resources for attack path analysis.
        
        Returns resources that are most critical and attractive to attackers.
        """
        resource_nodes = [
            node for node in self.nodes.values() 
            if node.node_type == NodeType.RESOURCE
        ]
        
        # Sort by combination of risk score, criticality, and centrality
        def target_value_score(node: AttackNode) -> float:
            degree_info = self.get_node_degree(node.node_id)
            centrality_score = degree_info["in_degree"] / max(len(self.nodes), 1)
            
            criticality_scores = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2}
            criticality_score = criticality_scores.get(node.criticality, 0.3)
            
            return (node.risk_score * 0.4) + (criticality_score * 0.4) + (centrality_score * 0.2)
        
        resource_nodes.sort(key=target_value_score, reverse=True)
        
        return resource_nodes[:limit]
    
    def get_high_privilege_principals(self, limit: int = 20) -> List[AttackNode]:
        """
        Get principals with highest privilege levels.
        
        Returns principals most likely to be targeted by attackers.
        """
        principal_nodes = [
            node for node in self.nodes.values()
            if node.node_type == NodeType.PRINCIPAL
        ]
        
        # Calculate privilege score based on outbound edges
        def privilege_score(node: AttackNode) -> float:
            if node.node_id not in self.graph:
                return 0.0
            
            # Get all outbound edges and their privilege levels
            outbound_edges = []
            for successor in self.graph.successors(node.node_id):
                edge_data = self.graph.edges[node.node_id, successor]
                outbound_edges.append(edge_data.get("privilege_level", 0))
            
            if not outbound_edges:
                return 0.0
            
            # Calculate privilege score
            max_privilege = max(outbound_edges)
            avg_privilege = sum(outbound_edges) / len(outbound_edges)
            edge_count_score = min(len(outbound_edges) / 10, 1.0)  # Normalize to 0-1
            
            return (max_privilege / 3) * 0.5 + (avg_privilege / 3) * 0.3 + edge_count_score * 0.2
        
        principal_nodes.sort(key=privilege_score, reverse=True)
        
        return principal_nodes[:limit]
    
    def export_graph_summary(self) -> Dict[str, Any]:
        """Export summary statistics of the attack graph."""
        node_type_counts = {}
        for node in self.nodes.values():
            node_type_counts[node.node_type.value] = node_type_counts.get(node.node_type.value, 0) + 1
        
        edge_type_counts = {}
        for edge in self.edges.values():
            edge_type_counts[edge.edge_type.value] = edge_type_counts.get(edge.edge_type.value, 0) + 1
        
        # Calculate graph metrics
        if self.graph.number_of_nodes() > 0:
            density = nx.density(self.graph)
            avg_degree = sum(dict(self.graph.degree()).values()) / self.graph.number_of_nodes()
        else:
            density = 0.0
            avg_degree = 0.0
        
        return {
            "organization_id": self.org_id,
            "last_built": self.last_built.isoformat() if self.last_built else None,
            "graph_metrics": {
                "total_nodes": len(self.nodes),
                "total_edges": len(self.edges),
                "graph_density": round(density, 4),
                "average_degree": round(avg_degree, 2)
            },
            "node_distribution": node_type_counts,
            "edge_distribution": edge_type_counts,
            "high_value_targets": min(len(self.get_high_value_targets()), 5),
            "high_privilege_principals": min(len(self.get_high_privilege_principals()), 5)
        }


# Global attack graph cache
_attack_graphs: Dict[str, AttackGraph] = {}


async def get_attack_graph(org_id: str, rebuild: bool = False) -> AttackGraph:
    """
    Get attack graph for organization.
    
    Args:
        org_id: Organization ID
        rebuild: Whether to rebuild the graph from current data
        
    Returns:
        AttackGraph instance
    """
    if org_id not in _attack_graphs or rebuild:
        graph = AttackGraph(org_id)
        await graph.build_graph()
        _attack_graphs[org_id] = graph
    
    return _attack_graphs[org_id]
