"""
Attack Path Simulator Tool

Enables agents to discover and analyze attack paths through the identity graph,
showing how compromised identities could laterally move or escalate privileges.

Wraps Cerebro's PathAnalyzer to provide tactical attack path intelligence
directly to Claude agents for threat modeling and incident response.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from .base import StructuredTool, AgentContext, ToolResult, ToolPermissionLevel
from cerebro.attack_path.graph_model import get_attack_graph
from cerebro.attack_path.path_analysis import PathAnalyzer, PathQuery, PathType
from cerebro.core.database import async_session_factory
import structlog

logger = structlog.get_logger(__name__)


class AttackPathSimulatorInput(BaseModel):
    """Input parameters for attack path simulation."""

    start_principal: Optional[str] = Field(
        None,
        description="Starting principal ID or email (e.g., 'user@company.com', 'arn:aws:iam::123:role/admin')",
    )
    target_resource: Optional[str] = Field(
        None,
        description="Target resource ID or ARN (e.g., 'arn:aws:s3:::prod-data', 's3://prod-data')",
    )
    max_depth: int = Field(
        default=5, description="Maximum path length (number of hops)", ge=1, le=10
    )
    include_privilege_escalation: bool = Field(
        default=True, description="Include privilege escalation paths"
    )


class AttackPathSimulatorOutput(BaseModel):
    """Output from attack path simulation."""

    paths_found: int
    most_critical_path: Optional[Dict[str, Any]]
    all_paths_summary: List[Dict[str, Any]]
    choke_points: List[str]
    recommended_mitigations: List[str]
    query_info: Dict[str, Any]


class AttackPathSimulatorTool(StructuredTool):
    """
    Simulate attack paths through the identity graph.

    This tool allows agents to answer questions like:
    - "How could a compromised GitHub Actions token reach prod S3?"
    - "What's the blast radius if this service account is compromised?"
    - "Show me all paths from this low-privilege user to admin access"
    - "What are the choke points I should monitor/protect?"

    Uses graph algorithms to find realistic attack paths that leverage
    actual permissions, group memberships, and cross-service privileges.
    """

    tool_name = "simulate_attack_path"
    tool_description = "Find attack paths showing how compromised identities could move laterally or escalate privileges"
    tool_version = "1.0.0"
    input_model = AttackPathSimulatorInput
    output_model = AttackPathSimulatorOutput
    required_permission = ToolPermissionLevel.READ_ONLY

    async def _run(  # type: ignore[override]
        self,
        context: AgentContext,
        start_principal: Optional[str] = None,
        target_resource: Optional[str] = None,
        max_depth: int = 5,
        include_privilege_escalation: bool = True,
    ) -> ToolResult:
        """
        Execute attack path simulation.

        Args:
            context: Agent execution context
            start_principal: Starting identity (optional if looking for all paths to target)
            target_resource: Target resource (optional if computing full blast radius)
            max_depth: Maximum path length
            include_privilege_escalation: Whether to include priv esc paths

        Returns:
            ToolResult with discovered attack paths
        """
        try:
            if not start_principal and not target_resource:
                return ToolResult(
                    success=False,
                    error="Must specify either start_principal or target_resource (or both)",
                )

            logger.info(
                "Attack path simulation requested",
                start=start_principal,
                target=target_resource,
                org_id=context.org_id,
            )

            async with async_session_factory() as db_session:
                # Build attack graph for this organization
                attack_graph = await get_attack_graph(  # type: ignore[call-arg]
                    db_session=db_session,
                    org_id=str(context.org_id),
                    provider_scope=context.provider_scope,
                )

                # Initialize path analyzer
                analyzer = PathAnalyzer(attack_graph)

                # Determine path type
                if start_principal and target_resource:
                    path_type = PathType.SHORTEST_PATH
                elif target_resource and include_privilege_escalation:
                    path_type = PathType.PRIVILEGE_ESCALATION
                else:
                    path_type = PathType.ALL_PATHS

                # Create query
                query = PathQuery(
                    source_principal=start_principal,
                    target_resource=target_resource,
                    max_path_length=max_depth,
                    path_type=path_type,
                    min_privilege_level=0,
                    exclude_conditions=[],
                )

                # Find paths
                paths = await analyzer.find_attack_paths(query)

                if not paths:
                    return ToolResult(
                        success=True,
                        data={
                            "paths_found": 0,
                            "message": "No attack paths found with given constraints",
                            "query_info": {
                                "start": start_principal,
                                "target": target_resource,
                                "max_depth": max_depth,
                            },
                        },
                    )

                # Format most critical path with full details
                most_critical = paths[0]  # Already sorted by exploitability
                critical_path_details = {
                    "severity": most_critical.severity.value,
                    "exploitability_score": round(
                        most_critical.exploitability_score, 2
                    ),
                    "impact_score": round(most_critical.impact_score, 2),
                    "path_length": most_critical.path_length,
                    "total_difficulty": round(most_critical.total_difficulty, 2),
                    "steps": [
                        {
                            "step": step.step_number,
                            "from": step.source_node,
                            "to": step.target_node,
                            "permission": step.permission,
                            "privilege_level": step.privilege_level,
                            "description": step.description,
                            "difficulty": round(step.difficulty_score, 2),
                            "conditions": step.conditions,
                        }
                        for step in most_critical.steps
                    ],
                    "mitigations": most_critical.mitigations,
                }

                # Summarize all paths (limit to top 10 to avoid token overload)
                all_paths_summary = [
                    {
                        "path_number": idx + 1,
                        "severity": path.severity.value,
                        "exploitability": round(path.exploitability_score, 2),
                        "steps": path.path_length,
                        "source": path.source_principal,
                        "target": path.target_resource,
                        "key_permissions": [
                            step.permission for step in path.steps[:3]  # First 3 steps
                        ],
                    }
                    for idx, path in enumerate(paths[:10])
                ]

                # Identify choke points (nodes that appear in many paths)
                choke_points = self._identify_choke_points(paths)

                # Generate recommendations
                recommendations = self._generate_recommendations(paths, choke_points)

                output = AttackPathSimulatorOutput(
                    paths_found=len(paths),
                    most_critical_path=critical_path_details,
                    all_paths_summary=all_paths_summary,
                    choke_points=choke_points,
                    recommended_mitigations=recommendations,
                    query_info={
                        "start_principal": start_principal,
                        "target_resource": target_resource,
                        "max_depth": max_depth,
                        "include_privilege_escalation": include_privilege_escalation,
                    },
                )

                logger.info(
                    "Attack path simulation completed",
                    paths_found=len(paths),
                    most_critical_severity=most_critical.severity.value,
                )

                return ToolResult(
                    success=True,
                    data=output.model_dump(),
                    metadata={
                        "paths_analyzed": len(paths),
                        "max_severity": most_critical.severity.value,
                    },
                )

        except Exception as e:
            logger.error("Attack path simulation failed", error=str(e), exc_info=True)
            return ToolResult(
                success=False, error=f"Attack path simulation failed: {str(e)}"
            )

    def _identify_choke_points(self, paths: List) -> List[str]:
        """
        Identify nodes that appear in many attack paths.
        These are critical points to monitor/protect.
        """
        node_frequency: dict[str, int] = {}

        for path in paths:
            nodes_in_path = set()
            for step in path.steps:
                nodes_in_path.add(step.source_node)
                nodes_in_path.add(step.target_node)

            for node in nodes_in_path:
                node_frequency[node] = node_frequency.get(node, 0) + 1

        # Return nodes that appear in >30% of paths
        threshold = max(1, len(paths) * 0.3)
        choke_points = [
            node for node, freq in node_frequency.items() if freq >= threshold
        ]

        return choke_points[:10]  # Limit to top 10

    def _generate_recommendations(
        self, paths: List, choke_points: List[str]
    ) -> List[str]:
        """Generate security recommendations based on paths found."""
        recommendations = []

        # High severity paths
        critical_paths = [p for p in paths if p.severity.value == "critical"]
        if critical_paths:
            recommendations.append(
                f"URGENT: {len(critical_paths)} critical attack paths found. "
                "Immediate remediation required."
            )

        # Choke points
        if choke_points:
            recommendations.append(
                f"Monitor these {len(choke_points)} choke points closely - "
                f"they appear in multiple attack paths: {', '.join(choke_points[:3])}"
            )

        # Low difficulty paths
        easy_paths = [p for p in paths if p.total_difficulty < 3.0]
        if easy_paths:
            recommendations.append(
                f"{len(easy_paths)} paths have low difficulty scores, "
                "making them easily exploitable by attackers."
            )

        # Privilege escalation
        priv_esc_paths = [
            p for p in paths if any(step.privilege_level > 5 for step in p.steps)
        ]
        if priv_esc_paths:
            recommendations.append(
                f"{len(priv_esc_paths)} paths involve privilege escalation. "
                "Review and apply least-privilege principles."
            )

        # Generic recommendations
        if len(paths) > 10:
            recommendations.append(
                "Consider implementing additional segmentation to reduce lateral movement opportunities."
            )

        return recommendations


class BlastRadiusTool(StructuredTool):
    """
    Calculate blast radius of a compromised identity.

    Shows all resources and principals that could be reached if a given
    identity is compromised. Critical for incident response and risk assessment.
    """

    tool_name = "calculate_blast_radius"
    tool_description = (
        "Calculate the full impact scope if a given identity is compromised"
    )
    tool_version = "1.0.0"
    required_permission = ToolPermissionLevel.READ_ONLY

    class Input(BaseModel):
        principal_id: str = Field(..., description="Principal/identity to analyze")
        max_hops: int = Field(
            default=5, description="Maximum hops to traverse", ge=1, le=10
        )
        include_transitive: bool = Field(
            default=True, description="Include transitive access"
        )

    class Output(BaseModel):
        principal_id: str
        directly_accessible: int
        transitively_accessible: int
        total_blast_radius: int
        critical_resources_at_risk: List[str]
        high_value_targets: List[Dict[str, Any]]
        recommended_containment: List[str]

    input_model = Input
    output_model = Output

    async def _run(  # type: ignore[override]
        self,
        context: AgentContext,
        principal_id: str,
        max_hops: int = 5,
        include_transitive: bool = True,
    ) -> ToolResult:
        """Calculate blast radius for compromised principal."""
        try:
            logger.info(
                "Blast radius calculation requested",
                principal=principal_id,
                org_id=context.org_id,
            )

            async with async_session_factory() as db_session:
                from cerebro.attack_path.reachability import ReachabilityAnalyzer

                # Build graph
                attack_graph = await get_attack_graph(  # type: ignore[call-arg]
                    db_session=db_session,
                    org_id=str(context.org_id),
                    provider_scope=context.provider_scope,
                )

                # Compute reachability
                reachability = ReachabilityAnalyzer(attack_graph)  # type: ignore[call-arg]
                blast_radius = await reachability.compute_blast_radius(  # type: ignore[attr-defined]
                    principal_id=principal_id,
                    max_hops=max_hops,
                    include_transitive=include_transitive,
                )

                # Identify high-value targets at risk
                high_value_targets = []
                for resource_id in blast_radius.reachable_resources[:20]:  # Top 20
                    resource_node = attack_graph.get_node(resource_id)  # type: ignore[attr-defined]
                    if resource_node and resource_node.get("risk_score", 0) > 7:
                        high_value_targets.append(
                            {
                                "resource_id": resource_id,
                                "resource_type": resource_node.get("resource_type"),
                                "risk_score": resource_node.get("risk_score"),
                                "hops_away": blast_radius.get_distance(
                                    principal_id, resource_id
                                ),
                            }
                        )

                # Generate containment recommendations
                containment = [
                    f"Immediately revoke credentials for {principal_id}",
                    f"Rotate secrets for {len(blast_radius.reachable_resources)} at-risk resources",
                ]

                if high_value_targets:
                    containment.append(
                        f"Prioritize protecting {len(high_value_targets)} high-value targets"
                    )

                if include_transitive and blast_radius.transitively_accessible > 10:
                    containment.append(
                        "Implement network segmentation to limit lateral movement"
                    )

                output = self.Output(
                    principal_id=principal_id,
                    directly_accessible=blast_radius.directly_accessible,
                    transitively_accessible=blast_radius.transitively_accessible,
                    total_blast_radius=blast_radius.total_reachable,
                    critical_resources_at_risk=[
                        r for r in blast_radius.critical_resources[:10]
                    ],
                    high_value_targets=high_value_targets,
                    recommended_containment=containment,
                )

                logger.info(
                    "Blast radius calculated",
                    principal=principal_id,
                    total_radius=blast_radius.total_reachable,
                )

                return ToolResult(
                    success=True,
                    data=output.model_dump(),
                    metadata={"principal_id": principal_id, "max_hops": max_hops},
                )

        except Exception as e:
            logger.error("Blast radius calculation failed", error=str(e), exc_info=True)
            return ToolResult(
                success=False, error=f"Blast radius calculation failed: {str(e)}"
            )
