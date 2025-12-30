"""
Attack path analysis with shortest path and k-step escalation queries.

Implements graph algorithms to find attack paths between principals and
resources with severity scoring and what-if simulation capabilities.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any

import networkx as nx
import structlog

from .graph_model import AttackGraph, get_attack_graph

logger = structlog.get_logger(__name__)


class PathType(Enum):
    """Types of attack paths."""

    SHORTEST_PATH = "shortest_path"
    K_STEP_ESCALATION = "k_step_escalation"
    ALL_PATHS = "all_paths"
    PRIVILEGE_ESCALATION = "privilege_escalation"


class PathSeverity(Enum):
    """Severity levels for attack paths."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AttackStep:
    """Single step in an attack path."""

    step_number: int
    source_node: str
    target_node: str
    edge_id: str
    permission: str
    privilege_level: int
    conditions: list[str]
    difficulty_score: float
    description: str


@dataclass
class AttackPath:
    """Complete attack path from principal to resource."""

    path_id: str
    source_principal: str
    target_resource: str
    steps: list[AttackStep]
    total_difficulty: float
    path_length: int
    severity: PathSeverity
    exploitability_score: float
    impact_score: float
    mitigations: list[str]
    evidence_references: list[str]


@dataclass
class PathQuery:
    """Query parameters for attack path analysis."""

    source_principal: str | None
    target_resource: str | None
    max_path_length: int
    path_type: PathType
    min_privilege_level: int
    exclude_conditions: list[str]  # Conditions to exclude from paths


class PathAnalyzer:
    """
    Analyzes attack paths through identity and resource graphs.

    Provides shortest path queries, k-step escalation analysis,
    and what-if simulation capabilities.
    """

    def __init__(self, attack_graph: AttackGraph):
        self.attack_graph = attack_graph
        self.graph = attack_graph.graph

    async def find_attack_paths(self, query: PathQuery) -> list[AttackPath]:
        """
        Find attack paths based on query parameters.

        Args:
            query: Path query specification

        Returns:
            List of attack paths matching criteria
        """
        paths = []

        if query.path_type == PathType.SHORTEST_PATH:
            paths = await self._find_shortest_paths(query)

        elif query.path_type == PathType.K_STEP_ESCALATION:
            paths = await self._find_k_step_escalation_paths(query)

        elif query.path_type == PathType.ALL_PATHS:
            paths = await self._find_all_simple_paths(query)

        elif query.path_type == PathType.PRIVILEGE_ESCALATION:
            paths = await self._find_privilege_escalation_paths(query)

        # Sort by exploitability score (most exploitable first)
        paths.sort(key=lambda p: p.exploitability_score, reverse=True)

        logger.info(f"Found {len(paths)} attack paths")

        return paths

    async def _find_shortest_paths(self, query: PathQuery) -> list[AttackPath]:
        """Find shortest paths between source and target."""
        paths = []

        # If both source and target specified, find direct path
        if query.source_principal and query.target_resource:
            try:
                path = nx.shortest_path(
                    self.graph,
                    query.source_principal,
                    query.target_resource,
                    weight="weight",
                )

                attack_path = await self._convert_to_attack_path(path, query)
                if attack_path:
                    paths.append(attack_path)

            except nx.NetworkXNoPath:
                logger.debug(
                    f"No path found from {query.source_principal} to {query.target_resource}"
                )

        # If only target specified, find paths from all high-privilege principals
        elif query.target_resource:
            high_privilege_principals = self.attack_graph.get_high_privilege_principals(
                10
            )

            for principal in high_privilege_principals:
                try:
                    path = nx.shortest_path(
                        self.graph,
                        principal.node_id,
                        query.target_resource,
                        weight="weight",
                    )

                    if len(path) <= query.max_path_length:
                        attack_path = await self._convert_to_attack_path(path, query)
                        if attack_path:
                            paths.append(attack_path)

                except nx.NetworkXNoPath:
                    continue

        return paths

    async def _find_k_step_escalation_paths(self, query: PathQuery) -> list[AttackPath]:
        """Find paths with exactly k steps for escalation analysis."""
        paths: list[AttackPath] = []

        if not query.source_principal:
            return paths

        # Find all paths of exactly k steps using BFS
        k = query.max_path_length

        # Use NetworkX to find all simple paths of length k
        if query.target_resource:
            # Find k-step paths to specific target
            try:
                all_paths = list(
                    nx.all_simple_paths(
                        self.graph,
                        query.source_principal,
                        query.target_resource,
                        cutoff=k,
                    )
                )

                k_step_paths = [
                    path for path in all_paths if len(path) == k + 1
                ]  # +1 because path includes start node

                for path in k_step_paths:
                    attack_path = await self._convert_to_attack_path(path, query)
                    if attack_path:
                        paths.append(attack_path)

            except nx.NetworkXNoPath:
                pass

        else:
            # Find k-step paths to any high-value target
            high_value_targets = self.attack_graph.get_high_value_targets(10)

            for target in high_value_targets:
                try:
                    all_paths = list(
                        nx.all_simple_paths(
                            self.graph, query.source_principal, target.node_id, cutoff=k
                        )
                    )

                    k_step_paths = [path for path in all_paths if len(path) == k + 1]

                    for path in k_step_paths:
                        attack_path = await self._convert_to_attack_path(path, query)
                        if attack_path:
                            paths.append(attack_path)

                except nx.NetworkXNoPath:
                    continue

        return paths

    async def _find_all_simple_paths(self, query: PathQuery) -> list[AttackPath]:
        """Find all simple paths up to maximum length."""
        paths: list[AttackPath] = []

        if not query.source_principal or not query.target_resource:
            return paths

        try:
            all_paths = list(
                nx.all_simple_paths(
                    self.graph,
                    query.source_principal,
                    query.target_resource,
                    cutoff=query.max_path_length,
                )
            )

            # Convert to attack paths
            for path in all_paths[:50]:  # Limit to prevent explosion
                attack_path = await self._convert_to_attack_path(path, query)
                if attack_path:
                    paths.append(attack_path)

        except nx.NetworkXNoPath:
            logger.debug("No paths found between specified nodes")

        return paths

    async def _find_privilege_escalation_paths(
        self, query: PathQuery
    ) -> list[AttackPath]:
        """Find paths that represent privilege escalation."""
        paths: list[AttackPath] = []

        if not query.source_principal:
            return paths

        # Find paths where privilege level increases along the path
        source_node = self.attack_graph.nodes.get(query.source_principal)
        if not source_node:
            return paths

        # Get all reachable nodes
        reachable_nodes = nx.descendants(self.graph, query.source_principal)

        for target_node_id in reachable_nodes:
            try:
                path = nx.shortest_path(
                    self.graph, query.source_principal, target_node_id, weight="weight"
                )

                # Check if this path represents privilege escalation
                if await self._is_privilege_escalation_path(path):
                    attack_path = await self._convert_to_attack_path(path, query)
                    if attack_path:
                        paths.append(attack_path)

            except nx.NetworkXNoPath:
                continue

        return paths

    async def _is_privilege_escalation_path(self, path: list[str]) -> bool:
        """Check if path represents privilege escalation."""
        if len(path) < 2:
            return False

        # Check if privilege level increases along the path
        max_privilege_seen = 0

        for i in range(len(path) - 1):
            source = path[i]
            target = path[i + 1]

            if self.graph.has_edge(source, target):
                edge_data = self.graph.edges[source, target]
                privilege_level = edge_data.get("privilege_level", 0)

                if privilege_level > max_privilege_seen:
                    max_privilege_seen = privilege_level

                    # If we reach admin level (3), this is escalation
                    if privilege_level >= 2:
                        return True

        return False

    async def _convert_to_attack_path(
        self, path: list[str], query: PathQuery
    ) -> AttackPath | None:
        """Convert NetworkX path to AttackPath object."""
        if len(path) < 2:
            return None

        steps = []
        total_difficulty = 0.0

        # Build attack steps
        for i in range(len(path) - 1):
            source_id = path[i]
            target_id = path[i + 1]

            if not self.graph.has_edge(source_id, target_id):
                return None  # Invalid path

            edge_data = self.graph.edges[source_id, target_id]

            # Find corresponding edge object
            edge_id = edge_data.get("edge_id", "")
            edge = self.edges.get(edge_id) if hasattr(self, "edges") else None

            step = AttackStep(
                step_number=i + 1,
                source_node=source_id,
                target_node=target_id,
                edge_id=edge_id,
                permission=edge_data.get("permission", ""),
                privilege_level=edge_data.get("privilege_level", 0),
                conditions=edge.conditions if edge else [],
                difficulty_score=edge_data.get("weight", 0.5),
                description=f"Access {target_id} via {edge_data.get('permission', 'unknown')}",
            )

            steps.append(step)
            total_difficulty += step.difficulty_score

        # Calculate path metrics
        exploitability_score = self._calculate_exploitability_score(steps)
        impact_score = self._calculate_impact_score(
            path[-1]
        )  # Impact of reaching target
        severity = self._calculate_path_severity(exploitability_score, impact_score)

        # Generate mitigations
        mitigations = self._generate_path_mitigations(steps)

        path_id = f"path_{source_id}_{target_id}_{len(steps)}"

        return AttackPath(
            path_id=path_id,
            source_principal=path[0],
            target_resource=path[-1],
            steps=steps,
            total_difficulty=total_difficulty,
            path_length=len(steps),
            severity=severity,
            exploitability_score=exploitability_score,
            impact_score=impact_score,
            mitigations=mitigations,
            evidence_references=[],
        )

    def _calculate_exploitability_score(self, steps: list[AttackStep]) -> float:
        """Calculate how easily exploitable this path is."""
        if not steps:
            return 0.0

        # Lower difficulty = higher exploitability
        avg_difficulty = sum(step.difficulty_score for step in steps) / len(steps)
        exploitability = 1.0 - avg_difficulty

        # Bonus for fewer conditions
        total_conditions = sum(len(step.conditions) for step in steps)
        condition_penalty = min(total_conditions * 0.1, 0.5)

        # Bonus for service account steps (often easier)
        service_steps = len([s for s in steps if "service" in s.source_node.lower()])
        service_bonus = min(service_steps * 0.1, 0.3)

        final_score = exploitability - condition_penalty + service_bonus

        return max(0.0, min(1.0, final_score))

    def _calculate_impact_score(self, target_resource: str) -> float:
        """Calculate impact score of reaching target resource."""
        target_node = self.attack_graph.nodes.get(target_resource)
        if not target_node:
            return 0.5

        # Base impact from node risk score and criticality
        base_impact = target_node.risk_score

        criticality_bonus = {
            "critical": 0.4,
            "high": 0.3,
            "medium": 0.2,
            "low": 0.1,
        }.get(target_node.criticality, 0.1)

        return min(1.0, base_impact + criticality_bonus)

    def _calculate_path_severity(
        self, exploitability: float, impact: float
    ) -> PathSeverity:
        """Calculate overall path severity."""
        # Combined risk score
        risk_score = (exploitability * 0.6) + (impact * 0.4)

        if risk_score >= 0.8:
            return PathSeverity.CRITICAL
        elif risk_score >= 0.6:
            return PathSeverity.HIGH
        elif risk_score >= 0.4:
            return PathSeverity.MEDIUM
        else:
            return PathSeverity.LOW

    def _generate_path_mitigations(self, steps: list[AttackStep]) -> list[str]:
        """Generate mitigation recommendations for attack path."""
        mitigations = []

        # Analyze steps for common mitigation patterns
        has_service_account_step = any(
            "service" in step.source_node.lower() for step in steps
        )
        has_high_privilege_step = any(step.privilege_level >= 2 for step in steps)
        has_cross_provider_step = (
            len(
                {
                    self.attack_graph.nodes[step.source_node].provider
                    for step in steps
                    if step.source_node in self.attack_graph.nodes
                }
            )
            > 1
        )

        # Service account mitigations
        if has_service_account_step:
            mitigations.extend(
                [
                    "Implement service account key rotation",
                    "Use workload identity instead of service account keys",
                    "Apply principle of least privilege to service accounts",
                ]
            )

        # High privilege mitigations
        if has_high_privilege_step:
            mitigations.extend(
                [
                    "Require MFA for high-privilege operations",
                    "Implement just-in-time access for admin permissions",
                    "Add approval workflow for elevated access",
                ]
            )

        # Cross-provider mitigations
        if has_cross_provider_step:
            mitigations.extend(
                [
                    "Review cross-provider trust relationships",
                    "Implement break-glass procedures",
                    "Monitor cross-provider access patterns",
                ]
            )

        # Step-specific mitigations
        for step in steps:
            if not step.conditions:
                mitigations.append(f"Add access conditions for {step.permission}")

            if step.difficulty_score < 0.3:  # Very easy step
                mitigations.append(f"Strengthen controls for {step.permission}")

        # Deduplicate and limit
        return list(set(mitigations))[:10]

    async def simulate_principal_compromise(
        self, principal_id: str, max_steps: int = 5
    ) -> dict[str, Any]:
        """
        Simulate what an attacker could reach if they compromise a principal.

        Args:
            principal_id: Principal to simulate compromise
            max_steps: Maximum steps for reachability analysis

        Returns:
            Simulation results with reachable resources and paths
        """
        if principal_id not in self.attack_graph.nodes:
            raise ValueError(f"Principal {principal_id} not found in attack graph")

        # Find all reachable resources within max_steps
        reachable_resources = []
        reachable_paths = []

        # Use NetworkX to find all nodes reachable within max_steps
        reachable_nodes = set()

        # BFS with depth limit
        queue = [(principal_id, 0)]  # (node, depth)
        visited = {principal_id}

        while queue:
            current_node, depth = queue.pop(0)

            if depth < max_steps:
                # Add neighbors to queue
                for neighbor in self.graph.successors(current_node):
                    if neighbor not in visited:
                        visited.add(neighbor)
                        queue.append((neighbor, depth + 1))
                        reachable_nodes.add(neighbor)

                        # If it's a resource, add to results
                        neighbor_node = self.attack_graph.nodes.get(neighbor)
                        if (
                            neighbor_node
                            and neighbor_node.node_type.value == "resource"
                        ):
                            # Find shortest path to this resource
                            try:
                                path = nx.shortest_path(
                                    self.graph, principal_id, neighbor, weight="weight"
                                )

                                attack_path = await self._convert_to_attack_path(
                                    path,
                                    PathQuery(
                                        source_principal=principal_id,
                                        target_resource=neighbor,
                                        max_path_length=max_steps,
                                        path_type=PathType.SHORTEST_PATH,
                                        min_privilege_level=0,
                                        exclude_conditions=[],
                                    ),
                                )

                                if attack_path:
                                    reachable_paths.append(attack_path)
                                    reachable_resources.append(
                                        {
                                            "resource_id": neighbor,
                                            "resource_type": neighbor_node.node_type.value,
                                            "provider": neighbor_node.provider,
                                            "criticality": neighbor_node.criticality,
                                            "steps_to_reach": len(path) - 1,
                                            "path_difficulty": attack_path.total_difficulty,
                                        }
                                    )

                            except nx.NetworkXNoPath:
                                continue

        # Sort by criticality and difficulty
        reachable_resources.sort(
            key=lambda r: (
                {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(
                    r["criticality"], 1
                ),
                -r["path_difficulty"],  # Negative for easier paths first
            ),
            reverse=True,
        )

        reachable_paths.sort(key=lambda p: p.exploitability_score, reverse=True)

        return {
            "compromised_principal": principal_id,
            "simulation_parameters": {
                "max_steps": max_steps,
                "analysis_date": datetime.now().isoformat(),
            },
            "blast_radius": {
                "total_reachable_resources": len(reachable_resources),
                "critical_resources": len(
                    [r for r in reachable_resources if r["criticality"] == "critical"]
                ),
                "high_risk_resources": len(
                    [r for r in reachable_resources if r["criticality"] == "high"]
                ),
                "average_steps_to_critical": sum(
                    r["steps_to_reach"]
                    for r in reachable_resources
                    if r["criticality"] == "critical"
                )
                / max(
                    len(
                        [
                            r
                            for r in reachable_resources
                            if r["criticality"] == "critical"
                        ]
                    ),
                    1,
                ),
            },
            "reachable_resources": reachable_resources[:20],  # Top 20
            "attack_paths": [
                {
                    "path_id": path.path_id,
                    "target_resource": path.target_resource,
                    "steps": len(path.steps),
                    "severity": path.severity.value,
                    "exploitability": path.exploitability_score,
                    "impact": path.impact_score,
                }
                for path in reachable_paths[:10]  # Top 10
            ],
            "recommended_mitigations": self._aggregate_mitigations(reachable_paths),
        }

    def _aggregate_mitigations(self, paths: list[AttackPath]) -> list[str]:
        """Aggregate mitigation recommendations from multiple paths."""
        all_mitigations = []
        for path in paths:
            all_mitigations.extend(path.mitigations)

        # Count frequency and return top recommendations
        mitigation_counts: dict[str, int] = {}
        for mitigation in all_mitigations:
            mitigation_counts[mitigation] = mitigation_counts.get(mitigation, 0) + 1

        # Sort by frequency and return top 10
        sorted_mitigations = sorted(
            mitigation_counts.items(), key=lambda x: x[1], reverse=True
        )

        return [mitigation for mitigation, count in sorted_mitigations[:10]]


# CLI path query examples
ATTACK_PATH_CLI_EXAMPLES = [
    "cerebro graph path --from principal:jane@acme.com --to resource:aws:s3://prod-secrets --show-evidence",
    "cerebro graph simulate --principal user123 --max-steps 3 --show-blast-radius",
    "cerebro graph escalation --from service:github-actions --steps 2 --min-privilege admin",
]


# Global path analyzer cache
_path_analyzers: dict[str, PathAnalyzer] = {}


async def get_path_analyzer(org_id: str) -> PathAnalyzer:
    """Get path analyzer for organization."""
    if org_id not in _path_analyzers:
        attack_graph = await get_attack_graph(org_id)
        _path_analyzers[org_id] = PathAnalyzer(attack_graph)

    return _path_analyzers[org_id]
