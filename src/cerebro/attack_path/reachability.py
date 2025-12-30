"""
Reachability analyzer for attack path queries.

Provides high-level interface for attack path analysis with
CLI integration and what-if simulation capabilities.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any

import structlog

from .graph_model import get_attack_graph
from .path_analysis import AttackPath, PathQuery, PathType, get_path_analyzer

logger = structlog.get_logger(__name__)


@dataclass
class ReachabilityResult:
    """Result of reachability analysis."""

    query_id: str
    source_principal: str | None
    target_resource: str | None
    analysis_type: str

    # Results
    paths_found: list[AttackPath]
    total_paths: int
    shortest_path_length: int | None
    most_exploitable_path: AttackPath | None

    # Risk assessment
    overall_risk_score: float
    blast_radius_size: int
    critical_paths: list[AttackPath]

    # Recommendations
    mitigations: list[str]
    monitoring_recommendations: list[str]

    # Metadata
    analysis_duration_ms: float
    graph_stats: dict[str, Any]
    generated_at: datetime


class ReachabilityAnalyzer:
    """
    High-level reachability analyzer for attack path queries.

    Provides comprehensive attack path analysis with risk scoring,
    mitigation recommendations, and simulation capabilities.
    """

    def __init__(self):
        pass

    async def analyze_principal_reachability(
        self, org_id: str, principal_id: str, max_steps: int = 5
    ) -> ReachabilityResult:
        """
        Analyze what a principal can reach (blast radius analysis).

        Args:
            org_id: Organization ID
            principal_id: Principal to analyze
            max_steps: Maximum steps in attack paths

        Returns:
            Comprehensive reachability analysis
        """
        start_time = datetime.now()
        query_id = f"reachability_{principal_id}_{int(start_time.timestamp())}"

        # Get attack graph and path analyzer
        attack_graph = await get_attack_graph(org_id)
        path_analyzer = await get_path_analyzer(org_id)

        # Simulate principal compromise
        simulation_result = await path_analyzer.simulate_principal_compromise(
            principal_id, max_steps
        )

        # Find paths to high-value targets
        high_value_targets = attack_graph.get_high_value_targets(10)

        paths_to_targets = []
        for target in high_value_targets:
            query = PathQuery(
                source_principal=principal_id,
                target_resource=target.node_id,
                max_path_length=max_steps,
                path_type=PathType.SHORTEST_PATH,
                min_privilege_level=0,
                exclude_conditions=[],
            )

            target_paths = await path_analyzer.find_attack_paths(query)
            paths_to_targets.extend(target_paths)

        # Calculate overall risk metrics
        overall_risk_score = self._calculate_overall_risk_score(
            paths_to_targets, simulation_result
        )

        # Identify critical paths
        critical_paths = [
            path
            for path in paths_to_targets
            if path.severity.value in ["high", "critical"]
        ]

        # Generate recommendations
        mitigations = self._generate_comprehensive_mitigations(
            paths_to_targets, simulation_result
        )
        monitoring_recs = self._generate_monitoring_recommendations(
            principal_id, paths_to_targets
        )

        analysis_duration = (datetime.now() - start_time).total_seconds() * 1000

        result = ReachabilityResult(
            query_id=query_id,
            source_principal=principal_id,
            target_resource=None,
            analysis_type="principal_reachability",
            paths_found=paths_to_targets,
            total_paths=len(paths_to_targets),
            shortest_path_length=min(
                (p.path_length for p in paths_to_targets), default=None
            ),
            most_exploitable_path=max(
                paths_to_targets, key=lambda p: p.exploitability_score, default=None
            ),
            overall_risk_score=overall_risk_score,
            blast_radius_size=simulation_result["blast_radius"][
                "total_reachable_resources"
            ],
            critical_paths=critical_paths,
            mitigations=mitigations,
            monitoring_recommendations=monitoring_recs,
            analysis_duration_ms=analysis_duration,
            graph_stats=attack_graph.export_graph_summary(),
            generated_at=start_time,
        )

        logger.info(
            f"Reachability analysis complete: {len(paths_to_targets)} paths found"
        )

        return result

    async def analyze_resource_reachability(
        self, org_id: str, resource_id: str, max_steps: int = 5
    ) -> ReachabilityResult:
        """
        Analyze what can reach a resource (who has access).

        Args:
            org_id: Organization ID
            resource_id: Resource to analyze
            max_steps: Maximum steps in attack paths

        Returns:
            Analysis of all paths that can reach the resource
        """
        start_time = datetime.now()
        query_id = f"resource_reachability_{resource_id}_{int(start_time.timestamp())}"

        # Get attack graph and path analyzer
        attack_graph = await get_attack_graph(org_id)
        path_analyzer = await get_path_analyzer(org_id)

        # Find paths from high-privilege principals to this resource
        high_privilege_principals = attack_graph.get_high_privilege_principals(20)

        paths_to_resource = []
        for principal in high_privilege_principals:
            query = PathQuery(
                source_principal=principal.node_id,
                target_resource=resource_id,
                max_path_length=max_steps,
                path_type=PathType.SHORTEST_PATH,
                min_privilege_level=0,
                exclude_conditions=[],
            )

            principal_paths = await path_analyzer.find_attack_paths(query)
            paths_to_resource.extend(principal_paths)

        # Calculate risk metrics
        overall_risk_score = self._calculate_resource_exposure_risk(
            resource_id, paths_to_resource
        )

        # Identify critical access paths
        critical_paths = [
            path
            for path in paths_to_resource
            if path.severity.value in ["high", "critical"]
        ]

        # Generate recommendations
        mitigations = self._generate_resource_protection_mitigations(
            resource_id, paths_to_resource
        )
        monitoring_recs = self._generate_resource_monitoring_recommendations(
            resource_id, paths_to_resource
        )

        analysis_duration = (datetime.now() - start_time).total_seconds() * 1000

        result = ReachabilityResult(
            query_id=query_id,
            source_principal=None,
            target_resource=resource_id,
            analysis_type="resource_reachability",
            paths_found=paths_to_resource,
            total_paths=len(paths_to_resource),
            shortest_path_length=min(
                (p.path_length for p in paths_to_resource), default=None
            ),
            most_exploitable_path=max(
                paths_to_resource, key=lambda p: p.exploitability_score, default=None
            ),
            overall_risk_score=overall_risk_score,
            blast_radius_size=len(
                paths_to_resource
            ),  # Number of ways to reach resource
            critical_paths=critical_paths,
            mitigations=mitigations,
            monitoring_recommendations=monitoring_recs,
            analysis_duration_ms=analysis_duration,
            graph_stats=attack_graph.export_graph_summary(),
            generated_at=start_time,
        )

        return result

    async def what_if_simulation(
        self, org_id: str, scenario: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Perform what-if simulation for attack scenarios.

        Args:
            org_id: Organization ID
            scenario: Simulation scenario parameters

        Returns:
            Simulation results with impact analysis
        """
        scenario_type = scenario.get("type", "principal_compromise")

        if scenario_type == "principal_compromise":
            principal_id = scenario["principal_id"]
            result = await self.analyze_principal_reachability(org_id, principal_id)

            return {
                "scenario": scenario,
                "simulation_type": "principal_compromise",
                "results": {
                    "blast_radius": result.blast_radius_size,
                    "critical_resources_reachable": len(result.critical_paths),
                    "shortest_path_to_critical": result.shortest_path_length,
                    "overall_risk": result.overall_risk_score,
                    "key_mitigations": result.mitigations[:5],
                },
            }

        elif scenario_type == "service_account_compromise":
            service_id = scenario["service_id"]
            # Similar analysis but focused on service account paths
            result = await self.analyze_principal_reachability(org_id, service_id)

            return {
                "scenario": scenario,
                "simulation_type": "service_account_compromise",
                "results": {
                    "service_blast_radius": result.blast_radius_size,
                    "cross_provider_reach": len(
                        [
                            p
                            for p in result.paths_found
                            if len(
                                {step.source_node.split("_")[0] for step in p.steps}
                            )
                            > 1
                        ]
                    ),
                    "automation_risk": (
                        "high" if "actions" in service_id.lower() else "medium"
                    ),
                },
            }

        else:
            raise ValueError(f"Unknown simulation scenario type: {scenario_type}")

    def _calculate_overall_risk_score(
        self, paths: list[AttackPath], simulation_result: dict[str, Any]
    ) -> float:
        """Calculate overall risk score from analysis results."""
        if not paths:
            return 0.0

        # Factor in path exploitability
        max_exploitability = max((p.exploitability_score for p in paths), default=0.0)
        avg_exploitability = sum(p.exploitability_score for p in paths) / len(paths)

        # Factor in blast radius
        blast_radius = simulation_result["blast_radius"]["total_reachable_resources"]
        blast_radius_score = min(blast_radius / 50, 1.0)  # Normalize to 0-1

        # Factor in critical resource access
        critical_resources = simulation_result["blast_radius"]["critical_resources"]
        critical_score = min(critical_resources / 10, 1.0)  # Normalize to 0-1

        # Combine scores
        overall_score = (
            max_exploitability * 0.3
            + avg_exploitability * 0.2
            + blast_radius_score * 0.2
            + critical_score * 0.3
        )

        return min(overall_score, 1.0)

    def _calculate_resource_exposure_risk(
        self, resource_id: str, paths: list[AttackPath]
    ) -> float:
        """Calculate exposure risk for a specific resource."""
        if not paths:
            return 0.0

        # Factor in number of paths (more paths = higher exposure)
        path_count_score = min(len(paths) / 20, 1.0)

        # Factor in shortest path length (shorter = higher risk)
        shortest_length = min(p.path_length for p in paths)
        length_score = max(0, 1.0 - (shortest_length / 5))  # 5+ steps = low risk

        # Factor in most exploitable path
        max_exploitability = max(p.exploitability_score for p in paths)

        exposure_risk = (
            path_count_score * 0.3 + length_score * 0.4 + max_exploitability * 0.3
        )

        return min(exposure_risk, 1.0)

    def _generate_comprehensive_mitigations(
        self, paths: list[AttackPath], simulation_result: dict[str, Any]
    ) -> list[str]:
        """Generate comprehensive mitigation recommendations."""
        all_mitigations = []

        # Collect mitigations from all paths
        for path in paths:
            all_mitigations.extend(path.mitigations)

        # Add simulation-specific mitigations
        blast_radius = simulation_result["blast_radius"]

        if blast_radius["critical_resources"] > 0:
            all_mitigations.append(
                "Implement additional controls for critical resource access"
            )

        if blast_radius["average_steps_to_critical"] < 3:
            all_mitigations.append(
                "Add intermediate approval steps for critical resource paths"
            )

        # Deduplicate and prioritize by frequency
        mitigation_counts: dict[str, int] = {}
        for mitigation in all_mitigations:
            mitigation_counts[mitigation] = mitigation_counts.get(mitigation, 0) + 1

        # Sort by frequency (most common first)
        sorted_mitigations = sorted(
            mitigation_counts.items(), key=lambda x: x[1], reverse=True
        )

        return [mitigation for mitigation, count in sorted_mitigations[:15]]

    def _generate_monitoring_recommendations(
        self, principal_id: str, paths: list[AttackPath]
    ) -> list[str]:
        """Generate monitoring recommendations for principal."""
        recommendations = [
            f"Monitor {principal_id} for unusual access patterns",
            "Alert on privilege escalation attempts",
            "Track cross-provider access chains",
        ]

        # Add path-specific monitoring
        if any(p.path_length == 1 for p in paths):
            recommendations.append("Monitor direct access to critical resources")

        if any(
            "service" in step.source_node.lower()
            for path in paths
            for step in path.steps
        ):
            recommendations.append("Monitor service account token usage")

        return recommendations

    def _generate_resource_protection_mitigations(
        self, resource_id: str, paths: list[AttackPath]
    ) -> list[str]:
        """Generate resource-specific protection recommendations."""
        mitigations = [
            f"Implement access logging for {resource_id}",
            "Add resource-specific access controls",
            "Monitor for unusual access patterns",
        ]

        # Add path-specific protections
        if paths:
            shortest_path = min(paths, key=lambda p: p.path_length)
            if shortest_path.path_length <= 2:
                mitigations.append("Add intermediate access controls (path too short)")

            highest_impact = max(paths, key=lambda p: p.impact_score)
            if highest_impact.impact_score >= 0.8:
                mitigations.append(
                    "Implement break-glass access for high-impact resource"
                )

        return mitigations

    def _generate_resource_monitoring_recommendations(
        self, resource_id: str, paths: list[AttackPath]
    ) -> list[str]:
        """Generate resource-specific monitoring recommendations."""
        recommendations = [
            f"Monitor all access to {resource_id}",
            "Alert on access from unusual principals",
            "Track privilege escalation to this resource",
        ]

        if paths:
            # Add specific monitoring based on paths
            service_paths = [
                p
                for p in paths
                if any("service" in step.source_node.lower() for step in p.steps)
            ]

            if service_paths:
                recommendations.append("Monitor service account access patterns")

        return recommendations


# CLI integration examples
CLI_EXAMPLES = [
    # Basic path query
    "cerebro graph path --from principal:jane@acme.com --to resource:aws:s3://prod-secrets --show-evidence",
    # Blast radius simulation
    "cerebro graph simulate --principal user123 --max-steps 3 --show-blast-radius",
    # K-step escalation
    "cerebro graph escalation --from service:github-actions --steps 2 --min-privilege admin",
    # Resource exposure analysis
    "cerebro graph exposure --resource aws:s3://critical-data --show-all-paths",
    # What-if scenario
    "cerebro graph what-if --scenario principal_compromise --principal contractor_user --show-mitigations",
]


# Global reachability analyzer
_reachability_analyzer = ReachabilityAnalyzer()


def get_reachability_analyzer() -> ReachabilityAnalyzer:
    """Get global reachability analyzer."""
    return _reachability_analyzer


async def analyze_attack_path(
    org_id: str, source_principal: str, target_resource: str, max_steps: int = 5
) -> ReachabilityResult:
    """Convenience function for attack path analysis."""
    analyzer = get_reachability_analyzer()
    return await analyzer.analyze_principal_reachability(
        org_id, source_principal, max_steps
    )
