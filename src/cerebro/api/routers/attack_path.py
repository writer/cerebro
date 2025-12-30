"""
Attack path analysis API endpoints.

Provides REST API for attack path queries, blast radius analysis,
and service identity mapping.
"""

from typing import Any
from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from ...api.auth import User, require_read_findings
from ...api.org_access import require_org_access
from ...attack_path.graph_model import get_attack_graph
from ...attack_path.path_analysis import PathQuery, PathType, get_path_analyzer
from ...attack_path.reachability import get_reachability_analyzer
from ...attack_path.service_identity import get_service_identity_mapper
from ...core.database import get_db
from ...core.models import Organization

router = APIRouter()
logger = structlog.get_logger(__name__)


class AttackPathQuery(BaseModel):
    """Request for attack path analysis."""

    source_principal: str | None = Field(None, description="Source principal ID")
    target_resource: str | None = Field(None, description="Target resource ID")
    max_path_length: int = Field(5, description="Maximum path length", ge=1, le=10)
    path_type: str = Field("shortest_path", description="Type of path analysis")
    min_privilege_level: int = Field(
        0, description="Minimum privilege level", ge=0, le=3
    )


class BlastRadiusQuery(BaseModel):
    """Request for blast radius analysis."""

    principal_id: str = Field(..., description="Principal to analyze")
    max_steps: int = Field(5, description="Maximum steps for analysis", ge=1, le=10)
    include_service_paths: bool = Field(
        True, description="Include service identity paths"
    )


class WhatIfScenario(BaseModel):
    """What-if simulation scenario."""

    scenario_type: str = Field(..., description="Scenario type")
    parameters: dict[str, Any] = Field(..., description="Scenario parameters")


@router.post("/organizations/{org_id}/attack-paths/analyze")
async def analyze_attack_paths(
    org_id: UUID,
    query: AttackPathQuery,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_org_access(require_read_findings)),
):
    """Analyze attack paths based on query parameters."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    try:
        path_analyzer = await get_path_analyzer(str(org_id))

        # Convert request to PathQuery
        path_query = PathQuery(
            source_principal=query.source_principal,
            target_resource=query.target_resource,
            max_path_length=query.max_path_length,
            path_type=PathType(query.path_type.lower()),
            min_privilege_level=query.min_privilege_level,
            exclude_conditions=[],
        )

        # Find attack paths
        paths = await path_analyzer.find_attack_paths(path_query)

        return {
            "success": True,
            "message": f"Found {len(paths)} attack paths",
            "data": {
                "query": {
                    "source_principal": query.source_principal,
                    "target_resource": query.target_resource,
                    "max_path_length": query.max_path_length,
                    "path_type": query.path_type,
                },
                "results": {
                    "total_paths": len(paths),
                    "shortest_path_length": min(
                        (p.path_length for p in paths), default=None
                    ),
                    "critical_paths": len(
                        [p for p in paths if p.severity.value == "critical"]
                    ),
                    "high_severity_paths": len(
                        [p for p in paths if p.severity.value in ["high", "critical"]]
                    ),
                },
                "paths": [
                    {
                        "path_id": path.path_id,
                        "source_principal": path.source_principal,
                        "target_resource": path.target_resource,
                        "steps": [
                            {
                                "step_number": step.step_number,
                                "source_node": step.source_node,
                                "target_node": step.target_node,
                                "permission": step.permission,
                                "privilege_level": step.privilege_level,
                                "conditions": step.conditions,
                                "description": step.description,
                            }
                            for step in path.steps
                        ],
                        "path_length": path.path_length,
                        "severity": path.severity.value,
                        "exploitability_score": path.exploitability_score,
                        "impact_score": path.impact_score,
                        "mitigations": path.mitigations,
                    }
                    for path in paths[:20]  # Limit results
                ],
            },
        }

    except Exception:
        logger.exception("Attack path analysis failed", extra={"org_id": str(org_id)})
        raise HTTPException(status_code=500, detail="Attack path analysis failed") from None



@router.post("/organizations/{org_id}/blast-radius")
async def analyze_blast_radius(
    org_id: UUID,
    query: BlastRadiusQuery,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_org_access(require_read_findings)),
):
    """Analyze blast radius for principal compromise."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    try:
        analyzer = get_reachability_analyzer()

        result = await analyzer.analyze_principal_reachability(
            str(org_id), query.principal_id, query.max_steps
        )

        return {
            "success": True,
            "message": f"Blast radius analysis complete - {result.blast_radius_size} resources reachable",
            "data": {
                "principal_id": query.principal_id,
                "analysis_parameters": {
                    "max_steps": query.max_steps,
                    "include_service_paths": query.include_service_paths,
                },
                "blast_radius": {
                    "total_reachable_resources": result.blast_radius_size,
                    "critical_resources": len(list(result.critical_paths)),
                    "shortest_path_length": result.shortest_path_length,
                    "overall_risk_score": result.overall_risk_score,
                },
                "attack_paths": [
                    {
                        "target_resource": path.target_resource,
                        "path_length": path.path_length,
                        "severity": path.severity.value,
                        "exploitability": path.exploitability_score,
                        "steps": len(path.steps),
                    }
                    for path in result.paths_found[:15]
                ],
                "mitigations": result.mitigations,
                "monitoring_recommendations": result.monitoring_recommendations,
                "analysis_duration_ms": result.analysis_duration_ms,
            },
        }

    except Exception:
        logger.exception("Blast radius analysis failed", extra={"org_id": str(org_id)})
        raise HTTPException(status_code=500, detail="Blast radius analysis failed") from None



@router.get("/organizations/{org_id}/attack-graph/summary")
async def get_attack_graph_summary(
    org_id: UUID,
    rebuild: bool = Query(False, description="Rebuild graph from current data"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_org_access(require_read_findings)),
):
    """Get attack graph summary statistics."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    try:
        attack_graph = await get_attack_graph(str(org_id), rebuild=rebuild)
        summary = attack_graph.export_graph_summary()

        return {
            "success": True,
            "message": f"Attack graph summary for {summary['graph_metrics']['total_nodes']} nodes",
            "data": summary,
        }

    except Exception:
        logger.exception("Attack graph summary failed", extra={"org_id": str(org_id)})
        raise HTTPException(status_code=500, detail="Graph summary failed") from None



@router.get("/organizations/{org_id}/service-identities")
async def get_service_identities(
    org_id: UUID,
    risk_level: str | None = Query(None, description="Filter by risk level"),
    trust_mechanism: str | None = Query(
        None, description="Filter by trust mechanism"
    ),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_org_access(require_read_findings)),
):
    """Get service identity mappings and risk analysis."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    try:
        service_mapper = get_service_identity_mapper()

        # Discover service identities
        service_edges = await service_mapper.discover_service_identities(str(org_id))

        # Apply filters
        filtered_edges = service_edges

        if risk_level:
            if risk_level == "high":
                filtered_edges = [e for e in filtered_edges if e.risk_score >= 0.7]
            elif risk_level == "medium":
                filtered_edges = [
                    e for e in filtered_edges if 0.4 <= e.risk_score < 0.7
                ]
            elif risk_level == "low":
                filtered_edges = [e for e in filtered_edges if e.risk_score < 0.4]

        if trust_mechanism:
            filtered_edges = [
                e for e in filtered_edges if e.trust_mechanism.value == trust_mechanism
            ]

        # Generate risk analysis
        risk_analysis = await service_mapper.analyze_service_identity_risks(str(org_id))

        return {
            "organization_id": str(org_id),
            "total_service_edges": len(service_edges),
            "filtered_edges": len(filtered_edges),
            "service_edges": [
                {
                    "edge_id": edge.edge_id,
                    "source_service": edge.source_service,
                    "target_service": edge.target_service,
                    "trust_mechanism": edge.trust_mechanism.value,
                    "provider_source": edge.provider_source,
                    "provider_target": edge.provider_target,
                    "risk_score": edge.risk_score,
                    "exploitability": edge.exploitability,
                    "conditions": edge.conditions,
                    "allowed_repositories": edge.allowed_repositories,
                }
                for edge in filtered_edges
            ],
            "risk_analysis": risk_analysis,
        }

    except Exception:
        logger.exception(
            "Service identity analysis failed", extra={"org_id": str(org_id)}
        )
        raise HTTPException(status_code=500, detail="Service identity analysis failed") from None



@router.post("/organizations/{org_id}/what-if")
async def what_if_simulation(
    org_id: UUID,
    scenario: WhatIfScenario,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_org_access(require_read_findings)),
):
    """Perform what-if attack simulation."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    try:
        analyzer = get_reachability_analyzer()

        simulation_result = await analyzer.what_if_simulation(
            str(org_id), {"type": scenario.scenario_type, **scenario.parameters}
        )

        return {
            "success": True,
            "message": f"What-if simulation completed: {scenario.scenario_type}",
            "data": simulation_result,
        }

    except Exception:
        logger.exception("What-if simulation failed", extra={"org_id": str(org_id)})
        raise HTTPException(status_code=500, detail="Simulation failed") from None



@router.get("/organizations/{org_id}/high-value-targets")
async def get_high_value_targets(
    org_id: UUID,
    limit: int = Query(20, description="Number of targets to return", ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_org_access(require_read_findings)),
):
    """Get high-value targets for attack path analysis."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    try:
        attack_graph = await get_attack_graph(str(org_id))
        targets = attack_graph.get_high_value_targets(limit)

        return {
            "organization_id": str(org_id),
            "total_targets": len(targets),
            "high_value_targets": [
                {
                    "node_id": target.node_id,
                    "display_name": target.display_name,
                    "provider": target.provider,
                    "risk_score": target.risk_score,
                    "criticality": target.criticality,
                    "node_type": target.node_type.value,
                    "properties": target.properties,
                }
                for target in targets
            ],
        }

    except Exception:
        logger.exception(
            "High-value targets query failed", extra={"org_id": str(org_id)}
        )
        raise HTTPException(status_code=500, detail="Target query failed") from None



@router.get("/organizations/{org_id}/high-privilege-principals")
async def get_high_privilege_principals(
    org_id: UUID,
    limit: int = Query(20, description="Number of principals to return", ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_org_access(require_read_findings)),
):
    """Get high-privilege principals for attack path analysis."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    try:
        attack_graph = await get_attack_graph(str(org_id))
        principals = attack_graph.get_high_privilege_principals(limit)

        return {
            "organization_id": str(org_id),
            "total_principals": len(principals),
            "high_privilege_principals": [
                {
                    "node_id": principal.node_id,
                    "display_name": principal.display_name,
                    "provider": principal.provider,
                    "risk_score": principal.risk_score,
                    "criticality": principal.criticality,
                    "node_type": principal.node_type.value,
                    "properties": principal.properties,
                }
                for principal in principals
            ],
        }

    except Exception:
        logger.exception(
            "High-privilege principals query failed", extra={"org_id": str(org_id)}
        )
        raise HTTPException(status_code=500, detail="Principals query failed") from None

