"""Risk analytics API endpoints."""

from typing import Any, Dict, List
from uuid import UUID
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from cerebro.core.analytics_db import get_analytics_db
from cerebro.core.database import get_db
from cerebro.core.models import Organization
from cerebro.api.auth import get_current_user, require_scopes, User
from cerebro.api.org_access import require_org_access
from cerebro.analytics.risk_scoring import RiskScoringEngine
from cerebro.analytics.identity_analytics import (
    IdentityAnalyzer,
    PrivilegeSprawlDetector,
)

router = APIRouter(dependencies=[Depends(get_current_user)])


@router.get("/organizations/{org_id}/risk-score")
async def get_organization_risk_score(
    org_id: UUID,
    db: AsyncSession = Depends(get_db),
    analytics_db: Any = Depends(get_analytics_db),
    current_user: User = Depends(require_org_access(require_scopes("read:findings"))),
) -> Dict[str, Any]:
    """Get detailed organizational risk score analysis."""

    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    risk_engine = RiskScoringEngine(analytics_db)
    risk_score = await risk_engine.calculate_organization_risk_score(org_id)

    return {
        "org_id": str(risk_score.org_id),
        "overall_score": risk_score.overall_score,
        "risk_level": risk_score.risk_level.value,
        "calculation_date": risk_score.calculation_date.isoformat(),
        "dimension_scores": {
            "vulnerability_exposure": risk_score.vulnerability_score,
            "identity_hygiene": risk_score.identity_score,
            "access_control": risk_score.access_control_score,
            "compliance_posture": risk_score.compliance_score,
            "operational_security": risk_score.operational_score,
        },
        "trend_analysis": {
            "score_trend": risk_score.score_trend,
            "trend_confidence": risk_score.trend_confidence,
        },
        "risk_factors": [
            {
                "factor_name": factor.factor_name,
                "category": factor.category,
                "current_value": factor.current_value,
                "risk_contribution": factor.risk_contribution,
                "description": factor.description,
                "remediation_suggestions": factor.remediation_suggestions,
            }
            for factor in risk_score.risk_factors
        ],
        "actionable_insights": {
            "top_risks": risk_score.top_risks,
            "quick_wins": risk_score.quick_wins,
            "strategic_initiatives": risk_score.strategic_initiatives,
        },
    }


@router.get("/organizations/{org_id}/risk-heatmap")
async def get_risk_heatmap(
    org_id: UUID,
    db: AsyncSession = Depends(get_db),
    analytics_db: Any = Depends(get_analytics_db),
    current_user: User = Depends(require_org_access(require_scopes("read:findings"))),
) -> Dict[str, Any]:
    """Get risk heatmap data for visualization."""

    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    risk_engine = RiskScoringEngine(analytics_db)
    heatmap = await risk_engine.generate_risk_heatmap(org_id)

    return {
        "org_id": str(heatmap.org_id),
        "heatmap_data": heatmap.heatmap_data,
        "high_risk_areas": heatmap.high_risk_areas,
        "improvement_opportunities": heatmap.improvement_opportunities,
    }


@router.get("/organizations/{org_id}/identity-analytics")
async def get_identity_analytics(
    org_id: UUID,
    db: AsyncSession = Depends(get_db),
    analytics_db: Any = Depends(get_analytics_db),
    current_user: User = Depends(require_org_access(require_scopes("read:principals"))),
) -> Dict[str, Any]:
    """Get identity-centric analytics and privilege sprawl data."""

    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    identity_analyzer = IdentityAnalyzer(analytics_db, core_db_session=db)
    identity_data = await identity_analyzer.generate_identity_dashboard_data(org_id)

    return identity_data


@router.get("/organizations/{org_id}/risky-identities")
async def get_risky_identities(
    org_id: UUID,
    limit: int = Query(
        default=20, description="Maximum number of risky identities to return"
    ),
    db: AsyncSession = Depends(get_db),
    analytics_db: Any = Depends(get_analytics_db),
    current_user: User = Depends(require_org_access(require_scopes("read:principals"))),
) -> List[Dict[str, Any]]:
    """Get identities with highest risk profiles."""

    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    identity_analyzer = IdentityAnalyzer(analytics_db, core_db_session=db)
    risky_identities = await identity_analyzer.analyze_risky_identities(
        org_id, limit=limit
    )

    return [
        {
            "principal_id": str(identity.principal_id),
            "display_name": identity.display_name,
            "email": identity.email,
            "risk_score": round(identity.risk_score, 1),
            "risk_level": identity.risk_level.value,
            "privilege_sprawl_score": round(identity.privilege_sprawl_score, 1),
            "cross_provider_access": identity.cross_provider_access,
            "admin_access_count": identity.admin_access_count,
            "stale_permissions_count": identity.stale_permissions_count,
            "mfa_status": identity.mfa_status,
            "provider_access": identity.provider_access,
            "risk_factors": identity.risk_factors,
            "remediation_actions": identity.remediation_actions,
        }
        for identity in risky_identities
    ]


@router.get("/organizations/{org_id}/privilege-sprawl")
async def get_privilege_sprawl_analysis(
    org_id: UUID,
    db: AsyncSession = Depends(get_db),
    analytics_db: Any = Depends(get_analytics_db),
    current_user: User = Depends(require_org_access(require_scopes("read:principals"))),
) -> Dict[str, Any]:
    """Get privilege sprawl analysis for the organization."""

    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    sprawl_detector = PrivilegeSprawlDetector(analytics_db)
    sprawl_analysis = await sprawl_detector.analyze_privilege_sprawl(org_id)

    return {
        "org_id": str(sprawl_analysis.org_id),
        "analysis_date": sprawl_analysis.analysis_date.isoformat(),
        "summary": {
            "total_identities": sprawl_analysis.total_identities,
            "high_privilege_identities": sprawl_analysis.high_privilege_identities,
            "cross_provider_identities": sprawl_analysis.cross_provider_identities,
            "avg_permissions_per_identity": round(
                sprawl_analysis.avg_permissions_per_identity, 1
            ),
            "max_permissions_per_identity": sprawl_analysis.max_permissions_per_identity,
        },
        "privilege_distribution": sprawl_analysis.privilege_distribution,
        "provider_breakdown": sprawl_analysis.provider_privilege_breakdown,
        "top_risky_identities": [
            {
                "principal_id": str(identity.principal_id),
                "display_name": identity.display_name,
                "risk_score": round(identity.risk_score, 1),
                "risk_level": identity.risk_level.value,
                "cross_provider_access": identity.cross_provider_access,
            }
            for identity in sprawl_analysis.top_risky_identities[:10]
        ],
    }


@router.get("/organizations/{org_id}/top-risks")
async def get_top_organizational_risks(
    org_id: UUID,
    limit: int = Query(default=10, description="Number of top risks to return"),
    db: AsyncSession = Depends(get_db),
    analytics_db: Any = Depends(get_analytics_db),
    current_user: User = Depends(require_org_access(require_scopes("read:findings"))),
) -> List[Dict[str, Any]]:
    """Get top organizational risks with context and remediation guidance."""

    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    # Get top risks with business context
    top_risks_query = text(
        """
        WITH risk_aggregation AS (
            SELECT
                r.name as risk_name,
                r.description,
                COUNT(*) as finding_count,
                f.severity,
                a.provider,
                COUNT(DISTINCT f.resource_id) as affected_resources,
                COUNT(DISTINCT f.principal_id) as affected_identities,
                MIN(f.first_seen) as first_occurrence,
                MAX(f.last_seen) as latest_occurrence,
                CASE f.severity
                    WHEN 'critical' THEN 100
                    WHEN 'high' THEN 75
                    WHEN 'medium' THEN 50
                    WHEN 'low' THEN 25
                    ELSE 10
                END * COUNT(*) as risk_impact_score
            FROM findings f
            JOIN rules r ON f.rule_id = r.rule_id
            JOIN accounts a ON f.account_id = a.account_id
            WHERE a.org_id = :org_id AND f.status = 'open'
            GROUP BY r.name, r.description, f.severity, a.provider
        )
        SELECT *
        FROM risk_aggregation
        ORDER BY risk_impact_score DESC, finding_count DESC
        LIMIT :limit
    """
    )

    result = await analytics_db.execute(
        top_risks_query, {"org_id": org_id, "limit": limit}
    )

    top_risks = []
    for i, row in enumerate(result.fetchall(), 1):

        # Generate business impact description
        impact_desc = f"Affects {row.affected_resources} resources"
        if row.affected_identities > 0:
            impact_desc += f" and {row.affected_identities} identities"

        # Generate remediation urgency
        first_occurrence = row.first_occurrence
        if first_occurrence is not None and first_occurrence.tzinfo is None:
            first_occurrence = first_occurrence.replace(tzinfo=timezone.utc)

        days_since_first = 0
        if first_occurrence is not None:
            days_since_first = (datetime.now(timezone.utc) - first_occurrence).days
        if row.severity == "critical" and days_since_first > 7:
            urgency = "immediate"
        elif row.severity == "high" and days_since_first > 14:
            urgency = "high"
        else:
            urgency = "normal"

        top_risks.append(
            {
                "rank": i,
                "risk_name": row.risk_name,
                "description": row.description,
                "severity": row.severity,
                "provider": row.provider,
                "finding_count": row.finding_count,
                "risk_impact_score": row.risk_impact_score,
                "business_impact": impact_desc,
                "first_seen": row.first_occurrence.isoformat(),
                "latest_occurrence": row.latest_occurrence.isoformat(),
                "days_since_first": days_since_first,
                "remediation_urgency": urgency,
                "affected_resources": row.affected_resources,
                "affected_identities": row.affected_identities,
            }
        )

    return top_risks
