"""Analytics API endpoints for dashboard insights and metrics."""

from typing import Dict, List, Any, Optional
from uuid import UUID
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.core.database import get_db
from cerebro.core.models import Organization
from cerebro.api.auth import get_current_user, require_scopes, User
from cerebro.analytics.dashboard_analytics import DashboardAnalytics
from cerebro.analytics.time_series import TrendAnalyzer, MetricType
from cerebro.analytics.risk_scoring import RiskScoringEngine
from cerebro.analytics.identity_analytics import IdentityAnalyzer, PrivilegeSprawlDetector

router = APIRouter(dependencies=[Depends(get_current_user)])


@router.get("/organizations/{org_id}/dashboard")
async def get_organization_dashboard(
    org_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scopes("read:findings"))
) -> Dict[str, Any]:
    """Get comprehensive dashboard data for an organization."""
    
    # Verify organization exists
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    # Generate comprehensive dashboard
    dashboard_analytics = DashboardAnalytics(db)
    dashboard_data = await dashboard_analytics.generate_comprehensive_dashboard(org_id)
    
    return dashboard_data


@router.get("/organizations/{org_id}/executive-summary")
async def get_executive_summary(
    org_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scopes("read:findings"))
) -> Dict[str, Any]:
    """Get executive-level security summary."""
    
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    dashboard_analytics = DashboardAnalytics(db)
    executive_summary = await dashboard_analytics.generate_executive_summary(org_id)
    
    return {
        "org_id": str(executive_summary.org_id),
        "report_date": executive_summary.report_date.isoformat(),
        "overall_risk_score": executive_summary.overall_risk_score,
        "risk_level": executive_summary.risk_level,
        "risk_trend": executive_summary.risk_trend,
        "total_assets": executive_summary.total_assets,
        "total_identities": executive_summary.total_identities,
        "active_findings": executive_summary.active_findings,
        "compliance_score": executive_summary.compliance_score,
        "top_5_risks": executive_summary.top_5_risks,
        "progress_indicators": {
            "findings_burned_down_30d": executive_summary.findings_burned_down_30d,
            "new_controls_implemented": executive_summary.new_controls_implemented,
            "risk_score_change_30d": executive_summary.risk_score_change_30d
        },
        "recommended_investments": executive_summary.recommended_investments
    }


@router.get("/organizations/{org_id}/risk-score")
async def get_organization_risk_score(
    org_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scopes("read:findings"))
) -> Dict[str, Any]:
    """Get detailed organizational risk score analysis."""
    
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    risk_engine = RiskScoringEngine(db)
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
            "operational_security": risk_score.operational_score
        },
        "trend_analysis": {
            "score_trend": risk_score.score_trend,
            "trend_confidence": risk_score.trend_confidence
        },
        "risk_factors": [
            {
                "factor_name": factor.factor_name,
                "category": factor.category,
                "current_value": factor.current_value,
                "risk_contribution": factor.risk_contribution,
                "description": factor.description,
                "remediation_suggestions": factor.remediation_suggestions
            }
            for factor in risk_score.risk_factors
        ],
        "actionable_insights": {
            "top_risks": risk_score.top_risks,
            "quick_wins": risk_score.quick_wins,
            "strategic_initiatives": risk_score.strategic_initiatives
        }
    }


@router.get("/organizations/{org_id}/risk-heatmap")
async def get_risk_heatmap(
    org_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scopes("read:findings"))
) -> Dict[str, Any]:
    """Get risk heatmap data for visualization."""
    
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    risk_engine = RiskScoringEngine(db)
    heatmap = await risk_engine.generate_risk_heatmap(org_id)
    
    return {
        "org_id": str(heatmap.org_id),
        "heatmap_data": heatmap.heatmap_data,
        "high_risk_areas": heatmap.high_risk_areas,
        "improvement_opportunities": heatmap.improvement_opportunities
    }


@router.get("/organizations/{org_id}/identity-analytics") 
async def get_identity_analytics(
    org_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scopes("read:principals"))
) -> Dict[str, Any]:
    """Get identity-centric analytics and privilege sprawl data."""
    
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    identity_analyzer = IdentityAnalyzer(db)
    identity_data = await identity_analyzer.generate_identity_dashboard_data(org_id)
    
    return identity_data


@router.get("/organizations/{org_id}/risky-identities")
async def get_risky_identities(
    org_id: UUID,
    limit: int = Query(default=20, description="Maximum number of risky identities to return"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scopes("read:principals"))
) -> List[Dict[str, Any]]:
    """Get identities with highest risk profiles."""
    
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    identity_analyzer = IdentityAnalyzer(db)
    risky_identities = await identity_analyzer.analyze_risky_identities(org_id, limit=limit)
    
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
            "remediation_actions": identity.remediation_actions
        }
        for identity in risky_identities
    ]


@router.get("/organizations/{org_id}/privilege-sprawl")
async def get_privilege_sprawl_analysis(
    org_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scopes("read:principals"))
) -> Dict[str, Any]:
    """Get privilege sprawl analysis for the organization."""
    
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    sprawl_detector = PrivilegeSprawlDetector(db)
    sprawl_analysis = await sprawl_detector.analyze_privilege_sprawl(org_id)
    
    return {
        "org_id": str(sprawl_analysis.org_id),
        "analysis_date": sprawl_analysis.analysis_date.isoformat(),
        "summary": {
            "total_identities": sprawl_analysis.total_identities,
            "high_privilege_identities": sprawl_analysis.high_privilege_identities,
            "cross_provider_identities": sprawl_analysis.cross_provider_identities,
            "avg_permissions_per_identity": round(sprawl_analysis.avg_permissions_per_identity, 1),
            "max_permissions_per_identity": sprawl_analysis.max_permissions_per_identity
        },
        "privilege_distribution": sprawl_analysis.privilege_distribution,
        "provider_breakdown": sprawl_analysis.provider_privilege_breakdown,
        "top_risky_identities": [
            {
                "principal_id": str(identity.principal_id),
                "display_name": identity.display_name,
                "risk_score": round(identity.risk_score, 1),
                "risk_level": identity.risk_level.value,
                "cross_provider_access": identity.cross_provider_access
            }
            for identity in sprawl_analysis.top_risky_identities[:10]
        ]
    }


@router.get("/organizations/{org_id}/metrics/trends")
async def get_metric_trends(
    org_id: UUID,
    metric_type: str = Query(..., description="Metric type to analyze"),
    days_back: int = Query(default=30, description="Days of historical data"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scopes("read:findings"))
) -> Dict[str, Any]:
    """Get trend analysis for a specific metric."""
    
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    try:
        metric_enum = MetricType(metric_type)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid metric type: {metric_type}")
    
    trend_analyzer = TrendAnalyzer(db)
    trend = await trend_analyzer.analyze_metric_trend(org_id, metric_enum, days_back)
    
    return {
        "metric_type": trend.metric_type,
        "current_value": trend.current_value,
        "previous_value": trend.previous_value,
        "change_absolute": trend.change_absolute,
        "change_percentage": round(trend.change_percentage, 2),
        "trend_direction": trend.trend_direction,
        "confidence": round(trend.confidence, 2),
        "data_points": trend.data_points,
        "sparkline_values": [point["value"] for point in trend.data_points]
    }


@router.get("/organizations/{org_id}/sla-breaches")
async def get_sla_breach_analysis(
    org_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scopes("read:findings"))
) -> Dict[str, Any]:
    """Get detailed SLA breach analysis with ownership."""
    
    from sqlalchemy import text
    
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    # Get SLA breaches by severity with details and ownership
    sla_breach_query = text("""
        SELECT 
            f.finding_id,
            f.title,
            f.severity,
            f.status,
            f.first_seen,
            r.name as rule_name,
            r.owner,
            r.backup_owner,
            a.provider,
            EXTRACT(EPOCH FROM (NOW() - f.first_seen)) / 86400 as days_old,
            CASE f.severity
                WHEN 'critical' THEN 7
                WHEN 'high' THEN 14
                WHEN 'medium' THEN 30
                WHEN 'low' THEN 90
                ELSE 30
            END as sla_days
        FROM findings f
        JOIN rules r ON f.rule_id = r.rule_id
        JOIN accounts a ON f.account_id = a.account_id
        WHERE a.org_id = :org_id 
            AND f.status = 'open'
            AND (
                (f.severity = 'critical' AND f.first_seen <= NOW() - INTERVAL '7 days') OR
                (f.severity = 'high' AND f.first_seen <= NOW() - INTERVAL '14 days') OR
                (f.severity = 'medium' AND f.first_seen <= NOW() - INTERVAL '30 days') OR
                (f.severity = 'low' AND f.first_seen <= NOW() - INTERVAL '90 days')
            )
        ORDER BY 
            CASE f.severity 
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
            END,
            f.first_seen
    """)
    
    result = await db.execute(sla_breach_query, {"org_id": org_id})
    breaches = result.fetchall()
    
    # Organize by severity
    breaches_by_severity = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": []
    }
    
    for breach in breaches:
        breach_data = {
            "finding_id": str(breach.finding_id),
            "title": breach.title,
            "rule_name": breach.rule_name,
            "provider": breach.provider,
            "days_old": int(breach.days_old),
            "sla_days": breach.sla_days,
            "days_overdue": int(breach.days_old) - breach.sla_days,
            "first_seen": breach.first_seen.isoformat(),
            "owner": breach.owner,
            "backup_owner": breach.backup_owner
        }
        breaches_by_severity[breach.severity].append(breach_data)
    
    # Calculate summary statistics
    total_breaches = len(breaches)
    critical_breaches = len(breaches_by_severity["critical"])
    high_breaches = len(breaches_by_severity["high"])
    
    return {
        "summary": {
            "total_sla_breaches": total_breaches,
            "critical_breaches": critical_breaches,
            "high_breaches": high_breaches,
            "average_days_overdue": round(sum(int(b.days_old) - b.sla_days for b in breaches) / len(breaches), 1) if breaches else 0
        },
        "breaches_by_severity": breaches_by_severity,
        "urgent_actions": [
            f"{critical_breaches} critical findings > 7 days old" if critical_breaches > 0 else None,
            f"{high_breaches} high findings > 14 days old" if high_breaches > 0 else None
        ]
    }


@router.get("/organizations/{org_id}/analytics/severity-breakdown")
async def get_severity_breakdown_chips(
    org_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scopes("read:findings"))
) -> Dict[str, Any]:
    """Get severity breakdown chips with SLA breach counts for dashboard badges."""
    
    from sqlalchemy import text
    
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    # Get counts by severity and SLA breach status
    severity_query = text("""
        WITH finding_counts AS (
            SELECT 
                f.severity,
                COUNT(*) as total_count,
                COUNT(CASE WHEN 
                    ((f.severity = 'critical' AND f.first_seen <= NOW() - INTERVAL '7 days') OR
                     (f.severity = 'high' AND f.first_seen <= NOW() - INTERVAL '14 days') OR
                     (f.severity = 'medium' AND f.first_seen <= NOW() - INTERVAL '30 days') OR
                     (f.severity = 'low' AND f.first_seen <= NOW() - INTERVAL '90 days'))
                     AND f.status = 'open'
                THEN 1 END) as sla_breach_count
            FROM findings f
            JOIN accounts a ON f.account_id = a.account_id
            WHERE a.org_id = :org_id AND f.status = 'open'
            GROUP BY f.severity
        )
        SELECT 
            'critical' as severity, 
            COALESCE(fc.total_count, 0) as total_count,
            COALESCE(fc.sla_breach_count, 0) as sla_breach_count
        FROM (SELECT 'critical' as severity) s
        LEFT JOIN finding_counts fc ON s.severity = fc.severity
        UNION ALL
        SELECT 
            'high' as severity,
            COALESCE(fc.total_count, 0) as total_count,
            COALESCE(fc.sla_breach_count, 0) as sla_breach_count
        FROM (SELECT 'high' as severity) s
        LEFT JOIN finding_counts fc ON s.severity = fc.severity
        UNION ALL
        SELECT 
            'medium' as severity,
            COALESCE(fc.total_count, 0) as total_count,
            COALESCE(fc.sla_breach_count, 0) as sla_breach_count
        FROM (SELECT 'medium' as severity) s
        LEFT JOIN finding_counts fc ON s.severity = fc.severity
        UNION ALL
        SELECT 
            'low' as severity,
            COALESCE(fc.total_count, 0) as total_count,
            COALESCE(fc.sla_breach_count, 0) as sla_breach_count
        FROM (SELECT 'low' as severity) s
        LEFT JOIN finding_counts fc ON s.severity = fc.severity
        ORDER BY 
            CASE severity 
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
            END
    """)
    
    result = await db.execute(severity_query, {"org_id": org_id})
    severity_data = result.fetchall()
    
    chips = []
    total_sla_breaches = 0
    
    # Map severity to short codes and colors
    severity_config = {
        "critical": {"code": "C", "color": "#dc2626", "bg_color": "#fee2e2"},
        "high": {"code": "H", "color": "#ea580c", "bg_color": "#fed7aa"},
        "medium": {"code": "M", "color": "#ca8a04", "bg_color": "#fef3c7"},
        "low": {"code": "L", "color": "#65a30d", "bg_color": "#ecfccb"}
    }
    
    for row in severity_data:
        config = severity_config[row.severity]
        total_sla_breaches += row.sla_breach_count
        
        chips.append({
            "severity": row.severity,
            "code": config["code"],
            "total_count": row.total_count,
            "sla_breach_count": row.sla_breach_count,
            "color": config["color"],
            "background_color": config["bg_color"],
            "filter_url": f"/findings?severity={row.severity}&status=open",
            "sla_filter_url": f"/findings?severity={row.severity}&status=open&sla_breach=true"
        })
    
    return {
        "severity_chips": chips,
        "total_sla_breaches": total_sla_breaches,
        "sla_breach_summary": {
            "count": total_sla_breaches,
            "filter_url": "/findings?status=open&sla_breach=true",
            "badge_text": f"SLA-breaching: {total_sla_breaches}"
        }
    }


@router.get("/organizations/{org_id}/metrics/sparklines")
async def get_metrics_sparklines(
    org_id: UUID,
    days_back: int = Query(default=7, description="Days of data for sparklines"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scopes("read:findings"))
) -> Dict[str, List[float]]:
    """Get sparkline data for key metrics."""
    
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    trend_analyzer = TrendAnalyzer(db)
    
    # Generate sparklines for key metrics
    sparklines = {}
    
    key_metrics = [
        MetricType.FINDING_COUNT,
        MetricType.MEAN_TIME_TO_REMEDIATION,
        MetricType.SLA_BREACH_COUNT
    ]
    
    for metric_type in key_metrics:
        sparkline_data = await trend_analyzer.generate_sparkline_data(
            org_id, metric_type, days_back
        )
        sparklines[metric_type.value] = sparkline_data
    
    return sparklines


@router.get("/organizations/{org_id}/analytics/trend/{card_type}")
async def get_card_sparkline(
    org_id: UUID,
    card_type: str,
    days_back: int = Query(default=7, description="Days of historical data"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scopes("read:findings"))
) -> Dict[str, Any]:
    """Get sparkline data for specific dashboard cards."""
    
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    # Map card types to metrics
    card_to_metric = {
        "findings": MetricType.FINDING_COUNT,
        "criticals": MetricType.CRITICAL_FINDING_COUNT,
        "sla_breaches": MetricType.SLA_BREACH_COUNT,
        "mttr": MetricType.MEAN_TIME_TO_REMEDIATION
    }
    
    if card_type not in card_to_metric:
        raise HTTPException(status_code=400, detail=f"Invalid card type: {card_type}")
    
    metric_type = card_to_metric[card_type]
    trend_analyzer = TrendAnalyzer(db)
    
    # Get trend analysis with sparkline
    trend = await trend_analyzer.analyze_metric_trend(org_id, metric_type, days_back)
    sparkline_data = await trend_analyzer.generate_sparkline_data(org_id, metric_type, days_back)
    
    return {
        "card_type": card_type,
        "current_value": trend.current_value,
        "change_percentage": round(trend.change_percentage, 1) if trend.change_percentage else 0,
        "trend_direction": trend.trend_direction,
        "sparkline": sparkline_data
    }


@router.get("/organizations/{org_id}/top-risks")
async def get_top_organizational_risks(
    org_id: UUID,
    limit: int = Query(default=10, description="Number of top risks to return"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scopes("read:findings"))
) -> List[Dict[str, Any]]:
    """Get top organizational risks with context and remediation guidance."""
    
    from sqlalchemy import text
    
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    # Get top risks with business context
    top_risks_query = text("""
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
    """)
    
    result = await db.execute(top_risks_query, {"org_id": org_id, "limit": limit})
    
    top_risks = []
    for i, row in enumerate(result.fetchall(), 1):
        
        # Generate business impact description
        impact_desc = f"Affects {row.affected_resources} resources"
        if row.affected_identities > 0:
            impact_desc += f" and {row.affected_identities} identities"
        
        # Generate remediation urgency
        days_since_first = (datetime.utcnow() - row.first_occurrence).days
        if row.severity == "critical" and days_since_first > 7:
            urgency = "immediate"
        elif row.severity == "high" and days_since_first > 14:
            urgency = "high"
        else:
            urgency = "normal"
        
        top_risks.append({
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
            "affected_identities": row.affected_identities
        })
    
    return top_risks


@router.get("/organizations/{org_id}/compliance-evidence")
async def get_compliance_evidence_status(
    org_id: UUID,
    framework: Optional[str] = Query(None, description="Filter by compliance framework"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scopes("read:findings"))
) -> Dict[str, Any]:
    """Get compliance evidence freshness and ownership status."""
    
    from sqlalchemy import text
    
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    # Get evidence freshness by framework
    evidence_query = text("""
        WITH evidence_freshness AS (
            SELECT 
                CASE 
                    WHEN r.cis IS NOT NULL THEN 'CIS'
                    WHEN r.nist_800_53 IS NOT NULL THEN 'NIST'
                    ELSE 'OTHER'
                END as framework,
                r.rule_id,
                r.name as control_name,
                MAX(cs.captured_at) as last_evidence_collected,
                COUNT(DISTINCT f.finding_id) as open_violations,
                EXTRACT(EPOCH FROM (NOW() - MAX(cs.captured_at))) / 86400 as evidence_age_days
            FROM rules r
            LEFT JOIN findings f ON r.rule_id = f.rule_id 
                AND f.status = 'open'
                AND f.account_id IN (SELECT account_id FROM accounts WHERE org_id = :org_id)
            LEFT JOIN config_snapshots cs ON f.resource_id = cs.resource_id
            WHERE (r.cis IS NOT NULL OR r.nist_800_53 IS NOT NULL)
            GROUP BY r.rule_id, r.name, 
                CASE 
                    WHEN r.cis IS NOT NULL THEN 'CIS'
                    WHEN r.nist_800_53 IS NOT NULL THEN 'NIST'
                    ELSE 'OTHER'
                END
        )
        SELECT 
            framework,
            COUNT(*) as total_controls,
            COUNT(CASE WHEN open_violations = 0 THEN 1 END) as compliant_controls,
            AVG(evidence_age_days) as avg_evidence_age_days,
            COUNT(CASE WHEN evidence_age_days > 30 THEN 1 END) as stale_evidence_controls
        FROM evidence_freshness
        WHERE (:framework IS NULL OR framework = :framework)
        GROUP BY framework
        ORDER BY framework
    """)
    
    result = await db.execute(evidence_query, {
        "org_id": org_id,
        "framework": framework.upper() if framework else None
    })
    
    compliance_evidence = {}
    for row in result.fetchall():
        compliance_percentage = (row.compliant_controls / row.total_controls * 100) if row.total_controls > 0 else 0
        
        compliance_evidence[row.framework] = {
            "total_controls": row.total_controls,
            "compliant_controls": row.compliant_controls,
            "compliance_percentage": round(compliance_percentage, 1),
            "avg_evidence_age_days": round(row.avg_evidence_age_days or 0, 1),
            "stale_evidence_controls": row.stale_evidence_controls,
            "evidence_freshness_status": "fresh" if (row.avg_evidence_age_days or 0) < 7 else "stale" if (row.avg_evidence_age_days or 0) > 30 else "aging"
        }
    
    return {
        "org_id": str(org_id),
        "frameworks": compliance_evidence,
        "summary": {
            "total_frameworks": len(compliance_evidence),
            "overall_compliance": round(sum(data["compliance_percentage"] for data in compliance_evidence.values()) / len(compliance_evidence), 1) if compliance_evidence else 0,
            "stale_evidence_count": sum(data["stale_evidence_controls"] for data in compliance_evidence.values())
        }
    }


@router.get("/organizations/{org_id}/analytics/evidence-freshness")
async def get_evidence_freshness_donut(
    org_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scopes("read:findings"))
) -> Dict[str, Any]:
    """Get evidence freshness donut chart data with click-through URLs."""
    
    from sqlalchemy import text
    
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    # Get evidence freshness categorization
    freshness_query = text("""
        WITH evidence_analysis AS (
            SELECT 
                r.rule_id,
                r.name as control_name,
                r.cis,
                r.nist_800_53,
                MAX(cs.captured_at) as last_evidence_collected,
                EXTRACT(EPOCH FROM (NOW() - MAX(cs.captured_at))) / 86400 as evidence_age_days
            FROM rules r
            LEFT JOIN findings f ON r.rule_id = f.rule_id 
                AND f.account_id IN (SELECT account_id FROM accounts WHERE org_id = :org_id)
            LEFT JOIN config_snapshots cs ON f.resource_id = cs.resource_id
            WHERE (r.cis IS NOT NULL OR r.nist_800_53 IS NOT NULL)
            GROUP BY r.rule_id, r.name, r.cis, r.nist_800_53
        )
        SELECT 
            CASE 
                WHEN evidence_age_days IS NULL THEN 'missing'
                WHEN evidence_age_days <= 7 THEN 'fresh'
                WHEN evidence_age_days <= 30 THEN 'aging'
                ELSE 'stale'
            END as freshness_status,
            COUNT(*) as control_count,
            ARRAY_AGG(control_name ORDER BY evidence_age_days DESC) as sample_controls
        FROM evidence_analysis
        GROUP BY 
            CASE 
                WHEN evidence_age_days IS NULL THEN 'missing'
                WHEN evidence_age_days <= 7 THEN 'fresh'
                WHEN evidence_age_days <= 30 THEN 'aging'
                ELSE 'stale'
            END
        ORDER BY 
            CASE 
                WHEN freshness_status = 'missing' THEN 1
                WHEN freshness_status = 'stale' THEN 2
                WHEN freshness_status = 'aging' THEN 3
                WHEN freshness_status = 'fresh' THEN 4
            END
    """)
    
    result = await db.execute(freshness_query, {"org_id": org_id})
    freshness_data = result.fetchall()
    
    # Donut chart configuration with colors and click-through
    freshness_config = {
        "fresh": {"color": "#22c55e", "label": "Fresh (≤7 days)", "priority": 4},
        "aging": {"color": "#f59e0b", "label": "Aging (8-30 days)", "priority": 3},
        "stale": {"color": "#ef4444", "label": "Stale (>30 days)", "priority": 2},
        "missing": {"color": "#6b7280", "label": "Missing Evidence", "priority": 1}
    }
    
    donut_segments = []
    total_controls = sum(row.control_count for row in freshness_data)
    
    for row in freshness_data:
        config = freshness_config[row.freshness_status]
        percentage = round((row.control_count / total_controls * 100), 1) if total_controls > 0 else 0
        
        donut_segments.append({
            "status": row.freshness_status,
            "label": config["label"],
            "count": row.control_count,
            "percentage": percentage,
            "color": config["color"],
            "priority": config["priority"],
            "click_through_url": f"/compliance/controls?evidence_freshness={row.freshness_status}",
            "sample_controls": row.sample_controls[:5] if row.sample_controls else []
        })
    
    # Sort by priority (most critical first)
    donut_segments.sort(key=lambda x: x["priority"])
    
    return {
        "org_id": str(org_id),
        "donut_data": {
            "segments": donut_segments,
            "total_controls": total_controls,
            "center_metric": {
                "value": total_controls,
                "label": "Total Controls",
                "subtitle": f"{sum(s['count'] for s in donut_segments if s['status'] in ['fresh', 'aging'])} monitored"
            }
        },
        "summary_stats": {
            "fresh_percentage": next((s["percentage"] for s in donut_segments if s["status"] == "fresh"), 0),
            "needs_attention": sum(s["count"] for s in donut_segments if s["status"] in ["stale", "missing"]),
            "most_critical": donut_segments[0]["status"] if donut_segments else "fresh"
        },
        "quick_actions": [
            f"Fix {sum(s['count'] for s in donut_segments if s['status'] == 'missing')} missing evidence collectors" if any(s['status'] == 'missing' for s in donut_segments) else None,
            f"Refresh {sum(s['count'] for s in donut_segments if s['status'] == 'stale')} stale evidence sources" if any(s['status'] == 'stale' for s in donut_segments) else None
        ]
    }


@router.get("/heartbeat")
async def get_heartbeat_chips(
    current_user: User = Depends(require_scopes("read:findings"))
) -> Dict[str, Any]:
    """Get Celery heartbeat status chips for dashboard monitoring."""
    
    from cerebro.tasks.celery_app import celery_app
    from datetime import datetime, timezone, timedelta
    import asyncio
    
    def get_worker_status():
        try:
            inspect = celery_app.control.inspect()
            
            # Get worker information
            active_tasks = inspect.active() or {}
            reserved_tasks = inspect.reserved() or {}
            worker_stats = inspect.stats() or {}
            registered_tasks = inspect.registered() or {}
            
            workers = []
            total_active = 0
            total_reserved = 0
            
            for worker_name in worker_stats:
                stats = worker_stats[worker_name]
                active_count = len(active_tasks.get(worker_name, []))
                reserved_count = len(reserved_tasks.get(worker_name, []))
                
                total_active += active_count
                total_reserved += reserved_count
                
                # Determine worker health
                health_status = "healthy"
                if 'rusage' not in stats:
                    health_status = "degraded"
                
                workers.append({
                    "name": worker_name.split('@')[0],  # Clean worker name
                    "host": worker_name.split('@')[1] if '@' in worker_name else "localhost",
                    "status": health_status,
                    "active_tasks": active_count,
                    "reserved_tasks": reserved_count,
                    "total_completed": stats.get('total', 0),
                    "registered_tasks": len(registered_tasks.get(worker_name, []))
                })
            
            return {
                "workers": workers,
                "summary": {
                    "total_workers": len(workers),
                    "healthy_workers": sum(1 for w in workers if w["status"] == "healthy"),
                    "total_active_tasks": total_active,
                    "total_reserved_tasks": total_reserved,
                    "total_queue_depth": total_active + total_reserved
                }
            }
            
        except Exception as e:
            return {
                "workers": [],
                "summary": {
                    "total_workers": 0,
                    "healthy_workers": 0,
                    "total_active_tasks": 0,
                    "total_reserved_tasks": 0,
                    "total_queue_depth": 0
                },
                "error": str(e)
            }
    
    # Run in executor to avoid blocking
    loop = asyncio.get_event_loop()
    celery_status = await loop.run_in_executor(None, get_worker_status)
    
    # Generate heartbeat chips
    now = datetime.now(timezone.utc)
    summary = celery_status["summary"]
    
    # Overall system status
    if summary["healthy_workers"] == 0:
        system_status = "critical"
        status_color = "#dc2626"
        status_message = "No workers available"
    elif summary["healthy_workers"] < summary["total_workers"]:
        system_status = "warning" 
        status_color = "#ea580c"
        status_message = f"{summary['healthy_workers']}/{summary['total_workers']} workers healthy"
    else:
        system_status = "healthy"
        status_color = "#22c55e"
        status_message = f"All {summary['total_workers']} workers healthy"
    
    # Queue depth assessment
    queue_depth = summary["total_queue_depth"]
    if queue_depth > 100:
        queue_status = "high"
        queue_color = "#dc2626"
    elif queue_depth > 20:
        queue_status = "medium"
        queue_color = "#ea580c"
    else:
        queue_status = "low"
        queue_color = "#22c55e"
    
    heartbeat_chips = [
        {
            "type": "workers",
            "label": "Workers",
            "value": f"{summary['healthy_workers']}/{summary['total_workers']}",
            "status": system_status,
            "color": status_color,
            "message": status_message,
            "click_through_url": "/admin/workers",
            "last_updated": now.isoformat()
        },
        {
            "type": "queue_depth", 
            "label": "Queue Depth",
            "value": str(queue_depth),
            "status": queue_status,
            "color": queue_color,
            "message": f"{queue_depth} tasks pending",
            "click_through_url": "/admin/tasks",
            "last_updated": now.isoformat()
        },
        {
            "type": "active_tasks",
            "label": "Active",
            "value": str(summary["total_active_tasks"]),
            "status": "info",
            "color": "#3b82f6",
            "message": f"{summary['total_active_tasks']} running tasks",
            "click_through_url": "/admin/tasks?status=active",
            "last_updated": now.isoformat()
        }
    ]
    
    return {
        "heartbeat_chips": heartbeat_chips,
        "system_health": {
            "overall_status": system_status,
            "last_check": now.isoformat(),
            "workers_online": summary["healthy_workers"],
            "total_workers": summary["total_workers"],
            "queue_backlog": queue_depth > 20
        },
        "worker_details": celery_status["workers"],
        "error": celery_status.get("error")
    }
