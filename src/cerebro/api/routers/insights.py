"""Unified insights and analysis endpoints for Cerebro.

Consolidates advanced analysis, analytics, and dashboard functionality
under a single coherent API structure.
"""

from typing import Dict, List, Any, Optional
from uuid import UUID
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
import logging

from cerebro.core.database import get_db
from cerebro.core.models import Organization, Principal
from cerebro.api.auth import get_current_user, require_scopes, require_read_findings, User
from cerebro.api.utils import get_entity_by_id_or_404, StandardResponses

# Advanced Analysis Imports
from cerebro.analysis.blast_radius import BlastRadiusAnalyzer
from cerebro.analysis.forensic_replay import ForensicReplayEngine
from cerebro.analysis.change_replay import ChangeReplayEngine
from cerebro.compliance.generator import ComplianceEvidenceGenerator
from cerebro.compliance.frameworks import list_frameworks, get_framework
from cerebro.rules.engine import rule_engine

# Analytics Imports
from cerebro.analytics.dashboard_analytics import DashboardAnalytics
from cerebro.analytics.time_series import TrendAnalyzer, MetricType
from cerebro.analytics.risk_scoring import RiskScoringEngine
from cerebro.analytics.identity_analytics import IdentityAnalyzer, PrivilegeSprawlDetector

router = APIRouter(prefix="/insights", dependencies=[Depends(get_current_user)])
logger = logging.getLogger(__name__)


# Pydantic Models for Request/Response
class BlastRadiusRequest(BaseModel):
    """Request model for blast radius analysis."""
    principal_id: UUID
    scenario_type: str = "credential_theft"
    at_time: Optional[datetime] = None


class ForensicReplayRequest(BaseModel):
    """Request model for forensic replay analysis."""
    target_time: datetime
    scope: Optional[dict] = None


class ChangeReplayRequest(BaseModel):
    """Request model for change replay analysis."""
    rule_expression: str
    start_time: datetime
    end_time: datetime
    providers: Optional[List[str]] = None


class IdentityAnomalyRequest(BaseModel):
    """Request model for identity anomaly detection."""
    org_id: UUID
    principal_id: Optional[UUID] = None
    lookback_days: int = 30


# === DASHBOARD & OVERVIEW ENDPOINTS ===

@router.get("/organizations/{org_id}/dashboard", summary="Organization Dashboard")
async def get_organization_insights_dashboard(
    org_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scopes("read:findings"))
) -> Dict[str, Any]:
    """Get comprehensive insights dashboard for an organization."""
    org = await get_entity_by_id_or_404(db, Organization, org_id, "Organization not found")

    dashboard_analytics = DashboardAnalytics(db)
    dashboard_data = await dashboard_analytics.generate_comprehensive_dashboard(org_id)

    return dashboard_data


@router.get("/organizations/{org_id}/executive-summary", summary="Executive Summary")
async def get_executive_insights_summary(
    org_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scopes("read:findings"))
) -> Dict[str, Any]:
    """Get executive-level security insights summary."""
    org = await get_entity_by_id_or_404(db, Organization, org_id, "Organization not found")

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


# === RISK ANALYSIS ENDPOINTS ===

@router.get("/organizations/{org_id}/risk-analysis", summary="Comprehensive Risk Analysis")
async def get_comprehensive_risk_analysis(
    org_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scopes("read:findings"))
) -> Dict[str, Any]:
    """Get comprehensive organizational risk analysis."""
    org = await get_entity_by_id_or_404(db, Organization, org_id, "Organization not found")

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


@router.get("/organizations/{org_id}/risk-heatmap", summary="Risk Heatmap")
async def get_risk_heatmap(
    org_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scopes("read:findings"))
) -> Dict[str, Any]:
    """Get risk heatmap data for visualization."""
    org = await get_entity_by_id_or_404(db, Organization, org_id, "Organization not found")

    risk_engine = RiskScoringEngine(db)
    heatmap = await risk_engine.generate_risk_heatmap(org_id)

    return {
        "org_id": str(heatmap.org_id),
        "heatmap_data": heatmap.heatmap_data,
        "high_risk_areas": heatmap.high_risk_areas,
        "improvement_opportunities": heatmap.improvement_opportunities
    }


# === IDENTITY INSIGHTS ENDPOINTS ===

@router.get("/organizations/{org_id}/identity-insights", summary="Identity Insights")
async def get_identity_insights(
    org_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scopes("read:principals"))
) -> Dict[str, Any]:
    """Get comprehensive identity-centric insights."""
    org = await get_entity_by_id_or_404(db, Organization, org_id, "Organization not found")

    identity_analyzer = IdentityAnalyzer(db)
    identity_data = await identity_analyzer.generate_identity_dashboard_data(org_id)

    return identity_data


@router.get("/organizations/{org_id}/risky-identities", summary="High-Risk Identities")
async def get_risky_identities(
    org_id: UUID,
    limit: int = Query(default=20, description="Maximum number of risky identities to return"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scopes("read:principals"))
) -> List[Dict[str, Any]]:
    """Get identities with highest risk profiles."""
    org = await get_entity_by_id_or_404(db, Organization, org_id, "Organization not found")

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


@router.get("/organizations/{org_id}/privilege-sprawl", summary="Privilege Sprawl Analysis")
async def get_privilege_sprawl_analysis(
    org_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scopes("read:principals"))
) -> Dict[str, Any]:
    """Get privilege sprawl analysis for the organization."""
    org = await get_entity_by_id_or_404(db, Organization, org_id, "Organization not found")

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


# === ADVANCED ANALYSIS ENDPOINTS ===

@router.post("/organizations/{org_id}/blast-radius", summary="Blast Radius Analysis")
async def analyze_blast_radius(
    org_id: UUID,
    request: BlastRadiusRequest,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_read_findings)
):
    """Analyze blast radius for principal compromise."""
    org = await get_entity_by_id_or_404(db, Organization, org_id, "Organization not found")

    # Verify principal exists and belongs to organization
    principal = await get_entity_by_id_or_404(db, Principal, request.principal_id, "Principal not found")
    if principal.account.org_id != org_id:
        raise StandardResponses.forbidden("Principal not in specified organization")

    try:
        analyzer = BlastRadiusAnalyzer(db)
        assessment = await analyzer.analyze_principal_compromise(
            request.principal_id,
            request.scenario_type,
            request.at_time
        )

        return {
            "scenario": {
                "principal_name": assessment.scenario.principal_name,
                "principal_type": assessment.scenario.principal_type,
                "provider": assessment.scenario.provider,
                "scenario_type": assessment.scenario.scenario_type,
                "compromise_time": assessment.scenario.compromise_time.isoformat()
            },
            "impact": {
                "total_resources_at_risk": assessment.total_resources_at_risk,
                "max_sensitivity_score": assessment.max_sensitivity_score,
                "business_impact_score": assessment.business_impact_score,
                "escalation_paths_count": len(assessment.escalation_paths)
            },
            "directly_accessible": [
                {
                    "resource_external_id": r.resource_external_id,
                    "resource_type": r.resource_type,
                    "provider": r.provider,
                    "access_level": r.access_level,
                    "sensitivity_score": r.sensitivity_score,
                    "potential_actions": r.potential_actions
                }
                for r in assessment.directly_accessible[:20]  # Limit for API response
            ],
            "mitigation_recommendations": assessment.mitigation_recommendations,
            "analysis_metadata": {
                "total_escalation_paths": len(assessment.escalation_paths),
                "cross_provider_resources": len(assessment.cross_provider_impact)
            }
        }

    except Exception as e:
        logger.error(f"Blast radius analysis failed: {e}")
        raise StandardResponses.internal_error(f"Analysis failed: {str(e)}")


@router.post("/organizations/{org_id}/forensic-replay", summary="Forensic Replay")
async def forensic_replay(
    org_id: UUID,
    request: ForensicReplayRequest,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_read_findings)
):
    """Reconstruct system state at a historical point in time."""
    org = await get_entity_by_id_or_404(db, Organization, org_id, "Organization not found")

    try:
        replay_engine = ForensicReplayEngine(db)
        historical_state = await replay_engine.reconstruct_state_at_time(
            org_id, request.target_time, request.scope
        )

        return {
            "timestamp": historical_state.timestamp.isoformat(),
            "organization": historical_state.organization,
            "summary": historical_state.security_summary,
            "principals": [
                {
                    "external_id": p.external_id,
                    "display_name": p.display_name,
                    "principal_type": p.principal_type,
                    "provider": p.provider,
                    "was_active": p.was_active,
                    "permission_count": len(p.permissions),
                    "admin_permissions": len([perm for perm in p.permissions if perm["is_admin"]])
                }
                for p in historical_state.principals[:50]  # Limit for API
            ],
            "resources": [
                {
                    "external_id": r.external_id,
                    "resource_type": r.resource_type,
                    "provider": r.provider,
                    "security_score": r.security_posture["overall_score"],
                    "access_count": len(r.who_had_access),
                    "issues": r.security_posture.get("issues", [])
                }
                for r in historical_state.resources[:50]  # Limit for API
            ],
            "active_findings": historical_state.active_findings[:50]
        }

    except Exception as e:
        logger.error(f"Forensic replay failed: {e}")
        raise StandardResponses.internal_error(f"Forensic replay failed: {str(e)}")


# === TREND & METRICS ENDPOINTS ===

@router.get("/organizations/{org_id}/trends/{metric_type}", summary="Metric Trends")
async def get_metric_trends(
    org_id: UUID,
    metric_type: str,
    days_back: int = Query(default=30, description="Days of historical data"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scopes("read:findings"))
) -> Dict[str, Any]:
    """Get trend analysis for a specific metric."""
    org = await get_entity_by_id_or_404(db, Organization, org_id, "Organization not found")

    try:
        metric_enum = MetricType(metric_type)
    except ValueError:
        raise StandardResponses.bad_request(f"Invalid metric type: {metric_type}")

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


# === COMPLIANCE ENDPOINTS ===

@router.get("/compliance/frameworks", summary="List Compliance Frameworks")
async def list_compliance_frameworks(
    current_user = Depends(require_read_findings)
):
    """List all available compliance frameworks."""
    frameworks = list_frameworks()
    framework_details = []

    for framework_name in frameworks:
        framework = get_framework(framework_name)
        if framework:
            automated_controls = len([c for c in framework.controls if c.automation_level == "automated"])

            framework_details.append({
                "name": framework.name,
                "key": framework_name,
                "version": framework.version,
                "description": framework.description,
                "total_controls": len(framework.controls),
                "automated_controls": automated_controls,
                "automation_percentage": round((automated_controls / len(framework.controls)) * 100, 1)
            })

    return {
        "frameworks": framework_details,
        "total_frameworks": len(framework_details)
    }


@router.post("/organizations/{org_id}/compliance/{framework_name}/evidence", summary="Generate Compliance Evidence")
async def generate_compliance_evidence(
    org_id: UUID,
    framework_name: str,
    period_start: Optional[str] = Query(None, description="Evidence period start (ISO format)"),
    period_end: Optional[str] = Query(None, description="Evidence period end (ISO format)"),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_read_findings)
):
    """Generate compliance evidence report for an organization."""
    org = await get_entity_by_id_or_404(db, Organization, org_id, "Organization not found")

    framework = get_framework(framework_name)
    if not framework:
        raise StandardResponses.not_found(f"Framework '{framework_name}' not found")

    # Parse dates
    from dateutil.parser import parse
    try:
        start_date = parse(period_start) if period_start else datetime.now() - timedelta(days=90)
        end_date = parse(period_end) if period_end else datetime.now()
    except Exception as e:
        raise StandardResponses.bad_request(f"Invalid date format: {e}")

    try:
        generator = ComplianceEvidenceGenerator()
        report = await generator.generate_compliance_report(
            framework_name, str(org_id), start_date, end_date
        )

        return {
            "organization_id": str(org_id),
            "framework": framework_name,
            "report": report,
            "generated_at": datetime.now().isoformat()
        }

    except Exception as e:
        logger.error(f"Compliance evidence generation failed: {e}")
        raise StandardResponses.internal_error(f"Evidence generation failed: {str(e)}")


# Health and monitoring endpoint
@router.get("/health", summary="Insights Service Health")
async def insights_health():
    """Check health status of the insights service."""
    return {
        "service": "insights",
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "capabilities": [
            "dashboard_analytics",
            "risk_analysis",
            "identity_insights",
            "blast_radius_analysis",
            "forensic_replay",
            "trend_analysis",
            "compliance_evidence"
        ]
    }