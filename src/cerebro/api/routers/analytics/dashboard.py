"""Dashboard analytics API endpoints."""

from typing import Dict, Any
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.core.database import get_db
from cerebro.core.models import Organization
from cerebro.api.auth import get_current_user, require_scopes, User
from cerebro.analytics.dashboard_analytics import DashboardAnalytics

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
        "dimension_scores": executive_summary.dimension_scores,
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