"""Dashboard analytics API endpoints."""

from typing import Dict, Any, Optional, Sequence
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field

from cerebro.core.database import get_db
from cerebro.core.models import Organization
from cerebro.api.auth import get_current_user, require_scopes, User
from cerebro.analytics.dashboard_analytics import DashboardAnalytics
from cerebro.analytics.dashboard_repository import DashboardRepository
from cerebro.integrations.freshness import IntegrationFreshnessService

router = APIRouter(dependencies=[Depends(get_current_user)])


class RemediationActionUpdateRequest(BaseModel):
    note: Optional[str] = Field(None, max_length=2000)


class RemediationNoteRequest(BaseModel):
    note: str = Field(..., min_length=1, max_length=2000)


class RemediationBulkUpdateRequest(BaseModel):
    action_ids: Sequence[UUID] = Field(..., min_length=1, max_length=500)
    note: Optional[str] = Field(None, max_length=2000)


def _map_bulk_error(exc: ValueError) -> HTTPException:
    message = str(exc)
    status = 404 if "not found" in message.lower() else 400
    return HTTPException(status_code=status, detail=message)


async def _ensure_org(db: AsyncSession, org_id: UUID) -> Organization:
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    return org


async def _bulk_update_remediation_actions(
    *,
    org_id: UUID,
    status: str,
    payload: RemediationBulkUpdateRequest,
    db: AsyncSession,
    current_user: User,
) -> Dict[str, Any]:
    await _ensure_org(db, org_id)

    repository = DashboardRepository(db)
    try:
        actions = await repository.update_remediation_actions_status_bulk(
            org_id=org_id,
            action_ids=payload.action_ids,
            status=status,
            user_id=current_user.user_id,
            note=payload.note,
            user_display_name=current_user.username or current_user.email,
        )
    except ValueError as exc:
        raise _map_bulk_error(exc) from exc

    await db.commit()
    return {"updated": repository.serialize_remediation_actions(actions)}


@router.post("/organizations/{org_id}/remediation/actions/bulk/accept")
async def bulk_accept_remediation_actions(
    org_id: UUID,
    payload: RemediationBulkUpdateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scopes("write:findings")),
):
    """Accept multiple remediation actions in a single request."""

    return await _bulk_update_remediation_actions(
        org_id=org_id,
        status="accepted",
        payload=payload,
        db=db,
        current_user=current_user,
    )


@router.post("/organizations/{org_id}/remediation/actions/bulk/complete")
async def bulk_complete_remediation_actions(
    org_id: UUID,
    payload: RemediationBulkUpdateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scopes("write:findings")),
):
    """Complete multiple remediation actions in a single request."""

    return await _bulk_update_remediation_actions(
        org_id=org_id,
        status="completed",
        payload=payload,
        db=db,
        current_user=current_user,
    )


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

    providers: set[str] = set()
    provider_breakdown = (
        dashboard_data.get("security_metrics", {}).get("provider_breakdown")
        if isinstance(dashboard_data, dict)
        else None
    )
    if isinstance(provider_breakdown, list):
        for entry in provider_breakdown:
            if isinstance(entry, dict):
                value = entry.get("provider") or entry.get("name")
                if isinstance(value, str):
                    providers.add(value)

    integration_coverage = dashboard_data.get("integration_coverage") if isinstance(dashboard_data, dict) else None
    if isinstance(integration_coverage, list):
        for entry in integration_coverage:
            if isinstance(entry, dict):
                for provider in entry.get("providers", []) or []:
                    if isinstance(provider, str):
                        providers.add(provider)

    freshness_service = IntegrationFreshnessService(db)
    freshness_map = await freshness_service.provider_freshness(providers)
    freshness_payload = {
        provider: {
            "last_synced_at": summary.last_synced_at.isoformat() if summary.last_synced_at else None,
            "age_seconds": summary.age_seconds,
            "age_human": summary.age_human,
            "status": summary.status,
            "sources": summary.sources,
        }
        for provider, summary in freshness_map.items()
    }
    warnings = [summary.warning for summary in freshness_map.values() if summary.warning]

    if isinstance(dashboard_data, dict):
        dashboard_data.setdefault("metadata", {})
        metadata = dashboard_data["metadata"]
        if isinstance(metadata, dict):
            metadata["data_freshness"] = {
                "providers": freshness_payload,
                "warnings": warnings,
            }
            freshest = [summary.last_synced_at for summary in freshness_map.values() if summary.last_synced_at]
            if freshest:
                metadata["data_as_of"] = max(freshest).isoformat()
        dashboard_data["freshness"] = freshness_payload
        dashboard_data["freshness_warnings"] = warnings

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


@router.get("/organizations/{org_id}/providers/{provider}/findings")
async def get_provider_findings(
    org_id: UUID,
    provider: str,
    limit: int = Query(25, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scopes("read:findings")),
):
    """List detailed findings for a specific provider."""

    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    repository = DashboardRepository(db)
    findings = await repository.get_findings_by_provider(org_id, provider, limit=limit)

    return {
        "provider": provider,
        "findings": findings,
    }


@router.post("/organizations/{org_id}/remediation/actions/{action_id}/accept")
async def accept_remediation_action(
    org_id: UUID,
    action_id: UUID,
    payload: RemediationActionUpdateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scopes("write:findings")),
):
    """Accept a remediation action and optionally append a note."""

    await _ensure_org(db, org_id)

    repository = DashboardRepository(db)
    try:
        action = await repository.update_remediation_action_status(
            org_id=org_id,
            action_id=action_id,
            status="accepted",
            user_id=current_user.user_id,
            note=payload.note,
            user_display_name=current_user.username or current_user.email,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    await db.commit()
    return repository.serialize_remediation_action(action)


@router.post("/organizations/{org_id}/remediation/actions/{action_id}/complete")
async def complete_remediation_action(
    org_id: UUID,
    action_id: UUID,
    payload: RemediationActionUpdateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scopes("write:findings")),
):
    """Mark a remediation action as completed."""

    await _ensure_org(db, org_id)

    repository = DashboardRepository(db)
    try:
        action = await repository.update_remediation_action_status(
            org_id=org_id,
            action_id=action_id,
            status="completed",
            user_id=current_user.user_id,
            note=payload.note,
            user_display_name=current_user.username or current_user.email,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    await db.commit()
    return repository.serialize_remediation_action(action)


@router.post("/organizations/{org_id}/remediation/actions/{action_id}/notes")
async def add_remediation_note(
    org_id: UUID,
    action_id: UUID,
    payload: RemediationNoteRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scopes("write:findings")),
):
    """Append a note to a remediation action."""

    await _ensure_org(db, org_id)

    repository = DashboardRepository(db)
    try:
        action = await repository.add_remediation_note(
            org_id=org_id,
            action_id=action_id,
            user_id=current_user.user_id,
            note=payload.note,
            user_display_name=current_user.username or current_user.email,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    await db.commit()
    return repository.serialize_remediation_action(action)

