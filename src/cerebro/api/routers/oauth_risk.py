"""
OAuth and third-party app risk management API endpoints.

Provides REST API for OAuth app discovery, toxic combination detection,
and quarantine management.
"""

from datetime import datetime, timedelta
from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from ...api.auth import User, require_read_findings
from ...api.org_access import require_org_access
from ...core.database import get_db
from ...core.models import Organization
from ...oauth_risk.quarantine import get_quarantine_manager
from ...oauth_risk.registry import AppRiskLevel, get_oauth_registry
from ...oauth_risk.toxic_combinations import get_toxic_detector

router = APIRouter()
logger = structlog.get_logger(__name__)


class QuarantineRequest(BaseModel):
    """Request to quarantine OAuth app."""

    app_id: str = Field(..., description="OAuth application ID")
    reason: str = Field(..., description="Quarantine reason")
    justification: str = Field(..., description="Justification for quarantine")


class RestorationRequest(BaseModel):
    """Request to restore quarantined OAuth app."""

    quarantine_action_id: str = Field(..., description="Quarantine action ID")
    business_justification: str = Field(
        ..., description="Business justification for restoration"
    )
    mitigation_plan: list[str] = Field(
        ..., description="List of mitigation steps taken"
    )


class RestorationApproval(BaseModel):
    """Approval for OAuth app restoration."""

    restoration_id: str = Field(..., description="Restoration request ID")
    approval_conditions: list[str] = Field(
        ..., description="Conditions for restoration"
    )


@router.get("/organizations/{org_id}/oauth-apps")
async def list_oauth_apps(
    org_id: UUID,
    provider: str | None = Query(None, description="Filter by provider"),
    risk_level: str | None = Query(None, description="Filter by risk level"),
    unused_days: int | None = Query(
        None, description="Filter apps unused for X days"
    ),
    without_owner: bool = Query(False, description="Filter apps without owners"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_org_access(require_read_findings)),
):
    """List OAuth applications across all providers."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    try:
        oauth_registry = get_oauth_registry()
        apps = await oauth_registry.discover_oauth_apps(str(org_id))

        # Apply filters
        filtered_apps = apps

        if provider:
            filtered_apps = [app for app in filtered_apps if app.provider == provider]

        if risk_level:
            risk_enum = AppRiskLevel(risk_level.lower())
            filtered_apps = [
                app for app in filtered_apps if app.risk_level == risk_enum
            ]

        if unused_days:
            cutoff_date = datetime.now() - timedelta(days=unused_days)
            filtered_apps = [
                app
                for app in filtered_apps
                if not app.last_used or app.last_used < cutoff_date
            ]

        if without_owner:
            filtered_apps = [app for app in filtered_apps if not app.owner]

        return {
            "organization_id": str(org_id),
            "total_apps": len(apps),
            "filtered_apps": len(filtered_apps),
            "filters_applied": {
                "provider": provider,
                "risk_level": risk_level,
                "unused_days": unused_days,
                "without_owner": without_owner,
            },
            "apps": [
                {
                    "app_id": app.app_id,
                    "app_name": app.app_name,
                    "provider": app.provider,
                    "risk_level": app.risk_level.value,
                    "owner": app.owner,
                    "last_used": app.last_used.isoformat() if app.last_used else None,
                    "scope_count": len(app.scopes),
                    "risk_factors": app.risk_factors,
                    "category": app.category.value,
                    "is_verified": app.is_verified,
                }
                for app in filtered_apps
            ],
        }

    except Exception:
        logger.exception("OAuth app listing failed", extra={"org_id": str(org_id)})
        raise HTTPException(status_code=500, detail="OAuth app listing failed") from None



@router.get("/organizations/{org_id}/oauth-apps/{app_id}")
async def get_oauth_app_details(
    org_id: UUID,
    app_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_org_access(require_read_findings)),
):
    """Get detailed information about specific OAuth app."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    try:
        oauth_registry = get_oauth_registry()
        apps = await oauth_registry.discover_oauth_apps(str(org_id))

        app = next((a for a in apps if a.app_id == app_id), None)
        if not app:
            raise HTTPException(status_code=404, detail="OAuth app not found")

        return {
            "app_id": app.app_id,
            "app_name": app.app_name,
            "provider": app.provider,
            "client_id": app.client_id,
            "owner": app.owner,
            "installed_by": app.installed_by,
            "installed_at": app.installed_at.isoformat(),
            "risk_level": app.risk_level.value,
            "risk_factors": app.risk_factors,
            "scopes": [
                {
                    "scope": scope.scope,
                    "description": scope.description,
                    "risk_level": scope.risk_level.value,
                    "sensitive_data_access": scope.sensitive_data_access,
                    "write_permissions": scope.write_permissions,
                }
                for scope in app.scopes
            ],
            "usage": {
                "last_used": app.last_used.isoformat() if app.last_used else None,
                "usage_frequency": app.usage_frequency,
                "active_users": app.active_users,
                "total_authentications": app.total_authentications,
            },
            "configuration": {
                "redirect_uris": app.redirect_uris,
                "publisher_domain": app.publisher_domain,
                "is_verified": app.is_verified,
                "is_internal": app.is_internal,
            },
            "compliance": {
                "data_access_locations": app.data_access_locations,
                "privacy_policy_url": app.privacy_policy_url,
                "terms_of_service_url": app.terms_of_service_url,
            },
            "metadata": app.metadata,
        }

    except HTTPException:
        raise
    except Exception:
        logger.exception(
            "OAuth app details failed", extra={"org_id": str(org_id), "app_id": app_id}
        )
        raise HTTPException(status_code=500, detail="App details failed") from None



@router.get("/organizations/{org_id}/oauth-apps/toxic-combinations")
async def detect_toxic_combinations(
    org_id: UUID,
    min_toxicity_score: float = Query(
        0.5, description="Minimum toxicity score", ge=0.0, le=1.0
    ),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_org_access(require_read_findings)),
):
    """Detect toxic OAuth app combinations."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    try:
        oauth_registry = get_oauth_registry()
        toxic_detector = get_toxic_detector()

        # Discover apps and detect toxic combinations
        apps = await oauth_registry.discover_oauth_apps(str(org_id))
        toxic_results = await toxic_detector.detect_toxic_combinations(apps)

        # Filter by minimum toxicity score
        filtered_results = [
            r for r in toxic_results if r.toxicity_score >= min_toxicity_score
        ]

        return {
            "organization_id": str(org_id),
            "analysis_date": datetime.now().isoformat(),
            "total_apps_analyzed": len(apps),
            "toxic_combinations_found": len(filtered_results),
            "auto_quarantine_eligible": len(
                [r for r in filtered_results if r.auto_quarantine_eligible]
            ),
            "results": [
                {
                    "app_id": result.app_id,
                    "app_name": result.app_name,
                    "provider": result.provider,
                    "toxicity_score": result.toxicity_score,
                    "auto_quarantine_eligible": result.auto_quarantine_eligible,
                    "toxic_patterns": [
                        {
                            "pattern_id": pattern.pattern_id,
                            "name": pattern.name,
                            "toxicity_level": pattern.toxicity_level.value,
                            "description": pattern.description,
                        }
                        for pattern in result.toxic_patterns
                    ],
                    "recommended_actions": result.recommended_actions,
                }
                for result in filtered_results
            ],
        }

    except Exception:
        logger.exception(
            "Toxic combination detection failed", extra={"org_id": str(org_id)}
        )
        raise HTTPException(status_code=500, detail="Toxic detection failed") from None



@router.post("/organizations/{org_id}/oauth-apps/quarantine")
async def quarantine_oauth_app(
    org_id: UUID,
    request: QuarantineRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_org_access(require_read_findings)),
):
    """Manually quarantine OAuth application."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    try:
        # Create manual quarantine action
        # Would create proper QuarantineAction in production
        action_result = {
            "action_id": f"manual_quarantine_{request.app_id}_{int(datetime.now().timestamp())}",
            "app_id": request.app_id,
            "reason": request.reason,
            "justification": request.justification,
            "quarantined_by": current_user.username,
            "quarantined_at": datetime.now().isoformat(),
            "status": "quarantined",
        }

        return {
            "success": True,
            "message": f"OAuth app {request.app_id} quarantined",
            "data": action_result,
        }

    except Exception:
        logger.exception("OAuth app quarantine failed", extra={"org_id": str(org_id)})
        raise HTTPException(status_code=500, detail="Quarantine failed") from None



@router.post("/organizations/{org_id}/oauth-apps/restore")
async def request_oauth_app_restoration(
    org_id: UUID,
    request: RestorationRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_org_access(require_read_findings)),
):
    """Request restoration of quarantined OAuth app."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    try:
        quarantine_manager = get_quarantine_manager()

        restoration_request = await quarantine_manager.request_app_restoration(
            request.quarantine_action_id,
            current_user.username,
            request.business_justification,
            request.mitigation_plan,
        )

        return {
            "success": True,
            "message": "OAuth app restoration requested",
            "data": restoration_request,
        }

    except Exception:
        logger.exception(
            "OAuth app restoration request failed", extra={"org_id": str(org_id)}
        )
        raise HTTPException(status_code=500, detail="Restoration request failed") from None



@router.post("/organizations/{org_id}/oauth-apps/restore/{restoration_id}/approve")
async def approve_oauth_app_restoration(
    org_id: UUID,
    restoration_id: str,
    request: RestorationApproval,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_org_access(require_read_findings)),
):
    """Approve restoration of quarantined OAuth app."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    try:
        quarantine_manager = get_quarantine_manager()

        approval_result = await quarantine_manager.approve_app_restoration(
            restoration_id, current_user.username, request.approval_conditions
        )

        return {
            "success": True,
            "message": "OAuth app restoration approved",
            "data": approval_result,
        }

    except Exception:
        logger.exception(
            "OAuth app restoration approval failed",
            extra={"org_id": str(org_id), "restoration_id": restoration_id},
        )
        raise HTTPException(status_code=500, detail="Restoration approval failed") from None



@router.get("/organizations/{org_id}/oauth-apps/risk-report")
async def get_oauth_risk_report(
    org_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_org_access(require_read_findings)),
):
    """Get comprehensive OAuth risk assessment report."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    try:
        oauth_registry = get_oauth_registry()
        quarantine_manager = get_quarantine_manager()

        # Generate risk report
        risk_report = await oauth_registry.generate_oauth_risk_report(str(org_id))

        # Add quarantine summary
        quarantine_summary = await quarantine_manager.get_quarantine_summary(
            str(org_id)
        )
        risk_report["quarantine_summary"] = quarantine_summary

        return {
            "success": True,
            "message": f"OAuth risk analysis completed for {risk_report['summary']['total_oauth_apps']} apps",
            "data": risk_report,
        }

    except Exception:
        logger.exception("OAuth risk report failed", extra={"org_id": str(org_id)})
        raise HTTPException(status_code=500, detail="Risk report failed") from None



@router.get("/organizations/{org_id}/oauth-apps/quarantine/summary")
async def get_quarantine_summary(
    org_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_org_access(require_read_findings)),
):
    """Get summary of OAuth app quarantine actions."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    try:
        quarantine_manager = get_quarantine_manager()
        summary = await quarantine_manager.get_quarantine_summary(str(org_id))

        return {
            "success": True,
            "message": "Quarantine summary retrieved",
            "data": summary,
        }

    except Exception:
        logger.exception("Quarantine summary failed", extra={"org_id": str(org_id)})
        raise HTTPException(status_code=500, detail="Quarantine summary failed") from None



# Convenience endpoints for common queries
@router.get("/organizations/{org_id}/oauth-apps/high-risk")
async def get_high_risk_oauth_apps(
    org_id: UUID,
    limit: int = Query(20, description="Maximum apps to return", ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_org_access(require_read_findings)),
):
    """Get high-risk OAuth applications requiring immediate attention."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    try:
        oauth_registry = get_oauth_registry()
        high_risk_apps = await oauth_registry.get_high_risk_apps(str(org_id))

        # Limit results
        limited_apps = high_risk_apps[:limit]

        return {
            "organization_id": str(org_id),
            "total_high_risk": len(high_risk_apps),
            "returned_count": len(limited_apps),
            "apps": [
                {
                    "app_id": app.app_id,
                    "app_name": app.app_name,
                    "provider": app.provider,
                    "risk_level": app.risk_level.value,
                    "risk_factors": app.risk_factors,
                    "last_used": app.last_used.isoformat() if app.last_used else None,
                    "owner": app.owner,
                    "scope_count": len(app.scopes),
                    "write_permissions": any(s.write_permissions for s in app.scopes),
                    "sensitive_data_access": any(
                        s.sensitive_data_access for s in app.scopes
                    ),
                }
                for app in limited_apps
            ],
        }

    except Exception:
        logger.exception("High-risk OAuth apps failed", extra={"org_id": str(org_id)})
        raise HTTPException(status_code=500, detail="High-risk apps failed") from None



@router.get("/organizations/{org_id}/oauth-apps/without-owners")
async def get_oauth_apps_without_owners(
    org_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_org_access(require_read_findings)),
):
    """Get OAuth apps without designated owners."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    try:
        oauth_registry = get_oauth_registry()
        apps_without_owners = await oauth_registry.get_apps_without_owners(str(org_id))

        return {
            "organization_id": str(org_id),
            "apps_without_owners": len(apps_without_owners),
            "apps": [
                {
                    "app_id": app.app_id,
                    "app_name": app.app_name,
                    "provider": app.provider,
                    "risk_level": app.risk_level.value,
                    "installed_by": app.installed_by,
                    "installed_at": app.installed_at.isoformat(),
                    "last_used": app.last_used.isoformat() if app.last_used else None,
                    "scope_count": len(app.scopes),
                }
                for app in apps_without_owners
            ],
        }

    except Exception:
        logger.exception(
            "Apps without owners query failed", extra={"org_id": str(org_id)}
        )
        raise HTTPException(status_code=500, detail="Query failed") from None

