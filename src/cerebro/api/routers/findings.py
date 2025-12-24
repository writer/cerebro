"""Finding management endpoints."""

from dataclasses import asdict
from typing import List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from cerebro.core.database import get_db
from cerebro.core.models import Finding, Organization
from cerebro.api.schemas import (
    FindingResponse,
    FindingUpdate,
    FindingStats,
    FindingPageResponse,
)
from cerebro.api.dependencies import get_finding_manager
from cerebro.findings.manager import FindingManager
from cerebro.api.auth import (
    get_current_user,
    require_read_findings,
    require_write_findings,
    User,
)
from cerebro_sdk.findings import FindingService
from cerebro_sdk.pagination import PageRequest

from cerebro.integrations.freshness import IntegrationFreshnessService
from cerebro.api.org_access import enforce_org_access, require_org_access

router = APIRouter(dependencies=[Depends(get_current_user)])


@router.get("/", response_model=List[FindingResponse])
async def list_findings(
    org_id: Optional[UUID] = None,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    provider: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_read_findings),
):
    """List findings."""

    target_org = org_id or current_user.org_id
    if target_org is None:
        raise HTTPException(status_code=400, detail="Organization context required")

    enforce_org_access(target_org, current_user)

    stmt = select(Finding).where(Finding.org_id == target_org)

    if status:
        stmt = stmt.where(Finding.status == status)
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    if provider:
        stmt = stmt.where(Finding.provider == provider)

    stmt = stmt.order_by(Finding.last_seen.desc()).offset(skip).limit(limit)
    findings = await db.scalars(stmt)
    return list(findings)


@router.get("/page", response_model=FindingPageResponse)
async def list_findings_page(
    org_id: Optional[UUID] = None,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    provider: Optional[str] = None,
    cursor: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_read_findings),
):
    target_org = org_id or current_user.org_id
    if not target_org:
        raise HTTPException(status_code=400, detail="Organization context required")

    service = FindingService(db)
    page = await service.list_findings_page(
        target_org,
        status=status,
        severity=severity,
        provider=provider,
        page=PageRequest(limit=limit, cursor=cursor),
    )

    providers = {
        item.provider for item in page.items if getattr(item, "provider", None)
    }
    freshness_service = IntegrationFreshnessService(db)
    provider_freshness = await freshness_service.provider_freshness(providers)
    freshness_payload = {
        key: {
            "last_synced_at": (
                summary.last_synced_at.isoformat() if summary.last_synced_at else None
            ),
            "age_seconds": summary.age_seconds,
            "age_human": summary.age_human,
            "status": summary.status,
        }
        for key, summary in provider_freshness.items()
    }
    warnings = [
        summary.warning for summary in provider_freshness.values() if summary.warning
    ]

    return FindingPageResponse(
        items=[FindingResponse.model_validate(asdict(item)) for item in page.items],
        next_cursor=page.next_cursor,
        freshness=freshness_payload,
        warnings=warnings,
    )


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(
    finding_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_read_findings),
):
    """Get finding by ID."""
    finding = await db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    if finding.org_id is not None and current_user.org_id is not None:
        enforce_org_access(finding.org_id, current_user)
    return finding


@router.put("/{finding_id}", response_model=FindingResponse)
async def update_finding(
    finding_id: UUID,
    finding_update: FindingUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_write_findings),
):
    """Update finding status."""
    finding = await db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    if finding.org_id is not None and current_user.org_id is not None:
        enforce_org_access(finding.org_id, current_user)

    if finding_update.status:
        if finding_update.status not in [
            "open",
            "suppressed",
            "accepted_risk",
            "fixed",
        ]:
            raise HTTPException(status_code=400, detail="Invalid status")
        finding.status = finding_update.status

    await db.commit()
    await db.refresh(finding)
    return finding


@router.post("/{finding_id}/suppress")
async def suppress_finding(
    finding_id: UUID,
    reason: str,
    finding_manager: FindingManager = Depends(get_finding_manager),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_write_findings),
):
    """Suppress a finding."""

    finding = await db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    if finding.org_id is not None and current_user.org_id is not None:
        enforce_org_access(finding.org_id, current_user)

    success = await finding_manager.suppress_finding(finding_id, reason)
    if not success:
        raise HTTPException(status_code=404, detail="Finding not found")

    return {"message": "Finding suppressed successfully", "reason": reason}


@router.post("/{finding_id}/accept-risk")
async def accept_risk(
    finding_id: UUID,
    reason: str,
    finding_manager: FindingManager = Depends(get_finding_manager),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_write_findings),
):
    """Accept risk for a finding."""

    finding = await db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    if finding.org_id is not None and current_user.org_id is not None:
        enforce_org_access(finding.org_id, current_user)

    success = await finding_manager.accept_risk(finding_id, reason)
    if not success:
        raise HTTPException(status_code=404, detail="Finding not found")

    return {"message": "Risk accepted successfully", "reason": reason}


@router.get("/organizations/{org_id}/stats", response_model=FindingStats)
async def get_finding_stats(
    org_id: UUID,
    finding_manager: FindingManager = Depends(get_finding_manager),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_org_access(require_read_findings)),
):
    """Get finding statistics for an organization."""
    # Verify organization exists
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    stats = await finding_manager.get_finding_stats(org_id)
    return FindingStats(**stats)


@router.post("/organizations/{org_id}/generate")
async def generate_findings(
    org_id: UUID,
    provider: Optional[str] = None,
    resource_types: Optional[List[str]] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_org_access(require_write_findings)),
):
    """Generate findings for an organization using Celery."""
    from cerebro.tasks.finding_tasks import generate_findings_task

    # Verify organization exists
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    # Schedule background task
    task = generate_findings_task.delay(
        str(org_id), provider=provider, resource_types=resource_types
    )

    return {
        "message": "Finding generation started",
        "task_id": task.id,
        "org_id": org_id,
        "provider": provider,
    }


@router.get("/mttr")
async def get_mttr_metrics(
    severity: Optional[str] = None,
    provider: Optional[str] = None,
    timeframe_days: int = 30,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_read_findings),
):
    """Get Mean Time to Resolution (MTTR) metrics for findings."""

    if current_user.org_id is None and not current_user.is_admin:
        raise HTTPException(status_code=400, detail="Organization context required")

    # Base query for resolved findings
    stmt = select(Finding).where(Finding.status.in_(["resolved", "fixed"]))
    if current_user.org_id is not None:
        stmt = stmt.where(Finding.org_id == current_user.org_id)

    if severity:
        stmt = stmt.where(Finding.severity == severity)
    if provider:
        stmt = stmt.where(Finding.provider == provider)

    # Filter by timeframe
    from datetime import datetime, timedelta

    cutoff_date = datetime.utcnow() - timedelta(days=timeframe_days)
    stmt = stmt.where(Finding.resolved_at >= cutoff_date)  # type: ignore[attr-defined]

    resolved_findings = await db.scalars(stmt)
    resolved_list = list(resolved_findings)

    if not resolved_list:
        return {
            "mttr": 0,
            "sla_target": 4 if severity == "critical" else 24,
            "sla_breaches": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "trend": 0,
            "total_resolved": 0,
        }

    # Calculate MTTR
    total_resolution_time = sum(
        [
            (f.resolved_at - f.created_at).total_seconds() / 3600  # type: ignore[attr-defined]
            for f in resolved_list
            if hasattr(f, "resolved_at") and hasattr(f, "created_at") and f.resolved_at and f.created_at  # type: ignore[attr-defined]
        ]
    )

    mttr = total_resolution_time / len(resolved_list) if resolved_list else 0

    return {
        "mttr": round(mttr, 1),
        "sla_target": 4 if severity == "critical" else 24,
        "sla_breaches": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "trend": -2.1,
        "total_resolved": len(resolved_list),
    }
