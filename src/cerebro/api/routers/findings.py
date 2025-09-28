"""Finding management endpoints."""

from typing import List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from cerebro.core.database import get_db
from cerebro.core.models import Finding, Organization
from cerebro.api.schemas import FindingResponse, FindingUpdate, FindingStats
from cerebro.api.dependencies import get_finding_manager
from cerebro.findings.manager import FindingManager

router = APIRouter()


@router.get("/", response_model=List[FindingResponse])
async def list_findings(
    org_id: Optional[UUID] = None,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    provider: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db)
):
    """List findings."""
    stmt = select(Finding)
    
    if org_id:
        stmt = stmt.where(Finding.org_id == org_id)
    if status:
        stmt = stmt.where(Finding.status == status)
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    if provider:
        stmt = stmt.where(Finding.provider == provider)
    
    stmt = stmt.order_by(Finding.last_seen.desc()).offset(skip).limit(limit)
    findings = await db.scalars(stmt)
    return list(findings)


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(
    finding_id: UUID,
    db: AsyncSession = Depends(get_db)
):
    """Get finding by ID."""
    finding = await db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.put("/{finding_id}", response_model=FindingResponse)
async def update_finding(
    finding_id: UUID,
    finding_update: FindingUpdate,
    db: AsyncSession = Depends(get_db)
):
    """Update finding status."""
    finding = await db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    if finding_update.status:
        if finding_update.status not in ["open", "suppressed", "accepted_risk", "fixed"]:
            raise HTTPException(status_code=400, detail="Invalid status")
        finding.status = finding_update.status
    
    await db.commit()
    await db.refresh(finding)
    return finding


@router.post("/{finding_id}/suppress")
async def suppress_finding(
    finding_id: UUID,
    reason: str,
    finding_manager: FindingManager = Depends(get_finding_manager)
):
    """Suppress a finding."""
    success = await finding_manager.suppress_finding(finding_id, reason)
    if not success:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    return {"message": "Finding suppressed successfully", "reason": reason}


@router.post("/{finding_id}/accept-risk")
async def accept_risk(
    finding_id: UUID,
    reason: str,
    finding_manager: FindingManager = Depends(get_finding_manager)
):
    """Accept risk for a finding."""
    success = await finding_manager.accept_risk(finding_id, reason)
    if not success:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    return {"message": "Risk accepted successfully", "reason": reason}


@router.get("/organizations/{org_id}/stats", response_model=FindingStats)
async def get_finding_stats(
    org_id: UUID,
    finding_manager: FindingManager = Depends(get_finding_manager),
    db: AsyncSession = Depends(get_db)
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
    db: AsyncSession = Depends(get_db)
):
    """Generate findings for an organization using Celery."""
    from cerebro.tasks.finding_tasks import generate_findings_task
    
    # Verify organization exists
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    # Schedule background task
    task = generate_findings_task.delay(
        str(org_id),
        provider=provider,
        resource_types=resource_types
    )
    
    return {
        "message": "Finding generation started",
        "task_id": task.id,
        "org_id": org_id,
        "provider": provider
    }
