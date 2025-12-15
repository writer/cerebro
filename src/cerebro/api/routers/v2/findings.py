"""Findings management endpoints using DynamoDB.

This is the DynamoDB version of the findings API.
"""

from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from cerebro.api.dynamodb_dependencies import finding_repository
from cerebro.core.repositories.finding import (
    Finding,
    FindingRepository,
    FindingStatus,
    Severity,
)


# Request/Response schemas

class FindingCreate(BaseModel):
    """Request schema for creating a finding."""
    org_id: UUID
    account_id: UUID
    provider: str
    rule_id: UUID
    rule_version: int = 1
    resource_id: Optional[UUID] = None
    principal_id: Optional[UUID] = None
    severity: str = Field(..., pattern="^(critical|high|medium|low|info)$")
    fingerprint: str
    title: str
    summary: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None


class FindingUpdate(BaseModel):
    """Request schema for updating a finding."""
    status: Optional[str] = Field(None, pattern="^(open|suppressed|accepted_risk|fixed)$")
    severity: Optional[str] = Field(None, pattern="^(critical|high|medium|low|info)$")
    summary: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None


class FindingResponse(BaseModel):
    """Response schema for finding."""
    finding_id: UUID
    org_id: UUID
    account_id: UUID
    provider: str
    rule_id: UUID
    rule_version: int
    resource_id: Optional[UUID] = None
    principal_id: Optional[UUID] = None
    first_seen: str
    last_seen: str
    status: str
    severity: str
    fingerprint: str
    title: str
    summary: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None

    class Config:
        from_attributes = True

    @classmethod
    def from_entity(cls, finding: Finding) -> "FindingResponse":
        return cls(
            finding_id=finding.finding_id,
            org_id=finding.org_id,
            account_id=finding.account_id,
            provider=finding.provider,
            rule_id=finding.rule_id,
            rule_version=finding.rule_version,
            resource_id=finding.resource_id,
            principal_id=finding.principal_id,
            first_seen=finding.first_seen.isoformat(),
            last_seen=finding.last_seen.isoformat(),
            status=finding.status.value if hasattr(finding.status, 'value') else finding.status,
            severity=finding.severity.value if hasattr(finding.severity, 'value') else finding.severity,
            fingerprint=finding.fingerprint,
            title=finding.title,
            summary=finding.summary,
            evidence=finding.evidence,
        )


class FindingStats(BaseModel):
    """Statistics about findings."""
    total: int
    by_status: Dict[str, int]
    by_severity: Dict[str, int]


# Router

router = APIRouter(prefix="/findings", tags=["findings"])


@router.post("/", response_model=FindingResponse, status_code=201)
async def create_finding(
    data: FindingCreate,
    repo: FindingRepository = Depends(finding_repository),
) -> FindingResponse:
    """Create a new finding."""
    finding = Finding(
        org_id=data.org_id,
        account_id=data.account_id,
        provider=data.provider,
        rule_id=data.rule_id,
        rule_version=data.rule_version,
        resource_id=data.resource_id,
        principal_id=data.principal_id,
        severity=Severity(data.severity),
        fingerprint=data.fingerprint,
        title=data.title,
        summary=data.summary,
        evidence=data.evidence,
    )
    created = await repo.create(finding)
    return FindingResponse.from_entity(created)


@router.get("/org/{org_id}", response_model=List[FindingResponse])
async def list_findings_by_org(
    org_id: UUID,
    status: Optional[str] = Query(None, pattern="^(open|suppressed|accepted_risk|fixed)$"),
    severity: Optional[str] = Query(None, pattern="^(critical|high|medium|low|info)$"),
    limit: int = Query(100, ge=1, le=1000),
    repo: FindingRepository = Depends(finding_repository),
) -> List[FindingResponse]:
    """List findings for an organization."""
    status_enum = FindingStatus(status) if status else None
    severity_enum = Severity(severity) if severity else None
    
    findings = await repo.list_by_org(org_id, status_enum, severity_enum, limit)
    return [FindingResponse.from_entity(f) for f in findings]


@router.get("/org/{org_id}/stats", response_model=FindingStats)
async def get_finding_stats(
    org_id: UUID,
    repo: FindingRepository = Depends(finding_repository),
) -> FindingStats:
    """Get finding statistics for an organization."""
    by_status = await repo.count_by_status(org_id)
    by_severity = await repo.count_by_severity(org_id)
    total = sum(by_status.values())
    
    return FindingStats(
        total=total,
        by_status=by_status,
        by_severity=by_severity,
    )


@router.get("/org/{org_id}/{finding_id}", response_model=FindingResponse)
async def get_finding(
    org_id: UUID,
    finding_id: UUID,
    repo: FindingRepository = Depends(finding_repository),
) -> FindingResponse:
    """Get a specific finding."""
    finding = await repo.get(finding_id, org_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return FindingResponse.from_entity(finding)


@router.patch("/org/{org_id}/{finding_id}", response_model=FindingResponse)
async def update_finding(
    org_id: UUID,
    finding_id: UUID,
    data: FindingUpdate,
    repo: FindingRepository = Depends(finding_repository),
) -> FindingResponse:
    """Update a finding."""
    updates = {}
    
    if data.status is not None:
        updates["status"] = FindingStatus(data.status)
    if data.severity is not None:
        updates["severity"] = Severity(data.severity)
    if data.summary is not None:
        updates["summary"] = data.summary
    if data.evidence is not None:
        updates["evidence"] = data.evidence
    
    if not updates:
        raise HTTPException(status_code=400, detail="No updates provided")
    
    finding = await repo.update(finding_id, org_id, **updates)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    return FindingResponse.from_entity(finding)


@router.post("/org/{org_id}/{finding_id}/suppress", response_model=FindingResponse)
async def suppress_finding(
    org_id: UUID,
    finding_id: UUID,
    repo: FindingRepository = Depends(finding_repository),
) -> FindingResponse:
    """Suppress a finding."""
    finding = await repo.update(finding_id, org_id, status=FindingStatus.SUPPRESSED)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return FindingResponse.from_entity(finding)


@router.post("/org/{org_id}/{finding_id}/accept-risk", response_model=FindingResponse)
async def accept_risk(
    org_id: UUID,
    finding_id: UUID,
    repo: FindingRepository = Depends(finding_repository),
) -> FindingResponse:
    """Accept risk for a finding."""
    finding = await repo.update(finding_id, org_id, status=FindingStatus.ACCEPTED_RISK)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return FindingResponse.from_entity(finding)


@router.post("/org/{org_id}/{finding_id}/reopen", response_model=FindingResponse)
async def reopen_finding(
    org_id: UUID,
    finding_id: UUID,
    repo: FindingRepository = Depends(finding_repository),
) -> FindingResponse:
    """Reopen a finding."""
    finding = await repo.update(finding_id, org_id, status=FindingStatus.OPEN)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return FindingResponse.from_entity(finding)


@router.delete("/org/{org_id}/{finding_id}", status_code=204)
async def delete_finding(
    org_id: UUID,
    finding_id: UUID,
    repo: FindingRepository = Depends(finding_repository),
) -> None:
    """Delete a finding."""
    finding = await repo.get(finding_id, org_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    await repo.delete(finding_id, org_id)


@router.get("/rule/{rule_id}", response_model=List[FindingResponse])
async def list_findings_by_rule(
    rule_id: UUID,
    limit: int = Query(100, ge=1, le=1000),
    repo: FindingRepository = Depends(finding_repository),
) -> List[FindingResponse]:
    """List findings for a specific rule."""
    findings = await repo.list_by_rule(rule_id, limit)
    return [FindingResponse.from_entity(f) for f in findings]
