"""Organization management endpoints."""

from typing import List
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from cerebro.core.database import get_db
from cerebro.core.models import Organization
from cerebro.api.schemas import OrganizationCreate, OrganizationResponse
from cerebro.api.auth import get_current_user, require_scopes, User

router = APIRouter(dependencies=[Depends(get_current_user)])


@router.post("/", response_model=OrganizationResponse)
async def create_organization(
    org: OrganizationCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scopes("admin")),
):
    """Create a new organization."""
    db_org = Organization(name=org.name)
    db.add(db_org)
    await db.commit()
    await db.refresh(db_org)
    return db_org


@router.get("/", response_model=List[OrganizationResponse])
async def list_organizations(
    skip: int = 0, limit: int = 100, db: AsyncSession = Depends(get_db)
):
    """List organizations."""
    stmt = select(Organization).offset(skip).limit(limit)
    orgs = await db.scalars(stmt)
    return list(orgs)


@router.get("/{org_id}", response_model=OrganizationResponse)
async def get_organization(org_id: UUID, db: AsyncSession = Depends(get_db)):
    """Get organization by ID."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    return org


@router.delete("/{org_id}")
async def delete_organization(
    org_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scopes("admin")),
):
    """Delete an organization."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    await db.delete(org)
    await db.commit()
    return {"message": "Organization deleted successfully"}
