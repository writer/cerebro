"""Principal management endpoints."""

from typing import List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from cerebro.core.database import get_db
from cerebro.core.models import Principal
from cerebro.api.schemas import PrincipalResponse

router = APIRouter()


@router.get("/", response_model=List[PrincipalResponse])
async def list_principals(
    account_id: Optional[UUID] = None,
    provider: Optional[str] = None,
    principal_type: Optional[str] = None,
    is_human: Optional[bool] = None,
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db)
):
    """List principals."""
    stmt = select(Principal)
    
    if account_id:
        stmt = stmt.where(Principal.account_id == account_id)
    if provider:
        stmt = stmt.where(Principal.provider == provider)
    if principal_type:
        stmt = stmt.where(Principal.principal_type == principal_type)
    if is_human is not None:
        stmt = stmt.where(Principal.is_human == is_human)
    
    stmt = stmt.offset(skip).limit(limit)
    principals = await db.scalars(stmt)
    return list(principals)


@router.get("/{principal_id}", response_model=PrincipalResponse)
async def get_principal(
    principal_id: UUID,
    db: AsyncSession = Depends(get_db)
):
    """Get principal by ID."""
    principal = await db.get(Principal, principal_id)
    if not principal:
        raise HTTPException(status_code=404, detail="Principal not found")
    return principal


@router.get("/{principal_id}/permissions")
async def get_principal_permissions(
    principal_id: UUID,
    db: AsyncSession = Depends(get_db)
):
    """Get permissions for a principal."""
    principal = await db.get(Principal, principal_id)
    if not principal:
        raise HTTPException(status_code=404, detail="Principal not found")
    
    # This would need to query IamEdge table
    # Simplified for now
    return {"principal_id": principal_id, "permissions": []}
