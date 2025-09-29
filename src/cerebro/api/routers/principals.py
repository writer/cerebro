"""Principal management endpoints."""

from typing import List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from cerebro.core.database import get_db
from cerebro.core.models import Principal
from cerebro.api.schemas import PrincipalResponse
from cerebro.api.auth import get_current_user, require_scopes, User

router = APIRouter(dependencies=[Depends(get_current_user)])


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
    active_only: bool = True,
    limit: int = 100,
    offset: int = 0,
    db: AsyncSession = Depends(get_db)
):
    """Get permissions for a principal."""
    from sqlalchemy import select, and_, or_, desc
    from cerebro.core.models import IamEdge, Resource
    
    principal = await db.get(Principal, principal_id)
    if not principal:
        raise HTTPException(status_code=404, detail="Principal not found")
    
    # Query IAM edges for this principal
    stmt = select(IamEdge).where(IamEdge.principal_id == principal_id)
    
    if active_only:
        # Only show currently effective permissions
        from datetime import datetime
        now = datetime.utcnow()
        stmt = stmt.where(
            and_(
                IamEdge.effective_at <= now,
                or_(
                    IamEdge.expires_at.is_(None),
                    IamEdge.expires_at > now
                )
            )
        )
    
    stmt = stmt.order_by(desc(IamEdge.effective_at)).offset(offset).limit(limit)
    
    iam_edges = await db.scalars(stmt)
    
    permissions = []
    for edge in iam_edges:
        # Get resource details if applicable
        resource_info = None
        if edge.resource_id:
            resource = await db.get(Resource, edge.resource_id)
            if resource:
                resource_info = {
                    "resource_id": str(resource.resource_id),
                    "external_id": resource.external_id,
                    "name": resource.name,
                    "resource_type": resource.resource_type
                }
        
        permissions.append({
            "edge_id": str(edge.edge_id),
            "permission": edge.permission,
            "via": edge.via,
            "effective_at": edge.effective_at.isoformat(),
            "expires_at": edge.expires_at.isoformat() if edge.expires_at else None,
            "is_admin": edge.is_admin,
            "resource": resource_info
        })
    
    return {
        "principal_id": principal_id,
        "principal_info": {
            "external_id": principal.external_id,
            "display_name": principal.display_name,
            "email": principal.email,
            "principal_type": principal.principal_type,
            "provider": principal.provider
        },
        "permissions": permissions,
        "total_permissions": len(permissions),
        "active_only": active_only
    }
