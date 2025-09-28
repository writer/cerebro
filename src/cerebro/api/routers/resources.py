"""Resource management endpoints."""

from typing import List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, desc

from cerebro.core.database import get_db
from cerebro.core.models import Resource, ConfigSnapshot
from cerebro.api.schemas import ResourceResponse, ConfigSnapshotResponse

router = APIRouter()


@router.get("/", response_model=List[ResourceResponse])
async def list_resources(
    account_id: Optional[UUID] = None,
    provider: Optional[str] = None,
    resource_type: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db)
):
    """List resources."""
    stmt = select(Resource)
    
    if account_id:
        stmt = stmt.where(Resource.account_id == account_id)
    if provider:
        stmt = stmt.where(Resource.provider == provider)
    if resource_type:
        stmt = stmt.where(Resource.resource_type == resource_type)
    
    stmt = stmt.order_by(Resource.created_at.desc()).offset(skip).limit(limit)
    resources = await db.scalars(stmt)
    return list(resources)


@router.get("/{resource_id}", response_model=ResourceResponse)
async def get_resource(
    resource_id: UUID,
    db: AsyncSession = Depends(get_db)
):
    """Get resource by ID."""
    resource = await db.get(Resource, resource_id)
    if not resource:
        raise HTTPException(status_code=404, detail="Resource not found")
    return resource


@router.get("/{resource_id}/configurations", response_model=List[ConfigSnapshotResponse])
async def get_resource_configurations(
    resource_id: UUID,
    limit: int = Query(default=10, description="Number of configurations to return"),
    db: AsyncSession = Depends(get_db)
):
    """Get configuration history for a resource."""
    # Verify resource exists
    resource = await db.get(Resource, resource_id)
    if not resource:
        raise HTTPException(status_code=404, detail="Resource not found")
    
    stmt = select(ConfigSnapshot).where(
        ConfigSnapshot.resource_id == resource_id
    ).order_by(desc(ConfigSnapshot.captured_at)).limit(limit)
    
    snapshots = await db.scalars(stmt)
    return list(snapshots)


@router.get("/{resource_id}/configurations/latest", response_model=ConfigSnapshotResponse)
async def get_latest_configuration(
    resource_id: UUID,
    db: AsyncSession = Depends(get_db)
):
    """Get latest configuration for a resource."""
    # Verify resource exists
    resource = await db.get(Resource, resource_id)
    if not resource:
        raise HTTPException(status_code=404, detail="Resource not found")
    
    stmt = select(ConfigSnapshot).where(
        ConfigSnapshot.resource_id == resource_id
    ).order_by(desc(ConfigSnapshot.captured_at)).limit(1)
    
    snapshot = await db.scalar(stmt)
    if not snapshot:
        raise HTTPException(status_code=404, detail="No configuration found for resource")
    
    return snapshot
