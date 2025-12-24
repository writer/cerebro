"""Resource management endpoints."""

from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.api.auth import User, get_current_user
from cerebro.api.schemas import ConfigSnapshotResponse, ResourceResponse
from cerebro.api.utils import (
    StandardFilters,
    StandardResponses,
    get_entity_by_id_or_404,
    paginated_list,
)
from cerebro.core.database import get_db
from cerebro.core.models import ConfigSnapshot, Resource

router = APIRouter(dependencies=[Depends(get_current_user)])


@router.get("/", response_model=list[ResourceResponse])
async def list_resources(
    resource_type: str | None = Query(None, description="Filter by resource type"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    filters: StandardFilters = Depends(),
):
    """List resources."""
    additional_filters = {}
    if resource_type:
        additional_filters["resource_type"] = resource_type

    return await paginated_list(
        db=db, model=Resource, filters=filters, additional_filters=additional_filters
    )


@router.get("/{resource_id}", response_model=ResourceResponse)
async def get_resource(resource_id: UUID, db: AsyncSession = Depends(get_db)):
    """Get resource by ID."""
    return await get_entity_by_id_or_404(
        db, Resource, resource_id, "Resource not found"
    )


@router.get(
    "/{resource_id}/configurations", response_model=list[ConfigSnapshotResponse]
)
async def get_resource_configurations(
    resource_id: UUID,
    limit: int = Query(default=10, description="Number of configurations to return"),
    db: AsyncSession = Depends(get_db),
):
    """Get configuration history for a resource."""
    # Verify resource exists
    await get_entity_by_id_or_404(db, Resource, resource_id, "Resource not found")

    stmt = (
        select(ConfigSnapshot)
        .where(ConfigSnapshot.resource_id == resource_id)
        .order_by(desc(ConfigSnapshot.captured_at))
        .limit(limit)
    )

    snapshots = await db.scalars(stmt)
    return list(snapshots)


@router.get(
    "/{resource_id}/configurations/latest", response_model=ConfigSnapshotResponse
)
async def get_latest_configuration(
    resource_id: UUID, db: AsyncSession = Depends(get_db)
):
    """Get latest configuration for a resource."""
    # Verify resource exists
    await get_entity_by_id_or_404(db, Resource, resource_id, "Resource not found")

    stmt = (
        select(ConfigSnapshot)
        .where(ConfigSnapshot.resource_id == resource_id)
        .order_by(desc(ConfigSnapshot.captured_at))
        .limit(1)
    )

    snapshot = await db.scalar(stmt)
    if not snapshot:
        raise StandardResponses.not_found("No configuration found for resource")

    return snapshot
