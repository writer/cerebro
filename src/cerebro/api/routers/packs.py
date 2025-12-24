"""API endpoints for artifact pack management."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.api.auth import require_scopes
from cerebro.core.database import get_db
from cerebro.telemetry.pack_service import PackManagementService
from cerebro.telemetry.schemas import (
    ArtifactPackCreate,
    ArtifactPackDefinition,
    ArtifactPackUpdate,
)

router = APIRouter(prefix="/packs", tags=["packs"])


@router.get("/", response_model=list[ArtifactPackDefinition])
async def list_packs(
    org_id: UUID | None = Query(None, description="Filter packs by organization id"),
    db: AsyncSession = Depends(get_db),
    _: Any = Depends(require_scopes("manage:packs")),
):
    service = PackManagementService(db)
    return await service.list_packs(org_id=org_id)


@router.post("/", response_model=ArtifactPackDefinition, status_code=201)
async def create_pack(
    payload: ArtifactPackCreate,
    org_name: str | None = Query(
        None, description="Organization name for new pack ownership"
    ),
    db: AsyncSession = Depends(get_db),
    _: Any = Depends(require_scopes("manage:packs")),
):
    try:
        service = PackManagementService(db)
        return await service.create_pack(payload, org_name=org_name)
    except ValueError as exc:  # pragma: no cover
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/{pack_id}", response_model=ArtifactPackDefinition)
async def get_pack(
    pack_id: UUID,
    db: AsyncSession = Depends(get_db),
    _: Any = Depends(require_scopes("manage:packs")),
):
    try:
        service = PackManagementService(db)
        return await service.get_pack(pack_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.patch("/{pack_id}", response_model=ArtifactPackDefinition)
async def update_pack(
    pack_id: UUID,
    payload: ArtifactPackUpdate,
    db: AsyncSession = Depends(get_db),
    _: Any = Depends(require_scopes("manage:packs")),
):
    try:
        service = PackManagementService(db)
        return await service.update_pack(pack_id, payload)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.delete("/{pack_id}", status_code=204)
async def delete_pack(
    pack_id: UUID,
    db: AsyncSession = Depends(get_db),
    _: Any = Depends(require_scopes("manage:packs")),
):
    service = PackManagementService(db)
    await service.delete_pack(pack_id)
