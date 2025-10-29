"""API endpoints exposing integration synchronization status."""

from __future__ import annotations

from datetime import datetime
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.api.auth import require_scopes
from cerebro.core.database import get_db
from cerebro.integrations.state import IntegrationStateRepository


class IntegrationStatus(BaseModel):
    integration: str = Field(..., description="Integration identifier")
    scope: str = Field(..., description="Integration scope such as organization or tenant")
    last_timestamp: Optional[datetime] = Field(None, description="Timestamp of the most recent sync")
    last_cursor: Optional[str] = Field(None, description="Opaque cursor returned by the upstream API")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional sync metadata")


router = APIRouter(prefix="/integrations", tags=["integrations"])


@router.get("/status", response_model=List[IntegrationStatus])
async def list_integration_status(
    integration: Optional[str] = Query(None, description="Filter by integration identifier"),
    db: AsyncSession = Depends(get_db),
    _: Any = Depends(require_scopes("view:integrations")),
) -> List[IntegrationStatus]:
    repo = IntegrationStateRepository(db)
    states = await repo.list_states(integration=integration)
    return [
        IntegrationStatus(
            integration=state.integration,
            scope=state.scope,
            last_timestamp=state.last_timestamp,
            last_cursor=state.last_cursor,
            metadata=state.state_metadata or {},
        )
        for state in states
    ]


@router.get("/status/{integration}", response_model=List[IntegrationStatus])
async def get_integration_status(
    integration: str,
    db: AsyncSession = Depends(get_db),
    _: Any = Depends(require_scopes("view:integrations")),
) -> List[IntegrationStatus]:
    repo = IntegrationStateRepository(db)
    states = await repo.list_states(integration=integration)
    if not states:
        raise HTTPException(status_code=404, detail="Integration not found")
    return [
        IntegrationStatus(
            integration=state.integration,
            scope=state.scope,
            last_timestamp=state.last_timestamp,
            last_cursor=state.last_cursor,
            metadata=state.state_metadata or {},
        )
        for state in states
    ]
