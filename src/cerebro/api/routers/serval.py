"""Serval integration configuration endpoints."""

from __future__ import annotations

from typing import Any, Dict, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.api.auth import require_scopes
from cerebro.core.database import get_db
from cerebro.integrations.serval_service import (
    ServalIntegrationRepository,
    ServalIntegrationSettings,
)
from cerebro.integrations.serval_ticket_service import ServalTicketService


class ServalConfigRequest(BaseModel):
    team_id: str = Field(..., description="Serval team identifier")
    client_id: str = Field(..., description="Serval client identifier")
    client_secret: str = Field(..., description="Serval client secret")
    default_created_by_user_id: str = Field(
        ..., description="Default Serval user recorded as creator"
    )
    api_base_url: Optional[str] = Field(
        default="https://public.api.serval.com",
        description="Serval API base URL",
    )
    default_status_id: Optional[str] = Field(
        None, description="Default Serval status id for new tickets"
    )
    default_priority_id: Optional[str] = Field(
        None, description="Default Serval priority id"
    )
    default_requester_user_id: Optional[str] = Field(
        None, description="Default Serval requester user id"
    )
    default_assigned_user_id: Optional[str] = Field(
        None, description="Default Serval assignee user id"
    )
    status_map: Dict[str, str] = Field(
        default_factory=dict,
        description="Mapping of Cerebro statuses to Serval status ids",
    )
    priority_map: Dict[str, str] = Field(
        default_factory=dict,
        description="Mapping of Cerebro priorities to Serval priority ids",
    )


class ServalConfigResponse(BaseModel):
    org_id: UUID
    team_id: str
    api_base_url: str
    default_created_by_user_id: str
    default_status_id: Optional[str]
    default_priority_id: Optional[str]
    default_requester_user_id: Optional[str]
    default_assigned_user_id: Optional[str]
    status_map: Dict[str, str]
    priority_map: Dict[str, str]

    @classmethod
    def from_settings(
        cls, settings: ServalIntegrationSettings
    ) -> "ServalConfigResponse":
        return cls(
            org_id=settings.org_id,
            team_id=settings.team_id,
            api_base_url=settings.api_base_url,
            default_created_by_user_id=settings.default_created_by_user_id,
            default_status_id=settings.default_status_id,
            default_priority_id=settings.default_priority_id,
            default_requester_user_id=settings.default_requester_user_id,
            default_assigned_user_id=settings.default_assigned_user_id,
            status_map=settings.status_map,
            priority_map=settings.priority_map,
        )


router = APIRouter(prefix="/serval", tags=["serval"])


@router.put("/{org_id}/config", response_model=ServalConfigResponse)
async def upsert_serval_config(
    org_id: UUID,
    payload: ServalConfigRequest,
    db: AsyncSession = Depends(get_db),
    _: Any = Depends(require_scopes("admin")),
) -> ServalConfigResponse:
    """Create or update Serval credentials and defaults for an organization."""
    repo = ServalIntegrationRepository(db)
    settings = await repo.upsert(
        org_id=org_id,
        api_base_url=payload.api_base_url or "https://public.api.serval.com",
        team_id=payload.team_id,
        client_id=payload.client_id,
        client_secret=payload.client_secret,
        default_created_by_user_id=payload.default_created_by_user_id,
        default_status_id=payload.default_status_id,
        default_priority_id=payload.default_priority_id,
        default_requester_user_id=payload.default_requester_user_id,
        default_assigned_user_id=payload.default_assigned_user_id,
        status_map=payload.status_map,
        priority_map=payload.priority_map,
    )
    return ServalConfigResponse.from_settings(settings)


@router.get("/{org_id}/config", response_model=ServalConfigResponse)
async def get_serval_config(
    org_id: UUID,
    db: AsyncSession = Depends(get_db),
    _: Any = Depends(require_scopes("view:integrations")),
) -> ServalConfigResponse:
    """Return the saved Serval integration settings or 404 if none exist."""
    repo = ServalIntegrationRepository(db)
    settings = await repo.get(org_id)
    if settings is None:
        raise HTTPException(status_code=404, detail="Serval integration not configured")
    return ServalConfigResponse.from_settings(settings)


@router.delete("/{org_id}/config", status_code=204, response_class=Response)
async def delete_serval_config(
    org_id: UUID,
    db: AsyncSession = Depends(get_db),
    _: Any = Depends(require_scopes("admin")),
) -> Response:
    """Remove the Serval configuration row for the organization."""
    repo = ServalIntegrationRepository(db)
    await repo.delete(org_id)
    return Response(status_code=204)


@router.get("/{org_id}/statuses")
async def list_serval_statuses(
    org_id: UUID,
    db: AsyncSession = Depends(get_db),
    _: Any = Depends(require_scopes("view:integrations")),
) -> list[dict[str, Any]]:
    """Proxy Serval status catalogue to populate configuration UIs."""
    service = ServalTicketService(db)
    return await service.list_statuses(org_id)


@router.get("/{org_id}/priorities")
async def list_serval_priorities(
    org_id: UUID,
    db: AsyncSession = Depends(get_db),
    _: Any = Depends(require_scopes("view:integrations")),
) -> list[dict[str, Any]]:
    """Expose Serval priority values for downstream mapping."""
    service = ServalTicketService(db)
    return await service.list_priorities(org_id)
