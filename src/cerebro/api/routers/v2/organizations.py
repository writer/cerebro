"""Organization management endpoints using DynamoDB.

This is the DynamoDB version of the organizations API.
It maintains the same API contract as the PostgreSQL version.
"""

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from cerebro.api.dynamodb_dependencies import org_repository
from cerebro.core.repositories.organization import Organization, OrganizationRepository

# Request/Response schemas


class OrganizationCreate(BaseModel):
    """Request schema for creating an organization."""

    name: str = Field(..., min_length=1, max_length=255)
    slack_config: dict[str, Any] | None = None


class OrganizationUpdate(BaseModel):
    """Request schema for updating an organization."""

    name: str | None = Field(None, min_length=1, max_length=255)
    slack_config: dict[str, Any] | None = None


class OrganizationResponse(BaseModel):
    """Response schema for organization."""

    org_id: UUID
    name: str
    slack_config: dict[str, Any] | None = None
    created_at: str

    model_config = ConfigDict(from_attributes=True)

    @classmethod
    def from_entity(cls, org: Organization) -> "OrganizationResponse":
        return cls(
            org_id=org.org_id,
            name=org.name,
            slack_config=org.slack_config,
            created_at=org.created_at.isoformat(),
        )


# Router

router = APIRouter(prefix="/organizations", tags=["organizations"])


@router.post("/", response_model=OrganizationResponse, status_code=201)
async def create_organization(
    data: OrganizationCreate,
    repo: OrganizationRepository = Depends(org_repository),
) -> OrganizationResponse:
    """Create a new organization."""
    org = Organization(
        name=data.name,
        slack_config=data.slack_config,
    )
    created = await repo.create(org)
    return OrganizationResponse.from_entity(created)


@router.get("/", response_model=list[OrganizationResponse])
async def list_organizations(
    limit: int = Query(100, ge=1, le=1000),
    repo: OrganizationRepository = Depends(org_repository),
) -> list[OrganizationResponse]:
    """List all organizations."""
    orgs = await repo.list_all(limit=limit)
    return [OrganizationResponse.from_entity(org) for org in orgs]


@router.get("/{org_id}", response_model=OrganizationResponse)
async def get_organization(
    org_id: UUID,
    repo: OrganizationRepository = Depends(org_repository),
) -> OrganizationResponse:
    """Get organization by ID."""
    org = await repo.get(org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    return OrganizationResponse.from_entity(org)


@router.patch("/{org_id}", response_model=OrganizationResponse)
async def update_organization(
    org_id: UUID,
    data: OrganizationUpdate,
    repo: OrganizationRepository = Depends(org_repository),
) -> OrganizationResponse:
    """Update an organization."""
    # Build updates dict from non-None values
    updates = {k: v for k, v in data.model_dump().items() if v is not None}

    if not updates:
        raise HTTPException(status_code=400, detail="No updates provided")

    org = await repo.update(org_id, **updates)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    return OrganizationResponse.from_entity(org)


@router.delete("/{org_id}", status_code=204)
async def delete_organization(
    org_id: UUID,
    repo: OrganizationRepository = Depends(org_repository),
) -> None:
    """Delete an organization."""
    # Check if exists first
    org = await repo.get(org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    await repo.delete(org_id)
