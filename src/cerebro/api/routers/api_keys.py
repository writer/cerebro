"""API Key management endpoints."""

from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from cerebro.api.auth import User, get_current_user, require_scopes
from cerebro.api.org_access import enforce_org_access
from cerebro.core.api_keys import (
    SCOPE_PRESETS,
    APIKey,
    APIKeyCreate,
    APIKeyCreatedResponse,
    APIKeyResponse,
    APIKeyScope,
    APIKeyUsageStats,
    generate_api_key,
)
from cerebro.core.repositories.api_key import APIKeyRepository

router = APIRouter(dependencies=[Depends(get_current_user)])


def get_api_key_repository() -> APIKeyRepository:
    """Get API key repository instance."""
    return APIKeyRepository()


class APIKeyListResponse(BaseModel):
    """Response for listing API keys."""

    items: list[APIKeyResponse]
    total: int


class ScopePresetsResponse(BaseModel):
    """Response for available scope presets."""

    presets: dict[str, list[str]]
    all_scopes: list[str]


@router.get("/scopes", response_model=ScopePresetsResponse)
async def list_available_scopes(
    current_user: User = Depends(get_current_user),
) -> ScopePresetsResponse:
    """List available scopes and presets for API keys."""
    return ScopePresetsResponse(
        presets={k: [s.value if hasattr(s, "value") else s for s in v] for k, v in SCOPE_PRESETS.items()},
        all_scopes=[s.value for s in APIKeyScope],
    )


@router.post(
    "/",
    response_model=APIKeyCreatedResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_api_key(
    request: APIKeyCreate,
    org_id: UUID = Query(..., description="Organization ID"),
    current_user: User = Depends(require_scopes("admin")),
    repo: APIKeyRepository = Depends(get_api_key_repository),
) -> APIKeyCreatedResponse:
    """
    Create a new API key for an organization.

    The full API key is only returned once at creation time.
    Store it securely - it cannot be retrieved again.
    """
    enforce_org_access(org_id, current_user)

    # Resolve scopes from preset if provided
    scopes = request.scopes
    if request.scope_preset:
        if request.scope_preset not in SCOPE_PRESETS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid scope preset: {request.scope_preset}. "
                f"Valid presets: {list(SCOPE_PRESETS.keys())}",
            )
        scopes = [
            s.value if hasattr(s, "value") else s
            for s in SCOPE_PRESETS[request.scope_preset]
        ]

    # Validate scopes
    valid_scopes = {s.value for s in APIKeyScope}
    invalid_scopes = set(scopes) - valid_scopes
    if invalid_scopes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid scopes: {invalid_scopes}. Valid scopes: {valid_scopes}",
        )

    # Generate key
    full_key, key_hash, key_prefix = generate_api_key(request.is_test_key)

    # Calculate expiration
    expires_at = None
    if request.expires_in_days:
        from datetime import timedelta
        expires_at = datetime.now(UTC) + timedelta(days=request.expires_in_days)

    api_key = APIKey(
        org_id=org_id,
        name=request.name,
        description=request.description,
        key_hash=key_hash,
        key_prefix=key_prefix,
        scopes=scopes,
        rate_limit_per_minute=request.rate_limit_per_minute,
        is_test_key=request.is_test_key,
        expires_at=expires_at,
        created_by=current_user.user_id,
        metadata=request.metadata,
    )

    await repo.create(api_key)

    return APIKeyCreatedResponse(
        key_id=api_key.key_id,
        org_id=api_key.org_id,
        name=api_key.name,
        description=api_key.description,
        key_prefix=api_key.key_prefix,
        scopes=api_key.scopes,
        rate_limit_per_minute=api_key.rate_limit_per_minute,
        is_active=api_key.is_active,
        is_test_key=api_key.is_test_key,
        expires_at=api_key.expires_at,
        last_used_at=api_key.last_used_at,
        created_at=api_key.created_at,
        created_by=api_key.created_by,
        key=full_key,  # Only returned at creation
    )


@router.get("/", response_model=APIKeyListResponse)
async def list_api_keys(
    org_id: UUID = Query(..., description="Organization ID"),
    include_revoked: bool = Query(False, description="Include revoked keys"),
    limit: int = Query(100, ge=1, le=1000),
    current_user: User = Depends(require_scopes("admin")),
    repo: APIKeyRepository = Depends(get_api_key_repository),
) -> APIKeyListResponse:
    """List API keys for an organization."""
    enforce_org_access(org_id, current_user)

    keys = await repo.list_by_org(org_id, include_revoked=include_revoked, limit=limit)

    return APIKeyListResponse(
        items=[
            APIKeyResponse(
                key_id=k.key_id,
                org_id=k.org_id,
                name=k.name,
                description=k.description,
                key_prefix=k.key_prefix,
                scopes=k.scopes,
                rate_limit_per_minute=k.rate_limit_per_minute,
                is_active=k.is_active,
                is_test_key=k.is_test_key,
                expires_at=k.expires_at,
                last_used_at=k.last_used_at,
                created_at=k.created_at,
                created_by=k.created_by,
            )
            for k in keys
        ],
        total=len(keys),
    )


@router.get("/{key_id}", response_model=APIKeyResponse)
async def get_api_key(
    key_id: UUID,
    org_id: UUID = Query(..., description="Organization ID"),
    current_user: User = Depends(require_scopes("admin")),
    repo: APIKeyRepository = Depends(get_api_key_repository),
) -> APIKeyResponse:
    """Get an API key by ID."""
    enforce_org_access(org_id, current_user)

    api_key = await repo.get(key_id, org_id)
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found",
        )

    return APIKeyResponse(
        key_id=api_key.key_id,
        org_id=api_key.org_id,
        name=api_key.name,
        description=api_key.description,
        key_prefix=api_key.key_prefix,
        scopes=api_key.scopes,
        rate_limit_per_minute=api_key.rate_limit_per_minute,
        is_active=api_key.is_active,
        is_test_key=api_key.is_test_key,
        expires_at=api_key.expires_at,
        last_used_at=api_key.last_used_at,
        created_at=api_key.created_at,
        created_by=api_key.created_by,
    )


class APIKeyUpdateRequest(BaseModel):
    """Request to update an API key."""

    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = None
    scopes: list[str] | None = None
    rate_limit_per_minute: int | None = Field(None, ge=1, le=10000)
    is_active: bool | None = None


@router.patch("/{key_id}", response_model=APIKeyResponse)
async def update_api_key(
    key_id: UUID,
    request: APIKeyUpdateRequest,
    org_id: UUID = Query(..., description="Organization ID"),
    current_user: User = Depends(require_scopes("admin")),
    repo: APIKeyRepository = Depends(get_api_key_repository),
) -> APIKeyResponse:
    """Update an API key."""
    enforce_org_access(org_id, current_user)

    # Validate scopes if provided
    if request.scopes is not None:
        valid_scopes = {s.value for s in APIKeyScope}
        invalid_scopes = set(request.scopes) - valid_scopes
        if invalid_scopes:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid scopes: {invalid_scopes}",
            )

    updates = request.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No updates provided",
        )

    api_key = await repo.update(key_id, org_id, **updates)
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found",
        )

    return APIKeyResponse(
        key_id=api_key.key_id,
        org_id=api_key.org_id,
        name=api_key.name,
        description=api_key.description,
        key_prefix=api_key.key_prefix,
        scopes=api_key.scopes,
        rate_limit_per_minute=api_key.rate_limit_per_minute,
        is_active=api_key.is_active,
        is_test_key=api_key.is_test_key,
        expires_at=api_key.expires_at,
        last_used_at=api_key.last_used_at,
        created_at=api_key.created_at,
        created_by=api_key.created_by,
    )


@router.post("/{key_id}/revoke", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_api_key(
    key_id: UUID,
    org_id: UUID = Query(..., description="Organization ID"),
    current_user: User = Depends(require_scopes("admin")),
    repo: APIKeyRepository = Depends(get_api_key_repository),
) -> None:
    """Revoke an API key."""
    enforce_org_access(org_id, current_user)

    success = await repo.revoke(key_id, org_id, revoked_by=current_user.user_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found",
        )


@router.delete("/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_api_key(
    key_id: UUID,
    org_id: UUID = Query(..., description="Organization ID"),
    current_user: User = Depends(require_scopes("admin")),
    repo: APIKeyRepository = Depends(get_api_key_repository),
) -> None:
    """
    Permanently delete an API key.

    Warning: This is irreversible. Consider using revoke instead.
    """
    enforce_org_access(org_id, current_user)

    success = await repo.delete(key_id, org_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found",
        )


@router.get("/{key_id}/usage", response_model=APIKeyUsageStats)
async def get_api_key_usage(
    key_id: UUID,
    org_id: UUID = Query(..., description="Organization ID"),
    current_user: User = Depends(require_scopes("admin")),
    repo: APIKeyRepository = Depends(get_api_key_repository),
) -> APIKeyUsageStats:
    """Get usage statistics for an API key."""
    enforce_org_access(org_id, current_user)

    api_key = await repo.get(key_id, org_id)
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found",
        )

    # Usage tracking requires CloudWatch or Redis integration.
    # For now, return basic stats from the key's last_used_at timestamp.
    return APIKeyUsageStats(
        key_id=key_id,
        total_requests=0,  # Would come from CloudWatch metrics
        requests_last_hour=0,
        requests_last_24h=0,
        requests_last_7d=0,
        avg_latency_ms=0.0,
        error_rate=0.0,
        top_endpoints=[],
    )


class RotateKeyResponse(BaseModel):
    """Response for key rotation."""

    old_key_id: UUID
    old_key_expires_at: datetime
    new_key: APIKeyCreatedResponse


@router.post("/{key_id}/rotate", response_model=RotateKeyResponse)
async def rotate_api_key(
    key_id: UUID,
    org_id: UUID = Query(..., description="Organization ID"),
    grace_period_hours: int = Query(24, ge=1, le=168, description="Hours to keep old key valid"),
    current_user: User = Depends(require_scopes("admin")),
    repo: APIKeyRepository = Depends(get_api_key_repository),
) -> RotateKeyResponse:
    """
    Rotate an API key, creating a new one while keeping the old valid for a grace period.

    This allows for zero-downtime key rotation.
    """
    enforce_org_access(org_id, current_user)

    old_key = await repo.get(key_id, org_id)
    if not old_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found",
        )

    if not old_key.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot rotate an inactive key",
        )

    # Set expiration on old key
    from datetime import timedelta
    old_expires_at = datetime.now(UTC) + timedelta(hours=grace_period_hours)
    await repo.update(key_id, org_id, expires_at=old_expires_at)

    # Create new key with same settings
    full_key, key_hash, key_prefix = generate_api_key(old_key.is_test_key)

    new_api_key = APIKey(
        org_id=org_id,
        name=f"{old_key.name} (rotated)",
        description=old_key.description,
        key_hash=key_hash,
        key_prefix=key_prefix,
        scopes=old_key.scopes,
        rate_limit_per_minute=old_key.rate_limit_per_minute,
        is_test_key=old_key.is_test_key,
        expires_at=old_key.expires_at,  # Keep original expiration if any
        created_by=current_user.user_id,
        metadata={**old_key.metadata, "rotated_from": str(key_id)},
    )

    await repo.create(new_api_key)

    return RotateKeyResponse(
        old_key_id=key_id,
        old_key_expires_at=old_expires_at,
        new_key=APIKeyCreatedResponse(
            key_id=new_api_key.key_id,
            org_id=new_api_key.org_id,
            name=new_api_key.name,
            description=new_api_key.description,
            key_prefix=new_api_key.key_prefix,
            scopes=new_api_key.scopes,
            rate_limit_per_minute=new_api_key.rate_limit_per_minute,
            is_active=new_api_key.is_active,
            is_test_key=new_api_key.is_test_key,
            expires_at=new_api_key.expires_at,
            last_used_at=new_api_key.last_used_at,
            created_at=new_api_key.created_at,
            created_by=new_api_key.created_by,
            key=full_key,
        ),
    )
