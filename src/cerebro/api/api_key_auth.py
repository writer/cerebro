"""API Key authentication for Cerebro API.

This module provides API key-based authentication as an alternative to JWT tokens.
API keys are ideal for machine-to-machine integrations and CI/CD pipelines.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import structlog
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import APIKeyHeader

from cerebro.api.auth import User
from cerebro.core.api_keys import hash_api_key, validate_api_key_format
from cerebro.core.repositories.api_key import APIKeyRepository

logger = structlog.get_logger(__name__)

# API Key header name (X-API-Key is standard)
API_KEY_HEADER = APIKeyHeader(
    name="X-API-Key",
    scheme_name="API Key",
    description="API key for authentication. Get one from the API Keys management page.",
    auto_error=False,  # Don't auto-error, we'll handle missing keys
)


class APIKeyUser(User):
    """Extended user context for API key authentication."""

    api_key_id: UUID
    api_key_name: str
    rate_limit_per_minute: int = 100
    is_test_key: bool = False


async def get_api_key_repository() -> APIKeyRepository:
    """Get API key repository instance."""
    return APIKeyRepository()


async def verify_api_key(
    request: Request,
    api_key: str | None = Depends(API_KEY_HEADER),
    repo: APIKeyRepository = Depends(get_api_key_repository),
) -> APIKeyUser | None:
    """
    Verify an API key and return the associated user context.

    Returns None if no API key is provided (allows fallback to JWT auth).
    Raises HTTPException if an invalid API key is provided.
    """
    if not api_key:
        return None

    # Validate format first (fast path for obviously invalid keys)
    if not validate_api_key_format(api_key):
        logger.warning("invalid_api_key_format", key_prefix=api_key[:20] if len(api_key) > 20 else "***")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key format",
            headers={"WWW-Authenticate": "API-Key"},
        )

    # Look up by hash
    key_hash = hash_api_key(api_key)
    key_entity = await repo.get_by_hash(key_hash)

    if not key_entity:
        logger.warning("api_key_not_found", key_prefix=api_key[:20])
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "API-Key"},
        )

    # Check if active
    if not key_entity.is_active:
        logger.warning("api_key_inactive", key_id=str(key_entity.key_id))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key has been revoked",
            headers={"WWW-Authenticate": "API-Key"},
        )

    # Check expiration
    if key_entity.expires_at and key_entity.expires_at < datetime.now(UTC):
        logger.warning("api_key_expired", key_id=str(key_entity.key_id))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key has expired",
            headers={"WWW-Authenticate": "API-Key"},
        )

    # Update last used (fire and forget)
    client_ip = request.client.host if request.client else None
    try:
        await repo.update_last_used(key_entity.key_id, key_entity.org_id, client_ip)
    except Exception as e:
        logger.warning("failed_to_update_api_key_usage", error=str(e))

    # Build user context
    return APIKeyUser(
        user_id=key_entity.created_by or UUID("00000000-0000-0000-0000-000000000000"),
        username=f"api_key:{key_entity.name}",
        email=None,
        is_admin="admin" in key_entity.scopes,
        scopes=key_entity.scopes,
        org_id=key_entity.org_id,
        api_key_id=key_entity.key_id,
        api_key_name=key_entity.name,
        rate_limit_per_minute=key_entity.rate_limit_per_minute,
        is_test_key=key_entity.is_test_key,
    )


async def get_current_user_or_api_key(
    request: Request,
    api_key_user: APIKeyUser | None = Depends(verify_api_key),
) -> User:
    """
    Get the current user from either API key or JWT authentication.

    Tries API key first, then falls back to JWT.
    """
    # If API key auth succeeded, use it
    if api_key_user is not None:
        return api_key_user

    # Fall back to JWT authentication
    from cerebro.api.auth import get_current_user
    from cerebro.api.dependencies import get_jwt_service
    from cerebro.core.database import get_db

    # We need to manually resolve dependencies here
    db = await anext(get_db())
    try:
        jwt_service = await get_jwt_service(db)
        return await get_current_user(request, db, jwt_service)
    finally:
        await db.close()


def require_api_key_scopes(*required_scopes: str):
    """
    Dependency that requires the API key to have specific scopes.

    Works with both API key and JWT authentication.
    """
    async def scope_checker(
        request: Request,
        api_key_user: APIKeyUser | None = Depends(verify_api_key),
    ) -> User:
        user = await get_current_user_or_api_key(request, api_key_user)

        missing = [scope for scope in required_scopes if scope not in user.scopes]
        if missing:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required scope: {missing[0]}",
            )
        return user

    return scope_checker
