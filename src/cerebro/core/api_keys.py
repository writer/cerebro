"""API Key authentication and management for Cerebro.

This module provides API key-based authentication for machine-to-machine
integrations, supporting scoped access, rate limiting, and key rotation.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from enum import Enum
from uuid import UUID, uuid4

import structlog
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

logger = structlog.get_logger(__name__)

# API Key prefix for identification (similar to GitHub's gh_, Stripe's sk_)
API_KEY_PREFIX = "cbr_"
API_KEY_LIVE_PREFIX = "cbr_live_"
API_KEY_TEST_PREFIX = "cbr_test_"


class APIKeyScope(str, Enum):
    """Available scopes for API keys."""

    # Read-only scopes
    READ_FINDINGS = "read:findings"
    READ_RESOURCES = "read:resources"
    READ_ORGANIZATIONS = "read:organizations"
    READ_ACCOUNTS = "read:accounts"
    READ_RULES = "read:rules"
    READ_ANALYTICS = "read:analytics"
    READ_COMPLIANCE = "read:compliance"

    # Write scopes
    WRITE_FINDINGS = "write:findings"
    WRITE_RESOURCES = "write:resources"
    WRITE_ORGANIZATIONS = "write:organizations"
    WRITE_ACCOUNTS = "write:accounts"
    WRITE_RULES = "write:rules"

    # Special scopes
    COLLECT_DATA = "collect:data"
    ADMIN = "admin"

    # Webhook scopes
    WEBHOOKS_MANAGE = "webhooks:manage"
    WEBHOOKS_READ = "webhooks:read"


# Predefined scope sets for common use cases
SCOPE_PRESETS = {
    "read_only": [
        APIKeyScope.READ_FINDINGS,
        APIKeyScope.READ_RESOURCES,
        APIKeyScope.READ_ORGANIZATIONS,
        APIKeyScope.READ_ACCOUNTS,
        APIKeyScope.READ_ANALYTICS,
    ],
    "findings_manager": [
        APIKeyScope.READ_FINDINGS,
        APIKeyScope.WRITE_FINDINGS,
        APIKeyScope.READ_RESOURCES,
        APIKeyScope.READ_RULES,
    ],
    "collector": [
        APIKeyScope.COLLECT_DATA,
        APIKeyScope.READ_ACCOUNTS,
        APIKeyScope.READ_ORGANIZATIONS,
    ],
    "integration": [
        APIKeyScope.READ_FINDINGS,
        APIKeyScope.READ_RESOURCES,
        APIKeyScope.READ_ANALYTICS,
        APIKeyScope.WEBHOOKS_READ,
    ],
    "full_access": list(APIKeyScope),
}


class APIKey(BaseModel):
    """API Key entity."""

    key_id: UUID = Field(default_factory=uuid4)
    org_id: UUID
    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = None
    key_hash: str  # SHA-256 hash of the key
    key_prefix: str  # First 8 chars for identification (e.g., "cbr_live_abc12345")
    scopes: list[str] = Field(default_factory=list)
    rate_limit_per_minute: int = Field(default=100, ge=1, le=10000)
    is_active: bool = True
    is_test_key: bool = False
    expires_at: datetime | None = None
    last_used_at: datetime | None = None
    last_used_ip: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    created_by: UUID | None = None
    revoked_at: datetime | None = None
    revoked_by: UUID | None = None
    metadata: dict = Field(default_factory=dict)


class APIKeyCreate(BaseModel):
    """Request schema for creating an API key."""

    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = None
    scopes: list[str] = Field(default_factory=lambda: SCOPE_PRESETS["read_only"])
    scope_preset: str | None = None  # Use a preset instead of explicit scopes
    rate_limit_per_minute: int = Field(default=100, ge=1, le=10000)
    expires_in_days: int | None = Field(default=None, ge=1, le=365)
    is_test_key: bool = False
    metadata: dict = Field(default_factory=dict)


class APIKeyResponse(BaseModel):
    """Response schema for API key (without sensitive data)."""

    key_id: UUID
    org_id: UUID
    name: str
    description: str | None
    key_prefix: str
    scopes: list[str]
    rate_limit_per_minute: int
    is_active: bool
    is_test_key: bool
    expires_at: datetime | None
    last_used_at: datetime | None
    created_at: datetime
    created_by: UUID | None


class APIKeyCreatedResponse(APIKeyResponse):
    """Response when creating a new API key (includes the actual key once)."""

    key: str  # Full API key - only shown once at creation


class APIKeyUsageStats(BaseModel):
    """Usage statistics for an API key."""

    key_id: UUID
    total_requests: int = 0
    requests_last_hour: int = 0
    requests_last_24h: int = 0
    requests_last_7d: int = 0
    avg_latency_ms: float = 0.0
    error_rate: float = 0.0
    top_endpoints: list[dict] = Field(default_factory=list)


def generate_api_key(is_test: bool = False) -> tuple[str, str, str]:
    """
    Generate a new API key.

    Returns:
        Tuple of (full_key, key_hash, key_prefix)
    """
    # Generate random key body
    key_body = secrets.token_urlsafe(32)

    # Add appropriate prefix
    prefix = API_KEY_TEST_PREFIX if is_test else API_KEY_LIVE_PREFIX
    full_key = f"{prefix}{key_body}"

    # Hash the key for storage
    key_hash = hashlib.sha256(full_key.encode()).hexdigest()

    # Store first 12 chars after prefix for identification
    key_prefix = full_key[:20]

    return full_key, key_hash, key_prefix


def hash_api_key(key: str) -> str:
    """Hash an API key for comparison."""
    return hashlib.sha256(key.encode()).hexdigest()


def validate_api_key_format(key: str) -> bool:
    """Validate that a string looks like a valid API key."""
    if not key:
        return False

    valid_prefixes = (API_KEY_PREFIX, API_KEY_LIVE_PREFIX, API_KEY_TEST_PREFIX)
    if not key.startswith(valid_prefixes):
        return False

    # Key should be at least prefix + 32 chars
    min_length = len(API_KEY_LIVE_PREFIX) + 32
    return len(key) >= min_length


class APIKeyService:
    """Service for managing API keys."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_key(
        self,
        org_id: UUID,
        request: APIKeyCreate,
        created_by: UUID | None = None,
    ) -> tuple[APIKey, str]:
        """
        Create a new API key.

        Returns:
            Tuple of (APIKey entity, full key string)
        """
        # Resolve scopes from preset if provided
        scopes = request.scopes
        if request.scope_preset and request.scope_preset in SCOPE_PRESETS:
            scopes = [s.value for s in SCOPE_PRESETS[request.scope_preset]]

        # Validate scopes
        valid_scopes = {s.value for s in APIKeyScope}
        invalid_scopes = set(scopes) - valid_scopes
        if invalid_scopes:
            raise ValueError(f"Invalid scopes: {invalid_scopes}")

        # Generate key
        full_key, key_hash, key_prefix = generate_api_key(request.is_test_key)

        # Calculate expiration
        expires_at = None
        if request.expires_in_days:
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
            created_by=created_by,
            metadata=request.metadata,
        )

        # Store in DynamoDB (using repository pattern)
        # For now, we'll use a simple in-memory approach
        # TODO: Implement DynamoDB storage via repository

        logger.info(
            "api_key_created",
            key_id=str(api_key.key_id),
            org_id=str(org_id),
            name=request.name,
            scopes=scopes,
            is_test=request.is_test_key,
        )

        return api_key, full_key

    async def verify_key(self, key: str) -> APIKey | None:
        """
        Verify an API key and return the associated key entity.

        Returns None if key is invalid, expired, or revoked.
        """
        if not validate_api_key_format(key):
            return None

        # TODO: Implement DynamoDB lookup via repository
        # key_hash = hash_api_key(key)
        # For now, return None (will be implemented with repository)

        return None

    async def revoke_key(
        self,
        key_id: UUID,
        org_id: UUID,
        revoked_by: UUID | None = None,
    ) -> bool:
        """Revoke an API key."""
        # TODO: Implement DynamoDB update
        logger.info(
            "api_key_revoked",
            key_id=str(key_id),
            org_id=str(org_id),
            revoked_by=str(revoked_by) if revoked_by else None,
        )
        return True

    async def list_keys(
        self,
        org_id: UUID,
        include_revoked: bool = False,
        limit: int = 100,
    ) -> list[APIKey]:
        """List API keys for an organization."""
        # TODO: Implement DynamoDB query
        return []

    async def update_last_used(
        self,
        key_id: UUID,
        ip_address: str | None = None,
    ) -> None:
        """Update the last used timestamp for a key."""
        # TODO: Implement DynamoDB update (with conditional write for rate limiting)
        pass

    async def rotate_key(
        self,
        key_id: UUID,
        org_id: UUID,
        grace_period_hours: int = 24,
    ) -> tuple[APIKey, str]:
        """
        Rotate an API key, keeping the old one valid for a grace period.

        Returns the new key entity and the new key string.
        """
        # TODO: Implement key rotation
        # 1. Create new key with same scopes/settings
        # 2. Mark old key for expiration after grace period
        # 3. Return new key
        raise NotImplementedError("Key rotation not yet implemented")

    async def get_usage_stats(self, key_id: UUID) -> APIKeyUsageStats:
        """Get usage statistics for an API key."""
        # TODO: Implement usage tracking via CloudWatch/DynamoDB
        return APIKeyUsageStats(key_id=key_id)
