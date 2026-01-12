"""Tests for API Key Service with DynamoDB integration.

These tests verify that the APIKeyService correctly integrates with
the APIKeyRepository for DynamoDB storage.
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from cerebro.core.api_keys import (
    SCOPE_PRESETS,
    APIKey,
    APIKeyCreate,
    APIKeyScope,
    APIKeyService,
    generate_api_key,
    hash_api_key,
    validate_api_key_format,
)


class TestAPIKeyGeneration:
    """Tests for API key generation utilities."""

    def test_generate_api_key_live(self):
        """Test generating a live API key."""
        full_key, key_hash, key_prefix = generate_api_key(is_test=False)

        assert full_key.startswith("cbr_live_")
        assert len(key_hash) == 64  # SHA-256 hex digest
        assert key_prefix == full_key[:20]

    def test_generate_api_key_test(self):
        """Test generating a test API key."""
        full_key, key_hash, key_prefix = generate_api_key(is_test=True)

        assert full_key.startswith("cbr_test_")
        assert len(key_hash) == 64
        assert key_prefix == full_key[:20]

    def test_hash_api_key(self):
        """Test API key hashing is consistent."""
        key = "cbr_live_test123456789012345678901234567890"
        hash1 = hash_api_key(key)
        hash2 = hash_api_key(key)

        assert hash1 == hash2
        assert len(hash1) == 64

    def test_validate_api_key_format_valid(self):
        """Test validation of valid API key formats."""
        assert validate_api_key_format("cbr_live_" + "x" * 40)
        assert validate_api_key_format("cbr_test_" + "x" * 40)
        assert validate_api_key_format("cbr_" + "x" * 40)

    def test_validate_api_key_format_invalid(self):
        """Test validation rejects invalid formats."""
        assert not validate_api_key_format("")
        assert not validate_api_key_format("invalid_key")
        assert not validate_api_key_format("cbr_live_short")
        assert not validate_api_key_format("sk_live_" + "x" * 40)


class TestAPIKeyService:
    """Tests for APIKeyService."""

    @pytest.fixture
    def mock_repository(self):
        """Create a mock repository."""
        repo = AsyncMock()
        repo.create = AsyncMock()
        repo.get = AsyncMock()
        repo.get_by_hash = AsyncMock()
        repo.list_by_org = AsyncMock()
        repo.update = AsyncMock()
        repo.revoke = AsyncMock()
        return repo

    @pytest.fixture
    def service(self, mock_repository):
        """Create service with mock repository."""
        return APIKeyService(repository=mock_repository)

    @pytest.mark.asyncio
    async def test_create_key(self, service, mock_repository):
        """Test creating a new API key."""
        org_id = uuid4()
        user_id = uuid4()

        request = APIKeyCreate(
            name="Test Key",
            description="A test API key",
            scopes=["read:findings", "read:resources"],
            rate_limit_per_minute=100,
        )

        mock_repository.create.return_value = MagicMock()

        api_key, full_key = await service.create_key(
            org_id=org_id,
            request=request,
            created_by=user_id,
        )

        assert api_key.name == "Test Key"
        assert api_key.org_id == org_id
        assert api_key.created_by == user_id
        assert "read:findings" in api_key.scopes
        assert full_key.startswith("cbr_live_")
        mock_repository.create.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_key_with_preset(self, service, mock_repository):
        """Test creating a key with a scope preset."""
        org_id = uuid4()

        request = APIKeyCreate(
            name="Read Only Key",
            scope_preset="read_only",
        )

        mock_repository.create.return_value = MagicMock()

        api_key, _ = await service.create_key(org_id=org_id, request=request)

        expected_scopes = [s.value for s in SCOPE_PRESETS["read_only"]]
        assert api_key.scopes == expected_scopes

    @pytest.mark.asyncio
    async def test_create_key_with_expiration(self, service, mock_repository):
        """Test creating a key with expiration."""
        org_id = uuid4()

        request = APIKeyCreate(
            name="Expiring Key",
            expires_in_days=30,
        )

        mock_repository.create.return_value = MagicMock()

        api_key, _ = await service.create_key(org_id=org_id, request=request)

        assert api_key.expires_at is not None
        expected_expiry = datetime.now(UTC) + timedelta(days=30)
        assert abs((api_key.expires_at - expected_expiry).total_seconds()) < 5

    @pytest.mark.asyncio
    async def test_create_key_invalid_scopes(self, service, mock_repository):
        """Test creating a key with invalid scopes raises error."""
        org_id = uuid4()

        request = APIKeyCreate(
            name="Bad Key",
            scopes=["invalid:scope", "read:findings"],
        )

        with pytest.raises(ValueError, match="Invalid scopes"):
            await service.create_key(org_id=org_id, request=request)

    @pytest.mark.asyncio
    async def test_verify_key_valid(self, service, mock_repository):
        """Test verifying a valid key."""
        org_id = uuid4()
        full_key, key_hash, _ = generate_api_key(is_test=False)

        mock_key = APIKey(
            org_id=org_id,
            name="Test Key",
            key_hash=key_hash,
            key_prefix=full_key[:20],
            scopes=["read:findings"],
            is_active=True,
        )
        mock_repository.get_by_hash.return_value = mock_key

        result = await service.verify_key(full_key)

        assert result is not None
        assert result.org_id == org_id
        mock_repository.get_by_hash.assert_called_once_with(key_hash)

    @pytest.mark.asyncio
    async def test_verify_key_invalid_format(self, service, mock_repository):
        """Test verifying a key with invalid format."""
        result = await service.verify_key("invalid_key")

        assert result is None
        mock_repository.get_by_hash.assert_not_called()

    @pytest.mark.asyncio
    async def test_verify_key_not_found(self, service, mock_repository):
        """Test verifying a key that doesn't exist."""
        full_key, _, _ = generate_api_key(is_test=False)
        mock_repository.get_by_hash.return_value = None

        result = await service.verify_key(full_key)

        assert result is None

    @pytest.mark.asyncio
    async def test_verify_key_inactive(self, service, mock_repository):
        """Test verifying an inactive key returns None."""
        full_key, key_hash, _ = generate_api_key(is_test=False)

        mock_key = APIKey(
            org_id=uuid4(),
            name="Inactive Key",
            key_hash=key_hash,
            key_prefix=full_key[:20],
            scopes=["read:findings"],
            is_active=False,
        )
        mock_repository.get_by_hash.return_value = mock_key

        result = await service.verify_key(full_key)

        assert result is None

    @pytest.mark.asyncio
    async def test_verify_key_revoked(self, service, mock_repository):
        """Test verifying a revoked key returns None."""
        full_key, key_hash, _ = generate_api_key(is_test=False)

        mock_key = APIKey(
            org_id=uuid4(),
            name="Revoked Key",
            key_hash=key_hash,
            key_prefix=full_key[:20],
            scopes=["read:findings"],
            is_active=True,
            revoked_at=datetime.now(UTC),
        )
        mock_repository.get_by_hash.return_value = mock_key

        result = await service.verify_key(full_key)

        assert result is None

    @pytest.mark.asyncio
    async def test_verify_key_expired(self, service, mock_repository):
        """Test verifying an expired key returns None."""
        full_key, key_hash, _ = generate_api_key(is_test=False)

        mock_key = APIKey(
            org_id=uuid4(),
            name="Expired Key",
            key_hash=key_hash,
            key_prefix=full_key[:20],
            scopes=["read:findings"],
            is_active=True,
            expires_at=datetime.now(UTC) - timedelta(days=1),
        )
        mock_repository.get_by_hash.return_value = mock_key

        result = await service.verify_key(full_key)

        assert result is None

    @pytest.mark.asyncio
    async def test_revoke_key(self, service, mock_repository):
        """Test revoking an API key."""
        key_id = uuid4()
        org_id = uuid4()
        revoked_by = uuid4()

        mock_repository.revoke.return_value = True

        result = await service.revoke_key(key_id, org_id, revoked_by)

        assert result is True
        mock_repository.revoke.assert_called_once_with(key_id, org_id, revoked_by)

    @pytest.mark.asyncio
    async def test_list_keys(self, service, mock_repository):
        """Test listing API keys for an organization."""
        org_id = uuid4()

        mock_keys = [
            APIKey(
                org_id=org_id,
                name="Key 1",
                key_hash="hash1",
                key_prefix="cbr_live_prefix1",
                scopes=["read:findings"],
            ),
            APIKey(
                org_id=org_id,
                name="Key 2",
                key_hash="hash2",
                key_prefix="cbr_live_prefix2",
                scopes=["admin"],
            ),
        ]
        mock_repository.list_by_org.return_value = mock_keys

        result = await service.list_keys(org_id)

        assert len(result) == 2
        mock_repository.list_by_org.assert_called_once_with(org_id, False, 100)

    @pytest.mark.asyncio
    async def test_rotate_key(self, service, mock_repository):
        """Test rotating an API key."""
        key_id = uuid4()
        org_id = uuid4()

        existing_key = APIKey(
            key_id=key_id,
            org_id=org_id,
            name="Original Key",
            key_hash="original_hash",
            key_prefix="cbr_live_original",
            scopes=["read:findings", "read:resources"],
            rate_limit_per_minute=200,
            is_test_key=False,
            metadata={"env": "production"},
        )
        mock_repository.get.return_value = existing_key
        mock_repository.create.return_value = MagicMock()
        mock_repository.update.return_value = MagicMock()

        new_key, full_key = await service.rotate_key(
            key_id=key_id,
            org_id=org_id,
            grace_period_hours=24,
        )

        assert new_key.name == "Original Key (rotated)"
        assert new_key.scopes == existing_key.scopes
        assert new_key.rate_limit_per_minute == existing_key.rate_limit_per_minute
        assert "rotated_from" in new_key.metadata
        assert full_key.startswith("cbr_live_")

        # Verify old key was updated with expiration
        mock_repository.update.assert_called_once()
        update_call = mock_repository.update.call_args
        assert update_call[0] == (key_id, org_id)
        assert "expires_at" in update_call[1]

    @pytest.mark.asyncio
    async def test_rotate_key_not_found(self, service, mock_repository):
        """Test rotating a non-existent key raises error."""
        mock_repository.get.return_value = None

        with pytest.raises(ValueError, match="not found"):
            await service.rotate_key(uuid4(), uuid4())

    @pytest.mark.asyncio
    async def test_rotate_key_already_revoked(self, service, mock_repository):
        """Test rotating a revoked key raises error."""
        key_id = uuid4()
        org_id = uuid4()

        revoked_key = APIKey(
            key_id=key_id,
            org_id=org_id,
            name="Revoked Key",
            key_hash="hash",
            key_prefix="cbr_live_",
            scopes=["read:findings"],
            revoked_at=datetime.now(UTC),
        )
        mock_repository.get.return_value = revoked_key

        with pytest.raises(ValueError, match="Cannot rotate a revoked key"):
            await service.rotate_key(key_id, org_id)

    @pytest.mark.asyncio
    async def test_update_last_used(self, service, mock_repository):
        """Test updating last used timestamp."""
        key_id = uuid4()
        org_id = uuid4()
        ip_address = "192.168.1.1"

        await service.update_last_used(key_id, org_id, ip_address)

        mock_repository.update_last_used.assert_called_once_with(
            key_id, org_id, ip_address
        )

    @pytest.mark.asyncio
    async def test_get_key(self, service, mock_repository):
        """Test getting a specific key."""
        key_id = uuid4()
        org_id = uuid4()

        mock_key = APIKey(
            key_id=key_id,
            org_id=org_id,
            name="Test Key",
            key_hash="hash",
            key_prefix="cbr_live_",
            scopes=["read:findings"],
        )
        mock_repository.get.return_value = mock_key

        result = await service.get_key(key_id, org_id)

        assert result == mock_key
        mock_repository.get.assert_called_once_with(key_id, org_id)


class TestScopePresets:
    """Tests for scope presets."""

    def test_read_only_preset(self):
        """Test read_only preset contains only read scopes."""
        scopes = SCOPE_PRESETS["read_only"]
        for scope in scopes:
            scope_value = scope.value if hasattr(scope, "value") else scope
            assert scope_value.startswith("read:")

    def test_full_access_preset(self):
        """Test full_access preset contains all scopes."""
        full_access = SCOPE_PRESETS["full_access"]
        all_scopes = list(APIKeyScope)
        assert len(full_access) == len(all_scopes)

    def test_collector_preset(self):
        """Test collector preset has collect:data scope."""
        scopes = SCOPE_PRESETS["collector"]
        scope_values = [s.value if hasattr(s, "value") else s for s in scopes]
        assert "collect:data" in scope_values
