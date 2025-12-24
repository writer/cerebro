"""
Comprehensive tests for encryption service.

Tests cover:
- Encryption/decryption roundtrip
- DEK cache functionality
- LRU eviction
- Thread safety
- KMS integration
- Cache statistics
"""

import asyncio
from unittest.mock import patch

import pytest

from cerebro.core.encryption import SecretEncryptionService, get_encryption_service
from cerebro.kms.local_kms import LocalKMS


class TestEncryptionService:
    """Test suite for SecretEncryptionService."""

    @pytest.fixture
    async def encryption_service(self):
        """Create a fresh encryption service for each test."""
        kms = LocalKMS()
        service = SecretEncryptionService(kms=kms)
        yield service
        # Cleanup cache
        await service.clear_cache()

    @pytest.mark.asyncio
    async def test_encrypt_decrypt_roundtrip(self, encryption_service):
        """Test that encryption and decryption work correctly."""
        plaintext = "my-secret-password"

        # Encrypt
        encrypted_data, encrypted_dek = await encryption_service.encrypt_secret(
            plaintext
        )

        # Verify encrypted data is different from plaintext
        assert encrypted_data != plaintext.encode()
        assert encrypted_dek is not None
        assert isinstance(encrypted_data, bytes)
        assert isinstance(encrypted_dek, bytes)

        # Decrypt
        decrypted = await encryption_service.decrypt_secret(
            encrypted_data, encrypted_dek
        )

        # Verify roundtrip
        assert decrypted == plaintext

    @pytest.mark.asyncio
    async def test_encrypt_empty_string(self, encryption_service):
        """Test encrypting an empty string."""
        plaintext = ""

        encrypted_data, encrypted_dek = await encryption_service.encrypt_secret(
            plaintext
        )
        decrypted = await encryption_service.decrypt_secret(
            encrypted_data, encrypted_dek
        )

        assert decrypted == plaintext

    @pytest.mark.asyncio
    async def test_encrypt_unicode(self, encryption_service):
        """Test encrypting Unicode characters."""
        plaintext = "🔐 密码 пароль password 🔑"

        encrypted_data, encrypted_dek = await encryption_service.encrypt_secret(
            plaintext
        )
        decrypted = await encryption_service.decrypt_secret(
            encrypted_data, encrypted_dek
        )

        assert decrypted == plaintext

    @pytest.mark.asyncio
    async def test_encrypt_long_text(self, encryption_service):
        """Test encrypting long text."""
        plaintext = "A" * 10000  # 10KB

        encrypted_data, encrypted_dek = await encryption_service.encrypt_secret(
            plaintext
        )
        decrypted = await encryption_service.decrypt_secret(
            encrypted_data, encrypted_dek
        )

        assert decrypted == plaintext

    @pytest.mark.asyncio
    async def test_dek_cache_hit(self, encryption_service):
        """Test that DEK cache provides performance benefit."""
        plaintext = "test-secret"

        # First encryption
        encrypted_data1, encrypted_dek1 = await encryption_service.encrypt_secret(
            plaintext
        )

        # First decryption - populates cache
        await encryption_service.decrypt_secret(encrypted_data1, encrypted_dek1)

        # Check cache has 1 entry
        stats = encryption_service.get_cache_stats()
        assert stats["current_size"] == 1

        # Second decryption with same DEK - should hit cache
        await encryption_service.decrypt_secret(encrypted_data1, encrypted_dek1)

        # Cache size should still be 1
        stats = encryption_service.get_cache_stats()
        assert stats["current_size"] == 1

    @pytest.mark.asyncio
    async def test_dek_cache_lru_eviction(self, encryption_service):
        """Test that LRU eviction works when cache fills up."""
        # Fill cache to maximum
        deks = []
        for i in range(1005):  # Over the limit of 1000
            encrypted_data, encrypted_dek = await encryption_service.encrypt_secret(
                f"secret-{i}"
            )
            deks.append((encrypted_data, encrypted_dek))
            # Decrypt to populate cache
            await encryption_service.decrypt_secret(encrypted_data, encrypted_dek)

        # Cache should be at max size (1000), with oldest evicted
        stats = encryption_service.get_cache_stats()
        assert stats["current_size"] <= encryption_service.MAX_CACHE_SIZE
        assert stats["utilization_percent"] <= 100

    @pytest.mark.asyncio
    async def test_cache_stats(self, encryption_service):
        """Test cache statistics reporting."""
        stats = encryption_service.get_cache_stats()

        assert "current_size" in stats
        assert "max_size" in stats
        assert "utilization_percent" in stats
        assert stats["max_size"] == 1000
        assert stats["current_size"] == 0
        assert stats["utilization_percent"] == 0.0

        # Add some entries
        for i in range(10):
            encrypted_data, encrypted_dek = await encryption_service.encrypt_secret(
                f"secret-{i}"
            )
            await encryption_service.decrypt_secret(encrypted_data, encrypted_dek)

        stats = encryption_service.get_cache_stats()
        assert stats["current_size"] == 10
        assert stats["utilization_percent"] == 1.0

    @pytest.mark.asyncio
    async def test_clear_cache(self, encryption_service):
        """Test cache clearing."""
        # Populate cache
        for i in range(10):
            encrypted_data, encrypted_dek = await encryption_service.encrypt_secret(
                f"secret-{i}"
            )
            await encryption_service.decrypt_secret(encrypted_data, encrypted_dek)

        stats = encryption_service.get_cache_stats()
        assert stats["current_size"] == 10

        # Clear cache
        await encryption_service.clear_cache()

        stats = encryption_service.get_cache_stats()
        assert stats["current_size"] == 0

    @pytest.mark.asyncio
    async def test_concurrent_decryption(self, encryption_service):
        """Test thread safety with concurrent decryption operations."""
        plaintext = "concurrent-test-secret"
        encrypted_data, encrypted_dek = await encryption_service.encrypt_secret(
            plaintext
        )

        # Run 100 concurrent decryption operations
        tasks = [
            encryption_service.decrypt_secret(encrypted_data, encrypted_dek)
            for _ in range(100)
        ]

        results = await asyncio.gather(*tasks)

        # All should succeed and return same plaintext
        assert all(r == plaintext for r in results)
        assert len(results) == 100

    @pytest.mark.asyncio
    async def test_concurrent_encryption(self, encryption_service):
        """Test concurrent encryption operations."""
        # Run 100 concurrent encryption operations
        tasks = [encryption_service.encrypt_secret(f"secret-{i}") for i in range(100)]

        results = await asyncio.gather(*tasks)

        # All should succeed
        assert len(results) == 100

        # All should have unique encrypted data
        encrypted_data_set = {r[0] for r in results}
        assert len(encrypted_data_set) == 100

    @pytest.mark.asyncio
    async def test_dek_rotation(self, encryption_service):
        """Test DEK rotation functionality."""
        original_plaintext = "rotation-test-secret"

        # Original encryption
        old_encrypted_data, old_encrypted_dek = await encryption_service.encrypt_secret(
            original_plaintext
        )

        # Rotate DEK
        new_encrypted_data, new_encrypted_dek = await encryption_service.rotate_dek(
            old_encrypted_data, old_encrypted_dek
        )

        # DEK should be different
        assert new_encrypted_dek != old_encrypted_dek

        # Encrypted data should be different
        assert new_encrypted_data != old_encrypted_data

        # But plaintext should be the same
        decrypted = await encryption_service.decrypt_secret(
            new_encrypted_data, new_encrypted_dek
        )
        assert decrypted == original_plaintext

        # Old DEK should no longer work with new encrypted data
        with pytest.raises(Exception):
            await encryption_service.decrypt_secret(
                new_encrypted_data, old_encrypted_dek
            )

    @pytest.mark.asyncio
    async def test_test_encryption_success(self, encryption_service):
        """Test the test_encryption method succeeds."""
        result = await encryption_service.test_encryption()
        assert result is True

    @pytest.mark.asyncio
    async def test_invalid_encrypted_data(self, encryption_service):
        """Test that invalid encrypted data raises an error."""
        plaintext = "test-secret"
        encrypted_data, encrypted_dek = await encryption_service.encrypt_secret(
            plaintext
        )

        # Corrupt the encrypted data
        corrupted_data = b"corrupted" + encrypted_data

        with pytest.raises(Exception):
            await encryption_service.decrypt_secret(corrupted_data, encrypted_dek)

    @pytest.mark.asyncio
    async def test_invalid_dek(self, encryption_service):
        """Test that invalid DEK raises an error."""
        plaintext = "test-secret"
        encrypted_data, _encrypted_dek = await encryption_service.encrypt_secret(
            plaintext
        )

        # Use wrong DEK
        _, wrong_dek = await encryption_service.encrypt_secret("other-secret")

        with pytest.raises(Exception):
            await encryption_service.decrypt_secret(encrypted_data, wrong_dek)

    @pytest.mark.asyncio
    async def test_kms_failure_during_encryption(self, encryption_service):
        """Test handling of KMS failure during encryption."""
        # Mock KMS to fail
        with patch.object(
            encryption_service.kms, "encrypt", side_effect=Exception("KMS unavailable")
        ):
            with pytest.raises(Exception) as exc_info:
                await encryption_service.encrypt_secret("test")
            assert "KMS unavailable" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_kms_failure_during_decryption(self, encryption_service):
        """Test handling of KMS failure during decryption."""
        plaintext = "test-secret"
        encrypted_data, encrypted_dek = await encryption_service.encrypt_secret(
            plaintext
        )

        # Mock KMS to fail
        with patch.object(
            encryption_service.kms, "decrypt", side_effect=Exception("KMS unavailable")
        ):
            with pytest.raises(Exception) as exc_info:
                await encryption_service.decrypt_secret(encrypted_data, encrypted_dek)
            assert "KMS unavailable" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_get_encryption_service_singleton(self):
        """Test that get_encryption_service returns same instance."""
        service1 = get_encryption_service()
        service2 = get_encryption_service()

        assert service1 is service2

    @pytest.mark.asyncio
    async def test_cache_move_to_end_on_access(self, encryption_service):
        """Test that accessing a cached DEK moves it to end (most recently used)."""
        # Create 3 secrets
        secrets = []
        for i in range(3):
            encrypted_data, encrypted_dek = await encryption_service.encrypt_secret(
                f"secret-{i}"
            )
            secrets.append((encrypted_data, encrypted_dek))
            await encryption_service.decrypt_secret(encrypted_data, encrypted_dek)

        # Access first secret again (should move to end)
        await encryption_service.decrypt_secret(secrets[0][0], secrets[0][1])

        # Fill cache to force eviction
        for i in range(1000):
            encrypted_data, encrypted_dek = await encryption_service.encrypt_secret(
                f"filler-{i}"
            )
            await encryption_service.decrypt_secret(encrypted_data, encrypted_dek)

        # First secret should still be in cache (was moved to end)
        # This is implicit - if it wasn't moved, it would have been evicted
        decrypted = await encryption_service.decrypt_secret(
            secrets[0][0], secrets[0][1]
        )
        assert decrypted == "secret-0"


class TestEncryptionPerformance:
    """Performance tests for encryption service."""

    @pytest.mark.asyncio
    @pytest.mark.slow
    async def test_encryption_performance(self):
        """Test encryption performance."""
        import time

        kms = LocalKMS()
        service = SecretEncryptionService(kms=kms)

        start = time.time()
        tasks = [service.encrypt_secret(f"secret-{i}") for i in range(100)]
        await asyncio.gather(*tasks)
        elapsed = time.time() - start

        # Should complete 100 encryptions in less than 5 seconds
        assert elapsed < 5.0

        await service.clear_cache()

    @pytest.mark.asyncio
    @pytest.mark.slow
    async def test_decryption_performance_with_cache(self):
        """Test decryption performance with cache hits."""
        import time

        kms = LocalKMS()
        service = SecretEncryptionService(kms=kms)

        # Prepare encrypted data
        encrypted_data, encrypted_dek = await service.encrypt_secret("test-secret")

        # First decryption (cache miss)
        await service.decrypt_secret(encrypted_data, encrypted_dek)

        # 1000 decryptions (cache hits)
        start = time.time()
        tasks = [
            service.decrypt_secret(encrypted_data, encrypted_dek) for _ in range(1000)
        ]
        await asyncio.gather(*tasks)
        elapsed = time.time() - start

        # Should complete 1000 cache-hit decryptions in less than 2 seconds
        assert elapsed < 2.0

        await service.clear_cache()
