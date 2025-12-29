"""Tests for KMS module."""

import pytest

from cerebro.kms.local_kms import LocalPlaintextKMS
from cerebro.kms.factory import get_kms, get_available_kms_providers


class TestLocalPlaintextKMS:
    """Tests for LocalPlaintextKMS."""

    def test_init_with_default_key(self):
        """Test initialization with default key."""
        kms = LocalPlaintextKMS()
        assert kms.name == "local_plaintext"
        assert kms.secret_key is not None

    def test_init_with_custom_key(self):
        """Test initialization with custom key."""
        kms = LocalPlaintextKMS(secret_key="test-secret-key")
        assert kms.secret_key == "test-secret-key"

    @pytest.mark.asyncio
    async def test_encrypt_decrypt_cycle(self):
        """Test encrypt/decrypt roundtrip."""
        kms = LocalPlaintextKMS(secret_key="test-key")
        plaintext = b"Hello, World!"

        encrypted = await kms.encrypt(plaintext)
        assert encrypted != plaintext

        decrypted = await kms.decrypt(encrypted)
        assert decrypted == plaintext

    @pytest.mark.asyncio
    async def test_encrypt_different_inputs(self):
        """Test that different inputs produce different ciphertexts."""
        kms = LocalPlaintextKMS(secret_key="test-key")

        encrypted1 = await kms.encrypt(b"message1")
        encrypted2 = await kms.encrypt(b"message2")

        assert encrypted1 != encrypted2

    @pytest.mark.asyncio
    async def test_decrypt_with_wrong_key_fails(self):
        """Test that decryption with wrong key fails."""
        kms1 = LocalPlaintextKMS(secret_key="key1")
        kms2 = LocalPlaintextKMS(secret_key="key2")

        encrypted = await kms1.encrypt(b"secret data")

        with pytest.raises(Exception):
            await kms2.decrypt(encrypted)

    @pytest.mark.asyncio
    async def test_test_connection(self):
        """Test connection test passes."""
        kms = LocalPlaintextKMS(secret_key="test-key")
        result = await kms.test_connection()
        assert result is True

    @pytest.mark.asyncio
    async def test_empty_plaintext(self):
        """Test encrypting empty data."""
        kms = LocalPlaintextKMS(secret_key="test-key")
        plaintext = b""

        encrypted = await kms.encrypt(plaintext)
        decrypted = await kms.decrypt(encrypted)

        assert decrypted == plaintext

    @pytest.mark.asyncio
    async def test_large_plaintext(self):
        """Test encrypting large data."""
        kms = LocalPlaintextKMS(secret_key="test-key")
        plaintext = b"x" * 1024 * 1024  # 1MB

        encrypted = await kms.encrypt(plaintext)
        decrypted = await kms.decrypt(encrypted)

        assert decrypted == plaintext


class TestKMSFactory:
    """Tests for KMS factory functions."""

    def test_get_kms_returns_local_by_default(self, monkeypatch):
        """Test that get_kms returns local KMS by default."""
        monkeypatch.setattr("cerebro.kms.factory.settings.kms_provider", "local")
        kms = get_kms()
        assert kms.name == "local_plaintext"

    def test_get_available_providers_includes_local(self):
        """Test that local is always available."""
        providers = get_available_kms_providers()
        assert "local" in providers

    def test_get_kms_raises_on_unknown_provider(self, monkeypatch):
        """Test that unknown provider raises ValueError."""
        monkeypatch.setattr("cerebro.kms.factory.settings.kms_provider", "unknown")
        with pytest.raises(ValueError, match="Unknown KMS provider"):
            get_kms()
