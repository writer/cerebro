"""Local KMS implementation for development/testing."""

import base64
import hashlib
import logging
import os
from typing import Optional

from cryptography.fernet import Fernet

from .base import BaseKMS

logger = logging.getLogger(__name__)


class LocalPlaintextKMS(BaseKMS):
    """Local KMS implementation using Fernet for development."""

    def __init__(self, secret_key: Optional[str] = None):
        """Initialize local KMS with Fernet encryption."""
        self.secret_key: str = secret_key or os.getenv("SECRET_KEY") or "default-dev-key"

        # Generate Fernet key from secret
        key_material = hashlib.sha256(self.secret_key.encode()).digest()
        fernet_key = base64.urlsafe_b64encode(key_material)
        self.fernet = Fernet(fernet_key)

        logger.warning("Using LocalPlaintextKMS - NOT SUITABLE FOR PRODUCTION")

    @property
    def name(self) -> str:
        return "local_plaintext"

    async def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt data with local Fernet key."""
        try:
            return self.fernet.encrypt(plaintext)
        except Exception as e:
            logger.error(f"Local KMS encryption failed: {e}")
            raise

    async def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt data with local Fernet key."""
        try:
            return self.fernet.decrypt(ciphertext)
        except Exception as e:
            logger.error(f"Local KMS decryption failed: {e}")
            raise

    async def test_connection(self) -> bool:
        """Test local KMS functionality."""
        try:
            # Test encrypt/decrypt cycle
            test_data = b"connection_test"
            encrypted = await self.encrypt(test_data)
            decrypted = await self.decrypt(encrypted)

            success = decrypted == test_data
            logger.info(
                f"Local KMS connection test: {'passed' if success else 'failed'}"
            )
            return success

        except Exception as e:
            logger.error(f"Local KMS connection test failed: {e}")
            return False


class LocalKMS(LocalPlaintextKMS):
    """Backward-compatible alias for the legacy LocalKMS name."""
