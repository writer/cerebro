"""Secret encryption service using envelope encryption with Fernet."""

import asyncio
import base64
import hashlib
import logging
import os
from collections import OrderedDict

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from cerebro.kms import BaseKMS, get_kms

logger = logging.getLogger(__name__)


class SecretEncryptionService:
    """Service for encrypting/decrypting secrets using envelope encryption.

    Envelope encryption architecture:
    1. Generate a unique DEK (Data Encryption Key) for each secret using Fernet
    2. Encrypt the secret with the DEK
    3. Encrypt the DEK with KMS KEK (Key Encryption Key)
    4. Store encrypted_secret + encrypted_dek together

    Benefits:
    - Secrets never stored in plaintext
    - KEK managed by KMS (AWS KMS, GCP KMS, Azure Key Vault, HashiCorp Vault)
    - DEK rotation without re-encrypting all secrets (just re-encrypt DEKs)
    - Works offline after DEK decryption
    """

    MAX_CACHE_SIZE = 1000  # Prevent memory leaks from unbounded cache growth

    def __init__(self, kms: BaseKMS | None = None):
        """Initialize encryption service.

        Args:
            kms: KMS provider for encrypting DEKs. If None, uses factory default.
        """
        self.kms = kms or get_kms()
        # Use OrderedDict for O(1) LRU operations (move_to_end is O(1))
        self._dek_cache: OrderedDict[bytes, Fernet] = OrderedDict()
        # Lock for thread-safe cache operations in async context
        self._cache_lock = asyncio.Lock()

    def _generate_dek(self) -> bytes:
        """Generate a new random Data Encryption Key.

        Returns:
            32-byte Fernet key (URL-safe base64-encoded)
        """
        return Fernet.generate_key()

    async def _get_fernet(self, dek: bytes) -> Fernet:
        """Get or create Fernet cipher for a DEK with thread-safe LRU cache eviction.

        Uses asyncio.Lock for thread safety and OrderedDict for O(1) LRU operations.

        Args:
            dek: Data Encryption Key

        Returns:
            Fernet cipher instance
        """
        async with self._cache_lock:
            if dek in self._dek_cache:
                # Move to end (most recently used) - O(1) operation
                self._dek_cache.move_to_end(dek)
                return self._dek_cache[dek]

            # Not in cache, create new entry
            fernet = Fernet(dek)

            # Evict oldest entry if cache is full
            if len(self._dek_cache) >= self.MAX_CACHE_SIZE:
                # popitem(last=False) removes oldest (first) item - O(1)
                _oldest_dek, _ = self._dek_cache.popitem(last=False)
                logger.debug(f"Evicted DEK from cache (size: {len(self._dek_cache)})")

            # Add to cache
            self._dek_cache[dek] = fernet

            return fernet

    async def encrypt_secret(self, plaintext: str) -> tuple[bytes, bytes]:
        """Encrypt a secret using envelope encryption.

        Args:
            plaintext: Secret to encrypt

        Returns:
            Tuple of (encrypted_secret, encrypted_dek)

        Example:
            encrypted_data, encrypted_dek = await service.encrypt_secret("my-password")
            # Store both encrypted_data and encrypted_dek in database
        """
        try:
            # Step 1: Generate a unique DEK for this secret
            dek = self._generate_dek()

            # Step 2: Encrypt the secret with the DEK
            fernet = await self._get_fernet(dek)
            encrypted_secret = fernet.encrypt(plaintext.encode("utf-8"))

            # Step 3: Encrypt the DEK with KMS KEK
            encrypted_dek = await self.kms.encrypt(dek)

            logger.debug(
                f"Encrypted secret (length={len(plaintext)}) with envelope encryption"
            )
            return encrypted_secret, encrypted_dek

        except Exception as e:
            logger.error(f"Failed to encrypt secret: {e}", exc_info=True)
            raise

    async def decrypt_secret(
        self, encrypted_secret: bytes, encrypted_dek: bytes
    ) -> str:
        """Decrypt a secret using envelope encryption with audit logging.

        Args:
            encrypted_secret: Encrypted secret data
            encrypted_dek: Encrypted Data Encryption Key

        Returns:
            Decrypted plaintext secret

        Example:
            plaintext = await service.decrypt_secret(encrypted_data, encrypted_dek)
        """
        try:
            # Audit log: Decryption attempt
            logger.info(
                "secret_decryption_attempt",
                extra={
                    "kms_provider": self.kms.name,
                    "encrypted_dek_hash": hashlib.sha256(encrypted_dek).hexdigest()[
                        :16
                    ],
                    "encrypted_data_size": len(encrypted_secret),
                },
            )

            # Step 1: Decrypt the DEK using KMS KEK
            dek = await self.kms.decrypt(encrypted_dek)

            # Step 2: Decrypt the secret using the DEK (now async for thread-safe cache)
            fernet = await self._get_fernet(dek)
            plaintext_bytes = fernet.decrypt(encrypted_secret)

            # Audit log: Successful decryption
            logger.info(
                "secret_decryption_success",
                extra={
                    "kms_provider": self.kms.name,
                    "decrypted_length": len(plaintext_bytes),
                    "cache_stats": self.get_cache_stats(),
                },
            )

            return plaintext_bytes.decode("utf-8")

        except Exception as e:
            # Audit log: Decryption failure (security-relevant)
            logger.error(
                "secret_decryption_failed",
                extra={
                    "kms_provider": self.kms.name,
                    "error_type": type(e).__name__,
                    "error": str(e),
                },
                exc_info=True,
            )
            raise

    async def rotate_dek(
        self, encrypted_secret: bytes, old_encrypted_dek: bytes
    ) -> tuple[bytes, bytes]:
        """Rotate the DEK for a secret without changing the secret itself.

        This is useful for key rotation compliance requirements.

        Args:
            encrypted_secret: Current encrypted secret
            old_encrypted_dek: Current encrypted DEK

        Returns:
            Tuple of (encrypted_secret, new_encrypted_dek)
        """
        try:
            # Step 1: Decrypt with old DEK
            plaintext = await self.decrypt_secret(encrypted_secret, old_encrypted_dek)

            # Step 2: Re-encrypt with new DEK
            new_encrypted_secret, new_encrypted_dek = await self.encrypt_secret(
                plaintext
            )

            logger.info("Successfully rotated DEK for secret")
            return new_encrypted_secret, new_encrypted_dek

        except Exception as e:
            logger.error(f"Failed to rotate DEK: {e}", exc_info=True)
            raise

    async def test_encryption(self) -> bool:
        """Test that encryption/decryption is working correctly.

        Returns:
            True if encryption is working, False otherwise
        """
        try:
            # Test KMS connectivity
            kms_ok = await self.kms.test_connection()
            if not kms_ok:
                logger.error(f"KMS connectivity test failed for {self.kms.name}")
                return False

            # Test envelope encryption roundtrip
            test_secret = "test-encryption-" + os.urandom(16).hex()
            encrypted_data, encrypted_dek = await self.encrypt_secret(test_secret)
            decrypted_secret = await self.decrypt_secret(encrypted_data, encrypted_dek)

            if decrypted_secret != test_secret:
                logger.error("Encryption roundtrip test failed - decrypted != original")
                return False

            logger.info(f"Encryption service test passed (KMS: {self.kms.name})")
            return True

        except Exception as e:
            logger.error(f"Encryption service test failed: {e}", exc_info=True)
            return False

    async def clear_cache(self):
        """Clear the DEK cache. Use after key rotation or for security."""
        async with self._cache_lock:
            cache_size = len(self._dek_cache)
            self._dek_cache.clear()
            logger.info(f"Cleared DEK cache ({cache_size} entries)")

    def get_cache_stats(self) -> dict:
        """Get cache statistics for monitoring.

        Returns:
            Dictionary with cache size, max size, and hit rate info
        """
        return {
            "current_size": len(self._dek_cache),
            "max_size": self.MAX_CACHE_SIZE,
            "utilization_percent": (len(self._dek_cache) / self.MAX_CACHE_SIZE) * 100,
        }


class FallbackEncryptionService:
    """Fallback encryption service for backwards compatibility.

    Uses direct Fernet encryption with SECRET_KEY (no envelope encryption).
    This is less secure but simpler for development/testing.

    DEPRECATED: Use SecretEncryptionService for production.
    """

    def __init__(self, secret_key: str | None = None):
        """Initialize fallback encryption service.

        Args:
            secret_key: Base secret key. If None, uses SECRET_KEY env var.
        """
        secret_key = secret_key or os.getenv("SECRET_KEY")
        if not secret_key:
            raise ValueError(
                "SECRET_KEY environment variable required for fallback encryption"
            )

        # Derive Fernet key from SECRET_KEY using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"cerebro-fallback-salt",  # Static salt for deterministic key
            iterations=100000,
            backend=default_backend(),
        )
        derived_key = kdf.derive(secret_key.encode("utf-8"))
        fernet_key = base64.urlsafe_b64encode(derived_key)
        self.fernet = Fernet(fernet_key)

    def encrypt_secret(self, plaintext: str) -> bytes:
        """Encrypt secret with direct Fernet encryption.

        Args:
            plaintext: Secret to encrypt

        Returns:
            Encrypted secret (no separate DEK)
        """
        return self.fernet.encrypt(plaintext.encode("utf-8"))

    def decrypt_secret(self, encrypted_secret: bytes) -> str:
        """Decrypt secret with direct Fernet encryption.

        Args:
            encrypted_secret: Encrypted secret

        Returns:
            Decrypted plaintext
        """
        return self.fernet.decrypt(encrypted_secret).decode("utf-8")


# Global service instance
_encryption_service: SecretEncryptionService | None = None


def get_encryption_service() -> SecretEncryptionService:
    """Get global encryption service instance.

    Returns:
        SecretEncryptionService instance
    """
    global _encryption_service
    if _encryption_service is None:
        _encryption_service = SecretEncryptionService()
    return _encryption_service


def get_fallback_encryption_service() -> FallbackEncryptionService:
    """Get fallback encryption service (deprecated).

    Returns:
        FallbackEncryptionService instance
    """
    return FallbackEncryptionService()
