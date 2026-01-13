"""Azure Key Vault implementation for envelope encryption."""

import structlog
from azure.identity import DefaultAzureCredential
from azure.keyvault.keys import KeyClient
from azure.keyvault.keys.crypto import CryptographyClient, EncryptionAlgorithm

from .base import BaseKMS

logger = structlog.get_logger(__name__)


class AzureKeyVaultKMS(BaseKMS):
    """Azure Key Vault implementation using customer-managed keys."""

    def __init__(
        self,
        vault_url: str,
        key_name: str,
        credential: DefaultAzureCredential | None = None,
    ):
        """Initialize Azure Key Vault client.

        Args:
            vault_url: Key Vault URL (e.g., https://vault.vault.azure.net/)
            key_name: Name of the encryption key
            credential: Azure credential (defaults to DefaultAzureCredential)
        """
        self.vault_url = vault_url
        self.key_name = key_name

        # Initialize credential and clients
        self.credential = credential or DefaultAzureCredential()
        self.key_client = KeyClient(vault_url=vault_url, credential=self.credential)

        # Get the key for crypto operations
        self.key = self.key_client.get_key(key_name)
        self.crypto_client = CryptographyClient(self.key, credential=self.credential)

    @property
    def name(self) -> str:
        return "azure_keyvault"

    async def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt data with Azure Key Vault."""
        try:
            # Azure Key Vault crypto operations are sync
            import asyncio

            def _encrypt() -> bytes:
                result: bytes = self.crypto_client.encrypt(
                    EncryptionAlgorithm.rsa_oaep_256, plaintext
                ).ciphertext
                return result

            return await asyncio.to_thread(_encrypt)

        except Exception as e:
            logger.error("Azure Key Vault encryption failed", error=str(e))
            raise

    async def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt data with Azure Key Vault."""
        try:
            import asyncio

            def _decrypt() -> bytes:
                result: bytes = self.crypto_client.decrypt(
                    EncryptionAlgorithm.rsa_oaep_256, ciphertext
                ).plaintext
                return result

            return await asyncio.to_thread(_decrypt)

        except Exception as e:
            logger.error("Azure Key Vault decryption failed", error=str(e))
            raise

    async def test_connection(self) -> bool:
        """Test Azure Key Vault connectivity and permissions."""
        try:
            # Test by listing keys (requires read permission)
            import asyncio

            def _test() -> bool:
                keys = list(self.key_client.list_properties_of_keys())
                return len(keys) >= 0  # Should not raise exception

            await asyncio.to_thread(_test)
            logger.info("Azure Key Vault connection test passed")
            return True

        except Exception as e:
            logger.error("Azure Key Vault connection test failed", error=str(e))
            return False
