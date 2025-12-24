"""HashiCorp Vault Transit Engine implementation."""

import base64
import logging
import os

import httpx

from .base import BaseKMS

logger = logging.getLogger(__name__)


class VaultTransitKMS(BaseKMS):
    """HashiCorp Vault Transit Engine implementation."""

    def __init__(
        self,
        vault_url: str,
        mount_path: str,
        key_name: str,
        token: str | None = None,
    ):
        """Initialize Vault Transit KMS.

        Args:
            vault_url: Vault server URL (e.g., https://vault.company.com)
            mount_path: Transit mount path (e.g., transit)
            key_name: Encryption key name
            token: Vault token (defaults to VAULT_TOKEN env var)
        """
        self.vault_url = vault_url.rstrip("/")
        self.mount_path = mount_path
        self.key_name = key_name
        self.token = token or os.getenv("VAULT_TOKEN")

        if not self.token:
            raise ValueError(
                "Vault token required (VAULT_TOKEN env var or token parameter)"
            )

        self.headers = {"X-Vault-Token": self.token, "Content-Type": "application/json"}

    @property
    def name(self) -> str:
        return "vault_transit"

    async def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt data with Vault Transit."""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.vault_url}/v1/{self.mount_path}/encrypt/{self.key_name}",
                    headers=self.headers,
                    json={"plaintext": base64.b64encode(plaintext).decode()},
                    timeout=30.0,
                )

                if response.status_code != 200:
                    raise Exception(
                        f"Vault encrypt failed: {response.status_code} {response.text}"
                    )

                data = response.json()
                if "errors" in data:
                    raise Exception(f"Vault encrypt errors: {data['errors']}")

                # Return the ciphertext (Vault format: "vault:v1:...")
                ciphertext = data["data"]["ciphertext"]
                return ciphertext.encode()

        except Exception as e:
            logger.error(f"Vault Transit encryption failed: {e}")
            raise

    async def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt data with Vault Transit."""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.vault_url}/v1/{self.mount_path}/decrypt/{self.key_name}",
                    headers=self.headers,
                    json={"ciphertext": ciphertext.decode()},
                    timeout=30.0,
                )

                if response.status_code != 200:
                    raise Exception(
                        f"Vault decrypt failed: {response.status_code} {response.text}"
                    )

                data = response.json()
                if "errors" in data:
                    raise Exception(f"Vault decrypt errors: {data['errors']}")

                # Decode the base64 plaintext
                plaintext_b64 = data["data"]["plaintext"]
                return base64.b64decode(plaintext_b64)

        except Exception as e:
            logger.error(f"Vault Transit decryption failed: {e}")
            raise

    async def test_connection(self) -> bool:
        """Test Vault connectivity and permissions."""
        try:
            # Test by encrypting/decrypting a small payload
            test_data = b"connection_test"
            encrypted = await self.encrypt(test_data)
            decrypted = await self.decrypt(encrypted)

            success = decrypted == test_data
            logger.info(
                f"Vault Transit connection test: {'passed' if success else 'failed'}"
            )
            return success

        except Exception as e:
            logger.error(f"Vault Transit connection test failed: {e}")
            return False
