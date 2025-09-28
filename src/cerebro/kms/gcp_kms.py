"""Google Cloud KMS implementation for envelope encryption."""

import logging
from typing import Optional

from google.cloud.kms_v1 import KeyManagementServiceAsyncClient
from google.cloud.kms_v1.types import EncryptRequest, DecryptRequest

from .base import BaseKMS

logger = logging.getLogger(__name__)


class GCPKMS(BaseKMS):
    """Google Cloud KMS implementation using customer-managed keys."""
    
    def __init__(
        self,
        key_name: str,
        credentials_path: Optional[str] = None
    ):
        """Initialize GCP KMS client.
        
        Args:
            key_name: Full resource name of the KMS key
                     projects/PROJECT_ID/locations/LOCATION/keyRings/RING_ID/cryptoKeys/KEY_ID
            credentials_path: Path to service account JSON file
        """
        self.key_name = key_name
        
        # Initialize async client
        client_options = {}
        if credentials_path:
            import os
            os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = credentials_path
        
        self._client = KeyManagementServiceAsyncClient()
    
    @property
    def name(self) -> str:
        return "gcp_kms"
    
    async def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt data with Google Cloud KMS."""
        try:
            request = EncryptRequest(
                name=self.key_name,
                plaintext=plaintext
            )
            
            response = await self._client.encrypt(request=request)
            return response.ciphertext
            
        except Exception as e:
            logger.error(f"GCP KMS encryption failed: {e}")
            raise
    
    async def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt data with Google Cloud KMS."""
        try:
            request = DecryptRequest(
                name=self.key_name,
                ciphertext=ciphertext
            )
            
            response = await self._client.decrypt(request=request)
            return response.plaintext
            
        except Exception as e:
            logger.error(f"GCP KMS decryption failed: {e}")
            raise
    
    async def test_connection(self) -> bool:
        """Test GCP KMS connectivity and permissions."""
        try:
            # Test by encrypting/decrypting a small payload
            test_data = b"connection_test"
            encrypted = await self.encrypt(test_data)
            decrypted = await self.decrypt(encrypted)
            
            return decrypted == test_data
            
        except Exception as e:
            logger.error(f"GCP KMS connection test failed: {e}")
            return False
