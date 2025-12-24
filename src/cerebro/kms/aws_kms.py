"""AWS KMS implementation for envelope encryption."""

import asyncio
import logging

import boto3
from botocore.exceptions import ClientError

from .base import BaseKMS

logger = logging.getLogger(__name__)


class AWSKMS(BaseKMS):
    """AWS KMS implementation using customer-managed keys."""

    def __init__(
        self,
        key_id: str,
        region: str,
        access_key_id: str | None = None,
        secret_access_key: str | None = None,
    ):
        """Initialize AWS KMS client."""
        self.key_id = key_id
        self.region = region

        session_kwargs = {"region_name": region}
        if access_key_id and secret_access_key:
            session_kwargs.update(
                {
                    "aws_access_key_id": access_key_id,
                    "aws_secret_access_key": secret_access_key,
                }
            )

        self.session = boto3.Session(**session_kwargs)
        self._client = self.session.client("kms")

    @property
    def name(self) -> str:
        return "aws_kms"

    async def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt data with AWS KMS."""

        def _encrypt():
            try:
                response = self._client.encrypt(KeyId=self.key_id, Plaintext=plaintext)
                return response["CiphertextBlob"]
            except ClientError as e:
                logger.error(f"AWS KMS encryption failed: {e}")
                raise

        return await asyncio.to_thread(_encrypt)

    async def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt data with AWS KMS."""

        def _decrypt():
            try:
                response = self._client.decrypt(CiphertextBlob=ciphertext)
                return response["Plaintext"]
            except ClientError as e:
                logger.error(f"AWS KMS decryption failed: {e}")
                raise

        return await asyncio.to_thread(_decrypt)

    async def test_connection(self) -> bool:
        """Test AWS KMS connectivity and permissions."""

        def _test():
            try:
                # Test by describing the key
                self._client.describe_key(KeyId=self.key_id)
                return True
            except ClientError as e:
                logger.error(f"AWS KMS connection test failed: {e}")
                return False

        return await asyncio.to_thread(_test)
