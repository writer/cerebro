"""Base KMS interface for envelope encryption."""

from abc import ABC, abstractmethod


class BaseKMS(ABC):
    """Base interface for Key Management Services."""
    
    @abstractmethod
    async def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt plaintext data with the KMS key."""
        pass
    
    @abstractmethod
    async def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt ciphertext data with the KMS key."""
        pass
    
    @abstractmethod
    async def test_connection(self) -> bool:
        """Test KMS connectivity and permissions."""
        pass
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Get KMS provider name."""
        pass
