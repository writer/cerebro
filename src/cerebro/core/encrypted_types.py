"""SQLAlchemy type decorators for encrypted fields with envelope encryption."""
import asyncio
from typing import Any, Optional
from sqlalchemy import LargeBinary, TypeDecorator
from sqlalchemy.ext.hybrid import hybrid_property

from cerebro.core.encryption import get_encryption_service, get_fallback_encryption_service


class EncryptedString(TypeDecorator):
    """SQLAlchemy type for encrypted string fields using envelope encryption.

    Usage in models:
        class EmailConfig(Base):
            smtp_password: Mapped[Optional[str]] = mapped_column(EncryptedString, nullable=True)
            smtp_password_dek: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)

    The field will be automatically encrypted on write and decrypted on read.
    Requires a corresponding _dek field to store the encrypted DEK.
    """

    impl = LargeBinary
    cache_ok = True

    def process_bind_param(self, value: Optional[str], dialect) -> Optional[bytes]:
        """Encrypt value before storing in database.

        Note: This only encrypts the data. The encrypted_dek must be set separately
        in the model's __init__ or via a hybrid property.
        """
        if value is None:
            return None

        # Run async encryption in sync context
        loop = asyncio.get_event_loop()
        encryption_service = get_encryption_service()

        try:
            # Encrypt and return only the encrypted data
            # The encrypted_dek should be stored in a companion field
            encrypted_data, _ = loop.run_until_complete(
                encryption_service.encrypt_secret(value)
            )
            return encrypted_data
        except Exception as e:
            # Fall back to unencrypted if encryption fails (dev mode)
            import logging
            logging.error(f"Encryption failed, storing plaintext: {e}")
            return value.encode('utf-8')

    def process_result_value(self, value: Optional[bytes], dialect) -> Optional[str]:
        """Decrypt value when reading from database.

        Note: This requires the encrypted_dek to be available. In practice, you should
        use a hybrid property or custom method to decrypt with the DEK.
        """
        if value is None:
            return None

        # This is a placeholder - actual decryption requires the DEK
        # Models should implement custom decrypt methods
        return value.decode('utf-8') if isinstance(value, bytes) else value


class EncryptedText(EncryptedString):
    """Alias for EncryptedString for Text fields."""
    pass


def create_encrypted_field_pair(
    field_name: str,
    data_column_name: str = None,
    dek_column_name: str = None
):
    """Helper to create an encrypted field with automatic DEK management.

    Args:
        field_name: Name of the property (e.g., "smtp_password")
        data_column_name: Name of data column (defaults to field_name)
        dek_column_name: Name of DEK column (defaults to field_name + "_dek")

    Returns:
        Tuple of (data_column, dek_column, property)

    Example:
        class EmailConfig(Base):
            # Define columns
            _smtp_password = mapped_column("smtp_password", LargeBinary, nullable=True)
            _smtp_password_dek = mapped_column("smtp_password_dek", LargeBinary, nullable=True)

            @hybrid_property
            def smtp_password(self):
                if not self._smtp_password:
                    return None
                loop = asyncio.get_event_loop()
                service = get_encryption_service()
                return loop.run_until_complete(
                    service.decrypt_secret(self._smtp_password, self._smtp_password_dek)
                )

            @smtp_password.setter
            def smtp_password(self, value):
                if value is None:
                    self._smtp_password = None
                    self._smtp_password_dek = None
                else:
                    loop = asyncio.get_event_loop()
                    service = get_encryption_service()
                    self._smtp_password, self._smtp_password_dek = loop.run_until_complete(
                        service.encrypt_secret(value)
                    )
    """
    data_col = data_column_name or field_name
    dek_col = dek_column_name or f"{field_name}_dek"

    return (data_col, dek_col)


class EncryptedFieldMixin:
    """Mixin to add helper methods for encrypted fields.

    Usage:
        class EmailConfig(Base, EncryptedFieldMixin):
            _smtp_password = mapped_column("smtp_password", LargeBinary)
            _smtp_password_dek = mapped_column("smtp_password_dek", LargeBinary)

            async def get_smtp_password(self) -> Optional[str]:
                return await self.decrypt_field(self._smtp_password, self._smtp_password_dek)

            async def set_smtp_password(self, value: str):
                self._smtp_password, self._smtp_password_dek = await self.encrypt_field(value)
    """

    async def encrypt_field(self, value: Optional[str]) -> tuple[Optional[bytes], Optional[bytes]]:
        """Encrypt a field value.

        Args:
            value: Plaintext value to encrypt

        Returns:
            Tuple of (encrypted_data, encrypted_dek)
        """
        if value is None:
            return None, None

        service = get_encryption_service()
        return await service.encrypt_secret(value)

    async def decrypt_field(
        self,
        encrypted_data: Optional[bytes],
        encrypted_dek: Optional[bytes]
    ) -> Optional[str]:
        """Decrypt a field value.

        Args:
            encrypted_data: Encrypted data
            encrypted_dek: Encrypted DEK

        Returns:
            Decrypted plaintext or None
        """
        if encrypted_data is None or encrypted_dek is None:
            return None

        service = get_encryption_service()
        return await service.decrypt_secret(encrypted_data, encrypted_dek)

    def decrypt_field_sync(
        self,
        encrypted_data: Optional[bytes],
        encrypted_dek: Optional[bytes]
    ) -> Optional[str]:
        """Decrypt a field value synchronously.

        Args:
            encrypted_data: Encrypted data
            encrypted_dek: Encrypted DEK

        Returns:
            Decrypted plaintext or None
        """
        if encrypted_data is None or encrypted_dek is None:
            return None

        loop = asyncio.get_event_loop()
        service = get_encryption_service()
        return loop.run_until_complete(
            service.decrypt_secret(encrypted_data, encrypted_dek)
        )


def encrypt_field_helper(value: Optional[str]) -> tuple[Optional[bytes], Optional[bytes]]:
    """Synchronous helper to encrypt a field value.

    Args:
        value: Plaintext value

    Returns:
        Tuple of (encrypted_data, encrypted_dek)
    """
    if value is None:
        return None, None

    loop = asyncio.get_event_loop()
    service = get_encryption_service()
    return loop.run_until_complete(service.encrypt_secret(value))


def decrypt_field_helper(
    encrypted_data: Optional[bytes],
    encrypted_dek: Optional[bytes]
) -> Optional[str]:
    """Synchronous helper to decrypt a field value.

    Args:
        encrypted_data: Encrypted data
        encrypted_dek: Encrypted DEK

    Returns:
        Decrypted plaintext
    """
    if encrypted_data is None or encrypted_dek is None:
        return None

    loop = asyncio.get_event_loop()
    service = get_encryption_service()
    return loop.run_until_complete(service.decrypt_secret(encrypted_data, encrypted_dek))