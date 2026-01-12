"""Encryption utilities for SQLAlchemy models with envelope encryption.

This module provides helper classes and functions for encrypting sensitive
fields in SQLAlchemy models using envelope encryption (data encrypted with
a DEK, DEK encrypted with KEK).

Recommended pattern:
    class EmailConfig(Base, EncryptedFieldMixin):
        smtp_password: Mapped[Optional[bytes]] = mapped_column(LargeBinary)
        smtp_password_dek: Mapped[Optional[bytes]] = mapped_column(LargeBinary)

        async def get_smtp_password(self) -> Optional[str]:
            return await self.decrypt_field(self.smtp_password, self.smtp_password_dek)

        async def set_smtp_password(self, password: Optional[str]) -> None:
            self.smtp_password, self.smtp_password_dek = await self.encrypt_field(password)
"""

from cerebro.core.encryption import get_encryption_service


def create_encrypted_field_pair(
    field_name: str,
    data_column_name: str | None = None,
    dek_column_name: str | None = None,
) -> tuple[str, str]:
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

    async def encrypt_field(
        self, value: str | None
    ) -> tuple[bytes | None, bytes | None]:
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
        self, encrypted_data: bytes | None, encrypted_dek: bytes | None
    ) -> str | None:
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


