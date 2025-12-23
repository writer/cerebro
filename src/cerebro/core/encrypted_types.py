"""SQLAlchemy type decorators for encrypted fields with envelope encryption.

DEPRECATION WARNING: The TypeDecorator approach (EncryptedString, EncryptedText) is
deprecated and should not be used. Use explicit async get/set methods on models instead.

Recommended pattern:
    class EmailConfig(Base):
        smtp_password: Mapped[Optional[bytes]] = mapped_column(LargeBinary)
        smtp_password_dek: Mapped[Optional[bytes]] = mapped_column(LargeBinary)

        async def get_smtp_password(self) -> Optional[str]:
            if not self.smtp_password or not self.smtp_password_dek:
                return None
            service = get_encryption_service()
            return await service.decrypt_secret(self.smtp_password, self.smtp_password_dek)

        async def set_smtp_password(self, password: Optional[str]) -> None:
            if password is None:
                self.smtp_password = None
                self.smtp_password_dek = None
                return
            service = get_encryption_service()
            self.smtp_password, self.smtp_password_dek = await service.encrypt_secret(password)
"""

import asyncio
from typing import Optional, Tuple

from sqlalchemy import Column, LargeBinary, TypeDecorator

from cerebro.core.encryption import (
    get_encryption_service,
)


class EncryptedString(TypeDecorator):
    """DEPRECATED: SQLAlchemy type for encrypted string fields.

    DO NOT USE - This TypeDecorator has limitations:
    - Runs in sync context, problematic for async encryption
    - Cannot handle DEK storage properly
    - Fallback to plaintext on error is insecure

    Use explicit async get/set methods on models instead (see module docstring).
    """

    impl = LargeBinary
    cache_ok = True

    def process_bind_param(self, value: Optional[str], dialect) -> Optional[bytes]:
        raise NotImplementedError(
            "EncryptedString TypeDecorator is deprecated. "
            "Use explicit async get/set methods on models instead."
        )

    def process_result_value(self, value: Optional[bytes], dialect) -> Optional[str]:
        raise NotImplementedError(
            "EncryptedString TypeDecorator is deprecated. "
            "Use explicit async get/set methods on models instead."
        )


class EncryptedText(EncryptedString):
    """DEPRECATED: Alias for EncryptedString. DO NOT USE."""

    pass


def create_encrypted_field_pair(
    field_name: str,
    data_column_name: Optional[str] = None,
    dek_column_name: Optional[str] = None,
) -> Tuple[str, str]:
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
        self, value: Optional[str]
    ) -> tuple[Optional[bytes], Optional[bytes]]:
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
        self, encrypted_data: Optional[bytes], encrypted_dek: Optional[bytes]
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
        self, encrypted_data: Optional[bytes], encrypted_dek: Optional[bytes]
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


def encrypt_field_helper(
    value: Optional[str],
) -> tuple[Optional[bytes], Optional[bytes]]:
    """DEPRECATED: Synchronous helper to encrypt a field value.

    DO NOT USE - This function uses deprecated asyncio.get_event_loop().
    Use async methods directly on models instead.

    Args:
        value: Plaintext value

    Returns:
        Tuple of (encrypted_data, encrypted_dek)
    """
    raise NotImplementedError(
        "encrypt_field_helper is deprecated. "
        "Use async model methods like 'await model.set_smtp_password(value)' instead."
    )


def decrypt_field_helper(
    encrypted_data: Optional[bytes], encrypted_dek: Optional[bytes]
) -> Optional[str]:
    """DEPRECATED: Synchronous helper to decrypt a field value.

    DO NOT USE - This function uses deprecated asyncio.get_event_loop().
    Use async methods directly on models instead.

    Args:
        encrypted_data: Encrypted data
        encrypted_dek: Encrypted DEK

    Returns:
        Decrypted plaintext
    """
    raise NotImplementedError(
        "decrypt_field_helper is deprecated. "
        "Use async model methods like 'await model.get_smtp_password()' instead."
    )
