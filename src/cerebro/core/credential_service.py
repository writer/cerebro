"""Secure credential management for providers."""

import base64
import json
import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from cryptography.fernet import Fernet
from sqlalchemy import Boolean, DateTime, LargeBinary, String, and_, select
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from .config import settings
from .database import Base

logger = logging.getLogger(__name__)


@dataclass
class ProviderCredentials:
    """Credentials for a provider."""

    provider: str
    account_external_id: str
    credentials: dict[str, Any]
    expires_at: datetime | None = None
    metadata: dict[str, Any] | None = None


class ProviderCredentialStore(Base):
    """Encrypted storage for provider credentials."""

    __tablename__ = "provider_credentials"

    credential_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    account_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True))
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    encrypted_credentials: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    encrypted_dek: Mapped[bytes] = mapped_column(
        LargeBinary, nullable=False
    )  # Data Encryption Key
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now(), onupdate=func.now()
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class CredentialService:
    """Service for managing provider credentials with envelope encryption."""

    def __init__(self, db_session: AsyncSession, kms=None):
        """Initialize credential service.

        Args:
            db_session: Database session
            kms: KMS instance (will be injected by caller)
        """
        self.db = db_session
        self.kms = kms

    @staticmethod
    def _generate_dek() -> bytes:
        """Generate a data encryption key for envelope encryption."""
        # Generate 32 random bytes and encode for Fernet
        return base64.urlsafe_b64encode(secrets.token_bytes(32))

    async def _encrypt_with_envelope(self, credentials: dict) -> tuple[bytes, bytes]:
        """Encrypt credentials using envelope encryption pattern."""
        # 1. Generate random DEK
        dek = self._generate_dek()

        # 2. Encrypt credentials with DEK
        fernet = Fernet(dek)
        credentials_json = json.dumps(credentials)
        encrypted_credentials = fernet.encrypt(credentials_json.encode())

        # 3. Encrypt DEK with KMS
        encrypted_dek = await self.kms.encrypt(dek)

        return encrypted_credentials, encrypted_dek

    async def _decrypt_with_envelope(
        self, encrypted_credentials: bytes, encrypted_dek: bytes
    ) -> dict:
        """Decrypt credentials using envelope encryption pattern."""
        # 1. Decrypt DEK with KMS
        dek = await self.kms.decrypt(encrypted_dek)

        # 2. Decrypt credentials with DEK
        fernet = Fernet(dek)
        credentials_json = fernet.decrypt(encrypted_credentials)

        return json.loads(credentials_json.decode())

    async def store_credentials(
        self,
        account_id: UUID,
        provider: str,
        credentials: dict[str, Any],
        expires_at: datetime | None = None,
    ) -> bool:
        """Store encrypted provider credentials using envelope encryption."""
        try:
            # Encrypt credentials with envelope encryption
            encrypted_credentials, encrypted_dek = await self._encrypt_with_envelope(
                credentials
            )

            # Check if credentials already exist
            stmt = select(ProviderCredentialStore).where(
                and_(
                    ProviderCredentialStore.account_id == account_id,
                    ProviderCredentialStore.provider == provider,
                    ProviderCredentialStore.is_active,
                )
            )
            existing = await self.db.scalar(stmt)

            if existing:
                # Update existing credentials
                existing.encrypted_credentials = encrypted_credentials
                existing.encrypted_dek = encrypted_dek
                existing.expires_at = expires_at
                existing.updated_at = datetime.utcnow()
            else:
                # Create new credentials
                new_creds = ProviderCredentialStore(
                    account_id=account_id,
                    provider=provider,
                    encrypted_credentials=encrypted_credentials,
                    encrypted_dek=encrypted_dek,
                    expires_at=expires_at,
                )
                self.db.add(new_creds)

            await self.db.commit()
            logger.info(f"Stored encrypted credentials for provider {provider}")
            return True

        except Exception as e:
            logger.error(f"Failed to store credentials for {provider}: {e}")
            await self.db.rollback()
            return False

    async def get_credentials(
        self, account_id: UUID, provider: str
    ) -> ProviderCredentials | None:
        """Retrieve and decrypt provider credentials."""
        try:
            stmt = select(ProviderCredentialStore).where(
                and_(
                    ProviderCredentialStore.account_id == account_id,
                    ProviderCredentialStore.provider == provider,
                    ProviderCredentialStore.is_active,
                )
            )
            cred_store = await self.db.scalar(stmt)

            if not cred_store:
                return None

            # Check expiration
            if cred_store.expires_at and cred_store.expires_at < datetime.utcnow():
                logger.warning(f"Credentials for {provider} have expired")
                return None

            # Decrypt credentials using envelope encryption
            credentials = await self._decrypt_with_envelope(
                cred_store.encrypted_credentials, cred_store.encrypted_dek
            )

            return ProviderCredentials(
                provider=provider,
                account_external_id=str(account_id),
                credentials=credentials,
                expires_at=cred_store.expires_at,
            )

        except Exception as e:
            logger.error(f"Failed to retrieve credentials for {provider}: {e}")
            return None

    async def delete_credentials(self, account_id: UUID, provider: str) -> bool:
        """Delete provider credentials."""
        try:
            stmt = select(ProviderCredentialStore).where(
                and_(
                    ProviderCredentialStore.account_id == account_id,
                    ProviderCredentialStore.provider == provider,
                )
            )
            cred_store = await self.db.scalar(stmt)

            if cred_store:
                cred_store.is_active = False
                await self.db.commit()
                logger.info(f"Deleted credentials for provider {provider}")
                return True

            return False

        except Exception as e:
            logger.error(f"Failed to delete credentials for {provider}: {e}")
            return False

    async def rotate_credentials(
        self, account_id: UUID, provider: str, new_credentials: dict[str, Any]
    ) -> bool:
        """Rotate provider credentials."""
        # Store new credentials
        success = await self.store_credentials(
            account_id,
            provider,
            new_credentials,
            expires_at=datetime.utcnow() + timedelta(days=90),  # 90-day rotation
        )

        if success:
            logger.info(f"Rotated credentials for provider {provider}")

        return success

    async def get_provider_credentials_for_collection(
        self, account_id: UUID, provider: str
    ) -> dict[str, Any]:
        """Get provider credentials formatted for collection use."""
        creds = await self.get_credentials(account_id, provider)

        if not creds:
            # Fall back to environment variables
            logger.warning(
                f"No stored credentials for {provider}, falling back to environment"
            )
            return self._get_credentials_from_environment(provider)

        return creds.credentials

    def _get_credentials_from_environment(self, provider: str) -> dict[str, Any]:
        """Get credentials from environment variables as fallback."""
        if provider == "github":
            return {"token": settings.github_token}
        elif provider == "aws":
            return {
                "access_key_id": settings.aws_access_key_id,
                "secret_access_key": settings.aws_secret_access_key,
                "region": settings.aws_default_region,
            }
        elif provider == "gcp":
            return {
                "service_account_path": settings.google_application_credentials,
                "project_id": settings.gcp_project_id,
            }
        elif provider == "google_workspace":
            return {
                "admin_email": settings.google_workspace_admin_email,
                "customer_id": settings.google_workspace_customer_id,
            }
        else:
            return {}

    async def test_credentials(
        self, account_id: UUID, provider: str, provider_registry=None
    ) -> bool:
        """Test if provider credentials are valid.

        Args:
            account_id: Account UUID
            provider: Provider name
            provider_registry: Provider registry instance (injected by caller)
        """
        if not provider_registry:
            raise ValueError("Provider registry must be injected by caller")

        try:
            # Get credentials
            credentials = await self.get_provider_credentials_for_collection(
                account_id, provider
            )

            if not credentials:
                return False

            # Create provider instance
            provider_instance = provider_registry.create_provider(
                provider, account_id=str(account_id), **credentials
            )

            # Test authentication
            return await provider_instance.authenticate()

        except Exception as e:
            logger.error(f"Credential test failed for {provider}: {e}")
            return False
