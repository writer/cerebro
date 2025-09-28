"""Secure credential management for providers."""

from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from datetime import datetime, timedelta
import logging
import json
import base64
import os

from cryptography.fernet import Fernet
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from .database import Base
from .config import settings

logger = logging.getLogger(__name__)


@dataclass
class ProviderCredentials:
    """Credentials for a provider."""
    provider: str
    account_external_id: str
    credentials: Dict[str, Any]
    expires_at: Optional[datetime] = None
    metadata: Optional[Dict[str, Any]] = None


class ProviderCredentialStore(Base):
    """Encrypted storage for provider credentials."""
    __tablename__ = "provider_credentials"
    
    credential_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    account_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True))
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    encrypted_credentials: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now(), onupdate=func.now())
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class CredentialService:
    """Service for managing provider credentials securely."""
    
    def __init__(self, db_session: AsyncSession):
        """Initialize credential service."""
        self.db = db_session
        self._fernet = self._get_encryption_key()
    
    def _get_encryption_key(self) -> Fernet:
        """Get or create encryption key for credentials."""
        # In production, this should come from a key management service
        key_env = os.getenv("CREDENTIAL_ENCRYPTION_KEY")
        
        if key_env:
            key = key_env.encode()
        else:
            # Generate deterministic key from secret_key for development
            import hashlib
            key_material = hashlib.sha256(settings.secret_key.encode()).digest()
            key = base64.urlsafe_b64encode(key_material)
        
        return Fernet(key)
    
    async def store_credentials(
        self,
        account_id: UUID,
        provider: str,
        credentials: Dict[str, Any],
        expires_at: Optional[datetime] = None
    ) -> bool:
        """Store encrypted provider credentials."""
        try:
            # Encrypt credentials
            credentials_json = json.dumps(credentials)
            encrypted_data = self._fernet.encrypt(credentials_json.encode())
            
            # Check if credentials already exist
            stmt = select(ProviderCredentialStore).where(
                and_(
                    ProviderCredentialStore.account_id == account_id,
                    ProviderCredentialStore.provider == provider,
                    ProviderCredentialStore.is_active == True
                )
            )
            existing = await self.db.scalar(stmt)
            
            if existing:
                # Update existing credentials
                existing.encrypted_credentials = encrypted_data
                existing.expires_at = expires_at
                existing.updated_at = datetime.utcnow()
            else:
                # Create new credentials
                new_creds = ProviderCredentialStore(
                    account_id=account_id,
                    provider=provider,
                    encrypted_credentials=encrypted_data,
                    expires_at=expires_at
                )
                self.db.add(new_creds)
            
            await self.db.commit()
            logger.info(f"Stored credentials for provider {provider}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to store credentials for {provider}: {e}")
            await self.db.rollback()
            return False
    
    async def get_credentials(
        self,
        account_id: UUID,
        provider: str
    ) -> Optional[ProviderCredentials]:
        """Retrieve and decrypt provider credentials."""
        try:
            stmt = select(ProviderCredentialStore).where(
                and_(
                    ProviderCredentialStore.account_id == account_id,
                    ProviderCredentialStore.provider == provider,
                    ProviderCredentialStore.is_active == True
                )
            )
            cred_store = await self.db.scalar(stmt)
            
            if not cred_store:
                return None
            
            # Check expiration
            if cred_store.expires_at and cred_store.expires_at < datetime.utcnow():
                logger.warning(f"Credentials for {provider} have expired")
                return None
            
            # Decrypt credentials
            decrypted_data = self._fernet.decrypt(cred_store.encrypted_credentials)
            credentials = json.loads(decrypted_data.decode())
            
            return ProviderCredentials(
                provider=provider,
                account_external_id=str(account_id),
                credentials=credentials,
                expires_at=cred_store.expires_at
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
                    ProviderCredentialStore.provider == provider
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
        self,
        account_id: UUID,
        provider: str,
        new_credentials: Dict[str, Any]
    ) -> bool:
        """Rotate provider credentials."""
        # Store new credentials
        success = await self.store_credentials(
            account_id, 
            provider, 
            new_credentials,
            expires_at=datetime.utcnow() + timedelta(days=90)  # 90-day rotation
        )
        
        if success:
            logger.info(f"Rotated credentials for provider {provider}")
        
        return success
    
    async def get_provider_credentials_for_collection(
        self,
        account_id: UUID,
        provider: str
    ) -> Dict[str, Any]:
        """Get provider credentials formatted for collection use."""
        creds = await self.get_credentials(account_id, provider)
        
        if not creds:
            # Fall back to environment variables
            logger.warning(f"No stored credentials for {provider}, falling back to environment")
            return self._get_credentials_from_environment(provider)
        
        return creds.credentials
    
    def _get_credentials_from_environment(self, provider: str) -> Dict[str, Any]:
        """Get credentials from environment variables as fallback."""
        if provider == "github":
            return {
                "token": settings.github_token
            }
        elif provider == "aws":
            return {
                "access_key_id": settings.aws_access_key_id,
                "secret_access_key": settings.aws_secret_access_key,
                "region": settings.aws_default_region
            }
        elif provider == "gcp":
            return {
                "service_account_path": settings.google_application_credentials,
                "project_id": settings.gcp_project_id
            }
        elif provider == "google_workspace":
            return {
                "admin_email": settings.google_workspace_admin_email,
                "customer_id": settings.google_workspace_customer_id
            }
        else:
            return {}
    
    async def test_credentials(self, account_id: UUID, provider: str) -> bool:
        """Test if provider credentials are valid."""
        from cerebro.infrastructure.provider_registry import get_provider_registry
        
        try:
            # Get credentials
            credentials = await self.get_provider_credentials_for_collection(account_id, provider)
            
            if not credentials:
                return False
            
            # Create provider instance
            registry = get_provider_registry()
            provider_instance = registry.create_provider(
                provider,
                account_id=str(account_id),
                **credentials
            )
            
            # Test authentication
            return await provider_instance.authenticate()
            
        except Exception as e:
            logger.error(f"Credential test failed for {provider}: {e}")
            return False
