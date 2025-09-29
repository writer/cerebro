"""JWT key store for managing signing keys and rotation."""

import logging
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from uuid import uuid4
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import Column, String, DateTime, LargeBinary, Boolean, Text
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import func
from sqlalchemy import select, and_, or_
from uuid import UUID

from cerebro.core.database import Base
from cerebro.core.config import settings
from cerebro.kms.factory import get_kms
from cerebro.metrics.jwt_metrics import jwt_metrics

logger = logging.getLogger(__name__)


class JWTSigningKey(Base):
    """Database model for JWT signing keys."""
    __tablename__ = "jwt_signing_keys"
    
    key_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    kid: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)  # Key ID for JWT header
    encrypted_private_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    encrypted_dek: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)  # Data encryption key
    public_key_pem: Mapped[str] = mapped_column(Text, nullable=False)  # Public key for JWKS
    algorithm: Mapped[str] = mapped_column(String(10), nullable=False, default="RS256")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now())
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    
    def to_jwks_entry(self) -> Dict[str, Any]:
        """Convert to JWKS (JSON Web Key Set) entry format."""
        # Parse public key to extract components for JWKS
        from cryptography.hazmat.primitives import serialization
        
        public_key = serialization.load_pem_public_key(self.public_key_pem.encode())
        public_numbers = public_key.public_numbers()
        
        # Convert to base64url-encoded integers for JWKS format
        import base64
        
        def int_to_base64url(num: int) -> str:
            """Convert integer to base64url-encoded string."""
            # Convert to bytes, removing leading zeros
            byte_length = (num.bit_length() + 7) // 8
            num_bytes = num.to_bytes(byte_length, 'big')
            return base64.urlsafe_b64encode(num_bytes).decode('ascii').rstrip('=')
        
        return {
            "kty": "RSA",
            "kid": self.kid,
            "use": "sig",
            "alg": self.algorithm,
            "n": int_to_base64url(public_numbers.n),
            "e": int_to_base64url(public_numbers.e)
        }


class JWTKeyStore:
    """Manages JWT signing keys with rotation and KMS integration."""
    
    def __init__(self, db_session: AsyncSession):
        """Initialize key store."""
        self.db = db_session
        self.kms = get_kms()
        
    async def get_current_signing_key(self) -> Optional[JWTSigningKey]:
        """Get the current active signing key."""
        now = datetime.utcnow()
        
        stmt = select(JWTSigningKey).where(
            and_(
                JWTSigningKey.is_active == True,
                or_(
                    JWTSigningKey.expires_at.is_(None),
                    JWTSigningKey.expires_at > now
                )
            )
        ).order_by(JWTSigningKey.created_at.desc()).limit(1)
        
        return await self.db.scalar(stmt)
    
    async def get_verification_keys(self) -> List[JWTSigningKey]:
        """Get all keys that can be used for token verification (current + overlap period)."""
        now = datetime.utcnow()
        overlap_cutoff = now - timedelta(hours=settings.jwt_key_overlap_hours)
        
        stmt = select(JWTSigningKey).where(
            and_(
                JWTSigningKey.is_active == True,
                JWTSigningKey.created_at > overlap_cutoff,
                or_(
                    JWTSigningKey.expires_at.is_(None),
                    JWTSigningKey.expires_at > now
                )
            )
        ).order_by(JWTSigningKey.created_at.desc())
        
        return list(await self.db.scalars(stmt))
    
    async def get_key_by_kid(self, kid: str) -> Optional[JWTSigningKey]:
        """Get signing key by key ID."""
        stmt = select(JWTSigningKey).where(
            and_(
                JWTSigningKey.kid == kid,
                JWTSigningKey.is_active == True
            )
        )
        return await self.db.scalar(stmt)
    
    async def create_new_signing_key(self) -> JWTSigningKey:
        """Generate a new RSA signing key and store it securely."""
        try:
            logger.info("Generating new JWT signing key")
            
            # Generate RSA key pair
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            
            # Serialize private key
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # Serialize public key  
            public_key = private_key.public_key()
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Encrypt private key using KMS envelope encryption
            encrypted_private_key, encrypted_dek = await self.kms.encrypt_data(private_pem)
            
            # Generate unique key ID
            kid = f"cerebro-{uuid4().hex[:8]}"
            
            # Create database record
            signing_key = JWTSigningKey(
                kid=kid,
                encrypted_private_key=encrypted_private_key,
                encrypted_dek=encrypted_dek,
                public_key_pem=public_pem.decode('utf-8'),
                algorithm=settings.jwt_algorithm,
                expires_at=datetime.utcnow() + timedelta(hours=settings.jwt_rotation_period_hours)
            )
            
            self.db.add(signing_key)
            await self.db.commit()
            await self.db.refresh(signing_key)
            
            jwt_metrics.record_key_rotation(True)
            jwt_metrics.set_active_keys(await self._count_active_keys())
            
            logger.info(f"Created new JWT signing key with kid: {kid}")
            return signing_key
            
        except Exception as e:
            logger.error(f"Failed to create new signing key: {e}")
            jwt_metrics.record_key_rotation(False)
            await self.db.rollback()
            raise
    
    async def get_private_key(self, signing_key: JWTSigningKey) -> bytes:
        """Decrypt and return the private key for signing."""
        try:
            # Decrypt private key using KMS
            private_key_bytes = await self.kms.decrypt_data(
                signing_key.encrypted_private_key,
                signing_key.encrypted_dek
            )
            return private_key_bytes
            
        except Exception as e:
            logger.error(f"Failed to decrypt private key {signing_key.kid}: {e}")
            raise
    
    async def rotate_keys_if_needed(self) -> bool:
        """Check if key rotation is needed and perform it."""
        current_key = await self.get_current_signing_key()
        
        if not current_key:
            logger.info("No current signing key found, creating initial key")
            await self.create_new_signing_key()
            return True
        
        # Check if rotation is needed
        now = datetime.utcnow()
        rotation_threshold = current_key.created_at + timedelta(hours=settings.jwt_rotation_period_hours)
        
        if now >= rotation_threshold:
            logger.info(f"Key rotation needed for kid: {current_key.kid}")
            await self.create_new_signing_key()
            return True
        
        return False
    
    async def cleanup_expired_keys(self) -> int:
        """Remove expired keys that are beyond the overlap period."""
        now = datetime.utcnow()
        cleanup_cutoff = now - timedelta(hours=settings.jwt_key_overlap_hours * 2)
        
        # Find expired keys
        stmt = select(JWTSigningKey).where(
            and_(
                JWTSigningKey.expires_at < cleanup_cutoff,
                JWTSigningKey.is_active == True
            )
        )
        expired_keys = list(await self.db.scalars(stmt))
        
        # Deactivate expired keys
        for key in expired_keys:
            key.is_active = False
            
        await self.db.commit()
        
        if expired_keys:
            logger.info(f"Cleaned up {len(expired_keys)} expired JWT keys")
            jwt_metrics.set_active_keys(await self._count_active_keys())
        
        return len(expired_keys)
    
    async def get_jwks_response(self) -> Dict[str, Any]:
        """Get JSON Web Key Set (JWKS) response for public key distribution."""
        verification_keys = await self.get_verification_keys()
        
        keys = []
        for key in verification_keys:
            try:
                jwks_entry = key.to_jwks_entry()
                keys.append(jwks_entry)
            except Exception as e:
                logger.warning(f"Failed to convert key {key.kid} to JWKS format: {e}")
        
        return {
            "keys": keys
        }
    
    async def _count_active_keys(self) -> int:
        """Count currently active keys."""
        now = datetime.utcnow()
        stmt = select(func.count(JWTSigningKey.key_id)).where(
            and_(
                JWTSigningKey.is_active == True,
                or_(
                    JWTSigningKey.expires_at.is_(None),
                    JWTSigningKey.expires_at > now
                )
            )
        )
        return await self.db.scalar(stmt) or 0
