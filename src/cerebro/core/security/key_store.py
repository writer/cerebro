"""JWT key store for managing signing keys and rotation."""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID, uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import (
    Boolean,
    DateTime,
    LargeBinary,
    String,
    Text,
    and_,
    or_,
    select,
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.exc import OperationalError, ProgrammingError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from cerebro.core.config import settings
from cerebro.core.database import Base
from cerebro.kms import BaseKMS as _BaseKMS
from cerebro.kms import get_kms as _get_kms_factory

logger = logging.getLogger(__name__)


class JWTSigningKey(Base):
    """Database model for JWT signing keys."""

    __tablename__ = "jwt_signing_keys"

    key_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    kid: Mapped[str] = mapped_column(
        String(50), unique=True, nullable=False
    )  # Key ID for JWT header
    encrypted_private_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    encrypted_dek: Mapped[bytes] = mapped_column(
        LargeBinary, nullable=False
    )  # Data encryption key
    public_key_pem: Mapped[str] = mapped_column(
        Text, nullable=False
    )  # Public key for JWKS
    algorithm: Mapped[str] = mapped_column(String(10), nullable=False, default="RS256")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now()
    )
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    def to_jwks_entry(self) -> Dict[str, Any]:
        """Convert to JWKS (JSON Web Key Set) entry format."""
        # Parse public key to extract components for JWKS
        from cryptography.hazmat.primitives import serialization

        public_key = serialization.load_pem_public_key(self.public_key_pem.encode())
        public_numbers = public_key.public_numbers()  # type: ignore[union-attr]

        # Convert to base64url-encoded integers for JWKS format
        import base64

        def int_to_base64url(num: int) -> str:
            """Convert integer to base64url-encoded string."""
            # Convert to bytes, removing leading zeros
            byte_length = (num.bit_length() + 7) // 8
            num_bytes = num.to_bytes(byte_length, "big")
            return base64.urlsafe_b64encode(num_bytes).decode("ascii").rstrip("=")

        return {
            "kty": "RSA",
            "kid": self.kid,
            "use": "sig",
            "alg": self.algorithm,
            "n": int_to_base64url(public_numbers.n),  # type: ignore[union-attr]
            "e": int_to_base64url(public_numbers.e),  # type: ignore[union-attr]
        }


def get_kms() -> _BaseKMS:
    """Return the default KMS instance used for key encryption."""

    return _get_kms_factory()


def _ensure_aware(dt: datetime) -> datetime:
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class JWTKeyStore:
    """Manages JWT signing keys with rotation and KMS integration."""

    def __init__(
        self, db_session: AsyncSession, kms: Optional[_BaseKMS] = None, metrics=None
    ):
        """Initialize key store.

        Args:
            db_session: Database session
            kms: KMS instance (injected by caller)
            metrics: Metrics instance (injected by caller)
        """
        self.db = db_session
        self.kms = kms or get_kms()
        self.metrics = metrics

    async def _encrypt_with_kms(self, plaintext: bytes) -> Tuple[bytes, bytes]:
        """Encrypt data using the configured KMS, supporting multiple interfaces."""

        encryptor = getattr(self.kms, "encrypt_data", None)
        if encryptor is not None:
            result = await encryptor(plaintext)
            if isinstance(result, tuple) and len(result) == 2:
                return result
            return result, b""

        ciphertext = await self.kms.encrypt(plaintext)
        return ciphertext, b""

    async def _decrypt_with_kms(
        self, ciphertext: bytes, dek: Optional[bytes] = None
    ) -> bytes:
        """Decrypt data using the configured KMS, accepting optional DEK."""

        decryptor = getattr(self.kms, "decrypt_data", None)
        if decryptor is not None:
            return await decryptor(ciphertext, dek)

        return await self.kms.decrypt(ciphertext)

    async def get_current_signing_key(self) -> Optional[JWTSigningKey]:
        """Get the current active signing key."""
        now = datetime.now(timezone.utc)

        stmt = (
            select(JWTSigningKey)
            .where(
                and_(
                    JWTSigningKey.is_active == True,
                    or_(
                        JWTSigningKey.expires_at.is_(None),
                        JWTSigningKey.expires_at > now,
                    ),
                )
            )
            .order_by(JWTSigningKey.created_at.desc())
            .limit(1)
        )

        return await self.db.scalar(stmt)

    async def get_verification_keys(self) -> List[JWTSigningKey]:
        """Get all keys that can be used for token verification (current + overlap period)."""
        now = datetime.now(timezone.utc)
        overlap_cutoff = now - timedelta(hours=settings.jwt_key_overlap_hours)

        stmt = (
            select(JWTSigningKey)
            .where(
                and_(
                    JWTSigningKey.is_active == True,
                    JWTSigningKey.created_at > overlap_cutoff,
                    or_(
                        JWTSigningKey.expires_at.is_(None),
                        JWTSigningKey.expires_at > now,
                    ),
                )
            )
            .order_by(JWTSigningKey.created_at.desc())
        )

        return list(await self.db.scalars(stmt))

    async def get_key_by_kid(self, kid: str) -> Optional[JWTSigningKey]:
        """Get signing key by key ID."""
        stmt = select(JWTSigningKey).where(
            and_(JWTSigningKey.kid == kid, JWTSigningKey.is_active == True)
        )
        return await self.db.scalar(stmt)

    async def create_new_signing_key(self) -> JWTSigningKey:
        """Generate a new RSA signing key and store it securely."""
        try:
            logger.info("Generating new JWT signing key")

            # Generate RSA key pair
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

            # Serialize private key
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )

            # Serialize public key
            public_key = private_key.public_key()
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            # Encrypt private key using KMS envelope encryption
            encrypted_private_key, encrypted_dek = await self._encrypt_with_kms(
                private_pem
            )

            # Generate unique key ID
            kid = f"cerebro-{uuid4().hex[:8]}"

            # Create database record
            signing_key = JWTSigningKey(
                kid=kid,
                encrypted_private_key=encrypted_private_key,
                encrypted_dek=encrypted_dek,
                public_key_pem=public_pem.decode("utf-8"),
                algorithm=settings.jwt_algorithm,
                expires_at=datetime.now(timezone.utc)
                + timedelta(hours=settings.jwt_rotation_period_hours),
            )

            self.db.add(signing_key)
            await self.db.commit()
            await self.db.refresh(signing_key)

            if self.metrics:
                self.metrics.record_key_rotation(True)
                self.metrics.set_active_keys(await self._count_active_keys())

            logger.info(f"Created new JWT signing key with kid: {kid}")
            return signing_key

        except Exception as e:
            logger.error(f"Failed to create new signing key: {e}")
            if self.metrics:
                self.metrics.record_key_rotation(False)
            await self.db.rollback()
            raise

    async def get_private_key(self, signing_key: JWTSigningKey) -> bytes:
        """Decrypt and return the private key for signing."""
        try:
            # Decrypt private key using KMS
            private_key_bytes = await self._decrypt_with_kms(
                signing_key.encrypted_private_key,
                signing_key.encrypted_dek,
            )
            return private_key_bytes

        except Exception as e:
            logger.error(f"Failed to decrypt private key {signing_key.kid}: {e}")
            raise

    async def rotate_keys_if_needed(self) -> bool:
        """Check if key rotation is needed and perform it."""
        try:
            current_key = await self.get_current_signing_key()
        except (OperationalError, ProgrammingError) as exc:
            logger.warning(
                "JWT signing key table unavailable; skipping rotation (%s)",
                exc,
            )
            return False

        if not current_key:
            logger.info("No current signing key found, creating initial key")
            await self.create_new_signing_key()
            return True

        # Check if rotation is needed
        now = datetime.now(timezone.utc)
        created_at = _ensure_aware(current_key.created_at)
        rotation_threshold = created_at + timedelta(
            hours=settings.jwt_rotation_period_hours
        )

        if now >= rotation_threshold:
            logger.info(f"Key rotation needed for kid: {current_key.kid}")
            await self.create_new_signing_key()
            return True

        return False

    async def cleanup_expired_keys(self) -> int:
        """Remove expired keys that are beyond the overlap period."""
        now = datetime.now(timezone.utc)
        cleanup_cutoff = now - timedelta(hours=settings.jwt_key_overlap_hours * 2)

        # Find expired keys
        try:
            stmt = select(JWTSigningKey).where(
                and_(
                    JWTSigningKey.expires_at < cleanup_cutoff,
                    JWTSigningKey.is_active == True,
                )
            )
            expired_keys = list(await self.db.scalars(stmt))
        except (OperationalError, ProgrammingError) as exc:
            logger.warning(
                "JWT signing key table unavailable for cleanup (%s)",
                exc,
            )
            return 0

        # Deactivate expired keys
        for key in expired_keys:
            key.is_active = False

        await self.db.commit()

        if expired_keys:
            logger.info(f"Cleaned up {len(expired_keys)} expired JWT keys")
            if self.metrics:
                self.metrics.set_active_keys(await self._count_active_keys())

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

        return {"keys": keys}

    async def _count_active_keys(self) -> int:
        """Count currently active keys."""
        now = datetime.now(timezone.utc)
        stmt = select(func.count(JWTSigningKey.key_id)).where(
            and_(
                JWTSigningKey.is_active == True,
                or_(JWTSigningKey.expires_at.is_(None), JWTSigningKey.expires_at > now),
            )
        )
        return await self.db.scalar(stmt) or 0
