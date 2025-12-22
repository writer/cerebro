"""Refresh token service for JWT token rotation."""

import hashlib
import logging
import secrets
from datetime import datetime, timedelta
from typing import Optional
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, String, and_, select
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from cerebro.core.database import Base

logger = logging.getLogger(__name__)


class RefreshToken(Base):
    """Database model for refresh tokens."""

    __tablename__ = "refresh_tokens"

    token_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    user_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    is_revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now()
    )
    last_used: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))


class RefreshTokenService:
    """Service for managing refresh tokens."""

    def __init__(self, db_session: AsyncSession):
        """Initialize refresh token service."""
        self.db = db_session

    def generate_refresh_token(self) -> str:
        """Generate a cryptographically secure refresh token."""
        return secrets.token_urlsafe(32)

    def hash_token(self, token: str) -> str:
        """Hash a refresh token for storage."""
        return hashlib.sha256(token.encode()).hexdigest()

    async def store_refresh_token(
        self, user_id: UUID, token: str, expires_in_days: int = 30
    ) -> RefreshToken:
        """Store a refresh token in the database."""

        # Hash the token for storage
        token_hash = self.hash_token(token)

        # Calculate expiration
        expires_at = datetime.utcnow() + timedelta(days=expires_in_days)

        # Create refresh token record
        refresh_token = RefreshToken(
            user_id=user_id, token_hash=token_hash, expires_at=expires_at
        )

        self.db.add(refresh_token)
        await self.db.commit()
        await self.db.refresh(refresh_token)

        logger.info(f"Stored refresh token for user {user_id}")
        return refresh_token

    async def verify_refresh_token(self, token: str) -> Optional[UUID]:
        """Verify a refresh token and return the user ID."""

        token_hash = self.hash_token(token)
        now = datetime.utcnow()

        stmt = select(RefreshToken).where(
            and_(
                RefreshToken.token_hash == token_hash,
                RefreshToken.expires_at > now,
                RefreshToken.is_revoked == False,
            )
        )

        refresh_token = await self.db.scalar(stmt)

        if not refresh_token:
            return None

        # Update last used timestamp
        refresh_token.last_used = now
        await self.db.commit()

        return refresh_token.user_id

    async def revoke_refresh_token(self, token: str) -> bool:
        """Revoke a refresh token."""

        token_hash = self.hash_token(token)

        stmt = select(RefreshToken).where(RefreshToken.token_hash == token_hash)
        refresh_token = await self.db.scalar(stmt)

        if not refresh_token:
            return False

        refresh_token.is_revoked = True
        await self.db.commit()

        logger.info(f"Revoked refresh token for user {refresh_token.user_id}")
        return True

    async def revoke_all_user_tokens(self, user_id: UUID) -> int:
        """Revoke all refresh tokens for a user."""

        stmt = select(RefreshToken).where(
            and_(RefreshToken.user_id == user_id, RefreshToken.is_revoked == False)
        )

        tokens = list(await self.db.scalars(stmt))

        for token in tokens:
            token.is_revoked = True

        await self.db.commit()

        logger.info(f"Revoked {len(tokens)} refresh tokens for user {user_id}")
        return len(tokens)

    async def cleanup_expired_tokens(self) -> int:
        """Clean up expired refresh tokens."""

        now = datetime.utcnow()

        stmt = select(RefreshToken).where(RefreshToken.expires_at < now)
        expired_tokens = list(await self.db.scalars(stmt))

        for token in expired_tokens:
            await self.db.delete(token)

        await self.db.commit()

        logger.info(f"Cleaned up {len(expired_tokens)} expired refresh tokens")
        return len(expired_tokens)
