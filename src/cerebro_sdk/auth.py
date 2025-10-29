"""Authentication helpers for the Cerebro SDK."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.core.config import settings
from cerebro.core.security.key_store import JWTKeyStore
from cerebro.core.security.jwt import JWTService
from cerebro.core.user_service import UserService
from cerebro.metrics.jwt_metrics import jwt_metrics


@dataclass(slots=True)
class TokenPair:
    access_token: str
    refresh_token: Optional[str] = None


class AuthSession:
    """High level facade around :class:`JWTService` and :class:`UserService`."""

    def __init__(self, db: AsyncSession) -> None:
        self._db = db
        self._user_service = UserService(db)
        self._jwt_service = JWTService(JWTKeyStore(db, metrics=jwt_metrics), metrics=jwt_metrics)

    async def login(self, username: str, password: str) -> Optional[TokenPair]:
        """Authenticate a user and return access/refresh tokens."""

        user = await self._user_service.authenticate_user(username, password)
        if not user:
            return None

        scopes = await self._user_service.get_user_scopes(user.user_id)
        access_token = await self._jwt_service.create_token(username=user.username, scopes=scopes)

        refresh_token = await self._jwt_service.create_token(
            username=user.username,
            scopes=scopes,
            expires_delta=timedelta(days=settings.refresh_token_expire_days),
            token_type="refresh",
        )

        return TokenPair(access_token=access_token, refresh_token=refresh_token)

    async def create_access_token(
        self,
        username: str,
        scopes: list[str],
        token_type: str = "access",
    ) -> str:
        """Issue a JWT using the underlying :class:`JWTService`."""

        return await self._jwt_service.create_token(
            username=username,
            scopes=scopes,
            token_type=token_type,
        )

    async def verify(self, token: str, expected_type: Optional[str] = None) -> dict:
        """Verify a token and return its payload."""

        return await self._jwt_service.verify_token(token, expected_type=expected_type)
