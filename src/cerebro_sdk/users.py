"""User management helpers for the Cerebro SDK."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.core.user_models import User
from cerebro.core.user_service import UserService


@dataclass
class UserRecord:
    user_id: UUID
    username: str
    email: str | None
    is_admin: bool
    scopes: list[str]


class UserManager:
    """Thin wrapper exposing high-level user operations for tooling."""

    def __init__(self, db: AsyncSession) -> None:
        self._service = UserService(db)
        self._db = db

    async def create_user(
        self,
        username: str,
        email: str,
        password: str,
        *,
        scopes: Iterable[str] | None = None,
        is_admin: bool = False,
    ) -> UserRecord:
        user = await self._service.create_user(
            username=username,
            email=email,
            password=password,
            is_admin=is_admin,
            scopes=list(scopes) if scopes else None,
        )
        return await self._to_record(user)

    async def get_user(self, username: str) -> UserRecord | None:
        user = await self._service.get_user_by_username(username)
        if not user:
            return None
        return await self._to_record(user)

    async def list_users(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        active_only: bool = True,
    ) -> list[UserRecord]:
        users = await self._service.list_users(
            limit=limit, offset=offset, active_only=active_only
        )
        return [await self._to_record(user) for user in users]

    async def add_scopes(self, user_id: UUID, scopes: Iterable[str]) -> None:
        await self._service.add_user_scopes(user_id, list(scopes))

    async def remove_scopes(self, user_id: UUID, scopes: Iterable[str]) -> None:
        await self._service.remove_user_scopes(user_id, list(scopes))

    async def authenticate(self, username: str, password: str) -> UserRecord | None:
        user = await self._service.authenticate_user(username, password)
        if not user:
            return None
        return await self._to_record(user)

    async def _to_record(self, user: User) -> UserRecord:
        scopes = await self._service.get_user_scopes(user.user_id)
        return UserRecord(
            user_id=user.user_id,
            username=user.username,
            email=user.email,
            is_admin=user.is_admin,
            scopes=scopes,
        )
