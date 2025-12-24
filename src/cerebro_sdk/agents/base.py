"""Base utilities shared across agent SDK facades."""

from __future__ import annotations

from enum import Enum
from typing import TypeVar

from sqlalchemy.ext.asyncio import AsyncSession

from cerebro_sdk.agents.types import AgentInvalidStatusError, AgentValidationError

EnumT = TypeVar("EnumT", bound=Enum)


class AsyncManagerBase:
    """Provides consistent AsyncSession helpers for manager facades."""

    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    def _transaction(self):  # pragma: no cover - thin wrapper
        return (
            self._db.begin_nested() if self._db.in_transaction() else self._db.begin()
        )

    @staticmethod
    def _coerce_enum(value: object, enum_cls: type[EnumT], *, message: str) -> EnumT:
        if isinstance(value, enum_cls):
            return value
        try:
            return enum_cls(value)
        except ValueError as exc:  # pragma: no cover - exercised via callers
            raise AgentValidationError(message) from exc

    @staticmethod
    def _require_enum(value: object, enum_cls: type[EnumT], *, message: str) -> EnumT:
        if isinstance(value, enum_cls):
            return value
        try:
            return enum_cls(value)
        except ValueError as exc:
            raise AgentInvalidStatusError(message) from exc
