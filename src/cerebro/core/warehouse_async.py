"""Async wrapper around the synchronous Snowflake SQLAlchemy session."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator, Mapping

import anyio
from sqlalchemy.engine import Result
from sqlalchemy.sql import Executable

from cerebro.core.warehouse import warehouse_session


class WarehouseAsyncSession:
    def __init__(self, sync_session: Any):
        self._session = sync_session
        bind = self._session.get_bind()
        self.dialect_name = getattr(getattr(bind, "dialect", None), "name", "unknown")

    async def execute(
        self, statement: Executable, params: Mapping[str, Any] | None = None
    ) -> Result[Any]:
        return await anyio.to_thread.run_sync(
            self._session.execute, statement, params or {}
        )

    async def scalars(
        self, statement: Executable, params: Mapping[str, Any] | None = None
    ):
        return await anyio.to_thread.run_sync(
            self._session.scalars, statement, params or {}
        )

    async def scalar(
        self, statement: Executable, params: Mapping[str, Any] | None = None
    ):
        result = await self.execute(statement, params)
        return result.scalar()

    async def close(self) -> None:
        await anyio.to_thread.run_sync(self._session.close)

    async def commit(self) -> None:
        await anyio.to_thread.run_sync(self._session.commit)

    async def rollback(self) -> None:
        await anyio.to_thread.run_sync(self._session.rollback)


@asynccontextmanager
async def warehouse_async_session() -> AsyncGenerator[WarehouseAsyncSession, None]:
    with warehouse_session() as session:
        wrapper = WarehouseAsyncSession(session)
        try:
            yield wrapper
        finally:
            await wrapper.close()
