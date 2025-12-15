"""Dependency that chooses the analytics database.

- Default: the core async DB (DATABASE_URL).
- When SNOWFLAKE_DATABASE_URL is configured: route analytics queries to Snowflake.
"""

from __future__ import annotations

from typing import Any, AsyncGenerator

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.core.database import get_db
from cerebro.core.warehouse import resolve_snowflake_database_url
from cerebro.core.warehouse_async import warehouse_async_session


async def get_analytics_db(db: AsyncSession = Depends(get_db)) -> AsyncGenerator[Any, None]:
    if not resolve_snowflake_database_url():
        yield db
        return

    async with warehouse_async_session() as warehouse:
        yield warehouse
