"""Dependency that chooses the analytics database.

- Default: the core async DB (DATABASE_URL).
- When SNOWFLAKE_DATABASE_URL is configured: route analytics queries to Snowflake.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.core.database import get_db
from cerebro.core.warehouse import resolve_snowflake_database_url
from cerebro.core.warehouse_async import warehouse_async_session


@asynccontextmanager
async def analytics_read_session(db: Any) -> AsyncGenerator[Any, None]:
    """Yield a DB-like session for analytics reads.

    - If Snowflake is not configured, yields the provided DB session.
    - If Snowflake is configured, yields the Snowflake-backed session.

    This is safe to use from FastAPI dependencies and Celery tasks.
    """

    if not resolve_snowflake_database_url():
        yield db
        return

    async with warehouse_async_session() as warehouse:
        yield warehouse


async def get_analytics_db(db: AsyncSession = Depends(get_db)) -> AsyncGenerator[Any, None]:
    async with analytics_read_session(db) as analytics_db:
        yield analytics_db
