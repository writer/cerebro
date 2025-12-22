"""Dependency that chooses the analytics database.

- In dev/test environments, falls back to the core async DB (DATABASE_URL) when
  SNOWFLAKE_DATABASE_URL is not configured.
- In non-dev environments, SNOWFLAKE_DATABASE_URL is required.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator

from fastapi import Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.core.config import settings
from cerebro.core.database import get_db
from cerebro.core.warehouse import resolve_snowflake_database_url
from cerebro.core.warehouse_async import warehouse_async_session


_DEV_ENVIRONMENTS = {"dev", "development", "test", "testing"}


@asynccontextmanager
async def analytics_read_session(db: Any) -> AsyncGenerator[Any, None]:
    """Yield a DB-like session for analytics reads.

    - If Snowflake is not configured, yields the provided DB session.
    - If Snowflake is configured, yields the Snowflake-backed session.

    This is safe to use from FastAPI dependencies and Celery tasks.
    """

    if not resolve_snowflake_database_url():
        env = (settings.environment or "development").lower()
        if env in _DEV_ENVIRONMENTS:
            yield db
            return
        raise RuntimeError("SNOWFLAKE_DATABASE_URL is not configured")

    async with warehouse_async_session() as warehouse:
        yield warehouse


async def get_analytics_db(
    db: AsyncSession = Depends(get_db),
) -> AsyncGenerator[Any, None]:
    try:
        async with analytics_read_session(db) as analytics_db:
            yield analytics_db
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
