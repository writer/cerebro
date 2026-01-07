"""Database configuration and session management."""

from collections.abc import AsyncGenerator
from typing import Any

from sqlalchemy import event
from sqlalchemy.engine.url import URL, make_url
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from cerebro.core.config import settings


class Base(DeclarativeBase):
    """Base class for all database models."""


def _build_engine() -> tuple["AsyncEngine", URL]:
    database_url = settings.database_url
    environment = settings.environment.lower()

    if environment in {"test", "testing"} and database_url.startswith("postgresql://"):
        database_url = "sqlite+aiosqlite:///./cerebro_test.db?cache=shared&uri=true"

    url = make_url(database_url)

    async_database_url = (
        database_url.replace("postgresql://", "postgresql+asyncpg://")
        if url.drivername.startswith("postgresql")
        else database_url
    )

    engine_options: dict[str, Any] = {
        "echo": False,
        "pool_pre_ping": True,
    }

    if url.drivername.startswith("sqlite"):
        engine_options["connect_args"] = {"check_same_thread": False}
    else:
        engine_options.update(
            {
                "pool_size": 20,
                "max_overflow": 10,
                "pool_recycle": 3600,
                "execution_options": {"isolation_level": "READ_COMMITTED"},
            }
        )

    return create_async_engine(async_database_url, **engine_options), url


# Create async engine
engine, _engine_url = _build_engine()

if _engine_url.drivername.startswith("sqlite"):

    @event.listens_for(engine.sync_engine, "connect")
    def _set_sqlite_schema_flag(_dbapi_connection, connection_record):
        connection_record.info.setdefault("_schema_initialized", False)

    @event.listens_for(engine.sync_engine, "begin")
    def _ensure_sqlite_schema(connection):
        if connection.info.get("_schema_initialized", False):
            return

        Base.metadata.create_all(bind=connection)

        try:
            from cerebro.agents import models as agent_models
        except ImportError:
            agent_models = None  # type: ignore[assignment]

        if agent_models is not None and hasattr(agent_models, "Base"):
            agent_models.Base.metadata.create_all(bind=connection)

        connection.info["_schema_initialized"] = True


# Create session factory
async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Get database session."""
    async with async_session_factory() as session:
        try:
            yield session
        finally:
            await session.close()


async def create_tables() -> None:
    """Create all tables."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def drop_tables() -> None:
    """Drop all tables."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
