"""Snowflake warehouse connection helpers.

Snowflake's SQLAlchemy driver is synchronous, so this module provides a sync
engine + session factory that can be wrapped for async endpoints.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from functools import lru_cache
from typing import Iterator

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import NullPool

from cerebro.core.config import settings


SNOWFLAKE_DATABASE_URL_ENV = "SNOWFLAKE_DATABASE_URL"


def resolve_snowflake_database_url() -> str | None:
    return settings.snowflake_database_url or os.getenv(SNOWFLAKE_DATABASE_URL_ENV)


@lru_cache
def get_warehouse_engine() -> Engine:
    url_value = resolve_snowflake_database_url()
    if not url_value:
        raise RuntimeError("SNOWFLAKE_DATABASE_URL is not configured")

    url = make_url(url_value)
    return create_engine(
        url,
        poolclass=NullPool,
        pool_pre_ping=True,
        connect_args={
            "client_session_keep_alive": True,
        },
    )


@lru_cache
def get_warehouse_session_factory() -> sessionmaker[Session]:
    return sessionmaker(
        bind=get_warehouse_engine(),
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
    )


@contextmanager
def warehouse_session() -> Iterator[Session]:
    session = get_warehouse_session_factory()()
    try:
        yield session
    finally:
        session.close()
