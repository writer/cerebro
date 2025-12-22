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
from sqlalchemy.pool import NullPool, QueuePool

from cerebro.core.config import settings


SNOWFLAKE_DATABASE_URL_ENV = "SNOWFLAKE_DATABASE_URL"
SNOWFLAKE_ROLE_ENV = "SNOWFLAKE_ROLE"
SNOWFLAKE_WAREHOUSE_ENV = "SNOWFLAKE_WAREHOUSE"
SNOWFLAKE_QUERY_TAG_ENV = "SNOWFLAKE_QUERY_TAG"
SNOWFLAKE_APPLICATION_ENV = "SNOWFLAKE_APPLICATION"
SNOWFLAKE_TIMEZONE_ENV = "SNOWFLAKE_TIMEZONE"
SNOWFLAKE_STATEMENT_TIMEOUT_SECONDS_ENV = "SNOWFLAKE_STATEMENT_TIMEOUT_SECONDS"

SNOWFLAKE_POOL_TYPE_ENV = "SNOWFLAKE_POOL_TYPE"  # null | queue
SNOWFLAKE_POOL_SIZE_ENV = "SNOWFLAKE_POOL_SIZE"
SNOWFLAKE_POOL_MAX_OVERFLOW_ENV = "SNOWFLAKE_POOL_MAX_OVERFLOW"
SNOWFLAKE_POOL_TIMEOUT_ENV = "SNOWFLAKE_POOL_TIMEOUT"
SNOWFLAKE_POOL_RECYCLE_ENV = "SNOWFLAKE_POOL_RECYCLE"


def resolve_snowflake_database_url() -> str | None:
    return settings.snowflake_database_url or os.getenv(SNOWFLAKE_DATABASE_URL_ENV)


def _get_int_env(name: str) -> int | None:
    value = os.getenv(name)
    if value is None or value == "":
        return None
    try:
        return int(value)
    except ValueError as exc:
        raise RuntimeError(f"Invalid integer for {name}: {value!r}") from exc


def _resolve_component() -> str:
    component = (
        os.getenv("CELERY_PROCESS_ROLE")
        or os.getenv("CEREBRO_PROCESS_ROLE")
        or os.getenv("CEREBRO_COMPONENT")
    )
    if component:
        return component.strip().lower()
    # Default to API when not otherwise specified.
    return "api"


def _sanitize_tag_part(value: str) -> str:
    return "".join(
        ch if ch.isalnum() or ch in {"-", "_", "."} else "-" for ch in value
    ).strip("-")


def _default_query_tag() -> str:
    base = "cerebro"
    environment = _sanitize_tag_part(
        (os.getenv("ENVIRONMENT") or settings.environment or "unknown").lower()
    )
    component = _sanitize_tag_part(_resolve_component())
    return f"{base}:{environment}:{component}"


def _resolve_snowflake_query_tag() -> str:
    return os.getenv(SNOWFLAKE_QUERY_TAG_ENV) or _default_query_tag()


def _resolve_snowflake_application_name() -> str:
    return os.getenv(SNOWFLAKE_APPLICATION_ENV, "cerebro")


def _resolve_snowflake_session_parameters() -> dict[str, object]:
    session_parameters: dict[str, object] = {
        "QUERY_TAG": _resolve_snowflake_query_tag(),
        "TIMEZONE": os.getenv(SNOWFLAKE_TIMEZONE_ENV, "UTC"),
    }

    component = _resolve_component().upper()
    per_component_timeout = _get_int_env(
        f"{SNOWFLAKE_STATEMENT_TIMEOUT_SECONDS_ENV}_{component}"
    )
    statement_timeout_seconds = (
        per_component_timeout
        if per_component_timeout is not None
        else _get_int_env(SNOWFLAKE_STATEMENT_TIMEOUT_SECONDS_ENV)
    )

    # Safe defaults to limit runaway interactive queries.
    if statement_timeout_seconds is None:
        component_lower = component.lower()
        if component_lower in {"api"}:
            statement_timeout_seconds = 60
        elif component_lower in {"worker", "beat"}:
            statement_timeout_seconds = 600
        elif component_lower in {"bootstrap"}:
            statement_timeout_seconds = 900
        elif component_lower in {"cli"}:
            statement_timeout_seconds = 300

    if statement_timeout_seconds is not None:
        session_parameters["STATEMENT_TIMEOUT_IN_SECONDS"] = statement_timeout_seconds

    return session_parameters


def _resolve_warehouse_pool_kwargs() -> dict[str, object]:
    pool_type = (os.getenv(SNOWFLAKE_POOL_TYPE_ENV) or "null").strip().lower()
    if pool_type in {"null", "none"}:
        return {"poolclass": NullPool}
    if pool_type != "queue":
        raise RuntimeError(
            f"Invalid {SNOWFLAKE_POOL_TYPE_ENV}={pool_type!r}; expected 'null' or 'queue'"
        )

    kwargs: dict[str, object] = {"poolclass": QueuePool}
    if (pool_size := _get_int_env(SNOWFLAKE_POOL_SIZE_ENV)) is not None:
        kwargs["pool_size"] = pool_size
    if (max_overflow := _get_int_env(SNOWFLAKE_POOL_MAX_OVERFLOW_ENV)) is not None:
        kwargs["max_overflow"] = max_overflow
    if (timeout := _get_int_env(SNOWFLAKE_POOL_TIMEOUT_ENV)) is not None:
        kwargs["pool_timeout"] = timeout
    if (recycle := _get_int_env(SNOWFLAKE_POOL_RECYCLE_ENV)) is not None:
        kwargs["pool_recycle"] = recycle

    return kwargs


def _build_warehouse_connect_args() -> dict[str, object]:
    connect_args: dict[str, object] = {
        "client_session_keep_alive": True,
        "application": _resolve_snowflake_application_name(),
        "session_parameters": _resolve_snowflake_session_parameters(),
    }

    component = _resolve_component().upper()
    role = os.getenv(f"{SNOWFLAKE_ROLE_ENV}_{component}") or os.getenv(
        SNOWFLAKE_ROLE_ENV
    )
    if role:
        connect_args["role"] = role
    warehouse = os.getenv(f"{SNOWFLAKE_WAREHOUSE_ENV}_{component}") or os.getenv(
        SNOWFLAKE_WAREHOUSE_ENV
    )
    if warehouse:
        connect_args["warehouse"] = warehouse

    return connect_args


@lru_cache
def get_warehouse_engine() -> Engine:
    url_value = resolve_snowflake_database_url()
    if not url_value:
        raise RuntimeError("SNOWFLAKE_DATABASE_URL is not configured")

    url = make_url(url_value)
    return create_engine(
        url,
        pool_pre_ping=True,
        connect_args=_build_warehouse_connect_args(),
        **_resolve_warehouse_pool_kwargs(),
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
