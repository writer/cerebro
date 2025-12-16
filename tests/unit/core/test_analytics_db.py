from __future__ import annotations

from contextlib import asynccontextmanager

from cerebro.core import analytics_db as analytics_db_module


async def test_analytics_read_session_yields_core_db_when_snowflake_disabled(monkeypatch):
    sentinel_db = object()
    monkeypatch.setattr(analytics_db_module, "resolve_snowflake_database_url", lambda: None)

    async with analytics_db_module.analytics_read_session(sentinel_db) as session:
        assert session is sentinel_db


async def test_analytics_read_session_yields_warehouse_when_snowflake_enabled(monkeypatch):
    sentinel_db = object()
    sentinel_warehouse = object()

    monkeypatch.setattr(analytics_db_module, "resolve_snowflake_database_url", lambda: "snowflake://")

    @asynccontextmanager
    async def _fake_warehouse_session():
        yield sentinel_warehouse

    monkeypatch.setattr(analytics_db_module, "warehouse_async_session", _fake_warehouse_session)

    async with analytics_db_module.analytics_read_session(sentinel_db) as session:
        assert session is sentinel_warehouse
