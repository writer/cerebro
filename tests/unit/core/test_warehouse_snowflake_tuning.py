from __future__ import annotations

import pytest

from sqlalchemy.pool import NullPool, QueuePool

from cerebro.core import warehouse


def test_default_query_tag_includes_celery_role(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(warehouse.SNOWFLAKE_QUERY_TAG_ENV, raising=False)
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("CELERY_PROCESS_ROLE", "analytics")
    assert warehouse._default_query_tag() == "cerebro:test:analytics"


def test_env_query_tag_overrides_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CELERY_PROCESS_ROLE", "analytics")
    monkeypatch.setenv(warehouse.SNOWFLAKE_QUERY_TAG_ENV, "explicit")
    assert warehouse._resolve_snowflake_query_tag() == "explicit"


def test_session_parameters_timezone_defaults_to_utc(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(warehouse.SNOWFLAKE_TIMEZONE_ENV, raising=False)
    params = warehouse._resolve_snowflake_session_parameters()
    assert params["TIMEZONE"] == "UTC"


def test_session_parameters_statement_timeout_optional(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(warehouse.SNOWFLAKE_STATEMENT_TIMEOUT_SECONDS_ENV, "123")
    params = warehouse._resolve_snowflake_session_parameters()
    assert params["STATEMENT_TIMEOUT_IN_SECONDS"] == 123


def test_pool_kwargs_default_nullpool(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(warehouse.SNOWFLAKE_POOL_TYPE_ENV, raising=False)
    kwargs = warehouse._resolve_warehouse_pool_kwargs()
    assert kwargs["poolclass"] is NullPool


def test_pool_kwargs_queuepool_with_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(warehouse.SNOWFLAKE_POOL_TYPE_ENV, "queue")
    monkeypatch.setenv(warehouse.SNOWFLAKE_POOL_SIZE_ENV, "3")
    monkeypatch.setenv(warehouse.SNOWFLAKE_POOL_MAX_OVERFLOW_ENV, "4")
    monkeypatch.setenv(warehouse.SNOWFLAKE_POOL_TIMEOUT_ENV, "5")
    monkeypatch.setenv(warehouse.SNOWFLAKE_POOL_RECYCLE_ENV, "6")
    kwargs = warehouse._resolve_warehouse_pool_kwargs()
    assert kwargs["poolclass"] is QueuePool
    assert kwargs["pool_size"] == 3
    assert kwargs["max_overflow"] == 4
    assert kwargs["pool_timeout"] == 5
    assert kwargs["pool_recycle"] == 6


def test_pool_kwargs_invalid_type_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(warehouse.SNOWFLAKE_POOL_TYPE_ENV, "nope")
    with pytest.raises(RuntimeError):
        warehouse._resolve_warehouse_pool_kwargs()


def test_connect_args_include_role_and_warehouse_when_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(warehouse.SNOWFLAKE_ROLE_ENV, "ANALYTICS_ROLE")
    monkeypatch.setenv(warehouse.SNOWFLAKE_WAREHOUSE_ENV, "ANALYTICS_WH")
    connect_args = warehouse._build_warehouse_connect_args()
    assert connect_args["role"] == "ANALYTICS_ROLE"
    assert connect_args["warehouse"] == "ANALYTICS_WH"
