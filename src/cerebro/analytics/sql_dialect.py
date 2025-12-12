"""Dialect helpers for SQL snippets used in analytics.

This module centralizes SQL differences across Postgres/SQLite/Snowflake so we
can keep query templates readable.
"""

from __future__ import annotations

from typing import Any


def get_dialect_name(db: Any) -> str:
    name = getattr(db, "dialect_name", None)
    if isinstance(name, str) and name:
        return name

    bind = getattr(db, "bind", None)
    if bind is not None and getattr(bind, "dialect", None) is not None:
        return bind.dialect.name

    get_bind = getattr(db, "get_bind", None)
    if callable(get_bind):
        try:
            bind = get_bind()
            if bind is not None and getattr(bind, "dialect", None) is not None:
                return bind.dialect.name
        except Exception:
            pass

    return "unknown"


def current_timestamp_expr(*, dialect: str) -> str:
    # Snowflake/Postgres/SQLite all accept CURRENT_TIMESTAMP.
    return "CURRENT_TIMESTAMP"


def timestamp_minus_days_expr(*, days: int, dialect: str) -> str:
    if dialect == "snowflake":
        return f"DATEADD(day, -{int(days)}, CURRENT_TIMESTAMP())"
    if dialect == "sqlite":
        return f"datetime('now', '-{int(days)} days')"
    return f"CURRENT_TIMESTAMP - INTERVAL '{int(days)} days'"


def days_since_expr(*, column_expr: str, dialect: str) -> str:
    if dialect == "snowflake":
        return f"DATEDIFF('second', {column_expr}, CURRENT_TIMESTAMP()) / 86400"
    if dialect == "sqlite":
        return f"(julianday('now') - julianday({column_expr}))"
    return f"EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - {column_expr})) / 86400"


def hours_between_expr(*, start_expr: str, end_expr: str, dialect: str) -> str:
    if dialect == "snowflake":
        return f"DATEDIFF('second', {start_expr}, {end_expr}) / 3600"
    if dialect == "sqlite":
        return f"(strftime('%s', {end_expr}) - strftime('%s', {start_expr})) / 3600.0"
    return f"EXTRACT(EPOCH FROM ({end_expr} - {start_expr})) / 3600"


def array_agg_ordered_expr(*, value_expr: str, order_by_expr: str, dialect: str) -> str:
    if dialect == "snowflake":
        return f"ARRAY_AGG({value_expr}) WITHIN GROUP (ORDER BY {order_by_expr})"
    return f"ARRAY_AGG({value_expr} ORDER BY {order_by_expr})"
