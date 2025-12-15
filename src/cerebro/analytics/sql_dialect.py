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


def timestamp_minus_hours_expr(*, hours: int, dialect: str) -> str:
    if dialect == "snowflake":
        return f"DATEADD(hour, -{int(hours)}, CURRENT_TIMESTAMP())"
    if dialect == "sqlite":
        return f"datetime('now', '-{int(hours)} hours')"
    return f"CURRENT_TIMESTAMP - INTERVAL '{int(hours)} hours'"


def case_insensitive_like_expr(*, column_expr: str, pattern_expr: str, dialect: str) -> str:
    if dialect in {"postgresql", "snowflake"}:
        return f"({column_expr} ILIKE {pattern_expr})"
    if dialect == "sqlite":
        return f"(LOWER({column_expr}) LIKE LOWER({pattern_expr}))"
    return f"({column_expr} ILIKE {pattern_expr})"


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


def minutes_between_expr(*, start_expr: str, end_expr: str, dialect: str) -> str:
    if dialect == "snowflake":
        return f"DATEDIFF('second', {start_expr}, {end_expr}) / 60"
    if dialect == "sqlite":
        return f"(strftime('%s', {end_expr}) - strftime('%s', {start_expr})) / 60.0"
    return f"EXTRACT(EPOCH FROM ({end_expr} - {start_expr})) / 60"


def array_agg_ordered_expr(*, value_expr: str, order_by_expr: str, dialect: str) -> str:
    if dialect == "snowflake":
        return f"ARRAY_AGG({value_expr}) WITHIN GROUP (ORDER BY {order_by_expr})"
    return f"ARRAY_AGG({value_expr} ORDER BY {order_by_expr})"


def split_part_expr(*, column_expr: str, delimiter: str, part: int, dialect: str) -> str:
    part_value = int(part)
    if dialect in {"postgresql", "snowflake"}:
        return f"SPLIT_PART({column_expr}, '{delimiter}', {part_value})"
    if dialect == "sqlite":
        if part_value != 1:
            raise ValueError("sqlite split_part_expr currently only supports part=1")
        return (
            f"CASE WHEN instr({column_expr}, '{delimiter}') > 0 "
            f"THEN substr({column_expr}, 1, instr({column_expr}, '{delimiter}') - 1) "
            f"ELSE {column_expr} END"
        )
    return f"SPLIT_PART({column_expr}, '{delimiter}', {part_value})"


def select_array_elements_subquery(*, array_column: str, dialect: str) -> str:
    """Return a subquery that yields (control, rule_id) rows from a rules array column."""

    if dialect == "snowflake":
        return (
            "SELECT elem.value::string as control, r.rule_id "
            "FROM rules r, LATERAL FLATTEN(input => r." + array_column + ") elem "
            "WHERE r." + array_column + " IS NOT NULL"
        )

    if dialect == "sqlite":
        return (
            "SELECT elem.value as control, r.rule_id "
            "FROM rules r, json_each(r." + array_column + ") elem "
            "WHERE r." + array_column + " IS NOT NULL"
        )

    return (
        "SELECT UNNEST(r." + array_column + ") as control, r.rule_id "
        "FROM rules r "
        "WHERE r." + array_column + " IS NOT NULL"
    )


def json_object_function(*, dialect: str) -> str:
    if dialect == "snowflake":
        return "OBJECT_CONSTRUCT"
    if dialect == "sqlite":
        return "json_object"
    return "jsonb_build_object"


def cast_to_string_expr(*, column_expr: str, dialect: str) -> str:
    if dialect == "snowflake":
        return f"TO_VARCHAR({column_expr})"
    if dialect == "sqlite":
        return f"CAST({column_expr} AS TEXT)"
    return f"({column_expr})::text"


def json_text_extract_expr(*, column_expr: str, key: str, dialect: str) -> str:
    if dialect == "snowflake":
        return f"{column_expr}:\"{key}\"::string"
    if dialect == "sqlite":
        return f"json_extract({column_expr}, '$.{key}')"
    if dialect == "postgresql":
        return f"{column_expr} ->> '{key}'"
    return f"{column_expr} ->> '{key}'"


def array_length_expr(*, column_expr: str, dialect: str) -> str:
    """Return an expression that yields the length of an array/JSON array column."""

    if dialect == "snowflake":
        return f"ARRAY_SIZE({column_expr})"
    if dialect == "sqlite":
        return f"json_array_length({column_expr})"
    if dialect == "postgresql":
        return f"CARDINALITY({column_expr})"
    return f"CARDINALITY({column_expr})"


def array_has_elements_expr(*, column_expr: str, dialect: str) -> str:
    """Return a boolean predicate that is true when the array has >= 1 element."""

    length = array_length_expr(column_expr=column_expr, dialect=dialect)
    return f"(COALESCE({length}, 0) > 0)"
