from __future__ import annotations

from sqlalchemy import String
from sqlalchemy.dialects.sqlite import dialect as SQLiteDialect

from snowflake.sqlalchemy.custom_types import ARRAY as SnowflakeArray
from snowflake.sqlalchemy.custom_types import VARIANT as SnowflakeVariant
from snowflake.sqlalchemy.snowdialect import SnowflakeDialect

from cerebro.core.database_types import ArrayType, JSONType


def test_array_type_uses_native_snowflake_array() -> None:
    dialect = SnowflakeDialect()
    array_type = ArrayType(String)

    impl = array_type.load_dialect_impl(dialect)
    assert isinstance(impl, SnowflakeArray)


def test_array_type_does_not_json_encode_on_snowflake_bind() -> None:
    dialect = SnowflakeDialect()
    array_type = ArrayType(String)

    value = ["cis.1.1", "cis.1.2"]
    assert array_type.process_bind_param(value, dialect) == value


def test_array_type_keeps_sqlite_json_text_encoding() -> None:
    dialect = SQLiteDialect()
    array_type = ArrayType(String)

    value = ["a", "b"]
    encoded = array_type.process_bind_param(value, dialect)
    assert isinstance(encoded, str)


def test_array_type_parses_snowflake_string_results() -> None:
    dialect = SnowflakeDialect()
    array_type = ArrayType(String)

    assert array_type.process_result_value('["a", "b"]', dialect) == ["a", "b"]


def test_json_type_uses_snowflake_variant() -> None:
    dialect = SnowflakeDialect()
    json_type = JSONType()

    impl = json_type.load_dialect_impl(dialect)
    assert isinstance(impl, SnowflakeVariant)


def test_json_type_parses_snowflake_string_results() -> None:
    dialect = SnowflakeDialect()
    json_type = JSONType()

    assert json_type.process_result_value('{"a": 1}', dialect) == {"a": 1}
