"""Tests for the SQL query engine and registry."""

from datetime import datetime

import pytest

from cerebro.providers.tables import register_all_provider_tables
from cerebro.query.engine import QueryEngine, SQLParser
from cerebro.query.registry import TableRegistry, get_registry
from cerebro.query.schema import ColumnType, SecurityColumn
from cerebro.query.table import QueryContext, SecurityTable


class MockSecurityTable(SecurityTable):
    """Simple in-memory table used for testing."""

    def __init__(self) -> None:
        columns = [
            SecurityColumn("id", ColumnType.TEXT, "Test ID", required=True),
            SecurityColumn("name", ColumnType.TEXT, "Test name"),
            SecurityColumn("count", ColumnType.INTEGER, "Test count"),
            SecurityColumn("active", ColumnType.BOOLEAN, "Test status"),
            SecurityColumn("created_at", ColumnType.TIMESTAMP, "Creation time"),
        ]
        super().__init__("test_table", "Test table", columns)
        now = datetime.now()
        self._rows = [
            {
                "id": "test-1",
                "name": "First Test",
                "count": 10,
                "active": True,
                "created_at": now,
            },
            {
                "id": "test-2",
                "name": "Second Test",
                "count": 20,
                "active": False,
                "created_at": now,
            },
        ]

    async def list_resources(self, ctx: QueryContext):  # type: ignore[override]
        for resource in self._rows:
            if self.apply_filters(resource, ctx.filters):
                yield resource


@pytest.fixture
def mock_registry() -> TableRegistry:
    registry = TableRegistry()
    registry.register_table(MockSecurityTable())
    return registry


@pytest.fixture
def query_engine(mock_registry: TableRegistry) -> QueryEngine:
    return QueryEngine(mock_registry)


class TestSQLParser:
    """Unit tests for SQL parsing utility."""

    def test_parse_simple_select(self) -> None:
        parser = SQLParser()
        plan = parser.parse_query("SELECT * FROM test_table")

        assert plan.table_name == "test_table"
        assert plan.selected_columns == ["*"]
        assert plan.filters == []
        assert plan.limit is None

    def test_parse_select_with_columns(self) -> None:
        parser = SQLParser()
        plan = parser.parse_query("SELECT id, name FROM test_table")

        assert plan.table_name == "test_table"
        assert plan.selected_columns == ["id", "name"]

    def test_parse_select_with_where(self) -> None:
        parser = SQLParser()
        plan = parser.parse_query("SELECT * FROM test_table WHERE active = true")

        assert plan.table_name == "test_table"
        assert len(plan.filters) == 1
        assert plan.filters[0].column == "active"
        assert plan.filters[0].operator == "="
        assert plan.filters[0].value is True

    def test_parse_select_with_limit(self) -> None:
        parser = SQLParser()
        plan = parser.parse_query("SELECT * FROM test_table LIMIT 5")

        assert plan.table_name == "test_table"
        assert plan.limit == 5

    def test_parse_complex_query(self) -> None:
        parser = SQLParser()
        plan = parser.parse_query(
            "SELECT id, name FROM test_table WHERE count > 15 AND active = true "
            "ORDER BY name LIMIT 10"
        )

        assert plan.table_name == "test_table"
        assert plan.selected_columns == ["id", "name"]
        assert len(plan.filters) == 2
        assert plan.limit == 10


@pytest.mark.asyncio
class TestQueryEngine:
    """Integration-style tests for the query engine."""

    async def test_simple_query(self, query_engine: QueryEngine) -> None:
        result = await query_engine.execute_query("SELECT * FROM test_table")

        assert result.errors == []
        assert result.total_rows == 2
        assert len(result.rows) == 2
        assert result.columns == ["id", "name", "count", "active", "created_at"]

    async def test_filtered_query(self, query_engine: QueryEngine) -> None:
        result = await query_engine.execute_query(
            "SELECT * FROM test_table WHERE active = true"
        )

        assert result.errors == []
        assert result.total_rows == 1
        assert result.rows[0]["active"] is True

    async def test_column_selection(self, query_engine: QueryEngine) -> None:
        result = await query_engine.execute_query("SELECT id, name FROM test_table")

        assert result.errors == []
        assert result.columns == ["id", "name"]
        for row in result.rows:
            assert set(row.keys()) == {"id", "name"}

    async def test_limit_query(self, query_engine: QueryEngine) -> None:
        result = await query_engine.execute_query("SELECT * FROM test_table LIMIT 1")

        assert result.errors == []
        assert result.total_rows == 1
        assert len(result.rows) == 1

    async def test_nonexistent_table(self, query_engine: QueryEngine) -> None:
        result = await query_engine.execute_query("SELECT * FROM nonexistent_table")

        assert result.errors
        assert "not found" in result.errors[0].lower()
        assert result.total_rows == 0

    async def test_invalid_column(self, query_engine: QueryEngine) -> None:
        result = await query_engine.execute_query(
            "SELECT invalid_column FROM test_table"
        )

        assert result.errors
        assert result.total_rows == 0


class TestTableRegistry:
    """Tests for the table registry helpers."""

    def test_register_table(self) -> None:
        registry = TableRegistry()
        table = MockSecurityTable()

        registry.register_table(table)

        assert "test_table" in registry.list_tables()
        retrieved_table = registry.get_table("test_table")
        assert retrieved_table is table

    def test_table_aliases(self) -> None:
        registry = TableRegistry()
        table = MockSecurityTable()

        registry.register_table(table, aliases=["test", "mock_table"])

        assert registry.get_table("test") is table
        assert registry.get_table("mock_table") is table

    def test_unregister_table(self) -> None:
        registry = TableRegistry()
        table = MockSecurityTable()

        registry.register_table(table)
        assert "test_table" in registry.list_tables()

        success = registry.unregister_table("test_table")
        assert success
        assert "test_table" not in registry.list_tables()

    def test_table_info(self) -> None:
        registry = TableRegistry()
        table = MockSecurityTable()

        registry.register_table(table)
        info = registry.get_table_info("test_table")

        assert info is not None
        assert info["name"] == "test_table"
        assert info["description"] == "Test table"
        assert len(info["columns"]) == 5


@pytest.mark.asyncio
class TestProviderTables:
    """Smoke tests for provider table registration."""

    async def test_register_all_tables(self) -> None:
        register_all_provider_tables()
        registry = get_registry()
        tables = registry.list_tables()

        assert any(name.startswith("aws_") for name in tables)
        assert any(name.startswith("okta_") for name in tables)
        assert any(name.startswith("github_") for name in tables)
        assert any(name.startswith("gcp_") for name in tables)
        assert any(name.startswith("m365_") for name in tables)

    async def test_aws_tables_query(self) -> None:
        register_all_provider_tables()
        engine = QueryEngine()

        result = await engine.execute_query(
            "SELECT instance_id FROM aws_ec2_instance LIMIT 1"
        )

        assert isinstance(result.errors, list)
        assert isinstance(result.total_rows, int)

    async def test_cross_provider_query(self) -> None:
        register_all_provider_tables()
        engine = QueryEngine()

        queries = [
            "SELECT username FROM okta_user LIMIT 1",
            "SELECT repository FROM github_repository LIMIT 1",
            "SELECT bucket_name FROM gcp_storage_bucket LIMIT 1",
            "SELECT display_name FROM m365_user LIMIT 1",
        ]

        for query in queries:
            result = await engine.execute_query(query)
            assert isinstance(result.total_rows, int)


if __name__ == "__main__":
    pytest.main([__file__])
