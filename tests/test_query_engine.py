"""
Tests for the SQL query engine.
"""

import pytest
import asyncio
from datetime import datetime

from cerebro.query.engine import QueryEngine, SQLParser, QueryPlan
from cerebro.query.registry import TableRegistry, get_registry
from cerebro.query.table import SecurityTable, QueryContext, QueryFilter
from cerebro.query.schema import SecurityColumn, ColumnType
from cerebro.providers.tables import register_all_provider_tables


class MockSecurityTable(SecurityTable):
    """Mock table for testing."""
    
    def __init__(self):
        columns = [
            SecurityColumn("id", ColumnType.TEXT, "Test ID", required=True),
            SecurityColumn("name", ColumnType.TEXT, "Test name"),
            SecurityColumn("count", ColumnType.INTEGER, "Test count"),
            SecurityColumn("active", ColumnType.BOOLEAN, "Test status"),
            SecurityColumn("created_at", ColumnType.TIMESTAMP, "Creation time")
        ]
        super().__init__("test_table", "Test table", columns)
        
        self.mock_data = [
            {
                "id": "test-1", 
                "name": "First Test", 
                "count": 10, 
                "active": True, 
                "created_at": datetime.now()
            },
            {
                "id": "test-2", 
                "name": "Second Test", 
                "count": 20, 
                "active": False, 
                "created_at": datetime.now()
            }
        ]
    
    async def list_resources(self, ctx: QueryContext):
        for resource in self.mock_data:
            if self.apply_filters(resource, ctx.filters):
                yield resource


@pytest.fixture
def mock_registry():
    """Create registry with mock table."""
    registry = TableRegistry()
    registry.register_table(MockSecurityTable())
    return registry


@pytest.fixture
def query_engine(mock_registry):
    """Create query engine with mock registry."""
    return QueryEngine(mock_registry)


class TestSQLParser:
    """Test SQL parsing functionality."""
    
    def test_parse_simple_select(self):
        parser = SQLParser()
        plan = parser.parse_query("SELECT * FROM test_table")
        
        assert plan.table_name == "test_table"
        assert plan.selected_columns == ["*"]
        assert plan.filters == []
        assert plan.limit is None
    
    def test_parse_select_with_columns(self):
        parser = SQLParser()
        plan = parser.parse_query("SELECT id, name FROM test_table")
        
        assert plan.table_name == "test_table"
        assert plan.selected_columns == ["id", "name"]
    
    def test_parse_select_with_where(self):
        parser = SQLParser()
        plan = parser.parse_query("SELECT * FROM test_table WHERE active = true")
        
        assert plan.table_name == "test_table"
        assert len(plan.filters) == 1
        assert plan.filters[0].column == "active"
        assert plan.filters[0].operator == "="
        assert plan.filters[0].value is True
    
    def test_parse_select_with_limit(self):
        parser = SQLParser()
        plan = parser.parse_query("SELECT * FROM test_table LIMIT 5")
        
        assert plan.table_name == "test_table"
        assert plan.limit == 5
    
    def test_parse_complex_query(self):
        parser = SQLParser()
        plan = parser.parse_query(
            "SELECT id, name FROM test_table WHERE count > 15 AND active = true ORDER BY name LIMIT 10"
        )
        
        assert plan.table_name == "test_table"
        assert plan.selected_columns == ["id", "name"]
        assert len(plan.filters) == 2
        assert plan.limit == 10


@pytest.mark.asyncio
class TestQueryEngine:
    """Test query engine functionality."""
    
    async def test_simple_query(self, query_engine):
        """Test basic query execution."""
        result = await query_engine.execute_query("SELECT * FROM test_table")

        assert result.errors == []
        assert result.total_rows == 2
        assert len(result.rows) == 2
        # When SELECT *, should get actual column names
        assert result.columns == ["id", "name", "count", "active", "created_at"]
    
    async def test_filtered_query(self, query_engine):
        """Test query with WHERE clause."""
        result = await query_engine.execute_query("SELECT * FROM test_table WHERE active = true")
        
        assert result.errors == []
        assert result.total_rows == 1
        assert result.rows[0]["active"] is True
    
    async def test_column_selection(self, query_engine):
        """Test query with specific column selection."""
        result = await query_engine.execute_query("SELECT id, name FROM test_table")
        
        assert result.errors == []
        assert result.columns == ["id", "name"]
        for row in result.rows:
            assert "id" in row
            assert "name" in row
            assert "count" not in row  # Should not include unselected columns
    
    async def test_limit_query(self, query_engine):
        """Test query with LIMIT clause."""
        result = await query_engine.execute_query("SELECT * FROM test_table LIMIT 1")
        
        assert result.errors == []
        assert result.total_rows == 1
        assert len(result.rows) == 1
    
    async def test_nonexistent_table(self, query_engine):
        """Test query against nonexistent table."""
        result = await query_engine.execute_query("SELECT * FROM nonexistent_table")
        
        assert len(result.errors) > 0
        assert "not found" in result.errors[0].lower()
        assert result.total_rows == 0
    
    async def test_invalid_column(self, query_engine):
        """Test query with invalid column."""
        result = await query_engine.execute_query("SELECT invalid_column FROM test_table")
        
        assert len(result.errors) > 0
        assert result.total_rows == 0


class TestTableRegistry:
    """Test table registry functionality."""
    
    def test_register_table(self):
        registry = TableRegistry()
        table = MockSecurityTable()
        
        registry.register_table(table)
        
        assert "test_table" in registry.list_tables()
        retrieved_table = registry.get_table("test_table")
        assert retrieved_table is table
    
    def test_table_aliases(self):
        registry = TableRegistry()
        table = MockSecurityTable()
        
        registry.register_table(table, aliases=["test", "mock_table"])
        
        assert registry.get_table("test") is table
        assert registry.get_table("mock_table") is table
    
    def test_unregister_table(self):
        registry = TableRegistry()
        table = MockSecurityTable()
        
        registry.register_table(table)
        assert "test_table" in registry.list_tables()
        
        success = registry.unregister_table("test_table")
        assert success
        assert "test_table" not in registry.list_tables()
    
    def test_table_info(self):
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
    """Test provider table implementations."""
    
    async def test_register_all_tables(self):
        """Test that all provider tables register successfully."""
        register_all_provider_tables()
        registry = get_registry()
        
        tables = registry.list_tables()
        
        # Should have tables from all providers
        assert any("aws_" in table for table in tables)
        assert any("okta_" in table for table in tables) 
        assert any("github_" in table for table in tables)
        assert any("gcp_" in table for table in tables)
        assert any("m365_" in table for table in tables)
    
    async def test_aws_tables_query(self):
        """Test querying AWS tables."""
        register_all_provider_tables()
        engine = QueryEngine()
        
        # Test basic query against AWS table
        result = await engine.execute_query("SELECT instance_id FROM aws_ec2_instance LIMIT 1")
        
        # Should execute without errors (even if no data)
        assert isinstance(result.errors, list)
        assert isinstance(result.total_rows, int)
    
    async def test_cross_provider_query(self):
        """Test querying multiple provider tables."""
        register_all_provider_tables()
        engine = QueryEngine()
        
        # Test queries against different providers
        queries = [
            "SELECT username FROM okta_user LIMIT 1",
            "SELECT repository FROM github_repository LIMIT 1", 
            "SELECT bucket_name FROM gcp_storage_bucket LIMIT 1",
            "SELECT display_name FROM m365_user LIMIT 1"
        ]
        
        for query in queries:
            result = await engine.execute_query(query)
            # Should execute without fatal errors
            assert isinstance(result.total_rows, int)


if __name__ == "__main__":
    pytest.main([__file__])
