package snowflake

import (
	"testing"
)

func TestNewClient_EmptyConnectionString(t *testing.T) {
	_, err := NewClient("", "", "")
	if err == nil {
		t.Error("expected error for empty connection string")
	}
}

func TestQueryResult_Fields(t *testing.T) {
	result := &QueryResult{
		Columns: []string{"id", "name", "value"},
		Rows: []map[string]interface{}{
			{"id": 1, "name": "test1", "value": 100},
			{"id": 2, "name": "test2", "value": 200},
		},
		Count: 2,
	}

	if len(result.Columns) != 3 {
		t.Errorf("expected 3 columns, got %d", len(result.Columns))
	}

	if len(result.Rows) != 2 {
		t.Errorf("expected 2 rows, got %d", len(result.Rows))
	}

	if result.Rows[0]["name"] != "test1" {
		t.Error("row data incorrect")
	}
}

// Note: Full integration tests require a real Snowflake connection
// These are unit tests for data structures and basic validation

func TestSchemaConstants(t *testing.T) {
	if SchemaName == "" {
		t.Error("SchemaName should not be empty")
	}

	if SchemaName != "CEREBRO" {
		t.Errorf("SchemaName = %s, want CEREBRO", SchemaName)
	}
}

func TestTableDDLs(t *testing.T) {
	expectedTables := []string{
		"findings",
		"tickets",
		"access_reviews",
		"review_items",
	}

	for _, table := range expectedTables {
		if _, ok := TableDDLs[table]; !ok {
			t.Errorf("expected DDL for table %s", table)
		}
	}
}

func TestTableDDLs_ContainsPrimaryKey(t *testing.T) {
	for name, ddl := range TableDDLs {
		if !contains(ddl, "PRIMARY KEY") {
			t.Errorf("table %s DDL should have PRIMARY KEY", name)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr, 0))
}

func containsAt(s, substr string, start int) bool {
	for i := start; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
