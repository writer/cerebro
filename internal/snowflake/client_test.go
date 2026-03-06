package snowflake

import (
	"testing"
)

func TestNewClient_MissingKeyPairConfig(t *testing.T) {
	_, err := NewClient(ClientConfig{})
	if err == nil {
		t.Error("expected error for missing Snowflake key-pair configuration")
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

	if result.Count != 2 {
		t.Errorf("expected count 2, got %d", result.Count)
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

func TestValidateTableName_Valid(t *testing.T) {
	validNames := []string{
		"aws_iam_users",
		"my_table",
		"Table123",
		"_internal",
	}

	for _, name := range validNames {
		if err := ValidateTableName(name); err != nil {
			t.Errorf("ValidateTableName(%q) = %v, want nil", name, err)
		}
	}
}

func TestValidateTableName_Invalid(t *testing.T) {
	invalidNames := []string{
		"",
		"table; DROP TABLE users",
		"table--comment",
		"table/*comment*/",
		"table'quote",
		"123_starts_with_number",
		"table name with spaces",
		"table OR 1=1",
	}

	for _, name := range invalidNames {
		if err := ValidateTableName(name); err == nil {
			t.Errorf("ValidateTableName(%q) = nil, want error", name)
		}
	}
}

func TestValidateColumnName_Valid(t *testing.T) {
	validNames := []string{
		"column",
		"my_column",
		"Column123",
		"_internal",
	}

	for _, name := range validNames {
		if err := ValidateColumnName(name); err != nil {
			t.Errorf("ValidateColumnName(%q) = %v, want nil", name, err)
		}
	}
}

func TestValidateColumnName_Invalid(t *testing.T) {
	invalidNames := []string{
		"",
		"column; DROP TABLE users",
		"column--comment",
		"column/*comment*/",
		"column'quote",
		"123_starts_with_number",
		"column name with spaces",
		"column OR 1=1",
	}

	for _, name := range invalidNames {
		if err := ValidateColumnName(name); err == nil {
			t.Errorf("ValidateColumnName(%q) = nil, want error", name)
		}
	}
}

func TestValidateTableNameStrict_KnownPrefixes(t *testing.T) {
	knownPrefixes := []string{
		"aws_iam_users",
		"gcp_compute_instances",
		"azure_storage_accounts",
		"okta_users",
		"mdm_devices",
		"backups",
		"cerebro_findings",
	}

	for _, name := range knownPrefixes {
		if err := ValidateTableNameStrict(name); err != nil {
			t.Errorf("ValidateTableNameStrict(%q) = %v, want nil", name, err)
		}
	}
}

func TestValidateTableNameStrict_UnknownPrefix(t *testing.T) {
	if err := ValidateTableNameStrict("unknown_table"); err == nil {
		t.Error("ValidateTableNameStrict should reject unknown prefixes")
	}
}

func TestQuoteIdentifier(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"table", `"table"`},
		{"my_table", `"my_table"`},
		{`table"quote`, `"table""quote"`},
	}

	for _, tc := range tests {
		result := QuoteIdentifier(tc.input)
		if result != tc.expected {
			t.Errorf("QuoteIdentifier(%q) = %q, want %q", tc.input, result, tc.expected)
		}
	}
}

func TestSafeTableRef_Valid(t *testing.T) {
	ref, err := SafeTableRef("CEREBRO", "RAW", "aws_iam_users")
	if err != nil {
		t.Errorf("SafeTableRef returned error: %v", err)
	}

	// SafeTableRef normalizes to uppercase for Snowflake
	expected := "CEREBRO.RAW.AWS_IAM_USERS"
	if ref != expected {
		t.Errorf("SafeTableRef = %q, want %q", ref, expected)
	}
}

func TestSafeTableRef_InvalidTable(t *testing.T) {
	_, err := SafeTableRef("CEREBRO", "RAW", "table; DROP")
	if err == nil {
		t.Error("SafeTableRef should reject invalid table name")
	}
}

func TestSafeTableRef_InvalidDatabase(t *testing.T) {
	_, err := SafeTableRef("bad;db", "RAW", "aws_iam_users")
	if err == nil {
		t.Error("SafeTableRef should reject invalid database name")
	}
}

func TestSafeTableRef_InvalidSchema(t *testing.T) {
	_, err := SafeTableRef("CEREBRO", "bad schema", "aws_iam_users")
	if err == nil {
		t.Error("SafeTableRef should reject invalid schema name")
	}
}
