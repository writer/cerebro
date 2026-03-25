package tableops

import (
	"testing"
)

func TestNormalizeReserved(t *testing.T) {
	custom := map[string]struct{}{
		"custom_col": {},
	}
	result := normalizeReserved(custom)

	expected := []string{"_CQ_ID", "_CQ_HASH", "_CQ_SYNC_TIME", "CUSTOM_COL"}
	for _, key := range expected {
		if _, ok := result[key]; !ok {
			t.Errorf("normalizeReserved should contain %q", key)
		}
	}
}

func TestFilteredColumns(t *testing.T) {
	reserved := map[string]struct{}{
		"_CQ_ID":        {},
		"_CQ_HASH":      {},
		"_CQ_SYNC_TIME": {},
	}

	columns := []string{"name", "_CQ_ID", "region", "", "name"} // duplicates + reserved
	result := filteredColumns(columns, reserved)

	if len(result) != 2 {
		t.Fatalf("expected 2 columns, got %d: %v", len(result), result)
	}
}

func TestValidateColumns(t *testing.T) {
	if err := validateColumns([]string{"valid_col", "another"}); err != nil {
		t.Errorf("validateColumns valid: unexpected error: %v", err)
	}

	if err := validateColumns([]string{"valid", "bad;col"}); err == nil {
		t.Error("validateColumns should reject invalid column names")
	}
}

func TestColumnsMissingFromSchema(t *testing.T) {
	existing := []string{"id", "name", "status"}
	desired := []string{"id", "name", "region", "account"}

	missing := columnsMissingFromSchema(existing, desired)
	if len(missing) != 2 {
		t.Fatalf("expected 2 missing columns, got %d: %v", len(missing), missing)
	}
}

func TestStringValue(t *testing.T) {
	tests := []struct {
		name  string
		input interface{}
		want  string
	}{
		{"nil", nil, ""},
		{"string", "hello", "hello"},
		{"bytes", []byte("world"), "world"},
		{"int", 42, "42"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := stringValue(tt.input); got != tt.want {
				t.Errorf("stringValue(%v) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestLookupCaseInsensitive(t *testing.T) {
	row := map[string]interface{}{
		"Column_Name": "test_value",
	}

	// exact match
	if v := lookupCaseInsensitive(row, "Column_Name"); v != "test_value" {
		t.Errorf("exact match failed: %v", v)
	}

	// case-insensitive match
	if v := lookupCaseInsensitive(row, "column_name"); v != "test_value" {
		t.Errorf("case-insensitive match failed: %v", v)
	}

	// no match
	if v := lookupCaseInsensitive(row, "nonexistent"); v != nil {
		t.Errorf("expected nil for nonexistent key, got %v", v)
	}

	// nil row
	if v := lookupCaseInsensitive(nil, "key"); v != nil {
		t.Errorf("expected nil for nil row, got %v", v)
	}
}
