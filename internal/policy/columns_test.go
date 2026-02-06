package policy

import (
	"testing"
)

func TestExtractConditionField(t *testing.T) {
	tests := []struct {
		condition string
		field     string
	}{
		{"public == true", "public"},
		{"encryption_enabled != false", "encryption_enabled"},
		{"max_age > 90", "max_age"},
		{"count < 10", "count"},
		{"name contains \"prod\"", "name"},
		{"tags.env exists", "tags.env"},
		{"mfa not exists", "mfa"},
		{"config.public_access.enabled == true", "config.public_access.enabled"},
		{"", ""},
	}

	for _, tc := range tests {
		got := extractConditionField(tc.condition)
		if got != tc.field {
			t.Errorf("extractConditionField(%q) = %q, want %q", tc.condition, got, tc.field)
		}
	}
}

func TestColumnsForTable(t *testing.T) {
	e := NewEngine()
	e.AddPolicy(&Policy{
		ID:         "p1",
		Resource:   "aws::s3::bucket",
		Conditions: []string{"public == true", "encryption_enabled != false"},
		Severity:   "high",
	})
	e.AddPolicy(&Policy{
		ID:         "p2",
		Resource:   "aws::s3::bucket",
		Conditions: []string{"versioning_enabled == false"},
		Severity:   "medium",
	})
	e.AddPolicy(&Policy{
		ID:         "p3",
		Resource:   "aws::iam::role",
		Conditions: []string{"assume_role_policy contains \"*\""},
		Severity:   "critical",
	})

	cols := e.ColumnsForTable("aws_s3_buckets")

	// Should include metadata columns + policy-referenced columns
	colSet := make(map[string]bool)
	for _, c := range cols {
		colSet[c] = true
	}

	if !colSet["_cq_id"] {
		t.Error("missing _cq_id")
	}
	if !colSet["_cq_sync_time"] {
		t.Error("missing _cq_sync_time")
	}
	if !colSet["public"] {
		t.Error("missing public")
	}
	if !colSet["encryption_enabled"] {
		t.Error("missing encryption_enabled")
	}
	if !colSet["versioning_enabled"] {
		t.Error("missing versioning_enabled")
	}
	// IAM role column should NOT be included for s3 table
	if colSet["assume_role_policy"] {
		t.Error("should not include columns from unrelated policies")
	}
}

func TestColumnsForTable_NestedField(t *testing.T) {
	e := NewEngine()
	e.AddPolicy(&Policy{
		ID:         "p1",
		Resource:   "aws::s3::bucket",
		Conditions: []string{"config.public_access.enabled == true"},
		Severity:   "high",
	})

	cols := e.ColumnsForTable("aws_s3_buckets")
	colSet := make(map[string]bool)
	for _, c := range cols {
		colSet[c] = true
	}

	// Should extract top-level column "config", not the full path
	if !colSet["config"] {
		t.Error("missing top-level column 'config' for nested field")
	}
}

func TestColumnsForTable_NoPolicies(t *testing.T) {
	e := NewEngine()
	cols := e.ColumnsForTable("aws_s3_buckets")
	// Should still have metadata columns
	if len(cols) < 2 {
		t.Errorf("expected at least metadata columns, got %d", len(cols))
	}
}
