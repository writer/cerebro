package policy

import (
	"reflect"
	"testing"
)

func TestExtractConditionFields(t *testing.T) {
	tests := []struct {
		condition string
		fields    []string
	}{
		{
			condition: "subject_kind IN ('User', 'ServiceAccount')",
			fields:    []string{"subject_kind"},
		},
		{
			condition: "risk_reasons CONTAINS 'secret_access'",
			fields:    []string{"risk_reasons"},
		},
		{
			condition: "(wildcard_verbs == true OR wildcard_resources == true)",
			fields:    []string{"wildcard_verbs", "wildcard_resources"},
		},
		{
			condition: "labels['pod-security.kubernetes.io/enforce'] == null",
			fields:    []string{"labels['pod-security.kubernetes.io/enforce']"},
		},
	}

	for _, tc := range tests {
		got := extractConditionFields(tc.condition)
		if !reflect.DeepEqual(got, tc.fields) {
			t.Errorf("extractConditionFields(%q) = %v, want %v", tc.condition, got, tc.fields)
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

func TestColumnsForTable_BracketAndOrConditions(t *testing.T) {
	e := NewEngine()
	e.AddPolicy(&Policy{
		ID:       "p1",
		Resource: "k8s::rbac::risky_binding",
		Conditions: []string{
			"subject_kind IN ('User', 'ServiceAccount')",
			"(wildcard_verbs == true OR wildcard_resources == true)",
			"risk_reasons CONTAINS 'secret_access'",
		},
		Severity: "low",
	})
	e.AddPolicy(&Policy{
		ID:         "p2",
		Resource:   "k8s::namespace",
		Conditions: []string{"labels['pod-security.kubernetes.io/enforce'] == null"},
		Severity:   "low",
	})

	rbacCols := e.ColumnsForTable("k8s_rbac_risky_bindings")
	rbacSet := make(map[string]bool)
	for _, c := range rbacCols {
		rbacSet[c] = true
	}
	for _, want := range []string{"subject_kind", "wildcard_verbs", "wildcard_resources", "risk_reasons"} {
		if !rbacSet[want] {
			t.Errorf("missing column %q for risky binding table", want)
		}
	}

	namespaceCols := e.ColumnsForTable("k8s_core_namespaces")
	nsSet := make(map[string]bool)
	for _, c := range namespaceCols {
		nsSet[c] = true
	}
	if !nsSet["labels"] {
		t.Error("missing top-level column 'labels' for bracket condition")
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
