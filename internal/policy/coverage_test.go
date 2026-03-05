package policy

import (
	"math"
	"testing"
)

func TestCoverageReport(t *testing.T) {
	engine := NewEngine()
	engine.policies = map[string]*Policy{
		"p1": {ID: "p1", Name: "Policy 1", Resource: "aws::s3::bucket"},
		"p2": {ID: "p2", Name: "Policy 2", Resource: "aws::ec2::instance"},
		"p3": {ID: "p3", Name: "Policy 3", Resource: "unknown::thing"},
	}

	report := engine.CoverageReport([]string{"aws_s3_buckets"})
	if report.TotalPolicies != 3 {
		t.Fatalf("expected 3 policies, got %d", report.TotalPolicies)
	}
	if report.CoveredPolicies != 1 {
		t.Fatalf("expected 1 covered policy, got %d", report.CoveredPolicies)
	}
	if report.UncoveredPolicies != 1 {
		t.Fatalf("expected 1 uncovered policy, got %d", report.UncoveredPolicies)
	}
	if report.UnknownResourcePolicies != 1 {
		t.Fatalf("expected 1 unknown policy, got %d", report.UnknownResourcePolicies)
	}
	if report.MissingTables["aws_ec2_instances"] != 1 {
		t.Fatalf("expected aws_ec2_instances missing once, got %d", report.MissingTables["aws_ec2_instances"])
	}
	if report.MissingByProvider["aws"] != 1 {
		t.Fatalf("expected aws provider missing count 1, got %d", report.MissingByProvider["aws"])
	}
	if math.Abs(report.CoveragePercent-33.3333) > 0.5 {
		t.Fatalf("unexpected coverage percent: %.2f", report.CoveragePercent)
	}
	if math.Abs(report.KnownCoveragePercent-50.0) > 0.1 {
		t.Fatalf("unexpected known coverage percent: %.2f", report.KnownCoveragePercent)
	}
}

func TestCoverageReport_QueryPolicyFallback(t *testing.T) {
	engine := NewEngine()
	engine.policies = map[string]*Policy{
		"qp-covered": {
			ID:    "qp-covered",
			Name:  "Query Covered",
			Query: "SELECT id FROM okta_system_logs",
		},
		"qp-missing": {
			ID:    "qp-missing",
			Name:  "Query Missing",
			Query: "SELECT id FROM custom_events",
		},
	}

	report := engine.CoverageReport([]string{"okta_system_logs"})
	if report.TotalPolicies != 2 {
		t.Fatalf("expected 2 policies, got %d", report.TotalPolicies)
	}
	if report.CoveredPolicies != 1 {
		t.Fatalf("expected 1 covered query policy, got %d", report.CoveredPolicies)
	}
	if report.UncoveredPolicies != 1 {
		t.Fatalf("expected 1 uncovered query policy, got %d", report.UncoveredPolicies)
	}
	if report.UnknownResourcePolicies != 0 {
		t.Fatalf("expected 0 unknown query policies, got %d", report.UnknownResourcePolicies)
	}
	if report.MissingTables["custom_events"] != 1 {
		t.Fatalf("expected custom_events to be missing once, got %d", report.MissingTables["custom_events"])
	}
}

func TestCoverageReport_ResourcePolicyCoveredByAnyMappedTable(t *testing.T) {
	engine := NewEngine()
	engine.policies = map[string]*Policy{
		"p1": {
			ID:       "p1",
			Name:     "Compute policy",
			Resource: "compute::instance",
		},
	}

	report := engine.CoverageReport([]string{"aws_ec2_instances"})
	if report.CoveredPolicies != 1 {
		t.Fatalf("expected compute policy to be covered when one mapped table is present, got %d", report.CoveredPolicies)
	}
	if report.UncoveredPolicies != 0 {
		t.Fatalf("expected no uncovered policies, got %d", report.UncoveredPolicies)
	}
	if len(report.MissingTables) != 0 {
		t.Fatalf("expected no missing tables to be counted for covered policy, got %v", report.MissingTables)
	}
}

func TestCoverageReport_QueryPolicyRequiresAllReferencedTables(t *testing.T) {
	engine := NewEngine()
	engine.policies = map[string]*Policy{
		"qp-join": {
			ID:    "qp-join",
			Name:  "Joined query policy",
			Query: "SELECT l.id FROM okta_system_logs l JOIN employees e ON e.email = l.actor_email",
		},
	}

	report := engine.CoverageReport([]string{"okta_system_logs"})
	if report.CoveredPolicies != 0 {
		t.Fatalf("expected query policy to be uncovered when join table is missing, got %d covered", report.CoveredPolicies)
	}
	if report.UncoveredPolicies != 1 {
		t.Fatalf("expected 1 uncovered query policy, got %d", report.UncoveredPolicies)
	}
	if report.MissingTables["employees"] != 1 {
		t.Fatalf("expected employees to be missing once, got %d", report.MissingTables["employees"])
	}
	if report.MissingByProvider["employees"] != 1 {
		t.Fatalf("expected missing provider bucket for employees, got %v", report.MissingByProvider)
	}
}

func TestTableProvider(t *testing.T) {
	tests := []struct {
		name  string
		table string
		want  string
	}{
		{name: "aws", table: "aws_ec2_instances", want: "aws"},
		{name: "google workspace", table: "google_workspace_users", want: "google_workspace"},
		{name: "terraform cloud", table: "terraform_cloud_workspaces", want: "terraform_cloud"},
		{name: "single token", table: "employees", want: "employees"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tableProvider(tt.table); got != tt.want {
				t.Fatalf("tableProvider(%q) = %q, want %q", tt.table, got, tt.want)
			}
		})
	}
}

func TestCoverageThresholdFromEnv(t *testing.T) {
	t.Setenv("CEREBRO_POLICY_COVERAGE_MIN", "82.5")
	value, ok, err := CoverageThresholdFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected threshold to be set")
	}
	if value != 82.5 {
		t.Fatalf("expected 82.5, got %.1f", value)
	}

	t.Setenv("CEREBRO_POLICY_COVERAGE_MIN", "bad")
	_, ok, err = CoverageThresholdFromEnv()
	if err == nil || ok {
		t.Fatal("expected invalid threshold to return error")
	}
}

func TestOrphanTableThresholdFromEnv(t *testing.T) {
	t.Setenv("CEREBRO_POLICY_ORPHAN_TABLES_MAX", "12")
	value, ok, err := OrphanTableThresholdFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected orphan threshold to be set")
	}
	if value != 12 {
		t.Fatalf("expected 12, got %d", value)
	}

	t.Setenv("CEREBRO_POLICY_ORPHAN_TABLES_MAX", "bad")
	_, ok, err = OrphanTableThresholdFromEnv()
	if err == nil || ok {
		t.Fatal("expected invalid orphan threshold to return error")
	}
}

func TestExplicitMappingsOnlyFromEnv(t *testing.T) {
	t.Setenv("CEREBRO_POLICY_EXPLICIT_MAPPINGS_ONLY", "true")
	value, err := ExplicitMappingsOnlyFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !value {
		t.Fatal("expected explicit mappings mode to be enabled")
	}

	t.Setenv("CEREBRO_POLICY_EXPLICIT_MAPPINGS_ONLY", "false")
	value, err = ExplicitMappingsOnlyFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if value {
		t.Fatal("expected explicit mappings mode to be disabled")
	}

	t.Setenv("CEREBRO_POLICY_EXPLICIT_MAPPINGS_ONLY", "not-a-bool")
	_, err = ExplicitMappingsOnlyFromEnv()
	if err == nil {
		t.Fatal("expected invalid explicit mapping mode to return error")
	}
}
