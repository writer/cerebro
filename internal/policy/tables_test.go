package policy

import (
	"reflect"
	"testing"
)

func TestResourceToTableMapping(t *testing.T) {
	// Verify key mappings exist
	tests := []struct {
		resource string
		wantLen  int
	}{
		{"aws::s3::bucket", 1},
		{"aws::iam::user", 2}, // users + credential_reports
		{"aws::ec2::instance", 1},
		{"gcp::storage::bucket", 1},
		{"gcp::sql::database_instance", 1},
		{"gcp::artifact_registry::repository", 1},
		{"gcp::container_registry::registry", 1},
		{"container::image", 2},
		{"azure::compute::virtual_machine", 1},
		{"azure::compute::vm", 1},
		{"azure::functionapp::function", 1},
		{"github::repository_dependabot_alert", 1},
		{"github::user", 1},
		{"k8s::role", 1},
		{"k8s::namespace", 1},
		{"k8s::rbac::risky_binding", 1},
		{"k8s::cluster::inventory", 1},
		{"compute::instance", 3},
	}

	for _, tt := range tests {
		tables, ok := ResourceToTableMapping[tt.resource]
		if !ok {
			t.Errorf("missing mapping for %s", tt.resource)
			continue
		}
		if len(tables) != tt.wantLen {
			t.Errorf("%s: got %d tables, want %d", tt.resource, len(tables), tt.wantLen)
		}
	}
}

func TestPolicyGetRequiredTables(t *testing.T) {
	p := &Policy{
		ID:       "test-policy",
		Resource: "aws::s3::bucket",
	}

	tables := p.GetRequiredTables()
	if len(tables) != 1 {
		t.Errorf("got %d tables, want 1", len(tables))
	}
	if tables[0] != "aws_s3_buckets" {
		t.Errorf("got %s, want aws_s3_buckets", tables[0])
	}

	// Pipe resources
	p.Resource = "aws::s3::bucket|gcp::storage::bucket"
	tables = p.GetRequiredTables()
	want := []string{"aws_s3_buckets", "gcp_storage_buckets"}
	if !reflect.DeepEqual(tables, want) {
		t.Errorf("got %v, want %v", tables, want)
	}

	// Generic resource mapping
	p.Resource = "compute::instance"
	tables = p.GetRequiredTables()
	want = []string{"aws_ec2_instances", "gcp_compute_instances", "azure_compute_virtual_machines"}
	if !reflect.DeepEqual(tables, want) {
		t.Errorf("got %v, want %v", tables, want)
	}

	// Explicit mapping
	p.Resource = "gcp::sql::database_instance"
	tables = p.GetRequiredTables()
	want = []string{"gcp_sql_instances"}
	if !reflect.DeepEqual(tables, want) {
		t.Errorf("got %v, want %v", tables, want)
	}

	p.Resource = "gcp::artifact_registry::repository"
	tables = p.GetRequiredTables()
	want = []string{"gcp_artifact_registry_repositories"}
	if !reflect.DeepEqual(tables, want) {
		t.Errorf("got %v, want %v", tables, want)
	}

	p.Resource = "container::image"
	tables = p.GetRequiredTables()
	want = []string{"snyk_container_images", "gcp_artifact_registry_images"}
	if !reflect.DeepEqual(tables, want) {
		t.Errorf("got %v, want %v", tables, want)
	}

	// Two-part fallback
	p.Resource = "github::repository"
	tables = p.GetRequiredTables()
	want = []string{"github_repositories"}
	if !reflect.DeepEqual(tables, want) {
		t.Errorf("got %v, want %v", tables, want)
	}

	// Explicit override for GitHub alerts
	p.Resource = "github::repository_dependabot_alert"
	tables = p.GetRequiredTables()
	want = []string{"github_dependabot_alerts"}
	if !reflect.DeepEqual(tables, want) {
		t.Errorf("got %v, want %v", tables, want)
	}

	// Kubernetes aliases
	p.Resource = "k8s::namespace"
	tables = p.GetRequiredTables()
	want = []string{"k8s_core_namespaces"}
	if !reflect.DeepEqual(tables, want) {
		t.Errorf("got %v, want %v", tables, want)
	}

	p.Resource = "kubernetes::pod"
	tables = p.GetRequiredTables()
	want = []string{"k8s_core_pods"}
	if !reflect.DeepEqual(tables, want) {
		t.Errorf("got %v, want %v", tables, want)
	}

	p.Resource = "k8s::rbac::risky_binding"
	tables = p.GetRequiredTables()
	want = []string{"k8s_rbac_risky_bindings"}
	if !reflect.DeepEqual(tables, want) {
		t.Errorf("got %v, want %v", tables, want)
	}

	p.Resource = "k8s::cluster::inventory"
	tables = p.GetRequiredTables()
	want = []string{"k8s_cluster_inventory"}
	if !reflect.DeepEqual(tables, want) {
		t.Errorf("got %v, want %v", tables, want)
	}

	// Heuristic mapping
	p.Resource = "aws::elbv2::listener"
	tables = p.GetRequiredTables()
	want = []string{"aws_lb_listeners"}
	if !reflect.DeepEqual(tables, want) {
		t.Errorf("got %v, want %v", tables, want)
	}

	// Direct table name
	p.Resource = "ai_models"
	tables = p.GetRequiredTables()
	want = []string{"ai_models"}
	if !reflect.DeepEqual(tables, want) {
		t.Errorf("got %v, want %v", tables, want)
	}

	// Wildcard resource
	p.Resource = "*"
	tables = p.GetRequiredTables()
	want = []string{"*"}
	if !reflect.DeepEqual(tables, want) {
		t.Errorf("got %v, want %v", tables, want)
	}

	// Unknown resource
	p.Resource = "unknown::type"
	tables = p.GetRequiredTables()
	if tables != nil {
		t.Error("expected nil for unknown resource")
	}
}

func TestGetAllRequiredTables(t *testing.T) {
	policies := []*Policy{
		{Resource: "aws::s3::bucket"},
		{Resource: "aws::ec2::instance"},
		{Resource: "aws::s3::bucket"}, // Duplicate
	}

	tables := GetAllRequiredTables(policies)

	// Should dedupe
	if len(tables) != 2 {
		t.Errorf("got %d tables, want 2", len(tables))
	}
}

func TestValidateTableCoverage(t *testing.T) {
	engine := NewEngine()
	engine.AddPolicy(&Policy{ID: "s3-policy", Name: "S3 Policy", Resource: "aws::s3::bucket"})
	engine.AddPolicy(&Policy{ID: "ec2-policy", Name: "EC2 Policy", Resource: "aws::ec2::instance"})

	// All tables available
	gaps := engine.ValidateTableCoverage([]string{"aws_s3_buckets", "aws_ec2_instances"})
	if len(gaps) != 0 {
		t.Errorf("expected no gaps, got %d", len(gaps))
	}

	// Missing EC2 table
	gaps = engine.ValidateTableCoverage([]string{"aws_s3_buckets"})
	if len(gaps) != 1 {
		t.Errorf("expected 1 gap, got %d", len(gaps))
	}
	if gaps[0].PolicyID != "ec2-policy" {
		t.Errorf("wrong policy in gap: %s", gaps[0].PolicyID)
	}
	if gaps[0].MissingTables[0] != "aws_ec2_instances" {
		t.Errorf("wrong missing table: %s", gaps[0].MissingTables[0])
	}
}
