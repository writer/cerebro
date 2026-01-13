package policy

import (
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
		{"azure::compute::virtual_machine", 1},
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
