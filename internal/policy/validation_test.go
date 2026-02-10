package policy

import (
	"testing"
)

func TestValidateTableCoverage_Validation(t *testing.T) {
	engine := NewEngine()

	// Add policies with various resource types
	engine.AddPolicy(&Policy{
		ID:       "s3-policy",
		Name:     "S3 Policy",
		Resource: "aws::s3::bucket", // Maps to aws_s3_buckets
	})
	engine.AddPolicy(&Policy{
		ID:       "iam-policy",
		Name:     "IAM Policy",
		Resource: "aws::iam::user", // Maps to aws_iam_users
	})
	engine.AddPolicy(&Policy{
		ID:       "unknown-policy",
		Name:     "Unknown Policy",
		Resource: "unknown::resource", // Should be ignored
	})
	engine.AddPolicy(&Policy{
		ID:       "direct-table-policy",
		Name:     "Direct Table Policy",
		Resource: "custom_table_name", // Treated as direct table name
	})

	// Case 1: All tables available
	// Note: aws_iam_user now maps to BOTH aws_iam_users and aws_iam_credential_reports
	available := []string{"aws_s3_buckets", "aws_iam_users", "aws_iam_credential_reports", "custom_table_name"}
	gaps := engine.ValidateTableCoverage(available)
	if len(gaps) != 0 {
		t.Errorf("expected 0 gaps, got %d", len(gaps))
	}

	// Case 2: Missing tables
	// Only provide s3 buckets, so IAM and custom table should be missing
	// custom_table_name is treated as direct table mapping so it requires 'custom_table_name' to be present
	availableMissing := []string{"aws_s3_buckets"}
	gapsMissing := engine.ValidateTableCoverage(availableMissing)

	// Expect gaps for:
	// 1. iam-policy (missing aws_iam_users AND aws_iam_credential_reports)
	// 2. direct-table-policy (missing custom_table_name)
	// unknown-policy is ignored because it doesn't map to a table
	if len(gapsMissing) != 2 {
		t.Logf("Found gaps: %v", gapsMissing) // Added logging
		t.Errorf("expected 2 gaps, got %d", len(gapsMissing))
	}

	gapMap := make(map[string]bool)
	for _, g := range gapsMissing {
		gapMap[g.PolicyID] = true
	}

	if !gapMap["iam-policy"] {
		t.Error("expected gap for iam-policy")
	}
	if !gapMap["direct-table-policy"] {
		t.Error("expected gap for direct-table-policy")
	}
	if gapMap["s3-policy"] {
		t.Error("did not expect gap for s3-policy")
	}
}

func TestResourceToTable(t *testing.T) {
	tests := []struct {
		resource string
		want     string
	}{
		{"aws::s3::bucket", "aws_s3_buckets"},
		{"AWS::S3::BUCKET", "aws_s3_buckets"}, // Case insensitive
		{"aws::ec2::instance", "aws_ec2_instances"},
		{"custom_table", "custom_table"},
		{"unknown::resource", ""},
	}

	for _, tt := range tests {
		got := resourceToTable(tt.resource)
		if got != tt.want {
			t.Errorf("resourceToTable(%q) = %q, want %q", tt.resource, got, tt.want)
		}
	}
}
