package cli

import (
	"testing"
	"time"

	"github.com/writerinternal/cerebro/internal/snowflake"
)

func TestResourceToTable_KnownMappings(t *testing.T) {
	tests := []struct {
		resource string
		table    string
	}{
		{"aws::s3::bucket", "aws_s3_buckets"},
		{"aws::ec2::instance", "aws_ec2_instances"},
		{"aws::iam::role", "aws_iam_roles"},
		{"aws::kms::key", "aws_kms_keys"},
		{"aws::lambda::function", "aws_lambda_functions"},
		{"aws::rds::instance", "aws_rds_instances"},
		{"aws::elbv2::load_balancer", "aws_elbv2_load_balancers"},
		{"aws::cloudtrail::trail", "aws_cloudtrail_trails"},
		{"gcp::storage::bucket", "gcp_storage_buckets"},
		{"gcp::compute::instance", "gcp_compute_instances"},
		{"gcp::compute::firewall", "gcp_compute_firewalls"},
		{"gcp::iam::service_account", "gcp_iam_service_accounts"},
		{"gcp::cloudrun::service", "gcp_cloudrun_services"},
		{"azure::storage::account", "azure_storage_accounts"},
		{"azure::compute::vm", "azure_compute_virtual_machines"},
	}

	for _, tc := range tests {
		got := resourceToTable(tc.resource)
		if got != tc.table {
			t.Errorf("resourceToTable(%q) = %q, want %q", tc.resource, got, tc.table)
		}
	}
}

func TestResourceToTable_FallbackConstruction(t *testing.T) {
	// Unknown resource should construct table name from parts
	got := resourceToTable("aws::sqs::queue")
	if got != "aws_sqs_queues" {
		t.Errorf("resourceToTable fallback = %q, want %q", got, "aws_sqs_queues")
	}
}

func TestResourceToTable_Empty(t *testing.T) {
	if got := resourceToTable(""); got != "" {
		t.Errorf("resourceToTable('') = %q, want empty", got)
	}
	if got := resourceToTable("invalid"); got != "" {
		t.Errorf("resourceToTable('invalid') = %q, want empty", got)
	}
}

func TestToString(t *testing.T) {
	tests := []struct {
		input    interface{}
		expected string
	}{
		{nil, ""},
		{"hello", "hello"},
		{true, "true"},
		{false, "false"},
		{42, "42"},
		{3.14, "3.14"},
	}

	for _, tc := range tests {
		got := toString(tc.input)
		if got != tc.expected {
			t.Errorf("toString(%v) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

func TestFilterCDCEvents(t *testing.T) {
	now := time.Now().UTC()
	events := []snowflake.CDCEvent{
		{ResourceID: "r1", ChangeType: "update", EventTime: now.Add(-2 * time.Hour)},
		{ResourceID: "r2", ChangeType: "create", EventTime: now.Add(-1 * time.Hour)},
		{ResourceID: "r3", ChangeType: "delete", EventTime: now}, // removed -- skipped
		{ResourceID: "r1", ChangeType: "update", EventTime: now}, // duplicate r1
		{ResourceID: "", ChangeType: "update", EventTime: now},   // empty ID -- skipped
	}

	ids, maxTime := filterCDCEvents(events)

	if len(ids) != 2 {
		t.Fatalf("expected 2 unique IDs, got %d: %v", len(ids), ids)
	}
	if ids[0] != "r1" || ids[1] != "r2" {
		t.Errorf("unexpected IDs: %v", ids)
	}
	if !maxTime.Equal(now) {
		t.Errorf("maxTime = %v, want %v", maxTime, now)
	}
}

func TestFilterCDCEvents_Empty(t *testing.T) {
	ids, maxTime := filterCDCEvents(nil)
	if len(ids) != 0 {
		t.Errorf("expected 0 IDs, got %d", len(ids))
	}
	if !maxTime.IsZero() {
		t.Errorf("maxTime should be zero")
	}
}

func TestDedupeStrings(t *testing.T) {
	input := []string{"a", "b", "a", "c", "b", "d"}
	got := dedupeStrings(input)
	if len(got) != 4 {
		t.Fatalf("expected 4 unique strings, got %d: %v", len(got), got)
	}
	expected := []string{"a", "b", "c", "d"}
	for i, v := range expected {
		if got[i] != v {
			t.Errorf("dedupeStrings[%d] = %q, want %q", i, got[i], v)
		}
	}
}

func TestIsRemovalEvent(t *testing.T) {
	removals := []string{"remove", "removed", "delete", "deleted", "Remove", "DELETED"}
	for _, r := range removals {
		if !isRemovalEvent(r) {
			t.Errorf("isRemovalEvent(%q) = false, want true", r)
		}
	}

	nonRemovals := []string{"create", "update", "modify", ""}
	for _, r := range nonRemovals {
		if isRemovalEvent(r) {
			t.Errorf("isRemovalEvent(%q) = true, want false", r)
		}
	}
}

func TestResourceToTable_DirectTableName(t *testing.T) {
	if got := resourceToTable("aws_iam_roles"); got != "aws_iam_roles" {
		t.Errorf("expected aws_iam_roles, got %q", got)
	}
}

func TestResourceToTables_CompoundResource(t *testing.T) {
	tables := resourceToTables("storage::bucket|storage::blob_container")
	if len(tables) != 0 {
		t.Errorf("expected 0 tables for unmapped 2-part resources, got %d: %v", len(tables), tables)
	}

	tables = resourceToTables("aws::s3::bucket|gcp::storage::bucket")
	if len(tables) != 2 {
		t.Errorf("expected 2 tables, got %d: %v", len(tables), tables)
	}
}

func TestResourceToTables_SingleResource(t *testing.T) {
	tables := resourceToTables("aws::s3::bucket")
	if len(tables) != 1 || tables[0] != "aws_s3_buckets" {
		t.Errorf("expected [aws_s3_buckets], got %v", tables)
	}
}
