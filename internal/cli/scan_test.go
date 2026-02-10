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

func TestMapToxicCombinationRows(t *testing.T) {
	rows := []map[string]interface{}{
		{
			"severity":        "CRITICAL",
			"policy_id":       "toxic-bucket-public-data",
			"title":           "Public bucket",
			"resource_id":     "r1",
			"resource_name":   "bucket-1",
			"url":             "https://example",
			"service_account": "sa-1",
			"description":     "desc",
			"risks":           "EXTERNAL_EXPOSURE, UNPROTECTED_DATA",
		},
		{
			"severity":    "",
			"policy_id":   "",
			"resource_id": "r2",
		},
	}

	findings := mapToxicCombinationRows(rows)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f["policy_id"] != "toxic-bucket-public-data" {
		t.Errorf("policy_id = %v", f["policy_id"])
	}
	if f["resource_id"] != "r1" {
		t.Errorf("resource_id = %v", f["resource_id"])
	}
	if tc, ok := f["toxic_combo"].(bool); !ok || !tc {
		t.Errorf("expected toxic_combo true, got %v", f["toxic_combo"])
	}
}

func TestCanonicalizeSQLRiskCategories(t *testing.T) {
	risks := canonicalizeSQLRiskCategories("EXTERNAL_EXPOSURE, UNPROTECTED_DATA, CONFUSED_DEPUTY")
	if !risks["network_exposure"] {
		t.Error("expected network_exposure")
	}
	if !risks["sensitive_data"] {
		t.Error("expected sensitive_data")
	}
	if !risks["privilege_escalation"] {
		t.Error("expected privilege_escalation")
	}
}

func TestShouldSkipGraphToxicCombination(t *testing.T) {
	sqlRiskSets := map[string][]map[string]bool{
		"r1": {canonicalizeSQLRiskCategories("EXTERNAL_EXPOSURE, UNPROTECTED_DATA")},
	}

	graphRiskSubset := canonicalizeGraphRiskCategories([]string{"network_exposure"})
	if !shouldSkipGraphToxicCombination("r1", graphRiskSubset, sqlRiskSets) {
		t.Error("expected graph finding to be skipped when SQL risks are a superset")
	}

	graphRiskExpanded := canonicalizeGraphRiskCategories([]string{"network_exposure", "vulnerability"})
	if shouldSkipGraphToxicCombination("r1", graphRiskExpanded, sqlRiskSets) {
		t.Error("expected graph finding not to be skipped when it adds new risk categories")
	}

	graphRiskEmpty := canonicalizeGraphRiskCategories(nil)
	if shouldSkipGraphToxicCombination("r1", graphRiskEmpty, sqlRiskSets) {
		t.Error("expected empty risk set to not be skipped")
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

func TestPluralize(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"bucket", "buckets"},
		{"instance", "instances"},
		{"policy", "policies"},
		{"summary", "summaries"},
		{"key", "keys"},
		{"buckets", "buckets"},
		{"function", "functions"},
		{"", ""},
	}
	for _, tc := range tests {
		got := pluralize(tc.input)
		if got != tc.want {
			t.Errorf("pluralize(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestResourceToTable_FallbackPluralization(t *testing.T) {
	got := resourceToTable("aws::iam::account_summary")
	if got != "aws_iam_account_summaries" {
		t.Errorf("resourceToTable fallback plural = %q, want %q", got, "aws_iam_account_summaries")
	}
}

func TestSchedulesEqual(t *testing.T) {
	base := []SyncSchedule{
		{Name: "s1", Cron: "0 * * * *", Provider: "aws", Enabled: true, Retry: 3},
		{Name: "s2", Cron: "0 0 * * *", Provider: "gcp", Enabled: false, Retry: 1, Table: "gcp_compute_instances"},
	}
	// Identical
	same := []SyncSchedule{
		{Name: "s1", Cron: "0 * * * *", Provider: "aws", Enabled: true, Retry: 3},
		{Name: "s2", Cron: "0 0 * * *", Provider: "gcp", Enabled: false, Retry: 1, Table: "gcp_compute_instances"},
	}
	if !schedulesEqual(base, same) {
		t.Error("identical schedules should be equal")
	}

	// Different order -- still equal (keyed by name)
	reordered := []SyncSchedule{same[1], same[0]}
	if !schedulesEqual(base, reordered) {
		t.Error("reordered schedules should be equal")
	}

	// Different length
	if schedulesEqual(base, base[:1]) {
		t.Error("different length should not be equal")
	}

	// Changed cron
	changed := []SyncSchedule{
		{Name: "s1", Cron: "30 * * * *", Provider: "aws", Enabled: true, Retry: 3},
		same[1],
	}
	if schedulesEqual(base, changed) {
		t.Error("changed cron should not be equal")
	}

	// Changed enabled
	toggled := []SyncSchedule{
		{Name: "s1", Cron: "0 * * * *", Provider: "aws", Enabled: false, Retry: 3},
		same[1],
	}
	if schedulesEqual(base, toggled) {
		t.Error("changed enabled should not be equal")
	}

	// New schedule name
	renamed := []SyncSchedule{
		{Name: "s3", Cron: "0 * * * *", Provider: "aws", Enabled: true, Retry: 3},
		same[1],
	}
	if schedulesEqual(base, renamed) {
		t.Error("different schedule name should not be equal")
	}

	// Runtime fields differ (LastRun, LastStatus) -- should still be equal
	withRuntime := []SyncSchedule{
		{Name: "s1", Cron: "0 * * * *", Provider: "aws", Enabled: true, Retry: 3,
			LastRun: time.Now(), LastStatus: "success"},
		same[1],
	}
	if !schedulesEqual(base, withRuntime) {
		t.Error("runtime field differences should not affect equality")
	}

	// Both empty
	if !schedulesEqual(nil, nil) {
		t.Error("two nil slices should be equal")
	}
	if !schedulesEqual([]SyncSchedule{}, []SyncSchedule{}) {
		t.Error("two empty slices should be equal")
	}
}
