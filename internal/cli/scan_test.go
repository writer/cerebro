package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/policy"
	"github.com/evalops/cerebro/internal/scanner"
	"github.com/evalops/cerebro/internal/snowflake"
)

func TestResourceToTables_KnownMappings(t *testing.T) {
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
		{"github::repository", "github_repositories"},
		{"github::repository_dependabot_alert", "github_dependabot_alerts"},
		{"okta::user", "okta_users"},
		{"k8s::namespace", "k8s_core_namespaces"},
		{"kubernetes::pod", "k8s_core_pods"},
	}

	for _, tc := range tests {
		got := resourceToTables(tc.resource)
		if len(got) != 1 || got[0] != tc.table {
			t.Errorf("resourceToTables(%q) = %v, want [%s]", tc.resource, got, tc.table)
		}
	}
}

func TestResourceToTables_FallbackConstruction(t *testing.T) {
	got := resourceToTables("aws::sqs::queue")
	if len(got) != 1 || got[0] != "aws_sqs_queues" {
		t.Errorf("resourceToTables fallback = %v, want [aws_sqs_queues]", got)
	}
}

func TestResourceToTables_Empty(t *testing.T) {
	if got := resourceToTables(""); len(got) != 0 {
		t.Errorf("resourceToTables('') = %v, want empty", got)
	}
	if got := resourceToTables("invalid"); len(got) != 0 {
		t.Errorf("resourceToTables('invalid') = %v, want empty", got)
	}
	if got := resourceToTables("unknown::resource"); len(got) != 0 {
		t.Errorf("resourceToTables('unknown::resource') = %v, want empty", got)
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

func TestSeverityPreservation_DevEnvironment(t *testing.T) {
	findings := []map[string]interface{}{
		{"severity": "CRITICAL", "resource_id": "arn:aws:s3:::-dev-bucket", "policy_id": "p1"},
		{"severity": "HIGH", "resource_id": "arn:aws:s3:::-dev-service", "policy_id": "p2"},
		{"severity": "MEDIUM", "resource_id": "arn:aws:s3:::-dev-db", "policy_id": "p3"},
		{"severity": "LOW", "resource_id": "arn:aws:s3:::prod-bucket", "policy_id": "p4"},
	}

	// Simulate the annotation logic (same as in scan command)
	for i, f := range findings {
		if isDevResource(toString(f["resource_id"])) {
			findings[i]["environment_context"] = "development"
			orig := strings.ToUpper(toString(f["severity"]))
			if orig == "CRITICAL" || orig == "HIGH" {
				findings[i]["triage_priority"] = "LOW"
				findings[i]["triage_score"] = triageScoreForDevSeverity(orig)
				findings[i]["dev_environment"] = true
			}
		}
	}

	// Canonical severity must be preserved
	if findings[0]["severity"] != "CRITICAL" {
		t.Errorf("expected CRITICAL severity preserved, got %v", findings[0]["severity"])
	}
	if findings[1]["severity"] != "HIGH" {
		t.Errorf("expected HIGH severity preserved, got %v", findings[1]["severity"])
	}
	// Triage metadata must be added
	if findings[0]["triage_priority"] != "LOW" {
		t.Errorf("expected triage_priority LOW, got %v", findings[0]["triage_priority"])
	}
	if findings[0]["environment_context"] != "development" {
		t.Errorf("expected environment_context development, got %v", findings[0]["environment_context"])
	}
	// triage_score: CRITICAL dev = 15, HIGH dev = 10
	if findings[0]["triage_score"] != 15 {
		t.Errorf("expected triage_score 15 for CRITICAL dev, got %v", findings[0]["triage_score"])
	}
	if findings[1]["triage_score"] != 10 {
		t.Errorf("expected triage_score 10 for HIGH dev, got %v", findings[1]["triage_score"])
	}
	// MEDIUM dev should have environment_context but no triage_score
	if _, ok := findings[2]["triage_score"]; ok {
		t.Error("MEDIUM dev finding should not have triage_score")
	}
	if findings[2]["environment_context"] != "development" {
		t.Errorf("MEDIUM dev should have environment_context, got %v", findings[2]["environment_context"])
	}
	// Non-dev resources should not have triage fields
	if _, ok := findings[3]["environment_context"]; ok {
		t.Error("prod resource should not have environment_context")
	}
}

func TestTriageScoreForDevSeverity(t *testing.T) {
	if got := triageScoreForDevSeverity("CRITICAL"); got != 15 {
		t.Errorf("CRITICAL = %d, want 15", got)
	}
	if got := triageScoreForDevSeverity("HIGH"); got != 10 {
		t.Errorf("HIGH = %d, want 10", got)
	}
	if got := triageScoreForDevSeverity("MEDIUM"); got != 5 {
		t.Errorf("MEDIUM = %d, want 5", got)
	}
}

func TestToxicWatermark_NotAdvancedWithoutDataCursor(t *testing.T) {
	// Simulates the call-site logic: if MaxSyncTime is zero, watermark must not be set.
	wm := scanner.NewWatermarkStore(nil)
	original := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	wm.SetWatermark("_toxic_relationships", original, "old-id", 5)

	// Simulate a toxic result with no data (empty query result → zero cursor)
	result := &scanner.ToxicDetectionResult{
		MaxSyncTime: time.Time{},
		MaxCursorID: "",
	}

	// Replicate call-site logic: only advance if data cursor is present
	if !result.MaxSyncTime.IsZero() {
		wm.SetWatermark("_toxic_relationships", result.MaxSyncTime, result.MaxCursorID, 0)
	}

	// Watermark must remain at original value
	got := wm.GetWatermark("_toxic_relationships")
	if got == nil {
		t.Fatal("watermark should still exist")
	}
	if !got.LastScanTime.Equal(original) {
		t.Errorf("watermark advanced from %v to %v", original, got.LastScanTime)
	}
	if got.LastScanID != "old-id" {
		t.Errorf("cursor id changed from old-id to %q", got.LastScanID)
	}
}

func TestToxicWatermark_AdvancesToDataCursor(t *testing.T) {
	wm := scanner.NewWatermarkStore(nil)

	dataCursor := time.Date(2026, 3, 15, 10, 30, 0, 0, time.UTC)
	result := &scanner.ToxicDetectionResult{
		Findings:    []scanner.RelationshipToxicFinding{{PolicyID: "p1", Severity: "HIGH", ResourceID: "r1"}},
		MaxSyncTime: dataCursor,
		MaxCursorID: "r1",
	}

	// Replicate call-site logic
	if !result.MaxSyncTime.IsZero() {
		wm.SetWatermark("_toxic_relationships", result.MaxSyncTime, result.MaxCursorID, int64(len(result.Findings)))
	}

	got := wm.GetWatermark("_toxic_relationships")
	if got == nil {
		t.Fatal("watermark should be set")
	}
	if !got.LastScanTime.Equal(dataCursor) {
		t.Errorf("expected watermark at %v, got %v", dataCursor, got.LastScanTime)
	}
	if got.LastScanID != "r1" {
		t.Errorf("expected cursor id r1, got %q", got.LastScanID)
	}
	if got.RowsScanned != 1 {
		t.Errorf("expected 1 row, got %d", got.RowsScanned)
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

	findings := scanner.MapRelationshipToxicRows(rows)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.PolicyID != "toxic-bucket-public-data" {
		t.Errorf("policy_id = %v", f.PolicyID)
	}
	if f.ResourceID != "r1" {
		t.Errorf("resource_id = %v", f.ResourceID)
	}
}

func TestPolicyFindingToMapIncludesActionableFields(t *testing.T) {
	finding := policy.Finding{
		ID:             "f-1",
		PolicyID:       "aws-s3-public-read",
		PolicyName:     "S3 bucket public read",
		Title:          "Public bucket",
		Description:    "Bucket is publicly readable",
		Severity:       "HIGH",
		ResourceType:   "aws::s3::bucket",
		ResourceID:     "arn:aws:s3:::example",
		ResourceName:   "example",
		RiskCategories: []string{"network_exposure"},
		Remediation:    "Disable public access block",
		ControlID:      "CIS-3.1",
	}

	mapped := policyFindingToMap(finding, findingSourcePolicy, map[string]interface{}{"toxic_combo": true})

	if mapped["policy_id"] != finding.PolicyID {
		t.Fatalf("expected policy_id %q, got %v", finding.PolicyID, mapped["policy_id"])
	}
	if mapped["title"] != finding.Title {
		t.Fatalf("expected title %q, got %v", finding.Title, mapped["title"])
	}
	if mapped["remediation"] != finding.Remediation {
		t.Fatalf("expected remediation %q, got %v", finding.Remediation, mapped["remediation"])
	}
	if mapped["source"] != findingSourcePolicy {
		t.Fatalf("expected source %q, got %v", findingSourcePolicy, mapped["source"])
	}
	if mapped["toxic_combo"] != true {
		t.Fatalf("expected toxic_combo=true, got %v", mapped["toxic_combo"])
	}
	if _, ok := mapped["risk_categories"].([]string); !ok {
		t.Fatalf("expected risk_categories to be []string, got %T", mapped["risk_categories"])
	}
}

func TestSummarizePolicyHotspots(t *testing.T) {
	findings := []map[string]interface{}{
		{"policy_id": "p1", "policy_name": "Policy One", "title": "Public bucket", "severity": "HIGH", "resource_id": "r1", "resource_name": "bucket-1"},
		{"policy_id": "p1", "title": "Public bucket", "severity": "CRITICAL", "resource_id": "r2", "resource_name": "bucket-2"},
		{"policy_id": "p1", "title": "Public bucket", "severity": "MEDIUM", "resource_id": "r2", "resource_name": "bucket-2"},
		{"policy_id": "p2", "title": "Weak key", "severity": "CRITICAL", "resource_id": "r3", "resource_name": "kms-key"},
	}

	summary := summarizePolicyHotspots(findings, 5)
	if len(summary) != 2 {
		t.Fatalf("expected 2 hotspot entries, got %d", len(summary))
	}

	if summary[0].PolicyID != "p1" {
		t.Fatalf("expected first hotspot to be p1, got %s", summary[0].PolicyID)
	}
	if summary[0].Count != 3 {
		t.Fatalf("expected p1 count=3, got %d", summary[0].Count)
	}
	if summary[0].ResourceCount != 2 {
		t.Fatalf("expected p1 resource_count=2, got %d", summary[0].ResourceCount)
	}
	if summary[0].HighestSeverity != "CRITICAL" {
		t.Fatalf("expected p1 highest severity CRITICAL, got %s", summary[0].HighestSeverity)
	}
}

func TestSummarizeRemediationActions(t *testing.T) {
	findings := []map[string]interface{}{
		{"policy_id": "p1", "severity": "HIGH", "remediation": "Rotate compromised keys", "resource_name": "key-a"},
		{"policy_id": "p2", "severity": "CRITICAL", "remediation": "rotate compromised keys", "resource_name": "key-b"},
		{"policy_id": "p3", "severity": "MEDIUM", "remediation": "Enable encryption at rest", "resource_name": "bucket-a"},
	}

	summary := summarizeRemediationActions(findings, 5)
	if len(summary) != 2 {
		t.Fatalf("expected 2 remediation entries, got %d", len(summary))
	}

	if summary[0].Count != 2 {
		t.Fatalf("expected first remediation count=2, got %d", summary[0].Count)
	}
	if summary[0].HighestSeverity != "CRITICAL" {
		t.Fatalf("expected highest severity CRITICAL, got %s", summary[0].HighestSeverity)
	}
	if len(summary[0].PolicyIDs) != 2 || summary[0].PolicyIDs[0] != "p1" || summary[0].PolicyIDs[1] != "p2" {
		t.Fatalf("expected policy IDs [p1 p2], got %v", summary[0].PolicyIDs)
	}
}

func TestFindingRiskString(t *testing.T) {
	if got := findingRiskString(map[string]interface{}{"risks": "NETWORK_EXPOSURE"}); got != "NETWORK_EXPOSURE" {
		t.Fatalf("expected risks field to be returned, got %q", got)
	}

	withCategories := map[string]interface{}{"risk_categories": []string{"network_exposure", "sensitive_data"}}
	if got := findingRiskString(withCategories); got != "network_exposure, sensitive_data" {
		t.Fatalf("expected joined categories, got %q", got)
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

func resourceToTables(resource string) []string {
	if strings.TrimSpace(resource) == "" {
		return nil
	}
	return (&policy.Policy{Resource: resource}).GetRequiredTables()
}

func TestResourceToTables_DirectTableName(t *testing.T) {
	got := resourceToTables("aws_iam_roles")
	if len(got) != 1 || got[0] != "aws_iam_roles" {
		t.Errorf("expected [aws_iam_roles], got %v", got)
	}
}

func TestResourceToTables_CompoundResource(t *testing.T) {
	tables := resourceToTables("storage::bucket|storage::blob_container")
	if len(tables) != 3 {
		t.Errorf("expected 3 tables, got %d: %v", len(tables), tables)
	}
	want := []string{"aws_s3_buckets", "gcp_storage_buckets", "azure_storage_containers"}
	for i, table := range want {
		if tables[i] != table {
			t.Errorf("expected %s at index %d, got %s", table, i, tables[i])
		}
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

	tables = resourceToTables("compute::instance")
	if len(tables) != 3 {
		t.Fatalf("expected 3 tables, got %d: %v", len(tables), tables)
	}
	want := []string{"aws_ec2_instances", "gcp_compute_instances", "azure_compute_virtual_machines"}
	for i, table := range want {
		if tables[i] != table {
			t.Errorf("expected %s at index %d, got %s", table, i, tables[i])
		}
	}
}

func TestResourceToTables_MappedOverride(t *testing.T) {
	got := resourceToTables("aws::iam::account_summary")
	if len(got) != 1 || got[0] != "aws_iam_accounts" {
		t.Errorf("resourceToTables mapped override = %v, want [aws_iam_accounts]", got)
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
