package sync

import (
	"reflect"
	"testing"
	"time"
)

func TestBuildAWSIdentityCenterPermissionUsageRollupRowsAggregatesAcrossAccounts(t *testing.T) {
	now := time.Date(2026, 3, 10, 8, 0, 0, 0, time.UTC)
	windowStart := now.Add(-90 * 24 * time.Hour)
	rows := []map[string]interface{}{
		{
			"_cq_id":                       "row-a",
			"account_id":                   "111111111111",
			"region":                       "us-east-1",
			"identity_center_instance_arn": "arn:aws:sso:::instance/ssoins-123",
			"identity_store_id":            "d-123",
			"permission_set_arn":           "arn:aws:sso:::permissionSet/ssoins-123/ps-123",
			"permission_set_name":          "Admin",
			"sso_role_arn":                 "arn:aws:iam::111111111111:role/AWSReservedSSO_Admin_a",
			"assignment_count":             2,
			"action":                       "iam:CreateUser",
			"usage_status":                 "unused",
			"unused_since":                 now.Add(-190 * 24 * time.Hour),
			"lookback_days":                90,
			"removal_threshold_days":       180,
			"evidence_source":              "aws_iam_access_advisor_action_level",
			"confidence":                   "high",
			"coverage":                     "full",
			"scan_window_start":            windowStart,
			"scan_window_end":              now,
		},
		{
			"_cq_id":                       "row-b",
			"account_id":                   "222222222222",
			"region":                       "us-east-1",
			"identity_center_instance_arn": "arn:aws:sso:::instance/ssoins-123",
			"identity_store_id":            "d-123",
			"permission_set_arn":           "arn:aws:sso:::permissionSet/ssoins-123/ps-123",
			"permission_set_name":          "Admin",
			"sso_role_arn":                 "arn:aws:iam::222222222222:role/AWSReservedSSO_Admin_b",
			"assignment_count":             3,
			"action":                       "iam:CreateUser",
			"usage_status":                 "used",
			"action_last_accessed":         now.Add(-2 * 24 * time.Hour),
			"lookback_days":                90,
			"removal_threshold_days":       180,
			"evidence_source":              "aws_iam_access_advisor_action_level",
			"confidence":                   "high",
			"coverage":                     "full",
			"scan_window_start":            windowStart,
			"scan_window_end":              now,
		},
	}

	rollupRows := buildAWSIdentityCenterPermissionUsageRollupRows(rows)
	if len(rollupRows) != 1 {
		t.Fatalf("expected 1 rollup row, got %d", len(rollupRows))
	}

	row := rollupRows[0]
	if row["usage_status"] != "used" {
		t.Fatalf("expected aggregate usage_status used, got %#v", row["usage_status"])
	}
	if row["assignment_count"] != 5 {
		t.Fatalf("expected assignment_count=5, got %#v", row["assignment_count"])
	}
	if row["account_count"] != 2 {
		t.Fatalf("expected account_count=2, got %#v", row["account_count"])
	}
	accountIDs, ok := row["account_ids"].([]string)
	if !ok {
		t.Fatalf("expected []string account_ids, got %T", row["account_ids"])
	}
	if !reflect.DeepEqual(accountIDs, []string{"111111111111", "222222222222"}) {
		t.Fatalf("unexpected account_ids: %#v", accountIDs)
	}
	if recommendation := row["recommendation"]; recommendation != "" {
		t.Fatalf("did not expect removal recommendation for used aggregate, got %#v", recommendation)
	}
}

func TestBuildAWSIdentityCenterPermissionUsageRollupRowsUsesConsecutiveUnusedWindow(t *testing.T) {
	now := time.Date(2026, 3, 10, 8, 0, 0, 0, time.UTC)
	windowStart := now.Add(-90 * 24 * time.Hour)
	rows := []map[string]interface{}{
		{
			"_cq_id":                       "row-a",
			"account_id":                   "111111111111",
			"region":                       "us-east-1",
			"identity_center_instance_arn": "arn:aws:sso:::instance/ssoins-123",
			"identity_store_id":            "d-123",
			"permission_set_arn":           "arn:aws:sso:::permissionSet/ssoins-123/ps-123",
			"permission_set_name":          "Admin",
			"sso_role_arn":                 "arn:aws:iam::111111111111:role/AWSReservedSSO_Admin_a",
			"assignment_count":             1,
			"action":                       "iam:CreateUser",
			"usage_status":                 "unused",
			"unused_since":                 now.Add(-220 * 24 * time.Hour),
			"lookback_days":                90,
			"removal_threshold_days":       180,
			"evidence_source":              "aws_iam_access_advisor_action_level",
			"confidence":                   "high",
			"coverage":                     "full",
			"scan_window_start":            windowStart,
			"scan_window_end":              now,
		},
		{
			"_cq_id":                       "row-b",
			"account_id":                   "222222222222",
			"region":                       "us-east-1",
			"identity_center_instance_arn": "arn:aws:sso:::instance/ssoins-123",
			"identity_store_id":            "d-123",
			"permission_set_arn":           "arn:aws:sso:::permissionSet/ssoins-123/ps-123",
			"permission_set_name":          "Admin",
			"sso_role_arn":                 "arn:aws:iam::222222222222:role/AWSReservedSSO_Admin_b",
			"assignment_count":             1,
			"action":                       "iam:CreateUser",
			"usage_status":                 "unused",
			"unused_since":                 now.Add(-190 * 24 * time.Hour),
			"lookback_days":                90,
			"removal_threshold_days":       180,
			"evidence_source":              "aws_iam_access_advisor_action_level",
			"confidence":                   "high",
			"coverage":                     "full",
			"scan_window_start":            windowStart,
			"scan_window_end":              now,
		},
	}

	rollupRows := buildAWSIdentityCenterPermissionUsageRollupRows(rows)
	if len(rollupRows) != 1 {
		t.Fatalf("expected 1 rollup row, got %d", len(rollupRows))
	}

	row := rollupRows[0]
	if row["usage_status"] != "unused" {
		t.Fatalf("expected aggregate usage_status unused, got %#v", row["usage_status"])
	}
	if row["days_unused"] != 190 {
		t.Fatalf("expected days_unused=190 from latest unused_since, got %#v", row["days_unused"])
	}
	if recommendation, _ := row["recommendation"].(string); recommendation == "" {
		t.Fatal("expected removal recommendation once all accounts exceed threshold")
	}
}

func TestBuildPermissionUsageHistoryRowsAddsHistoryMetadata(t *testing.T) {
	observedAt := time.Date(2026, 3, 10, 8, 30, 0, 0, time.UTC)
	historyRows := buildPermissionUsageHistoryRows([]map[string]interface{}{{
		"_cq_id":          "row-1",
		"usage_status":    "unused",
		"scan_window_end": observedAt,
	}})

	if len(historyRows) != 1 {
		t.Fatalf("expected 1 history row, got %d", len(historyRows))
	}
	if historyRows[0]["_cq_id"] != "row-1|2026-03-10" {
		t.Fatalf("unexpected history row id: %#v", historyRows[0]["_cq_id"])
	}
	if historyRows[0]["source_row_id"] != "row-1" {
		t.Fatalf("unexpected source_row_id: %#v", historyRows[0]["source_row_id"])
	}
	historyDay, ok := historyRows[0]["history_day"].(time.Time)
	if !ok {
		t.Fatalf("expected time history_day, got %T", historyRows[0]["history_day"])
	}
	if !historyDay.Equal(time.Date(2026, 3, 10, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("unexpected history_day: %s", historyDay)
	}
}
