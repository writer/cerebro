package sync

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/snowflake/tableops"
	"github.com/writer/cerebro/internal/warehouse"
)

const (
	awsIdentityCenterPermissionUsageRollupTable  = "aws_identitycenter_permission_set_permission_usage_rollup"
	awsIdentityCenterPermissionUsageHistoryTable = "aws_identitycenter_permission_set_permission_usage_history"
	gcpIAMGroupPermissionUsageHistoryTable       = "gcp_iam_group_permission_usage_history"
)

var awsIdentityCenterPermissionUsageRollupColumns = []string{
	"arn",
	"account_id",
	"account_ids",
	"account_count",
	"region",
	"identity_center_instance_arn",
	"identity_store_id",
	"permission_set_arn",
	"permission_set_name",
	"sso_role_arns",
	"assignment_count",
	"action",
	"action_last_accessed",
	"usage_status",
	"days_unused",
	"unused_since",
	"lookback_days",
	"removal_threshold_days",
	"recommendation",
	"evidence_source",
	"confidence",
	"coverage",
	"scan_window_start",
	"scan_window_end",
}

var awsIdentityCenterPermissionUsageHistoryColumns = append(append([]string{}, awsIdentityCenterPermissionUsageRollupColumns...), "source_row_id", "history_day")

var gcpIAMGroupPermissionUsageHistoryColumns = []string{
	"project_id",
	"id",
	"group",
	"permission",
	"granted_roles",
	"permission_last_used",
	"usage_status",
	"days_unused",
	"unused_since",
	"lookback_days",
	"removal_threshold_days",
	"member_count",
	"members_observed",
	"recommendation",
	"evidence_source",
	"confidence",
	"coverage",
	"scan_window_start",
	"scan_window_end",
	"source_row_id",
	"history_day",
}

func (e *SyncEngine) refreshAWSIdentityCenterPermissionUsageArtifacts(ctx context.Context) error {
	return refreshAWSIdentityCenterPermissionUsageArtifacts(ctx, e.sf, e.logger)
}

func (e *GCPSyncEngine) appendGCPIAMGroupPermissionUsageHistory(ctx context.Context, rows []map[string]interface{}) error {
	return upsertPermissionUsageHistoryRows(ctx, e.sf, gcpIAMGroupPermissionUsageHistoryTable, gcpIAMGroupPermissionUsageHistoryColumns, rows)
}

func refreshAWSIdentityCenterPermissionUsageArtifacts(ctx context.Context, sf warehouse.SyncWarehouse, logger *slog.Logger) error {
	if sf == nil {
		return nil
	}

	rows, err := loadAWSIdentityCenterPermissionUsageRows(ctx, sf)
	if err != nil {
		return err
	}

	if err := ensurePermissionUsageDerivedTable(ctx, sf, awsIdentityCenterPermissionUsageRollupTable, awsIdentityCenterPermissionUsageRollupColumns); err != nil {
		return err
	}

	rollupRows := buildAWSIdentityCenterPermissionUsageRollupRows(rows)
	if _, err := upsertScopedRowsWithChanges(ctx, sf, logger, awsIdentityCenterPermissionUsageRollupTable, rollupRows, "", nil, hashRowContent, false); err != nil {
		return err
	}

	return upsertPermissionUsageHistoryRows(ctx, sf, awsIdentityCenterPermissionUsageHistoryTable, awsIdentityCenterPermissionUsageHistoryColumns, rollupRows)
}

func ensurePermissionUsageDerivedTable(ctx context.Context, sf warehouse.SyncWarehouse, table string, columns []string) error {
	return tableops.EnsureVariantTable(ctx, sf, table, columns, tableops.EnsureVariantTableOptions{
		AddMissingColumns:     true,
		IgnoreLookupError:     true,
		IgnoreAddColumnErrors: true,
	})
}

func upsertPermissionUsageHistoryRows(ctx context.Context, sf warehouse.SyncWarehouse, table string, columns []string, rows []map[string]interface{}) error {
	if sf == nil || len(rows) == 0 {
		return nil
	}
	if err := ensurePermissionUsageDerivedTable(ctx, sf, table, columns); err != nil {
		return err
	}

	historyRows := buildPermissionUsageHistoryRows(rows)
	if len(historyRows) == 0 {
		return nil
	}

	mergeRows := make([]map[string]interface{}, 0, len(historyRows))
	for _, row := range dedupeRowsByID(historyRows) {
		id := queryRowString(row, "_cq_id")
		if id == "" {
			continue
		}
		mergeRow := make(map[string]interface{}, len(row)+1)
		mergeRow["_cq_id"] = id
		mergeRow["_cq_hash"] = hashRowContent(row)
		for key, value := range row {
			if key == "_cq_id" || key == "_cq_hash" {
				continue
			}
			mergeRow[key] = value
		}
		mergeRows = append(mergeRows, mergeRow)
	}

	return mergeRowsBatch(ctx, sf, table, mergeRows)
}

func buildPermissionUsageHistoryRows(rows []map[string]interface{}) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(rows))
	for _, row := range rows {
		sourceID := queryRowString(row, "_cq_id")
		if sourceID == "" {
			continue
		}

		observedAt, ok := parseAnyTime(queryRow(row, "scan_window_end"))
		if !ok {
			observedAt = time.Now().UTC()
		}
		historyDay := observedAt.UTC().Truncate(24 * time.Hour)
		historyID := fmt.Sprintf("%s|%s", sourceID, historyDay.Format("2006-01-02"))

		historyRow := make(map[string]interface{}, len(row)+2)
		for key, value := range row {
			if key == "_cq_hash" || strings.HasPrefix(key, "\x00") {
				continue
			}
			historyRow[key] = value
		}
		historyRow["_cq_id"] = historyID
		historyRow["source_row_id"] = sourceID
		historyRow["history_day"] = historyDay
		out = append(out, historyRow)
	}
	return out
}

func loadAWSIdentityCenterPermissionUsageRows(ctx context.Context, sf warehouse.SyncWarehouse) ([]map[string]interface{}, error) {
	if sf == nil {
		return nil, nil
	}

	rows, err := sf.Query(ctx, `
		SELECT
			_cq_id,
			arn,
			account_id,
			region,
			identity_center_instance_arn,
			identity_store_id,
			permission_set_arn,
			permission_set_name,
			sso_role_arn,
			assignment_count,
			action,
			action_last_accessed,
			usage_status,
			days_unused,
			unused_since,
			lookback_days,
			removal_threshold_days,
			recommendation,
			evidence_source,
			confidence,
			coverage,
			scan_window_start,
			scan_window_end
		FROM `+awsIdentityCenterPermissionUsageTable)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "does not exist") {
			return nil, nil
		}
		return nil, err
	}
	return rows.Rows, nil
}

type awsIdentityCenterPermissionUsageAggregate struct {
	RowID                 string
	AccountIDs            map[string]struct{}
	RoleARNs              map[string]struct{}
	Region                string
	InstanceArn           string
	IdentityStoreID       string
	PermissionSetArn      string
	PermissionSetName     string
	Action                string
	AssignmentCount       int
	LastAccessed          time.Time
	UnusedSince           time.Time
	UsageStatus           string
	LookbackDays          int
	RemovalThresholdDays  int
	Recommendation        string
	EvidenceSource        string
	Confidence            string
	Coverage              string
	ScanWindowStart       time.Time
	ScanWindowEnd         time.Time
	HasUnknown            bool
	HasUncertain          bool
	HasUsed               bool
	HasUnused             bool
	AuthoritativeCoverage bool
}

func buildAWSIdentityCenterPermissionUsageRollupRows(rows []map[string]interface{}) []map[string]interface{} {
	groups := make(map[string]*awsIdentityCenterPermissionUsageAggregate)

	for _, row := range rows {
		permissionSetArn := strings.TrimSpace(queryRowString(row, "permission_set_arn"))
		action := strings.TrimSpace(queryRowString(row, "action"))
		instanceArn := strings.TrimSpace(queryRowString(row, "identity_center_instance_arn"))
		if permissionSetArn == "" || action == "" || instanceArn == "" {
			continue
		}

		rowID := fmt.Sprintf("%s|%s|%s", instanceArn, permissionSetArn, strings.ToLower(action))
		agg := groups[rowID]
		if agg == nil {
			agg = &awsIdentityCenterPermissionUsageAggregate{
				RowID:                 rowID,
				AccountIDs:            make(map[string]struct{}),
				RoleARNs:              make(map[string]struct{}),
				InstanceArn:           instanceArn,
				IdentityStoreID:       strings.TrimSpace(queryRowString(row, "identity_store_id")),
				PermissionSetArn:      permissionSetArn,
				PermissionSetName:     strings.TrimSpace(queryRowString(row, "permission_set_name")),
				Action:                action,
				LookbackDays:          permissionUsageRowInt(queryRow(row, "lookback_days")),
				RemovalThresholdDays:  permissionUsageRowInt(queryRow(row, "removal_threshold_days")),
				EvidenceSource:        strings.TrimSpace(queryRowString(row, "evidence_source")),
				Confidence:            strings.TrimSpace(queryRowString(row, "confidence")),
				Coverage:              strings.TrimSpace(queryRowString(row, "coverage")),
				AuthoritativeCoverage: true,
			}
			groups[rowID] = agg
		}

		accountID := strings.TrimSpace(queryRowString(row, "account_id"))
		if accountID != "" {
			agg.AccountIDs[accountID] = struct{}{}
		}
		roleArn := strings.TrimSpace(queryRowString(row, "sso_role_arn"))
		if roleArn != "" {
			agg.RoleARNs[roleArn] = struct{}{}
		}
		agg.AssignmentCount += permissionUsageRowInt(queryRow(row, "assignment_count"))
		if agg.Region == "" {
			agg.Region = strings.TrimSpace(queryRowString(row, "region"))
		}

		if ts, ok := parseAnyTime(queryRow(row, "action_last_accessed")); ok && ts.After(agg.LastAccessed) {
			agg.LastAccessed = ts.UTC()
		}
		if ts, ok := parseAnyTime(queryRow(row, "unused_since")); ok && ts.After(agg.UnusedSince) {
			agg.UnusedSince = ts.UTC()
		}
		if ts, ok := parseAnyTime(queryRow(row, "scan_window_start")); ok && (agg.ScanWindowStart.IsZero() || ts.Before(agg.ScanWindowStart)) {
			agg.ScanWindowStart = ts.UTC()
		}
		if ts, ok := parseAnyTime(queryRow(row, "scan_window_end")); ok && ts.After(agg.ScanWindowEnd) {
			agg.ScanWindowEnd = ts.UTC()
		}

		status := strings.ToLower(strings.TrimSpace(queryRowString(row, "usage_status")))
		switch status {
		case "used":
			agg.HasUsed = true
		case "unused":
			agg.HasUnused = true
		case "attribution_uncertain":
			agg.HasUncertain = true
		default:
			agg.HasUnknown = true
		}

		coverage := strings.ToLower(strings.TrimSpace(queryRowString(row, "coverage")))
		if coverage == "partial" || coverage == "unknown" || coverage == "" {
			agg.AuthoritativeCoverage = false
		}
		agg.Coverage = mergePermissionUsageCoverage(agg.Coverage, strings.TrimSpace(queryRowString(row, "coverage")))
		agg.Confidence = mergePermissionUsageConfidence(agg.Confidence, strings.TrimSpace(queryRowString(row, "confidence")))
		if agg.EvidenceSource == "" {
			agg.EvidenceSource = strings.TrimSpace(queryRowString(row, "evidence_source"))
		}
		if agg.LookbackDays == 0 {
			agg.LookbackDays = permissionUsageRowInt(queryRow(row, "lookback_days"))
		}
		if agg.RemovalThresholdDays == 0 {
			agg.RemovalThresholdDays = permissionUsageRowInt(queryRow(row, "removal_threshold_days"))
		}
	}

	rollupRows := make([]map[string]interface{}, 0, len(groups))
	for _, agg := range groups {
		if agg.LookbackDays <= 0 {
			agg.LookbackDays = defaultPermissionUsageWindowDays
		}
		if agg.RemovalThresholdDays <= 0 {
			agg.RemovalThresholdDays = defaultPermissionRemovalThresholdDays
		}

		agg.UsageStatus = "unused"
		switch {
		case agg.HasUsed:
			agg.UsageStatus = "used"
			agg.UnusedSince = time.Time{}
		case agg.HasUncertain:
			agg.UsageStatus = "attribution_uncertain"
			agg.UnusedSince = time.Time{}
		case agg.HasUnknown || !agg.AuthoritativeCoverage:
			agg.UsageStatus = "unknown"
			agg.UnusedSince = time.Time{}
		default:
			agg.UsageStatus = "unused"
		}

		state := permissionUsageCurrentState{LastUsed: agg.LastAccessed, UnusedSince: agg.UnusedSince, Status: agg.UsageStatus}
		daysUnused := permissionUsageDaysUnused(agg.ScanWindowEnd, state, agg.LookbackDays)
		recommendation := ""
		if permissionUsageShouldRecommendRemoval(agg.UsageStatus, daysUnused, agg.RemovalThresholdDays, agg.AuthoritativeCoverage) {
			recommendation = fmt.Sprintf("Permission %s appears unused for this permission set for %d consecutive days; consider removing it from the Identity Center permission set.", agg.Action, daysUnused)
		}

		accountIDs := setToSortedSlice(agg.AccountIDs)
		roleARNs := setToSortedSlice(agg.RoleARNs)
		accountID := ""
		if len(accountIDs) == 1 {
			accountID = accountIDs[0]
		}

		row := map[string]interface{}{
			"_cq_id":                       agg.RowID,
			"arn":                          agg.RowID,
			"account_id":                   accountID,
			"account_ids":                  accountIDs,
			"account_count":                len(accountIDs),
			"region":                       agg.Region,
			"identity_center_instance_arn": agg.InstanceArn,
			"identity_store_id":            agg.IdentityStoreID,
			"permission_set_arn":           agg.PermissionSetArn,
			"permission_set_name":          agg.PermissionSetName,
			"sso_role_arns":                roleARNs,
			"assignment_count":             agg.AssignmentCount,
			"action":                       agg.Action,
			"usage_status":                 agg.UsageStatus,
			"days_unused":                  daysUnused,
			"lookback_days":                agg.LookbackDays,
			"removal_threshold_days":       agg.RemovalThresholdDays,
			"recommendation":               recommendation,
			"evidence_source":              firstNonEmptySync(agg.EvidenceSource, "aws_iam_access_advisor_action_level"),
			"confidence":                   firstNonEmptySync(agg.Confidence, "medium"),
			"coverage":                     firstNonEmptySync(agg.Coverage, "full"),
			"scan_window_start":            agg.ScanWindowStart,
			"scan_window_end":              agg.ScanWindowEnd,
		}
		if !agg.LastAccessed.IsZero() {
			row["action_last_accessed"] = agg.LastAccessed
		}
		if !state.UnusedSince.IsZero() {
			row["unused_since"] = state.UnusedSince
		}
		rollupRows = append(rollupRows, row)
	}

	sort.Slice(rollupRows, func(i, j int) bool {
		return queryRowString(rollupRows[i], "_cq_id") < queryRowString(rollupRows[j], "_cq_id")
	})
	return rollupRows
}

func mergePermissionUsageCoverage(current, candidate string) string {
	current = strings.ToLower(strings.TrimSpace(current))
	candidate = strings.ToLower(strings.TrimSpace(candidate))
	if current == "" {
		return candidate
	}
	if current == "partial" || candidate == "partial" {
		return "partial"
	}
	return current
}

func mergePermissionUsageConfidence(current, candidate string) string {
	rank := func(value string) int {
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "low":
			return 1
		case "medium":
			return 2
		case "high":
			return 3
		default:
			return 0
		}
	}
	if rank(current) == 0 {
		return candidate
	}
	if rank(candidate) == 0 {
		return current
	}
	if rank(candidate) < rank(current) {
		return candidate
	}
	return current
}

func setToSortedSlice(values map[string]struct{}) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for value := range values {
		if strings.TrimSpace(value) == "" {
			continue
		}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func permissionUsageRowInt(value interface{}) int {
	switch typed := value.(type) {
	case int:
		return typed
	case int32:
		parsed, err := strconv.Atoi(strconv.FormatInt(int64(typed), 10))
		if err == nil {
			return parsed
		}
	case int64:
		parsed, err := strconv.Atoi(strconv.FormatInt(typed, 10))
		if err == nil {
			return parsed
		}
	case float64:
		return int(typed)
	case float32:
		return int(typed)
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(typed))
		if err == nil {
			return parsed
		}
	}
	return 0
}

func firstNonEmptySync(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
