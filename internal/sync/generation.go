package sync

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/warehouse"
)

const (
	defaultSyncStalenessThreshold = 15 * time.Minute
	syncTableGenerationsTable     = "_sync_table_generations"
	syncGenerationAlertsTable     = "_sync_generation_alerts"
)

// SyncStalenessPoint identifies the table/region at an observed sync time.
type SyncStalenessPoint struct {
	Table    string
	Region   string
	SyncTime time.Time
}

// SyncStalenessAlert captures sync-time divergence across tables in one run.
type SyncStalenessAlert struct {
	Threshold time.Duration
	Drift     time.Duration
	Min       SyncStalenessPoint
	Max       SyncStalenessPoint
}

var dependencyBaseTables = map[string]struct{}{
	"aws_ec2_vpcs":                    {},
	"aws_ec2_subnets":                 {},
	"aws_ec2_security_groups":         {},
	"aws_ec2_security_group_rules":    {},
	"aws_ec2_route_tables":            {},
	"aws_ec2_internet_gateways":       {},
	"aws_ec2_nat_gateways":            {},
	"aws_ec2_network_interfaces":      {},
	"aws_ec2_vpc_peering_connections": {},
}

var dependencyDependentTables = map[string]struct{}{
	"aws_ec2_instances":        {},
	"aws_lambda_functions":     {},
	"aws_ecs_clusters":         {},
	"aws_ecs_services":         {},
	"aws_ecs_task_definitions": {},
	"aws_rds_instances":        {},
	"aws_rds_clusters":         {},
	"aws_eks_clusters":         {},
	"aws_eks_nodegroups":       {},
	"aws_s3_buckets":           {},
}

var defaultRelationshipSourceTables = []string{
	"aws_ec2_instances",
	"aws_ec2_security_groups",
	"aws_iam_roles",
	"aws_lambda_functions",
	"aws_s3_buckets",
	"aws_ecs_services",
	"aws_rds_instances",
	"aws_eks_clusters",
}

func newSyncGenerationID(provider, accountID string, now time.Time) string {
	providerPart := normalizeGenerationComponent(provider)
	accountPart := normalizeGenerationComponent(accountID)
	timestamp := now.UTC().Format("20060102T150405.000000000Z")
	return fmt.Sprintf("%s:%s:%s", providerPart, accountPart, timestamp)
}

func normalizeGenerationComponent(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		return "unknown"
	}
	replacer := strings.NewReplacer(":", "_", " ", "_", "|", "_")
	return replacer.Replace(normalized)
}

func generationRecordID(provider, accountID, generationID, table, region string) string {
	return fmt.Sprintf("%s:%s:%s:%s:%s",
		normalizeGenerationComponent(provider),
		normalizeGenerationComponent(accountID),
		normalizeGenerationComponent(generationID),
		normalizeGenerationComponent(table),
		normalizeGenerationComponent(region),
	)
}

func generationResultStatus(result SyncResult, syncErr error) (string, string) {
	errorMessage := strings.TrimSpace(result.Error)
	if errorMessage == "" && syncErr != nil {
		errorMessage = strings.TrimSpace(syncErr.Error())
	}

	if syncErr != nil || result.Errors > 0 {
		return "failed", errorMessage
	}
	if result.BackfillPending {
		return "partial", errorMessage
	}
	return "success", ""
}

func syncDependencyOrder(tableName string) int {
	normalized := normalizeBackfillScopeValue(tableName)
	if normalized == "" {
		return 2
	}
	if strings.HasPrefix(normalized, "aws_iam_") {
		return 0
	}
	if _, ok := dependencyBaseTables[normalized]; ok {
		return 0
	}
	if _, ok := dependencyDependentTables[normalized]; ok {
		return 1
	}
	return 2
}

func detectSyncStaleness(results []SyncResult, threshold time.Duration) (SyncStalenessAlert, bool) {
	var alert SyncStalenessAlert
	if threshold <= 0 {
		return alert, false
	}

	var minPoint *SyncStalenessPoint
	var maxPoint *SyncStalenessPoint
	for _, result := range results {
		if result.Errors > 0 || result.SyncTime.IsZero() {
			continue
		}
		point := SyncStalenessPoint{Table: result.Table, Region: result.Region, SyncTime: result.SyncTime.UTC()}
		if minPoint == nil || point.SyncTime.Before(minPoint.SyncTime) {
			p := point
			minPoint = &p
		}
		if maxPoint == nil || point.SyncTime.After(maxPoint.SyncTime) {
			p := point
			maxPoint = &p
		}
	}

	if minPoint == nil || maxPoint == nil {
		return alert, false
	}

	drift := maxPoint.SyncTime.Sub(minPoint.SyncTime)
	if drift <= threshold {
		return alert, false
	}

	alert = SyncStalenessAlert{
		Threshold: threshold,
		Drift:     drift,
		Min:       *minPoint,
		Max:       *maxPoint,
	}
	return alert, true
}

func CanExtractRelationships(results []SyncResult, requiredTables []string) (bool, string) {
	required := normalizeRequiredTables(requiredTables)
	if len(required) == 0 {
		required = normalizeRequiredTables(defaultRelationshipSourceTables)
	}

	type tableState struct {
		seen    bool
		blocked bool
	}
	states := make(map[string]tableState, len(required))
	for _, table := range required {
		states[table] = tableState{}
	}

	for _, result := range results {
		table := normalizeBackfillScopeValue(result.Table)
		state, ok := states[table]
		if !ok {
			continue
		}
		state.seen = true
		if result.Errors > 0 || strings.TrimSpace(result.Error) != "" || result.BackfillPending {
			state.blocked = true
		}
		states[table] = state
	}

	missing := make([]string, 0, len(required))
	blocked := make([]string, 0, len(required))
	for table, state := range states {
		if !state.seen {
			missing = append(missing, table)
			continue
		}
		if state.blocked {
			blocked = append(blocked, table)
		}
	}
	sort.Strings(missing)
	sort.Strings(blocked)

	if len(missing) == 0 && len(blocked) == 0 {
		return true, ""
	}

	reasons := make([]string, 0, 2)
	if len(missing) > 0 {
		reasons = append(reasons, fmt.Sprintf("missing required source tables: %s", strings.Join(missing, ", ")))
	}
	if len(blocked) > 0 {
		reasons = append(reasons, fmt.Sprintf("required source tables not cleanly synced: %s", strings.Join(blocked, ", ")))
	}

	return false, strings.Join(reasons, "; ")
}

func normalizeRequiredTables(requiredTables []string) []string {
	if len(requiredTables) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(requiredTables))
	normalized := make([]string, 0, len(requiredTables))
	for _, table := range requiredTables {
		name := normalizeBackfillScopeValue(table)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		normalized = append(normalized, name)
	}
	sort.Strings(normalized)
	return normalized
}

func (e *SyncEngine) ensureGenerationTrackingTable(ctx context.Context) error {
	createQuery := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
		id VARCHAR PRIMARY KEY,
		provider VARCHAR,
		account_id VARCHAR,
		generation_id VARCHAR,
		table_name VARCHAR,
		region VARCHAR,
		status VARCHAR,
		backfill_pending BOOLEAN,
		synced_rows NUMBER,
		error_message VARCHAR,
		sync_time TIMESTAMP_TZ,
		_cq_sync_time TIMESTAMP_TZ DEFAULT CURRENT_TIMESTAMP()
	)`, syncTableGenerationsTable)
	if _, err := e.sf.Exec(ctx, createQuery); err != nil {
		return fmt.Errorf("create sync generation table: %w", err)
	}
	return nil
}

func (e *SyncEngine) ensureGenerationAlertsTable(ctx context.Context) error {
	createQuery := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
		id VARCHAR PRIMARY KEY,
		provider VARCHAR,
		account_id VARCHAR,
		generation_id VARCHAR,
		drift_seconds NUMBER,
		threshold_seconds NUMBER,
		min_table_name VARCHAR,
		min_region VARCHAR,
		min_sync_time TIMESTAMP_TZ,
		max_table_name VARCHAR,
		max_region VARCHAR,
		max_sync_time TIMESTAMP_TZ,
		message VARCHAR,
		_cq_sync_time TIMESTAMP_TZ DEFAULT CURRENT_TIMESTAMP()
	)`, syncGenerationAlertsTable)
	if _, err := e.sf.Exec(ctx, createQuery); err != nil {
		return fmt.Errorf("create sync generation alerts table: %w", err)
	}
	return nil
}

func (e *SyncEngine) recordGenerationResult(ctx context.Context, generationID string, result SyncResult, syncErr error) error {
	if strings.TrimSpace(generationID) == "" || strings.TrimSpace(result.Table) == "" {
		return nil
	}
	if err := e.ensureGenerationTrackingTable(ctx); err != nil {
		return err
	}

	status, errorMessage := generationResultStatus(result, syncErr)
	syncTime := result.SyncTime
	if syncTime.IsZero() {
		syncTime = time.Now().UTC()
	}

	recordID := generationRecordID("aws", e.accountID, generationID, result.Table, result.Region)
	query := fmt.Sprintf(`MERGE INTO %s t
		USING (
			SELECT ? AS id, ? AS provider, ? AS account_id, ? AS generation_id, ? AS table_name,
				? AS region, ? AS status, ? AS backfill_pending, ? AS synced_rows, ? AS error_message, ? AS sync_time
		) s
		ON t.id = s.id
		WHEN MATCHED THEN UPDATE SET
			provider = s.provider,
			account_id = s.account_id,
			generation_id = s.generation_id,
			table_name = s.table_name,
			region = s.region,
			status = s.status,
			backfill_pending = s.backfill_pending,
			synced_rows = s.synced_rows,
			error_message = s.error_message,
			sync_time = s.sync_time,
			_cq_sync_time = CURRENT_TIMESTAMP()
		WHEN NOT MATCHED THEN INSERT
			(id, provider, account_id, generation_id, table_name, region, status, backfill_pending, synced_rows, error_message, sync_time)
			VALUES
			(s.id, s.provider, s.account_id, s.generation_id, s.table_name, s.region, s.status, s.backfill_pending, s.synced_rows, s.error_message, s.sync_time)`, syncTableGenerationsTable)
	if syncWarehouseDialect(e.sf) != warehouse.DialectSnowflake {
		query = fmt.Sprintf(`INSERT INTO %s
			(id, provider, account_id, generation_id, table_name, region, status, backfill_pending, synced_rows, error_message, sync_time)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (id) DO UPDATE SET
				provider = EXCLUDED.provider,
				account_id = EXCLUDED.account_id,
				generation_id = EXCLUDED.generation_id,
				table_name = EXCLUDED.table_name,
				region = EXCLUDED.region,
				status = EXCLUDED.status,
				backfill_pending = EXCLUDED.backfill_pending,
				synced_rows = EXCLUDED.synced_rows,
				error_message = EXCLUDED.error_message,
				sync_time = EXCLUDED.sync_time,
				_cq_sync_time = CURRENT_TIMESTAMP()`, syncTableGenerationsTable)
	}

	if _, err := e.sf.Exec(ctx, query,
		recordID,
		"aws",
		e.accountID,
		generationID,
		result.Table,
		result.Region,
		status,
		result.BackfillPending,
		result.Synced,
		errorMessage,
		syncTime,
	); err != nil {
		return fmt.Errorf("upsert sync generation result: %w", err)
	}

	return nil
}

func (e *SyncEngine) recordGenerationAlert(ctx context.Context, generationID string, alert SyncStalenessAlert) error {
	if strings.TrimSpace(generationID) == "" {
		return nil
	}
	if err := e.ensureGenerationAlertsTable(ctx); err != nil {
		return err
	}

	recordID := fmt.Sprintf("%s:%d", generationRecordID("aws", e.accountID, generationID, alert.Max.Table, alert.Max.Region), time.Now().UTC().UnixNano())
	message := fmt.Sprintf(
		"sync drift %s exceeded threshold %s (oldest=%s/%s newest=%s/%s)",
		alert.Drift.String(),
		alert.Threshold.String(),
		alert.Min.Table,
		alert.Min.Region,
		alert.Max.Table,
		alert.Max.Region,
	)

	query := fmt.Sprintf(`INSERT INTO %s
		(id, provider, account_id, generation_id, drift_seconds, threshold_seconds, min_table_name, min_region, min_sync_time, max_table_name, max_region, max_sync_time, message)
		SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?`, syncGenerationAlertsTable)

	if _, err := e.sf.Exec(ctx, query,
		recordID,
		"aws",
		e.accountID,
		generationID,
		int64(alert.Drift/time.Second),
		int64(alert.Threshold/time.Second),
		alert.Min.Table,
		alert.Min.Region,
		alert.Min.SyncTime,
		alert.Max.Table,
		alert.Max.Region,
		alert.Max.SyncTime,
		message,
	); err != nil {
		return fmt.Errorf("insert sync generation alert: %w", err)
	}

	return nil
}
