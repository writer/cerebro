package sync

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/writerinternal/cerebro/internal/snowflake"
)

type AWSSyncer struct {
	sf        *snowflake.Client
	logger    *slog.Logger
	region    string
	accountID string
}

func NewAWSSyncer(sf *snowflake.Client, logger *slog.Logger) *AWSSyncer {
	return &AWSSyncer{
		sf:     sf,
		logger: logger,
		region: "us-east-1",
	}
}

type syncFunc struct {
	name string
	fn   func(context.Context, aws.Config) (*SyncResult, error)
}

func (s *AWSSyncer) SyncAll(ctx context.Context) ([]SyncResult, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(s.region))
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}

	syncFuncs := []syncFunc{
		// Compute
		{"aws_ecs_clusters", s.syncECSClusters},
		{"aws_ecs_services", s.syncECSServices},
		{"aws_ecs_task_definitions", s.syncECSTaskDefinitions},
		{"aws_ec2_instances", s.syncEC2Instances},
		{"aws_ec2_security_groups", s.syncSecurityGroups},
		{"aws_ec2_vpcs", s.syncVPCs},
		{"aws_lambda_functions", s.syncLambdaFunctions},
		// IAM
		{"aws_iam_roles", s.syncIAMRoles},
		{"aws_iam_users", s.syncIAMUsers},
		{"aws_iam_credential_reports", s.syncCredentialReport},
		// Storage & Secrets
		{"aws_s3_buckets", s.syncS3Buckets},
		{"aws_ecr_repositories", s.syncECRRepositories},
		{"aws_kms_keys", s.syncKMSKeys},
		{"aws_secretsmanager_secrets", s.syncSecretsManagerSecrets},
	}

	var results []SyncResult
	for _, sf := range syncFuncs {
		s.logger.Info("syncing", "table", sf.name)
		result, err := sf.fn(ctx, cfg)
		if err != nil {
			s.logger.Error("sync failed", "table", sf.name, "error", err)
			results = append(results, SyncResult{Table: sf.name, Errors: 1})
			continue
		}
		results = append(results, *result)
		s.logger.Info("synced", "table", sf.name, "count", result.Synced)
	}

	return results, nil
}

func (s *AWSSyncer) getAccountID(ctx context.Context, cfg aws.Config) string {
	if s.accountID != "" {
		return s.accountID
	}
	stsClient := sts.NewFromConfig(cfg)
	out, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err == nil && out.Account != nil {
		s.accountID = *out.Account
	}
	return s.accountID
}

func (s *AWSSyncer) ensureTable(ctx context.Context, table string, columns []string) error {
	// First, try to create the table if it doesn't exist
	colDefs := make([]string, len(columns))
	for i, col := range columns {
		colDefs[i] = fmt.Sprintf("%s VARIANT", strings.ToUpper(col))
	}

	createQuery := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
		_CQ_ID VARCHAR PRIMARY KEY,
		_CQ_SYNC_TIME TIMESTAMP_TZ DEFAULT CURRENT_TIMESTAMP(),
		%s
	)`, table, strings.Join(colDefs, ", "))

	if _, err := s.sf.Exec(ctx, createQuery); err != nil {
		return fmt.Errorf("create table: %w", err)
	}

	// Now check for missing columns and add them
	existingCols, err := s.getTableColumns(ctx, table)
	if err != nil {
		return fmt.Errorf("get columns: %w", err)
	}

	existingSet := make(map[string]bool)
	for _, col := range existingCols {
		existingSet[strings.ToUpper(col)] = true
	}

	for _, col := range columns {
		upperCol := strings.ToUpper(col)
		if !existingSet[upperCol] {
			alterQuery := fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s VARIANT", table, upperCol)
			if _, err := s.sf.Exec(ctx, alterQuery); err != nil {
				s.logger.Warn("failed to add column", "table", table, "column", upperCol, "error", err)
			} else {
				s.logger.Debug("added missing column", "table", table, "column", upperCol)
			}
		}
	}

	return nil
}

func (s *AWSSyncer) getTableColumns(ctx context.Context, table string) ([]string, error) {
	query := fmt.Sprintf(`
		SELECT COLUMN_NAME 
		FROM INFORMATION_SCHEMA.COLUMNS 
		WHERE TABLE_NAME = '%s' 
		AND TABLE_SCHEMA = CURRENT_SCHEMA()
	`, strings.ToUpper(table))

	result, err := s.sf.Query(ctx, query)
	if err != nil {
		return nil, err
	}

	var columns []string
	for _, row := range result.Rows {
		if col, ok := row["COLUMN_NAME"].(string); ok {
			columns = append(columns, col)
		}
	}
	return columns, nil
}

func (s *AWSSyncer) upsertRows(ctx context.Context, table string, rows []map[string]interface{}) (*ChangeSet, error) {
	changes := &ChangeSet{}
	
	if len(rows) == 0 {
		return changes, nil
	}

	// Get existing rows for change detection
	existingRows := s.getExistingRows(ctx, table)
	
	// Build map of new rows by ID
	newRowMap := make(map[string]string) // id -> content hash
	for _, row := range rows {
		id := row["_cq_id"].(string)
		hash := hashRow(row)
		newRowMap[id] = hash
	}

	// Detect removed and modified
	for id, oldHash := range existingRows {
		if newHash, exists := newRowMap[id]; !exists {
			changes.Removed = append(changes.Removed, id)
		} else if newHash != oldHash {
			changes.Modified = append(changes.Modified, id)
		}
	}

	// Detect added
	for id := range newRowMap {
		if _, exists := existingRows[id]; !exists {
			changes.Added = append(changes.Added, id)
		}
	}

	// Log changes
	if changes.HasChanges() {
		s.logger.Info("detected changes", 
			"table", table,
			"added", len(changes.Added),
			"modified", len(changes.Modified),
			"removed", len(changes.Removed))
	}

	// Delete and re-insert
	if _, err := s.sf.Exec(ctx, fmt.Sprintf("DELETE FROM %s", table)); err != nil {
		s.logger.Debug("delete failed (table may not exist)", "error", err)
	}

	for _, row := range rows {
		id := row["_cq_id"].(string)
		delete(row, "_cq_id")

		cols := []string{"_CQ_ID"}
		selects := []string{fmt.Sprintf("'%s'", strings.ReplaceAll(id, "'", "''"))}

		for k, v := range row {
			cols = append(cols, strings.ToUpper(k))
			jsonVal, _ := json.Marshal(v)
			escaped := strings.ReplaceAll(string(jsonVal), "'", "''")
			selects = append(selects, fmt.Sprintf("PARSE_JSON('%s')", escaped))
		}

		query := fmt.Sprintf("INSERT INTO %s (%s) SELECT %s",
			table, strings.Join(cols, ", "), strings.Join(selects, ", "))

		if _, err := s.sf.Exec(ctx, query); err != nil {
			return changes, fmt.Errorf("insert row: %w", err)
		}
	}

	return changes, nil
}

func (s *AWSSyncer) getExistingRows(ctx context.Context, table string) map[string]string {
	result := make(map[string]string)
	
	query := fmt.Sprintf("SELECT _CQ_ID, HASH(*) as row_hash FROM %s", table)
	rows, err := s.sf.Query(ctx, query)
	if err != nil {
		return result
	}
	
	for _, row := range rows.Rows {
		if id, ok := row["_CQ_ID"].(string); ok {
			hash := ""
			if h, ok := row["ROW_HASH"]; ok {
				hash = fmt.Sprintf("%v", h)
			}
			result[id] = hash
		}
	}
	
	return result
}

func hashRow(row map[string]interface{}) string {
	// Simple hash based on JSON representation
	data, _ := json.Marshal(row)
	return fmt.Sprintf("%x", len(data)) // Simple length-based hash for now
}
