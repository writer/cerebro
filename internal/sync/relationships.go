package sync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/evalops/cerebro/internal/snowflake"
)

// Relationship represents a connection between two cloud resources
type Relationship struct {
	SourceID   string    `json:"source_id"`
	SourceType string    `json:"source_type"`
	TargetID   string    `json:"target_id"`
	TargetType string    `json:"target_type"`
	RelType    string    `json:"rel_type"`
	Properties string    `json:"properties,omitempty"` // JSON string
	SyncTime   time.Time `json:"sync_time"`
}

// RelationshipType constants
const (
	RelHasRole          = "HAS_ROLE"
	RelMemberOf         = "MEMBER_OF"
	RelAttachedTo       = "ATTACHED_TO"
	RelBelongsTo        = "BELONGS_TO"
	RelCanAccess        = "CAN_ACCESS"
	RelExposedTo        = "EXPOSED_TO"
	RelTrustedBy        = "TRUSTED_BY"
	RelContains         = "CONTAINS"
	RelProtects         = "PROTECTS"
	RelEncryptedBy      = "ENCRYPTED_BY"
	RelManagedBy        = "MANAGED_BY"
	RelLogsTo           = "LOGS_TO"
	RelReadsFrom        = "READS_FROM"
	RelWritesTo         = "WRITES_TO"
	RelInvokes          = "INVOKES"
	RelRoutes           = "ROUTES"
	RelInSubnet         = "IN_SUBNET"
	RelInVPC            = "IN_VPC"
	RelAssumableBy      = "ASSUMABLE_BY"
	RelHasPermission    = "HAS_PERMISSION"
	RelHasVulnerability = "HAS_VULNERABILITY"
)

// RelationshipExtractor extracts relationships from synced resources
type RelationshipExtractor struct {
	sf          *snowflake.Client
	logger      *slog.Logger
	runSyncTime time.Time
}

// RelationshipBackfillStats summarizes normalization updates.
type RelationshipBackfillStats struct {
	Scanned int `json:"scanned"`
	Updated int `json:"updated"`
	Deleted int `json:"deleted"`
	Skipped int `json:"skipped"`
}

var relationshipNowUTC = func() time.Time {
	return time.Now().UTC().Truncate(time.Millisecond)
}

var relationshipSchemaName = func(sf *snowflake.Client) string {
	if sf == nil {
		return ""
	}
	return sf.Schema()
}

var relationshipQueryBatch = func(ctx context.Context, sf *snowflake.Client, query string, args ...interface{}) error {
	if sf == nil {
		return fmt.Errorf("snowflake client is nil")
	}
	_, err := sf.Query(ctx, query, args...)
	return err
}

// NewRelationshipExtractor creates a new extractor
func NewRelationshipExtractor(sf *snowflake.Client, logger *slog.Logger) *RelationshipExtractor {
	return &RelationshipExtractor{sf: sf, logger: logger}
}

// ExtractAndPersist queries synced tables and extracts relationships
func (r *RelationshipExtractor) ExtractAndPersist(ctx context.Context) (int, error) {
	// Ensure relationships table exists
	if err := r.ensureTable(ctx); err != nil {
		return 0, err
	}

	runSyncTime := relationshipNowUTC()
	r.runSyncTime = runSyncTime
	defer func() {
		r.runSyncTime = time.Time{}
	}()

	var totalRels int
	var hadErrors bool

	// Extract from EC2 instances
	count, err := r.extractEC2Relationships(ctx)
	if err != nil {
		hadErrors = true
		r.logger.Warn("failed to extract EC2 relationships", "error", err)
	}
	totalRels += count

	// Extract from IAM roles
	count, err = r.extractIAMRoleRelationships(ctx)
	if err != nil {
		hadErrors = true
		r.logger.Warn("failed to extract IAM role relationships", "error", err)
	}
	totalRels += count

	// Extract from Lambda functions
	count, err = r.extractLambdaRelationships(ctx)
	if err != nil {
		hadErrors = true
		r.logger.Warn("failed to extract Lambda relationships", "error", err)
	}
	totalRels += count

	// Extract from Security Groups
	count, err = r.extractSecurityGroupRelationships(ctx)
	if err != nil {
		hadErrors = true
		r.logger.Warn("failed to extract Security Group relationships", "error", err)
	}
	totalRels += count

	// Extract from S3 buckets
	count, err = r.extractS3Relationships(ctx)
	if err != nil {
		hadErrors = true
		r.logger.Warn("failed to extract S3 relationships", "error", err)
	}
	totalRels += count

	// Extract from ECS
	count, err = r.extractECSRelationships(ctx)
	if err != nil {
		hadErrors = true
		r.logger.Warn("failed to extract ECS relationships", "error", err)
	}
	totalRels += count

	// Extract from RDS
	count, err = r.extractRDSRelationships(ctx)
	if err != nil {
		hadErrors = true
		r.logger.Warn("failed to extract RDS relationships", "error", err)
	}
	totalRels += count

	// Extract from EKS
	count, err = r.extractEKSRelationships(ctx)
	if err != nil {
		hadErrors = true
		r.logger.Warn("failed to extract EKS relationships", "error", err)
	}
	totalRels += count

	// Extract GCP relationships
	count, err = r.extractGCPRelationships(ctx)
	if err != nil {
		hadErrors = true
		r.logger.Warn("failed to extract GCP relationships", "error", err)
	}
	totalRels += count

	// Extract Azure relationships
	count, err = r.extractAzureRelationships(ctx)
	if err != nil {
		hadErrors = true
		r.logger.Warn("failed to extract Azure relationships", "error", err)
	}
	totalRels += count

	// Extract Okta relationships
	count, err = r.extractOktaRelationships(ctx)
	if err != nil {
		hadErrors = true
		r.logger.Warn("failed to extract Okta relationships", "error", err)
	}
	totalRels += count

	// Cleanup stale relationships from earlier runs.
	// Only cleanup if extraction had no errors.
	if !hadErrors && totalRels > 0 {
		if err := r.cleanupStaleRelationships(ctx, runSyncTime); err != nil {
			r.logger.Warn("failed to clean up stale relationships", "error", err)
		}
	}

	r.logger.Info("relationship extraction complete", "total", totalRels, "errors", hadErrors)
	if hadErrors {
		return totalRels, fmt.Errorf("relationship extraction encountered errors")
	}
	return totalRels, nil
}

// BackfillNormalizedRelationshipIDs normalizes IDs for existing relationships.
func (r *RelationshipExtractor) BackfillNormalizedRelationshipIDs(ctx context.Context, batchSize int) (RelationshipBackfillStats, error) {
	var stats RelationshipBackfillStats
	if err := r.ensureTable(ctx); err != nil {
		return stats, err
	}
	if batchSize <= 0 {
		batchSize = 200
	}

	schema := relationshipSchemaName(r.sf)
	if schema == "" {
		schema = "RAW"
	}
	if err := snowflake.ValidateTableName(schema); err != nil {
		return stats, fmt.Errorf("invalid schema name: %w", err)
	}
	if err := snowflake.ValidateTableName("RESOURCE_RELATIONSHIPS"); err != nil {
		return stats, fmt.Errorf("invalid relationships table name: %w", err)
	}
	fullTable := fmt.Sprintf("%s.RESOURCE_RELATIONSHIPS", schema)

	query := fmt.Sprintf(`SELECT ID, SOURCE_ID, SOURCE_TYPE, TARGET_ID, TARGET_TYPE, REL_TYPE, PROPERTIES, SYNC_TIME FROM %s`, fullTable)
	result, err := r.sf.Query(ctx, query)
	if err != nil {
		return stats, err
	}
	stats.Scanned = result.Count

	updates := make([]relationshipBackfillUpdate, 0, batchSize)
	deleteIDs := make([]string, 0, batchSize)
	seenNewIDs := make(map[string]struct{})

	for _, row := range result.Rows {
		oldID := toString(queryRow(row, "id"))
		sourceRaw := toString(queryRow(row, "source_id"))
		targetRaw := toString(queryRow(row, "target_id"))
		sourceID := normalizeRelationshipID(sourceRaw)
		targetID := normalizeRelationshipID(targetRaw)
		relType := toString(queryRow(row, "rel_type"))
		if sourceID == "" || targetID == "" || relType == "" {
			stats.Skipped++
			continue
		}

		props := formatRelationshipProperties(queryRow(row, "properties"))
		newID := buildRelationshipID(sourceID, relType, targetID, props)
		if newID == "" {
			stats.Skipped++
			continue
		}

		updateNeeded := sourceRaw != sourceID || targetRaw != targetID || oldID != newID
		if !updateNeeded {
			stats.Skipped++
			continue
		}
		stats.Updated++

		if oldID != "" && oldID != newID {
			deleteIDs = append(deleteIDs, oldID)
			stats.Deleted++
		}

		if _, ok := seenNewIDs[newID]; ok {
			if len(updates) >= batchSize || len(deleteIDs) >= batchSize {
				if err := r.applyRelationshipBackfillBatch(ctx, fullTable, updates, deleteIDs); err != nil {
					return stats, err
				}
				updates = updates[:0]
				deleteIDs = deleteIDs[:0]
			}
			continue
		}
		seenNewIDs[newID] = struct{}{}

		updates = append(updates, relationshipBackfillUpdate{
			OldID:      oldID,
			NewID:      newID,
			SourceID:   sourceID,
			SourceType: toString(queryRow(row, "source_type")),
			TargetID:   targetID,
			TargetType: toString(queryRow(row, "target_type")),
			RelType:    relType,
			Properties: props,
			SyncTime:   queryRow(row, "sync_time"),
		})

		if len(updates) >= batchSize || len(deleteIDs) >= batchSize {
			if err := r.applyRelationshipBackfillBatch(ctx, fullTable, updates, deleteIDs); err != nil {
				return stats, err
			}
			updates = updates[:0]
			deleteIDs = deleteIDs[:0]
		}
	}

	if len(updates) > 0 || len(deleteIDs) > 0 {
		if err := r.applyRelationshipBackfillBatch(ctx, fullTable, updates, deleteIDs); err != nil {
			return stats, err
		}
	}

	return stats, nil
}

type relationshipBackfillUpdate struct {
	OldID      string
	NewID      string
	SourceID   string
	SourceType string
	TargetID   string
	TargetType string
	RelType    string
	Properties string
	SyncTime   interface{}
}

func (r *RelationshipExtractor) applyRelationshipBackfillBatch(ctx context.Context, tableName string, updates []relationshipBackfillUpdate, deleteIDs []string) error {
	if len(updates) > 0 {
		values := make([]string, 0, len(updates))
		args := make([]interface{}, 0, len(updates)*8)
		for _, update := range updates {
			values = append(values, "(?, ?, ?, ?, ?, ?, ?, ?)")
			args = append(args,
				update.NewID,
				update.SourceID,
				update.SourceType,
				update.TargetID,
				update.TargetType,
				update.RelType,
				update.Properties,
				update.SyncTime,
			)
		}
		merge := fmt.Sprintf(`MERGE INTO %s AS t
USING (SELECT column1 AS id,
              column2 AS source_id,
              column3 AS source_type,
              column4 AS target_id,
              column5 AS target_type,
              column6 AS rel_type,
              column7 AS properties,
              column8 AS sync_time
       FROM VALUES %s) AS s
ON t.ID = s.id
WHEN MATCHED THEN UPDATE SET
  SOURCE_ID = s.source_id,
  SOURCE_TYPE = s.source_type,
  TARGET_ID = s.target_id,
  TARGET_TYPE = s.target_type,
  REL_TYPE = s.rel_type,
  PROPERTIES = TRY_PARSE_JSON(s.properties),
  SYNC_TIME = COALESCE(s.sync_time, t.SYNC_TIME)
WHEN NOT MATCHED THEN INSERT (ID, SOURCE_ID, SOURCE_TYPE, TARGET_ID, TARGET_TYPE, REL_TYPE, PROPERTIES, SYNC_TIME)
VALUES (s.id, s.source_id, s.source_type, s.target_id, s.target_type, s.rel_type, TRY_PARSE_JSON(s.properties), s.sync_time)`, tableName, strings.Join(values, ","))
		if _, err := r.sf.Exec(ctx, merge, args...); err != nil {
			return err
		}
	}

	if len(deleteIDs) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(deleteIDs))
	unique := make([]string, 0, len(deleteIDs))
	for _, id := range deleteIDs {
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		unique = append(unique, id)
	}
	if len(unique) == 0 {
		return nil
	}
	placeholders := make([]string, 0, len(unique))
	args := make([]interface{}, 0, len(unique))
	for _, id := range unique {
		placeholders = append(placeholders, "?")
		args = append(args, id)
	}
	deleteQuery := fmt.Sprintf("DELETE FROM %s WHERE ID IN (%s)", tableName, strings.Join(placeholders, ","))
	_, err := r.sf.Exec(ctx, deleteQuery, args...)
	return err
}

func formatRelationshipProperties(value interface{}) string {
	if value == nil {
		return "{}"
	}
	if m := asMap(value); m != nil {
		props, err := encodeProperties(m)
		if err == nil && props != "" {
			return props
		}
	}
	props := strings.TrimSpace(toString(value))
	if props == "" {
		return "{}"
	}
	return props
}

func (r *RelationshipExtractor) ensureTable(ctx context.Context) error {
	// Use fully qualified table name to ensure we're in the right schema
	schema := r.sf.Schema()
	if schema == "" {
		schema = "RAW"
	}
	if err := snowflake.ValidateTableName(schema); err != nil {
		return fmt.Errorf("invalid schema name: %w", err)
	}
	query := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s.RESOURCE_RELATIONSHIPS (
		ID VARCHAR PRIMARY KEY,
		SOURCE_ID VARCHAR NOT NULL,
		SOURCE_TYPE VARCHAR NOT NULL,
		TARGET_ID VARCHAR NOT NULL,
		TARGET_TYPE VARCHAR NOT NULL,
		REL_TYPE VARCHAR NOT NULL,
		PROPERTIES VARIANT,
		SYNC_TIME TIMESTAMP_TZ DEFAULT CURRENT_TIMESTAMP()
	)`, schema)
	_, err := r.sf.Exec(ctx, query)
	return err
}

func (r *RelationshipExtractor) cleanupStaleRelationships(ctx context.Context, cutoff time.Time) error {
	schema := r.sf.Schema()
	if schema == "" {
		schema = "RAW"
	}
	if err := snowflake.ValidateTableName(schema); err != nil {
		return fmt.Errorf("invalid schema name: %w", err)
	}
	query := fmt.Sprintf(`DELETE FROM %s.RESOURCE_RELATIONSHIPS WHERE SYNC_TIME < ?`, schema)
	_, err := r.sf.Exec(ctx, query, cutoff.UTC())
	return err
}

func (r *RelationshipExtractor) persistRelationships(ctx context.Context, rels []Relationship) (int, error) {
	if len(rels) == 0 {
		return 0, nil
	}

	r.logger.Info("persisting relationships", "count", len(rels))

	// Get the schema for fully qualified table name
	schema := relationshipSchemaName(r.sf)
	if schema == "" {
		schema = "RAW"
	}
	if err := snowflake.ValidateTableName(schema); err != nil {
		return 0, fmt.Errorf("invalid schema name: %w", err)
	}
	tableName := fmt.Sprintf("%s.RESOURCE_RELATIONSHIPS", schema)

	// Batch insert in chunks to avoid query size limits.
	const batchSize = 100
	total := 0
	syncTime := r.runSyncTime
	if syncTime.IsZero() {
		syncTime = relationshipNowUTC()
	}

	for i := 0; i < len(rels); i += batchSize {
		end := i + batchSize
		if end > len(rels) {
			end = len(rels)
		}
		batch := rels[i:end]

		values := make([]string, 0, len(batch))
		args := make([]interface{}, 0, len(batch)*8)
		for _, rel := range batch {
			sourceID := normalizeRelationshipID(rel.SourceID)
			targetID := normalizeRelationshipID(rel.TargetID)
			if sourceID == "" || targetID == "" {
				continue
			}
			props := rel.Properties
			if props == "" {
				props = "{}"
			}
			id := buildRelationshipID(sourceID, rel.RelType, targetID, props)
			values = append(values, "(?, ?, ?, ?, ?, ?, ?, ?)")
			args = append(args, id, sourceID, rel.SourceType, targetID, rel.TargetType, rel.RelType, props, syncTime)
		}
		if len(values) == 0 {
			continue
		}

		// Use simple INSERT with fully qualified table name
		query := fmt.Sprintf(`INSERT INTO %s (ID, SOURCE_ID, SOURCE_TYPE, TARGET_ID, TARGET_TYPE, REL_TYPE, PROPERTIES, SYNC_TIME)
			SELECT column1, column2, column3, column4, column5, column6, TRY_PARSE_JSON(column7), column8::TIMESTAMP_TZ
			FROM VALUES %s`,
			tableName, strings.Join(values, ", "))

		// Use Query instead of Exec - Exec has issues with Snowflake commit behavior
		err := relationshipQueryBatch(ctx, r.sf, query, args...)
		if err != nil {
			r.logger.Error("failed to persist relationships batch", "error", err, "batch_start", i, "batch_size", len(batch))
			return total, err
		}
		total += len(values)
	}

	r.logger.Info("relationships persisted", "total", total)
	return total, nil
}

// extractEC2Relationships extracts relationships from EC2 instances
// extractIAMRoleRelationships extracts role trust and policy relationships
// extractLambdaRelationships extracts Lambda function relationships
// extractSecurityGroupRelationships extracts ingress/egress rules
// extractS3Relationships extracts S3 bucket relationships
// extractECSRelationships extracts ECS service/task relationships
// extractGCPRelationships extracts GCP resource relationships
func (r *RelationshipExtractor) getTableColumnSet(ctx context.Context, table string) (map[string]struct{}, error) {
	if err := snowflake.ValidateTableName(table); err != nil {
		return nil, fmt.Errorf("invalid table name %s: %w", table, err)
	}

	query := `
		SELECT COLUMN_NAME
		FROM INFORMATION_SCHEMA.COLUMNS
		WHERE TABLE_SCHEMA = CURRENT_SCHEMA()
		AND TABLE_NAME = ?
	`

	result, err := r.sf.Query(ctx, query, strings.ToUpper(table))
	if err != nil {
		return nil, err
	}

	columns := make(map[string]struct{}, len(result.Rows))
	for _, row := range result.Rows {
		name := strings.ToUpper(queryRowString(row, "column_name"))
		if name == "" {
			continue
		}
		columns[name] = struct{}{}
	}

	return columns, nil
}

func (r *RelationshipExtractor) queryRowsForTable(ctx context.Context, table, query string, args ...interface{}) (*snowflake.QueryResult, bool, error) {
	columnSet, err := r.getTableColumnSet(ctx, table)
	if err != nil {
		return nil, false, err
	}
	if len(columnSet) == 0 {
		return nil, false, nil
	}

	result, err := r.sf.Query(ctx, query, args...)
	if err != nil {
		if isMissingRelationshipSourceError(err) {
			return nil, false, nil
		}
		return nil, false, err
	}

	return result, true, nil
}

func hasTableColumn(columns map[string]struct{}, column string) bool {
	if len(columns) == 0 {
		return false
	}
	_, ok := columns[strings.ToUpper(column)]
	return ok
}

func tableColumnExpression(columns map[string]struct{}, column string) string {
	upper := strings.ToUpper(column)
	if hasTableColumn(columns, upper) {
		return upper
	}
	return fmt.Sprintf("NULL AS %s", upper)
}

func gcpAssetColumnExpression(columns map[string]struct{}, column string) string {
	return tableColumnExpression(columns, column)
}

func buildGCPAssetInventoryQuery(table string, columns map[string]struct{}) string {
	selectColumns := []string{
		"_CQ_ID",
		gcpAssetColumnExpression(columns, "asset_type"),
		gcpAssetColumnExpression(columns, "parent_full_name"),
		gcpAssetColumnExpression(columns, "parent_asset_type"),
		gcpAssetColumnExpression(columns, "kms_keys"),
		gcpAssetColumnExpression(columns, "relationships"),
	}

	return fmt.Sprintf(
		"SELECT %s FROM %s WHERE _CQ_ID IS NOT NULL",
		strings.Join(selectColumns, ", "),
		table,
	)
}

// Helper functions
func extractPrincipals(principal interface{}) []string {
	var principals []string

	switch p := principal.(type) {
	case string:
		if p != "*" {
			principals = append(principals, p)
		}
	case map[string]interface{}:
		for _, v := range p {
			switch val := v.(type) {
			case string:
				if val != "*" {
					principals = append(principals, val)
				}
			case []interface{}:
				for _, item := range val {
					if s, ok := item.(string); ok && s != "*" {
						principals = append(principals, s)
					}
				}
			}
		}
	}

	return principals
}

func inferPrincipalType(principal string) string {
	if strings.HasPrefix(principal, "arn:aws:iam::") {
		if strings.Contains(principal, ":role/") {
			return "aws:iam:role"
		}
		if strings.Contains(principal, ":user/") {
			return "aws:iam:user"
		}
		if strings.Contains(principal, ":root") {
			return "aws:iam:account"
		}
	}
	if strings.HasSuffix(principal, ".amazonaws.com") {
		return "aws:service"
	}
	return "unknown"
}

func isMissingRelationshipSourceError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "does not exist") ||
		strings.Contains(msg, "not authorized") ||
		strings.Contains(msg, "invalid identifier")
}

func extractReferenceID(value interface{}) string {
	if value == nil {
		return ""
	}
	if ref := asMap(value); ref != nil {
		if id := getStringAny(ref, "id", "Id", "ID", "resourceId", "resource_id"); id != "" {
			return normalizeRelationshipID(id)
		}
		if properties := asMap(ref["properties"]); properties != nil {
			if id := getStringAny(properties, "id", "Id", "ID", "resourceId", "resource_id"); id != "" {
				return normalizeRelationshipID(id)
			}
		}
		if properties := asMap(ref["Properties"]); properties != nil {
			if id := getStringAny(properties, "id", "Id", "ID", "resourceId", "resource_id"); id != "" {
				return normalizeRelationshipID(id)
			}
		}
	}
	return normalizeRelationshipID(toString(value))
}

func extractManagedDiskID(value interface{}) string {
	if value == nil {
		return ""
	}
	osDisk := asMap(value)
	if osDisk == nil {
		return ""
	}
	if managedDisk := asMap(osDisk["managedDisk"]); managedDisk != nil {
		if id := getStringAny(managedDisk, "id", "Id", "ID"); id != "" {
			return normalizeRelationshipID(id)
		}
	}
	if managedDisk := asMap(osDisk["ManagedDisk"]); managedDisk != nil {
		if id := getStringAny(managedDisk, "id", "Id", "ID"); id != "" {
			return normalizeRelationshipID(id)
		}
	}
	return ""
}

func extractSubnetReferenceID(value interface{}) string {
	ipCfg := asMap(value)
	if ipCfg == nil {
		return ""
	}
	if subnet := asMap(ipCfg["subnet"]); subnet != nil {
		if id := getStringAny(subnet, "id", "Id", "ID"); id != "" {
			return normalizeRelationshipID(id)
		}
	}
	if subnet := asMap(ipCfg["Subnet"]); subnet != nil {
		if id := getStringAny(subnet, "id", "Id", "ID"); id != "" {
			return normalizeRelationshipID(id)
		}
	}
	if properties := asMap(ipCfg["properties"]); properties != nil {
		if subnet := asMap(properties["subnet"]); subnet != nil {
			if id := getStringAny(subnet, "id", "Id", "ID"); id != "" {
				return normalizeRelationshipID(id)
			}
		}
		if subnet := asMap(properties["Subnet"]); subnet != nil {
			if id := getStringAny(subnet, "id", "Id", "ID"); id != "" {
				return normalizeRelationshipID(id)
			}
		}
	}
	if properties := asMap(ipCfg["Properties"]); properties != nil {
		if subnet := asMap(properties["subnet"]); subnet != nil {
			if id := getStringAny(subnet, "id", "Id", "ID"); id != "" {
				return normalizeRelationshipID(id)
			}
		}
		if subnet := asMap(properties["Subnet"]); subnet != nil {
			if id := getStringAny(subnet, "id", "Id", "ID"); id != "" {
				return normalizeRelationshipID(id)
			}
		}
	}
	return ""
}

func azureIDSegment(resourceID, segment string) string {
	parts := strings.Split(resourceID, "/")
	for i, part := range parts {
		if strings.EqualFold(part, segment) && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func azureParentResourceID(resourceID, childSegment string) string {
	parts := strings.Split(resourceID, "/")
	for i, part := range parts {
		if strings.EqualFold(part, childSegment) && i > 0 {
			return strings.Join(parts[:i], "/")
		}
	}
	return ""
}

func azureSQLServerID(subscriptionID, resourceGroup, serverName string) string {
	if subscriptionID == "" || resourceGroup == "" || serverName == "" {
		return ""
	}
	return fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Sql/servers/%s", subscriptionID, resourceGroup, serverName)
}

func azureStorageAccountID(subscriptionID, resourceGroup, accountName string) string {
	if subscriptionID == "" || resourceGroup == "" || accountName == "" {
		return ""
	}
	return fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/storageAccounts/%s", subscriptionID, resourceGroup, accountName)
}

func azureStorageContainerID(subscriptionID, resourceGroup, accountName, containerName string) string {
	if subscriptionID == "" || resourceGroup == "" || accountName == "" || containerName == "" {
		return ""
	}
	return fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/storageAccounts/%s/blobServices/default/containers/%s", subscriptionID, resourceGroup, accountName, containerName)
}

func normalizeVaultURI(uri string) string {
	uri = strings.TrimSpace(strings.ToLower(uri))
	return strings.TrimSuffix(uri, "/")
}

func gcpAssetNodeType(assetType string) string {
	assetType = strings.TrimSpace(strings.ToLower(assetType))
	if assetType == "" {
		return ""
	}
	parts := strings.Split(assetType, "/")
	if len(parts) != 2 {
		token := normalizeGCPAssetRelationshipType(assetType)
		if token == "" {
			return ""
		}
		return fmt.Sprintf("gcp:asset:%s", strings.ToLower(token))
	}
	service := strings.Split(parts[0], ".")[0]
	resource := normalizeGCPAssetRelationshipType(parts[1])
	if service == "" || resource == "" {
		return ""
	}
	return fmt.Sprintf("gcp:%s:%s", service, strings.ToLower(resource))
}

func normalizeGCPAssetRelationshipType(relType string) string {
	relType = strings.TrimSpace(relType)
	if relType == "" {
		return ""
	}
	b := strings.Builder{}
	b.Grow(len(relType))
	lastUnderscore := false
	for _, ch := range relType {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') {
			b.WriteRune(ch)
			lastUnderscore = false
			continue
		}
		if !lastUnderscore {
			b.WriteRune('_')
			lastUnderscore = true
		}
	}
	out := strings.ToUpper(strings.Trim(b.String(), "_"))
	return out
}

func extractGCPKMSKeyID(value interface{}) string {
	if value == nil {
		return ""
	}
	if keyMap := asMap(value); keyMap != nil {
		if keyID := getStringAny(keyMap, "kms_key", "kmsKey", "name", "id"); keyID != "" {
			return normalizeRelationshipID(keyID)
		}
	}
	return normalizeRelationshipID(toString(value))
}

func gcpArtifactPackageID(cqID, selfLink, projectID, repository, packageName string) string {
	if id := normalizeRelationshipID(cqID); id != "" {
		return id
	}
	if id := normalizeRelationshipID(selfLink); id != "" {
		return id
	}
	projectID = strings.TrimSpace(projectID)
	repository = strings.TrimSpace(repository)
	packageName = strings.TrimSpace(packageName)
	if projectID == "" || repository == "" || packageName == "" {
		return ""
	}
	return fmt.Sprintf("projects/%s/locations/-/repositories/%s/packages/%s", projectID, repository, packageName)
}

func gcpArtifactVersionID(cqID, selfLink, projectID, repository, packageName, versionName string) string {
	if id := normalizeRelationshipID(cqID); id != "" {
		return id
	}
	if id := normalizeRelationshipID(selfLink); id != "" {
		return id
	}
	projectID = strings.TrimSpace(projectID)
	repository = strings.TrimSpace(repository)
	packageName = strings.TrimSpace(packageName)
	versionName = strings.TrimSpace(versionName)
	if projectID == "" || repository == "" || packageName == "" || versionName == "" {
		return ""
	}
	return fmt.Sprintf("projects/%s/locations/-/repositories/%s/packages/%s/versions/%s", projectID, repository, packageName, versionName)
}

func gcpArtifactRepositoryIDFromPackage(packageID, projectID, repository string) string {
	if packageID = normalizeRelationshipID(packageID); packageID != "" {
		if idx := strings.Index(packageID, "/packages/"); idx > 0 {
			return packageID[:idx]
		}
	}
	projectID = strings.TrimSpace(projectID)
	repository = strings.TrimSpace(repository)
	if projectID == "" || repository == "" {
		return ""
	}
	return fmt.Sprintf("projects/%s/locations/-/repositories/%s", projectID, repository)
}

func gcpArtifactPackageIDFromVersion(versionID, projectID, repository, packageName string) string {
	if versionID = normalizeRelationshipID(versionID); versionID != "" {
		if idx := strings.Index(versionID, "/versions/"); idx > 0 {
			return versionID[:idx]
		}
	}
	projectID = strings.TrimSpace(projectID)
	repository = strings.TrimSpace(repository)
	packageName = strings.TrimSpace(packageName)
	if projectID == "" || repository == "" || packageName == "" {
		return ""
	}
	return fmt.Sprintf("projects/%s/locations/-/repositories/%s/packages/%s", projectID, repository, packageName)
}

func gcpArtifactImageID(uri, cqID, name string) string {
	if id := normalizeRelationshipID(uri); id != "" {
		return id
	}
	if id := normalizeRelationshipID(cqID); id != "" {
		return id
	}
	return normalizeRelationshipID(name)
}

func gcpArtifactRepositoryID(repository, imageName string) string {
	if id := normalizeRelationshipID(repository); id != "" {
		return id
	}
	imageName = normalizeRelationshipID(imageName)
	if imageName == "" {
		return ""
	}
	if idx := strings.Index(imageName, "/dockerImages/"); idx > 0 {
		return imageName[:idx]
	}
	return ""
}

func gcpArtifactPackageIDFromImage(imageName string) string {
	imageName = normalizeRelationshipID(imageName)
	if imageName == "" {
		return ""
	}
	idx := strings.Index(imageName, "/dockerImages/")
	if idx <= 0 {
		return ""
	}

	repoID := imageName[:idx]
	imageRef := strings.TrimSpace(imageName[idx+len("/dockerImages/"):])
	if imageRef == "" {
		return ""
	}
	if suffixIdx := strings.IndexAny(imageRef, "@:"); suffixIdx > 0 {
		imageRef = imageRef[:suffixIdx]
	}
	imageRef = strings.TrimSpace(imageRef)
	if imageRef == "" {
		return ""
	}

	return fmt.Sprintf("%s/packages/%s", repoID, imageRef)
}

func gcpSCCFindingID(cqID, name string) string {
	if id := normalizeRelationshipID(cqID); id != "" {
		return id
	}
	return normalizeRelationshipID(name)
}

func gcpStorageBucketID(name string) string {
	name = normalizeRelationshipID(name)
	if name == "" {
		return ""
	}
	if strings.HasPrefix(name, "projects/") {
		return name
	}
	return fmt.Sprintf("projects/_/buckets/%s", name)
}

func gcpStorageObjectID(cqID, selfLink, bucket, name string) string {
	if id := normalizeRelationshipID(cqID); id != "" {
		return id
	}
	if id := normalizeRelationshipID(selfLink); id != "" {
		return id
	}
	bucket = normalizeRelationshipID(bucket)
	name = normalizeRelationshipID(name)
	if bucket == "" || name == "" {
		return ""
	}
	return fmt.Sprintf("projects/_/buckets/%s/objects/%s", bucket, name)
}

func gcpPubSubTopicID(cqID, projectID, name string) string {
	if id := normalizeRelationshipID(cqID); id != "" {
		return id
	}
	projectID = normalizeRelationshipID(projectID)
	name = normalizeRelationshipID(name)
	if projectID == "" || name == "" {
		return ""
	}
	return fmt.Sprintf("projects/%s/topics/%s", projectID, name)
}

func gcpIDSEndpointID(cqID, name string) string {
	if id := normalizeRelationshipID(cqID); id != "" {
		return id
	}
	return normalizeRelationshipID(name)
}

func gcpClusterID(cqID, selfLink, projectID, location, name string) string {
	if id := normalizeRelationshipID(cqID); id != "" {
		return id
	}
	if id := normalizeRelationshipID(selfLink); id != "" {
		return id
	}
	projectID = normalizeRelationshipID(projectID)
	location = normalizeRelationshipID(location)
	name = normalizeRelationshipID(name)
	if projectID == "" || location == "" || name == "" {
		return ""
	}
	return fmt.Sprintf("projects/%s/locations/%s/clusters/%s", projectID, location, name)
}

func gcpNodePoolID(cqID, selfLink, projectID, location, clusterName, nodePoolName string) string {
	if id := normalizeRelationshipID(cqID); id != "" {
		return id
	}
	if id := normalizeRelationshipID(selfLink); id != "" {
		return id
	}
	projectID = normalizeRelationshipID(projectID)
	location = normalizeRelationshipID(location)
	clusterName = normalizeRelationshipID(clusterName)
	nodePoolName = normalizeRelationshipID(nodePoolName)
	if projectID == "" || location == "" || clusterName == "" || nodePoolName == "" {
		return ""
	}
	return fmt.Sprintf("projects/%s/locations/%s/clusters/%s/nodePools/%s", projectID, location, clusterName, nodePoolName)
}

func gcpProjectPath(projectID string) string {
	projectID = normalizeRelationshipID(projectID)
	if projectID == "" {
		return ""
	}
	if strings.HasPrefix(projectID, "projects/") {
		return projectID
	}
	return fmt.Sprintf("projects/%s", projectID)
}

func gcpServiceAccountID(cqID, name, projectID, email string) string {
	if id := normalizeRelationshipID(cqID); id != "" {
		return id
	}
	if id := normalizeRelationshipID(name); id != "" {
		return id
	}
	projectID = normalizeRelationshipID(projectID)
	email = normalizeRelationshipID(email)
	if projectID == "" || email == "" {
		return ""
	}
	return fmt.Sprintf("projects/%s/serviceAccounts/%s", projectID, email)
}

func gcpIAMPrincipal(member, memberType, email, projectID string) (string, string) {
	member = normalizeRelationshipID(member)
	memberType = strings.TrimSpace(strings.ToLower(memberType))
	email = normalizeRelationshipID(email)

	if strings.HasPrefix(member, "serviceAccount:") {
		sa := normalizeRelationshipID(strings.TrimPrefix(member, "serviceAccount:"))
		if sa == "" {
			return "", ""
		}
		if strings.Contains(sa, "/") {
			return sa, "gcp:iam:service_account"
		}
		if project := normalizeRelationshipID(projectID); project != "" {
			return fmt.Sprintf("projects/%s/serviceAccounts/%s", project, sa), "gcp:iam:service_account"
		}
		return sa, "gcp:iam:service_account"
	}

	if member == "allUsers" || member == "allAuthenticatedUsers" {
		return member, "gcp:iam:principal"
	}

	if memberType == "user" || strings.HasPrefix(member, "user:") {
		if email == "" {
			email = normalizeRelationshipID(strings.TrimPrefix(member, "user:"))
		}
		return email, "gcp:iam:user"
	}

	if memberType == "group" || strings.HasPrefix(member, "group:") {
		if email == "" {
			email = normalizeRelationshipID(strings.TrimPrefix(member, "group:"))
		}
		return email, "gcp:iam:group"
	}

	if memberType == "domain" || strings.HasPrefix(member, "domain:") {
		domain := normalizeRelationshipID(strings.TrimPrefix(member, "domain:"))
		return domain, "gcp:iam:domain"
	}

	if member == "" {
		return "", ""
	}
	return member, "gcp:iam:principal"
}

func gcpLoggingSinkID(cqID, projectID, name string) string {
	if id := normalizeRelationshipID(cqID); id != "" {
		return id
	}
	project := gcpProjectPath(projectID)
	name = normalizeRelationshipID(name)
	if project == "" || name == "" {
		return ""
	}
	return fmt.Sprintf("%s/sinks/%s", project, name)
}

func gcpLoggingDestinationID(destination string) (string, string) {
	destination = normalizeRelationshipID(destination)
	if destination == "" {
		return "", ""
	}

	if strings.HasPrefix(destination, "storage.googleapis.com/") {
		bucket := strings.TrimSpace(strings.TrimPrefix(destination, "storage.googleapis.com/"))
		if id := gcpStorageBucketID(bucket); id != "" {
			return id, "gcp:storage:bucket"
		}
	}

	if strings.HasPrefix(destination, "pubsub.googleapis.com/") {
		id := normalizeRelationshipID(strings.TrimPrefix(destination, "pubsub.googleapis.com/"))
		return id, "gcp:pubsub:topic"
	}

	if strings.HasPrefix(destination, "bigquery.googleapis.com/") {
		id := normalizeRelationshipID(strings.TrimPrefix(destination, "bigquery.googleapis.com/"))
		return id, "gcp:bigquery:dataset"
	}

	return destination, "gcp:resource"
}

func toString(v interface{}) string {
	if v == nil {
		return ""
	}
	var s string
	if str, ok := v.(string); ok {
		s = str
	} else {
		s = fmt.Sprintf("%v", v)
	}
	// Snowflake VARIANT columns return strings with JSON quotes - strip them
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	return s
}

func normalizeRelationshipID(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return ""
	}
	if len(id) >= 2 && id[0] == '"' && id[len(id)-1] == '"' {
		id = id[1 : len(id)-1]
	}
	if strings.HasPrefix(id, "{") {
		var parsed map[string]interface{}
		if err := json.Unmarshal([]byte(id), &parsed); err == nil {
			if val := getStringAny(parsed, "arn", "Arn", "ARN", "id", "Id", "ID", "resource_id", "resourceId"); val != "" {
				return val
			}
		}
		if val := extractRelIDFromJSONString(id); val != "" {
			return val
		}
	}
	if strings.HasPrefix(id, "map[") {
		if val := extractRelIDFromMapString(id); val != "" {
			return val
		}
	}
	return id
}

func extractRelIDFromJSONString(raw string) string {
	for _, key := range []string{`"arn"`, `"Arn"`, `"ARN"`, `"id"`, `"Id"`, `"ID"`} {
		if idx := strings.Index(raw, key); idx >= 0 {
			rest := raw[idx+len(key):]
			rest = strings.TrimLeft(rest, `: "`)
			if end := strings.IndexByte(rest, '"'); end > 0 {
				return rest[:end]
			}
		}
	}
	return ""
}

func extractRelIDFromMapString(raw string) string {
	for _, key := range []string{"Arn:", "arn:", "ID:", "Id:", "id:"} {
		if idx := strings.Index(raw, key); idx >= 0 {
			rest := raw[idx+len(key):]
			if fields := strings.Fields(rest); len(fields) > 0 {
				return strings.Trim(fields[0], ",]")
			}
		}
	}
	return ""
}

func getStringAny(m map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if v, ok := m[key]; ok {
			if s := toString(v); s != "" {
				return s
			}
		}
	}
	return ""
}

func getSliceAny(m map[string]interface{}, keys ...string) []interface{} {
	for _, key := range keys {
		if v, ok := m[key]; ok {
			if slice := asSlice(v); len(slice) > 0 {
				return slice
			}
		}
	}
	return nil
}

func asMap(v interface{}) map[string]interface{} {
	if v == nil {
		return nil
	}
	switch val := v.(type) {
	case map[string]interface{}:
		return val
	case []byte:
		var m map[string]interface{}
		if err := json.Unmarshal(val, &m); err == nil {
			return m
		}
	case string:
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(val), &m); err == nil {
			return m
		}
	}
	return nil
}

func asSlice(v interface{}) []interface{} {
	if v == nil {
		return nil
	}
	switch val := v.(type) {
	case []interface{}:
		return val
	case []byte:
		var s []interface{}
		if err := json.Unmarshal(val, &s); err == nil {
			return s
		}
	case string:
		var s []interface{}
		if err := json.Unmarshal([]byte(val), &s); err == nil {
			return s
		}
	}
	return nil
}

func parsePolicyDocument(value interface{}) (map[string]interface{}, error) {
	if value == nil {
		return nil, nil
	}
	if doc := asMap(value); doc != nil {
		return doc, nil
	}
	raw := toString(value) // Use toString to strip Snowflake VARIANT quotes
	if raw == "" {
		return nil, nil
	}
	decoded, err := url.QueryUnescape(raw)
	if err != nil {
		decoded = raw
	}
	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(decoded), &doc); err != nil {
		return nil, err
	}
	return doc, nil
}

func encodeProperties(props map[string]interface{}) (string, error) {
	if len(props) == 0 {
		return "{}", nil
	}
	encoded, err := json.Marshal(props)
	if err != nil {
		return "{}", err
	}
	return string(encoded), nil
}

func buildRelationshipID(sourceID, relType, targetID, props string) string {
	base := fmt.Sprintf("%s|%s|%s", sourceID, relType, targetID)
	if props == "" || props == "{}" {
		return base
	}
	hash := sha256.Sum256([]byte(props))
	return fmt.Sprintf("%s|%s", base, hex.EncodeToString(hash[:8]))
}
