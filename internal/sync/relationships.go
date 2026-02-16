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

	"github.com/writerinternal/cerebro/internal/snowflake"
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
	RelHasRole       = "HAS_ROLE"
	RelMemberOf      = "MEMBER_OF"
	RelAttachedTo    = "ATTACHED_TO"
	RelBelongsTo     = "BELONGS_TO"
	RelCanAccess     = "CAN_ACCESS"
	RelExposedTo     = "EXPOSED_TO"
	RelTrustedBy     = "TRUSTED_BY"
	RelContains      = "CONTAINS"
	RelProtects      = "PROTECTS"
	RelEncryptedBy   = "ENCRYPTED_BY"
	RelManagedBy     = "MANAGED_BY"
	RelLogsTo        = "LOGS_TO"
	RelReadsFrom     = "READS_FROM"
	RelWritesTo      = "WRITES_TO"
	RelInvokes       = "INVOKES"
	RelRoutes        = "ROUTES"
	RelInSubnet      = "IN_SUBNET"
	RelInVPC         = "IN_VPC"
	RelAssumableBy   = "ASSUMABLE_BY"
	RelHasPermission = "HAS_PERMISSION"
)

// RelationshipExtractor extracts relationships from synced resources
type RelationshipExtractor struct {
	sf     *snowflake.Client
	logger *slog.Logger
}

// RelationshipBackfillStats summarizes normalization updates.
type RelationshipBackfillStats struct {
	Scanned int `json:"scanned"`
	Updated int `json:"updated"`
	Deleted int `json:"deleted"`
	Skipped int `json:"skipped"`
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

	startedAt := time.Now()
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

	// Cleanup stale relationships - use a safe window (1 minute) to avoid race conditions
	// Only cleanup if extraction had no errors
	if !hadErrors && totalRels > 0 {
		// Wait a moment to ensure all inserts have completed
		if err := r.cleanupStaleRelationships(ctx, startedAt.Add(-time.Minute)); err != nil {
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

	schema := r.sf.Schema()
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
		oldID := toString(row["id"])
		sourceRaw := toString(row["source_id"])
		targetRaw := toString(row["target_id"])
		sourceID := normalizeRelationshipID(sourceRaw)
		targetID := normalizeRelationshipID(targetRaw)
		relType := toString(row["rel_type"])
		if sourceID == "" || targetID == "" || relType == "" {
			stats.Skipped++
			continue
		}

		props := formatRelationshipProperties(row["properties"])
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
			SourceType: toString(row["source_type"]),
			TargetID:   targetID,
			TargetType: toString(row["target_type"]),
			RelType:    relType,
			Properties: props,
			SyncTime:   row["sync_time"],
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
	_, err := r.sf.Query(ctx, query, cutoff)
	return err
}

func (r *RelationshipExtractor) persistRelationships(ctx context.Context, rels []Relationship) (int, error) {
	if len(rels) == 0 {
		return 0, nil
	}

	r.logger.Info("persisting relationships", "count", len(rels))

	// Get the schema for fully qualified table name
	schema := r.sf.Schema()
	if schema == "" {
		schema = "RAW"
	}
	if err := snowflake.ValidateTableName(schema); err != nil {
		return 0, fmt.Errorf("invalid schema name: %w", err)
	}
	tableName := fmt.Sprintf("%s.RESOURCE_RELATIONSHIPS", schema)

	// Batch insert using MERGE - process in batches to avoid query size limits
	const batchSize = 100
	total := 0

	for i := 0; i < len(rels); i += batchSize {
		end := i + batchSize
		if end > len(rels) {
			end = len(rels)
		}
		batch := rels[i:end]

		values := make([]string, 0, len(batch))
		args := make([]interface{}, 0, len(batch)*7)
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
			values = append(values, "(?, ?, ?, ?, ?, ?, ?)")
			args = append(args, id, sourceID, rel.SourceType, targetID, rel.TargetType, rel.RelType, props)
		}
		if len(values) == 0 {
			continue
		}

		// Use simple INSERT with fully qualified table name
		query := fmt.Sprintf(`INSERT INTO %s (ID, SOURCE_ID, SOURCE_TYPE, TARGET_ID, TARGET_TYPE, REL_TYPE, PROPERTIES, SYNC_TIME)
			SELECT column1, column2, column3, column4, column5, column6, TRY_PARSE_JSON(column7), CURRENT_TIMESTAMP()
			FROM VALUES %s`,
			tableName, strings.Join(values, ", "))

		// Use Query instead of Exec - Exec has issues with Snowflake commit behavior
		_, err := r.sf.Query(ctx, query, args...)
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
func (r *RelationshipExtractor) extractEC2Relationships(ctx context.Context) (int, error) {
	query := `SELECT ARN, ACCOUNT_ID, REGION, VPC_ID, SUBNET_ID, IAM_INSTANCE_PROFILE, SECURITY_GROUPS 
	          FROM AWS_EC2_INSTANCES WHERE ARN IS NOT NULL`

	result, err := r.sf.Query(ctx, query)
	if err != nil {
		if isMissingRelationshipSourceError(err) {
			return 0, nil
		}
		return 0, err
	}

	var rels []Relationship
	for _, row := range result.Rows {
		instanceARN := toString(row["ARN"])
		if instanceARN == "" {
			continue
		}
		accountID := toString(row["ACCOUNT_ID"])
		region := toString(row["REGION"])

		// VPC relationship
		if vpcID := toString(row["VPC_ID"]); vpcID != "" {
			vpcARN := awsARNForResource("vpc", region, accountID, vpcID)
			rels = append(rels, Relationship{
				SourceID:   instanceARN,
				SourceType: "aws:ec2:instance",
				TargetID:   vpcARN,
				TargetType: "aws:ec2:vpc",
				RelType:    RelInVPC,
			})
		}

		// Subnet relationship
		if subnetID := toString(row["SUBNET_ID"]); subnetID != "" {
			subnetARN := awsARNForResource("subnet", region, accountID, subnetID)
			rels = append(rels, Relationship{
				SourceID:   instanceARN,
				SourceType: "aws:ec2:instance",
				TargetID:   subnetARN,
				TargetType: "aws:ec2:subnet",
				RelType:    RelInSubnet,
			})
		}

		// IAM instance profile relationship
		if profile := row["IAM_INSTANCE_PROFILE"]; profile != nil {
			switch val := profile.(type) {
			case map[string]interface{}:
				if roleARN := toString(val["arn"]); roleARN != "" {
					rels = append(rels, Relationship{
						SourceID:   instanceARN,
						SourceType: "aws:ec2:instance",
						TargetID:   roleARN,
						TargetType: "aws:iam:instance_profile",
						RelType:    RelHasRole,
					})
				} else if roleARN := toString(val["Arn"]); roleARN != "" {
					rels = append(rels, Relationship{
						SourceID:   instanceARN,
						SourceType: "aws:ec2:instance",
						TargetID:   roleARN,
						TargetType: "aws:iam:instance_profile",
						RelType:    RelHasRole,
					})
				}
			case string:
				if val != "" {
					rels = append(rels, Relationship{
						SourceID:   instanceARN,
						SourceType: "aws:ec2:instance",
						TargetID:   val,
						TargetType: "aws:iam:instance_profile",
						RelType:    RelHasRole,
					})
				}
			}
		}

		// Security group relationships
		if sgList := asSlice(row["SECURITY_GROUPS"]); len(sgList) > 0 {
			for _, sg := range sgList {
				if sgMap := asMap(sg); sgMap != nil {
					if sgID := getStringAny(sgMap, "GroupId", "groupId", "group_id"); sgID != "" {
						sgARN := awsARNForResource("security-group", region, accountID, sgID)
						rels = append(rels, Relationship{
							SourceID:   instanceARN,
							SourceType: "aws:ec2:instance",
							TargetID:   sgARN,
							TargetType: "aws:ec2:security_group",
							RelType:    RelMemberOf,
						})
					}
				}
			}
		}
	}

	return r.persistRelationships(ctx, rels)
}

// extractIAMRoleRelationships extracts role trust and policy relationships
func (r *RelationshipExtractor) extractIAMRoleRelationships(ctx context.Context) (int, error) {
	query := `SELECT ARN, ROLE_NAME, ASSUME_ROLE_POLICY_DOCUMENT 
	          FROM AWS_IAM_ROLES WHERE ARN IS NOT NULL`

	result, err := r.sf.Query(ctx, query)
	if err != nil {
		if isMissingRelationshipSourceError(err) {
			return 0, nil
		}
		return 0, err
	}

	var rels []Relationship
	for _, row := range result.Rows {
		roleARN := toString(row["ARN"])
		if roleARN == "" {
			continue
		}

		// Parse trust policy to extract who can assume the role
		if trustPolicy := row["ASSUME_ROLE_POLICY_DOCUMENT"]; trustPolicy != nil {
			policyDoc, err := parsePolicyDocument(trustPolicy)
			if err != nil {
				r.logger.Warn("failed to parse trust policy", "role", roleARN, "error", err)
				continue
			}
			if policyDoc == nil {
				continue
			}
			if statements, ok := policyDoc["Statement"].([]interface{}); ok {
				for _, stmt := range statements {
					if stmtMap, ok := stmt.(map[string]interface{}); ok {
						if effect := toString(stmtMap["Effect"]); effect == "Allow" {
							if principal := stmtMap["Principal"]; principal != nil {
								principals := extractPrincipals(principal)
								for _, p := range principals {
									rels = append(rels, Relationship{
										SourceID:   roleARN,
										SourceType: "aws:iam:role",
										TargetID:   p,
										TargetType: inferPrincipalType(p),
										RelType:    RelAssumableBy,
									})
								}
							}
						}
					}
				}
			}
		}
	}

	return r.persistRelationships(ctx, rels)
}

// extractLambdaRelationships extracts Lambda function relationships
func (r *RelationshipExtractor) extractLambdaRelationships(ctx context.Context) (int, error) {
	query := `SELECT ARN, FUNCTION_NAME, ROLE, VPC_CONFIG 
	          FROM AWS_LAMBDA_FUNCTIONS WHERE ARN IS NOT NULL`

	result, err := r.sf.Query(ctx, query)
	if err != nil {
		if isMissingRelationshipSourceError(err) {
			return 0, nil
		}
		return 0, err
	}

	var rels []Relationship
	for _, row := range result.Rows {
		functionARN := toString(row["ARN"])
		if functionARN == "" {
			continue
		}
		region, accountID := awsRegionAccountFromARN(functionARN)

		// Execution role relationship
		if roleARN := toString(row["ROLE"]); roleARN != "" {
			rels = append(rels, Relationship{
				SourceID:   functionARN,
				SourceType: "aws:lambda:function",
				TargetID:   roleARN,
				TargetType: "aws:iam:role",
				RelType:    RelHasRole,
			})
		}

		// VPC relationships
		if vpcConfig := asMap(row["VPC_CONFIG"]); vpcConfig != nil {
			if vpcID := getStringAny(vpcConfig, "VpcId", "vpcId", "vpc_id"); vpcID != "" {
				vpcARN := awsARNForResource("vpc", region, accountID, vpcID)
				rels = append(rels, Relationship{
					SourceID:   functionARN,
					SourceType: "aws:lambda:function",
					TargetID:   vpcARN,
					TargetType: "aws:ec2:vpc",
					RelType:    RelInVPC,
				})
			}

			// Security groups
			if sgs := asSlice(vpcConfig["SecurityGroupIds"]); len(sgs) > 0 {
				for _, sg := range sgs {
					if sgID := toString(sg); sgID != "" {
						sgARN := awsARNForResource("security-group", region, accountID, sgID)
						rels = append(rels, Relationship{
							SourceID:   functionARN,
							SourceType: "aws:lambda:function",
							TargetID:   sgARN,
							TargetType: "aws:ec2:security_group",
							RelType:    RelMemberOf,
						})
					}
				}
			}
		}
	}

	return r.persistRelationships(ctx, rels)
}

// extractSecurityGroupRelationships extracts ingress/egress rules
func (r *RelationshipExtractor) extractSecurityGroupRelationships(ctx context.Context) (int, error) {
	query := `SELECT ARN, ACCOUNT_ID, REGION, GROUP_ID, VPC_ID, IP_PERMISSIONS, IP_PERMISSIONS_EGRESS 
	          FROM AWS_EC2_SECURITY_GROUPS WHERE ARN IS NOT NULL`

	result, err := r.sf.Query(ctx, query)
	if err != nil {
		if isMissingRelationshipSourceError(err) {
			return 0, nil
		}
		return 0, err
	}

	var rels []Relationship
	for _, row := range result.Rows {
		sgARN := toString(row["ARN"])
		if sgARN == "" {
			continue
		}
		accountID := toString(row["ACCOUNT_ID"])
		region := toString(row["REGION"])

		// VPC relationship
		if vpcID := toString(row["VPC_ID"]); vpcID != "" {
			vpcARN := awsARNForResource("vpc", region, accountID, vpcID)
			rels = append(rels, Relationship{
				SourceID:   sgARN,
				SourceType: "aws:ec2:security_group",
				TargetID:   vpcARN,
				TargetType: "aws:ec2:vpc",
				RelType:    RelBelongsTo,
			})
		}

		// Check for internet exposure (0.0.0.0/0 ingress)
		if permList := asSlice(row["IP_PERMISSIONS"]); len(permList) > 0 {
			for _, perm := range permList {
				permMap := asMap(perm)
				if permMap == nil {
					continue
				}
				if ranges := asSlice(permMap["IpRanges"]); len(ranges) > 0 {
					for _, r := range ranges {
						rMap := asMap(r)
						if rMap == nil {
							continue
						}
						cidr := toString(rMap["CidrIp"])
						if cidr == "0.0.0.0/0" || cidr == "::/0" {
							props, _ := encodeProperties(map[string]interface{}{
								"from_port": permMap["FromPort"],
								"to_port":   permMap["ToPort"],
								"protocol":  permMap["IpProtocol"],
								"cidr":      cidr,
							})
							rels = append(rels, Relationship{
								SourceID:   sgARN,
								SourceType: "aws:ec2:security_group",
								TargetID:   "internet",
								TargetType: "network:internet",
								RelType:    RelExposedTo,
								Properties: props,
							})
						}
					}
				}
			}
		}
	}

	return r.persistRelationships(ctx, rels)
}

// extractS3Relationships extracts S3 bucket relationships
func (r *RelationshipExtractor) extractS3Relationships(ctx context.Context) (int, error) {
	query := `SELECT ARN, NAME, ENCRYPTION, LOGGING_TARGET_BUCKET
	          FROM AWS_S3_BUCKETS WHERE ARN IS NOT NULL`

	result, err := r.sf.Query(ctx, query)
	if err != nil {
		if isMissingRelationshipSourceError(err) {
			return 0, nil
		}
		return 0, err
	}

	var rels []Relationship
	for _, row := range result.Rows {
		bucketARN := toString(row["ARN"])
		if bucketARN == "" {
			continue
		}

		// KMS encryption relationship - extract from ENCRYPTION column
		if enc := row["ENCRYPTION"]; enc != nil {
			encStr := toString(enc)
			// Check if KMS encryption is configured
			if strings.Contains(encStr, "aws:kms") || strings.Contains(encStr, "KMS") {
				// Try to parse as JSON to extract KMS key ARN
				var encMap map[string]interface{}
				if err := json.Unmarshal([]byte(encStr), &encMap); err == nil {
					if kmsKeyID := toString(encMap["KMSMasterKeyID"]); kmsKeyID != "" {
						rels = append(rels, Relationship{
							SourceID:   bucketARN,
							SourceType: "aws:s3:bucket",
							TargetID:   kmsKeyID,
							TargetType: "aws:kms:key",
							RelType:    RelEncryptedBy,
						})
					}
				}
			}
		}

		// Logging relationship
		if targetBucket := toString(row["LOGGING_TARGET_BUCKET"]); targetBucket != "" {
			rels = append(rels, Relationship{
				SourceID:   bucketARN,
				SourceType: "aws:s3:bucket",
				TargetID:   fmt.Sprintf("arn:aws:s3:::%s", targetBucket),
				TargetType: "aws:s3:bucket",
				RelType:    RelLogsTo,
			})
		}
	}

	return r.persistRelationships(ctx, rels)
}

// extractECSRelationships extracts ECS service/task relationships
func (r *RelationshipExtractor) extractECSRelationships(ctx context.Context) (int, error) {
	query := `SELECT ARN, CLUSTER_ARN, TASK_DEFINITION, NETWORK_CONFIGURATION
	          FROM AWS_ECS_SERVICES WHERE ARN IS NOT NULL`

	result, err := r.sf.Query(ctx, query)
	if err != nil {
		if isMissingRelationshipSourceError(err) {
			return 0, nil
		}
		return 0, err
	}

	var rels []Relationship
	for _, row := range result.Rows {
		serviceARN := toString(row["ARN"])

		// Cluster relationship
		if clusterARN := toString(row["CLUSTER_ARN"]); clusterARN != "" {
			rels = append(rels, Relationship{
				SourceID:   serviceARN,
				SourceType: "aws:ecs:service",
				TargetID:   clusterARN,
				TargetType: "aws:ecs:cluster",
				RelType:    RelBelongsTo,
			})
		}

		// Task definition relationship
		if taskDef := toString(row["TASK_DEFINITION"]); taskDef != "" {
			rels = append(rels, Relationship{
				SourceID:   serviceARN,
				SourceType: "aws:ecs:service",
				TargetID:   taskDef,
				TargetType: "aws:ecs:task_definition",
				RelType:    RelManagedBy,
			})
		}
	}

	return r.persistRelationships(ctx, rels)
}

// extractGCPRelationships extracts GCP resource relationships
func (r *RelationshipExtractor) extractGCPRelationships(ctx context.Context) (int, error) {
	var rels []Relationship

	// GCP Compute instances
	query := `SELECT ID, PROJECT_ID, NETWORK_INTERFACES, SERVICE_ACCOUNTS
	          FROM GCP_COMPUTE_INSTANCES WHERE ID IS NOT NULL`

	result, err := r.sf.Query(ctx, query)
	if err == nil {
		for _, row := range result.Rows {
			instanceID := toString(row["ID"])
			projectID := toString(row["PROJECT_ID"])

			// Service account relationships
			if saList := asSlice(row["SERVICE_ACCOUNTS"]); len(saList) > 0 {
				for _, sa := range saList {
					if saMap := asMap(sa); saMap != nil {
						if email := getStringAny(saMap, "email", "Email"); email != "" {
							rels = append(rels, Relationship{
								SourceID:   instanceID,
								SourceType: "gcp:compute:instance",
								TargetID:   fmt.Sprintf("projects/%s/serviceAccounts/%s", projectID, email),
								TargetType: "gcp:iam:service_account",
								RelType:    RelHasRole,
							})
						}
					}
				}
			}

			// Network relationships
			if nicList := asSlice(row["NETWORK_INTERFACES"]); len(nicList) > 0 {
				for _, nic := range nicList {
					if nicMap := asMap(nic); nicMap != nil {
						if network := toString(nicMap["network"]); network != "" {
							rels = append(rels, Relationship{
								SourceID:   instanceID,
								SourceType: "gcp:compute:instance",
								TargetID:   network,
								TargetType: "gcp:compute:network",
								RelType:    RelInVPC,
							})
						}
						if subnetwork := toString(nicMap["subnetwork"]); subnetwork != "" {
							rels = append(rels, Relationship{
								SourceID:   instanceID,
								SourceType: "gcp:compute:instance",
								TargetID:   subnetwork,
								TargetType: "gcp:compute:subnetwork",
								RelType:    RelInSubnet,
							})
						}
					}
				}
			}
		}
	}

	// GCP Cloud Functions - service account is in SERVICE_CONFIG
	query = `SELECT NAME, PROJECT_ID, SERVICE_CONFIG
	         FROM GCP_CLOUDFUNCTIONS_FUNCTIONS WHERE NAME IS NOT NULL`

	result, err = r.sf.Query(ctx, query)
	if err == nil {
		for _, row := range result.Rows {
			funcName := toString(row["NAME"])
			projectID := toString(row["PROJECT_ID"])

			// Extract service account from SERVICE_CONFIG
			if svcConfig := row["SERVICE_CONFIG"]; svcConfig != nil {
				var configMap map[string]interface{}
				configStr := toString(svcConfig)
				if unmarshalErr := json.Unmarshal([]byte(configStr), &configMap); unmarshalErr == nil {
					if saEmail := toString(configMap["service_account_email"]); saEmail != "" {
						targetID := saEmail
						if projectID != "" {
							targetID = fmt.Sprintf("projects/%s/serviceAccounts/%s", projectID, saEmail)
						}
						rels = append(rels, Relationship{
							SourceID:   funcName,
							SourceType: "gcp:cloudfunctions:function",
							TargetID:   targetID,
							TargetType: "gcp:iam:service_account",
							RelType:    RelHasRole,
						})
					}
				}
			}
		}
	}

	// GCP Cloud Run Services - extract service account from TEMPLATE
	query = `SELECT NAME, PROJECT_ID, TEMPLATE, INGRESS, URI
	         FROM GCP_CLOUDRUN_SERVICES WHERE NAME IS NOT NULL`

	result, err = r.sf.Query(ctx, query)
	if err == nil {
		for _, row := range result.Rows {
			svcName := toString(row["NAME"])
			projectID := toString(row["PROJECT_ID"])
			ingress := toString(row["INGRESS"])
			uri := toString(row["URI"])

			// Extract service account from TEMPLATE
			if template := row["TEMPLATE"]; template != nil {
				var templateMap map[string]interface{}
				templateStr := toString(template)
				if unmarshalErr := json.Unmarshal([]byte(templateStr), &templateMap); unmarshalErr == nil {
					if saEmail := toString(templateMap["service_account"]); saEmail != "" {
						targetID := saEmail
						if projectID != "" && !strings.Contains(saEmail, "/") {
							targetID = fmt.Sprintf("projects/%s/serviceAccounts/%s", projectID, saEmail)
						}
						rels = append(rels, Relationship{
							SourceID:   svcName,
							SourceType: "gcp:cloudrun:service",
							TargetID:   targetID,
							TargetType: "gcp:iam:service_account",
							RelType:    RelHasRole,
						})

						// If using default compute SA, flag as high-risk relationship
						if strings.Contains(saEmail, "compute@developer.gserviceaccount.com") {
							props, _ := json.Marshal(map[string]interface{}{
								"risk": "default_compute_sa",
								"note": "Using default compute service account with broad permissions",
							})
							rels = append(rels, Relationship{
								SourceID:   svcName,
								SourceType: "gcp:cloudrun:service",
								TargetID:   targetID,
								TargetType: "gcp:iam:service_account",
								RelType:    "USES_DEFAULT_SA",
								Properties: string(props),
							})
						}
					}
				}
			}

			// If publicly accessible, create exposure relationship
			if ingress == "INGRESS_TRAFFIC_ALL" && uri != "" {
				props, _ := json.Marshal(map[string]interface{}{
					"exposure_level": "high",
					"uri":            uri,
				})
				rels = append(rels, Relationship{
					SourceID:   svcName,
					SourceType: "gcp:cloudrun:service",
					TargetID:   "internet",
					TargetType: "network:internet",
					RelType:    RelExposedTo,
					Properties: string(props),
				})
			}
		}
	}

	// GCP Cloud Run Revisions - extract service account directly
	query = `SELECT NAME, PROJECT_ID, SERVICE, SERVICE_ACCOUNT, CONTAINERS
	         FROM GCP_CLOUDRUN_REVISIONS WHERE NAME IS NOT NULL`

	result, err = r.sf.Query(ctx, query)
	if err == nil {
		for _, row := range result.Rows {
			revName := toString(row["NAME"])
			projectID := toString(row["PROJECT_ID"])
			serviceName := toString(row["SERVICE"])
			saEmail := toString(row["SERVICE_ACCOUNT"])

			// Revision -> Service relationship
			if serviceName != "" {
				rels = append(rels, Relationship{
					SourceID:   revName,
					SourceType: "gcp:cloudrun:revision",
					TargetID:   serviceName,
					TargetType: "gcp:cloudrun:service",
					RelType:    RelBelongsTo,
				})
			}

			// Revision -> Service Account relationship
			if saEmail != "" {
				targetID := saEmail
				if projectID != "" && !strings.Contains(saEmail, "/") {
					targetID = fmt.Sprintf("projects/%s/serviceAccounts/%s", projectID, saEmail)
				}
				rels = append(rels, Relationship{
					SourceID:   revName,
					SourceType: "gcp:cloudrun:revision",
					TargetID:   targetID,
					TargetType: "gcp:iam:service_account",
					RelType:    RelHasRole,
				})

				// Flag default compute SA usage
				if strings.Contains(saEmail, "compute@developer.gserviceaccount.com") {
					props, _ := json.Marshal(map[string]interface{}{
						"risk": "default_compute_sa",
						"note": "Revision uses default compute service account",
					})
					rels = append(rels, Relationship{
						SourceID:   revName,
						SourceType: "gcp:cloudrun:revision",
						TargetID:   targetID,
						TargetType: "gcp:iam:service_account",
						RelType:    "USES_DEFAULT_SA",
						Properties: string(props),
					})
				}
			}

			// Extract container image relationships
			if containers := row["CONTAINERS"]; containers != nil {
				var containerList []map[string]interface{}
				containerStr := toString(containers)
				if err := json.Unmarshal([]byte(containerStr), &containerList); err == nil {
					for _, container := range containerList {
						if image := toString(container["image"]); image != "" {
							rels = append(rels, Relationship{
								SourceID:   revName,
								SourceType: "gcp:cloudrun:revision",
								TargetID:   image,
								TargetType: "container:image",
								RelType:    "RUNS_IMAGE",
							})
						}
					}
				}
			}
		}
	}

	// GCP Storage buckets - encryption and logging relationships
	query = `SELECT NAME, LOGGING_LOG_BUCKET, ENCRYPTION_DEFAULT_KMS_KEY
	         FROM GCP_STORAGE_BUCKETS WHERE NAME IS NOT NULL`

	result, err = r.sf.Query(ctx, query)
	if err == nil {
		for _, row := range result.Rows {
			bucketName := toString(row["NAME"])
			if bucketName == "" {
				continue
			}
			bucketID := fmt.Sprintf("projects/_/buckets/%s", bucketName)

			if kmsKey := toString(row["ENCRYPTION_DEFAULT_KMS_KEY"]); kmsKey != "" {
				rels = append(rels, Relationship{
					SourceID:   bucketID,
					SourceType: "gcp:storage:bucket",
					TargetID:   kmsKey,
					TargetType: "gcp:kms:key",
					RelType:    RelEncryptedBy,
				})
			}

			if logBucket := toString(row["LOGGING_LOG_BUCKET"]); logBucket != "" {
				rels = append(rels, Relationship{
					SourceID:   bucketID,
					SourceType: "gcp:storage:bucket",
					TargetID:   fmt.Sprintf("projects/_/buckets/%s", logBucket),
					TargetType: "gcp:storage:bucket",
					RelType:    RelLogsTo,
				})
			}
		}
	}

	// GCP SQL instances - service account, network, and encryption relationships
	query = `SELECT NAME, PROJECT_ID, SELF_LINK, SERVICE_ACCOUNT_EMAIL_ADDRESS, SETTINGS, DISK_ENCRYPTION_CONFIGURATION
	         FROM GCP_SQL_INSTANCES WHERE NAME IS NOT NULL`

	result, err = r.sf.Query(ctx, query)
	if err == nil {
		for _, row := range result.Rows {
			instanceID := toString(row["SELF_LINK"])
			name := toString(row["NAME"])
			projectID := toString(row["PROJECT_ID"])
			if instanceID == "" && projectID != "" && name != "" {
				instanceID = fmt.Sprintf("projects/%s/instances/%s", projectID, name)
			}
			if instanceID == "" {
				continue
			}

			if saEmail := toString(row["SERVICE_ACCOUNT_EMAIL_ADDRESS"]); saEmail != "" {
				targetID := saEmail
				if projectID != "" && !strings.Contains(saEmail, "/") {
					targetID = fmt.Sprintf("projects/%s/serviceAccounts/%s", projectID, saEmail)
				}
				rels = append(rels, Relationship{
					SourceID:   instanceID,
					SourceType: "gcp:sql:instance",
					TargetID:   targetID,
					TargetType: "gcp:iam:service_account",
					RelType:    RelHasRole,
				})
			}

			if settings := asMap(row["SETTINGS"]); settings != nil {
				if privateNetwork := getStringAny(settings, "private_network", "privateNetwork"); privateNetwork != "" {
					rels = append(rels, Relationship{
						SourceID:   instanceID,
						SourceType: "gcp:sql:instance",
						TargetID:   privateNetwork,
						TargetType: "gcp:compute:network",
						RelType:    RelInVPC,
					})
				}
			}

			if encConfig := asMap(row["DISK_ENCRYPTION_CONFIGURATION"]); encConfig != nil {
				if kmsKey := getStringAny(encConfig, "kms_key_name", "kmsKeyName"); kmsKey != "" {
					rels = append(rels, Relationship{
						SourceID:   instanceID,
						SourceType: "gcp:sql:instance",
						TargetID:   kmsKey,
						TargetType: "gcp:kms:key",
						RelType:    RelEncryptedBy,
					})
				}
			}
		}
	}

	return r.persistRelationships(ctx, rels)
}

// extractAzureRelationships extracts Azure resource relationships.
func (r *RelationshipExtractor) extractAzureRelationships(ctx context.Context) (int, error) {
	var rels []Relationship

	query := `SELECT ID, NETWORK_INTERFACES, AVAILABILITY_SET, OS_DISK, DATA_DISKS
	          FROM AZURE_COMPUTE_VIRTUAL_MACHINES WHERE ID IS NOT NULL`

	result, err := r.sf.Query(ctx, query)
	if err != nil {
		if !isMissingRelationshipSourceError(err) {
			return 0, err
		}
	} else {
		for _, row := range result.Rows {
			vmID := toString(row["ID"])
			if vmID == "" {
				continue
			}

			if nicList := asSlice(row["NETWORK_INTERFACES"]); len(nicList) > 0 {
				for _, nic := range nicList {
					if nicID := extractReferenceID(nic); nicID != "" {
						rels = append(rels, Relationship{
							SourceID:   vmID,
							SourceType: "azure:compute:virtual_machine",
							TargetID:   nicID,
							TargetType: "azure:network:interface",
							RelType:    RelAttachedTo,
						})
					}
				}
			}

			if availabilitySetID := normalizeRelationshipID(toString(row["AVAILABILITY_SET"])); availabilitySetID != "" {
				rels = append(rels, Relationship{
					SourceID:   vmID,
					SourceType: "azure:compute:virtual_machine",
					TargetID:   availabilitySetID,
					TargetType: "azure:compute:availability_set",
					RelType:    RelBelongsTo,
				})
			}

			if osDiskID := extractManagedDiskID(row["OS_DISK"]); osDiskID != "" {
				rels = append(rels, Relationship{
					SourceID:   vmID,
					SourceType: "azure:compute:virtual_machine",
					TargetID:   osDiskID,
					TargetType: "azure:compute:disk",
					RelType:    RelAttachedTo,
				})
			}

			if dataDisks := asSlice(row["DATA_DISKS"]); len(dataDisks) > 0 {
				for _, disk := range dataDisks {
					if diskID := extractManagedDiskID(disk); diskID != "" {
						rels = append(rels, Relationship{
							SourceID:   vmID,
							SourceType: "azure:compute:virtual_machine",
							TargetID:   diskID,
							TargetType: "azure:compute:disk",
							RelType:    RelAttachedTo,
						})
					}
				}
			}
		}
	}

	query = `SELECT ID, NETWORK_SECURITY_GROUP, VIRTUAL_MACHINE, IP_CONFIGURATIONS
	         FROM AZURE_NETWORK_INTERFACES WHERE ID IS NOT NULL`
	result, err = r.sf.Query(ctx, query)
	if err != nil {
		if !isMissingRelationshipSourceError(err) {
			return 0, err
		}
	} else {
		for _, row := range result.Rows {
			nicID := toString(row["ID"])
			if nicID == "" {
				continue
			}

			if vmID := normalizeRelationshipID(toString(row["VIRTUAL_MACHINE"])); vmID != "" {
				rels = append(rels, Relationship{
					SourceID:   nicID,
					SourceType: "azure:network:interface",
					TargetID:   vmID,
					TargetType: "azure:compute:virtual_machine",
					RelType:    RelAttachedTo,
				})
			}

			if nsgID := normalizeRelationshipID(toString(row["NETWORK_SECURITY_GROUP"])); nsgID != "" {
				rels = append(rels, Relationship{
					SourceID:   nicID,
					SourceType: "azure:network:interface",
					TargetID:   nsgID,
					TargetType: "azure:network:security_group",
					RelType:    RelMemberOf,
				})
			}

			if ipConfigs := asSlice(row["IP_CONFIGURATIONS"]); len(ipConfigs) > 0 {
				for _, ipCfg := range ipConfigs {
					if subnetID := extractSubnetReferenceID(ipCfg); subnetID != "" {
						rels = append(rels, Relationship{
							SourceID:   nicID,
							SourceType: "azure:network:interface",
							TargetID:   subnetID,
							TargetType: "azure:network:subnet",
							RelType:    RelInSubnet,
						})
					}
				}
			}
		}
	}

	query = `SELECT ID, MANAGED_BY FROM AZURE_COMPUTE_DISKS WHERE ID IS NOT NULL`
	result, err = r.sf.Query(ctx, query)
	if err != nil {
		if !isMissingRelationshipSourceError(err) {
			return 0, err
		}
	} else {
		for _, row := range result.Rows {
			diskID := toString(row["ID"])
			if diskID == "" {
				continue
			}
			if managedBy := normalizeRelationshipID(toString(row["MANAGED_BY"])); managedBy != "" {
				rels = append(rels, Relationship{
					SourceID:   diskID,
					SourceType: "azure:compute:disk",
					TargetID:   managedBy,
					TargetType: "azure:compute:virtual_machine",
					RelType:    RelAttachedTo,
				})
			}
		}
	}

	query = `SELECT ID, SERVER_NAME, RESOURCE_GROUP, SUBSCRIPTION_ID
	         FROM AZURE_SQL_DATABASES WHERE ID IS NOT NULL`
	result, err = r.sf.Query(ctx, query)
	if err != nil {
		if !isMissingRelationshipSourceError(err) {
			return 0, err
		}
	} else {
		for _, row := range result.Rows {
			dbID := toString(row["ID"])
			if dbID == "" {
				continue
			}

			serverName := toString(row["SERVER_NAME"])
			if serverName == "" {
				serverName = azureIDSegment(dbID, "servers")
			}
			serverID := azureSQLServerID(toString(row["SUBSCRIPTION_ID"]), toString(row["RESOURCE_GROUP"]), serverName)
			if serverID == "" {
				continue
			}

			rels = append(rels, Relationship{
				SourceID:   dbID,
				SourceType: "azure:sql:database",
				TargetID:   serverID,
				TargetType: "azure:sql:server",
				RelType:    RelBelongsTo,
			})
		}
	}

	query = `SELECT ID, ACCOUNT_NAME, RESOURCE_GROUP, SUBSCRIPTION_ID
	         FROM AZURE_STORAGE_CONTAINERS WHERE ID IS NOT NULL`
	result, err = r.sf.Query(ctx, query)
	if err != nil {
		if !isMissingRelationshipSourceError(err) {
			return 0, err
		}
	} else {
		for _, row := range result.Rows {
			containerID := toString(row["ID"])
			if containerID == "" {
				continue
			}

			accountID := azureStorageAccountID(toString(row["SUBSCRIPTION_ID"]), toString(row["RESOURCE_GROUP"]), toString(row["ACCOUNT_NAME"]))
			if accountID == "" {
				continue
			}

			rels = append(rels, Relationship{
				SourceID:   containerID,
				SourceType: "azure:storage:container",
				TargetID:   accountID,
				TargetType: "azure:storage:account",
				RelType:    RelBelongsTo,
			})
		}
	}

	query = `SELECT ID, ACCOUNT_NAME, CONTAINER_NAME, RESOURCE_GROUP, SUBSCRIPTION_ID
	         FROM AZURE_STORAGE_BLOBS WHERE ID IS NOT NULL`
	result, err = r.sf.Query(ctx, query)
	if err != nil {
		if !isMissingRelationshipSourceError(err) {
			return 0, err
		}
	} else {
		for _, row := range result.Rows {
			blobID := toString(row["ID"])
			if blobID == "" {
				continue
			}

			containerID := azureStorageContainerID(
				toString(row["SUBSCRIPTION_ID"]),
				toString(row["RESOURCE_GROUP"]),
				toString(row["ACCOUNT_NAME"]),
				toString(row["CONTAINER_NAME"]),
			)
			if containerID == "" {
				continue
			}

			rels = append(rels, Relationship{
				SourceID:   blobID,
				SourceType: "azure:storage:blob",
				TargetID:   containerID,
				TargetType: "azure:storage:container",
				RelType:    RelBelongsTo,
			})
		}
	}

	vaultByURI := make(map[string]string)
	query = `SELECT ID, VAULT_URI FROM AZURE_KEYVAULT_VAULTS WHERE ID IS NOT NULL`
	result, err = r.sf.Query(ctx, query)
	if err != nil {
		if !isMissingRelationshipSourceError(err) {
			return 0, err
		}
	} else {
		for _, row := range result.Rows {
			vaultID := toString(row["ID"])
			vaultURI := normalizeVaultURI(toString(row["VAULT_URI"]))
			if vaultID != "" && vaultURI != "" {
				vaultByURI[vaultURI] = vaultID
			}
		}
	}

	query = `SELECT ID, VAULT_URI FROM AZURE_KEYVAULT_KEYS WHERE ID IS NOT NULL`
	result, err = r.sf.Query(ctx, query)
	if err != nil {
		if !isMissingRelationshipSourceError(err) {
			return 0, err
		}
	} else {
		for _, row := range result.Rows {
			keyID := toString(row["ID"])
			if keyID == "" {
				continue
			}
			vaultURI := normalizeVaultURI(toString(row["VAULT_URI"]))
			if vaultURI == "" {
				continue
			}
			targetID := vaultByURI[vaultURI]
			if targetID == "" {
				targetID = vaultURI
			}

			rels = append(rels, Relationship{
				SourceID:   keyID,
				SourceType: "azure:keyvault:key",
				TargetID:   targetID,
				TargetType: "azure:keyvault:vault",
				RelType:    RelBelongsTo,
			})
		}
	}

	return r.persistRelationships(ctx, rels)
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

func awsARNForResource(resource string, region, accountID, id string) string {
	if region == "" || accountID == "" || id == "" {
		return id
	}
	return fmt.Sprintf("arn:aws:ec2:%s:%s:%s/%s", region, accountID, resource, id)
}

func awsRegionAccountFromARN(arn string) (string, string) {
	parts := strings.Split(arn, ":")
	if len(parts) < 6 {
		return "", ""
	}
	return parts[3], parts[4]
}
