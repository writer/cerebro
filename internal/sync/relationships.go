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

func (r *RelationshipExtractor) ensureTable(ctx context.Context) error {
	// Use fully qualified table name to ensure we're in the right schema
	schema := r.sf.Schema()
	if schema == "" {
		schema = "RAW"
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
	// Use Query instead of Exec with embedded timestamp to ensure proper execution
	// Format time as Snowflake timestamp literal
	cutoffStr := cutoff.Format("2006-01-02 15:04:05.000 -0700")
	query := fmt.Sprintf(`DELETE FROM %s.RESOURCE_RELATIONSHIPS WHERE SYNC_TIME < '%s'`, schema, cutoffStr)
	_, err := r.sf.Query(ctx, query)
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
		for _, rel := range batch {
			props := rel.Properties
			if props == "" {
				props = "{}"
			}
			id := buildRelationshipID(rel.SourceID, rel.RelType, rel.TargetID, props)
			values = append(values, fmt.Sprintf("('%s', '%s', '%s', '%s', '%s', '%s', '%s')",
				escapeSQL(id),
				escapeSQL(rel.SourceID),
				escapeSQL(rel.SourceType),
				escapeSQL(rel.TargetID),
				escapeSQL(rel.TargetType),
				escapeSQL(rel.RelType),
				escapeSQL(props),
			))
		}

		// Use simple INSERT with fully qualified table name
		query := fmt.Sprintf(`INSERT INTO %s (ID, SOURCE_ID, SOURCE_TYPE, TARGET_ID, TARGET_TYPE, REL_TYPE, PROPERTIES, SYNC_TIME)
			SELECT column1, column2, column3, column4, column5, column6, TRY_PARSE_JSON(column7), CURRENT_TIMESTAMP()
			FROM VALUES %s`,
			tableName, strings.Join(values, ", "))

		// Use Query instead of Exec - Exec has issues with Snowflake commit behavior
		_, err := r.sf.Query(ctx, query)
		if err != nil {
			r.logger.Error("failed to persist relationships batch", "error", err, "batch_start", i, "batch_size", len(batch))
			return total, err
		}
		total += len(batch)
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
				if err := json.Unmarshal([]byte(configStr), &configMap); err == nil {
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
				if err := json.Unmarshal([]byte(templateStr), &templateMap); err == nil {
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

func escapeSQL(s string) string {
	return strings.ReplaceAll(s, "'", "''")
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
