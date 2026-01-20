package sync

import (
	"context"
	"fmt"
	"log/slog"
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
	RelHasRole         = "HAS_ROLE"
	RelMemberOf        = "MEMBER_OF"
	RelAttachedTo      = "ATTACHED_TO"
	RelBelongsTo       = "BELONGS_TO"
	RelCanAccess       = "CAN_ACCESS"
	RelExposedTo       = "EXPOSED_TO"
	RelTrustedBy       = "TRUSTED_BY"
	RelContains        = "CONTAINS"
	RelProtects        = "PROTECTS"
	RelEncryptedBy     = "ENCRYPTED_BY"
	RelManagedBy       = "MANAGED_BY"
	RelLogsTo          = "LOGS_TO"
	RelReadsFrom       = "READS_FROM"
	RelWritesTo        = "WRITES_TO"
	RelInvokes         = "INVOKES"
	RelRoutes          = "ROUTES"
	RelInSubnet        = "IN_SUBNET"
	RelInVPC           = "IN_VPC"
	RelAssumableBy     = "ASSUMABLE_BY"
	RelHasPermission   = "HAS_PERMISSION"
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

	var totalRels int

	// Extract from EC2 instances
	count, err := r.extractEC2Relationships(ctx)
	if err != nil {
		r.logger.Warn("failed to extract EC2 relationships", "error", err)
	}
	totalRels += count

	// Extract from IAM roles
	count, err = r.extractIAMRoleRelationships(ctx)
	if err != nil {
		r.logger.Warn("failed to extract IAM role relationships", "error", err)
	}
	totalRels += count

	// Extract from Lambda functions
	count, err = r.extractLambdaRelationships(ctx)
	if err != nil {
		r.logger.Warn("failed to extract Lambda relationships", "error", err)
	}
	totalRels += count

	// Extract from Security Groups
	count, err = r.extractSecurityGroupRelationships(ctx)
	if err != nil {
		r.logger.Warn("failed to extract Security Group relationships", "error", err)
	}
	totalRels += count

	// Extract from S3 buckets
	count, err = r.extractS3Relationships(ctx)
	if err != nil {
		r.logger.Warn("failed to extract S3 relationships", "error", err)
	}
	totalRels += count

	// Extract from ECS
	count, err = r.extractECSRelationships(ctx)
	if err != nil {
		r.logger.Warn("failed to extract ECS relationships", "error", err)
	}
	totalRels += count

	// Extract GCP relationships
	count, err = r.extractGCPRelationships(ctx)
	if err != nil {
		r.logger.Warn("failed to extract GCP relationships", "error", err)
	}
	totalRels += count

	r.logger.Info("relationship extraction complete", "total", totalRels)
	return totalRels, nil
}

func (r *RelationshipExtractor) ensureTable(ctx context.Context) error {
	query := `CREATE TABLE IF NOT EXISTS RESOURCE_RELATIONSHIPS (
		ID VARCHAR PRIMARY KEY,
		SOURCE_ID VARCHAR NOT NULL,
		SOURCE_TYPE VARCHAR NOT NULL,
		TARGET_ID VARCHAR NOT NULL,
		TARGET_TYPE VARCHAR NOT NULL,
		REL_TYPE VARCHAR NOT NULL,
		PROPERTIES VARIANT,
		SYNC_TIME TIMESTAMP_TZ DEFAULT CURRENT_TIMESTAMP()
	)`
	_, err := r.sf.Exec(ctx, query)
	return err
}

func (r *RelationshipExtractor) persistRelationships(ctx context.Context, rels []Relationship) (int, error) {
	if len(rels) == 0 {
		return 0, nil
	}

	// Batch insert using MERGE
	values := make([]string, 0, len(rels))
	for _, rel := range rels {
		id := fmt.Sprintf("%s|%s|%s", rel.SourceID, rel.RelType, rel.TargetID)
		props := rel.Properties
		if props == "" {
			props = "{}"
		}
		values = append(values, fmt.Sprintf("('%s', '%s', '%s', '%s', '%s', '%s', PARSE_JSON('%s'))",
			escape(id),
			escape(rel.SourceID),
			escape(rel.SourceType),
			escape(rel.TargetID),
			escape(rel.TargetType),
			escape(rel.RelType),
			escape(props),
		))
	}

	query := fmt.Sprintf(`MERGE INTO RESOURCE_RELATIONSHIPS AS target
		USING (SELECT $1 AS ID, $2 AS SOURCE_ID, $3 AS SOURCE_TYPE, $4 AS TARGET_ID, 
		              $5 AS TARGET_TYPE, $6 AS REL_TYPE, $7 AS PROPERTIES
		       FROM VALUES %s) AS source
		ON target.ID = source.ID
		WHEN MATCHED THEN UPDATE SET 
			PROPERTIES = source.PROPERTIES,
			SYNC_TIME = CURRENT_TIMESTAMP()
		WHEN NOT MATCHED THEN INSERT (ID, SOURCE_ID, SOURCE_TYPE, TARGET_ID, TARGET_TYPE, REL_TYPE, PROPERTIES)
			VALUES (source.ID, source.SOURCE_ID, source.SOURCE_TYPE, source.TARGET_ID, 
			        source.TARGET_TYPE, source.REL_TYPE, source.PROPERTIES)`,
		strings.Join(values, ", "))

	_, err := r.sf.Exec(ctx, query)
	if err != nil {
		return 0, err
	}
	return len(rels), nil
}

// extractEC2Relationships extracts relationships from EC2 instances
func (r *RelationshipExtractor) extractEC2Relationships(ctx context.Context) (int, error) {
	query := `SELECT ARN, VPC_ID, SUBNET_ID, IAM_INSTANCE_PROFILE, SECURITY_GROUPS 
	          FROM AWS_EC2_INSTANCES WHERE ARN IS NOT NULL`
	
	result, err := r.sf.Query(ctx, query)
	if err != nil {
		return 0, err
	}

	var rels []Relationship
	for _, row := range result.Rows {
		instanceARN := toString(row["ARN"])
		
		// VPC relationship
		if vpcID := toString(row["VPC_ID"]); vpcID != "" {
			rels = append(rels, Relationship{
				SourceID:   instanceARN,
				SourceType: "aws:ec2:instance",
				TargetID:   vpcID,
				TargetType: "aws:ec2:vpc",
				RelType:    RelInVPC,
			})
		}

		// Subnet relationship
		if subnetID := toString(row["SUBNET_ID"]); subnetID != "" {
			rels = append(rels, Relationship{
				SourceID:   instanceARN,
				SourceType: "aws:ec2:instance",
				TargetID:   subnetID,
				TargetType: "aws:ec2:subnet",
				RelType:    RelInSubnet,
			})
		}

		// IAM role relationship
		if profile := row["IAM_INSTANCE_PROFILE"]; profile != nil {
			if profileMap, ok := profile.(map[string]interface{}); ok {
				if roleARN := toString(profileMap["arn"]); roleARN != "" {
					rels = append(rels, Relationship{
						SourceID:   instanceARN,
						SourceType: "aws:ec2:instance",
						TargetID:   roleARN,
						TargetType: "aws:iam:instance_profile",
						RelType:    RelHasRole,
					})
				}
			}
		}

		// Security group relationships
		if sgs := row["SECURITY_GROUPS"]; sgs != nil {
			if sgList, ok := sgs.([]interface{}); ok {
				for _, sg := range sgList {
					if sgMap, ok := sg.(map[string]interface{}); ok {
						if sgID := toString(sgMap["GroupId"]); sgID != "" {
							rels = append(rels, Relationship{
								SourceID:   instanceARN,
								SourceType: "aws:ec2:instance",
								TargetID:   sgID,
								TargetType: "aws:ec2:security_group",
								RelType:    RelMemberOf,
							})
						}
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
		
		// Parse trust policy to extract who can assume the role
		if trustPolicy := row["ASSUME_ROLE_POLICY_DOCUMENT"]; trustPolicy != nil {
			// Trust policy is already parsed as JSON by Snowflake
			if policyDoc, ok := trustPolicy.(map[string]interface{}); ok {
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
		if vpcConfig := row["VPC_CONFIG"]; vpcConfig != nil {
			if vpcMap, ok := vpcConfig.(map[string]interface{}); ok {
				if vpcID := toString(vpcMap["VpcId"]); vpcID != "" {
					rels = append(rels, Relationship{
						SourceID:   functionARN,
						SourceType: "aws:lambda:function",
						TargetID:   vpcID,
						TargetType: "aws:ec2:vpc",
						RelType:    RelInVPC,
					})
				}
				
				// Security groups
				if sgs, ok := vpcMap["SecurityGroupIds"].([]interface{}); ok {
					for _, sg := range sgs {
						if sgID := toString(sg); sgID != "" {
							rels = append(rels, Relationship{
								SourceID:   functionARN,
								SourceType: "aws:lambda:function",
								TargetID:   sgID,
								TargetType: "aws:ec2:security_group",
								RelType:    RelMemberOf,
							})
						}
					}
				}
			}
		}
	}

	return r.persistRelationships(ctx, rels)
}

// extractSecurityGroupRelationships extracts ingress/egress rules
func (r *RelationshipExtractor) extractSecurityGroupRelationships(ctx context.Context) (int, error) {
	query := `SELECT ARN, GROUP_ID, VPC_ID, IP_PERMISSIONS, IP_PERMISSIONS_EGRESS 
	          FROM AWS_EC2_SECURITY_GROUPS WHERE ARN IS NOT NULL`
	
	result, err := r.sf.Query(ctx, query)
	if err != nil {
		return 0, err
	}

	var rels []Relationship
	for _, row := range result.Rows {
		sgARN := toString(row["ARN"])
		
		// VPC relationship
		if vpcID := toString(row["VPC_ID"]); vpcID != "" {
			rels = append(rels, Relationship{
				SourceID:   sgARN,
				SourceType: "aws:ec2:security_group",
				TargetID:   vpcID,
				TargetType: "aws:ec2:vpc",
				RelType:    RelBelongsTo,
			})
		}

		// Check for internet exposure (0.0.0.0/0 ingress)
		if perms := row["IP_PERMISSIONS"]; perms != nil {
			if permList, ok := perms.([]interface{}); ok {
				for _, perm := range permList {
					if permMap, ok := perm.(map[string]interface{}); ok {
						if ranges, ok := permMap["IpRanges"].([]interface{}); ok {
							for _, r := range ranges {
								if rMap, ok := r.(map[string]interface{}); ok {
									if cidr := toString(rMap["CidrIp"]); cidr == "0.0.0.0/0" || cidr == "::/0" {
										rels = append(rels, Relationship{
											SourceID:   sgARN,
											SourceType: "aws:ec2:security_group",
											TargetID:   "internet",
											TargetType: "network:internet",
											RelType:    RelExposedTo,
											Properties: fmt.Sprintf(`{"from_port":%v,"to_port":%v}`, 
												permMap["FromPort"], permMap["ToPort"]),
										})
									}
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

// extractS3Relationships extracts S3 bucket relationships
func (r *RelationshipExtractor) extractS3Relationships(ctx context.Context) (int, error) {
	query := `SELECT ARN, NAME, SERVER_SIDE_ENCRYPTION_CONFIGURATION, LOGGING, POLICY
	          FROM AWS_S3_BUCKETS WHERE ARN IS NOT NULL`
	
	result, err := r.sf.Query(ctx, query)
	if err != nil {
		return 0, err
	}

	var rels []Relationship
	for _, row := range result.Rows {
		bucketARN := toString(row["ARN"])
		
		// KMS encryption relationship
		if sseConfig := row["SERVER_SIDE_ENCRYPTION_CONFIGURATION"]; sseConfig != nil {
			if configMap, ok := sseConfig.(map[string]interface{}); ok {
				if rules, ok := configMap["Rules"].([]interface{}); ok {
					for _, rule := range rules {
						if ruleMap, ok := rule.(map[string]interface{}); ok {
							if apply, ok := ruleMap["ApplyServerSideEncryptionByDefault"].(map[string]interface{}); ok {
								if kmsKeyID := toString(apply["KMSMasterKeyID"]); kmsKeyID != "" {
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
				}
			}
		}

		// Logging relationship
		if logging := row["LOGGING"]; logging != nil {
			if logMap, ok := logging.(map[string]interface{}); ok {
				if targetBucket := toString(logMap["TargetBucket"]); targetBucket != "" {
					rels = append(rels, Relationship{
						SourceID:   bucketARN,
						SourceType: "aws:s3:bucket",
						TargetID:   fmt.Sprintf("arn:aws:s3:::%s", targetBucket),
						TargetType: "aws:s3:bucket",
						RelType:    RelLogsTo,
					})
				}
			}
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
			if sas := row["SERVICE_ACCOUNTS"]; sas != nil {
				if saList, ok := sas.([]interface{}); ok {
					for _, sa := range saList {
						if saMap, ok := sa.(map[string]interface{}); ok {
							if email := toString(saMap["email"]); email != "" {
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
			}

			// Network relationships
			if nics := row["NETWORK_INTERFACES"]; nics != nil {
				if nicList, ok := nics.([]interface{}); ok {
					for _, nic := range nicList {
						if nicMap, ok := nic.(map[string]interface{}); ok {
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
	}

	// GCP Cloud Functions
	query = `SELECT NAME, SERVICE_ACCOUNT_EMAIL, VPC_CONNECTOR
	         FROM GCP_CLOUDFUNCTIONS_FUNCTIONS WHERE NAME IS NOT NULL`
	
	result, err = r.sf.Query(ctx, query)
	if err == nil {
		for _, row := range result.Rows {
			funcName := toString(row["NAME"])
			
			if saEmail := toString(row["SERVICE_ACCOUNT_EMAIL"]); saEmail != "" {
				rels = append(rels, Relationship{
					SourceID:   funcName,
					SourceType: "gcp:cloudfunctions:function",
					TargetID:   saEmail,
					TargetType: "gcp:iam:service_account",
					RelType:    RelHasRole,
				})
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
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

func escape(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}
