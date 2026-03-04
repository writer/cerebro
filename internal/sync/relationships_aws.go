package sync

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

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
		instanceARN := toString(queryRow(row, "arn"))
		if instanceARN == "" {
			continue
		}
		accountID := toString(queryRow(row, "account_id"))
		region := toString(queryRow(row, "region"))

		// VPC relationship
		if vpcID := toString(queryRow(row, "vpc_id")); vpcID != "" {
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
		if subnetID := toString(queryRow(row, "subnet_id")); subnetID != "" {
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
		if profile := queryRow(row, "iam_instance_profile"); profile != nil {
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
		if sgList := asSlice(queryRow(row, "security_groups")); len(sgList) > 0 {
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
		roleARN := toString(queryRow(row, "arn"))
		if roleARN == "" {
			continue
		}

		// Parse trust policy to extract who can assume the role
		if trustPolicy := queryRow(row, "assume_role_policy_document"); trustPolicy != nil {
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
		functionARN := toString(queryRow(row, "arn"))
		if functionARN == "" {
			continue
		}
		region, accountID := awsRegionAccountFromARN(functionARN)

		// Execution role relationship
		if roleARN := toString(queryRow(row, "role")); roleARN != "" {
			rels = append(rels, Relationship{
				SourceID:   functionARN,
				SourceType: "aws:lambda:function",
				TargetID:   roleARN,
				TargetType: "aws:iam:role",
				RelType:    RelHasRole,
			})
		}

		// VPC relationships
		if vpcConfig := asMap(queryRow(row, "vpc_config")); vpcConfig != nil {
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
		sgARN := toString(queryRow(row, "arn"))
		if sgARN == "" {
			continue
		}
		accountID := toString(queryRow(row, "account_id"))
		region := toString(queryRow(row, "region"))

		// VPC relationship
		if vpcID := toString(queryRow(row, "vpc_id")); vpcID != "" {
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
		if permList := asSlice(queryRow(row, "ip_permissions")); len(permList) > 0 {
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
		bucketARN := toString(queryRow(row, "arn"))
		if bucketARN == "" {
			continue
		}

		// KMS encryption relationship - extract from ENCRYPTION column
		if enc := queryRow(row, "encryption"); enc != nil {
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
		if targetBucket := toString(queryRow(row, "logging_target_bucket")); targetBucket != "" {
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
		serviceARN := toString(queryRow(row, "arn"))

		// Cluster relationship
		if clusterARN := toString(queryRow(row, "cluster_arn")); clusterARN != "" {
			rels = append(rels, Relationship{
				SourceID:   serviceARN,
				SourceType: "aws:ecs:service",
				TargetID:   clusterARN,
				TargetType: "aws:ecs:cluster",
				RelType:    RelBelongsTo,
			})
		}

		// Task definition relationship
		if taskDef := toString(queryRow(row, "task_definition")); taskDef != "" {
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

func (r *RelationshipExtractor) extractRDSRelationships(ctx context.Context) (int, error) {
	var rels []Relationship
	instanceARNByIdentifier := make(map[string]string)
	clusterARNByIdentifier := make(map[string]string)
	snapshotARNByIdentifier := make(map[string]string)
	clusterSnapshotARNByIdentifier := make(map[string]string)
	subnetGroupARNByName := make(map[string]string)
	parameterGroupARNByName := make(map[string]string)
	clusterParameterGroupARNByName := make(map[string]string)
	optionGroupARNByName := make(map[string]string)
	proxyARNByName := make(map[string]string)
	clusterSubnetGroupRefs := make([]struct {
		clusterARN      string
		region          string
		accountID       string
		subnetGroupName string
	}, 0)
	instanceClusterRefs := make([]struct {
		instanceARN       string
		region            string
		accountID         string
		clusterIdentifier string
	}, 0)
	instanceParameterGroupRefs := make([]struct {
		instanceARN string
		region      string
		accountID   string
		groupName   string
	}, 0)
	clusterParameterGroupRefs := make([]struct {
		clusterARN string
		region     string
		accountID  string
		groupName  string
	}, 0)
	instanceOptionGroupRefs := make([]struct {
		instanceARN string
		region      string
		accountID   string
		groupName   string
	}, 0)

	lookupByEventSourceType := map[string]map[string]string{
		"db-instance":                instanceARNByIdentifier,
		"db-cluster":                 clusterARNByIdentifier,
		"db-snapshot":                snapshotARNByIdentifier,
		"db-cluster-snapshot":        clusterSnapshotARNByIdentifier,
		"db-subnet-group":            subnetGroupARNByName,
		"db-parameter-group":         parameterGroupARNByName,
		"db-cluster-parameter-group": clusterParameterGroupARNByName,
		"db-option-group":            optionGroupARNByName,
		"db-proxy":                   proxyARNByName,
	}

	query := ""
	instanceColumns, err := r.getTableColumnSet(ctx, "AWS_RDS_INSTANCES")
	if err != nil {
		return 0, err
	}
	if len(instanceColumns) > 0 {
		query = fmt.Sprintf(`SELECT ARN, ACCOUNT_ID, REGION, DB_INSTANCE_IDENTIFIER, KMS_KEY_ID, VPC_SECURITY_GROUPS, DB_SUBNET_GROUP, %s, %s, %s, %s
	          FROM AWS_RDS_INSTANCES WHERE ARN IS NOT NULL`,
			tableColumnExpression(instanceColumns, "db_cluster_identifier"),
			tableColumnExpression(instanceColumns, "db_parameter_groups"),
			tableColumnExpression(instanceColumns, "option_group_memberships"),
			tableColumnExpression(instanceColumns, "associated_roles"),
		)

		if result, ok, err := r.queryRowsForTable(ctx, "AWS_RDS_INSTANCES", query); err != nil {
			return 0, err
		} else if ok {
			for _, row := range result.Rows {
				instanceARN := toString(queryRow(row, "arn"))
				if instanceARN == "" {
					continue
				}

				region := toString(queryRow(row, "region"))
				accountID := toString(queryRow(row, "account_id"))
				if region == "" || accountID == "" {
					arnRegion, arnAccount := awsRegionAccountFromARN(instanceARN)
					if region == "" {
						region = arnRegion
					}
					if accountID == "" {
						accountID = arnAccount
					}
				}

				recordRDSLookup(instanceARNByIdentifier, region, toString(queryRow(row, "db_instance_identifier")), instanceARN)

				if clusterIdentifier := toString(queryRow(row, "db_cluster_identifier")); clusterIdentifier != "" {
					instanceClusterRefs = append(instanceClusterRefs, struct {
						instanceARN       string
						region            string
						accountID         string
						clusterIdentifier string
					}{
						instanceARN:       instanceARN,
						region:            region,
						accountID:         accountID,
						clusterIdentifier: clusterIdentifier,
					})
				}

				if kmsKeyID := toString(queryRow(row, "kms_key_id")); kmsKeyID != "" {
					rels = append(rels, Relationship{
						SourceID:   instanceARN,
						SourceType: "aws:rds:db_instance",
						TargetID:   kmsKeyID,
						TargetType: "aws:kms:key",
						RelType:    RelEncryptedBy,
					})
				}

				for _, role := range asSlice(queryRow(row, "associated_roles")) {
					roleMap := asMap(role)
					if roleMap == nil {
						continue
					}
					roleARN := getStringAny(roleMap, "RoleArn", "roleArn", "role_arn")
					if roleARN == "" {
						continue
					}
					rels = append(rels, Relationship{
						SourceID:   instanceARN,
						SourceType: "aws:rds:db_instance",
						TargetID:   roleARN,
						TargetType: "aws:iam:role",
						RelType:    RelHasRole,
					})
				}

				for _, parameterGroup := range asSlice(queryRow(row, "db_parameter_groups")) {
					groupMap := asMap(parameterGroup)
					if groupMap == nil {
						continue
					}
					groupName := getStringAny(groupMap, "DBParameterGroupName", "dbParameterGroupName", "db_parameter_group_name")
					if groupName == "" {
						continue
					}
					instanceParameterGroupRefs = append(instanceParameterGroupRefs, struct {
						instanceARN string
						region      string
						accountID   string
						groupName   string
					}{
						instanceARN: instanceARN,
						region:      region,
						accountID:   accountID,
						groupName:   groupName,
					})
				}

				for _, optionGroup := range asSlice(queryRow(row, "option_group_memberships")) {
					groupMap := asMap(optionGroup)
					if groupMap == nil {
						continue
					}
					groupName := getStringAny(groupMap, "OptionGroupName", "optionGroupName", "option_group_name")
					if groupName == "" {
						continue
					}
					instanceOptionGroupRefs = append(instanceOptionGroupRefs, struct {
						instanceARN string
						region      string
						accountID   string
						groupName   string
					}{
						instanceARN: instanceARN,
						region:      region,
						accountID:   accountID,
						groupName:   groupName,
					})
				}

				for _, sg := range asSlice(queryRow(row, "vpc_security_groups")) {
					sgMap := asMap(sg)
					if sgMap == nil {
						continue
					}
					sgID := getStringAny(sgMap, "VpcSecurityGroupId", "vpcSecurityGroupId", "groupId", "GroupId")
					if sgID == "" {
						continue
					}
					rels = append(rels, Relationship{
						SourceID:   instanceARN,
						SourceType: "aws:rds:db_instance",
						TargetID:   awsARNForResource("security-group", region, accountID, sgID),
						TargetType: "aws:ec2:security_group",
						RelType:    RelMemberOf,
					})
				}

				subnetGroup := asMap(queryRow(row, "db_subnet_group"))
				if subnetGroup == nil {
					continue
				}

				if subnetGroupARN := getStringAny(subnetGroup, "DBSubnetGroupArn", "dbSubnetGroupArn", "db_subnet_group_arn"); subnetGroupARN != "" {
					rels = append(rels, Relationship{
						SourceID:   instanceARN,
						SourceType: "aws:rds:db_instance",
						TargetID:   subnetGroupARN,
						TargetType: "aws:rds:db_subnet_group",
						RelType:    RelBelongsTo,
					})
				}

				if vpcID := getStringAny(subnetGroup, "VpcId", "vpcId", "vpc_id"); vpcID != "" {
					rels = append(rels, Relationship{
						SourceID:   instanceARN,
						SourceType: "aws:rds:db_instance",
						TargetID:   awsARNForResource("vpc", region, accountID, vpcID),
						TargetType: "aws:ec2:vpc",
						RelType:    RelInVPC,
					})
				}

				for _, subnet := range getSliceAny(subnetGroup, "Subnets", "subnets") {
					subnetMap := asMap(subnet)
					if subnetMap == nil {
						continue
					}
					subnetID := getStringAny(subnetMap, "SubnetIdentifier", "subnetIdentifier", "subnet_id", "SubnetId", "subnetId")
					if subnetID == "" {
						continue
					}
					rels = append(rels, Relationship{
						SourceID:   instanceARN,
						SourceType: "aws:rds:db_instance",
						TargetID:   awsARNForResource("subnet", region, accountID, subnetID),
						TargetType: "aws:ec2:subnet",
						RelType:    RelInSubnet,
					})
				}
			}
		}
	}

	clusterColumns, err := r.getTableColumnSet(ctx, "AWS_RDS_DB_CLUSTERS")
	if err != nil {
		return 0, err
	}
	if len(clusterColumns) > 0 {
		query = fmt.Sprintf(`SELECT ARN, ACCOUNT_ID, REGION, DB_CLUSTER_IDENTIFIER, KMS_KEY_ID, %s, %s, %s, %s, %s
	         FROM AWS_RDS_DB_CLUSTERS WHERE ARN IS NOT NULL`,
			tableColumnExpression(clusterColumns, "db_subnet_group"),
			tableColumnExpression(clusterColumns, "vpc_security_groups"),
			tableColumnExpression(clusterColumns, "db_cluster_members"),
			tableColumnExpression(clusterColumns, "db_cluster_parameter_group"),
			tableColumnExpression(clusterColumns, "associated_roles"),
		)

		if result, ok, err := r.queryRowsForTable(ctx, "AWS_RDS_DB_CLUSTERS", query); err != nil {
			return 0, err
		} else if ok {
			for _, row := range result.Rows {
				clusterARN := toString(queryRow(row, "arn"))
				if clusterARN == "" {
					continue
				}

				region := toString(queryRow(row, "region"))
				accountID := toString(queryRow(row, "account_id"))
				if region == "" || accountID == "" {
					arnRegion, arnAccount := awsRegionAccountFromARN(clusterARN)
					if region == "" {
						region = arnRegion
					}
					if accountID == "" {
						accountID = arnAccount
					}
				}

				recordRDSLookup(clusterARNByIdentifier, region, toString(queryRow(row, "db_cluster_identifier")), clusterARN)

				if kmsKeyID := toString(queryRow(row, "kms_key_id")); kmsKeyID != "" {
					rels = append(rels, Relationship{
						SourceID:   clusterARN,
						SourceType: "aws:rds:db_cluster",
						TargetID:   kmsKeyID,
						TargetType: "aws:kms:key",
						RelType:    RelEncryptedBy,
					})
				}

				for _, role := range asSlice(queryRow(row, "associated_roles")) {
					roleMap := asMap(role)
					if roleMap == nil {
						continue
					}
					roleARN := getStringAny(roleMap, "RoleArn", "roleArn", "role_arn")
					if roleARN == "" {
						continue
					}
					rels = append(rels, Relationship{
						SourceID:   clusterARN,
						SourceType: "aws:rds:db_cluster",
						TargetID:   roleARN,
						TargetType: "aws:iam:role",
						RelType:    RelHasRole,
					})
				}

				for _, sg := range asSlice(queryRow(row, "vpc_security_groups")) {
					sgMap := asMap(sg)
					if sgMap == nil {
						continue
					}
					sgID := getStringAny(sgMap, "VpcSecurityGroupId", "vpcSecurityGroupId", "groupId", "GroupId")
					if sgID == "" {
						continue
					}
					rels = append(rels, Relationship{
						SourceID:   clusterARN,
						SourceType: "aws:rds:db_cluster",
						TargetID:   awsARNForResource("security-group", region, accountID, sgID),
						TargetType: "aws:ec2:security_group",
						RelType:    RelMemberOf,
					})
				}

				if subnetGroupName := toString(queryRow(row, "db_subnet_group")); subnetGroupName != "" {
					clusterSubnetGroupRefs = append(clusterSubnetGroupRefs, struct {
						clusterARN      string
						region          string
						accountID       string
						subnetGroupName string
					}{
						clusterARN:      clusterARN,
						region:          region,
						accountID:       accountID,
						subnetGroupName: subnetGroupName,
					})
				}

				if parameterGroupName := toString(queryRow(row, "db_cluster_parameter_group")); parameterGroupName != "" {
					clusterParameterGroupRefs = append(clusterParameterGroupRefs, struct {
						clusterARN string
						region     string
						accountID  string
						groupName  string
					}{
						clusterARN: clusterARN,
						region:     region,
						accountID:  accountID,
						groupName:  parameterGroupName,
					})
				}

				for _, member := range asSlice(queryRow(row, "db_cluster_members")) {
					memberMap := asMap(member)
					if memberMap == nil {
						continue
					}
					instanceIdentifier := getStringAny(memberMap, "DBInstanceIdentifier", "dbInstanceIdentifier", "db_instance_identifier")
					if instanceIdentifier == "" {
						continue
					}
					instanceARN := lookupRDSResourceARN(instanceARNByIdentifier, region, instanceIdentifier)
					if instanceARN == "" {
						instanceARN = awsRDSARN("db", region, accountID, instanceIdentifier)
					}
					rels = append(rels, Relationship{
						SourceID:   instanceARN,
						SourceType: "aws:rds:db_instance",
						TargetID:   clusterARN,
						TargetType: "aws:rds:db_cluster",
						RelType:    RelBelongsTo,
					})
				}
			}
		}
	}

	for _, ref := range instanceClusterRefs {
		targetID := lookupRDSResourceARN(clusterARNByIdentifier, ref.region, ref.clusterIdentifier)
		if targetID == "" {
			targetID = awsRDSARN("cluster", ref.region, ref.accountID, ref.clusterIdentifier)
		}
		rels = append(rels, Relationship{
			SourceID:   ref.instanceARN,
			SourceType: "aws:rds:db_instance",
			TargetID:   targetID,
			TargetType: "aws:rds:db_cluster",
			RelType:    RelBelongsTo,
		})
	}

	query = `SELECT ARN, ACCOUNT_ID, REGION, DB_SNAPSHOT_IDENTIFIER, DB_INSTANCE_IDENTIFIER, DB_CLUSTER_IDENTIFIER, KMS_KEY_ID
	         FROM AWS_RDS_DB_SNAPSHOTS WHERE ARN IS NOT NULL`

	if result, ok, err := r.queryRowsForTable(ctx, "AWS_RDS_DB_SNAPSHOTS", query); err != nil {
		return 0, err
	} else if ok {
		for _, row := range result.Rows {
			snapshotARN := toString(queryRow(row, "arn"))
			if snapshotARN == "" {
				continue
			}

			region := toString(queryRow(row, "region"))
			accountID := toString(queryRow(row, "account_id"))
			if region == "" || accountID == "" {
				arnRegion, arnAccount := awsRegionAccountFromARN(snapshotARN)
				if region == "" {
					region = arnRegion
				}
				if accountID == "" {
					accountID = arnAccount
				}
			}

			recordRDSLookup(snapshotARNByIdentifier, region, toString(queryRow(row, "db_snapshot_identifier")), snapshotARN)

			if kmsKeyID := toString(queryRow(row, "kms_key_id")); kmsKeyID != "" {
				rels = append(rels, Relationship{
					SourceID:   snapshotARN,
					SourceType: "aws:rds:db_snapshot",
					TargetID:   kmsKeyID,
					TargetType: "aws:kms:key",
					RelType:    RelEncryptedBy,
				})
			}

			if instanceIdentifier := toString(queryRow(row, "db_instance_identifier")); instanceIdentifier != "" {
				targetID := lookupRDSResourceARN(instanceARNByIdentifier, region, instanceIdentifier)
				if targetID == "" {
					targetID = awsRDSARN("db", region, accountID, instanceIdentifier)
				}
				rels = append(rels, Relationship{
					SourceID:   snapshotARN,
					SourceType: "aws:rds:db_snapshot",
					TargetID:   targetID,
					TargetType: "aws:rds:db_instance",
					RelType:    RelBelongsTo,
				})
			}

			if clusterIdentifier := toString(queryRow(row, "db_cluster_identifier")); clusterIdentifier != "" {
				targetID := lookupRDSResourceARN(clusterARNByIdentifier, region, clusterIdentifier)
				if targetID == "" {
					targetID = awsRDSARN("cluster", region, accountID, clusterIdentifier)
				}
				rels = append(rels, Relationship{
					SourceID:   snapshotARN,
					SourceType: "aws:rds:db_snapshot",
					TargetID:   targetID,
					TargetType: "aws:rds:db_cluster",
					RelType:    RelBelongsTo,
				})
			}
		}
	}

	query = `SELECT ARN, ACCOUNT_ID, REGION, DB_CLUSTER_SNAPSHOT_IDENTIFIER, DB_CLUSTER_IDENTIFIER, KMS_KEY_ID
	         FROM AWS_RDS_DB_CLUSTER_SNAPSHOTS WHERE ARN IS NOT NULL`

	if result, ok, err := r.queryRowsForTable(ctx, "AWS_RDS_DB_CLUSTER_SNAPSHOTS", query); err != nil {
		return 0, err
	} else if ok {
		for _, row := range result.Rows {
			snapshotARN := toString(queryRow(row, "arn"))
			if snapshotARN == "" {
				continue
			}

			region := toString(queryRow(row, "region"))
			accountID := toString(queryRow(row, "account_id"))
			if region == "" || accountID == "" {
				arnRegion, arnAccount := awsRegionAccountFromARN(snapshotARN)
				if region == "" {
					region = arnRegion
				}
				if accountID == "" {
					accountID = arnAccount
				}
			}

			recordRDSLookup(clusterSnapshotARNByIdentifier, region, toString(queryRow(row, "db_cluster_snapshot_identifier")), snapshotARN)

			if kmsKeyID := toString(queryRow(row, "kms_key_id")); kmsKeyID != "" {
				rels = append(rels, Relationship{
					SourceID:   snapshotARN,
					SourceType: "aws:rds:db_cluster_snapshot",
					TargetID:   kmsKeyID,
					TargetType: "aws:kms:key",
					RelType:    RelEncryptedBy,
				})
			}

			if clusterIdentifier := toString(queryRow(row, "db_cluster_identifier")); clusterIdentifier != "" {
				targetID := lookupRDSResourceARN(clusterARNByIdentifier, region, clusterIdentifier)
				if targetID == "" {
					targetID = awsRDSARN("cluster", region, accountID, clusterIdentifier)
				}
				rels = append(rels, Relationship{
					SourceID:   snapshotARN,
					SourceType: "aws:rds:db_cluster_snapshot",
					TargetID:   targetID,
					TargetType: "aws:rds:db_cluster",
					RelType:    RelBelongsTo,
				})
			}
		}
	}

	query = `SELECT ARN, ACCOUNT_ID, REGION, DB_SUBNET_GROUP_NAME, VPC_ID, SUBNETS
	         FROM AWS_RDS_DB_SUBNET_GROUPS WHERE ARN IS NOT NULL`

	if result, ok, err := r.queryRowsForTable(ctx, "AWS_RDS_DB_SUBNET_GROUPS", query); err != nil {
		return 0, err
	} else if ok {
		for _, row := range result.Rows {
			subnetGroupARN := toString(queryRow(row, "arn"))
			if subnetGroupARN == "" {
				continue
			}

			region := toString(queryRow(row, "region"))
			accountID := toString(queryRow(row, "account_id"))
			if region == "" || accountID == "" {
				arnRegion, arnAccount := awsRegionAccountFromARN(subnetGroupARN)
				if region == "" {
					region = arnRegion
				}
				if accountID == "" {
					accountID = arnAccount
				}
			}

			recordRDSLookup(subnetGroupARNByName, region, toString(queryRow(row, "db_subnet_group_name")), subnetGroupARN)

			if vpcID := toString(queryRow(row, "vpc_id")); vpcID != "" {
				rels = append(rels, Relationship{
					SourceID:   subnetGroupARN,
					SourceType: "aws:rds:db_subnet_group",
					TargetID:   awsARNForResource("vpc", region, accountID, vpcID),
					TargetType: "aws:ec2:vpc",
					RelType:    RelInVPC,
				})
			}

			for _, subnet := range asSlice(queryRow(row, "subnets")) {
				subnetMap := asMap(subnet)
				if subnetMap == nil {
					continue
				}
				subnetID := getStringAny(subnetMap, "SubnetIdentifier", "subnetIdentifier", "subnet_id", "SubnetId", "subnetId")
				if subnetID == "" {
					continue
				}
				rels = append(rels, Relationship{
					SourceID:   subnetGroupARN,
					SourceType: "aws:rds:db_subnet_group",
					TargetID:   awsARNForResource("subnet", region, accountID, subnetID),
					TargetType: "aws:ec2:subnet",
					RelType:    RelInSubnet,
				})
			}
		}
	}

	for _, ref := range clusterSubnetGroupRefs {
		targetID := lookupRDSResourceARN(subnetGroupARNByName, ref.region, ref.subnetGroupName)
		if targetID == "" {
			targetID = awsRDSARN("subgrp", ref.region, ref.accountID, ref.subnetGroupName)
		}
		rels = append(rels, Relationship{
			SourceID:   ref.clusterARN,
			SourceType: "aws:rds:db_cluster",
			TargetID:   targetID,
			TargetType: "aws:rds:db_subnet_group",
			RelType:    RelBelongsTo,
		})
	}

	query = `SELECT ARN, ACCOUNT_ID, REGION, DB_PARAMETER_GROUP_NAME
	         FROM AWS_RDS_DB_PARAMETER_GROUPS WHERE ARN IS NOT NULL`

	if result, ok, err := r.queryRowsForTable(ctx, "AWS_RDS_DB_PARAMETER_GROUPS", query); err != nil {
		return 0, err
	} else if ok {
		for _, row := range result.Rows {
			groupARN := toString(queryRow(row, "arn"))
			if groupARN == "" {
				continue
			}

			region := toString(queryRow(row, "region"))
			if region == "" {
				arnRegion, _ := awsRegionAccountFromARN(groupARN)
				region = arnRegion
			}

			recordRDSLookup(parameterGroupARNByName, region, toString(queryRow(row, "db_parameter_group_name")), groupARN)
		}
	}

	query = `SELECT ARN, ACCOUNT_ID, REGION, DB_CLUSTER_PARAMETER_GROUP_NAME
	         FROM AWS_RDS_DB_CLUSTER_PARAMETER_GROUPS WHERE ARN IS NOT NULL`

	if result, ok, err := r.queryRowsForTable(ctx, "AWS_RDS_DB_CLUSTER_PARAMETER_GROUPS", query); err != nil {
		return 0, err
	} else if ok {
		for _, row := range result.Rows {
			groupARN := toString(queryRow(row, "arn"))
			if groupARN == "" {
				continue
			}

			region := toString(queryRow(row, "region"))
			if region == "" {
				arnRegion, _ := awsRegionAccountFromARN(groupARN)
				region = arnRegion
			}

			recordRDSLookup(clusterParameterGroupARNByName, region, toString(queryRow(row, "db_cluster_parameter_group_name")), groupARN)
		}
	}

	query = `SELECT ARN, ACCOUNT_ID, REGION, OPTION_GROUP_NAME, VPC_ID
	         FROM AWS_RDS_DB_OPTION_GROUPS WHERE ARN IS NOT NULL`

	if result, ok, err := r.queryRowsForTable(ctx, "AWS_RDS_DB_OPTION_GROUPS", query); err != nil {
		return 0, err
	} else if ok {
		for _, row := range result.Rows {
			groupARN := toString(queryRow(row, "arn"))
			if groupARN == "" {
				continue
			}

			region := toString(queryRow(row, "region"))
			accountID := toString(queryRow(row, "account_id"))
			if region == "" || accountID == "" {
				arnRegion, arnAccount := awsRegionAccountFromARN(groupARN)
				if region == "" {
					region = arnRegion
				}
				if accountID == "" {
					accountID = arnAccount
				}
			}

			recordRDSLookup(optionGroupARNByName, region, toString(queryRow(row, "option_group_name")), groupARN)

			if vpcID := toString(queryRow(row, "vpc_id")); vpcID != "" {
				rels = append(rels, Relationship{
					SourceID:   groupARN,
					SourceType: "aws:rds:db_option_group",
					TargetID:   awsARNForResource("vpc", region, accountID, vpcID),
					TargetType: "aws:ec2:vpc",
					RelType:    RelInVPC,
				})
			}
		}
	}

	for _, ref := range instanceParameterGroupRefs {
		targetID := lookupRDSResourceARN(parameterGroupARNByName, ref.region, ref.groupName)
		if targetID == "" {
			targetID = awsRDSARN("pg", ref.region, ref.accountID, ref.groupName)
		}
		rels = append(rels, Relationship{
			SourceID:   ref.instanceARN,
			SourceType: "aws:rds:db_instance",
			TargetID:   targetID,
			TargetType: "aws:rds:db_parameter_group",
			RelType:    RelBelongsTo,
		})
	}

	for _, ref := range clusterParameterGroupRefs {
		targetID := lookupRDSResourceARN(clusterParameterGroupARNByName, ref.region, ref.groupName)
		if targetID == "" {
			targetID = awsRDSARN("cluster-pg", ref.region, ref.accountID, ref.groupName)
		}
		rels = append(rels, Relationship{
			SourceID:   ref.clusterARN,
			SourceType: "aws:rds:db_cluster",
			TargetID:   targetID,
			TargetType: "aws:rds:db_cluster_parameter_group",
			RelType:    RelBelongsTo,
		})
	}

	for _, ref := range instanceOptionGroupRefs {
		targetID := lookupRDSResourceARN(optionGroupARNByName, ref.region, ref.groupName)
		if targetID == "" {
			targetID = awsRDSARN("og", ref.region, ref.accountID, ref.groupName)
		}
		rels = append(rels, Relationship{
			SourceID:   ref.instanceARN,
			SourceType: "aws:rds:db_instance",
			TargetID:   targetID,
			TargetType: "aws:rds:db_option_group",
			RelType:    RelBelongsTo,
		})
	}

	proxyColumns, err := r.getTableColumnSet(ctx, "AWS_RDS_DB_PROXIES")
	if err != nil {
		return 0, err
	}
	if len(proxyColumns) > 0 {
		query = fmt.Sprintf(`SELECT ARN, ACCOUNT_ID, REGION, ROLE_ARN, VPC_ID, VPC_SECURITY_GROUP_IDS, VPC_SUBNET_IDS, %s, %s
	         FROM AWS_RDS_DB_PROXIES WHERE ARN IS NOT NULL`,
			tableColumnExpression(proxyColumns, "db_proxy_name"),
			tableColumnExpression(proxyColumns, "auth"),
		)

		if result, ok, err := r.queryRowsForTable(ctx, "AWS_RDS_DB_PROXIES", query); err != nil {
			return 0, err
		} else if ok {
			for _, row := range result.Rows {
				proxyARN := toString(queryRow(row, "arn"))
				if proxyARN == "" {
					continue
				}

				region := toString(queryRow(row, "region"))
				accountID := toString(queryRow(row, "account_id"))
				if region == "" || accountID == "" {
					arnRegion, arnAccount := awsRegionAccountFromARN(proxyARN)
					if region == "" {
						region = arnRegion
					}
					if accountID == "" {
						accountID = arnAccount
					}
				}

				recordRDSLookup(proxyARNByName, region, toString(queryRow(row, "db_proxy_name")), proxyARN)

				if roleARN := toString(queryRow(row, "role_arn")); roleARN != "" {
					rels = append(rels, Relationship{
						SourceID:   proxyARN,
						SourceType: "aws:rds:db_proxy",
						TargetID:   roleARN,
						TargetType: "aws:iam:role",
						RelType:    RelHasRole,
					})
				}

				if vpcID := toString(queryRow(row, "vpc_id")); vpcID != "" {
					rels = append(rels, Relationship{
						SourceID:   proxyARN,
						SourceType: "aws:rds:db_proxy",
						TargetID:   awsARNForResource("vpc", region, accountID, vpcID),
						TargetType: "aws:ec2:vpc",
						RelType:    RelInVPC,
					})
				}

				for _, sg := range asSlice(queryRow(row, "vpc_security_group_ids")) {
					sgID := toString(sg)
					if sgID == "" {
						continue
					}
					rels = append(rels, Relationship{
						SourceID:   proxyARN,
						SourceType: "aws:rds:db_proxy",
						TargetID:   awsARNForResource("security-group", region, accountID, sgID),
						TargetType: "aws:ec2:security_group",
						RelType:    RelMemberOf,
					})
				}

				for _, subnet := range asSlice(queryRow(row, "vpc_subnet_ids")) {
					subnetID := toString(subnet)
					if subnetID == "" {
						continue
					}
					rels = append(rels, Relationship{
						SourceID:   proxyARN,
						SourceType: "aws:rds:db_proxy",
						TargetID:   awsARNForResource("subnet", region, accountID, subnetID),
						TargetType: "aws:ec2:subnet",
						RelType:    RelInSubnet,
					})
				}

				for _, authEntry := range asSlice(queryRow(row, "auth")) {
					authMap := asMap(authEntry)
					if authMap == nil {
						continue
					}
					if secretARN := getStringAny(authMap, "SecretArn", "secretArn", "secret_arn", "secretARN"); secretARN != "" {
						rels = append(rels, Relationship{
							SourceID:   proxyARN,
							SourceType: "aws:rds:db_proxy",
							TargetID:   secretARN,
							TargetType: "aws:secretsmanager:secret",
							RelType:    RelReadsFrom,
						})
					}
				}
			}
		}
	}

	proxyEndpointColumns, err := r.getTableColumnSet(ctx, "AWS_RDS_DB_PROXY_ENDPOINTS")
	if err != nil {
		return 0, err
	}
	if len(proxyEndpointColumns) > 0 {
		query = fmt.Sprintf(`SELECT ARN, ACCOUNT_ID, REGION, VPC_ID, VPC_SECURITY_GROUP_IDS, VPC_SUBNET_IDS, %s
	         FROM AWS_RDS_DB_PROXY_ENDPOINTS WHERE ARN IS NOT NULL`,
			tableColumnExpression(proxyEndpointColumns, "db_proxy_name"),
		)

		if result, ok, err := r.queryRowsForTable(ctx, "AWS_RDS_DB_PROXY_ENDPOINTS", query); err != nil {
			return 0, err
		} else if ok {
			for _, row := range result.Rows {
				endpointARN := toString(queryRow(row, "arn"))
				if endpointARN == "" {
					continue
				}

				region := toString(queryRow(row, "region"))
				accountID := toString(queryRow(row, "account_id"))
				if region == "" || accountID == "" {
					arnRegion, arnAccount := awsRegionAccountFromARN(endpointARN)
					if region == "" {
						region = arnRegion
					}
					if accountID == "" {
						accountID = arnAccount
					}
				}

				if proxyName := toString(queryRow(row, "db_proxy_name")); proxyName != "" {
					proxyARN := lookupRDSResourceARN(proxyARNByName, region, proxyName)
					if proxyARN == "" {
						proxyARN = awsRDSARN("db-proxy", region, accountID, proxyName)
					}
					rels = append(rels, Relationship{
						SourceID:   endpointARN,
						SourceType: "aws:rds:db_proxy_endpoint",
						TargetID:   proxyARN,
						TargetType: "aws:rds:db_proxy",
						RelType:    RelBelongsTo,
					})
				}

				if vpcID := toString(queryRow(row, "vpc_id")); vpcID != "" {
					rels = append(rels, Relationship{
						SourceID:   endpointARN,
						SourceType: "aws:rds:db_proxy_endpoint",
						TargetID:   awsARNForResource("vpc", region, accountID, vpcID),
						TargetType: "aws:ec2:vpc",
						RelType:    RelInVPC,
					})
				}

				for _, sg := range asSlice(queryRow(row, "vpc_security_group_ids")) {
					sgID := toString(sg)
					if sgID == "" {
						continue
					}
					rels = append(rels, Relationship{
						SourceID:   endpointARN,
						SourceType: "aws:rds:db_proxy_endpoint",
						TargetID:   awsARNForResource("security-group", region, accountID, sgID),
						TargetType: "aws:ec2:security_group",
						RelType:    RelMemberOf,
					})
				}

				for _, subnet := range asSlice(queryRow(row, "vpc_subnet_ids")) {
					subnetID := toString(subnet)
					if subnetID == "" {
						continue
					}
					rels = append(rels, Relationship{
						SourceID:   endpointARN,
						SourceType: "aws:rds:db_proxy_endpoint",
						TargetID:   awsARNForResource("subnet", region, accountID, subnetID),
						TargetType: "aws:ec2:subnet",
						RelType:    RelInSubnet,
					})
				}
			}
		}
	}

	query = `SELECT ARN, ACCOUNT_ID, REGION, SOURCE_TYPE, SOURCE_IDS, SNS_TOPIC_ARN
	         FROM AWS_RDS_EVENT_SUBSCRIPTIONS WHERE ARN IS NOT NULL`

	if result, ok, err := r.queryRowsForTable(ctx, "AWS_RDS_EVENT_SUBSCRIPTIONS", query); err != nil {
		return 0, err
	} else if ok {
		for _, row := range result.Rows {
			subscriptionARN := toString(queryRow(row, "arn"))
			if subscriptionARN == "" {
				continue
			}

			region := toString(queryRow(row, "region"))
			accountID := toString(queryRow(row, "account_id"))
			if region == "" || accountID == "" {
				arnRegion, arnAccount := awsRegionAccountFromARN(subscriptionARN)
				if region == "" {
					region = arnRegion
				}
				if accountID == "" {
					accountID = arnAccount
				}
			}

			if snsTopicARN := toString(queryRow(row, "sns_topic_arn")); snsTopicARN != "" {
				rels = append(rels, Relationship{
					SourceID:   subscriptionARN,
					SourceType: "aws:rds:event_subscription",
					TargetID:   snsTopicARN,
					TargetType: "aws:sns:topic",
					RelType:    RelRoutes,
				})
			}

			sourceType := toString(queryRow(row, "source_type"))
			for _, sourceIDValue := range asSlice(queryRow(row, "source_ids")) {
				sourceID := toString(sourceIDValue)
				if sourceID == "" {
					continue
				}

				targetID, targetType := resolveRDSEventSourceTarget(sourceType, region, accountID, sourceID, lookupByEventSourceType)
				if targetID == "" || targetType == "" {
					continue
				}

				rels = append(rels, Relationship{
					SourceID:   subscriptionARN,
					SourceType: "aws:rds:event_subscription",
					TargetID:   targetID,
					TargetType: targetType,
					RelType:    RelAttachedTo,
				})
			}
		}
	}

	return r.persistRelationships(ctx, rels)
}

func (r *RelationshipExtractor) extractEKSRelationships(ctx context.Context) (int, error) {
	var rels []Relationship

	query := `SELECT ARN, NAME, REGION, ACCOUNT_ID, ROLE_ARN, VPC_CONFIG, ENCRYPTION_CONFIG
	          FROM AWS_EKS_CLUSTERS WHERE ARN IS NOT NULL`

	if result, ok, err := r.queryRowsForTable(ctx, "AWS_EKS_CLUSTERS", query); err != nil {
		return 0, err
	} else if ok {
		for _, row := range result.Rows {
			clusterARN := toString(queryRow(row, "arn"))
			if clusterARN == "" {
				continue
			}

			region := toString(queryRow(row, "region"))
			accountID := toString(queryRow(row, "account_id"))
			if region == "" || accountID == "" {
				arnRegion, arnAccount := awsRegionAccountFromARN(clusterARN)
				if region == "" {
					region = arnRegion
				}
				if accountID == "" {
					accountID = arnAccount
				}
			}

			if roleARN := toString(queryRow(row, "role_arn")); roleARN != "" {
				rels = append(rels, Relationship{
					SourceID:   clusterARN,
					SourceType: "aws:eks:cluster",
					TargetID:   roleARN,
					TargetType: "aws:iam:role",
					RelType:    RelHasRole,
				})
			}

			if vpcConfig := asMap(queryRow(row, "vpc_config")); vpcConfig != nil {
				if vpcID := getStringAny(vpcConfig, "VpcId", "vpcId", "vpc_id"); vpcID != "" {
					vpcARN := awsARNForResource("vpc", region, accountID, vpcID)
					rels = append(rels, Relationship{
						SourceID:   clusterARN,
						SourceType: "aws:eks:cluster",
						TargetID:   vpcARN,
						TargetType: "aws:ec2:vpc",
						RelType:    RelInVPC,
					})
				}

				for _, subnet := range getSliceAny(vpcConfig, "SubnetIds", "subnetIds", "subnet_ids") {
					subnetID := toString(subnet)
					if subnetID == "" {
						continue
					}
					rels = append(rels, Relationship{
						SourceID:   clusterARN,
						SourceType: "aws:eks:cluster",
						TargetID:   awsARNForResource("subnet", region, accountID, subnetID),
						TargetType: "aws:ec2:subnet",
						RelType:    RelInSubnet,
					})
				}

				for _, sg := range getSliceAny(vpcConfig, "SecurityGroupIds", "securityGroupIds", "security_group_ids") {
					sgID := toString(sg)
					if sgID == "" {
						continue
					}
					rels = append(rels, Relationship{
						SourceID:   clusterARN,
						SourceType: "aws:eks:cluster",
						TargetID:   awsARNForResource("security-group", region, accountID, sgID),
						TargetType: "aws:ec2:security_group",
						RelType:    RelMemberOf,
					})
				}
			}

			if encConfigs := asSlice(queryRow(row, "encryption_config")); len(encConfigs) > 0 {
				for _, enc := range encConfigs {
					encMap := asMap(enc)
					if encMap == nil {
						continue
					}
					provider := asMap(encMap["Provider"])
					if provider == nil {
						provider = asMap(encMap["provider"])
					}
					if provider == nil {
						continue
					}
					if kmsKeyARN := getStringAny(provider, "KeyArn", "keyArn", "key_arn", "kmsKeyArn", "KMSKeyArn"); kmsKeyARN != "" {
						rels = append(rels, Relationship{
							SourceID:   clusterARN,
							SourceType: "aws:eks:cluster",
							TargetID:   kmsKeyARN,
							TargetType: "aws:kms:key",
							RelType:    RelEncryptedBy,
						})
					}
				}
			}
		}
	}

	query = `SELECT ARN, CLUSTER_NAME, REGION, ACCOUNT_ID, NODE_ROLE, SUBNETS
	         FROM AWS_EKS_NODE_GROUPS WHERE ARN IS NOT NULL`

	if result, ok, err := r.queryRowsForTable(ctx, "AWS_EKS_NODE_GROUPS", query); err != nil {
		return 0, err
	} else if ok {
		for _, row := range result.Rows {
			nodegroupARN := toString(queryRow(row, "arn"))
			if nodegroupARN == "" {
				continue
			}

			region := toString(queryRow(row, "region"))
			accountID := toString(queryRow(row, "account_id"))
			if region == "" || accountID == "" {
				arnRegion, arnAccount := awsRegionAccountFromARN(nodegroupARN)
				if region == "" {
					region = arnRegion
				}
				if accountID == "" {
					accountID = arnAccount
				}
			}

			if clusterName := toString(queryRow(row, "cluster_name")); clusterName != "" {
				if clusterARN := awsEKSClusterARN(region, accountID, clusterName); clusterARN != "" {
					rels = append(rels, Relationship{
						SourceID:   nodegroupARN,
						SourceType: "aws:eks:nodegroup",
						TargetID:   clusterARN,
						TargetType: "aws:eks:cluster",
						RelType:    RelBelongsTo,
					})
				}
			}

			if nodeRole := toString(queryRow(row, "node_role")); nodeRole != "" {
				rels = append(rels, Relationship{
					SourceID:   nodegroupARN,
					SourceType: "aws:eks:nodegroup",
					TargetID:   nodeRole,
					TargetType: "aws:iam:role",
					RelType:    RelHasRole,
				})
			}

			for _, subnet := range asSlice(queryRow(row, "subnets")) {
				subnetID := toString(subnet)
				if subnetID == "" {
					continue
				}
				rels = append(rels, Relationship{
					SourceID:   nodegroupARN,
					SourceType: "aws:eks:nodegroup",
					TargetID:   awsARNForResource("subnet", region, accountID, subnetID),
					TargetType: "aws:ec2:subnet",
					RelType:    RelInSubnet,
				})
			}
		}
	}

	query = `SELECT ARN, CLUSTER_NAME, REGION, ACCOUNT_ID, POD_EXECUTION_ROLE_ARN, SUBNETS
	         FROM AWS_EKS_FARGATE_PROFILES WHERE ARN IS NOT NULL`

	if result, ok, err := r.queryRowsForTable(ctx, "AWS_EKS_FARGATE_PROFILES", query); err != nil {
		return 0, err
	} else if ok {
		for _, row := range result.Rows {
			profileARN := toString(queryRow(row, "arn"))
			if profileARN == "" {
				continue
			}

			region := toString(queryRow(row, "region"))
			accountID := toString(queryRow(row, "account_id"))
			if region == "" || accountID == "" {
				arnRegion, arnAccount := awsRegionAccountFromARN(profileARN)
				if region == "" {
					region = arnRegion
				}
				if accountID == "" {
					accountID = arnAccount
				}
			}

			if clusterName := toString(queryRow(row, "cluster_name")); clusterName != "" {
				if clusterARN := awsEKSClusterARN(region, accountID, clusterName); clusterARN != "" {
					rels = append(rels, Relationship{
						SourceID:   profileARN,
						SourceType: "aws:eks:fargate_profile",
						TargetID:   clusterARN,
						TargetType: "aws:eks:cluster",
						RelType:    RelBelongsTo,
					})
				}
			}

			if roleARN := toString(queryRow(row, "pod_execution_role_arn")); roleARN != "" {
				rels = append(rels, Relationship{
					SourceID:   profileARN,
					SourceType: "aws:eks:fargate_profile",
					TargetID:   roleARN,
					TargetType: "aws:iam:role",
					RelType:    RelHasRole,
				})
			}

			for _, subnet := range asSlice(queryRow(row, "subnets")) {
				subnetID := toString(subnet)
				if subnetID == "" {
					continue
				}
				rels = append(rels, Relationship{
					SourceID:   profileARN,
					SourceType: "aws:eks:fargate_profile",
					TargetID:   awsARNForResource("subnet", region, accountID, subnetID),
					TargetType: "aws:ec2:subnet",
					RelType:    RelInSubnet,
				})
			}
		}
	}

	return r.persistRelationships(ctx, rels)
}

func recordRDSLookup(lookup map[string]string, region, identifier, arn string) {
	if identifier == "" || arn == "" {
		return
	}
	if region != "" {
		lookup[rdsLookupKey(region, identifier)] = arn
	}
	fallbackKey := rdsLookupKey("", identifier)
	if _, exists := lookup[fallbackKey]; !exists {
		lookup[fallbackKey] = arn
	}
}

func lookupRDSResourceARN(lookup map[string]string, region, identifier string) string {
	if identifier == "" {
		return ""
	}
	if region != "" {
		if arn, ok := lookup[rdsLookupKey(region, identifier)]; ok {
			return arn
		}
	}
	return lookup[rdsLookupKey("", identifier)]
}

func rdsLookupKey(region, identifier string) string {
	return strings.ToLower(strings.TrimSpace(region)) + "|" + strings.ToLower(strings.TrimSpace(identifier))
}

func resolveRDSEventSourceTarget(sourceType, region, accountID, sourceID string, lookupBySourceType map[string]map[string]string) (string, string) {
	resource, targetType := rdsEventSourceDescriptor(sourceType)
	if sourceID == "" || targetType == "" {
		return "", ""
	}

	normalizedType := strings.ToLower(strings.TrimSpace(sourceType))
	if lookup := lookupBySourceType[normalizedType]; len(lookup) > 0 {
		if targetARN := lookupRDSResourceARN(lookup, region, sourceID); targetARN != "" {
			return targetARN, targetType
		}
	}

	return awsRDSARN(resource, region, accountID, sourceID), targetType
}

func rdsEventSourceDescriptor(sourceType string) (resource, targetType string) {
	switch strings.ToLower(strings.TrimSpace(sourceType)) {
	case "db-instance":
		return "db", "aws:rds:db_instance"
	case "db-cluster":
		return "cluster", "aws:rds:db_cluster"
	case "db-snapshot":
		return "snapshot", "aws:rds:db_snapshot"
	case "db-cluster-snapshot":
		return "cluster-snapshot", "aws:rds:db_cluster_snapshot"
	case "db-subnet-group":
		return "subgrp", "aws:rds:db_subnet_group"
	case "db-parameter-group":
		return "pg", "aws:rds:db_parameter_group"
	case "db-cluster-parameter-group":
		return "cluster-pg", "aws:rds:db_cluster_parameter_group"
	case "db-option-group":
		return "og", "aws:rds:db_option_group"
	case "db-proxy":
		return "db-proxy", "aws:rds:db_proxy"
	case "db-security-group":
		return "secgrp", "aws:rds:db_security_group"
	default:
		return "", ""
	}
}

func awsARNForResource(resource string, region, accountID, id string) string {
	if region == "" || accountID == "" || id == "" {
		return id
	}
	return fmt.Sprintf("arn:aws:ec2:%s:%s:%s/%s", region, accountID, resource, id)
}

func awsRDSARN(resource, region, accountID, identifier string) string {
	if identifier == "" {
		return ""
	}
	if region == "" || accountID == "" {
		return identifier
	}
	return fmt.Sprintf("arn:aws:rds:%s:%s:%s:%s", region, accountID, resource, identifier)
}

func awsEKSClusterARN(region, accountID, clusterName string) string {
	if region == "" || accountID == "" || clusterName == "" {
		return ""
	}
	return fmt.Sprintf("arn:aws:eks:%s:%s:cluster/%s", region, accountID, clusterName)
}

func awsRegionAccountFromARN(arn string) (string, string) {
	parts := strings.Split(arn, ":")
	if len(parts) < 6 {
		return "", ""
	}
	return parts[3], parts[4]
}
