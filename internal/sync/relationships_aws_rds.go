package sync

import (
	"context"
	"fmt"
)

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
