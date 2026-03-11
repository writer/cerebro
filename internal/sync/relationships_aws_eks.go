package sync

import "context"

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
