package sync

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
)

func (e *SyncEngine) rdsInstanceTable() TableSpec {
	return TableSpec{
		Name: "aws_rds_instances",
		Columns: []string{
			"arn", "account_id", "region", "db_instance_identifier", "db_cluster_identifier",
			"db_instance_class", "engine", "engine_version", "db_instance_status", "master_username",
			"endpoint_address", "endpoint_port", "allocated_storage", "storage_type",
			"storage_encrypted", "kms_key_id", "publicly_accessible", "vpc_security_groups",
			"db_subnet_group", "db_parameter_groups", "option_group_memberships", "associated_roles", "iam_database_authentication_enabled",
			"multi_az", "auto_minor_version_upgrade", "deletion_protection", "tags",
		},
		Fetch: e.fetchRDSInstances,
	}
}

func (e *SyncEngine) rdsClusterTable() TableSpec {
	return TableSpec{
		Name: "aws_rds_db_clusters",
		Columns: []string{
			"arn", "account_id", "region", "db_cluster_identifier", "engine", "engine_version", "status",
			"database_name", "master_username", "endpoint", "reader_endpoint", "port",
			"storage_encrypted", "kms_key_id", "iam_database_authentication_enabled",
			"db_subnet_group", "vpc_security_groups", "db_cluster_members", "db_cluster_parameter_group", "associated_roles",
			"backup_retention_period", "preferred_backup_window", "preferred_maintenance_window",
			"multi_az", "deletion_protection", "tags",
		},
		Fetch: e.fetchRDSClusters,
	}
}

func (e *SyncEngine) rdsSnapshotTable() TableSpec {
	return TableSpec{
		Name: "aws_rds_db_snapshots",
		Columns: []string{
			"arn", "account_id", "region", "db_snapshot_identifier", "db_instance_identifier", "db_cluster_identifier",
			"snapshot_type", "engine", "engine_version", "status", "snapshot_create_time", "encrypted", "kms_key_id",
			"storage_type", "tags", "is_cluster_snapshot",
		},
		Fetch: e.fetchRDSSnapshots,
	}
}

func (e *SyncEngine) rdsClusterSnapshotTable() TableSpec {
	return TableSpec{
		Name: "aws_rds_db_cluster_snapshots",
		Columns: []string{
			"arn", "account_id", "region", "db_cluster_snapshot_identifier", "db_cluster_identifier",
			"snapshot_type", "engine", "engine_version", "status", "snapshot_create_time",
			"storage_encrypted", "kms_key_id", "tags",
		},
		Fetch: e.fetchRDSClusterSnapshots,
	}
}

func (e *SyncEngine) rdsSubnetGroupTable() TableSpec {
	return TableSpec{
		Name:    "aws_rds_db_subnet_groups",
		Columns: []string{"arn", "account_id", "region", "db_subnet_group_name", "db_subnet_group_description", "status", "vpc_id", "subnets", "supported_network_types"},
		Fetch:   e.fetchRDSSubnetGroups,
	}
}

func (e *SyncEngine) rdsParameterGroupTable() TableSpec {
	return TableSpec{
		Name:    "aws_rds_db_parameter_groups",
		Columns: []string{"arn", "account_id", "region", "db_parameter_group_name", "db_parameter_group_family", "description"},
		Fetch:   e.fetchRDSParameterGroups,
	}
}

func (e *SyncEngine) rdsClusterParameterGroupTable() TableSpec {
	return TableSpec{
		Name:    "aws_rds_db_cluster_parameter_groups",
		Columns: []string{"arn", "account_id", "region", "db_cluster_parameter_group_name", "db_parameter_group_family", "description"},
		Fetch:   e.fetchRDSClusterParameterGroups,
	}
}

func (e *SyncEngine) rdsOptionGroupTable() TableSpec {
	return TableSpec{
		Name:    "aws_rds_db_option_groups",
		Columns: []string{"arn", "account_id", "region", "option_group_name", "engine_name", "major_engine_version", "description", "allows_vpc_and_non_vpc_instance_memberships", "vpc_id", "options"},
		Fetch:   e.fetchRDSOptionGroups,
	}
}

func (e *SyncEngine) rdsProxyTable() TableSpec {
	return TableSpec{
		Name: "aws_rds_db_proxies",
		Columns: []string{
			"arn", "account_id", "region", "db_proxy_name", "engine_family", "status", "role_arn",
			"vpc_id", "vpc_security_group_ids", "vpc_subnet_ids", "require_tls", "idle_client_timeout",
			"debug_logging", "endpoint", "auth", "created_date", "updated_date", "tags",
		},
		Fetch: e.fetchRDSProxies,
	}
}

func (e *SyncEngine) rdsProxyEndpointTable() TableSpec {
	return TableSpec{
		Name: "aws_rds_db_proxy_endpoints",
		Columns: []string{
			"arn", "account_id", "region", "db_proxy_endpoint_name", "db_proxy_name", "status",
			"endpoint", "target_role", "is_default", "vpc_id", "vpc_security_group_ids", "vpc_subnet_ids",
			"created_date",
		},
		Fetch: e.fetchRDSProxyEndpoints,
	}
}

func (e *SyncEngine) rdsEventSubscriptionTable() TableSpec {
	return TableSpec{
		Name: "aws_rds_event_subscriptions",
		Columns: []string{
			"arn", "account_id", "region", "subscription_id", "customer_aws_id", "enabled",
			"event_categories", "sns_topic_arn", "source_ids", "source_type", "status",
			"subscription_creation_time",
		},
		Fetch: e.fetchRDSEventSubscriptions,
	}
}

func (e *SyncEngine) fetchRDSInstances(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := rds.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	var rows []map[string]interface{}
	paginator := rds.NewDescribeDBInstancesPaginator(client, &rds.DescribeDBInstancesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, db := range page.DBInstances {
			var endpointAddr, endpointPort interface{}
			if db.Endpoint != nil {
				endpointAddr = aws.ToString(db.Endpoint.Address)
				endpointPort = db.Endpoint.Port
			}

			rows = append(rows, map[string]interface{}{
				"_cq_id":                              aws.ToString(db.DBInstanceArn),
				"arn":                                 aws.ToString(db.DBInstanceArn),
				"account_id":                          accountID,
				"region":                              region,
				"db_instance_identifier":              aws.ToString(db.DBInstanceIdentifier),
				"db_cluster_identifier":               aws.ToString(db.DBClusterIdentifier),
				"db_instance_class":                   aws.ToString(db.DBInstanceClass),
				"engine":                              aws.ToString(db.Engine),
				"engine_version":                      aws.ToString(db.EngineVersion),
				"db_instance_status":                  aws.ToString(db.DBInstanceStatus),
				"master_username":                     aws.ToString(db.MasterUsername),
				"endpoint_address":                    endpointAddr,
				"endpoint_port":                       endpointPort,
				"allocated_storage":                   db.AllocatedStorage,
				"storage_type":                        aws.ToString(db.StorageType),
				"storage_encrypted":                   db.StorageEncrypted,
				"kms_key_id":                          aws.ToString(db.KmsKeyId),
				"publicly_accessible":                 db.PubliclyAccessible,
				"vpc_security_groups":                 db.VpcSecurityGroups,
				"db_subnet_group":                     db.DBSubnetGroup,
				"db_parameter_groups":                 db.DBParameterGroups,
				"option_group_memberships":            db.OptionGroupMemberships,
				"associated_roles":                    db.AssociatedRoles,
				"iam_database_authentication_enabled": aws.ToBool(db.IAMDatabaseAuthenticationEnabled),
				"multi_az":                            db.MultiAZ,
				"auto_minor_version_upgrade":          db.AutoMinorVersionUpgrade,
				"deletion_protection":                 db.DeletionProtection,
				"tags":                                db.TagList,
			})
		}
	}
	return rows, nil
}

func (e *SyncEngine) fetchRDSClusters(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := rds.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	var rows []map[string]interface{}
	if paginator := rds.NewDescribeDBClustersPaginator(client, &rds.DescribeDBClustersInput{}); paginator != nil {
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}

			for _, cluster := range page.DBClusters {
				row := map[string]interface{}{
					"_cq_id":                              aws.ToString(cluster.DBClusterArn),
					"arn":                                 aws.ToString(cluster.DBClusterArn),
					"account_id":                          accountID,
					"region":                              region,
					"db_cluster_identifier":               aws.ToString(cluster.DBClusterIdentifier),
					"engine":                              aws.ToString(cluster.Engine),
					"engine_version":                      aws.ToString(cluster.EngineVersion),
					"status":                              aws.ToString(cluster.Status),
					"database_name":                       aws.ToString(cluster.DatabaseName),
					"master_username":                     aws.ToString(cluster.MasterUsername),
					"endpoint":                            aws.ToString(cluster.Endpoint),
					"reader_endpoint":                     aws.ToString(cluster.ReaderEndpoint),
					"port":                                cluster.Port,
					"storage_encrypted":                   cluster.StorageEncrypted,
					"kms_key_id":                          aws.ToString(cluster.KmsKeyId),
					"iam_database_authentication_enabled": cluster.IAMDatabaseAuthenticationEnabled,
					"db_subnet_group":                     aws.ToString(cluster.DBSubnetGroup),
					"vpc_security_groups":                 cluster.VpcSecurityGroups,
					"db_cluster_members":                  cluster.DBClusterMembers,
					"db_cluster_parameter_group":          aws.ToString(cluster.DBClusterParameterGroup),
					"associated_roles":                    cluster.AssociatedRoles,
					"backup_retention_period":             cluster.BackupRetentionPeriod,
					"preferred_backup_window":             aws.ToString(cluster.PreferredBackupWindow),
					"preferred_maintenance_window":        aws.ToString(cluster.PreferredMaintenanceWindow),
					"multi_az":                            cluster.MultiAZ,
					"deletion_protection":                 cluster.DeletionProtection,
					"tags":                                cluster.TagList,
				}

				rows = append(rows, row)
			}
		}
	}

	return rows, nil
}

func (e *SyncEngine) fetchRDSSnapshots(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := rds.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	var rows []map[string]interface{}
	instPager := rds.NewDescribeDBSnapshotsPaginator(client, &rds.DescribeDBSnapshotsInput{})
	for instPager.HasMorePages() {
		page, err := instPager.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, snapshot := range page.DBSnapshots {
			row := map[string]interface{}{
				"_cq_id":                 aws.ToString(snapshot.DBSnapshotArn),
				"arn":                    aws.ToString(snapshot.DBSnapshotArn),
				"account_id":             accountID,
				"region":                 region,
				"db_snapshot_identifier": aws.ToString(snapshot.DBSnapshotIdentifier),
				"db_instance_identifier": aws.ToString(snapshot.DBInstanceIdentifier),
				"snapshot_type":          aws.ToString(snapshot.SnapshotType),
				"engine":                 aws.ToString(snapshot.Engine),
				"engine_version":         aws.ToString(snapshot.EngineVersion),
				"status":                 aws.ToString(snapshot.Status),
				"snapshot_create_time":   snapshot.SnapshotCreateTime,
				"encrypted":              snapshot.Encrypted,
				"kms_key_id":             aws.ToString(snapshot.KmsKeyId),
				"storage_type":           aws.ToString(snapshot.StorageType),
				"tags":                   snapshot.TagList,
				"is_cluster_snapshot":    false,
			}

			rows = append(rows, row)
		}
	}

	clusterPager := rds.NewDescribeDBClusterSnapshotsPaginator(client, &rds.DescribeDBClusterSnapshotsInput{})
	for clusterPager.HasMorePages() {
		page, err := clusterPager.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, snapshot := range page.DBClusterSnapshots {
			row := map[string]interface{}{
				"_cq_id":                 aws.ToString(snapshot.DBClusterSnapshotArn),
				"arn":                    aws.ToString(snapshot.DBClusterSnapshotArn),
				"account_id":             accountID,
				"region":                 region,
				"db_snapshot_identifier": aws.ToString(snapshot.DBClusterSnapshotIdentifier),
				"db_cluster_identifier":  aws.ToString(snapshot.DBClusterIdentifier),
				"snapshot_type":          aws.ToString(snapshot.SnapshotType),
				"engine":                 aws.ToString(snapshot.Engine),
				"engine_version":         aws.ToString(snapshot.EngineVersion),
				"status":                 aws.ToString(snapshot.Status),
				"snapshot_create_time":   snapshot.SnapshotCreateTime,
				"encrypted":              snapshot.StorageEncrypted,
				"kms_key_id":             aws.ToString(snapshot.KmsKeyId),
				"tags":                   snapshot.TagList,
				"is_cluster_snapshot":    true,
			}

			rows = append(rows, row)
		}
	}

	return rows, nil
}

func (e *SyncEngine) fetchRDSSubnetGroups(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := rds.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	paginator := rds.NewDescribeDBSubnetGroupsPaginator(client, &rds.DescribeDBSubnetGroupsInput{})
	var rows []map[string]interface{}
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, group := range page.DBSubnetGroups {
			arn := aws.ToString(group.DBSubnetGroupArn)
			if arn == "" {
				arn = aws.ToString(group.DBSubnetGroupName)
			}

			rows = append(rows, map[string]interface{}{
				"_cq_id":                      arn,
				"arn":                         arn,
				"account_id":                  accountID,
				"region":                      region,
				"db_subnet_group_name":        aws.ToString(group.DBSubnetGroupName),
				"db_subnet_group_description": aws.ToString(group.DBSubnetGroupDescription),
				"status":                      aws.ToString(group.SubnetGroupStatus),
				"vpc_id":                      aws.ToString(group.VpcId),
				"subnets":                     group.Subnets,
				"supported_network_types":     group.SupportedNetworkTypes,
			})
		}
	}

	return rows, nil
}

func (e *SyncEngine) fetchRDSParameterGroups(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := rds.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	paginator := rds.NewDescribeDBParameterGroupsPaginator(client, &rds.DescribeDBParameterGroupsInput{})
	var rows []map[string]interface{}
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, group := range page.DBParameterGroups {
			arn := aws.ToString(group.DBParameterGroupArn)
			if arn == "" {
				arn = aws.ToString(group.DBParameterGroupName)
			}

			rows = append(rows, map[string]interface{}{
				"_cq_id":                    arn,
				"arn":                       arn,
				"account_id":                accountID,
				"region":                    region,
				"db_parameter_group_name":   aws.ToString(group.DBParameterGroupName),
				"db_parameter_group_family": aws.ToString(group.DBParameterGroupFamily),
				"description":               aws.ToString(group.Description),
			})
		}
	}

	return rows, nil
}

func (e *SyncEngine) fetchRDSOptionGroups(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := rds.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	paginator := rds.NewDescribeOptionGroupsPaginator(client, &rds.DescribeOptionGroupsInput{})
	var rows []map[string]interface{}
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, group := range page.OptionGroupsList {
			arn := aws.ToString(group.OptionGroupArn)
			if arn == "" {
				arn = aws.ToString(group.OptionGroupName)
			}

			rows = append(rows, map[string]interface{}{
				"_cq_id":               arn,
				"arn":                  arn,
				"account_id":           accountID,
				"region":               region,
				"option_group_name":    aws.ToString(group.OptionGroupName),
				"engine_name":          aws.ToString(group.EngineName),
				"major_engine_version": aws.ToString(group.MajorEngineVersion),
				"description":          aws.ToString(group.OptionGroupDescription),
				"allows_vpc_and_non_vpc_instance_memberships": group.AllowsVpcAndNonVpcInstanceMemberships,
				"vpc_id":  aws.ToString(group.VpcId),
				"options": group.Options,
			})
		}
	}

	return rows, nil
}

func (e *SyncEngine) fetchRDSClusterSnapshots(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := rds.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	paginator := rds.NewDescribeDBClusterSnapshotsPaginator(client, &rds.DescribeDBClusterSnapshotsInput{})
	var rows []map[string]interface{}
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, snapshot := range page.DBClusterSnapshots {
			arn := aws.ToString(snapshot.DBClusterSnapshotArn)
			if arn == "" {
				arn = aws.ToString(snapshot.DBClusterSnapshotIdentifier)
			}

			rows = append(rows, map[string]interface{}{
				"_cq_id":                         arn,
				"arn":                            arn,
				"account_id":                     accountID,
				"region":                         region,
				"db_cluster_snapshot_identifier": aws.ToString(snapshot.DBClusterSnapshotIdentifier),
				"db_cluster_identifier":          aws.ToString(snapshot.DBClusterIdentifier),
				"snapshot_type":                  aws.ToString(snapshot.SnapshotType),
				"engine":                         aws.ToString(snapshot.Engine),
				"engine_version":                 aws.ToString(snapshot.EngineVersion),
				"status":                         aws.ToString(snapshot.Status),
				"snapshot_create_time":           snapshot.SnapshotCreateTime,
				"storage_encrypted":              aws.ToBool(snapshot.StorageEncrypted),
				"kms_key_id":                     aws.ToString(snapshot.KmsKeyId),
				"tags":                           snapshot.TagList,
			})
		}
	}

	return rows, nil
}

func (e *SyncEngine) fetchRDSClusterParameterGroups(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := rds.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	paginator := rds.NewDescribeDBClusterParameterGroupsPaginator(client, &rds.DescribeDBClusterParameterGroupsInput{})
	var rows []map[string]interface{}
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, group := range page.DBClusterParameterGroups {
			arn := aws.ToString(group.DBClusterParameterGroupArn)
			if arn == "" {
				arn = aws.ToString(group.DBClusterParameterGroupName)
			}

			rows = append(rows, map[string]interface{}{
				"_cq_id":                          arn,
				"arn":                             arn,
				"account_id":                      accountID,
				"region":                          region,
				"db_cluster_parameter_group_name": aws.ToString(group.DBClusterParameterGroupName),
				"db_parameter_group_family":       aws.ToString(group.DBParameterGroupFamily),
				"description":                     aws.ToString(group.Description),
			})
		}
	}

	return rows, nil
}

func (e *SyncEngine) fetchRDSProxies(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := rds.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	paginator := rds.NewDescribeDBProxiesPaginator(client, &rds.DescribeDBProxiesInput{})
	var rows []map[string]interface{}
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, proxy := range page.DBProxies {
			arn := aws.ToString(proxy.DBProxyArn)
			if arn == "" {
				arn = aws.ToString(proxy.DBProxyName)
			}

			var tags interface{}
			if arn != "" {
				tagOut, err := client.ListTagsForResource(ctx, &rds.ListTagsForResourceInput{
					ResourceName: aws.String(arn),
				})
				if err == nil {
					tags = tagOut.TagList
				}
			}

			rows = append(rows, map[string]interface{}{
				"_cq_id":                 arn,
				"arn":                    arn,
				"account_id":             accountID,
				"region":                 region,
				"db_proxy_name":          aws.ToString(proxy.DBProxyName),
				"engine_family":          aws.ToString(proxy.EngineFamily),
				"status":                 string(proxy.Status),
				"role_arn":               aws.ToString(proxy.RoleArn),
				"vpc_id":                 aws.ToString(proxy.VpcId),
				"vpc_security_group_ids": proxy.VpcSecurityGroupIds,
				"vpc_subnet_ids":         proxy.VpcSubnetIds,
				"require_tls":            aws.ToBool(proxy.RequireTLS),
				"idle_client_timeout":    proxy.IdleClientTimeout,
				"debug_logging":          aws.ToBool(proxy.DebugLogging),
				"endpoint":               aws.ToString(proxy.Endpoint),
				"auth":                   proxy.Auth,
				"created_date":           proxy.CreatedDate,
				"updated_date":           proxy.UpdatedDate,
				"tags":                   tags,
			})
		}
	}

	return rows, nil
}

func (e *SyncEngine) fetchRDSProxyEndpoints(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := rds.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	paginator := rds.NewDescribeDBProxyEndpointsPaginator(client, &rds.DescribeDBProxyEndpointsInput{})
	var rows []map[string]interface{}
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, endpoint := range page.DBProxyEndpoints {
			arn := aws.ToString(endpoint.DBProxyEndpointArn)
			if arn == "" {
				arn = aws.ToString(endpoint.DBProxyEndpointName)
			}

			rows = append(rows, map[string]interface{}{
				"_cq_id":                 arn,
				"arn":                    arn,
				"account_id":             accountID,
				"region":                 region,
				"db_proxy_endpoint_name": aws.ToString(endpoint.DBProxyEndpointName),
				"db_proxy_name":          aws.ToString(endpoint.DBProxyName),
				"status":                 string(endpoint.Status),
				"endpoint":               aws.ToString(endpoint.Endpoint),
				"target_role":            string(endpoint.TargetRole),
				"is_default":             aws.ToBool(endpoint.IsDefault),
				"vpc_id":                 aws.ToString(endpoint.VpcId),
				"vpc_security_group_ids": endpoint.VpcSecurityGroupIds,
				"vpc_subnet_ids":         endpoint.VpcSubnetIds,
				"created_date":           endpoint.CreatedDate,
			})
		}
	}

	return rows, nil
}

func (e *SyncEngine) fetchRDSEventSubscriptions(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := rds.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	paginator := rds.NewDescribeEventSubscriptionsPaginator(client, &rds.DescribeEventSubscriptionsInput{})
	var rows []map[string]interface{}
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, subscription := range page.EventSubscriptionsList {
			arn := aws.ToString(subscription.EventSubscriptionArn)
			if arn == "" {
				arn = aws.ToString(subscription.CustSubscriptionId)
			}

			rows = append(rows, map[string]interface{}{
				"_cq_id":                     arn,
				"arn":                        arn,
				"account_id":                 accountID,
				"region":                     region,
				"subscription_id":            aws.ToString(subscription.CustSubscriptionId),
				"customer_aws_id":            aws.ToString(subscription.CustomerAwsId),
				"enabled":                    aws.ToBool(subscription.Enabled),
				"event_categories":           subscription.EventCategoriesList,
				"sns_topic_arn":              aws.ToString(subscription.SnsTopicArn),
				"source_ids":                 subscription.SourceIdsList,
				"source_type":                aws.ToString(subscription.SourceType),
				"status":                     aws.ToString(subscription.Status),
				"subscription_creation_time": aws.ToString(subscription.SubscriptionCreationTime),
			})
		}
	}

	return rows, nil
}
