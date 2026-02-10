package sync

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
)

func (e *SyncEngine) rdsInstanceTable() TableSpec {
	return TableSpec{
		Name:    "aws_rds_instances",
		Columns: []string{"arn", "account_id", "region", "db_instance_identifier", "db_instance_class", "engine", "engine_version", "db_instance_status", "master_username", "endpoint_address", "endpoint_port", "allocated_storage", "storage_type", "storage_encrypted", "kms_key_id", "publicly_accessible", "vpc_security_groups", "db_subnet_group", "multi_az", "auto_minor_version_upgrade", "deletion_protection", "tags"},
		Fetch:   e.fetchRDSInstances,
	}
}

func (e *SyncEngine) rdsClusterTable() TableSpec {
	return TableSpec{
		Name: "aws_rds_db_clusters",
		Columns: []string{
			"arn", "account_id", "region", "db_cluster_identifier", "engine", "engine_version", "status",
			"database_name", "master_username", "endpoint", "reader_endpoint", "port",
			"storage_encrypted", "kms_key_id", "iam_database_authentication_enabled",
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
				"_cq_id":                     aws.ToString(db.DBInstanceArn),
				"arn":                        aws.ToString(db.DBInstanceArn),
				"account_id":                 accountID,
				"region":                     region,
				"db_instance_identifier":     aws.ToString(db.DBInstanceIdentifier),
				"db_instance_class":          aws.ToString(db.DBInstanceClass),
				"engine":                     aws.ToString(db.Engine),
				"engine_version":             aws.ToString(db.EngineVersion),
				"db_instance_status":         aws.ToString(db.DBInstanceStatus),
				"master_username":            aws.ToString(db.MasterUsername),
				"endpoint_address":           endpointAddr,
				"endpoint_port":              endpointPort,
				"allocated_storage":          db.AllocatedStorage,
				"storage_type":               aws.ToString(db.StorageType),
				"storage_encrypted":          db.StorageEncrypted,
				"kms_key_id":                 aws.ToString(db.KmsKeyId),
				"publicly_accessible":        db.PubliclyAccessible,
				"vpc_security_groups":        db.VpcSecurityGroups,
				"db_subnet_group":            db.DBSubnetGroup,
				"multi_az":                   db.MultiAZ,
				"auto_minor_version_upgrade": db.AutoMinorVersionUpgrade,
				"deletion_protection":        db.DeletionProtection,
				"tags":                       db.TagList,
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
