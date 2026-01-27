package sync

import (
	"context"
	"encoding/json"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/docdb"
)

// DocumentDB Clusters table
func (e *SyncEngine) docdbClusterTable() TableSpec {
	return TableSpec{
		Name: "aws_docdb_clusters",
		Columns: []string{
			"_cq_hash", "arn", "db_cluster_identifier", "account_id", "region",
			"availability_zones", "backup_retention_period", "clone_group_id",
			"cluster_create_time", "db_cluster_arn", "db_cluster_members",
			"db_cluster_parameter_group", "db_cluster_resource_id",
			"db_subnet_group", "deletion_protection", "earliest_restorable_time",
			"enabled_cloudwatch_logs_exports", "endpoint", "engine",
			"engine_version", "hosted_zone_id", "kms_key_id",
			"latest_restorable_time", "master_username", "multi_az",
			"percent_progress", "port", "preferred_backup_window",
			"preferred_maintenance_window", "read_replica_identifiers",
			"reader_endpoint", "replication_source_identifier", "status",
			"storage_encrypted", "storage_type", "vpc_security_groups",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := docdb.NewFromConfig(cfg, func(o *docdb.Options) {
				o.Region = region
			})
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			paginator := docdb.NewDescribeDBClustersPaginator(client, &docdb.DescribeDBClustersInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, err
				}

				for _, cluster := range page.DBClusters {
					azJSON, _ := json.Marshal(cluster.AvailabilityZones)
					membersJSON, _ := json.Marshal(cluster.DBClusterMembers)
					logsJSON, _ := json.Marshal(cluster.EnabledCloudwatchLogsExports)
					replicasJSON, _ := json.Marshal(cluster.ReadReplicaIdentifiers)
					vpcSGJSON, _ := json.Marshal(cluster.VpcSecurityGroups)

					row := map[string]interface{}{
						"arn":                             aws.ToString(cluster.DBClusterArn),
						"db_cluster_identifier":           aws.ToString(cluster.DBClusterIdentifier),
						"account_id":                      accountID,
						"region":                          region,
						"availability_zones":              string(azJSON),
						"backup_retention_period":         cluster.BackupRetentionPeriod,
						"clone_group_id":                  aws.ToString(cluster.CloneGroupId),
						"cluster_create_time":             timeToString(cluster.ClusterCreateTime),
						"db_cluster_arn":                  aws.ToString(cluster.DBClusterArn),
						"db_cluster_members":              string(membersJSON),
						"db_cluster_parameter_group":      aws.ToString(cluster.DBClusterParameterGroup),
						"db_cluster_resource_id":          aws.ToString(cluster.DbClusterResourceId),
						"db_subnet_group":                 aws.ToString(cluster.DBSubnetGroup),
						"deletion_protection":             cluster.DeletionProtection,
						"earliest_restorable_time":        timeToString(cluster.EarliestRestorableTime),
						"enabled_cloudwatch_logs_exports": string(logsJSON),
						"endpoint":                        aws.ToString(cluster.Endpoint),
						"engine":                          aws.ToString(cluster.Engine),
						"engine_version":                  aws.ToString(cluster.EngineVersion),
						"hosted_zone_id":                  aws.ToString(cluster.HostedZoneId),
						"kms_key_id":                      aws.ToString(cluster.KmsKeyId),
						"latest_restorable_time":          timeToString(cluster.LatestRestorableTime),
						"master_username":                 aws.ToString(cluster.MasterUsername),
						"multi_az":                        cluster.MultiAZ,
						"percent_progress":                aws.ToString(cluster.PercentProgress),
						"port":                            cluster.Port,
						"preferred_backup_window":         aws.ToString(cluster.PreferredBackupWindow),
						"preferred_maintenance_window":    aws.ToString(cluster.PreferredMaintenanceWindow),
						"read_replica_identifiers":        string(replicasJSON),
						"reader_endpoint":                 aws.ToString(cluster.ReaderEndpoint),
						"replication_source_identifier":   aws.ToString(cluster.ReplicationSourceIdentifier),
						"status":                          aws.ToString(cluster.Status),
						"storage_encrypted":               cluster.StorageEncrypted,
						"storage_type":                    aws.ToString(cluster.StorageType),
						"vpc_security_groups":             string(vpcSGJSON),
					}
					results = append(results, row)
				}
			}
			return results, nil
		},
	}
}

// DocumentDB Instances table
func (e *SyncEngine) docdbInstanceTable() TableSpec {
	return TableSpec{
		Name: "aws_docdb_instances",
		Columns: []string{
			"_cq_hash", "arn", "db_instance_identifier", "account_id", "region",
			"auto_minor_version_upgrade", "availability_zone", "backup_retention_period",
			"ca_certificate_identifier", "copy_tags_to_snapshot",
			"db_cluster_identifier", "db_instance_arn", "db_instance_class",
			"db_instance_status", "db_subnet_group", "dbi_resource_id",
			"enabled_cloudwatch_logs_exports", "endpoint", "engine",
			"engine_version", "instance_create_time", "kms_key_id",
			"latest_restorable_time", "pending_modified_values",
			"preferred_backup_window", "preferred_maintenance_window",
			"promotion_tier", "publicly_accessible", "status_infos",
			"storage_encrypted", "vpc_security_groups",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := docdb.NewFromConfig(cfg, func(o *docdb.Options) {
				o.Region = region
			})
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			paginator := docdb.NewDescribeDBInstancesPaginator(client, &docdb.DescribeDBInstancesInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, err
				}

				for _, instance := range page.DBInstances {
					logsJSON, _ := json.Marshal(instance.EnabledCloudwatchLogsExports)
					endpointJSON, _ := json.Marshal(instance.Endpoint)
					pendingJSON, _ := json.Marshal(instance.PendingModifiedValues)
					statusJSON, _ := json.Marshal(instance.StatusInfos)
					subnetJSON, _ := json.Marshal(instance.DBSubnetGroup)
					vpcSGJSON, _ := json.Marshal(instance.VpcSecurityGroups)

					row := map[string]interface{}{
						"arn":                             aws.ToString(instance.DBInstanceArn),
						"db_instance_identifier":          aws.ToString(instance.DBInstanceIdentifier),
						"account_id":                      accountID,
						"region":                          region,
						"auto_minor_version_upgrade":      instance.AutoMinorVersionUpgrade,
						"availability_zone":               aws.ToString(instance.AvailabilityZone),
						"backup_retention_period":         instance.BackupRetentionPeriod,
						"ca_certificate_identifier":       aws.ToString(instance.CACertificateIdentifier),
						"copy_tags_to_snapshot":           instance.CopyTagsToSnapshot,
						"db_cluster_identifier":           aws.ToString(instance.DBClusterIdentifier),
						"db_instance_arn":                 aws.ToString(instance.DBInstanceArn),
						"db_instance_class":               aws.ToString(instance.DBInstanceClass),
						"db_instance_status":              aws.ToString(instance.DBInstanceStatus),
						"db_subnet_group":                 string(subnetJSON),
						"dbi_resource_id":                 aws.ToString(instance.DbiResourceId),
						"enabled_cloudwatch_logs_exports": string(logsJSON),
						"endpoint":                        string(endpointJSON),
						"engine":                          aws.ToString(instance.Engine),
						"engine_version":                  aws.ToString(instance.EngineVersion),
						"instance_create_time":            timeToString(instance.InstanceCreateTime),
						"kms_key_id":                      aws.ToString(instance.KmsKeyId),
						"latest_restorable_time":          timeToString(instance.LatestRestorableTime),
						"pending_modified_values":         string(pendingJSON),
						"preferred_backup_window":         aws.ToString(instance.PreferredBackupWindow),
						"preferred_maintenance_window":    aws.ToString(instance.PreferredMaintenanceWindow),
						"promotion_tier":                  instance.PromotionTier,
						"publicly_accessible":             instance.PubliclyAccessible,
						"status_infos":                    string(statusJSON),
						"storage_encrypted":               instance.StorageEncrypted,
						"vpc_security_groups":             string(vpcSGJSON),
					}
					results = append(results, row)
				}
			}
			return results, nil
		},
	}
}
