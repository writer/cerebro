package sync

import (
	"context"
	"encoding/json"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/neptune"
)

// Neptune Clusters table
func (e *SyncEngine) neptuneClusterTable() TableSpec {
	return TableSpec{
		Name: "aws_neptune_clusters",
		Columns: []string{
			"_cq_hash", "arn", "db_cluster_identifier", "account_id", "region",
			"allocated_storage", "associated_roles", "automatic_restart_time",
			"availability_zones", "backup_retention_period", "cluster_create_time",
			"copy_tags_to_snapshot", "cross_account_clone", "db_cluster_arn",
			"db_cluster_members", "db_cluster_parameter_group",
			"db_cluster_resource_id", "db_subnet_group", "deletion_protection",
			"earliest_restorable_time", "enabled_cloudwatch_logs_exports",
			"endpoint", "engine", "engine_version", "global_cluster_identifier",
			"hosted_zone_id", "iam_database_authentication_enabled", "io_optimized_next_allowed_modification_time",
			"kms_key_id", "latest_restorable_time", "master_username",
			"multi_az", "pending_modified_values", "percent_progress", "port",
			"preferred_backup_window", "preferred_maintenance_window",
			"read_replica_identifiers", "reader_endpoint",
			"replication_source_identifier", "serverless_v2_scaling_configuration",
			"status", "storage_encrypted", "storage_type", "vpc_security_groups",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := neptune.NewFromConfig(cfg, func(o *neptune.Options) {
				o.Region = region
			})
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			paginator := neptune.NewDescribeDBClustersPaginator(client, &neptune.DescribeDBClustersInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, err
				}

				for _, cluster := range page.DBClusters {
					rolesJSON, _ := json.Marshal(cluster.AssociatedRoles)
					azJSON, _ := json.Marshal(cluster.AvailabilityZones)
					membersJSON, _ := json.Marshal(cluster.DBClusterMembers)
					logsJSON, _ := json.Marshal(cluster.EnabledCloudwatchLogsExports)
					pendingJSON, _ := json.Marshal(cluster.PendingModifiedValues)
					replicasJSON, _ := json.Marshal(cluster.ReadReplicaIdentifiers)
					serverlessJSON, _ := json.Marshal(cluster.ServerlessV2ScalingConfiguration)
					vpcSGJSON, _ := json.Marshal(cluster.VpcSecurityGroups)

					row := map[string]interface{}{
						"arn":                                         aws.ToString(cluster.DBClusterArn),
						"db_cluster_identifier":                       aws.ToString(cluster.DBClusterIdentifier),
						"account_id":                                  accountID,
						"region":                                      region,
						"allocated_storage":                           cluster.AllocatedStorage,
						"associated_roles":                            string(rolesJSON),
						"automatic_restart_time":                      timeToString(cluster.AutomaticRestartTime),
						"availability_zones":                          string(azJSON),
						"backup_retention_period":                     cluster.BackupRetentionPeriod,
						"cluster_create_time":                         timeToString(cluster.ClusterCreateTime),
						"copy_tags_to_snapshot":                       cluster.CopyTagsToSnapshot,
						"cross_account_clone":                         cluster.CrossAccountClone,
						"db_cluster_arn":                              aws.ToString(cluster.DBClusterArn),
						"db_cluster_members":                          string(membersJSON),
						"db_cluster_parameter_group":                  aws.ToString(cluster.DBClusterParameterGroup),
						"db_cluster_resource_id":                      aws.ToString(cluster.DbClusterResourceId),
						"db_subnet_group":                             aws.ToString(cluster.DBSubnetGroup),
						"deletion_protection":                         cluster.DeletionProtection,
						"earliest_restorable_time":                    timeToString(cluster.EarliestRestorableTime),
						"enabled_cloudwatch_logs_exports":             string(logsJSON),
						"endpoint":                                    aws.ToString(cluster.Endpoint),
						"engine":                                      aws.ToString(cluster.Engine),
						"engine_version":                              aws.ToString(cluster.EngineVersion),
						"global_cluster_identifier":                   aws.ToString(cluster.GlobalClusterIdentifier),
						"hosted_zone_id":                              aws.ToString(cluster.HostedZoneId),
						"iam_database_authentication_enabled":         cluster.IAMDatabaseAuthenticationEnabled,
						"io_optimized_next_allowed_modification_time": timeToString(cluster.IOOptimizedNextAllowedModificationTime),
						"kms_key_id":                                  aws.ToString(cluster.KmsKeyId),
						"latest_restorable_time":                      timeToString(cluster.LatestRestorableTime),
						"master_username":                             aws.ToString(cluster.MasterUsername),
						"multi_az":                                    cluster.MultiAZ,
						"pending_modified_values":                     string(pendingJSON),
						"percent_progress":                            aws.ToString(cluster.PercentProgress),
						"port":                                        cluster.Port,
						"preferred_backup_window":                     aws.ToString(cluster.PreferredBackupWindow),
						"preferred_maintenance_window":                aws.ToString(cluster.PreferredMaintenanceWindow),
						"read_replica_identifiers":                    string(replicasJSON),
						"reader_endpoint":                             aws.ToString(cluster.ReaderEndpoint),
						"replication_source_identifier":               aws.ToString(cluster.ReplicationSourceIdentifier),
						"serverless_v2_scaling_configuration":         string(serverlessJSON),
						"status":                                      aws.ToString(cluster.Status),
						"storage_encrypted":                           cluster.StorageEncrypted,
						"storage_type":                                aws.ToString(cluster.StorageType),
						"vpc_security_groups":                         string(vpcSGJSON),
					}
					results = append(results, row)
				}
			}
			return results, nil
		},
	}
}

// Neptune Instances table
func (e *SyncEngine) neptuneInstanceTable() TableSpec {
	return TableSpec{
		Name: "aws_neptune_instances",
		Columns: []string{
			"_cq_hash", "arn", "db_instance_identifier", "account_id", "region",
			"auto_minor_version_upgrade", "availability_zone",
			"ca_certificate_identifier", "copy_tags_to_snapshot",
			"db_cluster_identifier", "db_instance_arn", "db_instance_class",
			"db_instance_status", "db_parameter_groups", "db_security_groups",
			"db_subnet_group", "dbi_resource_id", "deletion_protection",
			"enabled_cloudwatch_logs_exports", "endpoint", "engine",
			"engine_version", "enhanced_monitoring_resource_arn",
			"instance_create_time", "kms_key_id", "latest_restorable_time",
			"license_model", "monitoring_interval", "monitoring_role_arn",
			"multi_az", "pending_modified_values", "preferred_backup_window",
			"preferred_maintenance_window", "promotion_tier",
			"publicly_accessible", "status_infos", "storage_encrypted",
			"storage_type", "vpc_security_groups",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := neptune.NewFromConfig(cfg, func(o *neptune.Options) {
				o.Region = region
			})
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			paginator := neptune.NewDescribeDBInstancesPaginator(client, &neptune.DescribeDBInstancesInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, err
				}

				for _, instance := range page.DBInstances {
					paramGroupsJSON, _ := json.Marshal(instance.DBParameterGroups)
					secGroupsJSON, _ := json.Marshal(instance.DBSecurityGroups)
					subnetJSON, _ := json.Marshal(instance.DBSubnetGroup)
					logsJSON, _ := json.Marshal(instance.EnabledCloudwatchLogsExports)
					endpointJSON, _ := json.Marshal(instance.Endpoint)
					pendingJSON, _ := json.Marshal(instance.PendingModifiedValues)
					statusJSON, _ := json.Marshal(instance.StatusInfos)
					vpcSGJSON, _ := json.Marshal(instance.VpcSecurityGroups)

					row := map[string]interface{}{
						"arn":                              aws.ToString(instance.DBInstanceArn),
						"db_instance_identifier":           aws.ToString(instance.DBInstanceIdentifier),
						"account_id":                       accountID,
						"region":                           region,
						"auto_minor_version_upgrade":       instance.AutoMinorVersionUpgrade,
						"availability_zone":                aws.ToString(instance.AvailabilityZone),
						"ca_certificate_identifier":        aws.ToString(instance.CACertificateIdentifier),
						"copy_tags_to_snapshot":            instance.CopyTagsToSnapshot,
						"db_cluster_identifier":            aws.ToString(instance.DBClusterIdentifier),
						"db_instance_arn":                  aws.ToString(instance.DBInstanceArn),
						"db_instance_class":                aws.ToString(instance.DBInstanceClass),
						"db_instance_status":               aws.ToString(instance.DBInstanceStatus),
						"db_parameter_groups":              string(paramGroupsJSON),
						"db_security_groups":               string(secGroupsJSON),
						"db_subnet_group":                  string(subnetJSON),
						"dbi_resource_id":                  aws.ToString(instance.DbiResourceId),
						"deletion_protection":              instance.DeletionProtection,
						"enabled_cloudwatch_logs_exports":  string(logsJSON),
						"endpoint":                         string(endpointJSON),
						"engine":                           aws.ToString(instance.Engine),
						"engine_version":                   aws.ToString(instance.EngineVersion),
						"enhanced_monitoring_resource_arn": aws.ToString(instance.EnhancedMonitoringResourceArn),
						"instance_create_time":             timeToString(instance.InstanceCreateTime),
						"kms_key_id":                       aws.ToString(instance.KmsKeyId),
						"latest_restorable_time":           timeToString(instance.LatestRestorableTime),
						"license_model":                    aws.ToString(instance.LicenseModel),
						"monitoring_interval":              instance.MonitoringInterval,
						"monitoring_role_arn":              aws.ToString(instance.MonitoringRoleArn),
						"multi_az":                         instance.MultiAZ,
						"pending_modified_values":          string(pendingJSON),
						"preferred_backup_window":          aws.ToString(instance.PreferredBackupWindow),
						"preferred_maintenance_window":     aws.ToString(instance.PreferredMaintenanceWindow),
						"promotion_tier":                   instance.PromotionTier,
						"publicly_accessible":              instance.PubliclyAccessible,
						"status_infos":                     string(statusJSON),
						"storage_encrypted":                instance.StorageEncrypted,
						"storage_type":                     aws.ToString(instance.StorageType),
						"vpc_security_groups":              string(vpcSGJSON),
					}
					results = append(results, row)
				}
			}
			return results, nil
		},
	}
}
