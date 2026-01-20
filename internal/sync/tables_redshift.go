package sync

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
)

func (e *SyncEngine) redshiftClusterTable() TableSpec {
	return TableSpec{
		Name:    "aws_redshift_clusters",
		Columns: []string{"arn", "account_id", "region", "cluster_identifier", "node_type", "cluster_status", "master_username", "db_name", "endpoint_address", "endpoint_port", "cluster_create_time", "automated_snapshot_retention_period", "cluster_security_groups", "vpc_security_groups", "cluster_parameter_groups", "cluster_subnet_group_name", "vpc_id", "availability_zone", "preferred_maintenance_window", "cluster_version", "allow_version_upgrade", "number_of_nodes", "publicly_accessible", "encrypted", "kms_key_id", "enhanced_vpc_routing", "iam_roles", "tags"},
		Fetch:   e.fetchRedshiftClusters,
	}
}

func (e *SyncEngine) fetchRedshiftClusters(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := redshift.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	var rows []map[string]interface{}
	paginator := redshift.NewDescribeClustersPaginator(client, &redshift.DescribeClustersInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, cluster := range page.Clusters {
			clusterID := aws.ToString(cluster.ClusterIdentifier)

			row := map[string]interface{}{
				"_cq_id":                              aws.ToString(cluster.ClusterNamespaceArn),
				"arn":                                 aws.ToString(cluster.ClusterNamespaceArn),
				"account_id":                          accountID,
				"region":                              region,
				"cluster_identifier":                  clusterID,
				"node_type":                           aws.ToString(cluster.NodeType),
				"cluster_status":                      aws.ToString(cluster.ClusterStatus),
				"master_username":                     aws.ToString(cluster.MasterUsername),
				"db_name":                             aws.ToString(cluster.DBName),
				"cluster_create_time":                 cluster.ClusterCreateTime,
				"automated_snapshot_retention_period": cluster.AutomatedSnapshotRetentionPeriod,
				"cluster_security_groups":             cluster.ClusterSecurityGroups,
				"vpc_security_groups":                 cluster.VpcSecurityGroups,
				"cluster_parameter_groups":            cluster.ClusterParameterGroups,
				"cluster_subnet_group_name":           aws.ToString(cluster.ClusterSubnetGroupName),
				"vpc_id":                              aws.ToString(cluster.VpcId),
				"availability_zone":                   aws.ToString(cluster.AvailabilityZone),
				"preferred_maintenance_window":        aws.ToString(cluster.PreferredMaintenanceWindow),
				"cluster_version":                     aws.ToString(cluster.ClusterVersion),
				"allow_version_upgrade":               cluster.AllowVersionUpgrade,
				"number_of_nodes":                     cluster.NumberOfNodes,
				"publicly_accessible":                 cluster.PubliclyAccessible,
				"encrypted":                           cluster.Encrypted,
				"kms_key_id":                          aws.ToString(cluster.KmsKeyId),
				"enhanced_vpc_routing":                cluster.EnhancedVpcRouting,
				"iam_roles":                           cluster.IamRoles,
				"tags":                                cluster.Tags,
			}

			if cluster.Endpoint != nil {
				row["endpoint_address"] = aws.ToString(cluster.Endpoint.Address)
				row["endpoint_port"] = cluster.Endpoint.Port
			}

			rows = append(rows, row)
		}
	}
	return rows, nil
}
