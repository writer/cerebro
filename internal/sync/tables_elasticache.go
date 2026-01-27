package sync

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
)

// ElastiCache Clusters
func (e *SyncEngine) elasticacheClusterTable() TableSpec {
	return TableSpec{
		Name:    "aws_elasticache_clusters",
		Columns: []string{"arn", "account_id", "region", "cache_cluster_id", "cache_cluster_status", "cache_node_type", "engine", "engine_version", "num_cache_nodes", "preferred_availability_zone", "cache_subnet_group_name", "security_groups", "cache_parameter_group", "auto_minor_version_upgrade", "snapshot_retention_limit", "snapshot_window", "auth_token_enabled", "transit_encryption_enabled", "at_rest_encryption_enabled"},
		Fetch:   e.fetchElastiCacheClusters,
	}
}

func (e *SyncEngine) fetchElastiCacheClusters(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := elasticache.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	var rows []map[string]interface{}
	paginator := elasticache.NewDescribeCacheClustersPaginator(client, &elasticache.DescribeCacheClustersInput{
		ShowCacheNodeInfo: aws.Bool(true),
	})

	for paginator.HasMorePages() {
		out, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, cluster := range out.CacheClusters {
			clusterID := aws.ToString(cluster.CacheClusterId)
			clusterArn := aws.ToString(cluster.ARN)
			if clusterArn == "" {
				clusterArn = fmt.Sprintf("arn:aws:elasticache:%s:%s:cluster:%s", region, accountID, clusterID)
			}

			var securityGroups []string
			for _, sg := range cluster.SecurityGroups {
				securityGroups = append(securityGroups, aws.ToString(sg.SecurityGroupId))
			}

			var paramGroup string
			if cluster.CacheParameterGroup != nil {
				paramGroup = aws.ToString(cluster.CacheParameterGroup.CacheParameterGroupName)
			}

			rows = append(rows, map[string]interface{}{
				"_cq_id":                      clusterArn,
				"arn":                         clusterArn,
				"account_id":                  accountID,
				"region":                      region,
				"cache_cluster_id":            clusterID,
				"cache_cluster_status":        aws.ToString(cluster.CacheClusterStatus),
				"cache_node_type":             aws.ToString(cluster.CacheNodeType),
				"engine":                      aws.ToString(cluster.Engine),
				"engine_version":              aws.ToString(cluster.EngineVersion),
				"num_cache_nodes":             cluster.NumCacheNodes,
				"preferred_availability_zone": aws.ToString(cluster.PreferredAvailabilityZone),
				"cache_subnet_group_name":     aws.ToString(cluster.CacheSubnetGroupName),
				"security_groups":             securityGroups,
				"cache_parameter_group":       paramGroup,
				"auto_minor_version_upgrade":  aws.ToBool(cluster.AutoMinorVersionUpgrade),
				"snapshot_retention_limit":    cluster.SnapshotRetentionLimit,
				"snapshot_window":             aws.ToString(cluster.SnapshotWindow),
				"auth_token_enabled":          aws.ToBool(cluster.AuthTokenEnabled),
				"transit_encryption_enabled":  aws.ToBool(cluster.TransitEncryptionEnabled),
				"at_rest_encryption_enabled":  aws.ToBool(cluster.AtRestEncryptionEnabled),
			})
		}
	}
	return rows, nil
}

// ElastiCache Replication Groups
func (e *SyncEngine) elasticacheReplicationGroupTable() TableSpec {
	return TableSpec{
		Name:    "aws_elasticache_replication_groups",
		Columns: []string{"arn", "account_id", "region", "replication_group_id", "description", "status", "automatic_failover", "multi_az", "cache_node_type", "auth_token_enabled", "transit_encryption_enabled", "at_rest_encryption_enabled", "kms_key_id", "snapshot_retention_limit", "cluster_enabled", "member_clusters"},
		Fetch:   e.fetchElastiCacheReplicationGroups,
	}
}

func (e *SyncEngine) fetchElastiCacheReplicationGroups(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := elasticache.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	var rows []map[string]interface{}
	paginator := elasticache.NewDescribeReplicationGroupsPaginator(client, &elasticache.DescribeReplicationGroupsInput{})

	for paginator.HasMorePages() {
		out, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, rg := range out.ReplicationGroups {
			rgID := aws.ToString(rg.ReplicationGroupId)
			rgArn := aws.ToString(rg.ARN)
			if rgArn == "" {
				rgArn = fmt.Sprintf("arn:aws:elasticache:%s:%s:replicationgroup:%s", region, accountID, rgID)
			}

			rows = append(rows, map[string]interface{}{
				"_cq_id":                     rgArn,
				"arn":                        rgArn,
				"account_id":                 accountID,
				"region":                     region,
				"replication_group_id":       rgID,
				"description":                aws.ToString(rg.Description),
				"status":                     aws.ToString(rg.Status),
				"automatic_failover":         string(rg.AutomaticFailover),
				"multi_az":                   string(rg.MultiAZ),
				"cache_node_type":            aws.ToString(rg.CacheNodeType),
				"auth_token_enabled":         aws.ToBool(rg.AuthTokenEnabled),
				"transit_encryption_enabled": aws.ToBool(rg.TransitEncryptionEnabled),
				"at_rest_encryption_enabled": aws.ToBool(rg.AtRestEncryptionEnabled),
				"kms_key_id":                 aws.ToString(rg.KmsKeyId),
				"snapshot_retention_limit":   rg.SnapshotRetentionLimit,
				"cluster_enabled":            aws.ToBool(rg.ClusterEnabled),
				"member_clusters":            rg.MemberClusters,
			})
		}
	}
	return rows, nil
}

// ElastiCache Subnet Groups
func (e *SyncEngine) elasticacheSubnetGroupTable() TableSpec {
	return TableSpec{
		Name:    "aws_elasticache_subnet_groups",
		Columns: []string{"arn", "account_id", "region", "cache_subnet_group_name", "cache_subnet_group_description", "vpc_id", "subnets"},
		Fetch:   e.fetchElastiCacheSubnetGroups,
	}
}

func (e *SyncEngine) fetchElastiCacheSubnetGroups(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := elasticache.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	var rows []map[string]interface{}
	paginator := elasticache.NewDescribeCacheSubnetGroupsPaginator(client, &elasticache.DescribeCacheSubnetGroupsInput{})

	for paginator.HasMorePages() {
		out, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, sg := range out.CacheSubnetGroups {
			sgName := aws.ToString(sg.CacheSubnetGroupName)
			sgArn := aws.ToString(sg.ARN)
			if sgArn == "" {
				sgArn = fmt.Sprintf("arn:aws:elasticache:%s:%s:subnetgroup:%s", region, accountID, sgName)
			}

			var subnets []map[string]interface{}
			for _, subnet := range sg.Subnets {
				subnets = append(subnets, map[string]interface{}{
					"subnet_identifier":        aws.ToString(subnet.SubnetIdentifier),
					"subnet_availability_zone": aws.ToString(subnet.SubnetAvailabilityZone.Name),
				})
			}

			rows = append(rows, map[string]interface{}{
				"_cq_id":                         sgArn,
				"arn":                            sgArn,
				"account_id":                     accountID,
				"region":                         region,
				"cache_subnet_group_name":        sgName,
				"cache_subnet_group_description": aws.ToString(sg.CacheSubnetGroupDescription),
				"vpc_id":                         aws.ToString(sg.VpcId),
				"subnets":                        subnets,
			})
		}
	}
	return rows, nil
}

// ElastiCache Parameter Groups
func (e *SyncEngine) elasticacheParameterGroupTable() TableSpec {
	return TableSpec{
		Name:    "aws_elasticache_parameter_groups",
		Columns: []string{"arn", "account_id", "region", "cache_parameter_group_name", "cache_parameter_group_family", "description", "is_global"},
		Fetch:   e.fetchElastiCacheParameterGroups,
	}
}

func (e *SyncEngine) fetchElastiCacheParameterGroups(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := elasticache.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	var rows []map[string]interface{}
	paginator := elasticache.NewDescribeCacheParameterGroupsPaginator(client, &elasticache.DescribeCacheParameterGroupsInput{})

	for paginator.HasMorePages() {
		out, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, pg := range out.CacheParameterGroups {
			pgName := aws.ToString(pg.CacheParameterGroupName)
			pgArn := aws.ToString(pg.ARN)
			if pgArn == "" {
				pgArn = fmt.Sprintf("arn:aws:elasticache:%s:%s:parametergroup:%s", region, accountID, pgName)
			}

			rows = append(rows, map[string]interface{}{
				"_cq_id":                       pgArn,
				"arn":                          pgArn,
				"account_id":                   accountID,
				"region":                       region,
				"cache_parameter_group_name":   pgName,
				"cache_parameter_group_family": aws.ToString(pg.CacheParameterGroupFamily),
				"description":                  aws.ToString(pg.Description),
				"is_global":                    aws.ToBool(pg.IsGlobal),
			})
		}
	}
	return rows, nil
}
