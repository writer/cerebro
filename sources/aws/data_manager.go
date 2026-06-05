package aws

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	elasticachetypes "github.com/aws/aws-sdk-go-v2/service/elasticache/types"
	"github.com/aws/aws-sdk-go-v2/service/fsx"
	fsxtypes "github.com/aws/aws-sdk-go-v2/service/fsx/types"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	opensearchtypes "github.com/aws/aws-sdk-go-v2/service/opensearch/types"
	"github.com/aws/aws-sdk-go-v2/service/opensearchserverless"
	opensearchserverlesstypes "github.com/aws/aws-sdk-go-v2/service/opensearchserverless/types"

	"github.com/writer/cerebro/internal/primitives"
)

type awsOpenSearchDomain struct {
	Domain opensearchtypes.DomainStatus
	Tags   map[string]string
}

type awsOpenSearchServerlessCollection struct {
	Collection opensearchserverlesstypes.CollectionDetail
	Tags       map[string]string
}

type awsOpenSearchServerlessSecurityPolicy struct {
	Policy opensearchserverlesstypes.SecurityPolicyDetail
}

type awsElastiCacheReplicationGroup struct {
	Group elasticachetypes.ReplicationGroup
	Tags  map[string]string
}

type awsElastiCacheCluster struct {
	Cluster elasticachetypes.CacheCluster
	Tags    map[string]string
}

type awsElastiCacheSubnetGroup struct {
	Group elasticachetypes.CacheSubnetGroup
	Tags  map[string]string
}

type awsFSxFileSystem struct {
	FileSystem fsxtypes.FileSystem
	Tags       map[string]string
}

type openSearchServerlessPolicyCursor struct {
	Type  string `json:"type,omitempty"`
	Token string `json:"token,omitempty"`
}

func listOpenSearchDomains(ctx context.Context, clients awsClients, _ settings, _ string, _ int) ([]awsOpenSearchDomain, string, error) {
	list, err := clients.openSearch.ListDomainNames(ctx, &opensearch.ListDomainNamesInput{})
	if err != nil {
		return nil, "", err
	}
	names := make([]string, 0, len(list.DomainNames))
	for _, domain := range list.DomainNames {
		if name := strings.TrimSpace(awssdk.ToString(domain.DomainName)); name != "" {
			names = append(names, name)
		}
	}
	records := make([]awsOpenSearchDomain, 0, len(names))
	for _, batch := range stringBatches(names, 5) {
		describe, err := clients.openSearch.DescribeDomains(ctx, &opensearch.DescribeDomainsInput{DomainNames: batch})
		if err != nil {
			return nil, "", fmt.Errorf("describe opensearch domains: %w", err)
		}
		for _, domain := range describe.DomainStatusList {
			record := awsOpenSearchDomain{Domain: domain}
			if arn := awssdk.ToString(domain.ARN); arn != "" {
				if tags, err := clients.openSearch.ListTags(ctx, &opensearch.ListTagsInput{ARN: awssdk.String(arn)}); err == nil {
					record.Tags = openSearchTagMap(tags.TagList)
				} else if !optionalAWSError(err, "ResourceNotFoundException", "ValidationException") {
					return nil, "", fmt.Errorf("list opensearch tags %q: %w", arn, err)
				}
			}
			records = append(records, record)
		}
	}
	return records, "", nil
}

func listOpenSearchServerlessCollections(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsOpenSearchServerlessCollection, string, error) {
	output, err := clients.openSearchServerless.ListCollections(ctx, &opensearchserverless.ListCollectionsInput{
		MaxResults: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 100))),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	ids := make([]string, 0, len(output.CollectionSummaries))
	for _, summary := range output.CollectionSummaries {
		if id := awssdk.ToString(summary.Id); id != "" {
			ids = append(ids, id)
		}
	}
	records := make([]awsOpenSearchServerlessCollection, 0, len(ids))
	for _, batch := range stringBatches(ids, 100) {
		describe, err := clients.openSearchServerless.BatchGetCollection(ctx, &opensearchserverless.BatchGetCollectionInput{Ids: batch})
		if err != nil {
			return nil, "", fmt.Errorf("batch get opensearch serverless collections: %w", err)
		}
		for _, collection := range describe.CollectionDetails {
			record := awsOpenSearchServerlessCollection{Collection: collection}
			if arn := awssdk.ToString(collection.Arn); arn != "" {
				if tags, err := clients.openSearchServerless.ListTagsForResource(ctx, &opensearchserverless.ListTagsForResourceInput{ResourceArn: awssdk.String(arn)}); err == nil {
					record.Tags = openSearchServerlessTagMap(tags.Tags)
				} else if !optionalAWSError(err, "ResourceNotFoundException", "ValidationException") {
					return nil, "", fmt.Errorf("list opensearch serverless collection tags %q: %w", arn, err)
				}
			}
			records = append(records, record)
		}
	}
	return records, awssdk.ToString(output.NextToken), nil
}

func listOpenSearchServerlessSecurityPolicies(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsOpenSearchServerlessSecurityPolicy, string, error) {
	state, err := decodeOpenSearchServerlessPolicyCursor(cursor)
	if err != nil {
		return nil, "", err
	}
	policyTypes := []opensearchserverlesstypes.SecurityPolicyType{
		opensearchserverlesstypes.SecurityPolicyTypeEncryption,
		opensearchserverlesstypes.SecurityPolicyTypeNetwork,
	}
	typeIndex := openSearchServerlessPolicyTypeIndex(policyTypes, state.Type)
	for typeIndex < len(policyTypes) {
		policyType := policyTypes[typeIndex]
		output, err := clients.openSearchServerless.ListSecurityPolicies(ctx, &opensearchserverless.ListSecurityPoliciesInput{
			Type:       policyType,
			MaxResults: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 100))),
			NextToken:  stringPtr(state.Token),
		})
		if err != nil {
			return nil, "", err
		}
		records := make([]awsOpenSearchServerlessSecurityPolicy, 0, len(output.SecurityPolicySummaries))
		for _, summary := range output.SecurityPolicySummaries {
			name := awssdk.ToString(summary.Name)
			if name == "" {
				continue
			}
			detail, err := clients.openSearchServerless.GetSecurityPolicy(ctx, &opensearchserverless.GetSecurityPolicyInput{Name: awssdk.String(name), Type: policyType})
			if err != nil {
				return nil, "", fmt.Errorf("get opensearch serverless security policy %s/%s: %w", policyTypeString(policyType), name, err)
			}
			if detail.SecurityPolicyDetail != nil {
				records = append(records, awsOpenSearchServerlessSecurityPolicy{Policy: *detail.SecurityPolicyDetail})
			}
		}
		if next := awssdk.ToString(output.NextToken); next != "" {
			return records, encodeOpenSearchServerlessPolicyCursor(openSearchServerlessPolicyCursor{Type: policyTypeString(policyType), Token: next}), nil
		}
		typeIndex++
		if len(records) != 0 {
			if typeIndex < len(policyTypes) {
				return records, encodeOpenSearchServerlessPolicyCursor(openSearchServerlessPolicyCursor{Type: policyTypeString(policyTypes[typeIndex])}), nil
			}
			return records, "", nil
		}
		state.Token = ""
	}
	return nil, "", nil
}

func listElastiCacheReplicationGroups(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsElastiCacheReplicationGroup, string, error) {
	output, err := clients.elasticache.DescribeReplicationGroups(ctx, &elasticache.DescribeReplicationGroupsInput{
		Marker:     stringPtr(cursor),
		MaxRecords: awssdk.Int32(int32(boundedAWSPageSize(limit, 20, 100))),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsElastiCacheReplicationGroup, 0, len(output.ReplicationGroups))
	for _, group := range output.ReplicationGroups {
		record := awsElastiCacheReplicationGroup{Group: group}
		if arn := awssdk.ToString(group.ARN); arn != "" {
			tags, err := listElastiCacheTags(ctx, clients, arn)
			if err != nil {
				return nil, "", fmt.Errorf("list elasticache replication group tags %q: %w", arn, err)
			}
			record.Tags = tags
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(output.Marker), nil
}

func listElastiCacheClusters(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsElastiCacheCluster, string, error) {
	output, err := clients.elasticache.DescribeCacheClusters(ctx, &elasticache.DescribeCacheClustersInput{
		Marker:            stringPtr(cursor),
		MaxRecords:        awssdk.Int32(int32(boundedAWSPageSize(limit, 20, 100))),
		ShowCacheNodeInfo: awssdk.Bool(true),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsElastiCacheCluster, 0, len(output.CacheClusters))
	for _, cluster := range output.CacheClusters {
		record := awsElastiCacheCluster{Cluster: cluster}
		if arn := awssdk.ToString(cluster.ARN); arn != "" {
			tags, err := listElastiCacheTags(ctx, clients, arn)
			if err != nil {
				return nil, "", fmt.Errorf("list elasticache cluster tags %q: %w", arn, err)
			}
			record.Tags = tags
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(output.Marker), nil
}

func listElastiCacheSubnetGroups(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsElastiCacheSubnetGroup, string, error) {
	output, err := clients.elasticache.DescribeCacheSubnetGroups(ctx, &elasticache.DescribeCacheSubnetGroupsInput{
		Marker:     stringPtr(cursor),
		MaxRecords: awssdk.Int32(int32(boundedAWSPageSize(limit, 20, 100))),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsElastiCacheSubnetGroup, 0, len(output.CacheSubnetGroups))
	for _, group := range output.CacheSubnetGroups {
		record := awsElastiCacheSubnetGroup{Group: group}
		if arn := awssdk.ToString(group.ARN); arn != "" {
			tags, err := listElastiCacheTags(ctx, clients, arn)
			if err != nil {
				return nil, "", fmt.Errorf("list elasticache subnet group tags %q: %w", arn, err)
			}
			record.Tags = tags
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(output.Marker), nil
}

func listFSxFileSystems(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsFSxFileSystem, string, error) {
	output, err := clients.fsx.DescribeFileSystems(ctx, &fsx.DescribeFileSystemsInput{
		MaxResults: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 100))),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsFSxFileSystem, 0, len(output.FileSystems))
	for _, fileSystem := range output.FileSystems {
		record := awsFSxFileSystem{FileSystem: fileSystem, Tags: fsxTagMap(fileSystem.Tags)}
		if arn := awssdk.ToString(fileSystem.ResourceARN); arn != "" {
			tags, err := listFSxTags(ctx, clients, arn)
			if err != nil {
				return nil, "", fmt.Errorf("list fsx file system tags %q: %w", arn, err)
			}
			if len(tags) != 0 {
				record.Tags = tags
			}
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(output.NextToken), nil
}

func openSearchDomainEvent(settings settings, record awsOpenSearchDomain) (*primitives.Event, error) {
	domain := record.Domain
	arn := awssdk.ToString(domain.ARN)
	name := awssdk.ToString(domain.DomainName)
	resourceID := firstNonEmpty(arn, name)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyOpenSearchDomain, resourceID, name, "opensearch_domain", record.Tags)
	attributes["arn"] = arn
	attributes["domain_id"] = awssdk.ToString(domain.DomainId)
	attributes["domain_name"] = name
	attributes["engine_version"] = awssdk.ToString(domain.EngineVersion)
	attributes["state"] = openSearchDomainState(domain)
	attributes["endpoint"] = openSearchDomainEndpoint(domain)
	attributes["public_endpoint"] = boolString(domain.VPCOptions == nil && openSearchDomainEndpoint(domain) != "")
	attributes["public"] = attributes["public_endpoint"]
	attributes["internet_exposed"] = attributes["public_endpoint"]
	attributes["vpc_id"] = openSearchDomainVPCID(domain)
	attributes["subnet_ids"] = strings.Join(openSearchDomainSubnetIDs(domain), ",")
	attributes["security_group_ids"] = strings.Join(openSearchDomainSecurityGroupIDs(domain), ",")
	attributes["encryption"] = boolString(openSearchDomainEncryption(domain))
	attributes["kms_key_id"] = openSearchDomainKMSKeyID(domain)
	attributes["node_to_node_encryption"] = boolString(openSearchDomainNodeEncryption(domain))
	attributes["enforce_https"] = boolString(openSearchDomainEnforceHTTPS(domain))
	if domain.ClusterConfig != nil {
		attributes["instance_type"] = string(domain.ClusterConfig.InstanceType)
		attributes["instance_count"] = int32AttrString(domain.ClusterConfig.InstanceCount)
		attributes["zone_awareness"] = boolString(awssdk.ToBool(domain.ClusterConfig.ZoneAwarenessEnabled))
	}
	if domain.EBSOptions != nil {
		attributes["ebs_enabled"] = boolString(awssdk.ToBool(domain.EBSOptions.EBSEnabled))
		attributes["volume_type"] = string(domain.EBSOptions.VolumeType)
		attributes["volume_size_gb"] = int32AttrString(domain.EBSOptions.VolumeSize)
	}
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "domain": domain, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-opensearch-domain-"+resourceID, "aws.opensearch_domain", "aws/opensearch_domain/v1", payload, attributes, time.Now().UTC())
}

func openSearchServerlessCollectionEvent(settings settings, record awsOpenSearchServerlessCollection) (*primitives.Event, error) {
	collection := record.Collection
	arn := awssdk.ToString(collection.Arn)
	name := awssdk.ToString(collection.Name)
	resourceID := firstNonEmpty(arn, awssdk.ToString(collection.Id), name)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyOpenSearchServerlessCollection, resourceID, name, "opensearch_serverless_collection", record.Tags)
	attributes["arn"] = arn
	attributes["collection_arn"] = arn
	attributes["collection_endpoint"] = awssdk.ToString(collection.CollectionEndpoint)
	attributes["collection_group_name"] = awssdk.ToString(collection.CollectionGroupName)
	attributes["collection_id"] = awssdk.ToString(collection.Id)
	attributes["collection_name"] = name
	attributes["collection_type"] = string(collection.Type)
	attributes["dashboard_endpoint"] = awssdk.ToString(collection.DashboardEndpoint)
	attributes["deletion_protection"] = string(collection.DeletionProtection)
	attributes["kms_key_id"] = awssdk.ToString(collection.KmsKeyArn)
	attributes["state"] = string(collection.Status)
	addEpochAttribute(attributes, "created_at", collection.CreatedDate)
	addEpochAttribute(attributes, "modified_at", collection.LastModifiedDate)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "collection": collection, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-opensearch-serverless-collection-"+resourceID, "aws.opensearch_serverless_collection", "aws/opensearch_serverless_collection/v1", payload, attributes, epochTime(collection.CreatedDate))
}

func openSearchServerlessSecurityPolicyEvent(settings settings, record awsOpenSearchServerlessSecurityPolicy) (*primitives.Event, error) {
	policy := record.Policy
	policyType := policyTypeString(policy.Type)
	name := awssdk.ToString(policy.Name)
	resourceID := firstNonEmpty(policyType+":"+name, name)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyOpenSearchServerlessSecurityPolicy, resourceID, name, "opensearch_serverless_security_policy", nil)
	attributes["policy_name"] = name
	attributes["policy_type"] = policyType
	attributes["policy_version"] = awssdk.ToString(policy.PolicyVersion)
	attributes["description"] = awssdk.ToString(policy.Description)
	attributes["policy"] = encodeJSONAttribute(policy.Policy)
	addEpochAttribute(attributes, "created_at", policy.CreatedDate)
	addEpochAttribute(attributes, "modified_at", policy.LastModifiedDate)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "policy": policy})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-opensearch-serverless-security-policy-"+resourceID, "aws.opensearch_serverless_security_policy", "aws/opensearch_serverless_security_policy/v1", payload, attributes, epochTime(policy.CreatedDate))
}

func elasticacheReplicationGroupEvent(settings settings, record awsElastiCacheReplicationGroup) (*primitives.Event, error) {
	group := record.Group
	arn := awssdk.ToString(group.ARN)
	name := awssdk.ToString(group.ReplicationGroupId)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyElastiCacheReplicationGroup, firstNonEmpty(arn, name), name, "elasticache_replication_group", record.Tags)
	attributes["arn"] = arn
	attributes["replication_group_arn"] = arn
	attributes["replication_group_id"] = name
	attributes["description"] = awssdk.ToString(group.Description)
	attributes["engine"] = awssdk.ToString(group.Engine)
	attributes["state"] = awssdk.ToString(group.Status)
	attributes["node_type"] = awssdk.ToString(group.CacheNodeType)
	attributes["cluster_enabled"] = boolString(awssdk.ToBool(group.ClusterEnabled))
	attributes["cluster_mode"] = string(group.ClusterMode)
	attributes["member_cluster_ids"] = strings.Join(cleanStrings(group.MemberClusters), ",")
	attributes["multi_az"] = string(group.MultiAZ)
	attributes["automatic_failover"] = string(group.AutomaticFailover)
	attributes["at_rest_encryption"] = boolString(awssdk.ToBool(group.AtRestEncryptionEnabled))
	attributes["transit_encryption"] = boolString(awssdk.ToBool(group.TransitEncryptionEnabled))
	attributes["auth_token_enabled"] = boolString(awssdk.ToBool(group.AuthTokenEnabled))
	attributes["kms_key_id"] = awssdk.ToString(group.KmsKeyId)
	attributes["storage_encryption_type"] = string(group.StorageEncryptionType)
	attributes["endpoint"] = endpointString(group.ConfigurationEndpoint)
	attributes["backup_retention_days"] = int32AttrString(group.SnapshotRetentionLimit)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "replication_group": group, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-elasticache-replication-group-"+firstNonEmpty(arn, name), "aws.elasticache_replication_group", "aws/elasticache_replication_group/v1", payload, attributes, firstTime(group.ReplicationGroupCreateTime))
}

func elasticacheClusterEvent(settings settings, record awsElastiCacheCluster) (*primitives.Event, error) {
	cluster := record.Cluster
	arn := awssdk.ToString(cluster.ARN)
	name := awssdk.ToString(cluster.CacheClusterId)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyElastiCacheCluster, firstNonEmpty(arn, name), name, "elasticache_cluster", record.Tags)
	attributes["arn"] = arn
	attributes["cache_cluster_arn"] = arn
	attributes["cache_cluster_id"] = name
	attributes["replication_group_id"] = awssdk.ToString(cluster.ReplicationGroupId)
	attributes["cache_subnet_group_name"] = awssdk.ToString(cluster.CacheSubnetGroupName)
	attributes["engine"] = awssdk.ToString(cluster.Engine)
	attributes["engine_version"] = awssdk.ToString(cluster.EngineVersion)
	attributes["state"] = awssdk.ToString(cluster.CacheClusterStatus)
	attributes["node_type"] = awssdk.ToString(cluster.CacheNodeType)
	attributes["num_cache_nodes"] = int32AttrString(cluster.NumCacheNodes)
	attributes["availability_zone"] = awssdk.ToString(cluster.PreferredAvailabilityZone)
	attributes["security_group_ids"] = strings.Join(elasticacheSecurityGroupIDs(cluster.SecurityGroups), ",")
	attributes["endpoint"] = firstNonEmpty(endpointString(cluster.ConfigurationEndpoint), strings.Join(elasticacheNodeEndpoints(cluster.CacheNodes), ","))
	attributes["at_rest_encryption"] = boolString(awssdk.ToBool(cluster.AtRestEncryptionEnabled))
	attributes["transit_encryption"] = boolString(awssdk.ToBool(cluster.TransitEncryptionEnabled))
	attributes["auth_token_enabled"] = boolString(awssdk.ToBool(cluster.AuthTokenEnabled))
	attributes["backup_retention_days"] = int32AttrString(cluster.SnapshotRetentionLimit)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "cluster": cluster, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-elasticache-cluster-"+firstNonEmpty(arn, name), "aws.elasticache_cluster", "aws/elasticache_cluster/v1", payload, attributes, firstTime(cluster.CacheClusterCreateTime))
}

func elasticacheSubnetGroupEvent(settings settings, record awsElastiCacheSubnetGroup) (*primitives.Event, error) {
	group := record.Group
	arn := awssdk.ToString(group.ARN)
	name := awssdk.ToString(group.CacheSubnetGroupName)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyElastiCacheSubnetGroup, firstNonEmpty(arn, name), name, "elasticache_subnet_group", record.Tags)
	attributes["arn"] = arn
	attributes["cache_subnet_group_arn"] = arn
	attributes["cache_subnet_group_name"] = name
	attributes["description"] = awssdk.ToString(group.CacheSubnetGroupDescription)
	attributes["vpc_id"] = awssdk.ToString(group.VpcId)
	attributes["subnet_ids"] = strings.Join(elasticacheSubnetIDs(group.Subnets), ",")
	attributes["supported_network_types"] = strings.Join(elasticacheNetworkTypes(group.SupportedNetworkTypes), ",")
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "subnet_group": group, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-elasticache-subnet-group-"+firstNonEmpty(arn, name), "aws.elasticache_subnet_group", "aws/elasticache_subnet_group/v1", payload, attributes, time.Now().UTC())
}

func fsxFileSystemEvent(settings settings, record awsFSxFileSystem) (*primitives.Event, error) {
	fileSystem := record.FileSystem
	arn := awssdk.ToString(fileSystem.ResourceARN)
	id := awssdk.ToString(fileSystem.FileSystemId)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyFSxFileSystem, firstNonEmpty(arn, id), id, "fsx_file_system", record.Tags)
	attributes["arn"] = arn
	attributes["dns_name"] = awssdk.ToString(fileSystem.DNSName)
	attributes["file_system_arn"] = arn
	attributes["file_system_id"] = id
	attributes["file_system_type"] = string(fileSystem.FileSystemType)
	attributes["file_system_type_version"] = awssdk.ToString(fileSystem.FileSystemTypeVersion)
	attributes["state"] = string(fileSystem.Lifecycle)
	attributes["kms_key_id"] = awssdk.ToString(fileSystem.KmsKeyId)
	attributes["storage_capacity_gib"] = int32AttrString(fileSystem.StorageCapacity)
	attributes["storage_type"] = string(fileSystem.StorageType)
	attributes["network_type"] = string(fileSystem.NetworkType)
	attributes["vpc_id"] = awssdk.ToString(fileSystem.VpcId)
	attributes["subnet_ids"] = strings.Join(cleanStrings(fileSystem.SubnetIds), ",")
	attributes["network_interface_ids"] = strings.Join(cleanStrings(fileSystem.NetworkInterfaceIds), ",")
	attributes["owner_id"] = awssdk.ToString(fileSystem.OwnerId)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "file_system": fileSystem, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-fsx-file-system-"+firstNonEmpty(arn, id), "aws.fsx_file_system", "aws/fsx_file_system/v1", payload, attributes, firstTime(fileSystem.CreationTime))
}

func listElastiCacheTags(ctx context.Context, clients awsClients, arn string) (map[string]string, error) {
	output, err := clients.elasticache.ListTagsForResource(ctx, &elasticache.ListTagsForResourceInput{ResourceName: awssdk.String(arn)})
	if err != nil {
		if optionalAWSError(err, "CacheClusterNotFound", "ReplicationGroupNotFoundFault", "CacheSubnetGroupNotFoundFault", "InvalidARN") {
			return nil, nil
		}
		return nil, err
	}
	return elasticacheTagMap(output.TagList), nil
}

func listFSxTags(ctx context.Context, clients awsClients, arn string) (map[string]string, error) {
	var tags []fsxtypes.Tag
	var next *string
	for {
		output, err := clients.fsx.ListTagsForResource(ctx, &fsx.ListTagsForResourceInput{ResourceARN: awssdk.String(arn), NextToken: next, MaxResults: awssdk.Int32(50)})
		if err != nil {
			if optionalAWSError(err, "ResourceNotFound", "FileSystemNotFound") {
				return nil, nil
			}
			return nil, err
		}
		tags = append(tags, output.Tags...)
		if awssdk.ToString(output.NextToken) == "" {
			break
		}
		next = output.NextToken
	}
	return fsxTagMap(tags), nil
}

func openSearchDomainState(domain opensearchtypes.DomainStatus) string {
	switch {
	case awssdk.ToBool(domain.Deleted):
		return "deleted"
	case awssdk.ToBool(domain.Processing) || awssdk.ToBool(domain.UpgradeProcessing):
		return "processing"
	case domain.DomainProcessingStatus != "":
		return string(domain.DomainProcessingStatus)
	case awssdk.ToBool(domain.Created):
		return "active"
	default:
		return ""
	}
}

func openSearchDomainEndpoint(domain opensearchtypes.DomainStatus) string {
	return firstNonEmpty(awssdk.ToString(domain.EndpointV2), awssdk.ToString(domain.Endpoint), domain.Endpoints["vpcv2"], domain.Endpoints["vpc"])
}

func openSearchDomainVPCID(domain opensearchtypes.DomainStatus) string {
	if domain.VPCOptions == nil {
		return ""
	}
	return awssdk.ToString(domain.VPCOptions.VPCId)
}

func openSearchDomainSubnetIDs(domain opensearchtypes.DomainStatus) []string {
	if domain.VPCOptions == nil {
		return nil
	}
	return cleanStrings(domain.VPCOptions.SubnetIds)
}

func openSearchDomainSecurityGroupIDs(domain opensearchtypes.DomainStatus) []string {
	if domain.VPCOptions == nil {
		return nil
	}
	return cleanStrings(domain.VPCOptions.SecurityGroupIds)
}

func openSearchDomainEncryption(domain opensearchtypes.DomainStatus) bool {
	return domain.EncryptionAtRestOptions != nil && awssdk.ToBool(domain.EncryptionAtRestOptions.Enabled)
}

func openSearchDomainKMSKeyID(domain opensearchtypes.DomainStatus) string {
	if domain.EncryptionAtRestOptions == nil {
		return ""
	}
	return awssdk.ToString(domain.EncryptionAtRestOptions.KmsKeyId)
}

func openSearchDomainNodeEncryption(domain opensearchtypes.DomainStatus) bool {
	return domain.NodeToNodeEncryptionOptions != nil && awssdk.ToBool(domain.NodeToNodeEncryptionOptions.Enabled)
}

func openSearchDomainEnforceHTTPS(domain opensearchtypes.DomainStatus) bool {
	return domain.DomainEndpointOptions != nil && awssdk.ToBool(domain.DomainEndpointOptions.EnforceHTTPS)
}

func endpointString(endpoint *elasticachetypes.Endpoint) string {
	if endpoint == nil {
		return ""
	}
	address := awssdk.ToString(endpoint.Address)
	if address == "" {
		return ""
	}
	if endpoint.Port == nil {
		return address
	}
	return address + ":" + strconv.FormatInt(int64(awssdk.ToInt32(endpoint.Port)), 10)
}

func elasticacheNodeEndpoints(nodes []elasticachetypes.CacheNode) []string {
	endpoints := make([]string, 0, len(nodes))
	for _, node := range nodes {
		endpoints = append(endpoints, endpointString(node.Endpoint))
	}
	return cleanStrings(endpoints)
}

func elasticacheSecurityGroupIDs(groups []elasticachetypes.SecurityGroupMembership) []string {
	ids := make([]string, 0, len(groups))
	for _, group := range groups {
		ids = append(ids, awssdk.ToString(group.SecurityGroupId))
	}
	return cleanStrings(ids)
}

func elasticacheSubnetIDs(subnets []elasticachetypes.Subnet) []string {
	ids := make([]string, 0, len(subnets))
	for _, subnet := range subnets {
		ids = append(ids, awssdk.ToString(subnet.SubnetIdentifier))
	}
	return cleanStrings(ids)
}

func elasticacheNetworkTypes(types []elasticachetypes.NetworkType) []string {
	values := make([]string, 0, len(types))
	for _, value := range types {
		values = append(values, string(value))
	}
	return cleanStrings(values)
}

func openSearchTagMap(tags []opensearchtypes.Tag) map[string]string {
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		if key := strings.TrimSpace(awssdk.ToString(tag.Key)); key != "" {
			out[key] = strings.TrimSpace(awssdk.ToString(tag.Value))
		}
	}
	return out
}

func openSearchServerlessTagMap(tags []opensearchserverlesstypes.Tag) map[string]string {
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		if key := strings.TrimSpace(awssdk.ToString(tag.Key)); key != "" {
			out[key] = strings.TrimSpace(awssdk.ToString(tag.Value))
		}
	}
	return out
}

func elasticacheTagMap(tags []elasticachetypes.Tag) map[string]string {
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		if key := strings.TrimSpace(awssdk.ToString(tag.Key)); key != "" {
			out[key] = strings.TrimSpace(awssdk.ToString(tag.Value))
		}
	}
	return out
}

func fsxTagMap(tags []fsxtypes.Tag) map[string]string {
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		if key := strings.TrimSpace(awssdk.ToString(tag.Key)); key != "" {
			out[key] = strings.TrimSpace(awssdk.ToString(tag.Value))
		}
	}
	return out
}

func policyTypeString(value opensearchserverlesstypes.SecurityPolicyType) string {
	return strings.TrimSpace(string(value))
}

func addEpochAttribute(attributes map[string]string, key string, value *int64) {
	if timestamp := epochTime(value); !timestamp.IsZero() {
		attributes[key] = timestamp.UTC().Format(time.RFC3339Nano)
	}
}

func epochTime(value *int64) time.Time {
	if value == nil || *value <= 0 {
		return time.Time{}
	}
	if *value > 1_000_000_000_000 {
		return time.UnixMilli(*value).UTC()
	}
	return time.Unix(*value, 0).UTC()
}

func encodeJSONAttribute(value any) string {
	if value == nil {
		return ""
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return string(payload)
}

func decodeOpenSearchServerlessPolicyCursor(raw string) (openSearchServerlessPolicyCursor, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return openSearchServerlessPolicyCursor{}, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return openSearchServerlessPolicyCursor{}, fmt.Errorf("decode opensearch serverless security policy cursor: %w", err)
	}
	var cursor openSearchServerlessPolicyCursor
	if err := json.Unmarshal(decoded, &cursor); err != nil {
		return openSearchServerlessPolicyCursor{}, fmt.Errorf("parse opensearch serverless security policy cursor: %w", err)
	}
	return cursor, nil
}

func encodeOpenSearchServerlessPolicyCursor(cursor openSearchServerlessPolicyCursor) string {
	payload, err := json.Marshal(cursor)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(payload)
}

func openSearchServerlessPolicyTypeIndex(values []opensearchserverlesstypes.SecurityPolicyType, raw string) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	for index, value := range values {
		if policyTypeString(value) == raw {
			return index
		}
	}
	return 0
}
