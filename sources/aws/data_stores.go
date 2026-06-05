package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/docdb"
	docdbtypes "github.com/aws/aws-sdk-go-v2/service/docdb/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	elasticachetypes "github.com/aws/aws-sdk-go-v2/service/elasticache/types"
	"github.com/aws/aws-sdk-go-v2/service/fsx"
	fsxtypes "github.com/aws/aws-sdk-go-v2/service/fsx/types"
	"github.com/aws/aws-sdk-go-v2/service/neptune"
	neptunetypes "github.com/aws/aws-sdk-go-v2/service/neptune/types"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	opensearchtypes "github.com/aws/aws-sdk-go-v2/service/opensearch/types"
	"github.com/aws/aws-sdk-go-v2/service/opensearchserverless"
	opensearchserverlessdocument "github.com/aws/aws-sdk-go-v2/service/opensearchserverless/document"
	opensearchserverlesstypes "github.com/aws/aws-sdk-go-v2/service/opensearchserverless/types"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
	redshifttypes "github.com/aws/aws-sdk-go-v2/service/redshift/types"

	"github.com/writer/cerebro/internal/primitives"
)

type awsFSxAPI interface {
	DescribeFileSystems(context.Context, *fsx.DescribeFileSystemsInput, ...func(*fsx.Options)) (*fsx.DescribeFileSystemsOutput, error)
}

type awsOpenSearchAPI interface {
	ListDomainNames(context.Context, *opensearch.ListDomainNamesInput, ...func(*opensearch.Options)) (*opensearch.ListDomainNamesOutput, error)
	DescribeDomains(context.Context, *opensearch.DescribeDomainsInput, ...func(*opensearch.Options)) (*opensearch.DescribeDomainsOutput, error)
	ListTags(context.Context, *opensearch.ListTagsInput, ...func(*opensearch.Options)) (*opensearch.ListTagsOutput, error)
}

type awsOpenSearchServerlessAPI interface {
	ListCollections(context.Context, *opensearchserverless.ListCollectionsInput, ...func(*opensearchserverless.Options)) (*opensearchserverless.ListCollectionsOutput, error)
	BatchGetCollection(context.Context, *opensearchserverless.BatchGetCollectionInput, ...func(*opensearchserverless.Options)) (*opensearchserverless.BatchGetCollectionOutput, error)
	ListSecurityPolicies(context.Context, *opensearchserverless.ListSecurityPoliciesInput, ...func(*opensearchserverless.Options)) (*opensearchserverless.ListSecurityPoliciesOutput, error)
	GetSecurityPolicy(context.Context, *opensearchserverless.GetSecurityPolicyInput, ...func(*opensearchserverless.Options)) (*opensearchserverless.GetSecurityPolicyOutput, error)
}

type awsElastiCacheAPI interface {
	DescribeReplicationGroups(context.Context, *elasticache.DescribeReplicationGroupsInput, ...func(*elasticache.Options)) (*elasticache.DescribeReplicationGroupsOutput, error)
	DescribeCacheClusters(context.Context, *elasticache.DescribeCacheClustersInput, ...func(*elasticache.Options)) (*elasticache.DescribeCacheClustersOutput, error)
	DescribeCacheSubnetGroups(context.Context, *elasticache.DescribeCacheSubnetGroupsInput, ...func(*elasticache.Options)) (*elasticache.DescribeCacheSubnetGroupsOutput, error)
	ListTagsForResource(context.Context, *elasticache.ListTagsForResourceInput, ...func(*elasticache.Options)) (*elasticache.ListTagsForResourceOutput, error)
}

type awsRedshiftAPI interface {
	DescribeClusters(context.Context, *redshift.DescribeClustersInput, ...func(*redshift.Options)) (*redshift.DescribeClustersOutput, error)
}

type awsDocDBAPI interface {
	DescribeDBClusters(context.Context, *docdb.DescribeDBClustersInput, ...func(*docdb.Options)) (*docdb.DescribeDBClustersOutput, error)
	DescribeDBInstances(context.Context, *docdb.DescribeDBInstancesInput, ...func(*docdb.Options)) (*docdb.DescribeDBInstancesOutput, error)
	ListTagsForResource(context.Context, *docdb.ListTagsForResourceInput, ...func(*docdb.Options)) (*docdb.ListTagsForResourceOutput, error)
}

type awsNeptuneAPI interface {
	DescribeDBClusters(context.Context, *neptune.DescribeDBClustersInput, ...func(*neptune.Options)) (*neptune.DescribeDBClustersOutput, error)
	DescribeDBInstances(context.Context, *neptune.DescribeDBInstancesInput, ...func(*neptune.Options)) (*neptune.DescribeDBInstancesOutput, error)
	ListTagsForResource(context.Context, *neptune.ListTagsForResourceInput, ...func(*neptune.Options)) (*neptune.ListTagsForResourceOutput, error)
}

type awsFSxFileSystem = fsxtypes.FileSystem
type awsOpenSearchServerlessCollection = opensearchserverlesstypes.CollectionDetail
type awsRedshiftCluster = redshifttypes.Cluster

type awsOpenSearchDomain struct {
	Domain opensearchtypes.DomainStatus
	Tags   map[string]string
}

type awsOpenSearchServerlessPolicy struct {
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

type awsDocDBCluster struct {
	Cluster docdbtypes.DBCluster
	Tags    map[string]string
}

type awsDocDBInstance struct {
	Instance docdbtypes.DBInstance
	Tags     map[string]string
}

type awsNeptuneCluster struct {
	Cluster neptunetypes.DBCluster
	Tags    map[string]string
}

type awsNeptuneInstance struct {
	Instance neptunetypes.DBInstance
	Tags     map[string]string
}

func listFSxFileSystems(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]fsxtypes.FileSystem, string, error) {
	out, err := clients.fsx.DescribeFileSystems(ctx, &fsx.DescribeFileSystemsInput{NextToken: stringPtr(cursor), MaxResults: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 100)))})
	if err != nil {
		return nil, "", err
	}
	return out.FileSystems, awssdk.ToString(out.NextToken), nil
}

func listOpenSearchDomains(ctx context.Context, clients awsClients, _ settings, _ string, _ int) ([]awsOpenSearchDomain, string, error) {
	out, err := clients.openSearch.ListDomainNames(ctx, &opensearch.ListDomainNamesInput{})
	if err != nil {
		return nil, "", err
	}
	names := make([]string, 0, len(out.DomainNames))
	for _, domain := range out.DomainNames {
		if name := awssdk.ToString(domain.DomainName); name != "" {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return nil, "", nil
	}
	describe, err := clients.openSearch.DescribeDomains(ctx, &opensearch.DescribeDomainsInput{DomainNames: names})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsOpenSearchDomain, 0, len(describe.DomainStatusList))
	for _, domain := range describe.DomainStatusList {
		record := awsOpenSearchDomain{Domain: domain}
		if arn := awssdk.ToString(domain.ARN); arn != "" {
			tags, err := clients.openSearch.ListTags(ctx, &opensearch.ListTagsInput{ARN: awssdk.String(arn)})
			if err != nil {
				return nil, "", fmt.Errorf("list opensearch domain tags %q: %w", arn, err)
			}
			record.Tags = openSearchTagMap(tags.TagList)
		}
		records = append(records, record)
	}
	return records, "", nil
}

func listOpenSearchServerlessCollections(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]opensearchserverlesstypes.CollectionDetail, string, error) {
	out, err := clients.openSearchServerless.ListCollections(ctx, &opensearchserverless.ListCollectionsInput{NextToken: stringPtr(cursor), MaxResults: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 100)))})
	if err != nil {
		return nil, "", err
	}
	names := make([]string, 0, len(out.CollectionSummaries))
	for _, summary := range out.CollectionSummaries {
		if name := awssdk.ToString(summary.Name); name != "" {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return nil, awssdk.ToString(out.NextToken), nil
	}
	details, err := clients.openSearchServerless.BatchGetCollection(ctx, &opensearchserverless.BatchGetCollectionInput{Names: names})
	if err != nil {
		return nil, "", err
	}
	return details.CollectionDetails, awssdk.ToString(out.NextToken), nil
}

const (
	openSearchServerlessPolicyCursorEncryption = "encryption:"
	openSearchServerlessPolicyCursorNetwork    = "network:"
)

func listOpenSearchServerlessSecurityPolicies(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsOpenSearchServerlessPolicy, string, error) {
	policyType := opensearchserverlesstypes.SecurityPolicyTypeEncryption
	token := strings.TrimSpace(cursor)
	switch {
	case strings.HasPrefix(token, openSearchServerlessPolicyCursorNetwork):
		policyType = opensearchserverlesstypes.SecurityPolicyTypeNetwork
		token = strings.TrimPrefix(token, openSearchServerlessPolicyCursorNetwork)
	case strings.HasPrefix(token, openSearchServerlessPolicyCursorEncryption):
		policyType = opensearchserverlesstypes.SecurityPolicyTypeEncryption
		token = strings.TrimPrefix(token, openSearchServerlessPolicyCursorEncryption)
	case token == "__network__":
		policyType = opensearchserverlesstypes.SecurityPolicyTypeNetwork
		token = ""
	case strings.HasPrefix(token, "__network__:"):
		policyType = opensearchserverlesstypes.SecurityPolicyTypeNetwork
		token = strings.TrimPrefix(token, "__network__:")
	}
	out, err := clients.openSearchServerless.ListSecurityPolicies(ctx, &opensearchserverless.ListSecurityPoliciesInput{Type: policyType, NextToken: stringPtr(token), MaxResults: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 100)))})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsOpenSearchServerlessPolicy, 0, len(out.SecurityPolicySummaries))
	for _, summary := range out.SecurityPolicySummaries {
		name := awssdk.ToString(summary.Name)
		if name == "" {
			continue
		}
		detail, err := clients.openSearchServerless.GetSecurityPolicy(ctx, &opensearchserverless.GetSecurityPolicyInput{Name: awssdk.String(name), Type: policyType})
		if err != nil {
			return nil, "", fmt.Errorf("get opensearch serverless security policy %q: %w", name, err)
		}
		if detail.SecurityPolicyDetail != nil {
			records = append(records, awsOpenSearchServerlessPolicy{Policy: *detail.SecurityPolicyDetail})
		}
	}
	next := awssdk.ToString(out.NextToken)
	if policyType == opensearchserverlesstypes.SecurityPolicyTypeEncryption {
		if next != "" {
			return records, openSearchServerlessPolicyCursorEncryption + next, nil
		}
		return records, openSearchServerlessPolicyCursorNetwork, nil
	}
	if next != "" {
		return records, openSearchServerlessPolicyCursorNetwork + next, nil
	}
	return records, "", nil
}

func listElastiCacheReplicationGroups(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsElastiCacheReplicationGroup, string, error) {
	out, err := clients.elasticache.DescribeReplicationGroups(ctx, &elasticache.DescribeReplicationGroupsInput{Marker: stringPtr(cursor), MaxRecords: awssdk.Int32(int32(boundedAWSPageSize(limit, 20, 100)))})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsElastiCacheReplicationGroup, 0, len(out.ReplicationGroups))
	for _, group := range out.ReplicationGroups {
		record := awsElastiCacheReplicationGroup{Group: group}
		record.Tags, err = elasticacheTags(ctx, clients, awssdk.ToString(group.ARN))
		if err != nil {
			return nil, "", err
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.Marker), nil
}

func listElastiCacheClusters(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsElastiCacheCluster, string, error) {
	out, err := clients.elasticache.DescribeCacheClusters(ctx, &elasticache.DescribeCacheClustersInput{Marker: stringPtr(cursor), MaxRecords: awssdk.Int32(int32(boundedAWSPageSize(limit, 20, 100)))})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsElastiCacheCluster, 0, len(out.CacheClusters))
	for _, cluster := range out.CacheClusters {
		record := awsElastiCacheCluster{Cluster: cluster}
		record.Tags, err = elasticacheTags(ctx, clients, awssdk.ToString(cluster.ARN))
		if err != nil {
			return nil, "", err
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.Marker), nil
}

func listElastiCacheSubnetGroups(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsElastiCacheSubnetGroup, string, error) {
	out, err := clients.elasticache.DescribeCacheSubnetGroups(ctx, &elasticache.DescribeCacheSubnetGroupsInput{Marker: stringPtr(cursor), MaxRecords: awssdk.Int32(int32(boundedAWSPageSize(limit, 20, 100)))})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsElastiCacheSubnetGroup, 0, len(out.CacheSubnetGroups))
	for _, group := range out.CacheSubnetGroups {
		record := awsElastiCacheSubnetGroup{Group: group}
		record.Tags, err = elasticacheTags(ctx, clients, awssdk.ToString(group.ARN))
		if err != nil {
			return nil, "", err
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.Marker), nil
}

func listRedshiftClusters(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]redshifttypes.Cluster, string, error) {
	out, err := clients.redshift.DescribeClusters(ctx, &redshift.DescribeClustersInput{Marker: stringPtr(cursor), MaxRecords: awssdk.Int32(int32(boundedAWSPageSize(limit, 20, 100)))})
	if err != nil {
		return nil, "", err
	}
	return out.Clusters, awssdk.ToString(out.Marker), nil
}

func listDocDBClusters(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsDocDBCluster, string, error) {
	out, err := clients.docdb.DescribeDBClusters(ctx, &docdb.DescribeDBClustersInput{Marker: stringPtr(cursor), MaxRecords: awssdk.Int32(int32(boundedAWSPageSize(limit, 20, 100)))})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsDocDBCluster, 0, len(out.DBClusters))
	for _, cluster := range out.DBClusters {
		record := awsDocDBCluster{Cluster: cluster}
		record.Tags, err = docdbTags(ctx, clients, awssdk.ToString(cluster.DBClusterArn))
		if err != nil {
			return nil, "", err
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.Marker), nil
}

func listDocDBInstances(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsDocDBInstance, string, error) {
	out, err := clients.docdb.DescribeDBInstances(ctx, &docdb.DescribeDBInstancesInput{Marker: stringPtr(cursor), MaxRecords: awssdk.Int32(int32(boundedAWSPageSize(limit, 20, 100)))})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsDocDBInstance, 0, len(out.DBInstances))
	for _, instance := range out.DBInstances {
		record := awsDocDBInstance{Instance: instance}
		record.Tags, err = docdbTags(ctx, clients, awssdk.ToString(instance.DBInstanceArn))
		if err != nil {
			return nil, "", err
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.Marker), nil
}

func listNeptuneClusters(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsNeptuneCluster, string, error) {
	out, err := clients.neptune.DescribeDBClusters(ctx, &neptune.DescribeDBClustersInput{Marker: stringPtr(cursor), MaxRecords: awssdk.Int32(int32(boundedAWSPageSize(limit, 20, 100)))})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsNeptuneCluster, 0, len(out.DBClusters))
	for _, cluster := range out.DBClusters {
		record := awsNeptuneCluster{Cluster: cluster}
		record.Tags, err = neptuneTags(ctx, clients, awssdk.ToString(cluster.DBClusterArn))
		if err != nil {
			return nil, "", err
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.Marker), nil
}

func listNeptuneInstances(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsNeptuneInstance, string, error) {
	out, err := clients.neptune.DescribeDBInstances(ctx, &neptune.DescribeDBInstancesInput{Marker: stringPtr(cursor), MaxRecords: awssdk.Int32(int32(boundedAWSPageSize(limit, 20, 100)))})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsNeptuneInstance, 0, len(out.DBInstances))
	for _, instance := range out.DBInstances {
		record := awsNeptuneInstance{Instance: instance}
		record.Tags, err = neptuneTags(ctx, clients, awssdk.ToString(instance.DBInstanceArn))
		if err != nil {
			return nil, "", err
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.Marker), nil
}

func fsxFileSystemEvent(settings settings, fs fsxtypes.FileSystem) (*primitives.Event, error) {
	arn := awssdk.ToString(fs.ResourceARN)
	id := awssdk.ToString(fs.FileSystemId)
	tags := fsxTagMap(fs.Tags)
	attrs := commonCloudAssetAttributes(settings, settings.region, familyFSxFileSystem, firstNonEmpty(arn, id), firstNonEmpty(tagLookup(tags, "Name"), id), "fsx_file_system", tags)
	attrs["arn"] = arn
	attrs["file_system_id"] = id
	attrs["file_system_type"] = string(fs.FileSystemType)
	attrs["state"] = string(fs.Lifecycle)
	attrs["encryption"] = boolString(awssdk.ToString(fs.KmsKeyId) != "")
	attrs["kms_key_id"] = awssdk.ToString(fs.KmsKeyId)
	attrs["backups"] = boolString(fsxBackupRetentionDays(fs) > 0)
	attrs["backup_retention_days"] = strconv.FormatInt(int64(fsxBackupRetentionDays(fs)), 10)
	attrs["dns_name"] = awssdk.ToString(fs.DNSName)
	attrs["network_interface_ids"] = strings.Join(cleanStrings(fs.NetworkInterfaceIds), ",")
	attrs["network_type"] = string(fs.NetworkType)
	attrs["storage_type"] = string(fs.StorageType)
	attrs["subnet_ids"] = strings.Join(cleanStrings(fs.SubnetIds), ",")
	attrs["vpc_id"] = awssdk.ToString(fs.VpcId)
	attrs["public"] = "false"
	attrs["internet_exposed"] = "false"
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "file_system": fs})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-fsx-file-system-"+firstNonEmpty(arn, id), "aws.fsx_file_system", "aws/fsx_file_system/v1", payload, attrs, firstTime(fs.CreationTime))
}

func openSearchDomainEvent(settings settings, record awsOpenSearchDomain) (*primitives.Event, error) {
	domain := record.Domain
	arn := awssdk.ToString(domain.ARN)
	name := awssdk.ToString(domain.DomainName)
	public := domain.VPCOptions == nil
	attrs := commonCloudAssetAttributes(settings, settings.region, familyOpenSearchDomain, firstNonEmpty(arn, name), name, "opensearch_domain", record.Tags)
	attrs["arn"] = arn
	attrs["domain_id"] = awssdk.ToString(domain.DomainId)
	attrs["domain_name"] = name
	attrs["endpoint"] = firstNonEmpty(awssdk.ToString(domain.Endpoint), awssdk.ToString(domain.EndpointV2))
	attrs["engine_version"] = awssdk.ToString(domain.EngineVersion)
	attrs["state"] = string(domain.DomainProcessingStatus)
	attrs["encryption"] = boolString(domain.EncryptionAtRestOptions != nil && awssdk.ToBool(domain.EncryptionAtRestOptions.Enabled))
	attrs["kms_key_id"] = openSearchKMSKey(domain)
	attrs["node_to_node_encryption"] = boolString(domain.NodeToNodeEncryptionOptions != nil && awssdk.ToBool(domain.NodeToNodeEncryptionOptions.Enabled))
	attrs["enforce_https"] = boolString(domain.DomainEndpointOptions != nil && awssdk.ToBool(domain.DomainEndpointOptions.EnforceHTTPS))
	attrs["public"] = boolString(public)
	attrs["internet_exposed"] = boolString(public)
	attrs["security_group_ids"] = strings.Join(openSearchSecurityGroupIDs(domain), ",")
	attrs["subnet_ids"] = strings.Join(openSearchSubnetIDs(domain), ",")
	attrs["vpc_id"] = openSearchVPCID(domain)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "domain": domain, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-opensearch-domain-"+firstNonEmpty(arn, name), "aws.opensearch_domain", "aws/opensearch_domain/v1", payload, attrs, time.Now().UTC())
}

func openSearchServerlessCollectionEvent(settings settings, collection opensearchserverlesstypes.CollectionDetail) (*primitives.Event, error) {
	arn := awssdk.ToString(collection.Arn)
	name := awssdk.ToString(collection.Name)
	attrs := commonCloudAssetAttributes(settings, settings.region, familyOpenSearchServerlessCollection, firstNonEmpty(arn, name), name, "opensearch_serverless_collection", nil)
	attrs["arn"] = arn
	attrs["collection_id"] = awssdk.ToString(collection.Id)
	attrs["collection_name"] = name
	attrs["collection_type"] = string(collection.Type)
	attrs["state"] = string(collection.Status)
	attrs["encryption"] = boolString(awssdk.ToString(collection.KmsKeyArn) != "")
	attrs["kms_key_id"] = awssdk.ToString(collection.KmsKeyArn)
	attrs["endpoint"] = awssdk.ToString(collection.CollectionEndpoint)
	attrs["dashboard_endpoint"] = awssdk.ToString(collection.DashboardEndpoint)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "collection": collection})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-opensearch-serverless-collection-"+firstNonEmpty(arn, name), "aws.opensearch_serverless_collection", "aws/opensearch_serverless_collection/v1", payload, attrs, awsEpochMillisTime(collection.CreatedDate))
}

func openSearchServerlessSecurityPolicyEvent(settings settings, record awsOpenSearchServerlessPolicy) (*primitives.Event, error) {
	policy := record.Policy
	name := awssdk.ToString(policy.Name)
	policyType := string(policy.Type)
	resourceID := "opensearch-serverless-security-policy/" + policyType + "/" + name
	attrs := commonCloudAssetAttributes(settings, settings.region, familyOpenSearchServerlessPolicy, resourceID, name, "opensearch_serverless_security_policy", nil)
	attrs["policy_name"] = name
	attrs["policy_type"] = policyType
	attrs["policy_version"] = awssdk.ToString(policy.PolicyVersion)
	attrs["encryption"] = boolString(policy.Type == opensearchserverlesstypes.SecurityPolicyTypeEncryption)
	attrs["public"] = boolString(policy.Type == opensearchserverlesstypes.SecurityPolicyTypeNetwork && policyDocumentMentionsPublic(policy.Policy))
	attrs["internet_exposed"] = attrs["public"]
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "policy": policy})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-opensearch-serverless-security-policy-"+policyType+"-"+name, "aws.opensearch_serverless_security_policy", "aws/opensearch_serverless_security_policy/v1", payload, attrs, time.Now().UTC())
}

func elastiCacheReplicationGroupEvent(settings settings, record awsElastiCacheReplicationGroup) (*primitives.Event, error) {
	group := record.Group
	arn := awssdk.ToString(group.ARN)
	id := awssdk.ToString(group.ReplicationGroupId)
	attrs := commonCloudAssetAttributes(settings, settings.region, familyElastiCacheReplica, firstNonEmpty(arn, id), id, "elasticache_replication_group", record.Tags)
	attrs["arn"] = arn
	attrs["replication_group_id"] = id
	attrs["state"] = awssdk.ToString(group.Status)
	attrs["engine"] = awssdk.ToString(group.Engine)
	attrs["encryption"] = boolString(awssdk.ToBool(group.AtRestEncryptionEnabled) || group.StorageEncryptionType != "")
	attrs["kms_key_id"] = awssdk.ToString(group.KmsKeyId)
	attrs["transit_encryption"] = boolString(awssdk.ToBool(group.TransitEncryptionEnabled))
	attrs["auth_token_enabled"] = boolString(awssdk.ToBool(group.AuthTokenEnabled))
	attrs["backups"] = boolString(awssdk.ToInt32(group.SnapshotRetentionLimit) > 0)
	attrs["backup_retention_days"] = int32AttrString(group.SnapshotRetentionLimit)
	attrs["multi_az"] = string(group.MultiAZ)
	attrs["automatic_failover"] = string(group.AutomaticFailover)
	attrs["network_type"] = string(group.NetworkType)
	attrs["public"] = "false"
	attrs["internet_exposed"] = "false"
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "replication_group": group, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-elasticache-replication-group-"+firstNonEmpty(arn, id), "aws.elasticache_replication_group", "aws/elasticache_replication_group/v1", payload, attrs, firstTime(group.ReplicationGroupCreateTime))
}

func elastiCacheClusterEvent(settings settings, record awsElastiCacheCluster) (*primitives.Event, error) {
	cluster := record.Cluster
	arn := awssdk.ToString(cluster.ARN)
	id := awssdk.ToString(cluster.CacheClusterId)
	attrs := commonCloudAssetAttributes(settings, settings.region, familyElastiCacheCluster, firstNonEmpty(arn, id), id, "elasticache_cluster", record.Tags)
	attrs["arn"] = arn
	attrs["cache_cluster_id"] = id
	attrs["state"] = awssdk.ToString(cluster.CacheClusterStatus)
	attrs["engine"] = awssdk.ToString(cluster.Engine)
	attrs["engine_version"] = awssdk.ToString(cluster.EngineVersion)
	attrs["encryption"] = boolString(awssdk.ToBool(cluster.AtRestEncryptionEnabled))
	attrs["transit_encryption"] = boolString(awssdk.ToBool(cluster.TransitEncryptionEnabled))
	attrs["auth_token_enabled"] = boolString(awssdk.ToBool(cluster.AuthTokenEnabled))
	attrs["subnet_group_name"] = awssdk.ToString(cluster.CacheSubnetGroupName)
	attrs["network_type"] = string(cluster.NetworkType)
	attrs["public"] = "false"
	attrs["internet_exposed"] = "false"
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "cluster": cluster, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-elasticache-cluster-"+firstNonEmpty(arn, id), "aws.elasticache_cluster", "aws/elasticache_cluster/v1", payload, attrs, firstTime(cluster.CacheClusterCreateTime))
}

func elastiCacheSubnetGroupEvent(settings settings, record awsElastiCacheSubnetGroup) (*primitives.Event, error) {
	group := record.Group
	arn := awssdk.ToString(group.ARN)
	name := awssdk.ToString(group.CacheSubnetGroupName)
	attrs := commonCloudAssetAttributes(settings, settings.region, familyElastiCacheSubnet, firstNonEmpty(arn, name), name, "elasticache_subnet_group", record.Tags)
	attrs["arn"] = arn
	attrs["subnet_group_name"] = name
	attrs["description"] = awssdk.ToString(group.CacheSubnetGroupDescription)
	attrs["subnet_ids"] = strings.Join(elastiCacheSubnetIDs(group.Subnets), ",")
	attrs["vpc_id"] = awssdk.ToString(group.VpcId)
	attrs["public"] = "false"
	attrs["internet_exposed"] = "false"
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "subnet_group": group, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-elasticache-subnet-group-"+firstNonEmpty(arn, name), "aws.elasticache_subnet_group", "aws/elasticache_subnet_group/v1", payload, attrs, time.Now().UTC())
}

func redshiftClusterEvent(settings settings, cluster redshifttypes.Cluster) (*primitives.Event, error) {
	arn := awssdk.ToString(cluster.ClusterNamespaceArn)
	id := awssdk.ToString(cluster.ClusterIdentifier)
	tags := redshiftTagMap(cluster.Tags)
	attrs := commonCloudAssetAttributes(settings, settings.region, familyRedshiftCluster, firstNonEmpty(arn, id), id, "redshift_cluster", tags)
	attrs["arn"] = arn
	attrs["cluster_identifier"] = id
	attrs["state"] = awssdk.ToString(cluster.ClusterStatus)
	attrs["engine"] = "redshift"
	attrs["engine_version"] = awssdk.ToString(cluster.ClusterVersion)
	attrs["encryption"] = boolString(awssdk.ToBool(cluster.Encrypted))
	attrs["kms_key_id"] = awssdk.ToString(cluster.KmsKeyId)
	attrs["public"] = boolString(awssdk.ToBool(cluster.PubliclyAccessible))
	attrs["internet_exposed"] = attrs["public"]
	attrs["backups"] = boolString(awssdk.ToInt32(cluster.AutomatedSnapshotRetentionPeriod) > 0)
	attrs["backup_retention_days"] = int32AttrString(cluster.AutomatedSnapshotRetentionPeriod)
	attrs["subnet_group_name"] = awssdk.ToString(cluster.ClusterSubnetGroupName)
	attrs["vpc_id"] = awssdk.ToString(cluster.VpcId)
	attrs["vpc_security_group_ids"] = strings.Join(redshiftSecurityGroupIDs(cluster.VpcSecurityGroups), ",")
	if cluster.Endpoint != nil {
		attrs["endpoint"] = awssdk.ToString(cluster.Endpoint.Address)
		attrs["port"] = int32AttrString(cluster.Endpoint.Port)
	}
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "cluster": cluster})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-redshift-cluster-"+firstNonEmpty(arn, id), "aws.redshift_cluster", "aws/redshift_cluster/v1", payload, attrs, firstTime(cluster.ClusterCreateTime))
}

func docdbClusterEvent(settings settings, record awsDocDBCluster) (*primitives.Event, error) {
	cluster := record.Cluster
	arn := awssdk.ToString(cluster.DBClusterArn)
	id := awssdk.ToString(cluster.DBClusterIdentifier)
	attrs := commonCloudAssetAttributes(settings, settings.region, familyDocDBCluster, firstNonEmpty(arn, id), id, "docdb_cluster", record.Tags)
	addDBClusterAttrs(attrs, awssdk.ToString(cluster.Endpoint), cluster.Port, awssdk.ToString(cluster.Engine), awssdk.ToString(cluster.EngineVersion), awssdk.ToBool(cluster.StorageEncrypted), awssdk.ToString(cluster.KmsKeyId), awssdk.ToBool(cluster.DeletionProtection), cluster.BackupRetentionPeriod, docdbSecurityGroupIDs(cluster.VpcSecurityGroups), awssdk.ToString(cluster.DBSubnetGroup))
	attrs["arn"] = arn
	attrs["cluster_identifier"] = id
	attrs["state"] = awssdk.ToString(cluster.Status)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "cluster": cluster, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-docdb-cluster-"+firstNonEmpty(arn, id), "aws.docdb_cluster", "aws/docdb_cluster/v1", payload, attrs, time.Now().UTC())
}

func docdbInstanceEvent(settings settings, record awsDocDBInstance) (*primitives.Event, error) {
	instance := record.Instance
	arn := awssdk.ToString(instance.DBInstanceArn)
	id := awssdk.ToString(instance.DBInstanceIdentifier)
	attrs := commonCloudAssetAttributes(settings, settings.region, familyDocDBInstance, firstNonEmpty(arn, id), id, "docdb_instance", record.Tags)
	endpoint, port := "", (*int32)(nil)
	if instance.Endpoint != nil {
		endpoint, port = awssdk.ToString(instance.Endpoint.Address), instance.Endpoint.Port
	}
	subnetGroup := ""
	if instance.DBSubnetGroup != nil {
		subnetGroup = awssdk.ToString(instance.DBSubnetGroup.DBSubnetGroupName)
	}
	addDBClusterAttrs(attrs, endpoint, port, awssdk.ToString(instance.Engine), awssdk.ToString(instance.EngineVersion), awssdk.ToBool(instance.StorageEncrypted), awssdk.ToString(instance.KmsKeyId), false, instance.BackupRetentionPeriod, docdbSecurityGroupIDs(instance.VpcSecurityGroups), subnetGroup)
	attrs["arn"] = arn
	attrs["instance_identifier"] = id
	attrs["cluster_identifier"] = awssdk.ToString(instance.DBClusterIdentifier)
	attrs["state"] = awssdk.ToString(instance.DBInstanceStatus)
	attrs["public"] = boolString(awssdk.ToBool(instance.PubliclyAccessible))
	attrs["internet_exposed"] = attrs["public"]
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "instance": instance, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-docdb-instance-"+firstNonEmpty(arn, id), "aws.docdb_instance", "aws/docdb_instance/v1", payload, attrs, time.Now().UTC())
}

func neptuneClusterEvent(settings settings, record awsNeptuneCluster) (*primitives.Event, error) {
	cluster := record.Cluster
	arn := awssdk.ToString(cluster.DBClusterArn)
	id := awssdk.ToString(cluster.DBClusterIdentifier)
	attrs := commonCloudAssetAttributes(settings, settings.region, familyNeptuneCluster, firstNonEmpty(arn, id), id, "neptune_cluster", record.Tags)
	addDBClusterAttrs(attrs, awssdk.ToString(cluster.Endpoint), cluster.Port, awssdk.ToString(cluster.Engine), awssdk.ToString(cluster.EngineVersion), awssdk.ToBool(cluster.StorageEncrypted), awssdk.ToString(cluster.KmsKeyId), awssdk.ToBool(cluster.DeletionProtection), cluster.BackupRetentionPeriod, neptuneSecurityGroupIDs(cluster.VpcSecurityGroups), "")
	attrs["arn"] = arn
	attrs["cluster_identifier"] = id
	attrs["state"] = awssdk.ToString(cluster.Status)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "cluster": cluster, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-neptune-cluster-"+firstNonEmpty(arn, id), "aws.neptune_cluster", "aws/neptune_cluster/v1", payload, attrs, time.Now().UTC())
}

func neptuneInstanceEvent(settings settings, record awsNeptuneInstance) (*primitives.Event, error) {
	instance := record.Instance
	arn := awssdk.ToString(instance.DBInstanceArn)
	id := awssdk.ToString(instance.DBInstanceIdentifier)
	attrs := commonCloudAssetAttributes(settings, settings.region, familyNeptuneInstance, firstNonEmpty(arn, id), id, "neptune_instance", record.Tags)
	endpoint, port := "", instance.DbInstancePort
	if instance.Endpoint != nil {
		endpoint = awssdk.ToString(instance.Endpoint.Address)
		if port == nil {
			port = instance.Endpoint.Port
		}
	}
	subnetGroup := ""
	if instance.DBSubnetGroup != nil {
		subnetGroup = awssdk.ToString(instance.DBSubnetGroup.DBSubnetGroupName)
	}
	addDBClusterAttrs(attrs, endpoint, port, awssdk.ToString(instance.Engine), awssdk.ToString(instance.EngineVersion), awssdk.ToBool(instance.StorageEncrypted), awssdk.ToString(instance.KmsKeyId), false, nil, neptuneSecurityGroupIDs(instance.VpcSecurityGroups), subnetGroup)
	attrs["arn"] = arn
	attrs["instance_identifier"] = id
	attrs["cluster_identifier"] = awssdk.ToString(instance.DBClusterIdentifier)
	attrs["state"] = awssdk.ToString(instance.DBInstanceStatus)
	attrs["public"] = boolString(awssdk.ToBool(instance.PubliclyAccessible))
	attrs["internet_exposed"] = attrs["public"]
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "instance": instance, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-neptune-instance-"+firstNonEmpty(arn, id), "aws.neptune_instance", "aws/neptune_instance/v1", payload, attrs, time.Now().UTC())
}

func addDBClusterAttrs(attrs map[string]string, endpoint string, port *int32, engine string, engineVersion string, encrypted bool, kmsKeyID string, deletionProtection bool, backupRetentionDays *int32, securityGroupIDs []string, subnetGroup string) {
	attrs["endpoint"] = endpoint
	attrs["port"] = int32AttrString(port)
	attrs["engine"] = engine
	attrs["engine_version"] = engineVersion
	attrs["encryption"] = boolString(encrypted)
	attrs["kms_key_id"] = kmsKeyID
	attrs["deletion_protection"] = boolString(deletionProtection)
	attrs["backups"] = boolString(awssdk.ToInt32(backupRetentionDays) > 0)
	attrs["backup_retention_days"] = int32AttrString(backupRetentionDays)
	attrs["subnet_group_name"] = subnetGroup
	attrs["vpc_security_group_ids"] = strings.Join(securityGroupIDs, ",")
	attrs["public"] = "false"
	attrs["internet_exposed"] = "false"
}

func fsxBackupRetentionDays(fs fsxtypes.FileSystem) int32 {
	switch {
	case fs.LustreConfiguration != nil:
		return awssdk.ToInt32(fs.LustreConfiguration.AutomaticBackupRetentionDays)
	case fs.OntapConfiguration != nil:
		return awssdk.ToInt32(fs.OntapConfiguration.AutomaticBackupRetentionDays)
	case fs.OpenZFSConfiguration != nil:
		return awssdk.ToInt32(fs.OpenZFSConfiguration.AutomaticBackupRetentionDays)
	case fs.WindowsConfiguration != nil:
		return awssdk.ToInt32(fs.WindowsConfiguration.AutomaticBackupRetentionDays)
	default:
		return 0
	}
}

func openSearchKMSKey(domain opensearchtypes.DomainStatus) string {
	if domain.EncryptionAtRestOptions == nil {
		return ""
	}
	return awssdk.ToString(domain.EncryptionAtRestOptions.KmsKeyId)
}

func openSearchSecurityGroupIDs(domain opensearchtypes.DomainStatus) []string {
	if domain.VPCOptions == nil {
		return nil
	}
	return cleanStrings(domain.VPCOptions.SecurityGroupIds)
}

func openSearchSubnetIDs(domain opensearchtypes.DomainStatus) []string {
	if domain.VPCOptions == nil {
		return nil
	}
	return cleanStrings(domain.VPCOptions.SubnetIds)
}

func openSearchVPCID(domain opensearchtypes.DomainStatus) string {
	if domain.VPCOptions == nil {
		return ""
	}
	return awssdk.ToString(domain.VPCOptions.VPCId)
}

func policyDocumentMentionsPublic(document any) bool {
	payload, err := marshalOpenSearchServerlessPolicyDocument(document)
	if err != nil {
		return false
	}
	var parsed any
	if err := json.Unmarshal(payload, &parsed); err != nil {
		return false
	}
	var statements []any
	switch value := parsed.(type) {
	case []any:
		statements = value
	case map[string]any:
		statements = append(statements, value)
	}
	for _, statement := range statements {
		statementMap, ok := statement.(map[string]any)
		if !ok {
			continue
		}
		if allow, ok := statementMap["AllowFromPublic"].(bool); ok && allow {
			return true
		}
	}
	return false
}

func marshalOpenSearchServerlessPolicyDocument(document any) ([]byte, error) {
	if smithyDocument, ok := document.(opensearchserverlessdocument.Interface); ok {
		return smithyDocument.MarshalSmithyDocument()
	}
	return json.Marshal(document)
}

func elasticacheTags(ctx context.Context, clients awsClients, arn string) (map[string]string, error) {
	if arn == "" {
		return nil, nil
	}
	out, err := clients.elasticache.ListTagsForResource(ctx, &elasticache.ListTagsForResourceInput{ResourceName: awssdk.String(arn)})
	if err != nil {
		return nil, fmt.Errorf("list elasticache tags %q: %w", arn, err)
	}
	return elasticacheTagMap(out.TagList), nil
}

func docdbTags(ctx context.Context, clients awsClients, arn string) (map[string]string, error) {
	if arn == "" {
		return nil, nil
	}
	out, err := clients.docdb.ListTagsForResource(ctx, &docdb.ListTagsForResourceInput{ResourceName: awssdk.String(arn)})
	if err != nil {
		return nil, fmt.Errorf("list docdb tags %q: %w", arn, err)
	}
	return docdbTagMap(out.TagList), nil
}

func neptuneTags(ctx context.Context, clients awsClients, arn string) (map[string]string, error) {
	if arn == "" {
		return nil, nil
	}
	out, err := clients.neptune.ListTagsForResource(ctx, &neptune.ListTagsForResourceInput{ResourceName: awssdk.String(arn)})
	if err != nil {
		return nil, fmt.Errorf("list neptune tags %q: %w", arn, err)
	}
	return neptuneTagMap(out.TagList), nil
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

func openSearchTagMap(tags []opensearchtypes.Tag) map[string]string {
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

func redshiftTagMap(tags []redshifttypes.Tag) map[string]string {
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		if key := strings.TrimSpace(awssdk.ToString(tag.Key)); key != "" {
			out[key] = strings.TrimSpace(awssdk.ToString(tag.Value))
		}
	}
	return out
}

func docdbTagMap(tags []docdbtypes.Tag) map[string]string {
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		if key := strings.TrimSpace(awssdk.ToString(tag.Key)); key != "" {
			out[key] = strings.TrimSpace(awssdk.ToString(tag.Value))
		}
	}
	return out
}

func neptuneTagMap(tags []neptunetypes.Tag) map[string]string {
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		if key := strings.TrimSpace(awssdk.ToString(tag.Key)); key != "" {
			out[key] = strings.TrimSpace(awssdk.ToString(tag.Value))
		}
	}
	return out
}

func elastiCacheSubnetIDs(subnets []elasticachetypes.Subnet) []string {
	ids := make([]string, 0, len(subnets))
	for _, subnet := range subnets {
		ids = append(ids, awssdk.ToString(subnet.SubnetIdentifier))
	}
	return cleanStrings(ids)
}

func redshiftSecurityGroupIDs(groups []redshifttypes.VpcSecurityGroupMembership) []string {
	ids := make([]string, 0, len(groups))
	for _, group := range groups {
		ids = append(ids, awssdk.ToString(group.VpcSecurityGroupId))
	}
	return cleanStrings(ids)
}

func docdbSecurityGroupIDs(groups []docdbtypes.VpcSecurityGroupMembership) []string {
	ids := make([]string, 0, len(groups))
	for _, group := range groups {
		ids = append(ids, awssdk.ToString(group.VpcSecurityGroupId))
	}
	return cleanStrings(ids)
}

func neptuneSecurityGroupIDs(groups []neptunetypes.VpcSecurityGroupMembership) []string {
	ids := make([]string, 0, len(groups))
	for _, group := range groups {
		ids = append(ids, awssdk.ToString(group.VpcSecurityGroupId))
	}
	return cleanStrings(ids)
}

func awsEpochMillisTime(value *int64) time.Time {
	if value == nil || *value <= 0 {
		return time.Now().UTC()
	}
	return time.UnixMilli(*value).UTC()
}
