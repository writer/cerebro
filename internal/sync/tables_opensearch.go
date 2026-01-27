package sync

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
)

// OpenSearch Domains
func (e *SyncEngine) opensearchDomainTable() TableSpec {
	return TableSpec{
		Name:    "aws_opensearch_domains",
		Columns: []string{"arn", "account_id", "region", "domain_id", "domain_name", "engine_version", "cluster_config", "ebs_options", "access_policies", "vpc_options", "encryption_at_rest_options", "node_to_node_encryption_options", "advanced_security_options", "endpoint", "processing", "created"},
		Fetch:   e.fetchOpenSearchDomains,
	}
}

func (e *SyncEngine) fetchOpenSearchDomains(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := opensearch.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	listOut, err := client.ListDomainNames(ctx, &opensearch.ListDomainNamesInput{})
	if err != nil {
		return nil, err
	}

	if len(listOut.DomainNames) == 0 {
		return nil, nil
	}

	var domainNames []string
	for _, d := range listOut.DomainNames {
		domainNames = append(domainNames, aws.ToString(d.DomainName))
	}

	descOut, err := client.DescribeDomains(ctx, &opensearch.DescribeDomainsInput{
		DomainNames: domainNames,
	})
	if err != nil {
		return nil, err
	}

	var rows []map[string]interface{}
	for _, domain := range descOut.DomainStatusList {
		domainArn := aws.ToString(domain.ARN)
		if domainArn == "" {
			domainArn = fmt.Sprintf("arn:aws:es:%s:%s:domain/%s", region, accountID, aws.ToString(domain.DomainName))
		}

		var clusterConfig, ebsOptions, vpcOptions interface{}
		var encryptionAtRest, nodeToNode, advancedSecurity interface{}

		if domain.ClusterConfig != nil {
			clusterConfig = map[string]interface{}{
				"instance_type":            string(domain.ClusterConfig.InstanceType),
				"instance_count":           domain.ClusterConfig.InstanceCount,
				"dedicated_master_enabled": aws.ToBool(domain.ClusterConfig.DedicatedMasterEnabled),
				"zone_awareness_enabled":   aws.ToBool(domain.ClusterConfig.ZoneAwarenessEnabled),
			}
		}

		if domain.EBSOptions != nil {
			ebsOptions = map[string]interface{}{
				"ebs_enabled": aws.ToBool(domain.EBSOptions.EBSEnabled),
				"volume_type": string(domain.EBSOptions.VolumeType),
				"volume_size": domain.EBSOptions.VolumeSize,
			}
		}

		if domain.VPCOptions != nil {
			vpcOptions = map[string]interface{}{
				"vpc_id":             aws.ToString(domain.VPCOptions.VPCId),
				"subnet_ids":         domain.VPCOptions.SubnetIds,
				"security_group_ids": domain.VPCOptions.SecurityGroupIds,
			}
		}

		if domain.EncryptionAtRestOptions != nil {
			encryptionAtRest = map[string]interface{}{
				"enabled":    aws.ToBool(domain.EncryptionAtRestOptions.Enabled),
				"kms_key_id": aws.ToString(domain.EncryptionAtRestOptions.KmsKeyId),
			}
		}

		if domain.NodeToNodeEncryptionOptions != nil {
			nodeToNode = map[string]interface{}{
				"enabled": aws.ToBool(domain.NodeToNodeEncryptionOptions.Enabled),
			}
		}

		if domain.AdvancedSecurityOptions != nil {
			advancedSecurity = map[string]interface{}{
				"enabled":                        aws.ToBool(domain.AdvancedSecurityOptions.Enabled),
				"internal_user_database_enabled": aws.ToBool(domain.AdvancedSecurityOptions.InternalUserDatabaseEnabled),
			}
		}

		rows = append(rows, map[string]interface{}{
			"_cq_id":                          domainArn,
			"arn":                             domainArn,
			"account_id":                      accountID,
			"region":                          region,
			"domain_id":                       aws.ToString(domain.DomainId),
			"domain_name":                     aws.ToString(domain.DomainName),
			"engine_version":                  aws.ToString(domain.EngineVersion),
			"cluster_config":                  clusterConfig,
			"ebs_options":                     ebsOptions,
			"access_policies":                 aws.ToString(domain.AccessPolicies),
			"vpc_options":                     vpcOptions,
			"encryption_at_rest_options":      encryptionAtRest,
			"node_to_node_encryption_options": nodeToNode,
			"advanced_security_options":       advancedSecurity,
			"endpoint":                        aws.ToString(domain.Endpoint),
			"processing":                      aws.ToBool(domain.Processing),
			"created":                         aws.ToBool(domain.Created),
		})
	}
	return rows, nil
}
