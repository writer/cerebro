package sync

import (
	"context"
	"encoding/json"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kafka"
)

// MSK Clusters table
func (e *SyncEngine) mskClusterTable() TableSpec {
	return TableSpec{
		Name: "aws_msk_clusters",
		Columns: []string{
			"_cq_hash", "arn", "cluster_name", "account_id", "region",
			"cluster_type", "creation_time", "current_version", "state",
			"state_info", "active_operation_arn", "broker_node_group_info",
			"client_authentication", "current_broker_software_info",
			"encryption_info", "enhanced_monitoring", "logging_info",
			"number_of_broker_nodes", "open_monitoring", "storage_mode",
			"zookeeper_connect_string", "zookeeper_connect_string_tls", "tags",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := kafka.NewFromConfig(cfg, func(o *kafka.Options) {
				o.Region = region
			})
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			paginator := kafka.NewListClustersV2Paginator(client, &kafka.ListClustersV2Input{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, err
				}

				for _, cluster := range page.ClusterInfoList {
					stateInfoJSON, _ := json.Marshal(cluster.StateInfo)
					tagsJSON, _ := json.Marshal(cluster.Tags)

					row := map[string]interface{}{
						"arn":                          aws.ToString(cluster.ClusterArn),
						"cluster_name":                 aws.ToString(cluster.ClusterName),
						"account_id":                   accountID,
						"region":                       region,
						"cluster_type":                 string(cluster.ClusterType),
						"creation_time":                timeToString(cluster.CreationTime),
						"current_version":              aws.ToString(cluster.CurrentVersion),
						"state":                        string(cluster.State),
						"state_info":                   string(stateInfoJSON),
						"active_operation_arn":         aws.ToString(cluster.ActiveOperationArn),
						"broker_node_group_info":       "",
						"client_authentication":        "",
						"current_broker_software_info": "",
						"encryption_info":              "",
						"enhanced_monitoring":          "",
						"logging_info":                 "",
						"number_of_broker_nodes":       0,
						"open_monitoring":              "",
						"storage_mode":                 "",
						"zookeeper_connect_string":     "",
						"zookeeper_connect_string_tls": "",
						"tags":                         string(tagsJSON),
					}

					// Add provisioned cluster info if available
					if cluster.Provisioned != nil {
						p := cluster.Provisioned
						brokerJSON, _ := json.Marshal(p.BrokerNodeGroupInfo)
						clientAuthJSON, _ := json.Marshal(p.ClientAuthentication)
						softwareJSON, _ := json.Marshal(p.CurrentBrokerSoftwareInfo)
						encryptionJSON, _ := json.Marshal(p.EncryptionInfo)
						loggingJSON, _ := json.Marshal(p.LoggingInfo)
						monitoringJSON, _ := json.Marshal(p.OpenMonitoring)

						row["broker_node_group_info"] = string(brokerJSON)
						row["client_authentication"] = string(clientAuthJSON)
						row["current_broker_software_info"] = string(softwareJSON)
						row["encryption_info"] = string(encryptionJSON)
						row["enhanced_monitoring"] = string(p.EnhancedMonitoring)
						row["logging_info"] = string(loggingJSON)
						row["number_of_broker_nodes"] = p.NumberOfBrokerNodes
						row["open_monitoring"] = string(monitoringJSON)
						row["storage_mode"] = string(p.StorageMode)
						row["zookeeper_connect_string"] = aws.ToString(p.ZookeeperConnectString)
						row["zookeeper_connect_string_tls"] = aws.ToString(p.ZookeeperConnectStringTls)
					}

					results = append(results, row)
				}
			}
			return results, nil
		},
	}
}

// MSK Configurations table
func (e *SyncEngine) mskConfigurationTable() TableSpec {
	return TableSpec{
		Name: "aws_msk_configurations",
		Columns: []string{
			"_cq_hash", "arn", "name", "account_id", "region",
			"creation_time", "description", "kafka_versions",
			"latest_revision", "state",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := kafka.NewFromConfig(cfg, func(o *kafka.Options) {
				o.Region = region
			})
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			var nextToken *string
			for {
				out, err := client.ListConfigurations(ctx, &kafka.ListConfigurationsInput{
					NextToken: nextToken,
				})
				if err != nil {
					return nil, err
				}

				for _, config := range out.Configurations {
					kafkaVersionsJSON, _ := json.Marshal(config.KafkaVersions)
					revisionJSON, _ := json.Marshal(config.LatestRevision)

					row := map[string]interface{}{
						"arn":             aws.ToString(config.Arn),
						"name":            aws.ToString(config.Name),
						"account_id":      accountID,
						"region":          region,
						"creation_time":   timeToString(config.CreationTime),
						"description":     aws.ToString(config.Description),
						"kafka_versions":  string(kafkaVersionsJSON),
						"latest_revision": string(revisionJSON),
						"state":           string(config.State),
					}
					results = append(results, row)
				}

				if out.NextToken == nil {
					break
				}
				nextToken = out.NextToken
			}
			return results, nil
		},
	}
}
