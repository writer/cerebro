package sync

import (
	"context"
	"encoding/json"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/mwaa"
)

// MWAA Environments table (Amazon Managed Workflows for Apache Airflow)
func (e *SyncEngine) mwaaEnvironmentTable() TableSpec {
	return TableSpec{
		Name: "aws_mwaa_environments",
		Columns: []string{
			"_cq_hash", "arn", "name", "account_id", "region",
			"airflow_configuration_options", "airflow_version",
			"celery_executor_queue", "created_at", "dag_s3_path",
			"database_vpc_endpoint_service", "endpoint_management",
			"environment_class", "execution_role_arn", "kms_key",
			"last_update", "logging_configuration", "max_webservers",
			"max_workers", "min_webservers", "min_workers",
			"network_configuration", "plugins_s3_object_version",
			"plugins_s3_path", "requirements_s3_object_version",
			"requirements_s3_path", "scheduler_count", "service_role_arn",
			"source_bucket_arn", "startup_script_s3_object_version",
			"startup_script_s3_path", "status", "webserver_access_mode",
			"webserver_url", "webserver_vpc_endpoint_service",
			"weekly_maintenance_window_start", "tags",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := mwaa.NewFromConfig(cfg, func(o *mwaa.Options) {
				o.Region = region
			})
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			var nextToken *string
			for {
				out, err := client.ListEnvironments(ctx, &mwaa.ListEnvironmentsInput{
					NextToken: nextToken,
				})
				if err != nil {
					return nil, err
				}

				for _, name := range out.Environments {
					// Get full details
					detail, err := client.GetEnvironment(ctx, &mwaa.GetEnvironmentInput{
						Name: aws.String(name),
					})
					if err != nil {
						continue
					}
					env := detail.Environment

					configOptionsJSON, _ := json.Marshal(env.AirflowConfigurationOptions)
					lastUpdateJSON, _ := json.Marshal(env.LastUpdate)
					loggingJSON, _ := json.Marshal(env.LoggingConfiguration)
					networkJSON, _ := json.Marshal(env.NetworkConfiguration)
					tagsJSON, _ := json.Marshal(env.Tags)

					row := map[string]interface{}{
						"arn":                              aws.ToString(env.Arn),
						"name":                             aws.ToString(env.Name),
						"account_id":                       accountID,
						"region":                           region,
						"airflow_configuration_options":    string(configOptionsJSON),
						"airflow_version":                  aws.ToString(env.AirflowVersion),
						"celery_executor_queue":            aws.ToString(env.CeleryExecutorQueue),
						"created_at":                       timeToString(env.CreatedAt),
						"dag_s3_path":                      aws.ToString(env.DagS3Path),
						"database_vpc_endpoint_service":    aws.ToString(env.DatabaseVpcEndpointService),
						"endpoint_management":              string(env.EndpointManagement),
						"environment_class":                aws.ToString(env.EnvironmentClass),
						"execution_role_arn":               aws.ToString(env.ExecutionRoleArn),
						"kms_key":                          aws.ToString(env.KmsKey),
						"last_update":                      string(lastUpdateJSON),
						"logging_configuration":            string(loggingJSON),
						"max_webservers":                   env.MaxWebservers,
						"max_workers":                      env.MaxWorkers,
						"min_webservers":                   env.MinWebservers,
						"min_workers":                      env.MinWorkers,
						"network_configuration":            string(networkJSON),
						"plugins_s3_object_version":        aws.ToString(env.PluginsS3ObjectVersion),
						"plugins_s3_path":                  aws.ToString(env.PluginsS3Path),
						"requirements_s3_object_version":   aws.ToString(env.RequirementsS3ObjectVersion),
						"requirements_s3_path":             aws.ToString(env.RequirementsS3Path),
						"scheduler_count":                  env.Schedulers,
						"service_role_arn":                 aws.ToString(env.ServiceRoleArn),
						"source_bucket_arn":                aws.ToString(env.SourceBucketArn),
						"startup_script_s3_object_version": aws.ToString(env.StartupScriptS3ObjectVersion),
						"startup_script_s3_path":           aws.ToString(env.StartupScriptS3Path),
						"status":                           string(env.Status),
						"webserver_access_mode":            string(env.WebserverAccessMode),
						"webserver_url":                    aws.ToString(env.WebserverUrl),
						"webserver_vpc_endpoint_service":   aws.ToString(env.WebserverVpcEndpointService),
						"weekly_maintenance_window_start":  aws.ToString(env.WeeklyMaintenanceWindowStart),
						"tags":                             string(tagsJSON),
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
