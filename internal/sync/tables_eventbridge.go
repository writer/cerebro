package sync

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
)

// EventBridge Event Buses table
func (e *SyncEngine) eventbridgeEventBusTable() TableSpec {
	return TableSpec{
		Name: "aws_eventbridge_event_buses",
		Columns: []string{
			"_cq_hash", "arn", "name", "account_id", "region",
			"creation_time", "description", "last_modified_time", "policy",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := eventbridge.NewFromConfig(cfg, func(o *eventbridge.Options) {
				o.Region = region
			})
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			out, err := client.ListEventBuses(ctx, &eventbridge.ListEventBusesInput{})
			if err != nil {
				return nil, err
			}

			for _, bus := range out.EventBuses {
				row := map[string]interface{}{
					"arn":                aws.ToString(bus.Arn),
					"name":               aws.ToString(bus.Name),
					"account_id":         accountID,
					"region":             region,
					"creation_time":      timeToString(bus.CreationTime),
					"description":        aws.ToString(bus.Description),
					"last_modified_time": timeToString(bus.LastModifiedTime),
					"policy":             aws.ToString(bus.Policy),
				}
				results = append(results, row)
			}
			return results, nil
		},
	}
}

// EventBridge Rules table
func (e *SyncEngine) eventbridgeRuleTable() TableSpec {
	return TableSpec{
		Name: "aws_eventbridge_rules",
		Columns: []string{
			"_cq_hash", "arn", "name", "account_id", "region",
			"description", "event_bus_name", "event_pattern",
			"managed_by", "role_arn", "schedule_expression", "state",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := eventbridge.NewFromConfig(cfg, func(o *eventbridge.Options) {
				o.Region = region
			})
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			var nextToken *string
			for {
				out, err := client.ListRules(ctx, &eventbridge.ListRulesInput{
					NextToken: nextToken,
				})
				if err != nil {
					return nil, err
				}

				for _, rule := range out.Rules {
					row := map[string]interface{}{
						"arn":                 aws.ToString(rule.Arn),
						"name":                aws.ToString(rule.Name),
						"account_id":          accountID,
						"region":              region,
						"description":         aws.ToString(rule.Description),
						"event_bus_name":      aws.ToString(rule.EventBusName),
						"event_pattern":       aws.ToString(rule.EventPattern),
						"managed_by":          aws.ToString(rule.ManagedBy),
						"role_arn":            aws.ToString(rule.RoleArn),
						"schedule_expression": aws.ToString(rule.ScheduleExpression),
						"state":               string(rule.State),
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

// EventBridge Targets table
func (e *SyncEngine) eventbridgeTargetTable() TableSpec {
	return TableSpec{
		Name: "aws_eventbridge_targets",
		Columns: []string{
			"_cq_hash", "id", "rule_name", "account_id", "region",
			"arn", "event_bus_name", "input", "input_path", "input_transformer",
			"kinesis_parameters", "role_arn", "run_command_parameters",
			"sqs_parameters", "ecs_parameters", "batch_parameters",
			"http_parameters", "redshift_parameters", "sagemaker_pipeline_parameters",
			"dead_letter_config", "retry_policy",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := eventbridge.NewFromConfig(cfg, func(o *eventbridge.Options) {
				o.Region = region
			})
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			// First get all rules
			var nextToken *string
			for {
				rulesOut, err := client.ListRules(ctx, &eventbridge.ListRulesInput{
					NextToken: nextToken,
				})
				if err != nil {
					return nil, err
				}

				for _, rule := range rulesOut.Rules {
					ruleName := aws.ToString(rule.Name)
					eventBusName := aws.ToString(rule.EventBusName)

					// Get targets for this rule
					targetsOut, err := client.ListTargetsByRule(ctx, &eventbridge.ListTargetsByRuleInput{
						Rule:         aws.String(ruleName),
						EventBusName: aws.String(eventBusName),
					})
					if err != nil {
						continue
					}

					for _, target := range targetsOut.Targets {
						inputTransformerJSON, _ := json.Marshal(target.InputTransformer)
						kinesisJSON, _ := json.Marshal(target.KinesisParameters)
						runCommandJSON, _ := json.Marshal(target.RunCommandParameters)
						sqsJSON, _ := json.Marshal(target.SqsParameters)
						ecsJSON, _ := json.Marshal(target.EcsParameters)
						batchJSON, _ := json.Marshal(target.BatchParameters)
						httpJSON, _ := json.Marshal(target.HttpParameters)
						redshiftJSON, _ := json.Marshal(target.RedshiftDataParameters)
						sagemakerJSON, _ := json.Marshal(target.SageMakerPipelineParameters)
						dlcJSON, _ := json.Marshal(target.DeadLetterConfig)
						retryJSON, _ := json.Marshal(target.RetryPolicy)

						row := map[string]interface{}{
							"id":                            aws.ToString(target.Id),
							"rule_name":                     ruleName,
							"account_id":                    accountID,
							"region":                        region,
							"arn":                           aws.ToString(target.Arn),
							"event_bus_name":                eventBusName,
							"input":                         aws.ToString(target.Input),
							"input_path":                    aws.ToString(target.InputPath),
							"input_transformer":             string(inputTransformerJSON),
							"kinesis_parameters":            string(kinesisJSON),
							"role_arn":                      aws.ToString(target.RoleArn),
							"run_command_parameters":        string(runCommandJSON),
							"sqs_parameters":                string(sqsJSON),
							"ecs_parameters":                string(ecsJSON),
							"batch_parameters":              string(batchJSON),
							"http_parameters":               string(httpJSON),
							"redshift_parameters":           string(redshiftJSON),
							"sagemaker_pipeline_parameters": string(sagemakerJSON),
							"dead_letter_config":            string(dlcJSON),
							"retry_policy":                  string(retryJSON),
						}
						results = append(results, row)
					}
				}

				if rulesOut.NextToken == nil {
					break
				}
				nextToken = rulesOut.NextToken
			}
			return results, nil
		},
	}
}

// EventBridge Archives table
func (e *SyncEngine) eventbridgeArchiveTable() TableSpec {
	return TableSpec{
		Name: "aws_eventbridge_archives",
		Columns: []string{
			"_cq_hash", "arn", "archive_name", "account_id", "region",
			"creation_time", "event_count", "event_source_arn",
			"retention_days", "size_bytes", "state", "state_reason",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := eventbridge.NewFromConfig(cfg, func(o *eventbridge.Options) {
				o.Region = region
			})
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			out, err := client.ListArchives(ctx, &eventbridge.ListArchivesInput{})
			if err != nil {
				return nil, err
			}

			for _, archive := range out.Archives {
				archiveName := aws.ToString(archive.ArchiveName)
				arn := fmt.Sprintf("arn:aws:events:%s:%s:archive/%s", region, accountID, archiveName)
				row := map[string]interface{}{
					"arn":              arn,
					"archive_name":     archiveName,
					"account_id":       accountID,
					"region":           region,
					"creation_time":    timeToString(archive.CreationTime),
					"event_count":      archive.EventCount,
					"event_source_arn": aws.ToString(archive.EventSourceArn),
					"retention_days":   archive.RetentionDays,
					"size_bytes":       archive.SizeBytes,
					"state":            string(archive.State),
					"state_reason":     aws.ToString(archive.StateReason),
				}
				results = append(results, row)
			}
			return results, nil
		},
	}
}

// EventBridge API Destinations table
func (e *SyncEngine) eventbridgeApiDestinationTable() TableSpec {
	return TableSpec{
		Name: "aws_eventbridge_api_destinations",
		Columns: []string{
			"_cq_hash", "arn", "name", "account_id", "region",
			"connection_arn", "creation_time", "http_method",
			"invocation_endpoint", "invocation_rate_limit_per_second",
			"last_modified_time", "state",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := eventbridge.NewFromConfig(cfg, func(o *eventbridge.Options) {
				o.Region = region
			})
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			out, err := client.ListApiDestinations(ctx, &eventbridge.ListApiDestinationsInput{})
			if err != nil {
				return nil, err
			}

			for _, dest := range out.ApiDestinations {
				row := map[string]interface{}{
					"arn":                              aws.ToString(dest.ApiDestinationArn),
					"name":                             aws.ToString(dest.Name),
					"account_id":                       accountID,
					"region":                           region,
					"connection_arn":                   aws.ToString(dest.ConnectionArn),
					"creation_time":                    timeToString(dest.CreationTime),
					"http_method":                      string(dest.HttpMethod),
					"invocation_endpoint":              aws.ToString(dest.InvocationEndpoint),
					"invocation_rate_limit_per_second": dest.InvocationRateLimitPerSecond,
					"last_modified_time":               timeToString(dest.LastModifiedTime),
					"state":                            string(dest.ApiDestinationState),
				}
				results = append(results, row)
			}
			return results, nil
		},
	}
}
