package sync

import (
	"context"
	"encoding/json"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cloudwatch_types "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
)

// CloudWatch Alarms table
func (e *SyncEngine) cloudwatchAlarmTable() TableSpec {
	return TableSpec{
		Name: "aws_cloudwatch_alarms",
		Columns: []string{
			"_cq_hash", "arn", "alarm_name", "account_id", "region",
			"actions_enabled", "alarm_actions", "alarm_configuration_updated_timestamp",
			"alarm_description", "comparison_operator", "datapoints_to_alarm",
			"dimensions", "evaluate_low_sample_count_percentile", "evaluation_periods",
			"evaluation_state", "extended_statistic", "insufficient_data_actions",
			"metric_name", "metrics", "namespace", "ok_actions", "period",
			"state_reason", "state_reason_data", "state_transitioned_timestamp",
			"state_updated_timestamp", "state_value", "statistic",
			"threshold", "threshold_metric_id", "treat_missing_data", "unit",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := cloudwatch.NewFromConfig(cfg, func(o *cloudwatch.Options) {
				o.Region = region
			})
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			paginator := cloudwatch.NewDescribeAlarmsPaginator(client, &cloudwatch.DescribeAlarmsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, err
				}

				for _, alarm := range page.MetricAlarms {
					actionsJSON, _ := json.Marshal(alarm.AlarmActions)
					dimensionsJSON, _ := json.Marshal(alarm.Dimensions)
					insufficientJSON, _ := json.Marshal(alarm.InsufficientDataActions)
					metricsJSON, _ := json.Marshal(alarm.Metrics)
					okActionsJSON, _ := json.Marshal(alarm.OKActions)

					row := map[string]interface{}{
						"arn":                                   aws.ToString(alarm.AlarmArn),
						"alarm_name":                            aws.ToString(alarm.AlarmName),
						"account_id":                            accountID,
						"region":                                region,
						"actions_enabled":                       alarm.ActionsEnabled,
						"alarm_actions":                         string(actionsJSON),
						"alarm_configuration_updated_timestamp": timeToString(alarm.AlarmConfigurationUpdatedTimestamp),
						"alarm_description":                     aws.ToString(alarm.AlarmDescription),
						"comparison_operator":                   string(alarm.ComparisonOperator),
						"datapoints_to_alarm":                   alarm.DatapointsToAlarm,
						"dimensions":                            string(dimensionsJSON),
						"evaluate_low_sample_count_percentile":  aws.ToString(alarm.EvaluateLowSampleCountPercentile),
						"evaluation_periods":                    alarm.EvaluationPeriods,
						"evaluation_state":                      string(alarm.EvaluationState),
						"extended_statistic":                    aws.ToString(alarm.ExtendedStatistic),
						"insufficient_data_actions":             string(insufficientJSON),
						"metric_name":                           aws.ToString(alarm.MetricName),
						"metrics":                               string(metricsJSON),
						"namespace":                             aws.ToString(alarm.Namespace),
						"ok_actions":                            string(okActionsJSON),
						"period":                                alarm.Period,
						"state_reason":                          aws.ToString(alarm.StateReason),
						"state_reason_data":                     aws.ToString(alarm.StateReasonData),
						"state_transitioned_timestamp":          timeToString(alarm.StateTransitionedTimestamp),
						"state_updated_timestamp":               timeToString(alarm.StateUpdatedTimestamp),
						"state_value":                           string(alarm.StateValue),
						"statistic":                             string(alarm.Statistic),
						"threshold":                             alarm.Threshold,
						"threshold_metric_id":                   aws.ToString(alarm.ThresholdMetricId),
						"treat_missing_data":                    aws.ToString(alarm.TreatMissingData),
						"unit":                                  string(alarm.Unit),
					}
					results = append(results, row)
				}
			}
			return results, nil
		},
	}
}

// CloudWatch Composite Alarms table
func (e *SyncEngine) cloudwatchCompositeAlarmTable() TableSpec {
	return TableSpec{
		Name: "aws_cloudwatch_composite_alarms",
		Columns: []string{
			"_cq_hash", "arn", "alarm_name", "account_id", "region",
			"actions_enabled", "actions_suppressed_by", "actions_suppressed_reason",
			"actions_suppressor", "actions_suppressor_extension_period",
			"actions_suppressor_wait_period", "alarm_actions", "alarm_description",
			"alarm_rule", "insufficient_data_actions", "ok_actions",
			"state_reason", "state_reason_data", "state_transitioned_timestamp",
			"state_updated_timestamp", "state_value",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := cloudwatch.NewFromConfig(cfg, func(o *cloudwatch.Options) {
				o.Region = region
			})
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			paginator := cloudwatch.NewDescribeAlarmsPaginator(client, &cloudwatch.DescribeAlarmsInput{
				AlarmTypes: []cloudwatch_types.AlarmType{cloudwatch_types.AlarmTypeCompositeAlarm},
			})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, err
				}

				for _, alarm := range page.CompositeAlarms {
					actionsJSON, _ := json.Marshal(alarm.AlarmActions)
					insufficientJSON, _ := json.Marshal(alarm.InsufficientDataActions)
					okActionsJSON, _ := json.Marshal(alarm.OKActions)

					row := map[string]interface{}{
						"arn":                                 aws.ToString(alarm.AlarmArn),
						"alarm_name":                          aws.ToString(alarm.AlarmName),
						"account_id":                          accountID,
						"region":                              region,
						"actions_enabled":                     alarm.ActionsEnabled,
						"actions_suppressed_by":               string(alarm.ActionsSuppressedBy),
						"actions_suppressed_reason":           aws.ToString(alarm.ActionsSuppressedReason),
						"actions_suppressor":                  aws.ToString(alarm.ActionsSuppressor),
						"actions_suppressor_extension_period": alarm.ActionsSuppressorExtensionPeriod,
						"actions_suppressor_wait_period":      alarm.ActionsSuppressorWaitPeriod,
						"alarm_actions":                       string(actionsJSON),
						"alarm_description":                   aws.ToString(alarm.AlarmDescription),
						"alarm_rule":                          aws.ToString(alarm.AlarmRule),
						"insufficient_data_actions":           string(insufficientJSON),
						"ok_actions":                          string(okActionsJSON),
						"state_reason":                        aws.ToString(alarm.StateReason),
						"state_reason_data":                   aws.ToString(alarm.StateReasonData),
						"state_transitioned_timestamp":        timeToString(alarm.StateTransitionedTimestamp),
						"state_updated_timestamp":             timeToString(alarm.StateUpdatedTimestamp),
						"state_value":                         string(alarm.StateValue),
					}
					results = append(results, row)
				}
			}
			return results, nil
		},
	}
}

// CloudWatch Dashboards table
func (e *SyncEngine) cloudwatchDashboardTable() TableSpec {
	return TableSpec{
		Name: "aws_cloudwatch_dashboards",
		Columns: []string{
			"_cq_hash", "arn", "dashboard_name", "account_id", "region",
			"last_modified", "size",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := cloudwatch.NewFromConfig(cfg, func(o *cloudwatch.Options) {
				o.Region = region
			})
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			paginator := cloudwatch.NewListDashboardsPaginator(client, &cloudwatch.ListDashboardsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, err
				}

				for _, dashboard := range page.DashboardEntries {
					row := map[string]interface{}{
						"arn":            aws.ToString(dashboard.DashboardArn),
						"dashboard_name": aws.ToString(dashboard.DashboardName),
						"account_id":     accountID,
						"region":         region,
						"last_modified":  timeToString(dashboard.LastModified),
						"size":           dashboard.Size,
					}
					results = append(results, row)
				}
			}
			return results, nil
		},
	}
}

// CloudWatch Metric Streams table
func (e *SyncEngine) cloudwatchMetricStreamTable() TableSpec {
	return TableSpec{
		Name: "aws_cloudwatch_metric_streams",
		Columns: []string{
			"_cq_hash", "arn", "name", "account_id", "region",
			"creation_date", "firehose_arn", "last_update_date",
			"output_format", "state",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := cloudwatch.NewFromConfig(cfg, func(o *cloudwatch.Options) {
				o.Region = region
			})
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			paginator := cloudwatch.NewListMetricStreamsPaginator(client, &cloudwatch.ListMetricStreamsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, err
				}

				for _, stream := range page.Entries {
					row := map[string]interface{}{
						"arn":              aws.ToString(stream.Arn),
						"name":             aws.ToString(stream.Name),
						"account_id":       accountID,
						"region":           region,
						"creation_date":    timeToString(stream.CreationDate),
						"firehose_arn":     aws.ToString(stream.FirehoseArn),
						"last_update_date": timeToString(stream.LastUpdateDate),
						"output_format":    string(stream.OutputFormat),
						"state":            aws.ToString(stream.State),
					}
					results = append(results, row)
				}
			}
			return results, nil
		},
	}
}
