package sync

import (
	"context"
	"encoding/json"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
)

// Step Functions State Machines table
func (e *SyncEngine) sfnStateMachineTable() TableSpec {
	return TableSpec{
		Name: "aws_sfn_state_machines",
		Columns: []string{
			"_cq_hash", "arn", "name", "account_id", "region",
			"creation_date", "type", "status", "definition",
			"role_arn", "logging_configuration", "tracing_configuration",
			"label", "revision_id", "description", "tags",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := sfn.NewFromConfig(cfg, func(o *sfn.Options) {
				o.Region = region
			})
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			paginator := sfn.NewListStateMachinesPaginator(client, &sfn.ListStateMachinesInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, err
				}

				for _, sm := range page.StateMachines {
					// Get full details
					detail, err := client.DescribeStateMachine(ctx, &sfn.DescribeStateMachineInput{
						StateMachineArn: sm.StateMachineArn,
					})
					if err != nil {
						continue
					}

					// Get tags
					tagsOut, _ := client.ListTagsForResource(ctx, &sfn.ListTagsForResourceInput{
						ResourceArn: sm.StateMachineArn,
					})
					tags := map[string]string{}
					if tagsOut != nil {
						for _, t := range tagsOut.Tags {
							if t.Key != nil && t.Value != nil {
								tags[*t.Key] = *t.Value
							}
						}
					}
					tagsJSON, _ := json.Marshal(tags)
					loggingJSON, _ := json.Marshal(detail.LoggingConfiguration)
					tracingJSON, _ := json.Marshal(detail.TracingConfiguration)

					row := map[string]interface{}{
						"arn":                   aws.ToString(detail.StateMachineArn),
						"name":                  aws.ToString(detail.Name),
						"account_id":            accountID,
						"region":                region,
						"creation_date":         timeToString(detail.CreationDate),
						"type":                  string(detail.Type),
						"status":                string(detail.Status),
						"definition":            aws.ToString(detail.Definition),
						"role_arn":              aws.ToString(detail.RoleArn),
						"logging_configuration": string(loggingJSON),
						"tracing_configuration": string(tracingJSON),
						"label":                 aws.ToString(detail.Label),
						"revision_id":           aws.ToString(detail.RevisionId),
						"description":           aws.ToString(detail.Description),
						"tags":                  string(tagsJSON),
					}
					results = append(results, row)
				}
			}
			return results, nil
		},
	}
}

// Step Functions Activities table
func (e *SyncEngine) sfnActivityTable() TableSpec {
	return TableSpec{
		Name: "aws_sfn_activities",
		Columns: []string{
			"_cq_hash", "arn", "name", "account_id", "region",
			"creation_date",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := sfn.NewFromConfig(cfg, func(o *sfn.Options) {
				o.Region = region
			})
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			paginator := sfn.NewListActivitiesPaginator(client, &sfn.ListActivitiesInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, err
				}

				for _, activity := range page.Activities {
					row := map[string]interface{}{
						"arn":           aws.ToString(activity.ActivityArn),
						"name":          aws.ToString(activity.Name),
						"account_id":    accountID,
						"region":        region,
						"creation_date": timeToString(activity.CreationDate),
					}
					results = append(results, row)
				}
			}
			return results, nil
		},
	}
}
