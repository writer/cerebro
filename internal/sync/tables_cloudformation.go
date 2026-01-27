package sync

import (
	"context"
	"encoding/json"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
)

// CloudFormation Stacks table
func (e *SyncEngine) cloudformationStackTable() TableSpec {
	return TableSpec{
		Name: "aws_cloudformation_stacks",
		Columns: []string{
			"_cq_hash", "arn", "stack_name", "account_id", "region",
			"stack_id", "stack_status", "stack_status_reason", "creation_time",
			"last_updated_time", "deletion_time", "description", "disable_rollback",
			"enable_termination_protection", "drift_information", "notification_arns",
			"outputs", "parameters", "parent_id", "role_arn", "root_id",
			"timeout_in_minutes", "capabilities", "tags",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := cloudformation.NewFromConfig(cfg, func(o *cloudformation.Options) {
				o.Region = region
			})
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			paginator := cloudformation.NewDescribeStacksPaginator(client, &cloudformation.DescribeStacksInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, err
				}

				for _, stack := range page.Stacks {
					driftJSON, _ := json.Marshal(stack.DriftInformation)
					notificationsJSON, _ := json.Marshal(stack.NotificationARNs)
					outputsJSON, _ := json.Marshal(stack.Outputs)
					paramsJSON, _ := json.Marshal(stack.Parameters)
					capsJSON, _ := json.Marshal(stack.Capabilities)

					tags := map[string]string{}
					for _, t := range stack.Tags {
						if t.Key != nil && t.Value != nil {
							tags[*t.Key] = *t.Value
						}
					}
					tagsJSON, _ := json.Marshal(tags)

					row := map[string]interface{}{
						"arn":                           aws.ToString(stack.StackId),
						"stack_name":                    aws.ToString(stack.StackName),
						"account_id":                    accountID,
						"region":                        region,
						"stack_id":                      aws.ToString(stack.StackId),
						"stack_status":                  string(stack.StackStatus),
						"stack_status_reason":           aws.ToString(stack.StackStatusReason),
						"creation_time":                 timeToString(stack.CreationTime),
						"last_updated_time":             timeToString(stack.LastUpdatedTime),
						"deletion_time":                 timeToString(stack.DeletionTime),
						"description":                   aws.ToString(stack.Description),
						"disable_rollback":              stack.DisableRollback,
						"enable_termination_protection": stack.EnableTerminationProtection,
						"drift_information":             string(driftJSON),
						"notification_arns":             string(notificationsJSON),
						"outputs":                       string(outputsJSON),
						"parameters":                    string(paramsJSON),
						"parent_id":                     aws.ToString(stack.ParentId),
						"role_arn":                      aws.ToString(stack.RoleARN),
						"root_id":                       aws.ToString(stack.RootId),
						"timeout_in_minutes":            stack.TimeoutInMinutes,
						"capabilities":                  string(capsJSON),
						"tags":                          string(tagsJSON),
					}
					results = append(results, row)
				}
			}
			return results, nil
		},
	}
}

// CloudFormation Stack Resources table
func (e *SyncEngine) cloudformationStackResourceTable() TableSpec {
	return TableSpec{
		Name: "aws_cloudformation_stack_resources",
		Columns: []string{
			"_cq_hash", "stack_name", "stack_id", "account_id", "region",
			"logical_resource_id", "physical_resource_id", "resource_type",
			"resource_status", "resource_status_reason", "last_updated_timestamp",
			"drift_information", "module_info",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := cloudformation.NewFromConfig(cfg, func(o *cloudformation.Options) {
				o.Region = region
			})
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			// First get all stacks
			stacksPaginator := cloudformation.NewDescribeStacksPaginator(client, &cloudformation.DescribeStacksInput{})
			for stacksPaginator.HasMorePages() {
				stacksPage, err := stacksPaginator.NextPage(ctx)
				if err != nil {
					return nil, err
				}

				for _, stack := range stacksPage.Stacks {
					stackName := aws.ToString(stack.StackName)

					// Get resources for this stack
					resourcesPaginator := cloudformation.NewListStackResourcesPaginator(client, &cloudformation.ListStackResourcesInput{
						StackName: aws.String(stackName),
					})
					for resourcesPaginator.HasMorePages() {
						resourcesPage, err := resourcesPaginator.NextPage(ctx)
						if err != nil {
							break
						}

						for _, resource := range resourcesPage.StackResourceSummaries {
							driftJSON, _ := json.Marshal(resource.DriftInformation)
							moduleJSON, _ := json.Marshal(resource.ModuleInfo)

							row := map[string]interface{}{
								"stack_name":             stackName,
								"stack_id":               aws.ToString(stack.StackId),
								"account_id":             accountID,
								"region":                 region,
								"logical_resource_id":    aws.ToString(resource.LogicalResourceId),
								"physical_resource_id":   aws.ToString(resource.PhysicalResourceId),
								"resource_type":          aws.ToString(resource.ResourceType),
								"resource_status":        string(resource.ResourceStatus),
								"resource_status_reason": aws.ToString(resource.ResourceStatusReason),
								"last_updated_timestamp": timeToString(resource.LastUpdatedTimestamp),
								"drift_information":      string(driftJSON),
								"module_info":            string(moduleJSON),
							}
							results = append(results, row)
						}
					}
				}
			}
			return results, nil
		},
	}
}
