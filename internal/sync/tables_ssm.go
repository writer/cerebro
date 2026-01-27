package sync

import (
	"context"
	"encoding/json"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

// SSM Parameters table
func (e *SyncEngine) ssmParameterTable() TableSpec {
	return TableSpec{
		Name: "aws_ssm_parameters",
		Columns: []string{
			"_cq_hash", "name", "arn", "account_id", "region",
			"type", "key_id", "last_modified_date", "last_modified_user",
			"description", "allowed_pattern", "version", "tier",
			"policies", "data_type", "tags",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := ssm.NewFromConfig(cfg, func(o *ssm.Options) {
				o.Region = region
			})
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			paginator := ssm.NewDescribeParametersPaginator(client, &ssm.DescribeParametersInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, err
				}

				for _, param := range page.Parameters {
					// Get tags
					tagsOut, _ := client.ListTagsForResource(ctx, &ssm.ListTagsForResourceInput{
						ResourceId:   param.Name,
						ResourceType: "Parameter",
					})
					tags := map[string]string{}
					if tagsOut != nil {
						for _, t := range tagsOut.TagList {
							if t.Key != nil && t.Value != nil {
								tags[*t.Key] = *t.Value
							}
						}
					}
					tagsJSON, _ := json.Marshal(tags)
					policiesJSON, _ := json.Marshal(param.Policies)

					row := map[string]interface{}{
						"name":               aws.ToString(param.Name),
						"arn":                aws.ToString(param.ARN),
						"account_id":         accountID,
						"region":             region,
						"type":               string(param.Type),
						"key_id":             aws.ToString(param.KeyId),
						"last_modified_date": timeToString(param.LastModifiedDate),
						"last_modified_user": aws.ToString(param.LastModifiedUser),
						"description":        aws.ToString(param.Description),
						"allowed_pattern":    aws.ToString(param.AllowedPattern),
						"version":            param.Version,
						"tier":               string(param.Tier),
						"policies":           string(policiesJSON),
						"data_type":          aws.ToString(param.DataType),
						"tags":               string(tagsJSON),
					}
					results = append(results, row)
				}
			}
			return results, nil
		},
	}
}

// SSM Managed Instances table
func (e *SyncEngine) ssmManagedInstanceTable() TableSpec {
	return TableSpec{
		Name: "aws_ssm_managed_instances",
		Columns: []string{
			"_cq_hash", "instance_id", "account_id", "region",
			"name", "ping_status", "last_ping_date_time", "agent_version",
			"is_latest_version", "platform_type", "platform_name", "platform_version",
			"activation_id", "iam_role", "registration_date", "resource_type",
			"ip_address", "computer_name", "association_status", "last_association_execution_date",
			"last_successful_association_execution_date", "association_overview",
			"source_id", "source_type",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := ssm.NewFromConfig(cfg, func(o *ssm.Options) {
				o.Region = region
			})
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			paginator := ssm.NewDescribeInstanceInformationPaginator(client, &ssm.DescribeInstanceInformationInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, err
				}

				for _, inst := range page.InstanceInformationList {
					overviewJSON, _ := json.Marshal(inst.AssociationOverview)

					row := map[string]interface{}{
						"instance_id":                     aws.ToString(inst.InstanceId),
						"account_id":                      accountID,
						"region":                          region,
						"name":                            aws.ToString(inst.Name),
						"ping_status":                     string(inst.PingStatus),
						"last_ping_date_time":             timeToString(inst.LastPingDateTime),
						"agent_version":                   aws.ToString(inst.AgentVersion),
						"is_latest_version":               inst.IsLatestVersion,
						"platform_type":                   string(inst.PlatformType),
						"platform_name":                   aws.ToString(inst.PlatformName),
						"platform_version":                aws.ToString(inst.PlatformVersion),
						"activation_id":                   aws.ToString(inst.ActivationId),
						"iam_role":                        aws.ToString(inst.IamRole),
						"registration_date":               timeToString(inst.RegistrationDate),
						"resource_type":                   string(inst.ResourceType),
						"ip_address":                      aws.ToString(inst.IPAddress),
						"computer_name":                   aws.ToString(inst.ComputerName),
						"association_status":              aws.ToString(inst.AssociationStatus),
						"last_association_execution_date": timeToString(inst.LastAssociationExecutionDate),
						"last_successful_association_execution_date": timeToString(inst.LastSuccessfulAssociationExecutionDate),
						"association_overview":                       string(overviewJSON),
						"source_id":                                  aws.ToString(inst.SourceId),
						"source_type":                                string(inst.SourceType),
					}
					results = append(results, row)
				}
			}
			return results, nil
		},
	}
}

// SSM Patch Compliance table
func (e *SyncEngine) ssmPatchComplianceTable() TableSpec {
	return TableSpec{
		Name: "aws_ssm_patch_compliance",
		Columns: []string{
			"_cq_hash", "instance_id", "account_id", "region",
			"baseline_id", "patch_group", "installed_count", "installed_other_count",
			"installed_pending_reboot_count", "installed_rejected_count",
			"missing_count", "failed_count", "unreported_not_applicable_count",
			"not_applicable_count", "operation_start_time", "operation_end_time",
			"operation", "last_no_reboot_install_operation_time", "reboot_option",
			"critical_non_compliant_count", "security_non_compliant_count",
			"other_non_compliant_count",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := ssm.NewFromConfig(cfg, func(o *ssm.Options) {
				o.Region = region
			})
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			paginator := ssm.NewDescribeInstancePatchStatesForPatchGroupPaginator(client, &ssm.DescribeInstancePatchStatesForPatchGroupInput{
				PatchGroup: aws.String("default"),
			})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					// Try alternative approach
					break
				}

				for _, state := range page.InstancePatchStates {
					row := map[string]interface{}{
						"instance_id":                           aws.ToString(state.InstanceId),
						"account_id":                            accountID,
						"region":                                region,
						"baseline_id":                           aws.ToString(state.BaselineId),
						"patch_group":                           aws.ToString(state.PatchGroup),
						"installed_count":                       state.InstalledCount,
						"installed_other_count":                 state.InstalledOtherCount,
						"installed_pending_reboot_count":        state.InstalledPendingRebootCount,
						"installed_rejected_count":              state.InstalledRejectedCount,
						"missing_count":                         state.MissingCount,
						"failed_count":                          state.FailedCount,
						"unreported_not_applicable_count":       state.UnreportedNotApplicableCount,
						"not_applicable_count":                  state.NotApplicableCount,
						"operation_start_time":                  timeToString(state.OperationStartTime),
						"operation_end_time":                    timeToString(state.OperationEndTime),
						"operation":                             string(state.Operation),
						"last_no_reboot_install_operation_time": timeToString(state.LastNoRebootInstallOperationTime),
						"reboot_option":                         string(state.RebootOption),
						"critical_non_compliant_count":          state.CriticalNonCompliantCount,
						"security_non_compliant_count":          state.SecurityNonCompliantCount,
						"other_non_compliant_count":             state.OtherNonCompliantCount,
					}
					results = append(results, row)
				}
			}
			return results, nil
		},
	}
}

// SSM Documents table
func (e *SyncEngine) ssmDocumentTable() TableSpec {
	return TableSpec{
		Name: "aws_ssm_documents",
		Columns: []string{
			"_cq_hash", "name", "arn", "account_id", "region",
			"document_version", "document_type", "schema_version", "document_format",
			"target_type", "owner", "platform_types", "requires",
			"review_status", "status", "status_information", "tags",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := ssm.NewFromConfig(cfg, func(o *ssm.Options) {
				o.Region = region
			})
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			paginator := ssm.NewListDocumentsPaginator(client, &ssm.ListDocumentsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, err
				}

				for _, doc := range page.DocumentIdentifiers {
					platformJSON, _ := json.Marshal(doc.PlatformTypes)
					requiresJSON, _ := json.Marshal(doc.Requires)
					tagsJSON, _ := json.Marshal(doc.Tags)

					row := map[string]interface{}{
						"name":               aws.ToString(doc.Name),
						"arn":                aws.ToString(doc.DocumentVersion), // ARN not available in list
						"account_id":         accountID,
						"region":             region,
						"document_version":   aws.ToString(doc.DocumentVersion),
						"document_type":      string(doc.DocumentType),
						"schema_version":     aws.ToString(doc.SchemaVersion),
						"document_format":    string(doc.DocumentFormat),
						"target_type":        aws.ToString(doc.TargetType),
						"owner":              aws.ToString(doc.Owner),
						"platform_types":     string(platformJSON),
						"requires":           string(requiresJSON),
						"review_status":      string(doc.ReviewStatus),
						"status":             "", // Not in list response
						"status_information": "",
						"tags":               string(tagsJSON),
					}
					results = append(results, row)
				}
			}
			return results, nil
		},
	}
}
