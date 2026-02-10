package sync

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
)

func (e *SyncEngine) sagemakerNotebookTable() TableSpec {
	return TableSpec{
		Name: "aws_sagemaker_notebook_instances",
		Columns: []string{
			"arn", "notebook_instance_name", "region", "account_id", "status",
			"instance_type", "role_arn", "kms_key_id", "direct_internet_access",
			"root_access", "subnet_id", "security_groups", "url",
			"volume_size_in_gb", "creation_time", "last_modified_time", "tags",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := sagemaker.NewFromConfig(cfg)
			var results []map[string]interface{}

			paginator := sagemaker.NewListNotebookInstancesPaginator(client, &sagemaker.ListNotebookInstancesInput{})

			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, fmt.Errorf("list notebook instances: %w", err)
				}

				for _, nb := range page.NotebookInstances {
					arn := ptrToStr(nb.NotebookInstanceArn)
					name := ptrToStr(nb.NotebookInstanceName)

					// Get detailed info
					detail, err := client.DescribeNotebookInstance(ctx, &sagemaker.DescribeNotebookInstanceInput{
						NotebookInstanceName: aws.String(name),
					})

					var tags map[string]string
					if err == nil {
						// Get tags
						tagsResp, _ := client.ListTags(ctx, &sagemaker.ListTagsInput{
							ResourceArn: aws.String(arn),
						})
						if tagsResp != nil {
							tags = make(map[string]string)
							for _, t := range tagsResp.Tags {
								if t.Key != nil && t.Value != nil {
									tags[*t.Key] = *t.Value
								}
							}
						}
					}

					row := map[string]interface{}{
						"_cq_id":                 arn,
						"arn":                    arn,
						"notebook_instance_name": name,
						"region":                 region,
						"account_id":             e.accountID,
						"status":                 string(nb.NotebookInstanceStatus),
						"instance_type":          string(nb.InstanceType),
						"url":                    ptrToStr(nb.Url),
						"creation_time":          nb.CreationTime,
						"last_modified_time":     nb.LastModifiedTime,
						"tags":                   tags,
					}

					if detail != nil {
						row["role_arn"] = ptrToStr(detail.RoleArn)
						row["kms_key_id"] = ptrToStr(detail.KmsKeyId)
						row["direct_internet_access"] = string(detail.DirectInternetAccess)
						row["root_access"] = string(detail.RootAccess)
						row["subnet_id"] = ptrToStr(detail.SubnetId)
						row["security_groups"] = detail.SecurityGroups
						row["volume_size_in_gb"] = detail.VolumeSizeInGB
					}

					results = append(results, row)
				}
			}

			return results, nil
		},
	}
}

func (e *SyncEngine) sagemakerModelTable() TableSpec {
	return TableSpec{
		Name: "aws_sagemaker_models",
		Columns: []string{
			"arn", "model_name", "region", "account_id", "creation_time",
			"execution_role_arn", "enable_network_isolation",
			"primary_container", "containers", "vpc_config", "tags",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := sagemaker.NewFromConfig(cfg)
			var results []map[string]interface{}

			paginator := sagemaker.NewListModelsPaginator(client, &sagemaker.ListModelsInput{})

			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, fmt.Errorf("list models: %w", err)
				}

				for _, model := range page.Models {
					arn := ptrToStr(model.ModelArn)
					name := ptrToStr(model.ModelName)

					// Get detailed info
					detail, err := client.DescribeModel(ctx, &sagemaker.DescribeModelInput{
						ModelName: aws.String(name),
					})

					var tags map[string]string
					tagsResp, _ := client.ListTags(ctx, &sagemaker.ListTagsInput{
						ResourceArn: aws.String(arn),
					})
					if tagsResp != nil {
						tags = make(map[string]string)
						for _, t := range tagsResp.Tags {
							if t.Key != nil && t.Value != nil {
								tags[*t.Key] = *t.Value
							}
						}
					}

					row := map[string]interface{}{
						"_cq_id":        arn,
						"arn":           arn,
						"model_name":    name,
						"region":        region,
						"account_id":    e.accountID,
						"creation_time": model.CreationTime,
						"tags":          tags,
					}

					if err == nil && detail != nil {
						row["execution_role_arn"] = ptrToStr(detail.ExecutionRoleArn)
						row["enable_network_isolation"] = detail.EnableNetworkIsolation
						row["primary_container"] = detail.PrimaryContainer
						row["containers"] = detail.Containers
						row["vpc_config"] = detail.VpcConfig
					}

					results = append(results, row)
				}
			}

			return results, nil
		},
	}
}

func (e *SyncEngine) sagemakerModelPackageGroupTable() TableSpec {
	return TableSpec{
		Name: "aws_sagemaker_model_package_groups",
		Columns: []string{
			"arn", "model_package_group_name", "region", "account_id", "status",
			"description", "creation_time", "created_by", "tags",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := sagemaker.NewFromConfig(cfg)
			var results []map[string]interface{}

			paginator := sagemaker.NewListModelPackageGroupsPaginator(client, &sagemaker.ListModelPackageGroupsInput{})

			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, fmt.Errorf("list model package groups: %w", err)
				}

				for _, group := range page.ModelPackageGroupSummaryList {
					arn := ptrToStr(group.ModelPackageGroupArn)
					name := ptrToStr(group.ModelPackageGroupName)

					row := map[string]interface{}{
						"_cq_id":                   arn,
						"arn":                      arn,
						"model_package_group_name": name,
						"region":                   region,
						"account_id":               e.accountID,
						"status":                   string(group.ModelPackageGroupStatus),
						"description":              ptrToStr(group.ModelPackageGroupDescription),
						"creation_time":            group.CreationTime,
					}

					if name != "" {
						detail, err := client.DescribeModelPackageGroup(ctx, &sagemaker.DescribeModelPackageGroupInput{
							ModelPackageGroupName: aws.String(name),
						})
						if err == nil && detail != nil {
							row["created_by"] = detail.CreatedBy
							row["description"] = ptrToStr(detail.ModelPackageGroupDescription)
							row["status"] = string(detail.ModelPackageGroupStatus)
							row["creation_time"] = detail.CreationTime
						}
					}

					if arn != "" {
						tagsResp, _ := client.ListTags(ctx, &sagemaker.ListTagsInput{
							ResourceArn: aws.String(arn),
						})
						if tagsResp != nil {
							tags := make(map[string]string)
							for _, tag := range tagsResp.Tags {
								if tag.Key != nil && tag.Value != nil {
									tags[*tag.Key] = *tag.Value
								}
							}
							if len(tags) > 0 {
								row["tags"] = tags
							}
						}
					}

					results = append(results, row)
				}
			}

			return results, nil
		},
	}
}

func (e *SyncEngine) sagemakerEndpointTable() TableSpec {
	return TableSpec{
		Name: "aws_sagemaker_endpoints",
		Columns: []string{
			"arn", "endpoint_name", "region", "account_id", "status",
			"endpoint_config_name", "creation_time", "last_modified_time",
			"failure_reason", "production_variants", "data_capture_config", "tags",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := sagemaker.NewFromConfig(cfg)
			var results []map[string]interface{}

			paginator := sagemaker.NewListEndpointsPaginator(client, &sagemaker.ListEndpointsInput{})

			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, fmt.Errorf("list endpoints: %w", err)
				}

				for _, ep := range page.Endpoints {
					arn := ptrToStr(ep.EndpointArn)
					name := ptrToStr(ep.EndpointName)

					// Get detailed info
					detail, err := client.DescribeEndpoint(ctx, &sagemaker.DescribeEndpointInput{
						EndpointName: aws.String(name),
					})

					var tags map[string]string
					tagsResp, _ := client.ListTags(ctx, &sagemaker.ListTagsInput{
						ResourceArn: aws.String(arn),
					})
					if tagsResp != nil {
						tags = make(map[string]string)
						for _, t := range tagsResp.Tags {
							if t.Key != nil && t.Value != nil {
								tags[*t.Key] = *t.Value
							}
						}
					}

					row := map[string]interface{}{
						"_cq_id":             arn,
						"arn":                arn,
						"endpoint_name":      name,
						"region":             region,
						"account_id":         e.accountID,
						"status":             string(ep.EndpointStatus),
						"creation_time":      ep.CreationTime,
						"last_modified_time": ep.LastModifiedTime,
						"tags":               tags,
					}

					if err == nil && detail != nil {
						row["endpoint_config_name"] = ptrToStr(detail.EndpointConfigName)
						row["failure_reason"] = ptrToStr(detail.FailureReason)
						row["production_variants"] = detail.ProductionVariants
						row["data_capture_config"] = detail.DataCaptureConfig
					}

					results = append(results, row)
				}
			}

			return results, nil
		},
	}
}

func (e *SyncEngine) sagemakerTrainingJobTable() TableSpec {
	return TableSpec{
		Name: "aws_sagemaker_training_jobs",
		Columns: []string{
			"arn", "training_job_name", "region", "account_id", "status",
			"creation_time", "training_end_time", "last_modified_time",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := sagemaker.NewFromConfig(cfg)
			var results []map[string]interface{}

			paginator := sagemaker.NewListTrainingJobsPaginator(client, &sagemaker.ListTrainingJobsInput{})

			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, fmt.Errorf("list training jobs: %w", err)
				}

				for _, job := range page.TrainingJobSummaries {
					arn := ptrToStr(job.TrainingJobArn)

					row := map[string]interface{}{
						"_cq_id":             arn,
						"arn":                arn,
						"training_job_name":  ptrToStr(job.TrainingJobName),
						"region":             region,
						"account_id":         e.accountID,
						"status":             string(job.TrainingJobStatus),
						"creation_time":      job.CreationTime,
						"training_end_time":  job.TrainingEndTime,
						"last_modified_time": job.LastModifiedTime,
					}

					results = append(results, row)
				}
			}

			return results, nil
		},
	}
}

func (e *SyncEngine) sagemakerEndpointConfigTable() TableSpec {
	return TableSpec{
		Name: "aws_sagemaker_endpoint_configurations",
		Columns: []string{
			"arn", "endpoint_config_name", "region", "account_id",
			"creation_time", "kms_key_id", "production_variants",
			"data_capture_config", "tags",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := sagemaker.NewFromConfig(cfg)
			var results []map[string]interface{}

			paginator := sagemaker.NewListEndpointConfigsPaginator(client, &sagemaker.ListEndpointConfigsInput{})

			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, fmt.Errorf("list endpoint configs: %w", err)
				}

				for _, cfg := range page.EndpointConfigs {
					arn := ptrToStr(cfg.EndpointConfigArn)
					name := ptrToStr(cfg.EndpointConfigName)

					// Get detailed info
					detail, err := client.DescribeEndpointConfig(ctx, &sagemaker.DescribeEndpointConfigInput{
						EndpointConfigName: aws.String(name),
					})

					var tags map[string]string
					tagsResp, _ := client.ListTags(ctx, &sagemaker.ListTagsInput{
						ResourceArn: aws.String(arn),
					})
					if tagsResp != nil {
						tags = make(map[string]string)
						for _, t := range tagsResp.Tags {
							if t.Key != nil && t.Value != nil {
								tags[*t.Key] = *t.Value
							}
						}
					}

					row := map[string]interface{}{
						"_cq_id":               arn,
						"arn":                  arn,
						"endpoint_config_name": name,
						"region":               region,
						"account_id":           e.accountID,
						"creation_time":        cfg.CreationTime,
						"tags":                 tags,
					}

					if err == nil && detail != nil {
						row["kms_key_id"] = ptrToStr(detail.KmsKeyId)
						row["production_variants"] = detail.ProductionVariants
						row["data_capture_config"] = detail.DataCaptureConfig
					}

					results = append(results, row)
				}
			}

			return results, nil
		},
	}
}
