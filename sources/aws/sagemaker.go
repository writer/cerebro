package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
	sagemakertypes "github.com/aws/aws-sdk-go-v2/service/sagemaker/types"

	"github.com/writer/cerebro/internal/primitives"
)

type awsSageMakerNotebookInstance struct {
	Summary sagemakertypes.NotebookInstanceSummary    `json:"summary"`
	Detail  *sagemaker.DescribeNotebookInstanceOutput `json:"detail,omitempty"`
	Tags    map[string]string                         `json:"tags,omitempty"`
}

type awsSageMakerEndpointConfig struct {
	Summary sagemakertypes.EndpointConfigSummary    `json:"summary"`
	Detail  *sagemaker.DescribeEndpointConfigOutput `json:"detail,omitempty"`
	Tags    map[string]string                       `json:"tags,omitempty"`
}

type awsSageMakerModel struct {
	Summary sagemakertypes.ModelSummary    `json:"summary"`
	Detail  *sagemaker.DescribeModelOutput `json:"detail,omitempty"`
	Tags    map[string]string              `json:"tags,omitempty"`
}

type awsSageMakerTrainingJob struct {
	Summary sagemakertypes.TrainingJobSummary    `json:"summary"`
	Detail  *sagemaker.DescribeTrainingJobOutput `json:"detail,omitempty"`
	Tags    map[string]string                    `json:"tags,omitempty"`
}

func listSageMakerEndpointConfigs(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsSageMakerEndpointConfig, string, error) {
	if clients.sageMaker == nil {
		return nil, "", nil
	}
	out, err := clients.sageMaker.ListEndpointConfigs(ctx, &sagemaker.ListEndpointConfigsInput{
		MaxResults: awssdk.Int32(boundedAWSPageSizeInt32(limit, 1, 100)),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", fmt.Errorf("list sagemaker endpoint configurations: %w", err)
	}
	records := make([]awsSageMakerEndpointConfig, 0, len(out.EndpointConfigs))
	for _, summary := range out.EndpointConfigs {
		name := awssdk.ToString(summary.EndpointConfigName)
		record := awsSageMakerEndpointConfig{Summary: summary}
		if name != "" {
			detail, err := clients.sageMaker.DescribeEndpointConfig(ctx, &sagemaker.DescribeEndpointConfigInput{EndpointConfigName: awssdk.String(name)})
			if err != nil {
				if !optionalAWSError(err, "ResourceNotFound", "ResourceNotFoundException", "ValidationException") {
					return nil, "", fmt.Errorf("describe sagemaker endpoint configuration %q: %w", name, err)
				}
			} else {
				record.Detail = detail
			}
		}
		arn := sageMakerEndpointConfigARN(record)
		if arn != "" {
			tags, err := listSageMakerTags(ctx, clients.sageMaker, arn)
			if err != nil {
				if !optionalAWSError(err, "ResourceNotFound", "ResourceNotFoundException", "ValidationException") {
					return nil, "", fmt.Errorf("list sagemaker endpoint configuration tags %q: %w", arn, err)
				}
			} else {
				record.Tags = tags
			}
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func listSageMakerModels(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsSageMakerModel, string, error) {
	if clients.sageMaker == nil {
		return nil, "", nil
	}
	out, err := clients.sageMaker.ListModels(ctx, &sagemaker.ListModelsInput{
		MaxResults: awssdk.Int32(boundedAWSPageSizeInt32(limit, 1, 100)),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", fmt.Errorf("list sagemaker models: %w", err)
	}
	records := make([]awsSageMakerModel, 0, len(out.Models))
	for _, summary := range out.Models {
		name := awssdk.ToString(summary.ModelName)
		record := awsSageMakerModel{Summary: summary}
		if name != "" {
			detail, err := clients.sageMaker.DescribeModel(ctx, &sagemaker.DescribeModelInput{ModelName: awssdk.String(name)})
			if err != nil {
				if !optionalAWSError(err, "ResourceNotFound", "ResourceNotFoundException", "ValidationException") {
					return nil, "", fmt.Errorf("describe sagemaker model %q: %w", name, err)
				}
			} else {
				record.Detail = detail
			}
		}
		arn := sageMakerModelARN(record)
		if arn != "" {
			tags, err := listSageMakerTags(ctx, clients.sageMaker, arn)
			if err != nil {
				if !optionalAWSError(err, "ResourceNotFound", "ResourceNotFoundException", "ValidationException") {
					return nil, "", fmt.Errorf("list sagemaker model tags %q: %w", arn, err)
				}
			} else {
				record.Tags = tags
			}
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func listSageMakerTrainingJobs(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsSageMakerTrainingJob, string, error) {
	if clients.sageMaker == nil {
		return nil, "", nil
	}
	out, err := clients.sageMaker.ListTrainingJobs(ctx, &sagemaker.ListTrainingJobsInput{
		MaxResults: awssdk.Int32(boundedAWSPageSizeInt32(limit, 1, 100)),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", fmt.Errorf("list sagemaker training jobs: %w", err)
	}
	records := make([]awsSageMakerTrainingJob, 0, len(out.TrainingJobSummaries))
	for _, summary := range out.TrainingJobSummaries {
		name := awssdk.ToString(summary.TrainingJobName)
		record := awsSageMakerTrainingJob{Summary: summary}
		if name != "" {
			detail, err := clients.sageMaker.DescribeTrainingJob(ctx, &sagemaker.DescribeTrainingJobInput{TrainingJobName: awssdk.String(name)})
			if err != nil {
				if !optionalAWSError(err, "ResourceNotFound", "ResourceNotFoundException", "ValidationException") {
					return nil, "", fmt.Errorf("describe sagemaker training job %q: %w", name, err)
				}
			} else {
				record.Detail = detail
			}
		}
		arn := sageMakerTrainingJobARN(record)
		if arn != "" {
			tags, err := listSageMakerTags(ctx, clients.sageMaker, arn)
			if err != nil {
				if !optionalAWSError(err, "ResourceNotFound", "ResourceNotFoundException", "ValidationException") {
					return nil, "", fmt.Errorf("list sagemaker training job tags %q: %w", arn, err)
				}
			} else {
				record.Tags = tags
			}
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func listSageMakerNotebookInstances(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsSageMakerNotebookInstance, string, error) {
	if clients.sageMaker == nil {
		return nil, "", nil
	}
	out, err := clients.sageMaker.ListNotebookInstances(ctx, &sagemaker.ListNotebookInstancesInput{
		MaxResults: awssdk.Int32(boundedAWSPageSizeInt32(limit, 1, 100)),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", fmt.Errorf("list sagemaker notebook instances: %w", err)
	}
	records := make([]awsSageMakerNotebookInstance, 0, len(out.NotebookInstances))
	for _, summary := range out.NotebookInstances {
		name := awssdk.ToString(summary.NotebookInstanceName)
		record := awsSageMakerNotebookInstance{Summary: summary}
		if name != "" {
			detail, err := clients.sageMaker.DescribeNotebookInstance(ctx, &sagemaker.DescribeNotebookInstanceInput{NotebookInstanceName: awssdk.String(name)})
			if err != nil {
				if !optionalAWSError(err, "ResourceNotFound", "ResourceNotFoundException", "ValidationException") {
					return nil, "", fmt.Errorf("describe sagemaker notebook instance %q: %w", name, err)
				}
			} else {
				record.Detail = detail
			}
		}
		arn := sageMakerNotebookInstanceARN(record)
		if arn != "" {
			tags, err := listSageMakerTags(ctx, clients.sageMaker, arn)
			if err != nil {
				if !optionalAWSError(err, "ResourceNotFound", "ResourceNotFoundException", "ValidationException") {
					return nil, "", fmt.Errorf("list sagemaker notebook instance tags %q: %w", arn, err)
				}
			} else {
				record.Tags = tags
			}
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func listSageMakerTags(ctx context.Context, client awsSageMakerAPI, arn string) (map[string]string, error) {
	tags := map[string]string{}
	var nextToken *string
	for {
		out, err := client.ListTags(ctx, &sagemaker.ListTagsInput{
			MaxResults:  awssdk.Int32(100),
			NextToken:   nextToken,
			ResourceArn: awssdk.String(arn),
		})
		if err != nil {
			return nil, err
		}
		for _, tag := range out.Tags {
			key := strings.TrimSpace(awssdk.ToString(tag.Key))
			if key == "" {
				continue
			}
			tags[key] = awssdk.ToString(tag.Value)
		}
		if out.NextToken == nil || awssdk.ToString(out.NextToken) == "" {
			return tags, nil
		}
		nextToken = out.NextToken
	}
}

func sageMakerEndpointConfigEvent(settings settings, record awsSageMakerEndpointConfig) (*primitives.Event, error) {
	arn := sageMakerEndpointConfigARN(record)
	name := sageMakerEndpointConfigName(record)
	detail := record.Detail
	attributes := commonCloudAssetAttributes(settings, settings.region, familySageMakerEndpointConfig, firstNonEmpty(arn, name), name, "sagemaker_endpoint_configuration", record.Tags)
	attributes["arn"] = arn
	attributes["endpoint_config_arn"] = arn
	attributes["endpoint_config_name"] = name
	if detail != nil {
		attributes["data_capture_enabled"] = boolString(detail.DataCaptureConfig != nil && awssdk.ToBool(detail.DataCaptureConfig.EnableCapture))
		attributes["enable_network_isolation"] = boolString(awssdk.ToBool(detail.EnableNetworkIsolation))
		attributes["execution_role_arn"] = awssdk.ToString(detail.ExecutionRoleArn)
		attributes["execution_role_name"] = roleNameFromARN(awssdk.ToString(detail.ExecutionRoleArn))
		attributes["role_arn"] = awssdk.ToString(detail.ExecutionRoleArn)
		attributes["role_name"] = roleNameFromARN(awssdk.ToString(detail.ExecutionRoleArn))
		attributes["kms_key_id"] = awssdk.ToString(detail.KmsKeyId)
		attributes["model_names"] = strings.Join(sageMakerEndpointConfigModelNames(detail), ",")
		attributes["production_variant_count"] = fmt.Sprintf("%d", len(detail.ProductionVariants))
		attributes["production_variant_names"] = strings.Join(sageMakerEndpointConfigVariantNames(detail), ",")
		attributes["production_variant_instance_types"] = strings.Join(sageMakerEndpointConfigInstanceTypes(detail), ",")
		attributes["security_group_ids"] = strings.Join(sageMakerEndpointConfigSecurityGroups(detail), ",")
		attributes["subnet_ids"] = strings.Join(sageMakerEndpointConfigSubnets(detail), ",")
		attributes["vpc_configured"] = boolString(detail.VpcConfig != nil)
		if detail.DataCaptureConfig != nil {
			attributes["data_capture_destination_s3_uri"] = awssdk.ToString(detail.DataCaptureConfig.DestinationS3Uri)
			attributes["data_capture_kms_key_id"] = awssdk.ToString(detail.DataCaptureConfig.KmsKeyId)
			attributes["data_capture_sampling_percent"] = sageMakerInt32String(detail.DataCaptureConfig.InitialSamplingPercentage)
		}
		addTimeAttribute(attributes, "created_at", detail.CreationTime)
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("marshal sagemaker endpoint configuration: %w", err)
	}
	return sourceEvent(settings, "aws-sagemaker-endpoint-configuration-"+firstNonEmpty(arn, name), "aws.sagemaker_endpoint_configuration", "aws/sagemaker_endpoint_configuration/v1", payload, attributes, sageMakerEndpointConfigTime(record))
}

func sageMakerModelEvent(settings settings, record awsSageMakerModel) (*primitives.Event, error) {
	arn := sageMakerModelARN(record)
	name := sageMakerModelName(record)
	detail := record.Detail
	attributes := commonCloudAssetAttributes(settings, settings.region, familySageMakerModel, firstNonEmpty(arn, name), name, "sagemaker_model", record.Tags)
	attributes["arn"] = arn
	attributes["model_arn"] = arn
	attributes["model_name"] = name
	if detail != nil {
		attributes["container_count"] = fmt.Sprintf("%d", sageMakerModelContainerCount(detail))
		attributes["enable_network_isolation"] = boolString(awssdk.ToBool(detail.EnableNetworkIsolation))
		attributes["execution_role_arn"] = awssdk.ToString(detail.ExecutionRoleArn)
		attributes["execution_role_name"] = roleNameFromARN(awssdk.ToString(detail.ExecutionRoleArn))
		attributes["role_arn"] = awssdk.ToString(detail.ExecutionRoleArn)
		attributes["role_name"] = roleNameFromARN(awssdk.ToString(detail.ExecutionRoleArn))
		attributes["container_images"] = strings.Join(sageMakerModelContainerImages(detail), ",")
		attributes["model_data_urls"] = strings.Join(sageMakerModelDataURLs(detail), ",")
		attributes["model_package_names"] = strings.Join(sageMakerModelPackageNames(detail), ",")
		attributes["primary_container_image"] = sageMakerContainerImage(detail.PrimaryContainer)
		attributes["primary_container_model_data_url"] = sageMakerContainerModelDataURL(detail.PrimaryContainer)
		attributes["primary_container_model_package_name"] = sageMakerContainerModelPackageName(detail.PrimaryContainer)
		attributes["security_group_ids"] = strings.Join(sageMakerModelSecurityGroups(detail), ",")
		attributes["subnet_ids"] = strings.Join(sageMakerModelSubnets(detail), ",")
		attributes["vpc_configured"] = boolString(detail.VpcConfig != nil)
		addTimeAttribute(attributes, "created_at", detail.CreationTime)
	}
	payload, err := json.Marshal(sageMakerSanitizedModel(record))
	if err != nil {
		return nil, fmt.Errorf("marshal sagemaker model: %w", err)
	}
	return sourceEvent(settings, "aws-sagemaker-model-"+firstNonEmpty(arn, name), "aws.sagemaker_model", "aws/sagemaker_model/v1", payload, attributes, sageMakerModelTime(record))
}

func sageMakerTrainingJobEvent(settings settings, record awsSageMakerTrainingJob) (*primitives.Event, error) {
	arn := sageMakerTrainingJobARN(record)
	name := sageMakerTrainingJobName(record)
	status := sageMakerTrainingJobStatus(record)
	detail := record.Detail
	attributes := commonCloudAssetAttributes(settings, settings.region, familySageMakerTrainingJob, firstNonEmpty(arn, name), name, "sagemaker_training_job", record.Tags)
	attributes["arn"] = arn
	attributes["training_job_arn"] = arn
	attributes["training_job_name"] = name
	attributes["training_job_status"] = status
	attributes["secondary_status"] = sageMakerTrainingJobSecondaryStatus(record)
	if detail != nil {
		attributes["algorithm_name"] = sageMakerTrainingAlgorithmName(detail)
		attributes["billable_time_seconds"] = sageMakerInt32String(detail.BillableTimeInSeconds)
		attributes["enable_inter_container_traffic_encryption"] = boolString(awssdk.ToBool(detail.EnableInterContainerTrafficEncryption))
		attributes["enable_managed_spot_training"] = boolString(awssdk.ToBool(detail.EnableManagedSpotTraining))
		attributes["enable_network_isolation"] = boolString(awssdk.ToBool(detail.EnableNetworkIsolation))
		attributes["instance_count"] = sageMakerTrainingInstanceCount(detail)
		attributes["instance_type"] = sageMakerTrainingInstanceType(detail)
		attributes["model_artifacts_s3_uri"] = sageMakerTrainingModelArtifactsS3URI(detail)
		attributes["output_data_config_kms_key_id"] = sageMakerTrainingOutputKMSKeyID(detail)
		attributes["output_kms_key_id"] = sageMakerTrainingOutputKMSKeyID(detail)
		attributes["output_s3_uri"] = sageMakerTrainingOutputS3URI(detail)
		attributes["resource_kms_key_id"] = sageMakerTrainingVolumeKMSKeyID(detail)
		attributes["role_arn"] = awssdk.ToString(detail.RoleArn)
		attributes["role_name"] = roleNameFromARN(awssdk.ToString(detail.RoleArn))
		attributes["security_group_ids"] = strings.Join(sageMakerTrainingSecurityGroups(detail), ",")
		attributes["subnet_ids"] = strings.Join(sageMakerTrainingSubnets(detail), ",")
		attributes["training_image"] = sageMakerTrainingImage(detail)
		attributes["training_input_mode"] = sageMakerTrainingInputMode(detail)
		attributes["training_time_seconds"] = sageMakerInt32String(detail.TrainingTimeInSeconds)
		attributes["volume_kms_key_id"] = sageMakerTrainingVolumeKMSKeyID(detail)
		attributes["volume_size_gb"] = sageMakerTrainingVolumeSizeGB(detail)
		attributes["vpc_configured"] = boolString(detail.VpcConfig != nil)
		addTimeAttribute(attributes, "created_at", detail.CreationTime)
		addTimeAttribute(attributes, "last_modified_at", detail.LastModifiedTime)
		addTimeAttribute(attributes, "training_end_at", detail.TrainingEndTime)
		addTimeAttribute(attributes, "training_start_at", detail.TrainingStartTime)
	}
	payload, err := json.Marshal(sageMakerSanitizedTrainingJob(record))
	if err != nil {
		return nil, fmt.Errorf("marshal sagemaker training job: %w", err)
	}
	return sourceEvent(settings, "aws-sagemaker-training-job-"+firstNonEmpty(arn, name), "aws.sagemaker_training_job", "aws/sagemaker_training_job/v1", payload, attributes, sageMakerTrainingJobTime(record))
}

func sageMakerNotebookInstanceEvent(settings settings, record awsSageMakerNotebookInstance) (*primitives.Event, error) {
	arn := sageMakerNotebookInstanceARN(record)
	name := sageMakerNotebookInstanceName(record)
	detail := record.Detail
	attributes := commonCloudAssetAttributes(settings, settings.region, familySageMakerNotebookInstance, firstNonEmpty(arn, name), name, "sagemaker_notebook_instance", record.Tags)
	attributes["arn"] = arn
	attributes["notebook_instance_arn"] = arn
	attributes["notebook_instance_name"] = name
	attributes["notebook_instance_status"] = sageMakerNotebookStatus(record)
	attributes["instance_type"] = sageMakerNotebookInstanceType(record)
	attributes["direct_internet_access"] = sageMakerNotebookDirectInternetAccess(detail)
	attributes["internet_exposed"] = boolString(attributes["direct_internet_access"] == string(sagemakertypes.DirectInternetAccessEnabled))
	attributes["root_access"] = sageMakerNotebookRootAccess(detail)
	if detail != nil {
		attributes["kms_key_id"] = awssdk.ToString(detail.KmsKeyId)
		attributes["lifecycle_config_name"] = awssdk.ToString(detail.NotebookInstanceLifecycleConfigName)
		attributes["network_interface_id"] = awssdk.ToString(detail.NetworkInterfaceId)
		attributes["platform_identifier"] = awssdk.ToString(detail.PlatformIdentifier)
		attributes["role_arn"] = awssdk.ToString(detail.RoleArn)
		attributes["role_name"] = roleNameFromARN(awssdk.ToString(detail.RoleArn))
		attributes["security_group_ids"] = strings.Join(cleanStrings(detail.SecurityGroups), ",")
		attributes["subnet_id"] = awssdk.ToString(detail.SubnetId)
		attributes["volume_size_gb"] = sageMakerInt32String(detail.VolumeSizeInGB)
		addTimeAttribute(attributes, "created_at", detail.CreationTime)
		addTimeAttribute(attributes, "last_modified_at", detail.LastModifiedTime)
		if detail.InstanceMetadataServiceConfiguration != nil {
			attributes["minimum_instance_metadata_service_version"] = awssdk.ToString(detail.InstanceMetadataServiceConfiguration.MinimumInstanceMetadataServiceVersion)
		}
		if detail.IpAddressType != "" {
			attributes["ip_address_type"] = string(detail.IpAddressType)
		}
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("marshal sagemaker notebook instance: %w", err)
	}
	return sourceEvent(settings, "aws-sagemaker-notebook-instance-"+firstNonEmpty(arn, name), "aws.sagemaker_notebook_instance", "aws/sagemaker_notebook_instance/v1", payload, attributes, sageMakerNotebookInstanceTime(record))
}

func sageMakerEndpointConfigARN(record awsSageMakerEndpointConfig) string {
	if record.Detail != nil {
		if arn := awssdk.ToString(record.Detail.EndpointConfigArn); arn != "" {
			return arn
		}
	}
	return awssdk.ToString(record.Summary.EndpointConfigArn)
}

func sageMakerEndpointConfigName(record awsSageMakerEndpointConfig) string {
	if record.Detail != nil {
		if name := awssdk.ToString(record.Detail.EndpointConfigName); name != "" {
			return name
		}
	}
	return awssdk.ToString(record.Summary.EndpointConfigName)
}

func sageMakerModelARN(record awsSageMakerModel) string {
	if record.Detail != nil {
		if arn := awssdk.ToString(record.Detail.ModelArn); arn != "" {
			return arn
		}
	}
	return awssdk.ToString(record.Summary.ModelArn)
}

func sageMakerModelName(record awsSageMakerModel) string {
	if record.Detail != nil {
		if name := awssdk.ToString(record.Detail.ModelName); name != "" {
			return name
		}
	}
	return awssdk.ToString(record.Summary.ModelName)
}

func sageMakerTrainingJobARN(record awsSageMakerTrainingJob) string {
	if record.Detail != nil {
		if arn := awssdk.ToString(record.Detail.TrainingJobArn); arn != "" {
			return arn
		}
	}
	return awssdk.ToString(record.Summary.TrainingJobArn)
}

func sageMakerTrainingJobName(record awsSageMakerTrainingJob) string {
	if record.Detail != nil {
		if name := awssdk.ToString(record.Detail.TrainingJobName); name != "" {
			return name
		}
	}
	return awssdk.ToString(record.Summary.TrainingJobName)
}

func sageMakerTrainingJobStatus(record awsSageMakerTrainingJob) string {
	if record.Detail != nil && record.Detail.TrainingJobStatus != "" {
		return string(record.Detail.TrainingJobStatus)
	}
	return string(record.Summary.TrainingJobStatus)
}

func sageMakerTrainingJobSecondaryStatus(record awsSageMakerTrainingJob) string {
	if record.Detail != nil && record.Detail.SecondaryStatus != "" {
		return string(record.Detail.SecondaryStatus)
	}
	return string(record.Summary.SecondaryStatus)
}

func sageMakerNotebookInstanceARN(record awsSageMakerNotebookInstance) string {
	if record.Detail != nil {
		if arn := awssdk.ToString(record.Detail.NotebookInstanceArn); arn != "" {
			return arn
		}
	}
	return awssdk.ToString(record.Summary.NotebookInstanceArn)
}

func sageMakerNotebookInstanceName(record awsSageMakerNotebookInstance) string {
	if record.Detail != nil {
		if name := awssdk.ToString(record.Detail.NotebookInstanceName); name != "" {
			return name
		}
	}
	return awssdk.ToString(record.Summary.NotebookInstanceName)
}

func sageMakerNotebookStatus(record awsSageMakerNotebookInstance) string {
	if record.Detail != nil && record.Detail.NotebookInstanceStatus != "" {
		return string(record.Detail.NotebookInstanceStatus)
	}
	return string(record.Summary.NotebookInstanceStatus)
}

func sageMakerNotebookInstanceType(record awsSageMakerNotebookInstance) string {
	if record.Detail != nil && record.Detail.InstanceType != "" {
		return string(record.Detail.InstanceType)
	}
	return string(record.Summary.InstanceType)
}

func sageMakerNotebookDirectInternetAccess(detail *sagemaker.DescribeNotebookInstanceOutput) string {
	if detail == nil {
		return ""
	}
	return string(detail.DirectInternetAccess)
}

func sageMakerNotebookRootAccess(detail *sagemaker.DescribeNotebookInstanceOutput) string {
	if detail == nil {
		return ""
	}
	return string(detail.RootAccess)
}

func sageMakerNotebookInstanceTime(record awsSageMakerNotebookInstance) time.Time {
	if record.Detail != nil {
		return firstTime(record.Detail.LastModifiedTime, record.Detail.CreationTime)
	}
	return firstTime(record.Summary.LastModifiedTime, record.Summary.CreationTime)
}

func sageMakerEndpointConfigTime(record awsSageMakerEndpointConfig) time.Time {
	if record.Detail != nil {
		return firstTime(record.Detail.CreationTime)
	}
	return firstTime(record.Summary.CreationTime)
}

func sageMakerModelTime(record awsSageMakerModel) time.Time {
	if record.Detail != nil {
		return firstTime(record.Detail.CreationTime)
	}
	return firstTime(record.Summary.CreationTime)
}

func sageMakerTrainingJobTime(record awsSageMakerTrainingJob) time.Time {
	if record.Detail != nil {
		return firstTime(record.Detail.LastModifiedTime, record.Detail.TrainingEndTime, record.Detail.CreationTime)
	}
	return firstTime(record.Summary.LastModifiedTime, record.Summary.TrainingEndTime, record.Summary.CreationTime)
}

func sageMakerTrainingAlgorithmName(detail *sagemaker.DescribeTrainingJobOutput) string {
	if detail.AlgorithmSpecification == nil {
		return ""
	}
	return awssdk.ToString(detail.AlgorithmSpecification.AlgorithmName)
}

func sageMakerTrainingImage(detail *sagemaker.DescribeTrainingJobOutput) string {
	if detail.AlgorithmSpecification == nil {
		return ""
	}
	return awssdk.ToString(detail.AlgorithmSpecification.TrainingImage)
}

func sageMakerTrainingInputMode(detail *sagemaker.DescribeTrainingJobOutput) string {
	if detail.AlgorithmSpecification == nil {
		return ""
	}
	return string(detail.AlgorithmSpecification.TrainingInputMode)
}

func sageMakerTrainingOutputKMSKeyID(detail *sagemaker.DescribeTrainingJobOutput) string {
	if detail.OutputDataConfig == nil {
		return ""
	}
	return awssdk.ToString(detail.OutputDataConfig.KmsKeyId)
}

func sageMakerTrainingOutputS3URI(detail *sagemaker.DescribeTrainingJobOutput) string {
	if detail.OutputDataConfig == nil {
		return ""
	}
	return awssdk.ToString(detail.OutputDataConfig.S3OutputPath)
}

func sageMakerTrainingModelArtifactsS3URI(detail *sagemaker.DescribeTrainingJobOutput) string {
	if detail.ModelArtifacts == nil {
		return ""
	}
	return awssdk.ToString(detail.ModelArtifacts.S3ModelArtifacts)
}

func sageMakerTrainingInstanceCount(detail *sagemaker.DescribeTrainingJobOutput) string {
	if detail.ResourceConfig == nil {
		return ""
	}
	return sageMakerInt32String(detail.ResourceConfig.InstanceCount)
}

func sageMakerTrainingInstanceType(detail *sagemaker.DescribeTrainingJobOutput) string {
	if detail.ResourceConfig == nil {
		return ""
	}
	return string(detail.ResourceConfig.InstanceType)
}

func sageMakerTrainingVolumeKMSKeyID(detail *sagemaker.DescribeTrainingJobOutput) string {
	if detail.ResourceConfig == nil {
		return ""
	}
	return awssdk.ToString(detail.ResourceConfig.VolumeKmsKeyId)
}

func sageMakerTrainingVolumeSizeGB(detail *sagemaker.DescribeTrainingJobOutput) string {
	if detail.ResourceConfig == nil {
		return ""
	}
	return sageMakerInt32String(detail.ResourceConfig.VolumeSizeInGB)
}

func sageMakerTrainingSecurityGroups(detail *sagemaker.DescribeTrainingJobOutput) []string {
	if detail.VpcConfig == nil {
		return nil
	}
	return cleanStrings(detail.VpcConfig.SecurityGroupIds)
}

func sageMakerTrainingSubnets(detail *sagemaker.DescribeTrainingJobOutput) []string {
	if detail.VpcConfig == nil {
		return nil
	}
	return cleanStrings(detail.VpcConfig.Subnets)
}

func sageMakerModelContainerCount(detail *sagemaker.DescribeModelOutput) int {
	if len(detail.Containers) > 0 {
		return len(detail.Containers)
	}
	if detail.PrimaryContainer != nil {
		return 1
	}
	return 0
}

func sageMakerModelContainers(detail *sagemaker.DescribeModelOutput) []sagemakertypes.ContainerDefinition {
	if len(detail.Containers) > 0 {
		return detail.Containers
	}
	if detail.PrimaryContainer != nil {
		return []sagemakertypes.ContainerDefinition{*detail.PrimaryContainer}
	}
	return nil
}

func sageMakerModelContainerImages(detail *sagemaker.DescribeModelOutput) []string {
	containers := sageMakerModelContainers(detail)
	values := make([]string, 0, len(containers))
	for _, container := range containers {
		values = append(values, awssdk.ToString(container.Image))
	}
	return cleanStrings(values)
}

func sageMakerModelDataURLs(detail *sagemaker.DescribeModelOutput) []string {
	containers := sageMakerModelContainers(detail)
	values := make([]string, 0, len(containers))
	for _, container := range containers {
		values = append(values, awssdk.ToString(container.ModelDataUrl))
	}
	return cleanStrings(values)
}

func sageMakerModelPackageNames(detail *sagemaker.DescribeModelOutput) []string {
	containers := sageMakerModelContainers(detail)
	values := make([]string, 0, len(containers))
	for _, container := range containers {
		values = append(values, awssdk.ToString(container.ModelPackageName))
	}
	return cleanStrings(values)
}

func sageMakerContainerImage(container *sagemakertypes.ContainerDefinition) string {
	if container == nil {
		return ""
	}
	return awssdk.ToString(container.Image)
}

func sageMakerContainerModelDataURL(container *sagemakertypes.ContainerDefinition) string {
	if container == nil {
		return ""
	}
	return awssdk.ToString(container.ModelDataUrl)
}

func sageMakerContainerModelPackageName(container *sagemakertypes.ContainerDefinition) string {
	if container == nil {
		return ""
	}
	return awssdk.ToString(container.ModelPackageName)
}

func sageMakerModelSecurityGroups(detail *sagemaker.DescribeModelOutput) []string {
	if detail.VpcConfig == nil {
		return nil
	}
	return cleanStrings(detail.VpcConfig.SecurityGroupIds)
}

func sageMakerModelSubnets(detail *sagemaker.DescribeModelOutput) []string {
	if detail.VpcConfig == nil {
		return nil
	}
	return cleanStrings(detail.VpcConfig.Subnets)
}

func sageMakerSanitizedModel(record awsSageMakerModel) awsSageMakerModel {
	if record.Detail == nil {
		return record
	}
	detail := *record.Detail
	if detail.PrimaryContainer != nil {
		primary := *detail.PrimaryContainer
		primary.Environment = nil
		detail.PrimaryContainer = &primary
	}
	if len(detail.Containers) > 0 {
		containers := append([]sagemakertypes.ContainerDefinition(nil), detail.Containers...)
		for index := range containers {
			containers[index].Environment = nil
		}
		detail.Containers = containers
	}
	record.Detail = &detail
	return record
}

func sageMakerSanitizedTrainingJob(record awsSageMakerTrainingJob) awsSageMakerTrainingJob {
	if record.Detail == nil {
		return record
	}
	detail := *record.Detail
	detail.Environment = nil
	detail.HyperParameters = nil
	record.Detail = &detail
	return record
}

func sageMakerEndpointConfigModelNames(detail *sagemaker.DescribeEndpointConfigOutput) []string {
	values := make([]string, 0, len(detail.ProductionVariants)+len(detail.ShadowProductionVariants))
	for _, variant := range append(detail.ProductionVariants, detail.ShadowProductionVariants...) {
		values = append(values, awssdk.ToString(variant.ModelName))
	}
	return cleanStrings(values)
}

func sageMakerEndpointConfigVariantNames(detail *sagemaker.DescribeEndpointConfigOutput) []string {
	values := make([]string, 0, len(detail.ProductionVariants)+len(detail.ShadowProductionVariants))
	for _, variant := range append(detail.ProductionVariants, detail.ShadowProductionVariants...) {
		values = append(values, awssdk.ToString(variant.VariantName))
	}
	return cleanStrings(values)
}

func sageMakerEndpointConfigInstanceTypes(detail *sagemaker.DescribeEndpointConfigOutput) []string {
	values := make([]string, 0, len(detail.ProductionVariants)+len(detail.ShadowProductionVariants))
	for _, variant := range append(detail.ProductionVariants, detail.ShadowProductionVariants...) {
		if variant.InstanceType != "" {
			values = append(values, string(variant.InstanceType))
		}
	}
	return cleanStrings(values)
}

func sageMakerEndpointConfigSecurityGroups(detail *sagemaker.DescribeEndpointConfigOutput) []string {
	if detail.VpcConfig == nil {
		return nil
	}
	return cleanStrings(detail.VpcConfig.SecurityGroupIds)
}

func sageMakerEndpointConfigSubnets(detail *sagemaker.DescribeEndpointConfigOutput) []string {
	if detail.VpcConfig == nil {
		return nil
	}
	return cleanStrings(detail.VpcConfig.Subnets)
}

func sageMakerInt32String(value *int32) string {
	if value == nil {
		return ""
	}
	return fmt.Sprintf("%d", *value)
}
