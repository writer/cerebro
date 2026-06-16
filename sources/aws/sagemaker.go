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

func sageMakerInt32String(value *int32) string {
	if value == nil {
		return ""
	}
	return fmt.Sprintf("%d", *value)
}
