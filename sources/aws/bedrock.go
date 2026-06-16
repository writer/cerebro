package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrock"
	bedrocktypes "github.com/aws/aws-sdk-go-v2/service/bedrock/types"

	"github.com/writer/cerebro/internal/primitives"
)

type awsBedrockCustomModel struct {
	Summary        bedrocktypes.CustomModelSummary `json:"summary"`
	Detail         *bedrock.GetCustomModelOutput   `json:"detail,omitempty"`
	ResourcePolicy string                          `json:"resource_policy,omitempty"`
	Tags           map[string]string               `json:"tags,omitempty"`
}

func listBedrockCustomModels(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsBedrockCustomModel, string, error) {
	if clients.bedrock == nil {
		return nil, "", nil
	}
	out, err := clients.bedrock.ListCustomModels(ctx, &bedrock.ListCustomModelsInput{
		MaxResults: awssdk.Int32(boundedAWSPageSizeInt32(limit, 1, 1000)),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", fmt.Errorf("list bedrock custom models: %w", err)
	}
	records := make([]awsBedrockCustomModel, 0, len(out.ModelSummaries))
	for _, summary := range out.ModelSummaries {
		arn := awssdk.ToString(summary.ModelArn)
		record := awsBedrockCustomModel{Summary: summary}
		if arn != "" {
			detail, err := clients.bedrock.GetCustomModel(ctx, &bedrock.GetCustomModelInput{ModelIdentifier: awssdk.String(arn)})
			if err != nil {
				if !optionalAWSError(err, "ResourceNotFoundException", "ValidationException") {
					return nil, "", fmt.Errorf("get bedrock custom model %q: %w", arn, err)
				}
			} else {
				record.Detail = detail
			}
			tags, err := clients.bedrock.ListTagsForResource(ctx, &bedrock.ListTagsForResourceInput{ResourceARN: awssdk.String(arn)})
			if err != nil {
				if !optionalAWSError(err, "ResourceNotFoundException", "ValidationException") {
					return nil, "", fmt.Errorf("list bedrock custom model tags %q: %w", arn, err)
				}
			} else {
				record.Tags = bedrockTagMap(tags.Tags)
			}
			policy, err := clients.bedrock.GetResourcePolicy(ctx, &bedrock.GetResourcePolicyInput{ResourceArn: awssdk.String(arn)})
			if err != nil {
				if !optionalAWSError(err, "ResourceNotFoundException", "ValidationException") {
					return nil, "", fmt.Errorf("get bedrock custom model resource policy %q: %w", arn, err)
				}
			} else {
				record.ResourcePolicy = awssdk.ToString(policy.ResourcePolicy)
			}
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func bedrockCustomModelEvent(settings settings, record awsBedrockCustomModel) (*primitives.Event, error) {
	arn := bedrockCustomModelARN(record)
	name := bedrockCustomModelName(record)
	policyPublic := record.ResourcePolicy != "" && policyAllowsWildcardPrincipal(record.ResourcePolicy)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyBedrockCustomModel, firstNonEmpty(arn, name), name, "bedrock_custom_model", record.Tags)
	putAttributes(attributes, map[string]string{
		"arn":                     arn,
		"base_model_arn":          bedrockCustomModelBaseModelARN(record),
		"base_model_name":         bedrockCustomModelBaseModelName(record),
		"custom_model_arn":        arn,
		"custom_model_name":       name,
		"customization_type":      bedrockCustomModelCustomizationType(record),
		"has_resource_policy":     boolString(record.ResourcePolicy != ""),
		"job_arn":                 bedrockCustomModelJobARN(record),
		"job_name":                bedrockCustomModelJobName(record),
		"kms_key_id":              bedrockCustomModelKMSKeyARN(record),
		"model_arn":               arn,
		"model_kms_key_arn":       bedrockCustomModelKMSKeyARN(record),
		"model_name":              name,
		"model_status":            bedrockCustomModelStatus(record),
		"output_data_s3_uri":      bedrockCustomModelOutputS3URI(record),
		"owner_account_id":        awssdk.ToString(record.Summary.OwnerAccountId),
		"public":                  boolString(policyPublic),
		"resource_policy_public":  boolString(policyPublic),
		"training_data_s3_uri":    bedrockCustomModelTrainingS3URI(record),
		"validation_data_s3_uris": strings.Join(bedrockCustomModelValidationS3URIs(record), ","),
	})
	addTimeAttribute(attributes, "created_at", bedrockCustomModelTime(record))
	payload, err := json.Marshal(bedrockSanitizedCustomModel(record))
	if err != nil {
		return nil, fmt.Errorf("marshal bedrock custom model: %w", err)
	}
	return sourceEvent(settings, "aws-bedrock-custom-model-"+firstNonEmpty(arn, name), "aws.bedrock_custom_model", "aws/bedrock_custom_model/v1", payload, attributes, firstTime(bedrockCustomModelTime(record)))
}

func bedrockTagMap(tags []bedrocktypes.Tag) map[string]string {
	result := map[string]string{}
	for _, tag := range tags {
		key := strings.TrimSpace(awssdk.ToString(tag.Key))
		if key == "" {
			continue
		}
		result[key] = awssdk.ToString(tag.Value)
	}
	return result
}

func bedrockSanitizedCustomModel(record awsBedrockCustomModel) awsBedrockCustomModel {
	if record.Detail == nil {
		return record
	}
	detail := *record.Detail
	detail.HyperParameters = nil
	record.Detail = &detail
	return record
}

func bedrockCustomModelARN(record awsBedrockCustomModel) string {
	if record.Detail != nil && awssdk.ToString(record.Detail.ModelArn) != "" {
		return awssdk.ToString(record.Detail.ModelArn)
	}
	return awssdk.ToString(record.Summary.ModelArn)
}

func bedrockCustomModelName(record awsBedrockCustomModel) string {
	if record.Detail != nil && awssdk.ToString(record.Detail.ModelName) != "" {
		return awssdk.ToString(record.Detail.ModelName)
	}
	return awssdk.ToString(record.Summary.ModelName)
}

func bedrockCustomModelBaseModelARN(record awsBedrockCustomModel) string {
	if record.Detail != nil && awssdk.ToString(record.Detail.BaseModelArn) != "" {
		return awssdk.ToString(record.Detail.BaseModelArn)
	}
	return awssdk.ToString(record.Summary.BaseModelArn)
}

func bedrockCustomModelBaseModelName(record awsBedrockCustomModel) string {
	return awssdk.ToString(record.Summary.BaseModelName)
}

func bedrockCustomModelCustomizationType(record awsBedrockCustomModel) string {
	if record.Detail != nil && record.Detail.CustomizationType != "" {
		return string(record.Detail.CustomizationType)
	}
	return string(record.Summary.CustomizationType)
}

func bedrockCustomModelStatus(record awsBedrockCustomModel) string {
	if record.Detail != nil && record.Detail.ModelStatus != "" {
		return string(record.Detail.ModelStatus)
	}
	return string(record.Summary.ModelStatus)
}

func bedrockCustomModelJobARN(record awsBedrockCustomModel) string {
	if record.Detail == nil {
		return ""
	}
	return awssdk.ToString(record.Detail.JobArn)
}

func bedrockCustomModelJobName(record awsBedrockCustomModel) string {
	if record.Detail == nil {
		return ""
	}
	return awssdk.ToString(record.Detail.JobName)
}

func bedrockCustomModelKMSKeyARN(record awsBedrockCustomModel) string {
	if record.Detail == nil {
		return ""
	}
	return awssdk.ToString(record.Detail.ModelKmsKeyArn)
}

func bedrockCustomModelTrainingS3URI(record awsBedrockCustomModel) string {
	if record.Detail == nil || record.Detail.TrainingDataConfig == nil {
		return ""
	}
	return awssdk.ToString(record.Detail.TrainingDataConfig.S3Uri)
}

func bedrockCustomModelOutputS3URI(record awsBedrockCustomModel) string {
	if record.Detail == nil || record.Detail.OutputDataConfig == nil {
		return ""
	}
	return awssdk.ToString(record.Detail.OutputDataConfig.S3Uri)
}

func bedrockCustomModelValidationS3URIs(record awsBedrockCustomModel) []string {
	if record.Detail == nil || record.Detail.ValidationDataConfig == nil {
		return nil
	}
	uris := make([]string, 0, len(record.Detail.ValidationDataConfig.Validators))
	for _, validator := range record.Detail.ValidationDataConfig.Validators {
		uris = append(uris, awssdk.ToString(validator.S3Uri))
	}
	return cleanStrings(uris)
}

func bedrockCustomModelTime(record awsBedrockCustomModel) *time.Time {
	if record.Detail != nil && record.Detail.CreationTime != nil {
		return record.Detail.CreationTime
	}
	return record.Summary.CreationTime
}
