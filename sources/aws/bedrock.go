package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
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

type awsBedrockProvisionedModelThroughput struct {
	Summary                   bedrocktypes.ProvisionedModelSummary                       `json:"summary"`
	Detail                    *bedrock.GetProvisionedModelThroughputOutput               `json:"detail,omitempty"`
	Tags                      map[string]string                                          `json:"tags,omitempty"`
	AccountEnforcedGuardrails []bedrocktypes.AccountEnforcedGuardrailOutputConfiguration `json:"account_enforced_guardrails,omitempty"`
	MatchedGuardrails         []bedrocktypes.AccountEnforcedGuardrailOutputConfiguration `json:"matched_guardrails,omitempty"`
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

func listBedrockProvisionedModelThroughputs(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsBedrockProvisionedModelThroughput, string, error) {
	if clients.bedrock == nil {
		return nil, "", nil
	}
	out, err := clients.bedrock.ListProvisionedModelThroughputs(ctx, &bedrock.ListProvisionedModelThroughputsInput{
		MaxResults: awssdk.Int32(boundedAWSPageSizeInt32(limit, 1, 1000)),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", fmt.Errorf("list bedrock provisioned model throughputs: %w", err)
	}
	var accountGuardrails []bedrocktypes.AccountEnforcedGuardrailOutputConfiguration
	if len(out.ProvisionedModelSummaries) > 0 {
		accountGuardrails, err = listBedrockEnforcedGuardrailConfigurations(ctx, clients)
		if err != nil {
			return nil, "", err
		}
	}
	records := make([]awsBedrockProvisionedModelThroughput, 0, len(out.ProvisionedModelSummaries))
	for _, summary := range out.ProvisionedModelSummaries {
		arn := awssdk.ToString(summary.ProvisionedModelArn)
		record := awsBedrockProvisionedModelThroughput{Summary: summary, AccountEnforcedGuardrails: accountGuardrails}
		if arn != "" {
			detail, err := clients.bedrock.GetProvisionedModelThroughput(ctx, &bedrock.GetProvisionedModelThroughputInput{ProvisionedModelId: awssdk.String(arn)})
			if err != nil {
				if !optionalAWSError(err, "ResourceNotFoundException", "ValidationException") {
					return nil, "", fmt.Errorf("get bedrock provisioned model throughput %q: %w", arn, err)
				}
			} else {
				record.Detail = detail
			}
			tags, err := clients.bedrock.ListTagsForResource(ctx, &bedrock.ListTagsForResourceInput{ResourceARN: awssdk.String(arn)})
			if err != nil {
				if !optionalAWSError(err, "ResourceNotFoundException", "ValidationException") {
					return nil, "", fmt.Errorf("list bedrock provisioned model throughput tags %q: %w", arn, err)
				}
			} else {
				record.Tags = bedrockTagMap(tags.Tags)
			}
		}
		record.MatchedGuardrails = bedrockMatchingGuardrails(record, accountGuardrails)
		records = append(records, record)
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func listBedrockEnforcedGuardrailConfigurations(ctx context.Context, clients awsClients) ([]bedrocktypes.AccountEnforcedGuardrailOutputConfiguration, error) {
	var records []bedrocktypes.AccountEnforcedGuardrailOutputConfiguration
	var nextToken *string
	const maxRecords = 1000
	seen := map[string]bool{}
	for {
		out, err := clients.bedrock.ListEnforcedGuardrailsConfiguration(ctx, &bedrock.ListEnforcedGuardrailsConfigurationInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("list bedrock enforced guardrail configurations: %w", err)
		}
		records = append(records, out.GuardrailsConfig...)
		if len(records) >= maxRecords {
			return records[:maxRecords], nil
		}
		token := awssdk.ToString(out.NextToken)
		if token == "" {
			return records, nil
		}
		if seen[token] {
			return nil, fmt.Errorf("bedrock enforced guardrail pagination repeated token")
		}
		seen[token] = true
		nextToken = out.NextToken
	}
}

func bedrockProvisionedModelThroughputEvent(settings settings, record awsBedrockProvisionedModelThroughput) (*primitives.Event, error) {
	arn := bedrockProvisionedModelThroughputARN(record)
	name := bedrockProvisionedModelThroughputName(record)
	matchedGuardrails := bedrockMatchedGuardrailIdentifiers(record.MatchedGuardrails)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyBedrockProvisionedModelThroughput, firstNonEmpty(arn, name), name, "bedrock_provisioned_model_throughput", record.Tags)
	putAttributes(attributes, map[string]string{
		"arn":                                 arn,
		"account_enforced_guardrail_arns":     strings.Join(bedrockGuardrailARNs(record.AccountEnforcedGuardrails), ","),
		"account_enforced_guardrail_count":    strconv.Itoa(len(record.AccountEnforcedGuardrails)),
		"account_enforced_guardrail_ids":      strings.Join(bedrockGuardrailIDs(record.AccountEnforcedGuardrails), ","),
		"commitment_duration":                 bedrockProvisionedModelThroughputCommitmentDuration(record),
		"desired_model_arn":                   bedrockProvisionedModelThroughputDesiredModelARN(record),
		"desired_model_units":                 int32AttrString(bedrockProvisionedModelThroughputDesiredModelUnits(record)),
		"failure_message":                     bedrockProvisionedModelThroughputFailureMessage(record),
		"foundation_model_arn":                bedrockProvisionedModelThroughputFoundationModelARN(record),
		"guardrail_arns":                      strings.Join(bedrockGuardrailARNs(record.MatchedGuardrails), ","),
		"guardrail_enforcement_state":         bedrockGuardrailEnforcementState(record),
		"guardrail_identifier":                firstNonEmpty(matchedGuardrails...),
		"guardrail_identifiers":               strings.Join(matchedGuardrails, ","),
		"guardrail_versions":                  strings.Join(bedrockGuardrailVersions(record.MatchedGuardrails), ","),
		"matched_enforced_guardrail_count":    strconv.Itoa(len(record.MatchedGuardrails)),
		"model_arn":                           bedrockProvisionedModelThroughputModelARN(record),
		"model_units":                         int32AttrString(bedrockProvisionedModelThroughputModelUnits(record)),
		"provisioned_model_arn":               arn,
		"provisioned_model_name":              name,
		"provisioned_model_throughput_arn":    arn,
		"provisioned_model_throughput_name":   name,
		"provisioned_model_throughput_status": bedrockProvisionedModelThroughputStatus(record),
		"resource_status":                     bedrockProvisionedModelThroughputStatus(record),
	})
	addTimeAttribute(attributes, "commitment_expiration_time", bedrockProvisionedModelThroughputCommitmentExpiration(record))
	addTimeAttribute(attributes, "created_at", bedrockProvisionedModelThroughputCreationTime(record))
	addTimeAttribute(attributes, "last_modified_at", bedrockProvisionedModelThroughputLastModifiedTime(record))
	payload, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("marshal bedrock provisioned model throughput: %w", err)
	}
	return sourceEvent(settings, "aws-bedrock-provisioned-model-throughput-"+firstNonEmpty(arn, name), "aws.bedrock_provisioned_model_throughput", "aws/bedrock_provisioned_model_throughput/v1", payload, attributes, firstTime(bedrockProvisionedModelThroughputCreationTime(record), bedrockProvisionedModelThroughputLastModifiedTime(record)))
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

func bedrockProvisionedModelThroughputARN(record awsBedrockProvisionedModelThroughput) string {
	if record.Detail != nil && awssdk.ToString(record.Detail.ProvisionedModelArn) != "" {
		return awssdk.ToString(record.Detail.ProvisionedModelArn)
	}
	return awssdk.ToString(record.Summary.ProvisionedModelArn)
}

func bedrockProvisionedModelThroughputName(record awsBedrockProvisionedModelThroughput) string {
	if record.Detail != nil && awssdk.ToString(record.Detail.ProvisionedModelName) != "" {
		return awssdk.ToString(record.Detail.ProvisionedModelName)
	}
	return awssdk.ToString(record.Summary.ProvisionedModelName)
}

func bedrockProvisionedModelThroughputModelARN(record awsBedrockProvisionedModelThroughput) string {
	if record.Detail != nil && awssdk.ToString(record.Detail.ModelArn) != "" {
		return awssdk.ToString(record.Detail.ModelArn)
	}
	return awssdk.ToString(record.Summary.ModelArn)
}

func bedrockProvisionedModelThroughputDesiredModelARN(record awsBedrockProvisionedModelThroughput) string {
	if record.Detail != nil && awssdk.ToString(record.Detail.DesiredModelArn) != "" {
		return awssdk.ToString(record.Detail.DesiredModelArn)
	}
	return awssdk.ToString(record.Summary.DesiredModelArn)
}

func bedrockProvisionedModelThroughputFoundationModelARN(record awsBedrockProvisionedModelThroughput) string {
	if record.Detail != nil && awssdk.ToString(record.Detail.FoundationModelArn) != "" {
		return awssdk.ToString(record.Detail.FoundationModelArn)
	}
	return awssdk.ToString(record.Summary.FoundationModelArn)
}

func bedrockProvisionedModelThroughputModelUnits(record awsBedrockProvisionedModelThroughput) *int32 {
	if record.Detail != nil && record.Detail.ModelUnits != nil {
		return record.Detail.ModelUnits
	}
	return record.Summary.ModelUnits
}

func bedrockProvisionedModelThroughputDesiredModelUnits(record awsBedrockProvisionedModelThroughput) *int32 {
	if record.Detail != nil && record.Detail.DesiredModelUnits != nil {
		return record.Detail.DesiredModelUnits
	}
	return record.Summary.DesiredModelUnits
}

func bedrockProvisionedModelThroughputStatus(record awsBedrockProvisionedModelThroughput) string {
	if record.Detail != nil && record.Detail.Status != "" {
		return string(record.Detail.Status)
	}
	return string(record.Summary.Status)
}

func bedrockProvisionedModelThroughputCommitmentDuration(record awsBedrockProvisionedModelThroughput) string {
	if record.Detail != nil && record.Detail.CommitmentDuration != "" {
		return string(record.Detail.CommitmentDuration)
	}
	return string(record.Summary.CommitmentDuration)
}

func bedrockProvisionedModelThroughputFailureMessage(record awsBedrockProvisionedModelThroughput) string {
	if record.Detail == nil {
		return ""
	}
	return awssdk.ToString(record.Detail.FailureMessage)
}

func bedrockProvisionedModelThroughputCreationTime(record awsBedrockProvisionedModelThroughput) *time.Time {
	if record.Detail != nil && record.Detail.CreationTime != nil {
		return record.Detail.CreationTime
	}
	return record.Summary.CreationTime
}

func bedrockProvisionedModelThroughputLastModifiedTime(record awsBedrockProvisionedModelThroughput) *time.Time {
	if record.Detail != nil && record.Detail.LastModifiedTime != nil {
		return record.Detail.LastModifiedTime
	}
	return record.Summary.LastModifiedTime
}

func bedrockProvisionedModelThroughputCommitmentExpiration(record awsBedrockProvisionedModelThroughput) *time.Time {
	if record.Detail != nil && record.Detail.CommitmentExpirationTime != nil {
		return record.Detail.CommitmentExpirationTime
	}
	return record.Summary.CommitmentExpirationTime
}

func bedrockMatchingGuardrails(record awsBedrockProvisionedModelThroughput, guardrails []bedrocktypes.AccountEnforcedGuardrailOutputConfiguration) []bedrocktypes.AccountEnforcedGuardrailOutputConfiguration {
	matches := make([]bedrocktypes.AccountEnforcedGuardrailOutputConfiguration, 0, len(guardrails))
	candidates := bedrockProvisionedModelCandidates(record)
	for _, guardrail := range guardrails {
		if bedrockGuardrailMatchesCandidates(guardrail, candidates) {
			matches = append(matches, guardrail)
		}
	}
	return matches
}

func bedrockProvisionedModelCandidates(record awsBedrockProvisionedModelThroughput) []string {
	values := []string{
		bedrockProvisionedModelThroughputModelARN(record),
		bedrockProvisionedModelThroughputDesiredModelARN(record),
		bedrockProvisionedModelThroughputFoundationModelARN(record),
		bedrockProvisionedModelThroughputARN(record),
		bedrockProvisionedModelThroughputName(record),
	}
	for _, value := range append([]string(nil), values...) {
		values = append(values, bedrockARNResourceNames(value)...)
	}
	return cleanStrings(values)
}

func bedrockGuardrailMatchesCandidates(guardrail bedrocktypes.AccountEnforcedGuardrailOutputConfiguration, candidates []string) bool {
	if guardrail.ModelEnforcement == nil {
		return true
	}
	if bedrockAnyModelMatches(guardrail.ModelEnforcement.ExcludedModels, candidates) {
		return false
	}
	included := cleanStrings(guardrail.ModelEnforcement.IncludedModels)
	if len(included) == 0 {
		return true
	}
	return bedrockAnyModelMatches(included, candidates)
}

func bedrockAnyModelMatches(models []string, candidates []string) bool {
	candidateSet := map[string]bool{}
	for _, candidate := range candidates {
		normalized := strings.ToLower(strings.TrimSpace(candidate))
		if normalized != "" {
			candidateSet[normalized] = true
		}
	}
	for _, model := range models {
		normalized := strings.ToLower(strings.TrimSpace(model))
		if normalized != "" && candidateSet[normalized] {
			return true
		}
	}
	return false
}

func bedrockARNResourceNames(value string) []string {
	if !strings.HasPrefix(value, "arn:") {
		return nil
	}
	parts := strings.Split(value, "/")
	return cleanStrings(parts[1:])
}

func bedrockMatchedGuardrailIdentifiers(guardrails []bedrocktypes.AccountEnforcedGuardrailOutputConfiguration) []string {
	values := make([]string, 0, len(guardrails))
	for _, guardrail := range guardrails {
		values = append(values, firstNonEmpty(awssdk.ToString(guardrail.GuardrailArn), awssdk.ToString(guardrail.GuardrailId)))
	}
	return cleanStrings(values)
}

func bedrockGuardrailARNs(guardrails []bedrocktypes.AccountEnforcedGuardrailOutputConfiguration) []string {
	values := make([]string, 0, len(guardrails))
	for _, guardrail := range guardrails {
		values = append(values, awssdk.ToString(guardrail.GuardrailArn))
	}
	return cleanStrings(values)
}

func bedrockGuardrailIDs(guardrails []bedrocktypes.AccountEnforcedGuardrailOutputConfiguration) []string {
	values := make([]string, 0, len(guardrails))
	for _, guardrail := range guardrails {
		values = append(values, awssdk.ToString(guardrail.GuardrailId))
	}
	return cleanStrings(values)
}

func bedrockGuardrailVersions(guardrails []bedrocktypes.AccountEnforcedGuardrailOutputConfiguration) []string {
	values := make([]string, 0, len(guardrails))
	for _, guardrail := range guardrails {
		values = append(values, awssdk.ToString(guardrail.GuardrailVersion))
	}
	return cleanStrings(values)
}

func bedrockGuardrailEnforcementState(record awsBedrockProvisionedModelThroughput) string {
	switch {
	case len(record.MatchedGuardrails) > 0:
		return "account_enforced"
	case len(record.AccountEnforcedGuardrails) > 0:
		return "account_enforcement_not_matched"
	default:
		return "not_observed"
	}
}
