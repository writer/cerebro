package aws

import (
	"context"
	"encoding/json"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cloudformationtypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"

	"github.com/writer/cerebro/internal/primitives"
)

func listCloudFormationStacks(ctx context.Context, clients awsClients, _ settings, cursor string, _ int) ([]cloudformationtypes.Stack, string, error) {
	if clients.cloudFormation == nil {
		return nil, "", fmt.Errorf("aws cloudformation client is not configured")
	}
	out, err := clients.cloudFormation.DescribeStacks(ctx, &cloudformation.DescribeStacksInput{NextToken: stringPtr(cursor)})
	if err != nil {
		return nil, "", err
	}
	return out.Stacks, awssdk.ToString(out.NextToken), nil
}

func cloudFormationStackEvent(settings settings, stack cloudformationtypes.Stack) (*primitives.Event, error) {
	name := awssdk.ToString(stack.StackName)
	stackID := awssdk.ToString(stack.StackId)
	arn := firstNonEmpty(stackID, cloudFormationStackARN(settings, name), name)
	tags := cloudFormationTagMap(stack.Tags)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyCloudFormationStack, arn, name, "aws_cloudformation_stack", tags)
	terminationProtection := awssdk.ToBool(stack.EnableTerminationProtection)
	driftStatus := cloudFormationDriftStatus(stack.DriftInformation)
	attributes["arn"] = arn
	attributes["cloudformation_stack_drift_detected_compliant"] = boolString(driftStatus == string(cloudformationtypes.StackDriftStatusInSync))
	attributes["cloudformation_stack_termination_protection_compliant"] = boolString(terminationProtection)
	attributes["drift_detected"] = boolString(driftStatus == string(cloudformationtypes.StackDriftStatusDrifted))
	attributes["drift_status"] = driftStatus
	attributes["stack_id"] = stackID
	attributes["stack_name"] = name
	attributes["stack_status"] = string(stack.StackStatus)
	attributes["termination_protection"] = boolString(terminationProtection)
	if stack.DriftInformation != nil {
		addTimeAttribute(attributes, "drift_last_checked_at", stack.DriftInformation.LastCheckTimestamp)
	}
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "stack": stack, "tags": tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-cloudformation-stack-"+firstNonEmpty(stackID, name), "aws.cloudformation_stack", "aws/cloudformation_stack/v1", payload, attributes, firstTime(stack.LastUpdatedTime, stack.CreationTime))
}

func cloudFormationDriftStatus(info *cloudformationtypes.StackDriftInformation) string {
	if info == nil {
		return ""
	}
	return string(info.StackDriftStatus)
}

func cloudFormationTagMap(tags []cloudformationtypes.Tag) map[string]string {
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		key := awssdk.ToString(tag.Key)
		if key == "" {
			continue
		}
		out[key] = awssdk.ToString(tag.Value)
	}
	return out
}

func cloudFormationStackARN(settings settings, name string) string {
	if name == "" {
		return ""
	}
	return fmt.Sprintf("arn:aws:cloudformation:%s:%s:stack/%s", firstNonEmpty(settings.region, defaultRegion), settings.accountID, name)
}
