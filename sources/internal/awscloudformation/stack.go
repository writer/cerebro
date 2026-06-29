package awscloudformation

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cloudformationtypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/textutil"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const FamilyStack = "cloudformation_stack"

type Client interface {
	DescribeStacks(context.Context, *cloudformation.DescribeStacksInput, ...func(*cloudformation.Options)) (*cloudformation.DescribeStacksOutput, error)
}

type Settings struct {
	AccountID string
	Region    string
}

func Family[S any, C any](clientFactory func(context.Context, S) (C, error), clientFromClients func(C) any, sourceSettings func(S) Settings) sourcecdk.Family[S] {
	const label = "aws cloudformation stacks"
	return sourcecdk.Family[S]{
		Name: FamilyStack,
		Check: func(ctx context.Context, settings S) error {
			client, err := resolveClient(ctx, settings, clientFactory, clientFromClients)
			if err != nil {
				return err
			}
			_, _, err = ListStacks(ctx, client, "")
			return err
		},
		Discover: func(ctx context.Context, settings S) ([]sourcecdk.URN, error) {
			client, err := resolveClient(ctx, settings, clientFactory, clientFromClients)
			if err != nil {
				return nil, err
			}
			records, _, err := ListStacks(ctx, client, "")
			if err != nil {
				return nil, fmt.Errorf("lookup %s for %s: %w", label, sourceSettings(settings).AccountID, err)
			}
			urns := make([]sourcecdk.URN, 0, len(records))
			for _, record := range records {
				parsed, err := sourcecdk.ParseURN(StackURN(sourceSettings(settings), record))
				if err != nil {
					return nil, err
				}
				urns = append(urns, parsed)
			}
			return urns, nil
		},
		Read: func(ctx context.Context, settings S, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
			client, err := resolveClient(ctx, settings, clientFactory, clientFromClients)
			if err != nil {
				return sourcecdk.Pull{}, err
			}
			records, next, err := ListStacks(ctx, client, sourcecdk.CursorToken(cursor))
			if err != nil {
				return sourcecdk.Pull{}, fmt.Errorf("lookup %s for %s: %w", label, sourceSettings(settings).AccountID, err)
			}
			build := func(record cloudformationtypes.Stack) (*primitives.Event, error) {
				return Event(sourceSettings(settings), record)
			}
			return sourcecdk.PullFromRecords(records, next, build, StackCursor)
		},
	}
}

func resolveClient[S any, C any](ctx context.Context, settings S, clientFactory func(context.Context, S) (C, error), clientFromClients func(C) any) (Client, error) {
	clients, err := clientFactory(ctx, settings)
	if err != nil {
		return nil, err
	}
	client, ok := clientFromClients(clients).(Client)
	if !ok {
		return nil, fmt.Errorf("aws cloudformation client is not configured")
	}
	return client, nil
}

func ListStacks(ctx context.Context, client Client, cursor string) ([]cloudformationtypes.Stack, string, error) {
	out, err := client.DescribeStacks(ctx, &cloudformation.DescribeStacksInput{NextToken: stringPtr(cursor)})
	if err != nil {
		return nil, "", err
	}
	return out.Stacks, awssdk.ToString(out.NextToken), nil
}

func Event(settings Settings, stack cloudformationtypes.Stack) (*primitives.Event, error) {
	name := awssdk.ToString(stack.StackName)
	stackID := awssdk.ToString(stack.StackId)
	arn := firstNonEmpty(stackID, StackARN(settings, name), name)
	tags := tagMap(stack.Tags)
	attributes := commonCloudAssetAttributes(settings, settings.Region, FamilyStack, arn, name, "aws_cloudformation_stack", tags)
	terminationProtection := awssdk.ToBool(stack.EnableTerminationProtection)
	driftStatus := driftStatus(stack.DriftInformation)
	driftDetected := driftStatus == string(cloudformationtypes.StackDriftStatusDrifted)
	attributes["arn"] = arn
	attributes["cloudformation_stack_drift_detected_compliant"] = boolString(!driftDetected)
	attributes["cloudformation_stack_termination_protection_compliant"] = boolString(terminationProtection)
	attributes["drift_detected"] = boolString(driftDetected)
	attributes["drift_status"] = driftStatus
	attributes["stack_id"] = stackID
	attributes["stack_name"] = name
	attributes["stack_status"] = string(stack.StackStatus)
	attributes["termination_protection"] = boolString(terminationProtection)
	if stack.DriftInformation != nil {
		addTimeAttribute(attributes, "drift_last_checked_at", stack.DriftInformation.LastCheckTimestamp)
	}
	payload, err := json.Marshal(map[string]any{"account_id": settings.AccountID, "region": settings.Region, "stack": stack, "tags": tags})
	if err != nil {
		return nil, err
	}
	return event(settings, "aws-cloudformation-stack-"+firstNonEmpty(stackID, name), "aws.cloudformation_stack", "aws/cloudformation_stack/v1", payload, attributes, firstTime(stack.LastUpdatedTime, stack.CreationTime)), nil
}

func StackURN(settings Settings, stack cloudformationtypes.Stack) string {
	name := awssdk.ToString(stack.StackName)
	return fmt.Sprintf("urn:cerebro:%s:aws_cloudformation_stack:%s", settings.AccountID, firstNonEmpty(awssdk.ToString(stack.StackId), StackARN(settings, name), name))
}

func StackCursor(stack cloudformationtypes.Stack) string {
	return firstNonEmpty(awssdk.ToString(stack.StackId), awssdk.ToString(stack.StackName))
}

func StackARN(settings Settings, name string) string {
	if name == "" {
		return ""
	}
	return fmt.Sprintf("arn:aws:cloudformation:%s:%s:stack/%s", firstNonEmpty(settings.Region, "us-east-1"), settings.AccountID, name)
}

func event(settings Settings, id string, kind string, schemaRef string, payload []byte, attributes map[string]string, occurredAt time.Time) *primitives.Event {
	trimEmptyAttributes(attributes)
	return &primitives.Event{
		Id:         sanitizeEventID(id),
		TenantId:   settings.AccountID,
		SourceId:   "aws",
		Kind:       kind,
		OccurredAt: timestamppb.New(occurredAt.UTC()),
		SchemaRef:  schemaRef,
		Payload:    payload,
		Attributes: attributes,
	}
}

func commonCloudAssetAttributes(settings Settings, region string, family string, resourceID string, resourceName string, resourceType string, tags map[string]string) map[string]string {
	env := tagLookup(tags, "environment", "env", "stage")
	return map[string]string{
		"domain":            settings.AccountID,
		"env":               env,
		"environment":       env,
		"family":            family,
		"owner":             tagLookup(tags, "owner", "application_owner", "business_owner", "service_owner"),
		"region":            firstNonEmpty(region, settings.Region),
		"resource_id":       resourceID,
		"resource_name":     resourceName,
		"resource_provider": "aws",
		"resource_type":     resourceType,
		"tags":              encodeTags(tags),
		"team":              tagLookup(tags, "team", "squad", "group"),
	}
}

func driftStatus(info *cloudformationtypes.StackDriftInformation) string {
	if info == nil {
		return ""
	}
	return string(info.StackDriftStatus)
}

func tagMap(tags []cloudformationtypes.Tag) map[string]string {
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		key := strings.TrimSpace(awssdk.ToString(tag.Key))
		if key == "" {
			continue
		}
		out[key] = strings.TrimSpace(awssdk.ToString(tag.Value))
	}
	return out
}

func tagLookup(tags map[string]string, keys ...string) string {
	if len(tags) == 0 {
		return ""
	}
	normalized := make(map[string]string, len(tags))
	for key, value := range tags {
		normalized[normalizeTagKey(key)] = value
	}
	for _, key := range keys {
		if value := strings.TrimSpace(normalized[normalizeTagKey(key)]); value != "" {
			return value
		}
	}
	return ""
}

func normalizeTagKey(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "-", "_")
	value = strings.ReplaceAll(value, " ", "_")
	value = strings.ReplaceAll(value, ".", "_")
	value = strings.Trim(value, "_")
	for strings.Contains(value, "__") {
		value = strings.ReplaceAll(value, "__", "_")
	}
	return value
}

func encodeTags(tags map[string]string) string {
	if len(tags) == 0 {
		return ""
	}
	keys := make([]string, 0, len(tags))
	for key := range tags {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	pairs := make([]string, 0, len(keys))
	for _, key := range keys {
		pairs = append(pairs, key+"="+tags[key])
	}
	return strings.Join(pairs, ",")
}

func addTimeAttribute(attributes map[string]string, key string, value *time.Time) {
	if value != nil && !value.IsZero() {
		attributes[key] = value.UTC().Format(time.RFC3339)
	}
}

func firstTime(values ...*time.Time) time.Time {
	for _, value := range values {
		if value != nil && !value.IsZero() {
			return value.UTC()
		}
	}
	return time.Now().UTC()
}

func firstNonEmpty(values ...string) string { return textutil.FirstNonEmpty(values...) }

func boolString(value bool) string { return strconv.FormatBool(value) }

func stringPtr(value string) *string {
	if trimmed := strings.TrimSpace(value); trimmed != "" {
		return &trimmed
	}
	return nil
}

func trimEmptyAttributes(attributes map[string]string) {
	for key, value := range attributes {
		if strings.TrimSpace(value) == "" {
			delete(attributes, key)
			continue
		}
		attributes[key] = strings.TrimSpace(value)
	}
}

func sanitizeEventID(value string) string {
	return strings.Trim(strings.NewReplacer(" ", "-", "/", "-", ":", "-").Replace(value), "-")
}
