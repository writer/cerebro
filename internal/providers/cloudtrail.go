package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
)

// CloudTrailProvider syncs audit logs from AWS CloudTrail
type CloudTrailProvider struct {
	*BaseProvider
	region       string
	trailARN     string
	lookbackDays int
	client       *cloudtrail.Client
}

func NewCloudTrailProvider() *CloudTrailProvider {
	return &CloudTrailProvider{
		BaseProvider: NewBaseProvider("cloudtrail", ProviderTypeCloud),
		region:       "us-east-1",
		lookbackDays: 7,
	}
}

func (c *CloudTrailProvider) Configure(ctx context.Context, cfgMap map[string]interface{}) error {
	if err := c.BaseProvider.Configure(ctx, cfgMap); err != nil {
		return err
	}

	if region := c.GetConfigString("region"); region != "" {
		c.region = region
	}
	if trailARN := c.GetConfigString("trail_arn"); trailARN != "" {
		c.trailARN = trailARN
	}
	if days := c.GetConfig("lookback_days"); days != nil {
		if d, ok := days.(int); ok {
			c.lookbackDays = d
		}
	}

	// Initialize AWS client
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(c.region))
	if err != nil {
		return fmt.Errorf("load AWS config: %w", err)
	}

	c.client = cloudtrail.NewFromConfig(cfg)
	return nil
}

func (c *CloudTrailProvider) Test(ctx context.Context) error {
	_, err := c.client.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	return err
}

func (c *CloudTrailProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "cloudtrail_events",
			Description: "AWS CloudTrail audit log events",
			Columns: []ColumnSchema{
				{Name: "event_id", Type: "string", Required: true},
				{Name: "event_name", Type: "string"},
				{Name: "event_source", Type: "string"},
				{Name: "event_time", Type: "timestamp"},
				{Name: "event_type", Type: "string"},
				{Name: "aws_region", Type: "string"},
				{Name: "source_ip_address", Type: "string"},
				{Name: "user_agent", Type: "string"},
				{Name: "user_identity_type", Type: "string"},
				{Name: "user_identity_arn", Type: "string"},
				{Name: "user_identity_principal_id", Type: "string"},
				{Name: "user_identity_account_id", Type: "string"},
				{Name: "user_identity_access_key_id", Type: "string"},
				{Name: "user_identity_username", Type: "string"},
				{Name: "error_code", Type: "string"},
				{Name: "error_message", Type: "string"},
				{Name: "request_parameters", Type: "object"},
				{Name: "response_elements", Type: "object"},
				{Name: "resources", Type: "array"},
				{Name: "read_only", Type: "boolean"},
				{Name: "management_event", Type: "boolean"},
			},
			PrimaryKey: []string{"event_id"},
		},
		{
			Name:        "cloudtrail_trails",
			Description: "AWS CloudTrail trail configurations",
			Columns: []ColumnSchema{
				{Name: "trail_arn", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "home_region", Type: "string"},
				{Name: "s3_bucket_name", Type: "string"},
				{Name: "s3_key_prefix", Type: "string"},
				{Name: "sns_topic_arn", Type: "string"},
				{Name: "include_global_service_events", Type: "boolean"},
				{Name: "is_multi_region_trail", Type: "boolean"},
				{Name: "is_organization_trail", Type: "boolean"},
				{Name: "log_file_validation_enabled", Type: "boolean"},
				{Name: "kms_key_id", Type: "string"},
				{Name: "has_custom_event_selectors", Type: "boolean"},
				{Name: "has_insight_selectors", Type: "boolean"},
			},
			PrimaryKey: []string{"trail_arn"},
		},
		{
			Name:        "cloudtrail_console_logins",
			Description: "AWS Console login events",
			Columns: []ColumnSchema{
				{Name: "event_id", Type: "string", Required: true},
				{Name: "event_time", Type: "timestamp"},
				{Name: "user_identity_arn", Type: "string"},
				{Name: "user_identity_username", Type: "string"},
				{Name: "source_ip_address", Type: "string"},
				{Name: "user_agent", Type: "string"},
				{Name: "mfa_used", Type: "boolean"},
				{Name: "login_result", Type: "string"},
				{Name: "error_message", Type: "string"},
			},
			PrimaryKey: []string{"event_id"},
		},
		{
			Name:        "cloudtrail_iam_changes",
			Description: "IAM change events from CloudTrail",
			Columns: []ColumnSchema{
				{Name: "event_id", Type: "string", Required: true},
				{Name: "event_name", Type: "string"},
				{Name: "event_time", Type: "timestamp"},
				{Name: "user_identity_arn", Type: "string"},
				{Name: "source_ip_address", Type: "string"},
				{Name: "affected_entity", Type: "string"},
				{Name: "affected_entity_type", Type: "string"},
				{Name: "change_type", Type: "string"},
				{Name: "request_parameters", Type: "object"},
			},
			PrimaryKey: []string{"event_id"},
		},
		{
			Name:        "cloudtrail_security_events",
			Description: "Security-relevant CloudTrail events",
			Columns: []ColumnSchema{
				{Name: "event_id", Type: "string", Required: true},
				{Name: "event_name", Type: "string"},
				{Name: "event_source", Type: "string"},
				{Name: "event_time", Type: "timestamp"},
				{Name: "severity", Type: "string"},
				{Name: "category", Type: "string"},
				{Name: "user_identity_arn", Type: "string"},
				{Name: "source_ip_address", Type: "string"},
				{Name: "error_code", Type: "string"},
				{Name: "affected_resources", Type: "array"},
			},
			PrimaryKey: []string{"event_id"},
		},
	}
}

func (c *CloudTrailProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	start := time.Now()
	result := &SyncResult{
		Provider:  c.Name(),
		StartedAt: start,
	}

	// Sync trails
	trails, err := c.syncTrails(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "trails: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *trails)
		result.TotalRows += trails.Rows
	}

	// Sync events
	events, err := c.syncEvents(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "events: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *events)
		result.TotalRows += events.Rows
	}

	// Sync console logins
	logins, err := c.syncConsoleLogins(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "console_logins: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *logins)
		result.TotalRows += logins.Rows
	}

	// Sync IAM changes
	iamChanges := c.syncIAMChanges(ctx)
	result.Tables = append(result.Tables, *iamChanges)
	result.TotalRows += iamChanges.Rows

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)

	return result, nil
}

func (c *CloudTrailProvider) syncTrails(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "cloudtrail_trails"}

	output, err := c.client.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	if err != nil {
		return result, err
	}

	result.Rows = int64(len(output.TrailList))
	result.Inserted = result.Rows
	return result, nil
}

func (c *CloudTrailProvider) syncEvents(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "cloudtrail_events"}

	startTime := time.Now().AddDate(0, 0, -c.lookbackDays)
	endTime := time.Now()

	input := &cloudtrail.LookupEventsInput{
		StartTime:  &startTime,
		EndTime:    &endTime,
		MaxResults: intPtr(50),
	}

	var parsedEvents []map[string]interface{}
	paginator := cloudtrail.NewLookupEventsPaginator(c.client, input)

	for paginator.HasMorePages() {
		output, err := paginator.NextPage(ctx)
		if err != nil {
			return result, err
		}

		// Parse each event to extract rich details
		for _, event := range output.Events {
			parsed := parseCloudTrailEvent(event)
			parsedEvents = append(parsedEvents, parsed)
		}

		// Limit total events for performance
		if len(parsedEvents) >= 10000 {
			break
		}
	}

	result.Rows = int64(len(parsedEvents))
	result.Inserted = result.Rows
	return result, nil
}

func (c *CloudTrailProvider) syncConsoleLogins(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "cloudtrail_console_logins"}

	startTime := time.Now().AddDate(0, 0, -c.lookbackDays)
	endTime := time.Now()

	input := &cloudtrail.LookupEventsInput{
		StartTime: &startTime,
		EndTime:   &endTime,
		LookupAttributes: []types.LookupAttribute{
			{
				AttributeKey:   types.LookupAttributeKeyEventName,
				AttributeValue: strPtr("ConsoleLogin"),
			},
		},
		MaxResults: intPtr(50),
	}

	var loginEvents []types.Event
	paginator := cloudtrail.NewLookupEventsPaginator(c.client, input)

	for paginator.HasMorePages() {
		output, err := paginator.NextPage(ctx)
		if err != nil {
			return result, err
		}
		loginEvents = append(loginEvents, output.Events...)
	}

	result.Rows = int64(len(loginEvents))
	result.Inserted = result.Rows
	return result, nil
}

func (c *CloudTrailProvider) syncIAMChanges(ctx context.Context) *TableResult {
	result := &TableResult{Name: "cloudtrail_iam_changes"}

	startTime := time.Now().AddDate(0, 0, -c.lookbackDays)
	endTime := time.Now()

	// IAM-related events
	iamEventNames := []string{
		"CreateUser", "DeleteUser", "UpdateUser",
		"CreateRole", "DeleteRole", "UpdateRole",
		"CreatePolicy", "DeletePolicy", "CreatePolicyVersion",
		"AttachUserPolicy", "DetachUserPolicy",
		"AttachRolePolicy", "DetachRolePolicy",
		"PutUserPolicy", "DeleteUserPolicy",
		"PutRolePolicy", "DeleteRolePolicy",
		"CreateAccessKey", "DeleteAccessKey",
		"AddUserToGroup", "RemoveUserFromGroup",
	}

	var allIAMEvents []types.Event

	for _, eventName := range iamEventNames {
		input := &cloudtrail.LookupEventsInput{
			StartTime: &startTime,
			EndTime:   &endTime,
			LookupAttributes: []types.LookupAttribute{
				{
					AttributeKey:   types.LookupAttributeKeyEventName,
					AttributeValue: &eventName,
				},
			},
			MaxResults: intPtr(50),
		}

		output, err := c.client.LookupEvents(ctx, input)
		if err != nil {
			continue
		}
		allIAMEvents = append(allIAMEvents, output.Events...)
	}

	result.Rows = int64(len(allIAMEvents))
	result.Inserted = result.Rows
	return result
}

// parseCloudTrailEvent extracts relevant fields from a CloudTrail event
func parseCloudTrailEvent(event types.Event) map[string]interface{} {
	result := map[string]interface{}{
		"event_id":     event.EventId,
		"event_name":   event.EventName,
		"event_source": event.EventSource,
		"event_time":   event.EventTime,
		"username":     event.Username,
	}

	if event.CloudTrailEvent != nil {
		var details map[string]interface{}
		if err := json.Unmarshal([]byte(*event.CloudTrailEvent), &details); err == nil {
			if ui, ok := details["userIdentity"].(map[string]interface{}); ok {
				result["user_identity_type"] = ui["type"]
				result["user_identity_arn"] = ui["arn"]
				result["user_identity_account_id"] = ui["accountId"]
			}
			result["source_ip_address"] = details["sourceIPAddress"]
			result["user_agent"] = details["userAgent"]
			result["aws_region"] = details["awsRegion"]
			result["error_code"] = details["errorCode"]
			result["error_message"] = details["errorMessage"]
			result["request_parameters"] = details["requestParameters"]
			result["response_elements"] = details["responseElements"]
		}
	}

	return result
}

func intPtr(i int32) *int32 {
	return &i
}

func strPtr(s string) *string {
	return &s
}
