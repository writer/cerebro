package aws

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cloudtrailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	defaultFamily       = familyCloudTrail
	defaultRegion       = "us-east-1"
	defaultPageSize     = 10
	maxPageSize         = 200
	familyCloudTrail    = "cloudtrail"
	familyIAMGroup      = "iam_group"
	familyIAMMembership = "iam_group_membership"
	familyIAMRoleAssign = "iam_role_assignment"
	familyIAMUser       = "iam_user"
)

// Source reads AWS IAM inventory and CloudTrail activity through the AWS SDK for Go v2.
type Source struct {
	spec     *cerebrov1.SourceSpec
	clients  awsClientFactory
	families *sourcecdk.FamilyEngine[settings]
}

type settings struct {
	family          string
	accountID       string
	region          string
	profile         string
	accessKeyID     string
	secretAccessKey string
	sessionToken    string
	groupName       string
	principalType   string
	principalName   string
	lookupKey       string
	lookupValue     string
	startTime       string
	endTime         string
	perPage         int
}

type awsClientFactory func(context.Context, settings) (awsClients, error)

type awsClients struct {
	iam        awsIAMAPI
	cloudTrail awsCloudTrailAPI
}

type awsIAMAPI interface {
	ListUsers(context.Context, *iam.ListUsersInput, ...func(*iam.Options)) (*iam.ListUsersOutput, error)
	ListGroups(context.Context, *iam.ListGroupsInput, ...func(*iam.Options)) (*iam.ListGroupsOutput, error)
	GetGroup(context.Context, *iam.GetGroupInput, ...func(*iam.Options)) (*iam.GetGroupOutput, error)
	ListAttachedUserPolicies(context.Context, *iam.ListAttachedUserPoliciesInput, ...func(*iam.Options)) (*iam.ListAttachedUserPoliciesOutput, error)
	ListAttachedGroupPolicies(context.Context, *iam.ListAttachedGroupPoliciesInput, ...func(*iam.Options)) (*iam.ListAttachedGroupPoliciesOutput, error)
	ListAttachedRolePolicies(context.Context, *iam.ListAttachedRolePoliciesInput, ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error)
}

type awsCloudTrailAPI interface {
	LookupEvents(context.Context, *cloudtrail.LookupEventsInput, ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error)
}

type awsFamilyOptions[T any] struct {
	Name           string
	Label          string
	List           func(context.Context, awsClients, settings, string, int) ([]T, string, error)
	Event          func(settings, T) (*primitives.Event, error)
	URN            func(settings, T) (string, error)
	Discover       func(context.Context, awsClients, settings) ([]sourcecdk.URN, error)
	CursorFallback func(T) string
}

type iamPolicyAssignment struct {
	PrincipalType string
	PrincipalName string
	Policy        iamtypes.AttachedPolicy
}

type cloudTrailDetail struct {
	EventName       string                  `json:"eventName"`
	EventSource     string                  `json:"eventSource"`
	EventTime       string                  `json:"eventTime"`
	SourceIPAddress string                  `json:"sourceIPAddress"`
	UserIdentity    cloudTrailUserIdentity  `json:"userIdentity"`
	Resources       []cloudTrailResourceRef `json:"resources"`
}

type cloudTrailUserIdentity struct {
	Type        string `json:"type"`
	PrincipalID string `json:"principalId"`
	Arn         string `json:"arn"`
	UserName    string `json:"userName"`
}

type cloudTrailResourceRef struct {
	ARN       string `json:"ARN"`
	ARNLower  string `json:"arn"`
	Name      string `json:"resourceName"`
	Type      string `json:"resourceType"`
	AccountID string `json:"accountId"`
}

// New constructs the live AWS source.
func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	source := &Source{spec: spec, clients: newAWSClients}
	source.families, err = source.newFamilyEngine()
	if err != nil {
		return nil, err
	}
	return source, nil
}

func loadSpec() (*cerebrov1.SourceSpec, error) {
	specBytes, err := catalogFS.ReadFile("catalog.yaml")
	if err != nil {
		return nil, fmt.Errorf("read catalog: %w", err)
	}
	spec, err := sourcecdk.LoadCatalog(specBytes)
	if err != nil {
		return nil, fmt.Errorf("load catalog: %w", err)
	}
	return spec, nil
}

// Spec returns static source metadata.
func (s *Source) Spec() *cerebrov1.SourceSpec {
	return s.spec
}

// Check validates that the configured AWS family is reachable.
func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	return s.families.Check(ctx, cfg)
}

// Discover returns AWS resource URNs for the configured family.
func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	return s.families.Discover(ctx, cfg)
}

// Read returns one page of normalized AWS events.
func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return s.families.Read(ctx, cfg, cursor)
}

func (s *Source) newFamilyEngine() (*sourcecdk.FamilyEngine[settings], error) {
	return sourcecdk.NewFamilyEngine(parseSettings, func(settings settings) string { return settings.family },
		awsFamily(s.clients, awsFamilyOptions[cloudtrailtypes.Event]{
			Name:  familyCloudTrail,
			Label: "aws cloudtrail events",
			List:  listCloudTrailEvents,
			Event: cloudTrailEvent,
			Discover: func(ctx context.Context, clients awsClients, settings settings) ([]sourcecdk.URN, error) {
				if err := awsCheck(ctx, clients, settings, listCloudTrailEvents, "aws cloudtrail events"); err != nil {
					return nil, err
				}
				return parseAWSURNs(fmt.Sprintf("urn:cerebro:%s:aws_account:%s", settings.accountID, settings.accountID))
			},
			CursorFallback: func(event cloudtrailtypes.Event) string { return awssdk.ToString(event.EventId) },
		}),
		awsFamily(s.clients, awsFamilyOptions[iamtypes.Group]{
			Name:  familyIAMGroup,
			Label: "aws iam groups",
			List:  listIAMGroups,
			Event: iamGroupEvent,
			URN: func(settings settings, group iamtypes.Group) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:iam_group:%s", settings.accountID, firstNonEmpty(awssdk.ToString(group.GroupId), awssdk.ToString(group.GroupName))), nil
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[iamtypes.User]{
			Name:  familyIAMMembership,
			Label: "aws iam group memberships",
			List:  listIAMGroupMembers,
			Event: iamGroupMembershipEvent,
			URN: func(settings settings, user iamtypes.User) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:iam_group_membership:%s:%s", settings.accountID, settings.groupName, firstNonEmpty(awssdk.ToString(user.UserId), awssdk.ToString(user.UserName))), nil
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[iamPolicyAssignment]{
			Name:  familyIAMRoleAssign,
			Label: "aws iam policy assignments",
			List:  listIAMPolicyAssignments,
			Event: iamRoleAssignmentEvent,
			URN: func(settings settings, assignment iamPolicyAssignment) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:iam_role_assignment:%s:%s", settings.accountID, assignment.PrincipalName, firstNonEmpty(awssdk.ToString(assignment.Policy.PolicyArn), awssdk.ToString(assignment.Policy.PolicyName))), nil
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[iamtypes.User]{
			Name:  familyIAMUser,
			Label: "aws iam users",
			List:  listIAMUsers,
			Event: iamUserEvent,
			URN: func(settings settings, user iamtypes.User) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:iam_user:%s", settings.accountID, firstNonEmpty(awssdk.ToString(user.UserId), awssdk.ToString(user.UserName))), nil
			},
			CursorFallback: func(user iamtypes.User) string { return awssdk.ToString(user.UserName) },
		}),
	)
}

func awsFamily[T any](clientFactory awsClientFactory, options awsFamilyOptions[T]) sourcecdk.Family[settings] {
	return sourcecdk.Family[settings]{
		Name: options.Name,
		Check: func(ctx context.Context, settings settings) error {
			clients, err := clientFactory(ctx, settings)
			if err != nil {
				return err
			}
			return awsCheck(ctx, clients, settings, options.List, options.Label)
		},
		Discover: func(ctx context.Context, settings settings) ([]sourcecdk.URN, error) {
			clients, err := clientFactory(ctx, settings)
			if err != nil {
				return nil, err
			}
			if options.Discover != nil {
				return options.Discover(ctx, clients, settings)
			}
			records, _, err := options.List(ctx, clients, settings, "", settings.perPage)
			if err != nil {
				return nil, fmt.Errorf("lookup %s for %s: %w", options.Label, settings.accountID, err)
			}
			return awsURNsFor(settings, records, options.URN)
		},
		Read: func(ctx context.Context, settings settings, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
			clients, err := clientFactory(ctx, settings)
			if err != nil {
				return sourcecdk.Pull{}, err
			}
			records, next, err := options.List(ctx, clients, settings, strings.TrimSpace(cursor.GetOpaque()), settings.perPage)
			if err != nil {
				return sourcecdk.Pull{}, fmt.Errorf("lookup %s for %s: %w", options.Label, settings.accountID, err)
			}
			build := func(record T) (*primitives.Event, error) { return options.Event(settings, record) }
			return awsPullFromRecords(records, next, build, options.CursorFallback)
		},
	}
}

func newAWSClients(ctx context.Context, settings settings) (awsClients, error) {
	options := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(settings.region)}
	if settings.profile != "" {
		options = append(options, awsconfig.WithSharedConfigProfile(settings.profile))
	}
	if settings.accessKeyID != "" || settings.secretAccessKey != "" || settings.sessionToken != "" {
		if settings.accessKeyID == "" || settings.secretAccessKey == "" {
			return awsClients{}, fmt.Errorf("aws access_key_id and secret_access_key must be provided together")
		}
		provider := credentials.NewStaticCredentialsProvider(settings.accessKeyID, settings.secretAccessKey, settings.sessionToken)
		options = append(options, awsconfig.WithCredentialsProvider(provider))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, options...)
	if err != nil {
		return awsClients{}, fmt.Errorf("load aws config: %w", err)
	}
	return awsClients{iam: iam.NewFromConfig(cfg), cloudTrail: cloudtrail.NewFromConfig(cfg)}, nil
}

func parseSettings(cfg sourcecdk.Config) (settings, error) {
	settings := settings{
		family:          configValue(cfg, "family"),
		accountID:       configValue(cfg, "account_id"),
		region:          configValue(cfg, "region"),
		profile:         configValue(cfg, "profile"),
		accessKeyID:     configValue(cfg, "access_key_id"),
		secretAccessKey: configValue(cfg, "secret_access_key"),
		sessionToken:    configValue(cfg, "session_token"),
		groupName:       configValue(cfg, "group_name"),
		principalType:   configValue(cfg, "principal_type"),
		principalName:   configValue(cfg, "principal_name"),
		lookupKey:       configValue(cfg, "lookup_key"),
		lookupValue:     configValue(cfg, "lookup_value"),
		startTime:       configValue(cfg, "start_time"),
		endTime:         configValue(cfg, "end_time"),
		perPage:         defaultPageSize,
	}
	if settings.family == "" {
		settings.family = defaultFamily
	}
	if settings.accountID == "" {
		return settings, fmt.Errorf("aws account_id is required")
	}
	if settings.region == "" {
		settings.region = defaultRegion
	}
	if rawPerPage, ok := cfg.Lookup("per_page"); ok && strings.TrimSpace(rawPerPage) != "" {
		perPage, err := strconv.Atoi(strings.TrimSpace(rawPerPage))
		if err != nil {
			return settings, fmt.Errorf("parse aws per_page: %w", err)
		}
		if perPage < 1 || perPage > maxPageSize {
			return settings, fmt.Errorf("aws per_page must be between 1 and %d", maxPageSize)
		}
		settings.perPage = perPage
	}
	switch settings.family {
	case familyCloudTrail, familyIAMGroup, familyIAMUser:
	case familyIAMMembership:
		if settings.groupName == "" {
			return settings, fmt.Errorf("aws group_name is required when family=%q", familyIAMMembership)
		}
	case familyIAMRoleAssign:
		if settings.principalType == "" {
			settings.principalType = "user"
		}
		settings.principalType = strings.ToLower(settings.principalType)
		if settings.principalType != "user" && settings.principalType != "group" && settings.principalType != "role" {
			return settings, fmt.Errorf("aws principal_type must be user, group, or role when family=%q", familyIAMRoleAssign)
		}
		if settings.principalName == "" {
			return settings, fmt.Errorf("aws principal_name is required when family=%q", familyIAMRoleAssign)
		}
	default:
		return settings, fmt.Errorf("aws family must be one of cloudtrail, iam_group, iam_group_membership, iam_role_assignment, or iam_user")
	}
	return settings, nil
}

func listIAMUsers(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]iamtypes.User, string, error) {
	out, err := clients.iam.ListUsers(ctx, &iam.ListUsersInput{Marker: stringPtr(cursor), MaxItems: int32Ptr(limit)})
	if err != nil {
		return nil, "", err
	}
	return out.Users, nextMarker(out.IsTruncated, out.Marker), nil
}

func listIAMGroups(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]iamtypes.Group, string, error) {
	out, err := clients.iam.ListGroups(ctx, &iam.ListGroupsInput{Marker: stringPtr(cursor), MaxItems: int32Ptr(limit)})
	if err != nil {
		return nil, "", err
	}
	return out.Groups, nextMarker(out.IsTruncated, out.Marker), nil
}

func listIAMGroupMembers(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]iamtypes.User, string, error) {
	out, err := clients.iam.GetGroup(ctx, &iam.GetGroupInput{GroupName: awssdk.String(settings.groupName), Marker: stringPtr(cursor), MaxItems: int32Ptr(limit)})
	if err != nil {
		return nil, "", err
	}
	return out.Users, nextMarker(out.IsTruncated, out.Marker), nil
}

func listIAMPolicyAssignments(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]iamPolicyAssignment, string, error) {
	var policies []iamtypes.AttachedPolicy
	var next string
	switch settings.principalType {
	case "group":
		out, err := clients.iam.ListAttachedGroupPolicies(ctx, &iam.ListAttachedGroupPoliciesInput{GroupName: awssdk.String(settings.principalName), Marker: stringPtr(cursor), MaxItems: int32Ptr(limit)})
		if err != nil {
			return nil, "", err
		}
		policies = out.AttachedPolicies
		next = nextMarker(out.IsTruncated, out.Marker)
	case "role":
		out, err := clients.iam.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{RoleName: awssdk.String(settings.principalName), Marker: stringPtr(cursor), MaxItems: int32Ptr(limit)})
		if err != nil {
			return nil, "", err
		}
		policies = out.AttachedPolicies
		next = nextMarker(out.IsTruncated, out.Marker)
	default:
		out, err := clients.iam.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{UserName: awssdk.String(settings.principalName), Marker: stringPtr(cursor), MaxItems: int32Ptr(limit)})
		if err != nil {
			return nil, "", err
		}
		policies = out.AttachedPolicies
		next = nextMarker(out.IsTruncated, out.Marker)
	}
	assignments := make([]iamPolicyAssignment, 0, len(policies))
	for _, policy := range policies {
		assignments = append(assignments, iamPolicyAssignment{PrincipalType: settings.principalType, PrincipalName: settings.principalName, Policy: policy})
	}
	return assignments, next, nil
}

func listCloudTrailEvents(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]cloudtrailtypes.Event, string, error) {
	input := &cloudtrail.LookupEventsInput{MaxResults: awssdk.Int32(int32(limit)), NextToken: stringPtr(cursor)}
	if settings.lookupKey != "" && settings.lookupValue != "" {
		input.LookupAttributes = []cloudtrailtypes.LookupAttribute{{AttributeKey: cloudtrailtypes.LookupAttributeKey(settings.lookupKey), AttributeValue: awssdk.String(settings.lookupValue)}}
	}
	if settings.startTime != "" {
		parsed, err := time.Parse(time.RFC3339, settings.startTime)
		if err != nil {
			return nil, "", fmt.Errorf("parse aws start_time: %w", err)
		}
		input.StartTime = &parsed
	}
	if settings.endTime != "" {
		parsed, err := time.Parse(time.RFC3339, settings.endTime)
		if err != nil {
			return nil, "", fmt.Errorf("parse aws end_time: %w", err)
		}
		input.EndTime = &parsed
	}
	out, err := clients.cloudTrail.LookupEvents(ctx, input)
	if err != nil {
		return nil, "", err
	}
	return out.Events, awssdk.ToString(out.NextToken), nil
}

func iamUserEvent(settings settings, user iamtypes.User) (*primitives.Event, error) {
	attributes := map[string]string{
		"domain":       settings.accountID,
		"family":       familyIAMUser,
		"user_id":      firstNonEmpty(awssdk.ToString(user.UserId), awssdk.ToString(user.Arn), awssdk.ToString(user.UserName)),
		"login":        awssdk.ToString(user.UserName),
		"email":        emailLike(awssdk.ToString(user.UserName)),
		"display_name": awssdk.ToString(user.UserName),
		"arn":          awssdk.ToString(user.Arn),
		"is_admin":     boolString(containsAny(strings.ToLower(awssdk.ToString(user.UserName)), "admin", "root")),
	}
	addTimeAttribute(attributes, "created_at", user.CreateDate)
	addTimeAttribute(attributes, "last_login_at", user.PasswordLastUsed)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "user": user})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-iam-user-"+firstNonEmpty(awssdk.ToString(user.UserId), awssdk.ToString(user.UserName)), "aws.iam_user", "aws/iam_user/v1", payload, attributes, firstTime(user.PasswordLastUsed, user.CreateDate))
}

func iamGroupEvent(settings settings, group iamtypes.Group) (*primitives.Event, error) {
	attributes := map[string]string{
		"domain":     settings.accountID,
		"family":     familyIAMGroup,
		"group_id":   firstNonEmpty(awssdk.ToString(group.GroupId), awssdk.ToString(group.Arn), awssdk.ToString(group.GroupName)),
		"group_name": awssdk.ToString(group.GroupName),
		"arn":        awssdk.ToString(group.Arn),
	}
	addTimeAttribute(attributes, "created_at", group.CreateDate)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "group": group})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-iam-group-"+firstNonEmpty(awssdk.ToString(group.GroupId), awssdk.ToString(group.GroupName)), "aws.iam_group", "aws/iam_group/v1", payload, attributes, firstTime(group.CreateDate))
}

func iamGroupMembershipEvent(settings settings, user iamtypes.User) (*primitives.Event, error) {
	attributes := map[string]string{
		"domain":         settings.accountID,
		"family":         familyIAMMembership,
		"group_id":       settings.groupName,
		"group_name":     settings.groupName,
		"member_email":   emailLike(awssdk.ToString(user.UserName)),
		"member_id":      firstNonEmpty(awssdk.ToString(user.UserId), awssdk.ToString(user.Arn), awssdk.ToString(user.UserName)),
		"member_user_id": firstNonEmpty(awssdk.ToString(user.UserId), awssdk.ToString(user.UserName)),
		"member_type":    "user",
		"role":           "member",
	}
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "group_name": settings.groupName, "user": user})
	if err != nil {
		return nil, err
	}
	id := fmt.Sprintf("aws-iam-group-membership-%s-%s", settings.groupName, firstNonEmpty(awssdk.ToString(user.UserId), awssdk.ToString(user.UserName)))
	return sourceEvent(settings, id, "aws.iam_group_membership", "aws/iam_group_membership/v1", payload, attributes, firstTime(user.CreateDate))
}

func iamRoleAssignmentEvent(settings settings, assignment iamPolicyAssignment) (*primitives.Event, error) {
	policyName := awssdk.ToString(assignment.Policy.PolicyName)
	policyARN := awssdk.ToString(assignment.Policy.PolicyArn)
	attributes := map[string]string{
		"domain":         settings.accountID,
		"family":         familyIAMRoleAssign,
		"principal_type": assignment.PrincipalType,
		"role_id":        firstNonEmpty(policyARN, policyName),
		"role_name":      policyName,
		"role_type":      "aws_iam_policy",
		"subject_email":  emailLike(assignment.PrincipalName),
		"subject_id":     assignment.PrincipalName,
		"subject_login":  assignment.PrincipalName,
		"subject_type":   assignment.PrincipalType,
		"is_admin":       boolString(isAdminPolicy(policyName, policyARN)),
	}
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "assignment": assignment})
	if err != nil {
		return nil, err
	}
	id := fmt.Sprintf("aws-iam-role-assignment-%s-%s", assignment.PrincipalName, firstNonEmpty(policyARN, policyName))
	return sourceEvent(settings, id, "aws.iam_role_assignment", "aws/iam_role_assignment/v1", payload, attributes, time.Now().UTC())
}

func cloudTrailEvent(settings settings, event cloudtrailtypes.Event) (*primitives.Event, error) {
	detail := cloudTrailDetail{}
	if raw := awssdk.ToString(event.CloudTrailEvent); raw != "" {
		_ = json.Unmarshal([]byte(raw), &detail)
	}
	resourceID, resourceType := cloudTrailResource(event, detail)
	actor := cloudTrailActor(event, detail)
	attributes := map[string]string{
		"actor_alternate_id": firstNonEmpty(actor.UserName, actor.Arn, actor.PrincipalID, awssdk.ToString(event.Username)),
		"actor_email":        emailLike(firstNonEmpty(actor.UserName, actor.Arn, awssdk.ToString(event.Username))),
		"actor_id":           firstNonEmpty(actor.Arn, actor.PrincipalID, awssdk.ToString(event.Username)),
		"actor_type":         actor.Type,
		"domain":             settings.accountID,
		"event_name":         firstNonEmpty(detail.EventName, awssdk.ToString(event.EventName)),
		"event_type":         firstNonEmpty(detail.EventName, awssdk.ToString(event.EventName)),
		"family":             familyCloudTrail,
		"resource_id":        resourceID,
		"resource_name":      resourceID,
		"resource_type":      resourceType,
		"source_ip":          detail.SourceIPAddress,
	}
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "event": event, "detail": detail})
	if err != nil {
		return nil, err
	}
	occurredAt := time.Now().UTC()
	if event.EventTime != nil {
		occurredAt = event.EventTime.UTC()
	} else if detail.EventTime != "" {
		if parsed, err := time.Parse(time.RFC3339, detail.EventTime); err == nil {
			occurredAt = parsed.UTC()
		}
	}
	return sourceEvent(settings, "aws-cloudtrail-"+firstNonEmpty(awssdk.ToString(event.EventId), attributes["event_type"], strconv.FormatInt(occurredAt.UnixNano(), 10)), "aws.cloudtrail", "aws/cloudtrail/v1", payload, attributes, occurredAt)
}

func sourceEvent(settings settings, id string, kind string, schemaRef string, payload []byte, attributes map[string]string, occurredAt time.Time) (*primitives.Event, error) {
	trimEmptyAttributes(attributes)
	return &primitives.Event{
		Id:         sanitizeEventID(id),
		TenantId:   settings.accountID,
		SourceId:   "aws",
		Kind:       kind,
		OccurredAt: timestamppb.New(occurredAt.UTC()),
		SchemaRef:  schemaRef,
		Payload:    payload,
		Attributes: attributes,
	}, nil
}

func awsPullFromRecords[T any](records []T, next string, build func(T) (*primitives.Event, error), cursorFallback func(T) string) (sourcecdk.Pull, error) {
	if len(records) == 0 {
		return sourcecdk.Pull{}, nil
	}
	events := make([]*primitives.Event, 0, len(records))
	for _, record := range records {
		event, err := build(record)
		if err != nil {
			return sourcecdk.Pull{}, err
		}
		events = append(events, event)
	}
	fallback := events[len(events)-1].GetId()
	if cursorFallback != nil {
		fallback = cursorFallback(records[len(records)-1])
	}
	pull := sourcecdk.Pull{
		Events: events,
		Checkpoint: &cerebrov1.SourceCheckpoint{
			Watermark:    events[len(events)-1].OccurredAt,
			CursorOpaque: firstNonEmpty(next, fallback),
		},
	}
	if next != "" {
		pull.NextCursor = &cerebrov1.SourceCursor{Opaque: next}
	}
	return pull, nil
}

func awsCheck[T any](ctx context.Context, clients awsClients, settings settings, list func(context.Context, awsClients, settings, string, int) ([]T, string, error), label string) error {
	_, _, err := list(ctx, clients, settings, "", 1)
	if err != nil {
		return fmt.Errorf("lookup %s for %s: %w", label, settings.accountID, err)
	}
	return nil
}

func awsURNsFor[T any](settings settings, records []T, render func(settings, T) (string, error)) ([]sourcecdk.URN, error) {
	values := make([]string, 0, len(records))
	for _, record := range records {
		rawURN, err := render(settings, record)
		if err != nil {
			return nil, err
		}
		values = append(values, rawURN)
	}
	return parseAWSURNs(values...)
}

func parseAWSURNs(values ...string) ([]sourcecdk.URN, error) {
	urns := make([]sourcecdk.URN, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			continue
		}
		urn, err := sourcecdk.ParseURN(value)
		if err != nil {
			return nil, err
		}
		urns = append(urns, urn)
	}
	return urns, nil
}

func nextMarker(truncated bool, marker *string) string {
	if !truncated {
		return ""
	}
	return awssdk.ToString(marker)
}

func int32Ptr(value int) *int32 {
	if value == 0 {
		return nil
	}
	parsed := int32(value)
	return &parsed
}

func stringPtr(value string) *string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	return &trimmed
}

func configValue(cfg sourcecdk.Config, key string) string {
	value, _ := cfg.Lookup(key)
	return strings.TrimSpace(value)
}

func cloudTrailActor(event cloudtrailtypes.Event, detail cloudTrailDetail) cloudTrailUserIdentity {
	if detail.UserIdentity.Arn != "" || detail.UserIdentity.PrincipalID != "" || detail.UserIdentity.UserName != "" {
		return detail.UserIdentity
	}
	return cloudTrailUserIdentity{UserName: awssdk.ToString(event.Username)}
}

func cloudTrailResource(event cloudtrailtypes.Event, detail cloudTrailDetail) (string, string) {
	if len(detail.Resources) != 0 {
		resource := detail.Resources[0]
		return firstNonEmpty(resource.ARN, resource.ARNLower, resource.Name), firstNonEmpty(resource.Type, "resource")
	}
	if len(event.Resources) != 0 {
		resource := event.Resources[0]
		return awssdk.ToString(resource.ResourceName), awssdk.ToString(resource.ResourceType)
	}
	return firstNonEmpty(awssdk.ToString(event.EventSource), awssdk.ToString(event.EventName)), "resource"
}

func firstTime(values ...*time.Time) time.Time {
	for _, value := range values {
		if value != nil && !value.IsZero() {
			return value.UTC()
		}
	}
	return time.Now().UTC()
}

func addTimeAttribute(attributes map[string]string, key string, value *time.Time) {
	if value == nil || value.IsZero() {
		return
	}
	attributes[key] = value.UTC().Format(time.RFC3339)
}

func isAdminPolicy(values ...string) bool {
	joined := strings.ToLower(strings.Join(values, " "))
	return containsAny(joined, "administratoraccess", "admin", "poweruser", "iamfullaccess")
}

func emailLike(value string) string {
	trimmed := strings.TrimSpace(value)
	if strings.Contains(trimmed, "@") {
		return strings.ToLower(trimmed)
	}
	return ""
}

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func containsAny(value string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(value, strings.ToLower(needle)) {
			return true
		}
	}
	return false
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
	value = strings.ReplaceAll(value, " ", "-")
	value = strings.ReplaceAll(value, "/", "-")
	value = strings.ReplaceAll(value, ":", "-")
	return strings.Trim(value, "-")
}
