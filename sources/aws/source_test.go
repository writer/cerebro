package aws

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cloudtrailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestNewLoadsCatalog(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if source.Spec().Id != "aws" {
		t.Fatalf("Spec().Id = %q, want aws", source.Spec().Id)
	}
}

func TestCheckRequiresAccountID(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := source.Check(context.Background(), sourcecdk.NewConfig(map[string]string{})); err == nil {
		t.Fatal("Check() error = nil, want account_id error")
	}
}

func TestAWSPullFromRecordsPreservesNextCursorWithoutEvents(t *testing.T) {
	pull, err := awsPullFromRecords[string](nil, "next-page", nil, nil)
	if err != nil {
		t.Fatalf("awsPullFromRecords() error = %v", err)
	}
	if len(pull.Events) != 0 {
		t.Fatalf("len(Events) = %d, want 0", len(pull.Events))
	}
	if got := pull.NextCursor.GetOpaque(); got != "next-page" {
		t.Fatalf("NextCursor = %q, want next-page", got)
	}
}

func TestNewFixtureReplaysAWSFamilies(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}
	for _, tt := range []struct {
		family string
		config map[string]string
		kind   string
	}{
		{family: familyAccessKey, config: map[string]string{"user_name": "admin@writer.com"}, kind: "aws.access_key"},
		{family: familyIAMUser, kind: "aws.iam_user"},
		{family: familyIAMRole, kind: "aws.iam_role"},
		{family: familyIAMRoleTrust, kind: "aws.iam_role_trust"},
		{family: familyIAMGroup, kind: "aws.iam_group"},
		{family: familyIAMMembership, config: map[string]string{"group_name": "Security"}, kind: "aws.iam_group_membership"},
		{family: familyIAMRoleAssign, config: map[string]string{"principal_name": "admin@writer.com", "principal_type": "user"}, kind: "aws.iam_role_assignment"},
		{family: familyCloudTrail, kind: "aws.cloudtrail"},
		{family: familyResourceExposure, kind: "aws.resource_exposure"},
	} {
		t.Run(tt.family, func(t *testing.T) {
			config := map[string]string{"account_id": "123456789012", "family": tt.family}
			for key, value := range tt.config {
				config[key] = value
			}
			pull, err := source.Read(context.Background(), sourcecdk.NewConfig(config), nil)
			if err != nil {
				t.Fatalf("Read(%s) error = %v", tt.family, err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("len(Read(%s).Events) = %d, want 1", tt.family, len(pull.Events))
			}
			if got := pull.Events[0].Kind; got != tt.kind {
				t.Fatalf("Read(%s).Events[0].Kind = %q, want %q", tt.family, got, tt.kind)
			}
		})
	}
}

func TestReadAWSIAMUserPreview(t *testing.T) {
	source := newTestSource(t, fakeAWS{users: []iamtypes.User{{
		Arn: awssdk.String("arn:aws:iam::123456789012:user/admin@writer.com"), UserId: awssdk.String("AIDAADMIN"), UserName: awssdk.String("admin@writer.com"), CreateDate: timePtr("2026-01-01T00:00:00Z"),
	}}})
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"account_id": "123456789012", "family": familyIAMUser}), nil)
	if err != nil {
		t.Fatalf("Read(iam_user) error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(pull.Events))
	}
	if got := pull.Events[0].Attributes["email"]; got != "admin@writer.com" {
		t.Fatalf("email = %q, want admin@writer.com", got)
	}
}

func TestReadAWSRoleAndAccessKeyPreview(t *testing.T) {
	source := newTestSource(t, fakeAWS{
		roles: []iamtypes.Role{{
			Arn: awssdk.String("arn:aws:iam::123456789012:role/AdminRole"), RoleId: awssdk.String("AROADMIN"), RoleName: awssdk.String("AdminRole"), CreateDate: timePtr("2026-01-01T00:00:00Z"),
		}},
		accessKeys: []iamtypes.AccessKeyMetadata{{
			AccessKeyId: awssdk.String("AKIAEXAMPLE"), UserName: awssdk.String("admin@writer.com"), Status: iamtypes.StatusTypeActive, CreateDate: timePtr("2026-01-01T00:00:00Z"),
		}},
	})
	for _, tt := range []struct {
		family string
		config map[string]string
		kind   string
	}{
		{family: familyIAMRole, kind: "aws.iam_role"},
		{family: familyAccessKey, config: map[string]string{"user_name": "admin@writer.com"}, kind: "aws.access_key"},
	} {
		t.Run(tt.family, func(t *testing.T) {
			config := map[string]string{"account_id": "123456789012", "family": tt.family}
			for key, value := range tt.config {
				config[key] = value
			}
			pull, err := source.Read(context.Background(), sourcecdk.NewConfig(config), nil)
			if err != nil {
				t.Fatalf("Read(%s) error = %v", tt.family, err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("len(events) = %d, want 1", len(pull.Events))
			}
			if got := pull.Events[0].Kind; got != tt.kind {
				t.Fatalf("kind = %q, want %q", got, tt.kind)
			}
		})
	}
}

func TestReadAWSExposureAndTrustPreview(t *testing.T) {
	trustPolicy := `{"Version":"2012-10-17","Statement":[{"Sid":"ExternalTrust","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999999999999:role/ExternalAdmin"},"Action":"sts:AssumeRole"}]}`
	source := newTestSource(t, fakeAWS{
		roles: []iamtypes.Role{{
			Arn: awssdk.String("arn:aws:iam::123456789012:role/AdminRole"), RoleId: awssdk.String("AROADMIN"), RoleName: awssdk.String("AdminRole"), AssumeRolePolicyDocument: awssdk.String(trustPolicy), CreateDate: timePtr("2026-01-01T00:00:00Z"),
		}},
		securityGroups: []ec2types.SecurityGroup{{
			GroupId: awssdk.String("sg-1"), GroupName: awssdk.String("prod-web"), SecurityGroupArn: awssdk.String("arn:aws:ec2:us-east-1:123456789012:security-group/sg-1"), VpcId: awssdk.String("vpc-1"),
			IpPermissions: []ec2types.IpPermission{{
				IpProtocol: awssdk.String("tcp"), FromPort: awssdk.Int32(443), ToPort: awssdk.Int32(443), IpRanges: []ec2types.IpRange{{CidrIp: awssdk.String("0.0.0.0/0")}},
			}},
		}},
	})
	for _, tt := range []struct {
		family string
		kind   string
		attr   string
		want   string
	}{
		{family: familyIAMRoleTrust, kind: "aws.iam_role_trust", attr: "relationship", want: "can_assume"},
		{family: familyResourceExposure, kind: "aws.resource_exposure", attr: "internet_exposed", want: "true"},
	} {
		t.Run(tt.family, func(t *testing.T) {
			pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"account_id": "123456789012", "family": tt.family}), nil)
			if err != nil {
				t.Fatalf("Read(%s) error = %v", tt.family, err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("len(events) = %d, want 1", len(pull.Events))
			}
			if got := pull.Events[0].Kind; got != tt.kind {
				t.Fatalf("kind = %q, want %q", got, tt.kind)
			}
			if got := pull.Events[0].Attributes[tt.attr]; got != tt.want {
				t.Fatalf("%s = %q, want %q", tt.attr, got, tt.want)
			}
		})
	}
}

func TestReadAWSRoleAssignmentAndCloudTrailPreview(t *testing.T) {
	detail, err := json.Marshal(map[string]any{
		"eventName":    "AttachUserPolicy",
		"eventTime":    "2026-04-23T00:00:00Z",
		"userIdentity": map[string]any{"arn": "arn:aws:iam::123456789012:user/admin@writer.com", "userName": "admin@writer.com", "principalId": "AIDAADMIN", "type": "IAMUser"},
		"resources":    []map[string]any{{"ARN": "arn:aws:iam::aws:policy/AdministratorAccess", "resourceType": "AWS::IAM::Policy"}},
	})
	if err != nil {
		t.Fatalf("marshal cloudtrail detail: %v", err)
	}
	source := newTestSource(t, fakeAWS{
		attachedPolicies: []iamtypes.AttachedPolicy{{PolicyArn: awssdk.String("arn:aws:iam::aws:policy/AdministratorAccess"), PolicyName: awssdk.String("AdministratorAccess")}},
		cloudTrailEvents: []cloudtrailtypes.Event{{EventId: awssdk.String("evt-1"), EventName: awssdk.String("AttachUserPolicy"), CloudTrailEvent: awssdk.String(string(detail)), EventTime: timePtr("2026-04-23T00:00:00Z")}},
	})
	for _, tt := range []struct {
		family string
		config map[string]string
		kind   string
	}{
		{family: familyIAMRoleAssign, config: map[string]string{"principal_name": "admin@writer.com", "principal_type": "user"}, kind: "aws.iam_role_assignment"},
		{family: familyCloudTrail, kind: "aws.cloudtrail"},
	} {
		t.Run(tt.family, func(t *testing.T) {
			config := map[string]string{"account_id": "123456789012", "family": tt.family}
			for key, value := range tt.config {
				config[key] = value
			}
			pull, err := source.Read(context.Background(), sourcecdk.NewConfig(config), nil)
			if err != nil {
				t.Fatalf("Read(%s) error = %v", tt.family, err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("len(events) = %d, want 1", len(pull.Events))
			}
			if got := pull.Events[0].Kind; got != tt.kind {
				t.Fatalf("kind = %q, want %q", got, tt.kind)
			}
		})
	}
}

func newTestSource(t *testing.T, fake fakeAWS) *Source {
	t.Helper()
	spec, err := loadSpec()
	if err != nil {
		t.Fatalf("loadSpec() error = %v", err)
	}
	source := &Source{spec: spec, clients: func(context.Context, settings) (awsClients, error) {
		return awsClients{iam: fake, cloudTrail: fake, ec2: fake}, nil
	}}
	source.families, err = source.newFamilyEngine()
	if err != nil {
		t.Fatalf("newFamilyEngine() error = %v", err)
	}
	return source
}

type fakeAWS struct {
	users            []iamtypes.User
	groups           []iamtypes.Group
	roles            []iamtypes.Role
	accessKeys       []iamtypes.AccessKeyMetadata
	attachedPolicies []iamtypes.AttachedPolicy
	cloudTrailEvents []cloudtrailtypes.Event
	securityGroups   []ec2types.SecurityGroup
}

func (f fakeAWS) ListUsers(context.Context, *iam.ListUsersInput, ...func(*iam.Options)) (*iam.ListUsersOutput, error) {
	return &iam.ListUsersOutput{Users: f.users}, nil
}

func (f fakeAWS) ListGroups(context.Context, *iam.ListGroupsInput, ...func(*iam.Options)) (*iam.ListGroupsOutput, error) {
	return &iam.ListGroupsOutput{Groups: f.groups}, nil
}

func (f fakeAWS) ListRoles(context.Context, *iam.ListRolesInput, ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	return &iam.ListRolesOutput{Roles: f.roles}, nil
}

func (f fakeAWS) ListAccessKeys(context.Context, *iam.ListAccessKeysInput, ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
	return &iam.ListAccessKeysOutput{AccessKeyMetadata: f.accessKeys}, nil
}

func (f fakeAWS) GetGroup(context.Context, *iam.GetGroupInput, ...func(*iam.Options)) (*iam.GetGroupOutput, error) {
	return &iam.GetGroupOutput{Users: f.users}, nil
}

func (f fakeAWS) ListAttachedUserPolicies(context.Context, *iam.ListAttachedUserPoliciesInput, ...func(*iam.Options)) (*iam.ListAttachedUserPoliciesOutput, error) {
	return &iam.ListAttachedUserPoliciesOutput{AttachedPolicies: f.attachedPolicies}, nil
}

func (f fakeAWS) ListAttachedGroupPolicies(context.Context, *iam.ListAttachedGroupPoliciesInput, ...func(*iam.Options)) (*iam.ListAttachedGroupPoliciesOutput, error) {
	return &iam.ListAttachedGroupPoliciesOutput{AttachedPolicies: f.attachedPolicies}, nil
}

func (f fakeAWS) ListAttachedRolePolicies(context.Context, *iam.ListAttachedRolePoliciesInput, ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error) {
	return &iam.ListAttachedRolePoliciesOutput{AttachedPolicies: f.attachedPolicies}, nil
}

func (f fakeAWS) LookupEvents(context.Context, *cloudtrail.LookupEventsInput, ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
	return &cloudtrail.LookupEventsOutput{Events: f.cloudTrailEvents}, nil
}

func (f fakeAWS) DescribeSecurityGroups(context.Context, *ec2.DescribeSecurityGroupsInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	return &ec2.DescribeSecurityGroupsOutput{SecurityGroups: f.securityGroups}, nil
}

func timePtr(value string) *time.Time {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		panic(err)
	}
	return &parsed
}
