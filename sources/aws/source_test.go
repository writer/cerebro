package aws

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	apigatewaytypes "github.com/aws/aws-sdk-go-v2/service/apigateway/types"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	apigatewayv2types "github.com/aws/aws-sdk-go-v2/service/apigatewayv2/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	cloudfronttypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cloudtrailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi"
	resourcegroupstaggingapitypes "github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi/types"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	route53types "github.com/aws/aws-sdk-go-v2/service/route53/types"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceconfig"
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

func TestParseSettingsValidatesAssumeRoleConfig(t *testing.T) {
	roleARN := "arn:aws:iam::123456789012:role/cerebro-org-scan-role"
	settings, err := parseSettings(sourcecdk.NewConfig(map[string]string{
		"account_id":                           "123456789012",
		"role_arn":                             roleARN,
		"external_id":                          "external-1",
		"role_session_name":                    "legacy-session",
		sourceconfig.AWSAssumeRoleAllowlistKey: "writer=" + roleARN,
		sourceconfig.RuntimeTenantIDKey:        "writer",
	}))
	if err != nil {
		t.Fatalf("parseSettings() error = %v", err)
	}
	if settings.roleARN != roleARN {
		t.Fatalf("roleARN = %q, want %q", settings.roleARN, roleARN)
	}
	if settings.externalID != "external-1" {
		t.Fatalf("externalID = %q, want external-1", settings.externalID)
	}
}

func TestParseSettingsAllowsLegacyTenantlessAssumeRoleOnlyWithInternalMarker(t *testing.T) {
	roleARN := "arn:aws:iam::123456789012:role/cerebro-org-scan-role"
	if _, err := parseSettings(sourcecdk.NewConfig(map[string]string{
		"account_id":                           "123456789012",
		"role_arn":                             roleARN,
		sourceconfig.AWSAssumeRoleAllowlistKey: roleARN,
		sourceconfig.LegacyTenantlessAssumeRoleKey: "true",
	})); err != nil {
		t.Fatalf("parseSettings() error = %v", err)
	}
}

func TestParseSettingsRejectsUnsafeAssumeRoleConfig(t *testing.T) {
	allowed := "arn:aws:iam::123456789012:role/cerebro-org-scan-role"
	for _, tt := range []struct {
		name   string
		config map[string]string
	}{
		{
			name:   "unallowlisted role",
			config: map[string]string{"account_id": "123456789012", "role_arn": "arn:aws:iam::123456789012:role/OtherRole", sourceconfig.AWSAssumeRoleAllowlistKey: "writer=" + allowed, sourceconfig.RuntimeTenantIDKey: "writer"},
		},
		{
			name:   "account mismatch",
			config: map[string]string{"account_id": "123456789012", "role_arn": "arn:aws:iam::210987654321:role/cerebro-org-scan-role", sourceconfig.AWSAssumeRoleAllowlistKey: "writer=" + allowed, sourceconfig.RuntimeTenantIDKey: "writer"},
		},
		{
			name:   "invalid role arn",
			config: map[string]string{"account_id": "123456789012", "role_arn": "legacy", sourceconfig.AWSAssumeRoleAllowlistKey: "writer=" + allowed, sourceconfig.RuntimeTenantIDKey: "writer"},
		},
		{
			name:   "tenant mismatch",
			config: map[string]string{"account_id": "123456789012", "role_arn": allowed, sourceconfig.AWSAssumeRoleAllowlistKey: "other=" + allowed, sourceconfig.RuntimeTenantIDKey: "writer"},
		},
		{
			name:   "bare allowlist entry",
			config: map[string]string{"account_id": "123456789012", "role_arn": allowed, sourceconfig.AWSAssumeRoleAllowlistKey: allowed, sourceconfig.RuntimeTenantIDKey: "writer"},
		},
		{
			name:   "missing runtime tenant",
			config: map[string]string{"account_id": "123456789012", "role_arn": allowed, sourceconfig.AWSAssumeRoleAllowlistKey: "writer=" + allowed},
		},
		{
			name:   "empty tenant allowlist entry",
			config: map[string]string{"account_id": "123456789012", "role_arn": allowed, sourceconfig.AWSAssumeRoleAllowlistKey: "=" + allowed},
		},
		{
			name:   "external id without role",
			config: map[string]string{"account_id": "123456789012", "external_id": "external-1"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseSettings(sourcecdk.NewConfig(tt.config)); err == nil {
				t.Fatal("parseSettings() error = nil, want non-nil")
			}
		})
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

func TestCloudTrailCursorFreezesRelativeSinceAcrossPages(t *testing.T) {
	var inputs []cloudtrail.LookupEventsInput
	source := newTestSource(t, fakeAWS{cloudTrailLookup: func(_ context.Context, input *cloudtrail.LookupEventsInput) (*cloudtrail.LookupEventsOutput, error) {
		inputs = append(inputs, *input)
		if len(inputs) == 1 {
			return &cloudtrail.LookupEventsOutput{NextToken: awssdk.String("token-1")}, nil
		}
		return &cloudtrail.LookupEventsOutput{}, nil
	}})
	config := sourcecdk.NewConfig(map[string]string{"account_id": "123456789012", "family": familyCloudTrail, "since": "PT2H"})

	first, err := source.Read(context.Background(), config, nil)
	if err != nil {
		t.Fatalf("Read(cloudtrail first) error = %v", err)
	}
	if first.NextCursor == nil {
		t.Fatal("first.NextCursor = nil, want encoded cursor")
	}
	if _, ok := parseCloudTrailCursor(first.NextCursor.GetOpaque(), settings{since: "PT2H"}, time.Now().UTC()); !ok {
		t.Fatalf("first.NextCursor is not a resumable CloudTrail cursor: %q", first.NextCursor.GetOpaque())
	}
	if _, err = source.Read(context.Background(), config, first.NextCursor); err != nil {
		t.Fatalf("Read(cloudtrail second) error = %v", err)
	}

	if len(inputs) != 2 {
		t.Fatalf("LookupEvents calls = %d, want 2", len(inputs))
	}
	if got := awssdk.ToString(inputs[1].NextToken); got != "token-1" {
		t.Fatalf("second NextToken = %q, want token-1", got)
	}
	if inputs[0].StartTime == nil || inputs[1].StartTime == nil {
		t.Fatalf("StartTime values = %v, %v; want both set", inputs[0].StartTime, inputs[1].StartTime)
	}
	if !inputs[0].StartTime.Equal(*inputs[1].StartTime) {
		t.Fatalf("second StartTime = %s, want frozen first StartTime %s", inputs[1].StartTime.Format(time.RFC3339Nano), inputs[0].StartTime.Format(time.RFC3339Nano))
	}
}

func TestCloudTrailCursorInvalidatesUnsafeTokens(t *testing.T) {
	for _, tt := range []struct {
		name   string
		cursor string
		config map[string]string
	}{
		{
			name: "expired encoded cursor",
			cursor: encodeCloudTrailCursor(
				settings{since: "PT2H"},
				&cloudtrail.LookupEventsInput{StartTime: timePtr("2026-05-24T00:00:00Z")},
				"expired-token",
				time.Now().UTC().Add(-2*time.Hour),
			),
			config: map[string]string{"account_id": "123456789012", "family": familyCloudTrail, "since": "PT2H"},
		},
		{
			name: "selector changed",
			cursor: encodeCloudTrailCursor(
				settings{since: "PT1H"},
				&cloudtrail.LookupEventsInput{StartTime: timePtr("2026-05-24T00:00:00Z")},
				"mismatched-token",
				time.Now().UTC(),
			),
			config: map[string]string{"account_id": "123456789012", "family": familyCloudTrail, "since": "PT2H"},
		},
		{
			name:   "legacy raw token",
			cursor: "legacy-aws-token",
			config: map[string]string{"account_id": "123456789012", "family": familyCloudTrail, "since": "PT2H"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var gotInput *cloudtrail.LookupEventsInput
			source := newTestSource(t, fakeAWS{cloudTrailLookup: func(_ context.Context, input *cloudtrail.LookupEventsInput) (*cloudtrail.LookupEventsOutput, error) {
				copy := *input
				gotInput = &copy
				return &cloudtrail.LookupEventsOutput{}, nil
			}})

			if _, err := source.Read(context.Background(), sourcecdk.NewConfig(tt.config), &cerebrov1.SourceCursor{Opaque: tt.cursor}); err != nil {
				t.Fatalf("Read(cloudtrail) error = %v", err)
			}
			if gotInput == nil {
				t.Fatal("LookupEvents was not called")
			}
			if got := awssdk.ToString(gotInput.NextToken); got != "" {
				t.Fatalf("NextToken = %q, want discarded token", got)
			}
		})
	}
}

func TestParsePublicEndpointCursorUpgradesLegacyStages(t *testing.T) {
	legacyPastAPIGateway := legacyPublicEndpointCursor(t, publicEndpointCursor{Stage: publicEndpointStageEIP, Token: "old-token"})
	got, err := parsePublicEndpointCursor(legacyPastAPIGateway)
	if err != nil {
		t.Fatalf("parsePublicEndpointCursor(legacy eip) error = %v", err)
	}
	if got.Stage != publicEndpointStageAPIGatewayRestAPI {
		t.Fatalf("legacy eip stage = %q, want %q", got.Stage, publicEndpointStageAPIGatewayRestAPI)
	}
	if got.Token != "" {
		t.Fatalf("legacy eip token = %q, want empty backfill token", got.Token)
	}

	legacyAPIGateway := legacyPublicEndpointCursor(t, publicEndpointCursor{Stage: publicEndpointStageAPIGateway, Token: "domain-page"})
	got, err = parsePublicEndpointCursor(legacyAPIGateway)
	if err != nil {
		t.Fatalf("parsePublicEndpointCursor(legacy apigateway) error = %v", err)
	}
	if got.Stage != publicEndpointStageAPIGateway || got.Token != "domain-page" {
		t.Fatalf("legacy apigateway cursor = %#v, want stage %q token domain-page", got, publicEndpointStageAPIGateway)
	}

	versioned := encodePublicEndpointCursor(publicEndpointCursor{Stage: publicEndpointStageEIP, Token: "new-token"})
	got, err = parsePublicEndpointCursor(versioned)
	if err != nil {
		t.Fatalf("parsePublicEndpointCursor(versioned eip) error = %v", err)
	}
	if got.Stage != publicEndpointStageEIP || got.Token != "new-token" || got.Version != publicEndpointCursorV2 {
		t.Fatalf("versioned eip cursor = %#v, want stage %q token new-token version %d", got, publicEndpointStageEIP, publicEndpointCursorV2)
	}

	got, err = parsePublicEndpointCursor("eni:legacy-token")
	if err != nil {
		t.Fatalf("parsePublicEndpointCursor(legacy eni) error = %v", err)
	}
	if got.Stage != publicEndpointStageAPIGatewayRestAPI {
		t.Fatalf("legacy eni stage = %q, want %q", got.Stage, publicEndpointStageAPIGatewayRestAPI)
	}
}

func legacyPublicEndpointCursor(t *testing.T, cursor publicEndpointCursor) string {
	t.Helper()
	cursor.Version = 0
	payload, err := json.Marshal(cursor)
	if err != nil {
		t.Fatalf("marshal legacy cursor: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(payload)
}

func TestEmailLikeExtractsSSOSessionEmail(t *testing.T) {
	arn := "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_admin/alice@example.com"
	if got := emailLike(arn); got != "alice@example.com" {
		t.Fatalf("emailLike() = %q, want alice@example.com", got)
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
		{family: familyAssetMetadata, kind: "asset.data_sensitivity"},
		{family: familyEffectivePermission, config: map[string]string{"principal_name": "admin@writer.com", "principal_type": "user"}, kind: "aws.effective_permission"},
		{family: familyIAMUser, kind: "aws.iam_user"},
		{family: familyIAMRole, kind: "aws.iam_role"},
		{family: familyIAMRoleTrust, kind: "aws.iam_role_trust"},
		{family: familyIAMGroup, kind: "aws.iam_group"},
		{family: familyIAMMembership, config: map[string]string{"group_name": "Security"}, kind: "aws.iam_group_membership"},
		{family: familyIAMRoleAssign, config: map[string]string{"principal_name": "admin@writer.com", "principal_type": "user"}, kind: "aws.iam_role_assignment"},
		{family: familyCloudTrail, kind: "aws.cloudtrail"},
		{family: familyPublicEndpoint, kind: "aws.public_endpoint"},
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

func TestReadAWSAssetMetadataPreview(t *testing.T) {
	source := newTestSource(t, fakeAWS{taggedResources: []resourcegroupstaggingapitypes.ResourceTagMapping{{
		ResourceARN: awssdk.String("arn:aws:ec2:us-east-1:123456789012:security-group/sg-1"),
		Tags: []resourcegroupstaggingapitypes.Tag{
			{Key: awssdk.String("Name"), Value: awssdk.String("prod-web")},
			{Key: awssdk.String("Owner"), Value: awssdk.String("security@writer.com")},
			{Key: awssdk.String("DataClassification"), Value: awssdk.String("restricted")},
			{Key: awssdk.String("Criticality"), Value: awssdk.String("tier0")},
		},
	}}})
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"account_id": "123456789012", "family": familyAssetMetadata}), nil)
	if err != nil {
		t.Fatalf("Read(asset_metadata) error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "asset.data_sensitivity" {
		t.Fatalf("kind = %q, want asset.data_sensitivity", event.Kind)
	}
	for key, want := range map[string]string{
		"data_classification": "restricted",
		"owner":               "security@writer.com",
		"resource_id":         "arn:aws:ec2:us-east-1:123456789012:security-group/sg-1",
		"resource_name":       "prod-web",
		"resource_type":       "security_group",
	} {
		if got := event.Attributes[key]; got != want {
			t.Fatalf("attributes[%s] = %q, want %q", key, got, want)
		}
	}
	if got := event.Attributes["crown_jewel"]; got != "true" {
		t.Fatalf("crown_jewel = %q, want true for tier0 criticality", got)
	}
}

func TestReadAWSAssetMetadataPaginatesTaggedResources(t *testing.T) {
	source := newTestSource(t, fakeAWS{taggedResources: []resourcegroupstaggingapitypes.ResourceTagMapping{
		{ResourceARN: awssdk.String("arn:aws:ec2:us-east-1:123456789012:security-group/sg-1")},
		{ResourceARN: awssdk.String("arn:aws:s3:::prod-data")},
	}})
	config := sourcecdk.NewConfig(map[string]string{"account_id": "123456789012", "family": familyAssetMetadata, "per_page": "1"})

	first, err := source.Read(context.Background(), config, nil)
	if err != nil {
		t.Fatalf("Read(asset_metadata first page) error = %v", err)
	}
	if len(first.Events) != 1 {
		t.Fatalf("len(first.Events) = %d, want 1", len(first.Events))
	}
	if first.NextCursor == nil || first.NextCursor.GetOpaque() == "" {
		t.Fatal("first.NextCursor = nil/empty, want second page cursor")
	}

	second, err := source.Read(context.Background(), config, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(asset_metadata second page) error = %v", err)
	}
	if len(second.Events) != 1 {
		t.Fatalf("len(second.Events) = %d, want 1", len(second.Events))
	}
	if second.NextCursor != nil {
		t.Fatalf("second.NextCursor = %q, want nil", second.NextCursor.GetOpaque())
	}
	if got := second.Events[0].Attributes["resource_id"]; got != "arn:aws:s3:::prod-data" {
		t.Fatalf("second resource_id = %q, want arn:aws:s3:::prod-data", got)
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

func TestIAMRoleTrustEventTargetsSameRoleIdentifierAsIAMRoleEvent(t *testing.T) {
	role := iamtypes.Role{
		Arn:      awssdk.String("arn:aws:iam::123456789012:role/AdminRole"),
		RoleId:   awssdk.String("AROADMIN"),
		RoleName: awssdk.String("AdminRole"),
	}
	roleEvent, err := iamRoleEvent(settings{accountID: "123456789012"}, role)
	if err != nil {
		t.Fatalf("iamRoleEvent() error = %v", err)
	}
	trustEvent, err := iamRoleTrustEvent(settings{accountID: "123456789012"}, iamRoleTrust{
		Role:      role,
		Principal: "arn:aws:iam::999999999999:role/ExternalAdmin",
		Statement: trustStatement{Action: "sts:AssumeRole"},
	})
	if err != nil {
		t.Fatalf("iamRoleTrustEvent() error = %v", err)
	}
	roleARN := "arn:aws:iam::123456789012:role/AdminRole"
	if got := trustEvent.Attributes["target_id"]; got != roleARN {
		t.Fatalf("trust target_id = %q, want role ARN %q", got, roleARN)
	}
	if got := trustEvent.Attributes["role_id"]; got != roleARN {
		t.Fatalf("trust role_id = %q, want role ARN %q", got, roleARN)
	}
	if got := trustEvent.Attributes["role_unique_id"]; got != roleEvent.Attributes["user_id"] {
		t.Fatalf("trust role_unique_id = %q, want role event user_id %q", got, roleEvent.Attributes["user_id"])
	}
	if got := trustEvent.Attributes["target_arn"]; got != roleARN {
		t.Fatalf("trust target_arn = %q, want role ARN preserved", got)
	}
}

func TestIAMRoleTrustClassifiesPrincipalTypes(t *testing.T) {
	trustPolicy := `{"Version":"2012-10-17","Statement":[{"Sid":"AccountTrust","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999999999999:root"},"Action":"sts:AssumeRole"},{"Sid":"ServiceTrust","Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"},{"Sid":"OIDCTrust","Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},"Action":["sts:AssumeRoleWithWebIdentity","sts:TagSession"]},{"Sid":"SAMLTrust","Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:saml-provider/Okta"},"Action":"sts:AssumeRoleWithSAML"}]}`
	role := iamtypes.Role{
		Arn:                      awssdk.String("arn:aws:iam::123456789012:role/DeployRole"),
		AssumeRolePolicyDocument: awssdk.String(trustPolicy),
		RoleId:                   awssdk.String("ARODEPLOY"),
		RoleName:                 awssdk.String("DeployRole"),
	}

	trusts := roleTrusts(role)
	if len(trusts) != 4 {
		t.Fatalf("len(roleTrusts) = %d, want 4", len(trusts))
	}

	events := make(map[string]*cerebrov1.EventEnvelope, len(trusts))
	for _, trust := range trusts {
		event, err := iamRoleTrustEvent(settings{accountID: "123456789012"}, trust)
		if err != nil {
			t.Fatalf("iamRoleTrustEvent() error = %v", err)
		}
		events[event.Attributes["statement_sid"]] = event
	}
	if got := events["AccountTrust"].Attributes["subject_type"]; got != "account" {
		t.Fatalf("account subject_type = %q, want account", got)
	}
	if got := events["AccountTrust"].Attributes["subject_id"]; got != "999999999999" {
		t.Fatalf("account subject_id = %q, want external account ID", got)
	}
	if got := events["AccountTrust"].Attributes["is_external"]; got != "true" {
		t.Fatalf("account is_external = %q, want true", got)
	}
	if got := events["ServiceTrust"].Attributes["subject_type"]; got != "service_principal" {
		t.Fatalf("service subject_type = %q, want service_principal", got)
	}
	if got := events["ServiceTrust"].Attributes["subject_id"]; got != "lambda.amazonaws.com" {
		t.Fatalf("service subject_id = %q, want lambda.amazonaws.com", got)
	}
	if got := events["OIDCTrust"].Attributes["subject_type"]; got != "service_principal" {
		t.Fatalf("oidc subject_type = %q, want service_principal", got)
	}
	if got := events["SAMLTrust"].Attributes["trust_action"]; got != "sts:AssumeRoleWithSAML" {
		t.Fatalf("saml trust_action = %q, want sts:AssumeRoleWithSAML", got)
	}
}

func TestIAMRoleTrustIncludesWildcardAssumeActions(t *testing.T) {
	for _, action := range []any{"sts:*", "sts:AssumeRole*", "*:AssumeRole", []any{"sts:TagSession", "sts:AssumeRole*"}} {
		t.Run(fmt.Sprint(action), func(t *testing.T) {
			role := iamtypes.Role{
				Arn:      awssdk.String("arn:aws:iam::123456789012:role/WildcardRole"),
				RoleId:   awssdk.String("AROWILDCARD"),
				RoleName: awssdk.String("WildcardRole"),
			}
			statement := trustStatement{
				Effect:    "Allow",
				Action:    action,
				Principal: json.RawMessage(`{"AWS":"arn:aws:iam::999999999999:role/ExternalAdmin"}`),
			}
			payload, err := json.Marshal(trustPolicyDocument{Statement: []trustStatement{statement}})
			if err != nil {
				t.Fatalf("Marshal() error = %v", err)
			}
			role.AssumeRolePolicyDocument = awssdk.String(string(payload))

			trusts := roleTrusts(role)
			if len(trusts) != 1 {
				t.Fatalf("len(roleTrusts) = %d, want 1", len(trusts))
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
		addresses: []ec2types.Address{{AllocationId: awssdk.String("eipalloc-1"), PublicIp: awssdk.String("203.0.113.10"), NetworkInterfaceId: awssdk.String("eni-1"), InstanceId: awssdk.String("i-1")}},
	})
	for _, tt := range []struct {
		family string
		kind   string
		attr   string
		want   string
	}{
		{family: familyIAMRoleTrust, kind: "aws.iam_role_trust", attr: "relationship", want: "can_assume"},
		{family: familyResourceExposure, kind: "aws.resource_exposure", attr: "internet_exposed", want: "true"},
		{family: familyPublicEndpoint, kind: "aws.public_endpoint", attr: "ip", want: "203.0.113.10"},
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
			if tt.family == familyPublicEndpoint {
				if got := pull.Events[0].Attributes["resource_id"]; got != "eipalloc-1" {
					t.Fatalf("resource_id = %q, want eipalloc-1", got)
				}
				if got := pull.Events[0].Attributes["associated_instance_id"]; got != "i-1" {
					t.Fatalf("associated_instance_id = %q, want i-1", got)
				}
			}
		})
	}
}

func TestReadAWSEffectivePermissionIncludesInlinePolicies(t *testing.T) {
	source := newTestSource(t, fakeAWS{
		inlinePolicyNames: []string{"InlineAdmin"},
		inlinePolicyDocuments: map[string]string{
			"InlineAdmin": url.QueryEscape(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:*","s3:GetObject"],"Resource":"*"},{"Effect":"Deny","Action":"ec2:*","Resource":"*"}]}`),
		},
	})

	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"account_id":     "123456789012",
		"family":         familyEffectivePermission,
		"principal_name": "admin@writer.com",
		"principal_type": "user",
	}), nil)
	if err != nil {
		t.Fatalf("Read(effective_permission inline policy) error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(pull.Events))
	}
	attrs := pull.Events[0].Attributes
	if got := attrs["policy_source"]; got != "inline" {
		t.Fatalf("policy_source = %q, want inline", got)
	}
	if got := attrs["actions"]; got != "iam:*,s3:GetObject" {
		t.Fatalf("actions = %q, want inline allow actions", got)
	}
	if got := attrs["is_admin"]; got != "true" {
		t.Fatalf("is_admin = %q, want true for wildcard inline actions", got)
	}
	if got := attrs["role_id"]; got != "inline:user:admin@writer.com:InlineAdmin" {
		t.Fatalf("role_id = %q, want synthetic inline policy id", got)
	}
}

func TestReadAWSEffectivePermissionPaginatesInlinePolicies(t *testing.T) {
	source := newTestSource(t, fakeAWS{
		inlinePolicyNames: []string{"InlineOne", "InlineTwo"},
		inlinePolicyDocuments: map[string]string{
			"InlineOne": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`,
			"InlineTwo": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*"}]}`,
		},
	})
	cfg := sourcecdk.NewConfig(map[string]string{
		"account_id":     "123456789012",
		"family":         familyEffectivePermission,
		"principal_name": "admin@writer.com",
		"principal_type": "user",
		"per_page":       "1",
	})

	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first inline policy page) error = %v", err)
	}
	if len(first.Events) != 1 {
		t.Fatalf("len(first.Events) = %d, want 1", len(first.Events))
	}
	if got := first.Events[0].Attributes["role_name"]; got != "InlineOne" {
		t.Fatalf("first inline role_name = %q, want InlineOne", got)
	}
	if first.NextCursor == nil {
		t.Fatal("first.NextCursor = nil, want cursor for second inline policy")
	}

	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second inline policy page) error = %v", err)
	}
	if len(second.Events) != 1 {
		t.Fatalf("len(second.Events) = %d, want 1", len(second.Events))
	}
	if got := second.Events[0].Attributes["role_name"]; got != "InlineTwo" {
		t.Fatalf("second inline role_name = %q, want InlineTwo", got)
	}
	if second.NextCursor != nil {
		t.Fatalf("second.NextCursor = %v, want nil", second.NextCursor)
	}
}

func TestReadAWSEffectivePermissionIncludesManagedPolicyActions(t *testing.T) {
	policyARN := "arn:aws:iam::123456789012:policy/CustomReadOnly"
	source := newTestSource(t, fakeAWS{
		attachedPolicies: []iamtypes.AttachedPolicy{{PolicyName: awssdk.String("CustomReadOnly"), PolicyArn: awssdk.String(policyARN)}},
		managedPolicyDocuments: map[string]string{
			policyARN: url.QueryEscape(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:ListBucket"],"Resource":"*"},{"Effect":"Deny","Action":"s3:DeleteObject","Resource":"*"}]}`),
		},
	})

	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"account_id":     "123456789012",
		"family":         familyEffectivePermission,
		"principal_name": "analyst@writer.com",
		"principal_type": "user",
	}), nil)
	if err != nil {
		t.Fatalf("Read(effective_permission managed policy) error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(pull.Events))
	}
	attrs := pull.Events[0].Attributes
	if got := attrs["policy_source"]; got != "attached" {
		t.Fatalf("policy_source = %q, want attached", got)
	}
	if got := attrs["actions"]; got != "s3:GetObject,s3:ListBucket" {
		t.Fatalf("actions = %q, want managed policy allow actions", got)
	}
	if got := attrs["role_id"]; got != policyARN {
		t.Fatalf("role_id = %q, want policy ARN", got)
	}
}

func TestDiscoverAWSEffectivePermissionIncludesInlinePolicies(t *testing.T) {
	source := newTestSource(t, fakeAWS{
		inlinePolicyNames: []string{"InlineAdmin"},
		inlinePolicyDocuments: map[string]string{
			"InlineAdmin": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"*"}]}`,
		},
	})

	urns, err := source.Discover(context.Background(), sourcecdk.NewConfig(map[string]string{
		"account_id":     "123456789012",
		"family":         familyEffectivePermission,
		"principal_name": "admin@writer.com",
		"principal_type": "user",
	}))
	if err != nil {
		t.Fatalf("Discover(effective_permission inline policy) error = %v", err)
	}
	want := sourcecdk.URN("urn:cerebro:123456789012:effective_permission:admin@writer.com:inline:user:admin@writer.com:InlineAdmin")
	if len(urns) != 1 || urns[0] != want {
		t.Fatalf("Discover inline policy URNs = %v, want [%s]", urns, want)
	}
}

func TestExpandedAWSGraphFamiliesUseExpectedAPIs(t *testing.T) {
	basePrincipalData := func(fake *recordingAWS) {
		fake.users = []iamtypes.User{{UserName: awssdk.String("admin@writer.com"), UserId: awssdk.String("AIDAADMIN")}}
		fake.groups = []iamtypes.Group{{GroupName: awssdk.String("Security"), GroupId: awssdk.String("AGPSECURITY")}}
		fake.roles = []iamtypes.Role{{RoleName: awssdk.String("AdminRole"), RoleId: awssdk.String("AROADMIN"), Arn: awssdk.String("arn:aws:iam::123456789012:role/AdminRole")}}
		fake.attachedPolicies = []iamtypes.AttachedPolicy{{PolicyName: awssdk.String("AdministratorAccess"), PolicyArn: awssdk.String("arn:aws:iam::aws:policy/AdministratorAccess")}}
		fake.managedPolicyDocuments = map[string]string{"arn:aws:iam::aws:policy/AdministratorAccess": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`}
		fake.inlinePolicyNames = []string{"InlineAdmin"}
		fake.inlinePolicyDocuments = map[string]string{"InlineAdmin": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"*"}]}`}
	}
	publicEndpointData := func(fake *recordingAWS) {
		fake.hostedZones = []route53types.HostedZone{{
			Id:     awssdk.String("/hostedzone/Z123"),
			Name:   awssdk.String("writer.com."),
			Config: &route53types.HostedZoneConfig{PrivateZone: false},
		}}
		fake.recordSets = []route53types.ResourceRecordSet{{
			Name: awssdk.String("app.writer.com."),
			Type: route53types.RRTypeCname,
			ResourceRecords: []route53types.ResourceRecord{{
				Value: awssdk.String("d111111abcdef8.cloudfront.net."),
			}},
		}}
		fake.distributions = []cloudfronttypes.DistributionSummary{{
			ARN:        awssdk.String("arn:aws:cloudfront::123456789012:distribution/EDFDVBD632BHDS5"),
			Id:         awssdk.String("EDFDVBD632BHDS5"),
			DomainName: awssdk.String("d111111abcdef8.cloudfront.net"),
			Enabled:    awssdk.Bool(true),
		}}
		fake.loadBalancers = []elbv2types.LoadBalancer{{
			LoadBalancerArn:  awssdk.String("arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/prod-web/123"),
			LoadBalancerName: awssdk.String("prod-web"),
			DNSName:          awssdk.String("prod-web-123.us-east-1.elb.amazonaws.com"),
			Scheme:           elbv2types.LoadBalancerSchemeEnumInternetFacing,
		}}
		fake.apiDomains = []apigatewaytypes.DomainName{{
			DomainName:    awssdk.String("api.writer.com"),
			DomainNameArn: awssdk.String("arn:aws:apigateway:us-east-1::/domainnames/api.writer.com"),
		}}
		fake.restAPIs = []apigatewaytypes.RestApi{{
			Id:   awssdk.String("rest123"),
			Name: awssdk.String("orders"),
		}}
		fake.apiV2Domains = []apigatewayv2types.DomainName{{
			DomainName: awssdk.String("events.writer.com"),
		}}
		fake.apiV2APIs = []apigatewayv2types.Api{{
			ApiId:        awssdk.String("v2abc"),
			ApiEndpoint:  awssdk.String("https://v2abc.execute-api.us-east-1.amazonaws.com"),
			Name:         awssdk.String("events"),
			ProtocolType: apigatewayv2types.ProtocolTypeHttp,
		}}
		fake.addresses = []ec2types.Address{{
			AllocationId: awssdk.String("eipalloc-1"),
			PublicIp:     awssdk.String("203.0.113.10"),
		}}
		fake.networkInterfaces = []ec2types.NetworkInterface{{
			NetworkInterfaceId: awssdk.String("eni-1"),
			Association:        &ec2types.NetworkInterfaceAssociation{PublicIp: awssdk.String("203.0.113.20")},
		}}
	}
	assetMetadataData := func(fake *recordingAWS) {
		fake.taggedResources = []resourcegroupstaggingapitypes.ResourceTagMapping{{
			ResourceARN: awssdk.String("arn:aws:ec2:us-east-1:123456789012:security-group/sg-1"),
			Tags: []resourcegroupstaggingapitypes.Tag{
				{Key: awssdk.String("Owner"), Value: awssdk.String("security@writer.com")},
				{Key: awssdk.String("DataClassification"), Value: awssdk.String("restricted")},
			},
		}}
	}
	for _, tt := range []struct {
		family  string
		seed    func(*recordingAWS)
		wantAPI []string
	}{
		{
			family:  familyAccessKey,
			seed:    basePrincipalData,
			wantAPI: []string{"iam:ListAccessKeys", "iam:ListUsers"},
		},
		{
			family:  familyAssetMetadata,
			seed:    assetMetadataData,
			wantAPI: []string{"tagging:GetResources"},
		},
		{
			family:  familyEffectivePermission,
			seed:    basePrincipalData,
			wantAPI: []string{"iam:GetGroupPolicy", "iam:GetPolicy", "iam:GetPolicyVersion", "iam:GetRolePolicy", "iam:GetUserPolicy", "iam:ListAttachedGroupPolicies", "iam:ListAttachedRolePolicies", "iam:ListAttachedUserPolicies", "iam:ListGroupPolicies", "iam:ListGroups", "iam:ListRolePolicies", "iam:ListRoles", "iam:ListUserPolicies", "iam:ListUsers"},
		},
		{
			family:  familyIAMGroup,
			wantAPI: []string{"iam:ListGroups"},
		},
		{
			family:  familyIAMMembership,
			seed:    basePrincipalData,
			wantAPI: []string{"iam:GetGroup", "iam:ListGroups"},
		},
		{
			family:  familyIAMRole,
			wantAPI: []string{"iam:ListRoles"},
		},
		{
			family:  familyIAMRoleAssign,
			seed:    basePrincipalData,
			wantAPI: []string{"iam:GetGroupPolicy", "iam:GetPolicy", "iam:GetPolicyVersion", "iam:GetRolePolicy", "iam:GetUserPolicy", "iam:ListAttachedGroupPolicies", "iam:ListAttachedRolePolicies", "iam:ListAttachedUserPolicies", "iam:ListGroupPolicies", "iam:ListGroups", "iam:ListRolePolicies", "iam:ListRoles", "iam:ListUserPolicies", "iam:ListUsers"},
		},
		{
			family:  familyIAMRoleTrust,
			wantAPI: []string{"iam:ListRoles"},
		},
		{
			family:  familyIAMUser,
			wantAPI: []string{"iam:ListUsers"},
		},
		{
			family:  familyPublicEndpoint,
			seed:    publicEndpointData,
			wantAPI: []string{"apigateway:GetDomainNames", "apigateway:GetRestApis", "apigatewayv2:GetApis", "apigatewayv2:GetDomainNames", "cloudfront:ListDistributions", "ec2:DescribeAddresses", "ec2:DescribeNetworkInterfaces", "elasticloadbalancing:DescribeLoadBalancers", "route53:ListHostedZones", "route53:ListResourceRecordSets"},
		},
		{
			family:  familyResourceExposure,
			wantAPI: []string{"ec2:DescribeSecurityGroups"},
		},
	} {
		t.Run(tt.family, func(t *testing.T) {
			fake := &recordingAWS{}
			if tt.seed != nil {
				tt.seed(fake)
			}
			source := newRecordingSource(t, fake)

			readAllPages(t, source, sourcecdk.NewConfig(map[string]string{"account_id": "123456789012", "family": tt.family}))

			if !sameStringSet(fake.calls, tt.wantAPI) {
				t.Fatalf("AWS API calls for %s = %v, want %v", tt.family, sortedUnique(fake.calls), sortedUnique(tt.wantAPI))
			}
		})
	}
}

func TestReadAWSNetworkInterfacePublicEndpointIncludesAttachedInstance(t *testing.T) {
	endpoints, _, err := listNetworkInterfacePublicEndpoints(context.Background(), awsClients{ec2: fakeAWS{
		networkInterfaces: []ec2types.NetworkInterface{{
			NetworkInterfaceId: awssdk.String("eni-1"),
			Description:        awssdk.String("prod-web-eni"),
			Association: &ec2types.NetworkInterfaceAssociation{
				PublicDnsName: awssdk.String("ec2-203-0-113-10.compute-1.amazonaws.com"),
				PublicIp:      awssdk.String("203.0.113.10"),
			},
			Attachment: &ec2types.NetworkInterfaceAttachment{
				InstanceId: awssdk.String("i-1234567890abcdef0"),
			},
		}},
	}}, settings{accountID: "123456789012", region: "us-east-1"}, publicEndpointCursor{}, 10)
	if err != nil {
		t.Fatalf("listNetworkInterfacePublicEndpoints() error = %v", err)
	}
	if len(endpoints) != 1 {
		t.Fatalf("len(endpoints) = %d, want 1", len(endpoints))
	}
	event, err := publicEndpointEvent(settings{accountID: "123456789012"}, endpoints[0])
	if err != nil {
		t.Fatalf("publicEndpointEvent() error = %v", err)
	}
	if got := event.Attributes["attached_instance_id"]; got != "i-1234567890abcdef0" {
		t.Fatalf("attached_instance_id = %q, want attached EC2 instance", got)
	}
	if got := event.Attributes["resource_type"]; got != "network_interface" {
		t.Fatalf("resource_type = %q, want network_interface", got)
	}
}

func TestReadAWSPublicEndpointCollectsDNSAndEdgeHosts(t *testing.T) {
	source := newTestSource(t, fakeAWS{
		hostedZones: []route53types.HostedZone{{
			Id:     awssdk.String("/hostedzone/Z123"),
			Name:   awssdk.String("writer.com."),
			Config: &route53types.HostedZoneConfig{PrivateZone: false},
		}},
		recordSets: []route53types.ResourceRecordSet{{
			Name: awssdk.String("app.writer.com."),
			Type: route53types.RRTypeCname,
			ResourceRecords: []route53types.ResourceRecord{{
				Value: awssdk.String("d111111abcdef8.cloudfront.net."),
			}},
		}},
		distributions: []cloudfronttypes.DistributionSummary{{
			ARN:        awssdk.String("arn:aws:cloudfront::123456789012:distribution/EDFDVBD632BHDS5"),
			Id:         awssdk.String("EDFDVBD632BHDS5"),
			DomainName: awssdk.String("d111111abcdef8.cloudfront.net"),
			Aliases:    &cloudfronttypes.Aliases{Items: []string{"app.writer.com"}},
			Enabled:    awssdk.Bool(true),
		}, {
			ARN:        awssdk.String("arn:aws:cloudfront::123456789012:distribution/DISABLED"),
			Id:         awssdk.String("DISABLED"),
			DomainName: awssdk.String("disabled.cloudfront.net"),
			Enabled:    awssdk.Bool(false),
		}},
	})

	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"account_id": "123456789012", "family": familyPublicEndpoint}), nil)
	if err != nil {
		t.Fatalf("Read(public_endpoint route53) error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(route53 events) = %d, want 1", len(pull.Events))
	}
	route53Event := pull.Events[0]
	if got := route53Event.Attributes["host"]; got != "app.writer.com" {
		t.Fatalf("route53 host = %q, want app.writer.com", got)
	}
	if got := route53Event.Attributes["target_host"]; got != "d111111abcdef8.cloudfront.net" {
		t.Fatalf("route53 target_host = %q, want d111111abcdef8.cloudfront.net", got)
	}
	if pull.NextCursor == nil {
		t.Fatal("route53 NextCursor = nil, want cloudfront cursor")
	}

	pull, err = source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"account_id": "123456789012", "family": familyPublicEndpoint}), pull.NextCursor)
	if err != nil {
		t.Fatalf("Read(public_endpoint cloudfront) error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(cloudfront events) = %d, want 1", len(pull.Events))
	}
	cloudfrontEvent := pull.Events[0]
	if got := cloudfrontEvent.Attributes["host"]; got != "d111111abcdef8.cloudfront.net" {
		t.Fatalf("cloudfront host = %q, want d111111abcdef8.cloudfront.net", got)
	}
	if got := cloudfrontEvent.Attributes["alternate_hosts"]; got != "app.writer.com" {
		t.Fatalf("cloudfront alternate_hosts = %q, want app.writer.com", got)
	}
}

func TestReadAWSPublicEndpointCollectsDefaultAPIGatewayHosts(t *testing.T) {
	source := newTestSource(t, fakeAWS{
		restAPIs: []apigatewaytypes.RestApi{{
			Id:   awssdk.String("rest123"),
			Name: awssdk.String("orders"),
			EndpointConfiguration: &apigatewaytypes.EndpointConfiguration{
				Types: []apigatewaytypes.EndpointType{apigatewaytypes.EndpointTypeRegional},
			},
		}, {
			Id:                        awssdk.String("restdisabled"),
			Name:                      awssdk.String("disabled"),
			DisableExecuteApiEndpoint: true,
		}, {
			Id:   awssdk.String("restprivate"),
			Name: awssdk.String("private"),
			EndpointConfiguration: &apigatewaytypes.EndpointConfiguration{
				Types: []apigatewaytypes.EndpointType{apigatewaytypes.EndpointTypePrivate},
			},
		}},
		apiV2APIs: []apigatewayv2types.Api{{
			ApiId:        awssdk.String("v2abc"),
			ApiEndpoint:  awssdk.String("https://v2abc.execute-api.us-east-1.amazonaws.com"),
			Name:         awssdk.String("events"),
			ProtocolType: apigatewayv2types.ProtocolTypeHttp,
		}, {
			ApiId:                     awssdk.String("v2disabled"),
			ApiEndpoint:               awssdk.String("https://v2disabled.execute-api.us-east-1.amazonaws.com"),
			Name:                      awssdk.String("disabled"),
			ProtocolType:              apigatewayv2types.ProtocolTypeHttp,
			DisableExecuteApiEndpoint: awssdk.Bool(true),
		}},
	})
	config := sourcecdk.NewConfig(map[string]string{"account_id": "123456789012", "family": familyPublicEndpoint})

	pull, err := source.Read(context.Background(), config, nil)
	if err != nil {
		t.Fatalf("Read(public_endpoint rest api) error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(rest api events) = %d, want 1", len(pull.Events))
	}
	restEvent := pull.Events[0]
	if got := restEvent.Attributes["host"]; got != "rest123.execute-api.us-east-1.amazonaws.com" {
		t.Fatalf("rest api host = %q, want rest123.execute-api.us-east-1.amazonaws.com", got)
	}
	if got := restEvent.Attributes["resource_type"]; got != "apigateway_rest_api" {
		t.Fatalf("rest api resource_type = %q, want apigateway_rest_api", got)
	}
	if pull.NextCursor == nil {
		t.Fatal("rest api NextCursor = nil, want apigatewayv2 cursor")
	}

	pull, err = source.Read(context.Background(), config, pull.NextCursor)
	if err != nil {
		t.Fatalf("Read(public_endpoint api v2) error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(api v2 events) = %d, want 1", len(pull.Events))
	}
	apiV2Event := pull.Events[0]
	if got := apiV2Event.Attributes["host"]; got != "v2abc.execute-api.us-east-1.amazonaws.com" {
		t.Fatalf("api v2 host = %q, want v2abc.execute-api.us-east-1.amazonaws.com", got)
	}
	if got := apiV2Event.Attributes["resource_type"]; got != "apigatewayv2_api" {
		t.Fatalf("api v2 resource_type = %q, want apigatewayv2_api", got)
	}
}

func TestAPIGatewayRestAPIPublicEndpointUsesPartitionSuffix(t *testing.T) {
	endpoint := apiGatewayRestAPIPublicEndpoint(settings{accountID: "123456789012", region: "cn-north-1"}, apigatewaytypes.RestApi{
		Id:   awssdk.String("rest123"),
		Name: awssdk.String("orders"),
	})
	if endpoint.Host != "rest123.execute-api.cn-north-1.amazonaws.com.cn" {
		t.Fatalf("Host = %q, want rest123.execute-api.cn-north-1.amazonaws.com.cn", endpoint.Host)
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
		{family: familyEffectivePermission, config: map[string]string{"principal_name": "admin@writer.com", "principal_type": "user"}, kind: "aws.effective_permission"},
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
		return awsClients{iam: fake, cloudTrail: fake, ec2: fake, route53: fake, cloudFront: fake, elbv2: fake, apiGateway: fake, apiGatewayV2: fakeAPIGatewayV2{domains: fake.apiV2Domains, apis: fake.apiV2APIs}, tagging: fake}, nil
	}}
	source.families, err = source.newFamilyEngine()
	if err != nil {
		t.Fatalf("newFamilyEngine() error = %v", err)
	}
	return source
}

func newRecordingSource(t *testing.T, fake *recordingAWS) *Source {
	t.Helper()
	spec, err := loadSpec()
	if err != nil {
		t.Fatalf("loadSpec() error = %v", err)
	}
	source := &Source{spec: spec, clients: func(context.Context, settings) (awsClients, error) {
		return awsClients{iam: fake, cloudTrail: fake, ec2: fake, route53: fake, cloudFront: fake, elbv2: fake, apiGateway: fake, apiGatewayV2: recordingAPIGatewayV2{fake: fake}, tagging: fake}, nil
	}}
	source.families, err = source.newFamilyEngine()
	if err != nil {
		t.Fatalf("newFamilyEngine() error = %v", err)
	}
	return source
}

func readAllPages(t *testing.T, source *Source, cfg sourcecdk.Config) {
	t.Helper()
	var cursor *cerebrov1.SourceCursor
	for page := 0; page < 20; page++ {
		pull, err := source.Read(context.Background(), cfg, cursor)
		if err != nil {
			t.Fatalf("Read page %d error = %v", page, err)
		}
		if pull.NextCursor == nil {
			return
		}
		cursor = pull.NextCursor
	}
	t.Fatal("Read did not finish within 20 pages")
}

func sameStringSet(got []string, want []string) bool {
	gotSet := sortedUnique(got)
	wantSet := sortedUnique(want)
	if len(gotSet) != len(wantSet) {
		return false
	}
	for index := range gotSet {
		if gotSet[index] != wantSet[index] {
			return false
		}
	}
	return true
}

func sortedUnique(values []string) []string {
	seen := map[string]bool{}
	for _, value := range values {
		seen[value] = true
	}
	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

type fakeAWS struct {
	users                  []iamtypes.User
	groups                 []iamtypes.Group
	roles                  []iamtypes.Role
	accessKeys             []iamtypes.AccessKeyMetadata
	attachedPolicies       []iamtypes.AttachedPolicy
	managedPolicyDocuments map[string]string
	inlinePolicyNames      []string
	inlinePolicyDocuments  map[string]string
	cloudTrailEvents       []cloudtrailtypes.Event
	cloudTrailLookup       func(context.Context, *cloudtrail.LookupEventsInput) (*cloudtrail.LookupEventsOutput, error)
	securityGroups         []ec2types.SecurityGroup
	addresses              []ec2types.Address
	networkInterfaces      []ec2types.NetworkInterface
	hostedZones            []route53types.HostedZone
	recordSets             []route53types.ResourceRecordSet
	distributions          []cloudfronttypes.DistributionSummary
	loadBalancers          []elbv2types.LoadBalancer
	apiDomains             []apigatewaytypes.DomainName
	restAPIs               []apigatewaytypes.RestApi
	apiV2Domains           []apigatewayv2types.DomainName
	apiV2APIs              []apigatewayv2types.Api
	taggedResources        []resourcegroupstaggingapitypes.ResourceTagMapping
}

type recordingAWS struct {
	fakeAWS
	calls []string
}

func (f *recordingAWS) record(action string) {
	f.calls = append(f.calls, action)
}

func (f *recordingAWS) ListUsers(ctx context.Context, input *iam.ListUsersInput, options ...func(*iam.Options)) (*iam.ListUsersOutput, error) {
	f.record("iam:ListUsers")
	return f.fakeAWS.ListUsers(ctx, input, options...)
}

func (f *recordingAWS) ListGroups(ctx context.Context, input *iam.ListGroupsInput, options ...func(*iam.Options)) (*iam.ListGroupsOutput, error) {
	f.record("iam:ListGroups")
	return f.fakeAWS.ListGroups(ctx, input, options...)
}

func (f *recordingAWS) ListRoles(ctx context.Context, input *iam.ListRolesInput, options ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	f.record("iam:ListRoles")
	return f.fakeAWS.ListRoles(ctx, input, options...)
}

func (f *recordingAWS) ListAccessKeys(ctx context.Context, input *iam.ListAccessKeysInput, options ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
	f.record("iam:ListAccessKeys")
	return f.fakeAWS.ListAccessKeys(ctx, input, options...)
}

func (f *recordingAWS) GetGroup(ctx context.Context, input *iam.GetGroupInput, options ...func(*iam.Options)) (*iam.GetGroupOutput, error) {
	f.record("iam:GetGroup")
	return f.fakeAWS.GetGroup(ctx, input, options...)
}

func (f *recordingAWS) ListAttachedUserPolicies(ctx context.Context, input *iam.ListAttachedUserPoliciesInput, options ...func(*iam.Options)) (*iam.ListAttachedUserPoliciesOutput, error) {
	f.record("iam:ListAttachedUserPolicies")
	return f.fakeAWS.ListAttachedUserPolicies(ctx, input, options...)
}

func (f *recordingAWS) ListAttachedGroupPolicies(ctx context.Context, input *iam.ListAttachedGroupPoliciesInput, options ...func(*iam.Options)) (*iam.ListAttachedGroupPoliciesOutput, error) {
	f.record("iam:ListAttachedGroupPolicies")
	return f.fakeAWS.ListAttachedGroupPolicies(ctx, input, options...)
}

func (f *recordingAWS) ListAttachedRolePolicies(ctx context.Context, input *iam.ListAttachedRolePoliciesInput, options ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error) {
	f.record("iam:ListAttachedRolePolicies")
	return f.fakeAWS.ListAttachedRolePolicies(ctx, input, options...)
}

func (f *recordingAWS) ListUserPolicies(ctx context.Context, input *iam.ListUserPoliciesInput, options ...func(*iam.Options)) (*iam.ListUserPoliciesOutput, error) {
	f.record("iam:ListUserPolicies")
	return f.fakeAWS.ListUserPolicies(ctx, input, options...)
}

func (f *recordingAWS) ListGroupPolicies(ctx context.Context, input *iam.ListGroupPoliciesInput, options ...func(*iam.Options)) (*iam.ListGroupPoliciesOutput, error) {
	f.record("iam:ListGroupPolicies")
	return f.fakeAWS.ListGroupPolicies(ctx, input, options...)
}

func (f *recordingAWS) ListRolePolicies(ctx context.Context, input *iam.ListRolePoliciesInput, options ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error) {
	f.record("iam:ListRolePolicies")
	return f.fakeAWS.ListRolePolicies(ctx, input, options...)
}

func (f *recordingAWS) GetPolicy(ctx context.Context, input *iam.GetPolicyInput, options ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
	f.record("iam:GetPolicy")
	return f.fakeAWS.GetPolicy(ctx, input, options...)
}

func (f *recordingAWS) GetPolicyVersion(ctx context.Context, input *iam.GetPolicyVersionInput, options ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
	f.record("iam:GetPolicyVersion")
	return f.fakeAWS.GetPolicyVersion(ctx, input, options...)
}

func (f *recordingAWS) GetUserPolicy(ctx context.Context, input *iam.GetUserPolicyInput, options ...func(*iam.Options)) (*iam.GetUserPolicyOutput, error) {
	f.record("iam:GetUserPolicy")
	return f.fakeAWS.GetUserPolicy(ctx, input, options...)
}

func (f *recordingAWS) GetGroupPolicy(ctx context.Context, input *iam.GetGroupPolicyInput, options ...func(*iam.Options)) (*iam.GetGroupPolicyOutput, error) {
	f.record("iam:GetGroupPolicy")
	return f.fakeAWS.GetGroupPolicy(ctx, input, options...)
}

func (f *recordingAWS) GetRolePolicy(ctx context.Context, input *iam.GetRolePolicyInput, options ...func(*iam.Options)) (*iam.GetRolePolicyOutput, error) {
	f.record("iam:GetRolePolicy")
	return f.fakeAWS.GetRolePolicy(ctx, input, options...)
}

func (f *recordingAWS) LookupEvents(ctx context.Context, input *cloudtrail.LookupEventsInput, options ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
	f.record("cloudtrail:LookupEvents")
	return f.fakeAWS.LookupEvents(ctx, input, options...)
}

func (f *recordingAWS) DescribeSecurityGroups(ctx context.Context, input *ec2.DescribeSecurityGroupsInput, options ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	f.record("ec2:DescribeSecurityGroups")
	return f.fakeAWS.DescribeSecurityGroups(ctx, input, options...)
}

func (f *recordingAWS) DescribeAddresses(ctx context.Context, input *ec2.DescribeAddressesInput, options ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
	f.record("ec2:DescribeAddresses")
	return f.fakeAWS.DescribeAddresses(ctx, input, options...)
}

func (f *recordingAWS) DescribeNetworkInterfaces(ctx context.Context, input *ec2.DescribeNetworkInterfacesInput, options ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
	f.record("ec2:DescribeNetworkInterfaces")
	return f.fakeAWS.DescribeNetworkInterfaces(ctx, input, options...)
}

func (f *recordingAWS) ListHostedZones(ctx context.Context, input *route53.ListHostedZonesInput, options ...func(*route53.Options)) (*route53.ListHostedZonesOutput, error) {
	f.record("route53:ListHostedZones")
	return f.fakeAWS.ListHostedZones(ctx, input, options...)
}

func (f *recordingAWS) ListResourceRecordSets(ctx context.Context, input *route53.ListResourceRecordSetsInput, options ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error) {
	f.record("route53:ListResourceRecordSets")
	return f.fakeAWS.ListResourceRecordSets(ctx, input, options...)
}

func (f *recordingAWS) ListDistributions(ctx context.Context, input *cloudfront.ListDistributionsInput, options ...func(*cloudfront.Options)) (*cloudfront.ListDistributionsOutput, error) {
	f.record("cloudfront:ListDistributions")
	return f.fakeAWS.ListDistributions(ctx, input, options...)
}

func (f *recordingAWS) DescribeLoadBalancers(ctx context.Context, input *elbv2.DescribeLoadBalancersInput, options ...func(*elbv2.Options)) (*elbv2.DescribeLoadBalancersOutput, error) {
	f.record("elasticloadbalancing:DescribeLoadBalancers")
	return f.fakeAWS.DescribeLoadBalancers(ctx, input, options...)
}

func (f *recordingAWS) GetDomainNames(ctx context.Context, input *apigateway.GetDomainNamesInput, options ...func(*apigateway.Options)) (*apigateway.GetDomainNamesOutput, error) {
	f.record("apigateway:GetDomainNames")
	return f.fakeAWS.GetDomainNames(ctx, input, options...)
}

func (f *recordingAWS) GetRestApis(ctx context.Context, input *apigateway.GetRestApisInput, options ...func(*apigateway.Options)) (*apigateway.GetRestApisOutput, error) {
	f.record("apigateway:GetRestApis")
	return f.fakeAWS.GetRestApis(ctx, input, options...)
}

func (f *recordingAWS) GetResources(ctx context.Context, input *resourcegroupstaggingapi.GetResourcesInput, options ...func(*resourcegroupstaggingapi.Options)) (*resourcegroupstaggingapi.GetResourcesOutput, error) {
	f.record("tagging:GetResources")
	return f.fakeAWS.GetResources(ctx, input, options...)
}

type recordingAPIGatewayV2 struct {
	fake *recordingAWS
}

func (f recordingAPIGatewayV2) GetApis(ctx context.Context, input *apigatewayv2.GetApisInput, options ...func(*apigatewayv2.Options)) (*apigatewayv2.GetApisOutput, error) {
	f.fake.record("apigatewayv2:GetApis")
	return fakeAPIGatewayV2{domains: f.fake.apiV2Domains, apis: f.fake.apiV2APIs}.GetApis(ctx, input, options...)
}

func (f recordingAPIGatewayV2) GetDomainNames(ctx context.Context, input *apigatewayv2.GetDomainNamesInput, options ...func(*apigatewayv2.Options)) (*apigatewayv2.GetDomainNamesOutput, error) {
	f.fake.record("apigatewayv2:GetDomainNames")
	return fakeAPIGatewayV2{domains: f.fake.apiV2Domains, apis: f.fake.apiV2APIs}.GetDomainNames(ctx, input, options...)
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

func (f fakeAWS) ListUserPolicies(_ context.Context, input *iam.ListUserPoliciesInput, _ ...func(*iam.Options)) (*iam.ListUserPoliciesOutput, error) {
	names, truncated, marker := paginateStringValues(f.inlinePolicyNames, awssdk.ToString(input.Marker), int(awssdk.ToInt32(input.MaxItems)))
	return &iam.ListUserPoliciesOutput{PolicyNames: names, IsTruncated: truncated, Marker: stringPtr(marker)}, nil
}

func (f fakeAWS) ListGroupPolicies(_ context.Context, input *iam.ListGroupPoliciesInput, _ ...func(*iam.Options)) (*iam.ListGroupPoliciesOutput, error) {
	names, truncated, marker := paginateStringValues(f.inlinePolicyNames, awssdk.ToString(input.Marker), int(awssdk.ToInt32(input.MaxItems)))
	return &iam.ListGroupPoliciesOutput{PolicyNames: names, IsTruncated: truncated, Marker: stringPtr(marker)}, nil
}

func (f fakeAWS) ListRolePolicies(_ context.Context, input *iam.ListRolePoliciesInput, _ ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error) {
	names, truncated, marker := paginateStringValues(f.inlinePolicyNames, awssdk.ToString(input.Marker), int(awssdk.ToInt32(input.MaxItems)))
	return &iam.ListRolePoliciesOutput{PolicyNames: names, IsTruncated: truncated, Marker: stringPtr(marker)}, nil
}

func (f fakeAWS) GetPolicy(_ context.Context, input *iam.GetPolicyInput, _ ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
	return &iam.GetPolicyOutput{Policy: &iamtypes.Policy{Arn: input.PolicyArn, DefaultVersionId: awssdk.String("v1")}}, nil
}

func (f fakeAWS) GetPolicyVersion(_ context.Context, input *iam.GetPolicyVersionInput, _ ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
	return &iam.GetPolicyVersionOutput{PolicyVersion: &iamtypes.PolicyVersion{Document: awssdk.String(f.managedPolicyDocument(awssdk.ToString(input.PolicyArn))), VersionId: input.VersionId}}, nil
}

func (f fakeAWS) GetUserPolicy(_ context.Context, input *iam.GetUserPolicyInput, _ ...func(*iam.Options)) (*iam.GetUserPolicyOutput, error) {
	return &iam.GetUserPolicyOutput{PolicyDocument: awssdk.String(f.inlinePolicyDocument(awssdk.ToString(input.PolicyName)))}, nil
}

func (f fakeAWS) GetGroupPolicy(_ context.Context, input *iam.GetGroupPolicyInput, _ ...func(*iam.Options)) (*iam.GetGroupPolicyOutput, error) {
	return &iam.GetGroupPolicyOutput{PolicyDocument: awssdk.String(f.inlinePolicyDocument(awssdk.ToString(input.PolicyName)))}, nil
}

func (f fakeAWS) GetRolePolicy(_ context.Context, input *iam.GetRolePolicyInput, _ ...func(*iam.Options)) (*iam.GetRolePolicyOutput, error) {
	return &iam.GetRolePolicyOutput{PolicyDocument: awssdk.String(f.inlinePolicyDocument(awssdk.ToString(input.PolicyName)))}, nil
}

func (f fakeAWS) inlinePolicyDocument(policyName string) string {
	if f.inlinePolicyDocuments != nil {
		return f.inlinePolicyDocuments[policyName]
	}
	return ""
}

func (f fakeAWS) managedPolicyDocument(policyARN string) string {
	if f.managedPolicyDocuments != nil {
		return f.managedPolicyDocuments[policyARN]
	}
	return ""
}

func paginateStringValues(values []string, marker string, limit int) ([]string, bool, string) {
	start := 0
	if marker != "" {
		parsed, err := strconv.Atoi(marker)
		if err == nil && parsed >= 0 && parsed <= len(values) {
			start = parsed
		}
	}
	if limit <= 0 || start+limit >= len(values) {
		return values[start:], false, ""
	}
	next := strconv.Itoa(start + limit)
	return values[start : start+limit], true, next
}

func paginateResourceTags(values []resourcegroupstaggingapitypes.ResourceTagMapping, marker string, limit int) ([]resourcegroupstaggingapitypes.ResourceTagMapping, string) {
	start := 0
	if marker != "" {
		parsed, err := strconv.Atoi(marker)
		if err == nil && parsed >= 0 && parsed <= len(values) {
			start = parsed
		}
	}
	if limit <= 0 || start+limit >= len(values) {
		return values[start:], ""
	}
	next := strconv.Itoa(start + limit)
	return values[start : start+limit], next
}

func (f fakeAWS) LookupEvents(ctx context.Context, input *cloudtrail.LookupEventsInput, _ ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
	if f.cloudTrailLookup != nil {
		return f.cloudTrailLookup(ctx, input)
	}
	return &cloudtrail.LookupEventsOutput{Events: f.cloudTrailEvents}, nil
}

func (f fakeAWS) DescribeSecurityGroups(context.Context, *ec2.DescribeSecurityGroupsInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	return &ec2.DescribeSecurityGroupsOutput{SecurityGroups: f.securityGroups}, nil
}

func (f fakeAWS) DescribeAddresses(context.Context, *ec2.DescribeAddressesInput, ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
	return &ec2.DescribeAddressesOutput{Addresses: f.addresses}, nil
}

func (f fakeAWS) DescribeNetworkInterfaces(context.Context, *ec2.DescribeNetworkInterfacesInput, ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
	return &ec2.DescribeNetworkInterfacesOutput{NetworkInterfaces: f.networkInterfaces}, nil
}

func (f fakeAWS) ListHostedZones(context.Context, *route53.ListHostedZonesInput, ...func(*route53.Options)) (*route53.ListHostedZonesOutput, error) {
	return &route53.ListHostedZonesOutput{HostedZones: f.hostedZones}, nil
}

func (f fakeAWS) ListResourceRecordSets(context.Context, *route53.ListResourceRecordSetsInput, ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error) {
	return &route53.ListResourceRecordSetsOutput{ResourceRecordSets: f.recordSets}, nil
}

func (f fakeAWS) ListDistributions(context.Context, *cloudfront.ListDistributionsInput, ...func(*cloudfront.Options)) (*cloudfront.ListDistributionsOutput, error) {
	return &cloudfront.ListDistributionsOutput{DistributionList: &cloudfronttypes.DistributionList{Items: f.distributions}}, nil
}

func (f fakeAWS) DescribeLoadBalancers(context.Context, *elbv2.DescribeLoadBalancersInput, ...func(*elbv2.Options)) (*elbv2.DescribeLoadBalancersOutput, error) {
	return &elbv2.DescribeLoadBalancersOutput{LoadBalancers: f.loadBalancers}, nil
}

func (f fakeAWS) GetDomainNames(_ context.Context, _ *apigateway.GetDomainNamesInput, _ ...func(*apigateway.Options)) (*apigateway.GetDomainNamesOutput, error) {
	return &apigateway.GetDomainNamesOutput{Items: f.apiDomains}, nil
}

func (f fakeAWS) GetRestApis(_ context.Context, _ *apigateway.GetRestApisInput, _ ...func(*apigateway.Options)) (*apigateway.GetRestApisOutput, error) {
	return &apigateway.GetRestApisOutput{Items: f.restAPIs}, nil
}

func (f fakeAWS) GetResources(_ context.Context, input *resourcegroupstaggingapi.GetResourcesInput, _ ...func(*resourcegroupstaggingapi.Options)) (*resourcegroupstaggingapi.GetResourcesOutput, error) {
	records, next := paginateResourceTags(f.taggedResources, awssdk.ToString(input.PaginationToken), int(awssdk.ToInt32(input.ResourcesPerPage)))
	return &resourcegroupstaggingapi.GetResourcesOutput{ResourceTagMappingList: records, PaginationToken: stringPtr(next)}, nil
}

type fakeAPIGatewayV2 struct {
	domains []apigatewayv2types.DomainName
	apis    []apigatewayv2types.Api
}

func (f fakeAPIGatewayV2) GetApis(_ context.Context, _ *apigatewayv2.GetApisInput, _ ...func(*apigatewayv2.Options)) (*apigatewayv2.GetApisOutput, error) {
	return &apigatewayv2.GetApisOutput{Items: f.apis}, nil
}

func (f fakeAPIGatewayV2) GetDomainNames(_ context.Context, _ *apigatewayv2.GetDomainNamesInput, _ ...func(*apigatewayv2.Options)) (*apigatewayv2.GetDomainNamesOutput, error) {
	return &apigatewayv2.GetDomainNamesOutput{Items: f.domains}, nil
}

func timePtr(value string) *time.Time {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		panic(err)
	}
	return &parsed
}
