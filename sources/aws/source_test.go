package aws

import (
	"context"
	"encoding/base64"
	"encoding/json"
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
	"github.com/aws/aws-sdk-go-v2/service/route53"
	route53types "github.com/aws/aws-sdk-go-v2/service/route53/types"

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
			name:   "external id without role",
			config: map[string]string{"account_id": "123456789012", "external_id": "external-1"},
		},
		{
			name:   "caller supplied session name",
			config: map[string]string{"account_id": "123456789012", "role_arn": allowed, "role_session_name": "caller", sourceconfig.AWSAssumeRoleAllowlistKey: "writer=" + allowed, sourceconfig.RuntimeTenantIDKey: "writer"},
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
		addresses: []ec2types.Address{{AllocationId: awssdk.String("eipalloc-1"), PublicIp: awssdk.String("203.0.113.10"), NetworkInterfaceId: awssdk.String("eni-1")}},
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
			}
		})
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
		return awsClients{iam: fake, cloudTrail: fake, ec2: fake, route53: fake, cloudFront: fake, elbv2: fake, apiGateway: fake, apiGatewayV2: fakeAPIGatewayV2{domains: fake.apiV2Domains, apis: fake.apiV2APIs}}, nil
	}}
	source.families, err = source.newFamilyEngine()
	if err != nil {
		t.Fatalf("newFamilyEngine() error = %v", err)
	}
	return source
}

type fakeAWS struct {
	users             []iamtypes.User
	groups            []iamtypes.Group
	roles             []iamtypes.Role
	accessKeys        []iamtypes.AccessKeyMetadata
	attachedPolicies  []iamtypes.AttachedPolicy
	cloudTrailEvents  []cloudtrailtypes.Event
	securityGroups    []ec2types.SecurityGroup
	addresses         []ec2types.Address
	networkInterfaces []ec2types.NetworkInterface
	hostedZones       []route53types.HostedZone
	recordSets        []route53types.ResourceRecordSet
	distributions     []cloudfronttypes.DistributionSummary
	loadBalancers     []elbv2types.LoadBalancer
	apiDomains        []apigatewaytypes.DomainName
	restAPIs          []apigatewaytypes.RestApi
	apiV2Domains      []apigatewayv2types.DomainName
	apiV2APIs         []apigatewayv2types.Api
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
