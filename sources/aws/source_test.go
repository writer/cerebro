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
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi"
	resourcegroupstaggingapitypes "github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi/types"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	route53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	secretsmanagertypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	snstypes "github.com/aws/aws-sdk-go-v2/service/sns/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

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
		{family: familyEC2Instance, kind: "aws.ec2_instance"},
		{family: familyECRRepository, kind: "aws.ecr_repository"},
		{family: familyECSService, kind: "aws.ecs_service"},
		{family: familyECSTask, kind: "aws.ecs_task"},
		{family: familyECSTaskDefinition, kind: "aws.ecs_task_definition"},
		{family: familyEKSCluster, kind: "aws.eks_cluster"},
		{family: familyEKSNodegroup, kind: "aws.eks_nodegroup"},
		{family: familyEKSFargateProfile, kind: "aws.eks_fargate_profile"},
		{family: familyEKSPodIdentity, kind: "aws.eks_pod_identity_association"},
		{family: familyEffectivePermission, config: map[string]string{"principal_name": "admin@writer.com", "principal_type": "user"}, kind: "aws.effective_permission"},
		{family: familyIAMUser, kind: "aws.iam_user"},
		{family: familyKMSKey, kind: "aws.kms_key"},
		{family: familyLambdaFunction, kind: "aws.lambda_function"},
		{family: familyRDSInstance, kind: "aws.rds_instance"},
		{family: familyS3Bucket, kind: "aws.s3_bucket"},
		{family: familySecret, kind: "aws.secret"},
		{family: familySNSTopic, kind: "aws.sns_topic"},
		{family: familySQSQueue, kind: "aws.sqs_queue"},
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

func TestReadAWSComputeInventoryEvents(t *testing.T) {
	profileARN := "arn:aws:iam::123456789012:instance-profile/WebProfile"
	instanceRoleARN := "arn:aws:iam::123456789012:role/WebInstanceRole"
	taskDefinitionARN := "arn:aws:ecs:us-east-1:123456789012:task-definition/orders:7"
	taskARN := "arn:aws:ecs:us-east-1:123456789012:task/prod/abcd1234"
	serviceARN := "arn:aws:ecs:us-east-1:123456789012:service/prod/orders"
	clusterARN := "arn:aws:ecs:us-east-1:123456789012:cluster/prod"
	eksClusterName := "prod-eks"
	eksClusterARN := "arn:aws:eks:us-east-1:123456789012:cluster/prod-eks"
	nodegroupARN := "arn:aws:eks:us-east-1:123456789012:nodegroup/prod-eks/managed-linux/uuid"
	fargateProfileARN := "arn:aws:eks:us-east-1:123456789012:fargateprofile/prod-eks/payments/uuid"
	podIdentityARN := "arn:aws:eks:us-east-1:123456789012:podidentityassociation/prod-eks/a-123"
	source := newTestSource(t, fakeAWS{
		networkInterfaces: []ec2types.NetworkInterface{{
			NetworkInterfaceId: awssdk.String("eni-task"),
			Groups:             []ec2types.GroupIdentifier{{GroupId: awssdk.String("sg-task")}},
			PrivateIpAddress:   awssdk.String("10.0.2.25"),
			SubnetId:           awssdk.String("subnet-task"),
			VpcId:              awssdk.String("vpc-1"),
		}},
		compute: fakeAWSCompute{
			instances: []ec2types.Instance{{
				InstanceId:   awssdk.String("i-123"),
				ImageId:      awssdk.String("ami-123"),
				InstanceType: ec2types.InstanceTypeT3Micro,
				IamInstanceProfile: &ec2types.IamInstanceProfile{
					Arn: awssdk.String(profileARN),
					Id:  awssdk.String("AIPROFILE"),
				},
				NetworkInterfaces: []ec2types.InstanceNetworkInterface{{
					NetworkInterfaceId: awssdk.String("eni-1"),
					Groups:             []ec2types.GroupIdentifier{{GroupId: awssdk.String("sg-1")}},
				}},
				Placement:        &ec2types.Placement{AvailabilityZone: awssdk.String("us-east-1a")},
				PrivateIpAddress: awssdk.String("10.0.1.10"),
				SecurityGroups:   []ec2types.GroupIdentifier{{GroupId: awssdk.String("sg-1")}},
				State:            &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
				SubnetId:         awssdk.String("subnet-1"),
				Tags:             []ec2types.Tag{{Key: awssdk.String("Name"), Value: awssdk.String("prod-web")}},
				VpcId:            awssdk.String("vpc-1"),
			}},
			instanceProfiles: map[string]iamtypes.InstanceProfile{
				"WebProfile": {Roles: []iamtypes.Role{{Arn: awssdk.String(instanceRoleARN), RoleName: awssdk.String("WebInstanceRole"), RoleId: awssdk.String("AROWEB")}}},
			},
			lambdaFunctions: []lambdatypes.FunctionConfiguration{{
				FunctionArn:  awssdk.String("arn:aws:lambda:us-east-1:123456789012:function:orders"),
				FunctionName: awssdk.String("orders"),
				Role:         awssdk.String("arn:aws:iam::123456789012:role/LambdaOrdersRole"),
				Runtime:      lambdatypes.RuntimePython312,
				State:        lambdatypes.StateActive,
				VpcConfig: &lambdatypes.VpcConfigResponse{
					SecurityGroupIds: []string{"sg-lambda"},
					SubnetIds:        []string{"subnet-lambda"},
					VpcId:            awssdk.String("vpc-1"),
				},
			}},
			ecsClusters:    []string{clusterARN},
			ecsServiceARNs: map[string][]string{clusterARN: []string{serviceARN}},
			ecsServices:    map[string]ecstypes.Service{serviceARN: {ClusterArn: awssdk.String(clusterARN), ServiceArn: awssdk.String(serviceARN), ServiceName: awssdk.String("orders"), Status: awssdk.String("ACTIVE"), TaskDefinition: awssdk.String(taskDefinitionARN), DesiredCount: 2, RunningCount: 2}},
			ecsTaskARNs:    map[string][]string{clusterARN: []string{taskARN}},
			ecsTasks: map[string]ecstypes.Task{taskARN: {
				Attachments: []ecstypes.Attachment{{Details: []ecstypes.KeyValuePair{
					{Name: awssdk.String("networkInterfaceId"), Value: awssdk.String("eni-task")},
					{Name: awssdk.String("subnetId"), Value: awssdk.String("subnet-task")},
					{Name: awssdk.String("privateIPv4Address"), Value: awssdk.String("10.0.2.25")},
				}}},
				ClusterArn:        awssdk.String(clusterARN),
				Group:             awssdk.String("service:orders"),
				LastStatus:        awssdk.String("RUNNING"),
				LaunchType:        ecstypes.LaunchTypeFargate,
				TaskArn:           awssdk.String(taskARN),
				TaskDefinitionArn: awssdk.String(taskDefinitionARN),
			}},
			ecsTaskDefinitionARNs: []string{taskDefinitionARN},
			ecsTaskDefinitions: map[string]ecstypes.TaskDefinition{taskDefinitionARN: {
				ContainerDefinitions: []ecstypes.ContainerDefinition{{Name: awssdk.String("orders"), Image: awssdk.String("repo/orders:latest")}},
				ExecutionRoleArn:     awssdk.String("arn:aws:iam::123456789012:role/ECSExecutionRole"),
				Family:               awssdk.String("orders"),
				RequiresCompatibilities: []ecstypes.Compatibility{
					ecstypes.CompatibilityFargate,
				},
				Revision:          7,
				Status:            ecstypes.TaskDefinitionStatusActive,
				TaskDefinitionArn: awssdk.String(taskDefinitionARN),
				TaskRoleArn:       awssdk.String("arn:aws:iam::123456789012:role/ECSTaskRole"),
			}},
			eksClusters: []ekstypes.Cluster{{
				Arn:      awssdk.String(eksClusterARN),
				Endpoint: awssdk.String("https://ABCDEF.gr7.us-east-1.eks.amazonaws.com"),
				Name:     awssdk.String(eksClusterName),
				ResourcesVpcConfig: &ekstypes.VpcConfigResponse{
					ClusterSecurityGroupId: awssdk.String("sg-eks-control"),
					EndpointPublicAccess:   true,
					PublicAccessCidrs:      []string{"0.0.0.0/0"},
					SecurityGroupIds:       []string{"sg-eks"},
					SubnetIds:              []string{"subnet-eks"},
					VpcId:                  awssdk.String("vpc-1"),
				},
				RoleArn: awssdk.String("arn:aws:iam::123456789012:role/EKSClusterRole"),
				Status:  ekstypes.ClusterStatusActive,
				Version: awssdk.String("1.30"),
			}},
			eksNodegroupNames: map[string][]string{eksClusterName: []string{"managed-linux"}},
			eksNodegroups: map[string]ekstypes.Nodegroup{awsTestEKSChildKey(eksClusterName, "managed-linux"): {
				ClusterName:   awssdk.String(eksClusterName),
				InstanceTypes: []string{"m7g.large"},
				NodegroupArn:  awssdk.String(nodegroupARN),
				NodegroupName: awssdk.String("managed-linux"),
				NodeRole:      awssdk.String("arn:aws:iam::123456789012:role/EKSNodeRole"),
				Status:        ekstypes.NodegroupStatusActive,
				Subnets:       []string{"subnet-eks"},
				Version:       awssdk.String("1.30"),
			}},
			eksFargateNames: map[string][]string{eksClusterName: []string{"payments"}},
			eksFargateProfiles: map[string]ekstypes.FargateProfile{awsTestEKSChildKey(eksClusterName, "payments"): {
				ClusterName:         awssdk.String(eksClusterName),
				FargateProfileArn:   awssdk.String(fargateProfileARN),
				FargateProfileName:  awssdk.String("payments"),
				PodExecutionRoleArn: awssdk.String("arn:aws:iam::123456789012:role/EKSFargatePodExecutionRole"),
				Selectors:           []ekstypes.FargateProfileSelector{{Namespace: awssdk.String("payments"), Labels: map[string]string{"runtime": "fargate"}}},
				Status:              ekstypes.FargateProfileStatusActive,
				Subnets:             []string{"subnet-eks"},
			}},
			eksPodIdentityIDs: map[string][]string{eksClusterName: []string{"a-123"}},
			eksPodIdentities: map[string]ekstypes.PodIdentityAssociation{awsTestEKSChildKey(eksClusterName, "a-123"): {
				AssociationArn: awssdk.String(podIdentityARN),
				AssociationId:  awssdk.String("a-123"),
				ClusterName:    awssdk.String(eksClusterName),
				Namespace:      awssdk.String("payments"),
				RoleArn:        awssdk.String("arn:aws:iam::123456789012:role/EKSPaymentsPodRole"),
				ServiceAccount: awssdk.String("api"),
			}},
		},
	})
	for _, tt := range []struct {
		family string
		kind   string
		assert func(*testing.T, *cerebrov1.EventEnvelope)
	}{
		{
			family: familyEC2Instance,
			kind:   "aws.ec2_instance",
			assert: func(t *testing.T, event *cerebrov1.EventEnvelope) {
				if got := event.Attributes["role_arn"]; got != instanceRoleARN {
					t.Fatalf("ec2 role_arn = %q, want %q", got, instanceRoleARN)
				}
				if got := event.Attributes["network_interface_ids"]; got != "eni-1" {
					t.Fatalf("ec2 network_interface_ids = %q, want eni-1", got)
				}
			},
		},
		{
			family: familyLambdaFunction,
			kind:   "aws.lambda_function",
			assert: func(t *testing.T, event *cerebrov1.EventEnvelope) {
				if got := event.Attributes["role_name"]; got != "LambdaOrdersRole" {
					t.Fatalf("lambda role_name = %q, want LambdaOrdersRole", got)
				}
			},
		},
		{
			family: familyECSService,
			kind:   "aws.ecs_service",
			assert: func(t *testing.T, event *cerebrov1.EventEnvelope) {
				if got := event.Attributes["task_definition_arn"]; got != taskDefinitionARN {
					t.Fatalf("ecs service task_definition_arn = %q, want %q", got, taskDefinitionARN)
				}
			},
		},
		{
			family: familyECSTask,
			kind:   "aws.ecs_task",
			assert: func(t *testing.T, event *cerebrov1.EventEnvelope) {
				if got := event.Attributes["launch_type"]; got != "FARGATE" {
					t.Fatalf("ecs task launch_type = %q, want FARGATE", got)
				}
				if got := event.Attributes["network_interface_ids"]; got != "eni-task" {
					t.Fatalf("ecs task network_interface_ids = %q, want eni-task", got)
				}
			},
		},
		{
			family: familyECSTaskDefinition,
			kind:   "aws.ecs_task_definition",
			assert: func(t *testing.T, event *cerebrov1.EventEnvelope) {
				if got := event.Attributes["task_role_name"]; got != "ECSTaskRole" {
					t.Fatalf("ecs task task_role_name = %q, want ECSTaskRole", got)
				}
			},
		},
		{
			family: familyEKSCluster,
			kind:   "aws.eks_cluster",
			assert: func(t *testing.T, event *cerebrov1.EventEnvelope) {
				if got := event.Attributes["endpoint_public_access"]; got != "true" {
					t.Fatalf("eks cluster endpoint_public_access = %q, want true", got)
				}
				if got := event.Attributes["role_name"]; got != "EKSClusterRole" {
					t.Fatalf("eks cluster role_name = %q, want EKSClusterRole", got)
				}
			},
		},
		{
			family: familyEKSNodegroup,
			kind:   "aws.eks_nodegroup",
			assert: func(t *testing.T, event *cerebrov1.EventEnvelope) {
				if got := event.Attributes["role_name"]; got != "EKSNodeRole" {
					t.Fatalf("eks nodegroup role_name = %q, want EKSNodeRole", got)
				}
			},
		},
		{
			family: familyEKSFargateProfile,
			kind:   "aws.eks_fargate_profile",
			assert: func(t *testing.T, event *cerebrov1.EventEnvelope) {
				if got := event.Attributes["selector_namespaces"]; got != "payments" {
					t.Fatalf("eks fargate selector_namespaces = %q, want payments", got)
				}
			},
		},
		{
			family: familyEKSPodIdentity,
			kind:   "aws.eks_pod_identity_association",
			assert: func(t *testing.T, event *cerebrov1.EventEnvelope) {
				if got := event.Attributes["role_name"]; got != "EKSPaymentsPodRole" {
					t.Fatalf("eks pod identity role_name = %q, want EKSPaymentsPodRole", got)
				}
				if got := event.Attributes["service_account"]; got != "api" {
					t.Fatalf("eks pod identity service_account = %q, want api", got)
				}
			},
		},
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
			tt.assert(t, pull.Events[0])
		})
	}
}

func TestReadAWSCloudAssetInventoryEvents(t *testing.T) {
	rdsARN := "arn:aws:rds:us-east-1:123456789012:db:orders-db"
	kmsARN := "arn:aws:kms:us-east-1:123456789012:key/key-123"
	secretARN := "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/api-key-AbCd"
	sqsARN := "arn:aws:sqs:us-east-1:123456789012:orders"
	sqsURL := "https://sqs.us-east-1.amazonaws.com/123456789012/orders"
	snsARN := "arn:aws:sns:us-east-1:123456789012:orders"
	ecrARN := "arn:aws:ecr:us-east-1:123456789012:repository/orders"
	source := newTestSource(t, fakeAWS{
		s3Buckets: []s3types.Bucket{{
			Name:         awssdk.String("prod-data"),
			CreationDate: timePtr("2026-04-23T00:00:00Z"),
		}},
		s3BucketRegions: map[string]s3types.BucketLocationConstraint{"prod-data": ""},
		s3Tags:          map[string][]s3types.Tag{"prod-data": {{Key: awssdk.String("Owner"), Value: awssdk.String("data@writer.com")}}},
		s3Encryption: map[string]*s3types.ServerSideEncryptionConfiguration{"prod-data": {
			Rules: []s3types.ServerSideEncryptionRule{{
				ApplyServerSideEncryptionByDefault: &s3types.ServerSideEncryptionByDefault{
					SSEAlgorithm:   s3types.ServerSideEncryptionAwsKms,
					KMSMasterKeyID: awssdk.String(kmsARN),
				},
			}},
		}},
		s3Versioning: map[string]s3types.BucketVersioningStatus{"prod-data": s3types.BucketVersioningStatusEnabled},
		s3Logging:    map[string]bool{"prod-data": true},
		s3PublicAccessBlocks: map[string]*s3types.PublicAccessBlockConfiguration{"prod-data": {
			BlockPublicAcls:       awssdk.Bool(true),
			BlockPublicPolicy:     awssdk.Bool(true),
			IgnorePublicAcls:      awssdk.Bool(true),
			RestrictPublicBuckets: awssdk.Bool(true),
		}},
		rdsInstances: []rdstypes.DBInstance{{
			DBInstanceArn:         awssdk.String(rdsARN),
			DBInstanceIdentifier:  awssdk.String("orders-db"),
			Engine:                awssdk.String("postgres"),
			StorageEncrypted:      awssdk.Bool(true),
			KmsKeyId:              awssdk.String(kmsARN),
			DeletionProtection:    awssdk.Bool(true),
			BackupRetentionPeriod: awssdk.Int32(7),
			PubliclyAccessible:    awssdk.Bool(false),
			InstanceCreateTime:    timePtr("2026-04-23T00:00:00Z"),
			TagList:               []rdstypes.Tag{{Key: awssdk.String("Owner"), Value: awssdk.String("database@writer.com")}},
		}},
		kmsKeys: []kmstypes.KeyMetadata{{
			Arn:          awssdk.String(kmsARN),
			KeyId:        awssdk.String("key-123"),
			CreationDate: timePtr("2026-04-23T00:00:00Z"),
			Enabled:      true,
			KeyManager:   kmstypes.KeyManagerTypeCustomer,
			KeyState:     kmstypes.KeyStateEnabled,
			KeySpec:      kmstypes.KeySpecSymmetricDefault,
			KeyUsage:     kmstypes.KeyUsageTypeEncryptDecrypt,
			Origin:       kmstypes.OriginTypeAwsKms,
		}},
		kmsTags:     map[string][]kmstypes.Tag{"key-123": {{TagKey: awssdk.String("Owner"), TagValue: awssdk.String("security@writer.com")}}},
		kmsRotation: map[string]bool{"key-123": true},
		secrets: []secretsmanagertypes.SecretListEntry{{
			ARN:             awssdk.String(secretARN),
			Name:            awssdk.String("prod/api-key"),
			CreatedDate:     timePtr("2026-04-23T00:00:00Z"),
			KmsKeyId:        awssdk.String(kmsARN),
			RotationEnabled: awssdk.Bool(true),
			Tags:            []secretsmanagertypes.Tag{{Key: awssdk.String("Owner"), Value: awssdk.String("platform@writer.com")}},
		}},
		sqsQueueURLs: []string{sqsURL},
		sqsAttributes: map[string]map[string]string{sqsURL: {
			"QueueArn":               sqsARN,
			"KmsMasterKeyId":         kmsARN,
			"MessageRetentionPeriod": "1209600",
			"CreatedTimestamp":       "1776902400",
		}},
		sqsTags:   map[string]map[string]string{sqsURL: {"Team": "payments"}},
		snsTopics: []snstypes.Topic{{TopicArn: awssdk.String(snsARN)}},
		snsAttributes: map[string]map[string]string{snsARN: {
			"TopicArn":       snsARN,
			"KmsMasterKeyId": kmsARN,
		}},
		snsTags: map[string][]snstypes.Tag{snsARN: {{Key: awssdk.String("Team"), Value: awssdk.String("payments")}}},
		ecrRepositories: []ecrtypes.Repository{{
			RepositoryArn:  awssdk.String(ecrARN),
			RepositoryName: awssdk.String("orders"),
			RepositoryUri:  awssdk.String("123456789012.dkr.ecr.us-east-1.amazonaws.com/orders"),
			CreatedAt:      timePtr("2026-04-23T00:00:00Z"),
			EncryptionConfiguration: &ecrtypes.EncryptionConfiguration{
				EncryptionType: ecrtypes.EncryptionTypeKms,
				KmsKey:         awssdk.String(kmsARN),
			},
			ImageScanningConfiguration: &ecrtypes.ImageScanningConfiguration{ScanOnPush: true},
			ImageTagMutability:         ecrtypes.ImageTagMutabilityImmutable,
		}},
		ecrTags: map[string][]ecrtypes.Tag{ecrARN: {{Key: awssdk.String("Team"), Value: awssdk.String("payments")}}},
	})
	for _, tt := range []struct {
		family string
		kind   string
		attr   string
		want   string
	}{
		{family: familyS3Bucket, kind: "aws.s3_bucket", attr: "versioning", want: "Enabled"},
		{family: familyRDSInstance, kind: "aws.rds_instance", attr: "deletion_protection", want: "true"},
		{family: familyKMSKey, kind: "aws.kms_key", attr: "rotation", want: "true"},
		{family: familySecret, kind: "aws.secret", attr: "rotation", want: "true"},
		{family: familySQSQueue, kind: "aws.sqs_queue", attr: "encryption", want: "true"},
		{family: familySNSTopic, kind: "aws.sns_topic", attr: "encryption", want: "true"},
		{family: familyECRRepository, kind: "aws.ecr_repository", attr: "scan_on_push", want: "true"},
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

func TestReadAWSAssetMetadataRestartsExpiredPaginationToken(t *testing.T) {
	var tokens []string
	source := newTestSource(t, fakeAWS{getResources: func(_ context.Context, input *resourcegroupstaggingapi.GetResourcesInput, _ ...func(*resourcegroupstaggingapi.Options)) (*resourcegroupstaggingapi.GetResourcesOutput, error) {
		token := awssdk.ToString(input.PaginationToken)
		tokens = append(tokens, token)
		if token == "expired-token" {
			return nil, &resourcegroupstaggingapitypes.PaginationTokenExpiredException{}
		}
		return &resourcegroupstaggingapi.GetResourcesOutput{ResourceTagMappingList: []resourcegroupstaggingapitypes.ResourceTagMapping{{
			ResourceARN: awssdk.String("arn:aws:s3:::prod-data"),
		}}}, nil
	}})

	pull, err := source.Read(
		context.Background(),
		sourcecdk.NewConfig(map[string]string{"account_id": "123456789012", "family": familyAssetMetadata}),
		&cerebrov1.SourceCursor{Opaque: "expired-token"},
	)
	if err != nil {
		t.Fatalf("Read(asset_metadata expired cursor) error = %v", err)
	}
	if len(tokens) != 2 || tokens[0] != "expired-token" || tokens[1] != "" {
		t.Fatalf("GetResources tokens = %#v, want expired token then restart without token", tokens)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(pull.Events))
	}
	if got := pull.Events[0].Attributes["resource_id"]; got != "arn:aws:s3:::prod-data" {
		t.Fatalf("resource_id = %q, want arn:aws:s3:::prod-data", got)
	}
}

func TestReadAWSCloudTrailRestartsInvalidNextToken(t *testing.T) {
	var inputs []cloudtrail.LookupEventsInput
	source := newTestSource(t, fakeAWS{cloudTrailLookup: func(_ context.Context, input *cloudtrail.LookupEventsInput) (*cloudtrail.LookupEventsOutput, error) {
		inputs = append(inputs, *input)
		switch {
		case len(inputs) == 1:
			return &cloudtrail.LookupEventsOutput{NextToken: awssdk.String("token-1")}, nil
		case awssdk.ToString(input.NextToken) == "token-1":
			return nil, &cloudtrailtypes.InvalidNextTokenException{}
		default:
			return &cloudtrail.LookupEventsOutput{Events: []cloudtrailtypes.Event{{
				EventId: awssdk.String("evt-1"), EventName: awssdk.String("AttachUserPolicy"), EventTime: timePtr("2026-04-23T00:00:00Z"),
			}}}, nil
		}
	}})
	config := sourcecdk.NewConfig(map[string]string{"account_id": "123456789012", "family": familyCloudTrail, "since": "PT2H"})

	first, err := source.Read(context.Background(), config, nil)
	if err != nil {
		t.Fatalf("Read(cloudtrail first) error = %v", err)
	}
	if first.NextCursor == nil {
		t.Fatal("first.NextCursor = nil, want resumable cursor")
	}

	second, err := source.Read(context.Background(), config, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(cloudtrail resume) error = %v", err)
	}

	if len(inputs) != 3 {
		t.Fatalf("LookupEvents calls = %d, want 3 (first, stale resume, restart)", len(inputs))
	}
	if got := awssdk.ToString(inputs[1].NextToken); got != "token-1" {
		t.Fatalf("resume NextToken = %q, want token-1", got)
	}
	if inputs[2].NextToken != nil {
		t.Fatalf("restart NextToken = %q, want nil after stale-token recovery", awssdk.ToString(inputs[2].NextToken))
	}
	if inputs[2].StartTime == nil {
		t.Fatal("restart StartTime = nil, want preserved lookup window")
	}
	if len(second.Events) != 1 {
		t.Fatalf("resume events = %d, want 1 after restart", len(second.Events))
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
	computeData := func(fake *recordingAWS) {
		profileARN := "arn:aws:iam::123456789012:instance-profile/WebProfile"
		taskDefinitionARN := "arn:aws:ecs:us-east-1:123456789012:task-definition/orders:7"
		taskARN := "arn:aws:ecs:us-east-1:123456789012:task/prod/abcd1234"
		serviceARN := "arn:aws:ecs:us-east-1:123456789012:service/prod/orders"
		clusterARN := "arn:aws:ecs:us-east-1:123456789012:cluster/prod"
		eksClusterName := "prod-eks"
		eksClusterARN := "arn:aws:eks:us-east-1:123456789012:cluster/prod-eks"
		fake.compute.instances = []ec2types.Instance{{InstanceId: awssdk.String("i-123"), IamInstanceProfile: &ec2types.IamInstanceProfile{Arn: awssdk.String(profileARN)}}}
		fake.compute.instanceProfiles = map[string]iamtypes.InstanceProfile{"WebProfile": {Roles: []iamtypes.Role{{Arn: awssdk.String("arn:aws:iam::123456789012:role/WebInstanceRole"), RoleName: awssdk.String("WebInstanceRole")}}}}
		fake.compute.lambdaFunctions = []lambdatypes.FunctionConfiguration{{FunctionArn: awssdk.String("arn:aws:lambda:us-east-1:123456789012:function:orders"), FunctionName: awssdk.String("orders"), Role: awssdk.String("arn:aws:iam::123456789012:role/LambdaOrdersRole")}}
		fake.compute.ecsClusters = []string{clusterARN}
		fake.compute.ecsServiceARNs = map[string][]string{clusterARN: []string{serviceARN}}
		fake.compute.ecsServices = map[string]ecstypes.Service{serviceARN: {ClusterArn: awssdk.String(clusterARN), ServiceArn: awssdk.String(serviceARN), TaskDefinition: awssdk.String(taskDefinitionARN)}}
		fake.compute.ecsTaskARNs = map[string][]string{clusterARN: []string{taskARN}}
		fake.compute.ecsTasks = map[string]ecstypes.Task{taskARN: {ClusterArn: awssdk.String(clusterARN), TaskArn: awssdk.String(taskARN), TaskDefinitionArn: awssdk.String(taskDefinitionARN)}}
		fake.compute.ecsTaskDefinitionARNs = []string{taskDefinitionARN}
		fake.compute.ecsTaskDefinitions = map[string]ecstypes.TaskDefinition{taskDefinitionARN: {TaskDefinitionArn: awssdk.String(taskDefinitionARN), TaskRoleArn: awssdk.String("arn:aws:iam::123456789012:role/ECSTaskRole")}}
		fake.compute.eksClusters = []ekstypes.Cluster{{Arn: awssdk.String(eksClusterARN), Name: awssdk.String(eksClusterName), Status: ekstypes.ClusterStatusActive}}
		fake.compute.eksNodegroupNames = map[string][]string{eksClusterName: []string{"managed-linux"}}
		fake.compute.eksNodegroups = map[string]ekstypes.Nodegroup{awsTestEKSChildKey(eksClusterName, "managed-linux"): {ClusterName: awssdk.String(eksClusterName), NodegroupArn: awssdk.String("arn:aws:eks:us-east-1:123456789012:nodegroup/prod-eks/managed-linux/uuid"), NodegroupName: awssdk.String("managed-linux"), NodeRole: awssdk.String("arn:aws:iam::123456789012:role/EKSNodeRole")}}
		fake.compute.eksFargateNames = map[string][]string{eksClusterName: []string{"payments"}}
		fake.compute.eksFargateProfiles = map[string]ekstypes.FargateProfile{awsTestEKSChildKey(eksClusterName, "payments"): {ClusterName: awssdk.String(eksClusterName), FargateProfileArn: awssdk.String("arn:aws:eks:us-east-1:123456789012:fargateprofile/prod-eks/payments/uuid"), FargateProfileName: awssdk.String("payments"), PodExecutionRoleArn: awssdk.String("arn:aws:iam::123456789012:role/EKSFargatePodExecutionRole")}}
		fake.compute.eksPodIdentityIDs = map[string][]string{eksClusterName: []string{"a-123"}}
		fake.compute.eksPodIdentities = map[string]ekstypes.PodIdentityAssociation{awsTestEKSChildKey(eksClusterName, "a-123"): {AssociationArn: awssdk.String("arn:aws:eks:us-east-1:123456789012:podidentityassociation/prod-eks/a-123"), AssociationId: awssdk.String("a-123"), ClusterName: awssdk.String(eksClusterName), Namespace: awssdk.String("payments"), RoleArn: awssdk.String("arn:aws:iam::123456789012:role/EKSPaymentsPodRole"), ServiceAccount: awssdk.String("api")}}
	}
	cloudAssetData := func(fake *recordingAWS) {
		kmsARN := "arn:aws:kms:us-east-1:123456789012:key/key-123"
		sqsURL := "https://sqs.us-east-1.amazonaws.com/123456789012/orders"
		snsARN := "arn:aws:sns:us-east-1:123456789012:orders"
		ecrARN := "arn:aws:ecr:us-east-1:123456789012:repository/orders"
		fake.s3Buckets = []s3types.Bucket{{Name: awssdk.String("prod-data")}}
		fake.s3Tags = map[string][]s3types.Tag{"prod-data": {{Key: awssdk.String("Owner"), Value: awssdk.String("data@writer.com")}}}
		fake.s3Encryption = map[string]*s3types.ServerSideEncryptionConfiguration{"prod-data": {}}
		fake.s3Versioning = map[string]s3types.BucketVersioningStatus{"prod-data": s3types.BucketVersioningStatusEnabled}
		fake.s3PublicAccessBlocks = map[string]*s3types.PublicAccessBlockConfiguration{"prod-data": {}}
		fake.rdsInstances = []rdstypes.DBInstance{{DBInstanceArn: awssdk.String("arn:aws:rds:us-east-1:123456789012:db:orders-db"), DBInstanceIdentifier: awssdk.String("orders-db")}}
		fake.kmsKeys = []kmstypes.KeyMetadata{{Arn: awssdk.String(kmsARN), KeyId: awssdk.String("key-123")}}
		fake.kmsTags = map[string][]kmstypes.Tag{"key-123": {{TagKey: awssdk.String("Owner"), TagValue: awssdk.String("security@writer.com")}}}
		fake.kmsRotation = map[string]bool{"key-123": true}
		fake.secrets = []secretsmanagertypes.SecretListEntry{{ARN: awssdk.String("arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/api-key-AbCd"), Name: awssdk.String("prod/api-key")}}
		fake.sqsQueueURLs = []string{sqsURL}
		fake.sqsAttributes = map[string]map[string]string{sqsURL: {"QueueArn": "arn:aws:sqs:us-east-1:123456789012:orders"}}
		fake.sqsTags = map[string]map[string]string{sqsURL: {"Team": "payments"}}
		fake.snsTopics = []snstypes.Topic{{TopicArn: awssdk.String(snsARN)}}
		fake.snsAttributes = map[string]map[string]string{snsARN: {"TopicArn": snsARN}}
		fake.snsTags = map[string][]snstypes.Tag{snsARN: {{Key: awssdk.String("Team"), Value: awssdk.String("payments")}}}
		fake.ecrRepositories = []ecrtypes.Repository{{RepositoryArn: awssdk.String(ecrARN), RepositoryName: awssdk.String("orders")}}
		fake.ecrTags = map[string][]ecrtypes.Tag{ecrARN: {{Key: awssdk.String("Team"), Value: awssdk.String("payments")}}}
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
			family:  familyEC2Instance,
			seed:    computeData,
			wantAPI: []string{"ec2:DescribeInstances", "iam:GetInstanceProfile"},
		},
		{
			family:  familyS3Bucket,
			seed:    cloudAssetData,
			wantAPI: []string{"s3:GetBucketEncryption", "s3:GetBucketLocation", "s3:GetBucketLogging", "s3:GetBucketTagging", "s3:GetBucketVersioning", "s3:GetPublicAccessBlock", "s3:ListBuckets"},
		},
		{
			family:  familyRDSInstance,
			seed:    cloudAssetData,
			wantAPI: []string{"rds:DescribeDBInstances"},
		},
		{
			family:  familyKMSKey,
			seed:    cloudAssetData,
			wantAPI: []string{"kms:DescribeKey", "kms:GetKeyRotationStatus", "kms:ListKeys", "kms:ListResourceTags"},
		},
		{
			family:  familySecret,
			seed:    cloudAssetData,
			wantAPI: []string{"secretsmanager:ListSecrets"},
		},
		{
			family:  familySQSQueue,
			seed:    cloudAssetData,
			wantAPI: []string{"sqs:GetQueueAttributes", "sqs:ListQueueTags", "sqs:ListQueues"},
		},
		{
			family:  familySNSTopic,
			seed:    cloudAssetData,
			wantAPI: []string{"sns:GetTopicAttributes", "sns:ListTagsForResource", "sns:ListTopics"},
		},
		{
			family:  familyECRRepository,
			seed:    cloudAssetData,
			wantAPI: []string{"ecr:DescribeRepositories", "ecr:ListTagsForResource"},
		},
		{
			family:  familyECSService,
			seed:    computeData,
			wantAPI: []string{"ecs:DescribeServices", "ecs:ListClusters", "ecs:ListServices"},
		},
		{
			family:  familyECSTask,
			seed:    computeData,
			wantAPI: []string{"ecs:DescribeTasks", "ecs:ListClusters", "ecs:ListTasks"},
		},
		{
			family:  familyECSTaskDefinition,
			seed:    computeData,
			wantAPI: []string{"ecs:DescribeTaskDefinition", "ecs:ListTaskDefinitions"},
		},
		{
			family:  familyEKSCluster,
			seed:    computeData,
			wantAPI: []string{"eks:DescribeCluster", "eks:ListClusters"},
		},
		{
			family:  familyEKSNodegroup,
			seed:    computeData,
			wantAPI: []string{"eks:DescribeNodegroup", "eks:ListClusters", "eks:ListNodegroups"},
		},
		{
			family:  familyEKSFargateProfile,
			seed:    computeData,
			wantAPI: []string{"eks:DescribeFargateProfile", "eks:ListClusters", "eks:ListFargateProfiles"},
		},
		{
			family:  familyEKSPodIdentity,
			seed:    computeData,
			wantAPI: []string{"eks:DescribePodIdentityAssociation", "eks:ListClusters", "eks:ListPodIdentityAssociations"},
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
			family:  familyLambdaFunction,
			seed:    computeData,
			wantAPI: []string{"lambda:ListFunctions"},
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
		return awsClients{iam: fake, cloudTrail: fake, ec2: fake, route53: fake, cloudFront: fake, elbv2: fake, ecs: fake, eks: fakeEKS{compute: fake.compute}, ecr: fakeECR{fake: &fake}, apiGateway: fake, apiGatewayV2: fakeAPIGatewayV2{domains: fake.apiV2Domains, apis: fake.apiV2APIs}, lambda: fake, tagging: fake, s3: fake, rds: fake, kms: fake, secrets: fake, sqs: fake, sns: fakeSNS{fake: &fake}}, nil
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
		return awsClients{iam: fake, cloudTrail: fake, ec2: fake, route53: fake, cloudFront: fake, elbv2: fake, ecs: fake, eks: recordingEKS{fake: fake}, ecr: recordingECR{fake: fake}, apiGateway: fake, apiGatewayV2: recordingAPIGatewayV2{fake: fake}, lambda: fake, tagging: fake, s3: fake, rds: fake, kms: fake, secrets: fake, sqs: fake, sns: recordingSNS{fake: fake}}, nil
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
	compute                fakeAWSCompute
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
	getResources           func(context.Context, *resourcegroupstaggingapi.GetResourcesInput, ...func(*resourcegroupstaggingapi.Options)) (*resourcegroupstaggingapi.GetResourcesOutput, error)
	s3Buckets              []s3types.Bucket
	s3BucketRegions        map[string]s3types.BucketLocationConstraint
	s3Tags                 map[string][]s3types.Tag
	s3Encryption           map[string]*s3types.ServerSideEncryptionConfiguration
	s3Versioning           map[string]s3types.BucketVersioningStatus
	s3Logging              map[string]bool
	s3PublicAccessBlocks   map[string]*s3types.PublicAccessBlockConfiguration
	rdsInstances           []rdstypes.DBInstance
	kmsKeys                []kmstypes.KeyMetadata
	kmsTags                map[string][]kmstypes.Tag
	kmsRotation            map[string]bool
	secrets                []secretsmanagertypes.SecretListEntry
	sqsQueueURLs           []string
	sqsAttributes          map[string]map[string]string
	sqsTags                map[string]map[string]string
	snsTopics              []snstypes.Topic
	snsAttributes          map[string]map[string]string
	snsTags                map[string][]snstypes.Tag
	ecrRepositories        []ecrtypes.Repository
	ecrTags                map[string][]ecrtypes.Tag
}

type fakeAWSCompute struct {
	instances             []ec2types.Instance
	instanceProfiles      map[string]iamtypes.InstanceProfile
	lambdaFunctions       []lambdatypes.FunctionConfiguration
	ecsClusters           []string
	ecsServiceARNs        map[string][]string
	ecsServices           map[string]ecstypes.Service
	ecsTaskARNs           map[string][]string
	ecsTasks              map[string]ecstypes.Task
	ecsTaskDefinitionARNs []string
	ecsTaskDefinitions    map[string]ecstypes.TaskDefinition
	eksClusters           []ekstypes.Cluster
	eksNodegroupNames     map[string][]string
	eksNodegroups         map[string]ekstypes.Nodegroup
	eksFargateNames       map[string][]string
	eksFargateProfiles    map[string]ekstypes.FargateProfile
	eksPodIdentityIDs     map[string][]string
	eksPodIdentities      map[string]ekstypes.PodIdentityAssociation
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

func (f *recordingAWS) GetInstanceProfile(ctx context.Context, input *iam.GetInstanceProfileInput, options ...func(*iam.Options)) (*iam.GetInstanceProfileOutput, error) {
	f.record("iam:GetInstanceProfile")
	return f.fakeAWS.GetInstanceProfile(ctx, input, options...)
}

func (f *recordingAWS) LookupEvents(ctx context.Context, input *cloudtrail.LookupEventsInput, options ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
	f.record("cloudtrail:LookupEvents")
	return f.fakeAWS.LookupEvents(ctx, input, options...)
}

func (f *recordingAWS) DescribeSecurityGroups(ctx context.Context, input *ec2.DescribeSecurityGroupsInput, options ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	f.record("ec2:DescribeSecurityGroups")
	return f.fakeAWS.DescribeSecurityGroups(ctx, input, options...)
}

func (f *recordingAWS) DescribeInstances(ctx context.Context, input *ec2.DescribeInstancesInput, options ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	f.record("ec2:DescribeInstances")
	return f.fakeAWS.DescribeInstances(ctx, input, options...)
}

func (f *recordingAWS) DescribeAddresses(ctx context.Context, input *ec2.DescribeAddressesInput, options ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
	f.record("ec2:DescribeAddresses")
	return f.fakeAWS.DescribeAddresses(ctx, input, options...)
}

func (f *recordingAWS) DescribeNetworkInterfaces(ctx context.Context, input *ec2.DescribeNetworkInterfacesInput, options ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
	f.record("ec2:DescribeNetworkInterfaces")
	return f.fakeAWS.DescribeNetworkInterfaces(ctx, input, options...)
}

func (f *recordingAWS) ListFunctions(ctx context.Context, input *lambda.ListFunctionsInput, options ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
	f.record("lambda:ListFunctions")
	return f.fakeAWS.ListFunctions(ctx, input, options...)
}

func (f *recordingAWS) ListClusters(ctx context.Context, input *ecs.ListClustersInput, options ...func(*ecs.Options)) (*ecs.ListClustersOutput, error) {
	f.record("ecs:ListClusters")
	return f.fakeAWS.ListClusters(ctx, input, options...)
}

func (f *recordingAWS) ListServices(ctx context.Context, input *ecs.ListServicesInput, options ...func(*ecs.Options)) (*ecs.ListServicesOutput, error) {
	f.record("ecs:ListServices")
	return f.fakeAWS.ListServices(ctx, input, options...)
}

func (f *recordingAWS) DescribeServices(ctx context.Context, input *ecs.DescribeServicesInput, options ...func(*ecs.Options)) (*ecs.DescribeServicesOutput, error) {
	f.record("ecs:DescribeServices")
	return f.fakeAWS.DescribeServices(ctx, input, options...)
}

func (f *recordingAWS) ListTasks(ctx context.Context, input *ecs.ListTasksInput, options ...func(*ecs.Options)) (*ecs.ListTasksOutput, error) {
	f.record("ecs:ListTasks")
	return f.fakeAWS.ListTasks(ctx, input, options...)
}

func (f *recordingAWS) DescribeTasks(ctx context.Context, input *ecs.DescribeTasksInput, options ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error) {
	f.record("ecs:DescribeTasks")
	return f.fakeAWS.DescribeTasks(ctx, input, options...)
}

func (f *recordingAWS) ListTaskDefinitions(ctx context.Context, input *ecs.ListTaskDefinitionsInput, options ...func(*ecs.Options)) (*ecs.ListTaskDefinitionsOutput, error) {
	f.record("ecs:ListTaskDefinitions")
	return f.fakeAWS.ListTaskDefinitions(ctx, input, options...)
}

func (f *recordingAWS) DescribeTaskDefinition(ctx context.Context, input *ecs.DescribeTaskDefinitionInput, options ...func(*ecs.Options)) (*ecs.DescribeTaskDefinitionOutput, error) {
	f.record("ecs:DescribeTaskDefinition")
	return f.fakeAWS.DescribeTaskDefinition(ctx, input, options...)
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

func (f *recordingAWS) ListBuckets(ctx context.Context, input *s3.ListBucketsInput, options ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	f.record("s3:ListBuckets")
	return f.fakeAWS.ListBuckets(ctx, input, options...)
}

func (f *recordingAWS) GetBucketLocation(ctx context.Context, input *s3.GetBucketLocationInput, options ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error) {
	f.record("s3:GetBucketLocation")
	return f.fakeAWS.GetBucketLocation(ctx, input, options...)
}

func (f *recordingAWS) GetBucketTagging(ctx context.Context, input *s3.GetBucketTaggingInput, options ...func(*s3.Options)) (*s3.GetBucketTaggingOutput, error) {
	f.record("s3:GetBucketTagging")
	return f.fakeAWS.GetBucketTagging(ctx, input, options...)
}

func (f *recordingAWS) GetBucketEncryption(ctx context.Context, input *s3.GetBucketEncryptionInput, options ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error) {
	f.record("s3:GetBucketEncryption")
	return f.fakeAWS.GetBucketEncryption(ctx, input, options...)
}

func (f *recordingAWS) GetBucketVersioning(ctx context.Context, input *s3.GetBucketVersioningInput, options ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error) {
	f.record("s3:GetBucketVersioning")
	return f.fakeAWS.GetBucketVersioning(ctx, input, options...)
}

func (f *recordingAWS) GetBucketLogging(ctx context.Context, input *s3.GetBucketLoggingInput, options ...func(*s3.Options)) (*s3.GetBucketLoggingOutput, error) {
	f.record("s3:GetBucketLogging")
	return f.fakeAWS.GetBucketLogging(ctx, input, options...)
}

func (f *recordingAWS) GetPublicAccessBlock(ctx context.Context, input *s3.GetPublicAccessBlockInput, options ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
	f.record("s3:GetPublicAccessBlock")
	return f.fakeAWS.GetPublicAccessBlock(ctx, input, options...)
}

func (f *recordingAWS) DescribeDBInstances(ctx context.Context, input *rds.DescribeDBInstancesInput, options ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error) {
	f.record("rds:DescribeDBInstances")
	return f.fakeAWS.DescribeDBInstances(ctx, input, options...)
}

func (f *recordingAWS) ListKeys(ctx context.Context, input *kms.ListKeysInput, options ...func(*kms.Options)) (*kms.ListKeysOutput, error) {
	f.record("kms:ListKeys")
	return f.fakeAWS.ListKeys(ctx, input, options...)
}

func (f *recordingAWS) DescribeKey(ctx context.Context, input *kms.DescribeKeyInput, options ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	f.record("kms:DescribeKey")
	return f.fakeAWS.DescribeKey(ctx, input, options...)
}

func (f *recordingAWS) ListResourceTags(ctx context.Context, input *kms.ListResourceTagsInput, options ...func(*kms.Options)) (*kms.ListResourceTagsOutput, error) {
	f.record("kms:ListResourceTags")
	return f.fakeAWS.ListResourceTags(ctx, input, options...)
}

func (f *recordingAWS) GetKeyRotationStatus(ctx context.Context, input *kms.GetKeyRotationStatusInput, options ...func(*kms.Options)) (*kms.GetKeyRotationStatusOutput, error) {
	f.record("kms:GetKeyRotationStatus")
	return f.fakeAWS.GetKeyRotationStatus(ctx, input, options...)
}

func (f *recordingAWS) ListSecrets(ctx context.Context, input *secretsmanager.ListSecretsInput, options ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error) {
	f.record("secretsmanager:ListSecrets")
	return f.fakeAWS.ListSecrets(ctx, input, options...)
}

func (f *recordingAWS) ListQueues(ctx context.Context, input *sqs.ListQueuesInput, options ...func(*sqs.Options)) (*sqs.ListQueuesOutput, error) {
	f.record("sqs:ListQueues")
	return f.fakeAWS.ListQueues(ctx, input, options...)
}

func (f *recordingAWS) GetQueueAttributes(ctx context.Context, input *sqs.GetQueueAttributesInput, options ...func(*sqs.Options)) (*sqs.GetQueueAttributesOutput, error) {
	f.record("sqs:GetQueueAttributes")
	return f.fakeAWS.GetQueueAttributes(ctx, input, options...)
}

func (f *recordingAWS) ListQueueTags(ctx context.Context, input *sqs.ListQueueTagsInput, options ...func(*sqs.Options)) (*sqs.ListQueueTagsOutput, error) {
	f.record("sqs:ListQueueTags")
	return f.fakeAWS.ListQueueTags(ctx, input, options...)
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

type fakeSNS struct {
	fake *fakeAWS
}

type recordingSNS struct {
	fake *recordingAWS
}

func (f recordingSNS) ListTopics(ctx context.Context, input *sns.ListTopicsInput, options ...func(*sns.Options)) (*sns.ListTopicsOutput, error) {
	f.fake.record("sns:ListTopics")
	return fakeSNS{fake: &f.fake.fakeAWS}.ListTopics(ctx, input, options...)
}

func (f recordingSNS) GetTopicAttributes(ctx context.Context, input *sns.GetTopicAttributesInput, options ...func(*sns.Options)) (*sns.GetTopicAttributesOutput, error) {
	f.fake.record("sns:GetTopicAttributes")
	return fakeSNS{fake: &f.fake.fakeAWS}.GetTopicAttributes(ctx, input, options...)
}

func (f recordingSNS) ListTagsForResource(ctx context.Context, input *sns.ListTagsForResourceInput, options ...func(*sns.Options)) (*sns.ListTagsForResourceOutput, error) {
	f.fake.record("sns:ListTagsForResource")
	return fakeSNS{fake: &f.fake.fakeAWS}.ListTagsForResource(ctx, input, options...)
}

func (f fakeSNS) ListTopics(context.Context, *sns.ListTopicsInput, ...func(*sns.Options)) (*sns.ListTopicsOutput, error) {
	return &sns.ListTopicsOutput{Topics: f.fake.snsTopics}, nil
}

func (f fakeSNS) GetTopicAttributes(_ context.Context, input *sns.GetTopicAttributesInput, _ ...func(*sns.Options)) (*sns.GetTopicAttributesOutput, error) {
	return &sns.GetTopicAttributesOutput{Attributes: f.fake.snsAttributes[awssdk.ToString(input.TopicArn)]}, nil
}

func (f fakeSNS) ListTagsForResource(_ context.Context, input *sns.ListTagsForResourceInput, _ ...func(*sns.Options)) (*sns.ListTagsForResourceOutput, error) {
	return &sns.ListTagsForResourceOutput{Tags: f.fake.snsTags[awssdk.ToString(input.ResourceArn)]}, nil
}

type fakeECR struct {
	fake *fakeAWS
}

type recordingECR struct {
	fake *recordingAWS
}

func (f recordingECR) DescribeRepositories(ctx context.Context, input *ecr.DescribeRepositoriesInput, options ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error) {
	f.fake.record("ecr:DescribeRepositories")
	return fakeECR{fake: &f.fake.fakeAWS}.DescribeRepositories(ctx, input, options...)
}

func (f recordingECR) ListTagsForResource(ctx context.Context, input *ecr.ListTagsForResourceInput, options ...func(*ecr.Options)) (*ecr.ListTagsForResourceOutput, error) {
	f.fake.record("ecr:ListTagsForResource")
	return fakeECR{fake: &f.fake.fakeAWS}.ListTagsForResource(ctx, input, options...)
}

func (f fakeECR) DescribeRepositories(context.Context, *ecr.DescribeRepositoriesInput, ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error) {
	return &ecr.DescribeRepositoriesOutput{Repositories: f.fake.ecrRepositories}, nil
}

func (f fakeECR) ListTagsForResource(_ context.Context, input *ecr.ListTagsForResourceInput, _ ...func(*ecr.Options)) (*ecr.ListTagsForResourceOutput, error) {
	return &ecr.ListTagsForResourceOutput{Tags: f.fake.ecrTags[awssdk.ToString(input.ResourceArn)]}, nil
}

type fakeEKS struct {
	compute fakeAWSCompute
}

type recordingEKS struct {
	fake *recordingAWS
}

func (f recordingEKS) ListClusters(ctx context.Context, input *eks.ListClustersInput, options ...func(*eks.Options)) (*eks.ListClustersOutput, error) {
	f.fake.record("eks:ListClusters")
	return fakeEKS{compute: f.fake.compute}.ListClusters(ctx, input, options...)
}

func (f recordingEKS) DescribeCluster(ctx context.Context, input *eks.DescribeClusterInput, options ...func(*eks.Options)) (*eks.DescribeClusterOutput, error) {
	f.fake.record("eks:DescribeCluster")
	return fakeEKS{compute: f.fake.compute}.DescribeCluster(ctx, input, options...)
}

func (f recordingEKS) ListNodegroups(ctx context.Context, input *eks.ListNodegroupsInput, options ...func(*eks.Options)) (*eks.ListNodegroupsOutput, error) {
	f.fake.record("eks:ListNodegroups")
	return fakeEKS{compute: f.fake.compute}.ListNodegroups(ctx, input, options...)
}

func (f recordingEKS) DescribeNodegroup(ctx context.Context, input *eks.DescribeNodegroupInput, options ...func(*eks.Options)) (*eks.DescribeNodegroupOutput, error) {
	f.fake.record("eks:DescribeNodegroup")
	return fakeEKS{compute: f.fake.compute}.DescribeNodegroup(ctx, input, options...)
}

func (f recordingEKS) ListFargateProfiles(ctx context.Context, input *eks.ListFargateProfilesInput, options ...func(*eks.Options)) (*eks.ListFargateProfilesOutput, error) {
	f.fake.record("eks:ListFargateProfiles")
	return fakeEKS{compute: f.fake.compute}.ListFargateProfiles(ctx, input, options...)
}

func (f recordingEKS) DescribeFargateProfile(ctx context.Context, input *eks.DescribeFargateProfileInput, options ...func(*eks.Options)) (*eks.DescribeFargateProfileOutput, error) {
	f.fake.record("eks:DescribeFargateProfile")
	return fakeEKS{compute: f.fake.compute}.DescribeFargateProfile(ctx, input, options...)
}

func (f recordingEKS) ListPodIdentityAssociations(ctx context.Context, input *eks.ListPodIdentityAssociationsInput, options ...func(*eks.Options)) (*eks.ListPodIdentityAssociationsOutput, error) {
	f.fake.record("eks:ListPodIdentityAssociations")
	return fakeEKS{compute: f.fake.compute}.ListPodIdentityAssociations(ctx, input, options...)
}

func (f recordingEKS) DescribePodIdentityAssociation(ctx context.Context, input *eks.DescribePodIdentityAssociationInput, options ...func(*eks.Options)) (*eks.DescribePodIdentityAssociationOutput, error) {
	f.fake.record("eks:DescribePodIdentityAssociation")
	return fakeEKS{compute: f.fake.compute}.DescribePodIdentityAssociation(ctx, input, options...)
}

func (f fakeEKS) ListClusters(context.Context, *eks.ListClustersInput, ...func(*eks.Options)) (*eks.ListClustersOutput, error) {
	names := make([]string, 0, len(f.compute.eksClusters))
	for _, cluster := range f.compute.eksClusters {
		name := awssdk.ToString(cluster.Name)
		if name == "" {
			name = pathBase(awssdk.ToString(cluster.Arn))
		}
		if name != "" {
			names = append(names, name)
		}
	}
	return &eks.ListClustersOutput{Clusters: names}, nil
}

func (f fakeEKS) DescribeCluster(_ context.Context, input *eks.DescribeClusterInput, _ ...func(*eks.Options)) (*eks.DescribeClusterOutput, error) {
	name := awssdk.ToString(input.Name)
	for _, cluster := range f.compute.eksClusters {
		if awssdk.ToString(cluster.Name) == name || pathBase(awssdk.ToString(cluster.Arn)) == name {
			copy := cluster
			return &eks.DescribeClusterOutput{Cluster: &copy}, nil
		}
	}
	return &eks.DescribeClusterOutput{}, nil
}

func (f fakeEKS) ListNodegroups(_ context.Context, input *eks.ListNodegroupsInput, _ ...func(*eks.Options)) (*eks.ListNodegroupsOutput, error) {
	if f.compute.eksNodegroupNames == nil {
		return &eks.ListNodegroupsOutput{}, nil
	}
	return &eks.ListNodegroupsOutput{Nodegroups: f.compute.eksNodegroupNames[awssdk.ToString(input.ClusterName)]}, nil
}

func (f fakeEKS) DescribeNodegroup(_ context.Context, input *eks.DescribeNodegroupInput, _ ...func(*eks.Options)) (*eks.DescribeNodegroupOutput, error) {
	if f.compute.eksNodegroups != nil {
		nodegroup := f.compute.eksNodegroups[awsTestEKSChildKey(awssdk.ToString(input.ClusterName), awssdk.ToString(input.NodegroupName))]
		return &eks.DescribeNodegroupOutput{Nodegroup: &nodegroup}, nil
	}
	return &eks.DescribeNodegroupOutput{}, nil
}

func (f fakeEKS) ListFargateProfiles(_ context.Context, input *eks.ListFargateProfilesInput, _ ...func(*eks.Options)) (*eks.ListFargateProfilesOutput, error) {
	if f.compute.eksFargateNames == nil {
		return &eks.ListFargateProfilesOutput{}, nil
	}
	return &eks.ListFargateProfilesOutput{FargateProfileNames: f.compute.eksFargateNames[awssdk.ToString(input.ClusterName)]}, nil
}

func (f fakeEKS) DescribeFargateProfile(_ context.Context, input *eks.DescribeFargateProfileInput, _ ...func(*eks.Options)) (*eks.DescribeFargateProfileOutput, error) {
	if f.compute.eksFargateProfiles != nil {
		profile := f.compute.eksFargateProfiles[awsTestEKSChildKey(awssdk.ToString(input.ClusterName), awssdk.ToString(input.FargateProfileName))]
		return &eks.DescribeFargateProfileOutput{FargateProfile: &profile}, nil
	}
	return &eks.DescribeFargateProfileOutput{}, nil
}

func (f fakeEKS) ListPodIdentityAssociations(_ context.Context, input *eks.ListPodIdentityAssociationsInput, _ ...func(*eks.Options)) (*eks.ListPodIdentityAssociationsOutput, error) {
	ids := f.compute.eksPodIdentityIDs[awssdk.ToString(input.ClusterName)]
	summaries := make([]ekstypes.PodIdentityAssociationSummary, 0, len(ids))
	for _, id := range ids {
		summaries = append(summaries, ekstypes.PodIdentityAssociationSummary{AssociationId: awssdk.String(id), ClusterName: input.ClusterName})
	}
	return &eks.ListPodIdentityAssociationsOutput{Associations: summaries}, nil
}

func (f fakeEKS) DescribePodIdentityAssociation(_ context.Context, input *eks.DescribePodIdentityAssociationInput, _ ...func(*eks.Options)) (*eks.DescribePodIdentityAssociationOutput, error) {
	if f.compute.eksPodIdentities != nil {
		association := f.compute.eksPodIdentities[awsTestEKSChildKey(awssdk.ToString(input.ClusterName), awssdk.ToString(input.AssociationId))]
		return &eks.DescribePodIdentityAssociationOutput{Association: &association}, nil
	}
	return &eks.DescribePodIdentityAssociationOutput{}, nil
}

func awsTestEKSChildKey(clusterName string, childName string) string {
	return clusterName + "/" + childName
}

func pathBase(value string) string {
	index := len(value) - 1
	for index >= 0 && value[index] == '/' {
		index--
	}
	if index < 0 {
		return ""
	}
	start := index
	for start >= 0 && value[start] != '/' {
		start--
	}
	return value[start+1 : index+1]
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

func (f fakeAWS) GetInstanceProfile(_ context.Context, input *iam.GetInstanceProfileInput, _ ...func(*iam.Options)) (*iam.GetInstanceProfileOutput, error) {
	name := awssdk.ToString(input.InstanceProfileName)
	if f.compute.instanceProfiles != nil {
		profile := f.compute.instanceProfiles[name]
		return &iam.GetInstanceProfileOutput{InstanceProfile: &profile}, nil
	}
	return &iam.GetInstanceProfileOutput{InstanceProfile: &iamtypes.InstanceProfile{InstanceProfileName: awssdk.String(name)}}, nil
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

func paginateEC2Instances(values []ec2types.Instance, marker string, limit int) ([]ec2types.Instance, string) {
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

func paginateLambdaFunctions(values []lambdatypes.FunctionConfiguration, marker string, limit int) ([]lambdatypes.FunctionConfiguration, string) {
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

func (f fakeAWS) DescribeInstances(_ context.Context, input *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	instances, next := paginateEC2Instances(f.compute.instances, awssdk.ToString(input.NextToken), int(awssdk.ToInt32(input.MaxResults)))
	return &ec2.DescribeInstancesOutput{Reservations: []ec2types.Reservation{{Instances: instances}}, NextToken: stringPtr(next)}, nil
}

func (f fakeAWS) DescribeAddresses(context.Context, *ec2.DescribeAddressesInput, ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
	return &ec2.DescribeAddressesOutput{Addresses: f.addresses}, nil
}

func (f fakeAWS) DescribeNetworkInterfaces(context.Context, *ec2.DescribeNetworkInterfacesInput, ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
	return &ec2.DescribeNetworkInterfacesOutput{NetworkInterfaces: f.networkInterfaces}, nil
}

func (f fakeAWS) ListFunctions(_ context.Context, input *lambda.ListFunctionsInput, _ ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
	functions, next := paginateLambdaFunctions(f.compute.lambdaFunctions, awssdk.ToString(input.Marker), int(awssdk.ToInt32(input.MaxItems)))
	return &lambda.ListFunctionsOutput{Functions: functions, NextMarker: stringPtr(next)}, nil
}

func (f fakeAWS) ListClusters(context.Context, *ecs.ListClustersInput, ...func(*ecs.Options)) (*ecs.ListClustersOutput, error) {
	return &ecs.ListClustersOutput{ClusterArns: f.compute.ecsClusters}, nil
}

func (f fakeAWS) ListServices(_ context.Context, input *ecs.ListServicesInput, _ ...func(*ecs.Options)) (*ecs.ListServicesOutput, error) {
	if f.compute.ecsServiceARNs == nil {
		return &ecs.ListServicesOutput{}, nil
	}
	return &ecs.ListServicesOutput{ServiceArns: f.compute.ecsServiceARNs[awssdk.ToString(input.Cluster)]}, nil
}

func (f fakeAWS) DescribeServices(_ context.Context, input *ecs.DescribeServicesInput, _ ...func(*ecs.Options)) (*ecs.DescribeServicesOutput, error) {
	services := make([]ecstypes.Service, 0, len(input.Services))
	for _, arn := range input.Services {
		if f.compute.ecsServices != nil {
			services = append(services, f.compute.ecsServices[arn])
		}
	}
	return &ecs.DescribeServicesOutput{Services: services}, nil
}

func (f fakeAWS) ListTasks(_ context.Context, input *ecs.ListTasksInput, _ ...func(*ecs.Options)) (*ecs.ListTasksOutput, error) {
	if f.compute.ecsTaskARNs == nil {
		return &ecs.ListTasksOutput{}, nil
	}
	return &ecs.ListTasksOutput{TaskArns: f.compute.ecsTaskARNs[awssdk.ToString(input.Cluster)]}, nil
}

func (f fakeAWS) DescribeTasks(_ context.Context, input *ecs.DescribeTasksInput, _ ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error) {
	tasks := make([]ecstypes.Task, 0, len(input.Tasks))
	for _, arn := range input.Tasks {
		if f.compute.ecsTasks != nil {
			tasks = append(tasks, f.compute.ecsTasks[arn])
		}
	}
	return &ecs.DescribeTasksOutput{Tasks: tasks}, nil
}

func (f fakeAWS) ListTaskDefinitions(context.Context, *ecs.ListTaskDefinitionsInput, ...func(*ecs.Options)) (*ecs.ListTaskDefinitionsOutput, error) {
	return &ecs.ListTaskDefinitionsOutput{TaskDefinitionArns: f.compute.ecsTaskDefinitionARNs}, nil
}

func (f fakeAWS) DescribeTaskDefinition(_ context.Context, input *ecs.DescribeTaskDefinitionInput, _ ...func(*ecs.Options)) (*ecs.DescribeTaskDefinitionOutput, error) {
	if f.compute.ecsTaskDefinitions != nil {
		task := f.compute.ecsTaskDefinitions[awssdk.ToString(input.TaskDefinition)]
		return &ecs.DescribeTaskDefinitionOutput{TaskDefinition: &task}, nil
	}
	return &ecs.DescribeTaskDefinitionOutput{}, nil
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

func (f fakeAWS) GetResources(ctx context.Context, input *resourcegroupstaggingapi.GetResourcesInput, options ...func(*resourcegroupstaggingapi.Options)) (*resourcegroupstaggingapi.GetResourcesOutput, error) {
	if f.getResources != nil {
		return f.getResources(ctx, input, options...)
	}
	records, next := paginateResourceTags(f.taggedResources, awssdk.ToString(input.PaginationToken), int(awssdk.ToInt32(input.ResourcesPerPage)))
	return &resourcegroupstaggingapi.GetResourcesOutput{ResourceTagMappingList: records, PaginationToken: stringPtr(next)}, nil
}

func (f fakeAWS) ListBuckets(context.Context, *s3.ListBucketsInput, ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	return &s3.ListBucketsOutput{Buckets: f.s3Buckets}, nil
}

func (f fakeAWS) GetBucketLocation(_ context.Context, input *s3.GetBucketLocationInput, _ ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error) {
	return &s3.GetBucketLocationOutput{LocationConstraint: f.s3BucketRegions[awssdk.ToString(input.Bucket)]}, nil
}

func (f fakeAWS) GetBucketTagging(_ context.Context, input *s3.GetBucketTaggingInput, _ ...func(*s3.Options)) (*s3.GetBucketTaggingOutput, error) {
	return &s3.GetBucketTaggingOutput{TagSet: f.s3Tags[awssdk.ToString(input.Bucket)]}, nil
}

func (f fakeAWS) GetBucketEncryption(_ context.Context, input *s3.GetBucketEncryptionInput, _ ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error) {
	return &s3.GetBucketEncryptionOutput{ServerSideEncryptionConfiguration: f.s3Encryption[awssdk.ToString(input.Bucket)]}, nil
}

func (f fakeAWS) GetBucketVersioning(_ context.Context, input *s3.GetBucketVersioningInput, _ ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error) {
	return &s3.GetBucketVersioningOutput{Status: f.s3Versioning[awssdk.ToString(input.Bucket)]}, nil
}

func (f fakeAWS) GetBucketLogging(_ context.Context, input *s3.GetBucketLoggingInput, _ ...func(*s3.Options)) (*s3.GetBucketLoggingOutput, error) {
	if f.s3Logging[awssdk.ToString(input.Bucket)] {
		return &s3.GetBucketLoggingOutput{LoggingEnabled: &s3types.LoggingEnabled{}}, nil
	}
	return &s3.GetBucketLoggingOutput{}, nil
}

func (f fakeAWS) GetPublicAccessBlock(_ context.Context, input *s3.GetPublicAccessBlockInput, _ ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
	return &s3.GetPublicAccessBlockOutput{PublicAccessBlockConfiguration: f.s3PublicAccessBlocks[awssdk.ToString(input.Bucket)]}, nil
}

func (f fakeAWS) DescribeDBInstances(context.Context, *rds.DescribeDBInstancesInput, ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error) {
	return &rds.DescribeDBInstancesOutput{DBInstances: f.rdsInstances}, nil
}

func (f fakeAWS) ListKeys(context.Context, *kms.ListKeysInput, ...func(*kms.Options)) (*kms.ListKeysOutput, error) {
	keys := make([]kmstypes.KeyListEntry, 0, len(f.kmsKeys))
	for _, key := range f.kmsKeys {
		keys = append(keys, kmstypes.KeyListEntry{KeyArn: key.Arn, KeyId: key.KeyId})
	}
	return &kms.ListKeysOutput{Keys: keys}, nil
}

func (f fakeAWS) DescribeKey(_ context.Context, input *kms.DescribeKeyInput, _ ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	keyID := awssdk.ToString(input.KeyId)
	for _, key := range f.kmsKeys {
		if awssdk.ToString(key.KeyId) == keyID || awssdk.ToString(key.Arn) == keyID {
			copy := key
			return &kms.DescribeKeyOutput{KeyMetadata: &copy}, nil
		}
	}
	return &kms.DescribeKeyOutput{}, nil
}

func (f fakeAWS) ListResourceTags(_ context.Context, input *kms.ListResourceTagsInput, _ ...func(*kms.Options)) (*kms.ListResourceTagsOutput, error) {
	return &kms.ListResourceTagsOutput{Tags: f.kmsTags[awssdk.ToString(input.KeyId)]}, nil
}

func (f fakeAWS) GetKeyRotationStatus(_ context.Context, input *kms.GetKeyRotationStatusInput, _ ...func(*kms.Options)) (*kms.GetKeyRotationStatusOutput, error) {
	return &kms.GetKeyRotationStatusOutput{KeyRotationEnabled: f.kmsRotation[awssdk.ToString(input.KeyId)]}, nil
}

func (f fakeAWS) ListSecrets(context.Context, *secretsmanager.ListSecretsInput, ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error) {
	return &secretsmanager.ListSecretsOutput{SecretList: f.secrets}, nil
}

func (f fakeAWS) ListQueues(context.Context, *sqs.ListQueuesInput, ...func(*sqs.Options)) (*sqs.ListQueuesOutput, error) {
	return &sqs.ListQueuesOutput{QueueUrls: f.sqsQueueURLs}, nil
}

func (f fakeAWS) GetQueueAttributes(_ context.Context, input *sqs.GetQueueAttributesInput, _ ...func(*sqs.Options)) (*sqs.GetQueueAttributesOutput, error) {
	return &sqs.GetQueueAttributesOutput{Attributes: f.sqsAttributes[awssdk.ToString(input.QueueUrl)]}, nil
}

func (f fakeAWS) ListQueueTags(_ context.Context, input *sqs.ListQueueTagsInput, _ ...func(*sqs.Options)) (*sqs.ListQueueTagsOutput, error) {
	return &sqs.ListQueueTagsOutput{Tags: f.sqsTags[awssdk.ToString(input.QueueUrl)]}, nil
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
