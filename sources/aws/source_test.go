package aws

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	apigatewaytypes "github.com/aws/aws-sdk-go-v2/service/apigateway/types"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	apigatewayv2types "github.com/aws/aws-sdk-go-v2/service/apigatewayv2/types"
	"github.com/aws/aws-sdk-go-v2/service/apprunner"
	apprunnertypes "github.com/aws/aws-sdk-go-v2/service/apprunner/types"
	"github.com/aws/aws-sdk-go-v2/service/athena"
	athenatypes "github.com/aws/aws-sdk-go-v2/service/athena/types"
	"github.com/aws/aws-sdk-go-v2/service/backup"
	backuptypes "github.com/aws/aws-sdk-go-v2/service/backup/types"
	"github.com/aws/aws-sdk-go-v2/service/batch"
	batchtypes "github.com/aws/aws-sdk-go-v2/service/batch/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	cloudfronttypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cloudtrailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cloudwatchtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cloudwatchlogstypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	codebuildtypes "github.com/aws/aws-sdk-go-v2/service/codebuild/types"
	"github.com/aws/aws-sdk-go-v2/service/datasync"
	datasynctypes "github.com/aws/aws-sdk-go-v2/service/datasync/types"
	"github.com/aws/aws-sdk-go-v2/service/docdb"
	docdbtypes "github.com/aws/aws-sdk-go-v2/service/docdb/types"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamodbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/dynamodbstreams"
	dynamodbstreamstypes "github.com/aws/aws-sdk-go-v2/service/dynamodbstreams/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	efstypes "github.com/aws/aws-sdk-go-v2/service/efs/types"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	elasticachetypes "github.com/aws/aws-sdk-go-v2/service/elasticache/types"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	eventbridgetypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
	"github.com/aws/aws-sdk-go-v2/service/firehose"
	firehosetypes "github.com/aws/aws-sdk-go-v2/service/firehose/types"
	"github.com/aws/aws-sdk-go-v2/service/fsx"
	fsxtypes "github.com/aws/aws-sdk-go-v2/service/fsx/types"
	"github.com/aws/aws-sdk-go-v2/service/globalaccelerator"
	globalacceleratortypes "github.com/aws/aws-sdk-go-v2/service/globalaccelerator/types"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	gluetypes "github.com/aws/aws-sdk-go-v2/service/glue/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/identitystore"
	identitystoretypes "github.com/aws/aws-sdk-go-v2/service/identitystore/types"
	"github.com/aws/aws-sdk-go-v2/service/kafka"
	kafkatypes "github.com/aws/aws-sdk-go-v2/service/kafka/types"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	kinesistypes "github.com/aws/aws-sdk-go-v2/service/kinesis/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/lakeformation"
	lakeformationtypes "github.com/aws/aws-sdk-go-v2/service/lakeformation/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/neptune"
	neptunetypes "github.com/aws/aws-sdk-go-v2/service/neptune/types"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	opensearchtypes "github.com/aws/aws-sdk-go-v2/service/opensearch/types"
	"github.com/aws/aws-sdk-go-v2/service/opensearchserverless"
	opensearchserverlesstypes "github.com/aws/aws-sdk-go-v2/service/opensearchserverless/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	organizationstypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/pipes"
	pipestypes "github.com/aws/aws-sdk-go-v2/service/pipes/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
	redshifttypes "github.com/aws/aws-sdk-go-v2/service/redshift/types"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi"
	resourcegroupstaggingapitypes "github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi/types"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	route53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	s3controltypes "github.com/aws/aws-sdk-go-v2/service/s3control/types"
	"github.com/aws/aws-sdk-go-v2/service/scheduler"
	schedulertypes "github.com/aws/aws-sdk-go-v2/service/scheduler/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	secretsmanagertypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	sfntypes "github.com/aws/aws-sdk-go-v2/service/sfn/types"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	snstypes "github.com/aws/aws-sdk-go-v2/service/sns/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	ssoadmintypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	"github.com/aws/aws-sdk-go-v2/service/vpclattice"
	vpclatticetypes "github.com/aws/aws-sdk-go-v2/service/vpclattice/types"

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
	if _, ok := parseCloudTrailCursor(first.NextCursor.GetOpaque(), settings{cloudTrail: cloudTrailSettings{since: "PT2H"}}, time.Now().UTC()); !ok {
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
				settings{cloudTrail: cloudTrailSettings{since: "PT2H"}},
				&cloudtrail.LookupEventsInput{StartTime: timePtr("2026-05-24T00:00:00Z")},
				"expired-token",
				time.Now().UTC().Add(-2*time.Hour),
			),
			config: map[string]string{"account_id": "123456789012", "family": familyCloudTrail, "since": "PT2H"},
		},
		{
			name: "selector changed",
			cursor: encodeCloudTrailCursor(
				settings{cloudTrail: cloudTrailSettings{since: "PT1H"}},
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

func TestIAMAccountPostureCollectors(t *testing.T) {
	generated := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	source := newTestSource(t, fakeAWS{
		accountSummary: map[string]int32{
			"AccountAccessKeysPresent": 0,
			"AccountMFAEnabled":        1,
			"Users":                    3,
		},
		accountPasswordPolicy: &iamtypes.PasswordPolicy{
			AllowUsersToChangePassword: true,
			MinimumPasswordLength:      awssdk.Int32(14),
			PasswordReusePrevention:    awssdk.Int32(24),
			RequireLowercaseCharacters: true,
			RequireNumbers:             true,
			RequireSymbols:             true,
			RequireUppercaseCharacters: true,
		},
		credentialReport: fakeCredentialReport{
			generatedTime: &generated,
			content: []byte(strings.Join([]string{
				"user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_2_active,access_key_2_last_rotated",
				"<root_account>,arn:aws:iam::123456789012:root,2026-01-01T00:00:00+00:00,false,N/A,N/A,N/A,true,false,N/A,false,N/A",
				"admin,arn:aws:iam::123456789012:user/admin,2026-01-02T00:00:00+00:00,true,2026-06-01T00:00:00+00:00,2026-05-01T00:00:00+00:00,N/A,false,true,2026-04-01T00:00:00+00:00,false,N/A",
			}, "\n")),
		},
	})

	summaryPull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"account_id": "123456789012", "family": "iam_account_summary"}), nil)
	if err != nil {
		t.Fatalf("Read(iam_account_summary) error = %v", err)
	}
	if got := summaryPull.Events[0].Kind; got != "aws.iam_account_summary" {
		t.Fatalf("summary kind = %q, want aws.iam_account_summary", got)
	}
	if got := summaryPull.Events[0].Attributes["root_mfa_enabled"]; got != "true" {
		t.Fatalf("root_mfa_enabled = %q, want true", got)
	}
	if got := summaryPull.Events[0].Attributes["root_access_keys_present"]; got != "false" {
		t.Fatalf("root_access_keys_present = %q, want false", got)
	}

	policyPull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"account_id": "123456789012", "family": "iam_account_password_policy"}), nil)
	if err != nil {
		t.Fatalf("Read(iam_account_password_policy) error = %v", err)
	}
	if got := policyPull.Events[0].Attributes["minimum_password_length"]; got != "14" {
		t.Fatalf("minimum_password_length = %q, want 14", got)
	}
	if got := policyPull.Events[0].Attributes["password_reuse_prevention"]; got != "24" {
		t.Fatalf("password_reuse_prevention = %q, want 24", got)
	}

	reportPull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"account_id": "123456789012", "family": "iam_credential_report"}), nil)
	if err != nil {
		t.Fatalf("Read(iam_credential_report) error = %v", err)
	}
	if len(reportPull.Events) != 2 {
		t.Fatalf("credential report events = %d, want 2", len(reportPull.Events))
	}
	if got := reportPull.Events[0].Attributes["mfa_active"]; got != "true" {
		t.Fatalf("root mfa_active = %q, want true", got)
	}
	if got := reportPull.Events[1].Attributes["access_key_1_active"]; got != "true" {
		t.Fatalf("admin access_key_1_active = %q, want true", got)
	}
}

func TestIAMCredentialReportCollectorSkipsWhileGenerating(t *testing.T) {
	source := newTestSource(t, fakeAWS{credentialReport: fakeCredentialReport{state: iamtypes.ReportStateTypeInprogress}})
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"account_id": "123456789012", "family": "iam_credential_report"}), nil)
	if err != nil {
		t.Fatalf("Read(iam_credential_report) error = %v", err)
	}
	if len(pull.Events) != 0 {
		t.Fatalf("credential report events = %d, want 0 while report is generating", len(pull.Events))
	}
}

func TestIAMCredentialReportCollectorWaitsForGeneratedReport(t *testing.T) {
	stateIndex := 0
	generated := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	source := newTestSource(t, fakeAWS{
		credentialReport: fakeCredentialReport{
			states:        []iamtypes.ReportStateType{iamtypes.ReportStateTypeStarted, iamtypes.ReportStateTypeInprogress, iamtypes.ReportStateTypeComplete},
			stateIndex:    &stateIndex,
			generatedTime: &generated,
			content: []byte(strings.Join([]string{
				"user,arn,user_creation_time,password_enabled,mfa_active,access_key_1_active,access_key_2_active",
				"admin,arn:aws:iam::123456789012:user/admin,2026-01-02T00:00:00+00:00,true,false,true,false",
			}, "\n")),
		},
	})
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"account_id": "123456789012", "family": "iam_credential_report"}), nil)
	if err != nil {
		t.Fatalf("Read(iam_credential_report) error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("credential report events = %d, want 1 after report is generated", len(pull.Events))
	}
	if got := pull.Events[0].Attributes["access_key_1_active"]; got != "true" {
		t.Fatalf("access_key_1_active = %q, want true", got)
	}
}

func TestIAMCredentialReportCollectorSkipsNotReadyReport(t *testing.T) {
	source := newTestSource(t, fakeAWS{credentialReport: fakeCredentialReport{err: &iamtypes.CredentialReportNotReadyException{}}})
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"account_id": "123456789012", "family": "iam_credential_report"}), nil)
	if err != nil {
		t.Fatalf("Read(iam_credential_report) error = %v", err)
	}
	if len(pull.Events) != 0 {
		t.Fatalf("credential report events = %d, want 0 while report is not ready", len(pull.Events))
	}
}

func TestParsePublicEndpointCursorRejectsLegacyStages(t *testing.T) {
	legacyPayload, err := json.Marshal(publicEndpointCursor{Stage: publicEndpointStageEIP, Token: "old-token"})
	if err != nil {
		t.Fatalf("marshal legacy cursor: %v", err)
	}
	legacy := base64.RawURLEncoding.EncodeToString(legacyPayload)
	if _, err := parsePublicEndpointCursor(legacy); err == nil {
		t.Fatal("parsePublicEndpointCursor(legacy) error = nil, want unsupported version")
	}
	if _, err := parsePublicEndpointCursor("eni:legacy-token"); err == nil {
		t.Fatal("parsePublicEndpointCursor(raw legacy eni) error = nil, want parse error")
	}

	versioned := encodePublicEndpointCursor(publicEndpointCursor{Stage: publicEndpointStageEIP, Token: "new-token"})
	got, err := parsePublicEndpointCursor(versioned)
	if err != nil {
		t.Fatalf("parsePublicEndpointCursor(versioned eip) error = %v", err)
	}
	if got.Stage != publicEndpointStageEIP || got.Token != "new-token" || got.Version != publicEndpointCursorV2 {
		t.Fatalf("versioned eip cursor = %#v, want stage %q token new-token version %d", got, publicEndpointStageEIP, publicEndpointCursorV2)
	}
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
		{family: familyAccessAnalyzer, kind: "aws.access_analyzer"},
		{family: familyAssetMetadata, kind: "asset.data_sensitivity"},
		{family: familyConfigRecorder, kind: "aws.config_recorder"},
		{family: familyACMCertificate, kind: "aws.acm_certificate"},
		{family: familyAssetMetadata, kind: "asset.data_sensitivity"},
		{family: familyBatchComputeEnv, kind: "aws.batch_compute_environment"},
		{family: familyBatchJobQueue, kind: "aws.batch_job_queue"},
		{family: familyBackupVault, kind: "aws.backup_vault"},
		{family: familyBackupPlan, kind: "aws.backup_plan"},
		{family: familyBackupProtected, kind: "aws.backup_protected_resource"},
		{family: familyBackupRecoveryPoint, kind: "aws.backup_recovery_point"},
		{family: familyCodeBuildProject, kind: "aws.codebuild_project"},
		{family: familyCodeBuildSourceCredential, kind: "aws.codebuild_source_credential"},
		{family: familyDataSyncLocation, kind: "aws.datasync_location"},
		{family: familyDataSyncTask, kind: "aws.datasync_task"},
		{family: familyDocDBCluster, kind: "aws.docdb_cluster"},
		{family: familyDocDBInstance, kind: "aws.docdb_instance"},
		{family: familyDynamoDBBackup, kind: "aws.dynamodb_backup"},
		{family: familyDynamoDBStream, kind: "aws.dynamodb_stream"},
		{family: familyDynamoDBTable, kind: "aws.dynamodb_table"},
		{family: familyEBSSnapshot, kind: "aws.ebs_snapshot"},
		{family: familyEBSVolume, kind: "aws.ebs_volume"},
		{family: familyEC2EBSEncryptionByDefault, kind: "aws.ec2_ebs_encryption_by_default"},
		{family: familyEC2AMI, kind: "aws.ec2_ami"},
		{family: familyAthenaDataCatalog, kind: "aws.athena_data_catalog"},
		{family: familyAthenaWorkgroup, kind: "aws.athena_workgroup"},
		{family: familyEC2Instance, kind: "aws.ec2_instance"},
		{family: familyECRRepository, kind: "aws.ecr_repository"},
		{family: familyECSService, kind: "aws.ecs_service"},
		{family: familyECSTask, kind: "aws.ecs_task"},
		{family: familyECSTaskDefinition, kind: "aws.ecs_task_definition"},
		{family: familyEFSAccessPoint, kind: "aws.efs_access_point"},
		{family: familyEFSFileSystem, kind: "aws.efs_file_system"},
		{family: familyEKSCluster, kind: "aws.eks_cluster"},
		{family: familyEKSNodegroup, kind: "aws.eks_nodegroup"},
		{family: familyEKSFargateProfile, kind: "aws.eks_fargate_profile"},
		{family: familyEKSPodIdentity, kind: "aws.eks_pod_identity_association"},
		{family: familyElastiCacheCluster, kind: "aws.elasticache_cluster"},
		{family: familyElastiCacheReplicationGroup, kind: "aws.elasticache_replication_group"},
		{family: familyElastiCacheSubnetGroup, kind: "aws.elasticache_subnet_group"},
		{family: familyGlobalAccelerator, kind: "aws.globalaccelerator_accelerator"},
		{family: familyGAListener, kind: "aws.globalaccelerator_listener"},
		{family: familyGAEndpointGroup, kind: "aws.globalaccelerator_endpoint_group"},
		{family: familyVPCLatticeService, kind: "aws.vpclattice_service"},
		{family: familyVPCLatticeListener, kind: "aws.vpclattice_listener"},
		{family: familyVPCLatticeTG, kind: "aws.vpclattice_target_group"},
		{family: familyELBV2Listener, kind: "aws.elbv2_listener"},
		{family: familyELBV2TargetGroup, kind: "aws.elbv2_target_group"},
		{family: familyAPIGatewayStage, kind: "aws.apigateway_stage"},
		{family: familyAPIGatewayRoute, kind: "aws.apigateway_route"},
		{family: familyAPIGatewayInteg, kind: "aws.apigateway_integration"},
		{family: familyCloudFrontOAC, kind: "aws.cloudfront_origin_access_control"},
		{family: familyCloudFrontKeyGroup, kind: "aws.cloudfront_key_group"},
		{family: familyCloudFrontPublicKey, kind: "aws.cloudfront_public_key"},
		{family: familyCloudFrontRHP, kind: "aws.cloudfront_response_headers_policy"},
		{family: familyEffectivePermission, config: map[string]string{"principal_name": "admin@writer.com", "principal_type": "user"}, kind: "aws.effective_permission"},
		{family: familyGuardDutyDetector, kind: "aws.guardduty_detector"},
		{family: familyGuardDutyFinding, kind: "aws.guardduty_finding"},
		{family: "iam_account_password_policy", kind: "aws.iam_account_password_policy"},
		{family: "iam_account_summary", kind: "aws.iam_account_summary"},
		{family: "iam_credential_report", kind: "aws.iam_credential_report"},
		{family: familyIAMUser, kind: "aws.iam_user"},
		{family: familyInspector2Finding, kind: "aws.inspector2_finding"},
		{family: familyFirehoseDelivery, kind: "aws.firehose_delivery_stream"},
		{family: familyGlueCrawler, kind: "aws.glue_crawler"},
		{family: familyGlueDatabase, kind: "aws.glue_database"},
		{family: familyGlueJob, kind: "aws.glue_job"},
		{family: familyGlueTable, kind: "aws.glue_table"},
		{family: familyIAMUser, kind: "aws.iam_user"},
		{family: familyFSxFileSystem, kind: "aws.fsx_file_system"},
		{family: familyKinesisStream, kind: "aws.kinesis_stream"},
		{family: familyKMSKey, kind: "aws.kms_key"},
		{family: familyLakeFormationLFTag, kind: "aws.lakeformation_lf_tag"},
		{family: familyLakeFormationPerm, kind: "aws.lakeformation_permission"},
		{family: familyLakeFormationRes, kind: "aws.lakeformation_resource"},
		{family: familyLambdaFunction, kind: "aws.lambda_function"},
		{family: familyMacie2Finding, kind: "aws.macie2_finding"},
		{family: familyNetworkACL, kind: "aws.network_acl"},
		{family: familyNetworkFirewall, kind: "aws.network_firewall"},
		{family: familyMSKCluster, kind: "aws.msk_cluster"},
		{family: familyOpenSearchDomain, kind: "aws.opensearch_domain"},
		{family: familyOpenSearchServerlessCollection, kind: "aws.opensearch_serverless_collection"},
		{family: familyOpenSearchServerlessSecurityPolicy, kind: "aws.opensearch_serverless_security_policy"},
		{family: familyNeptuneCluster, kind: "aws.neptune_cluster"},
		{family: familyNeptuneInstance, kind: "aws.neptune_instance"},
		{family: familyRDSDBSnapshot, kind: "aws.rds_db_snapshot"},
		{family: familyRDSInstance, kind: "aws.rds_instance"},
		{family: familyRedshiftCluster, kind: "aws.redshift_cluster"},
		{family: familyS3AccessPoint, kind: "aws.s3_access_point"},
		{family: familyS3Bucket, kind: "aws.s3_bucket"},
		{family: familyS3MultiRegionAccessPoint, kind: "aws.s3_multi_region_access_point"},
		{family: familySecret, kind: "aws.secret"},
		{family: familySecurityHubFinding, kind: "aws.securityhub_finding"},
		{family: familySNSTopic, kind: "aws.sns_topic"},
		{family: familySQSQueue, kind: "aws.sqs_queue"},
		{family: familyWAFV2WebACL, kind: "aws.wafv2_web_acl"},
		{family: familyIAMRole, kind: "aws.iam_role"},
		{family: familyIAMRoleTrust, kind: "aws.iam_role_trust"},
		{family: familyIAMSAMLProvider, kind: "aws.iam_saml_provider"},
		{family: familyIAMGroup, kind: "aws.iam_group"},
		{family: familyIAMMembership, config: map[string]string{"group_name": "Security"}, kind: "aws.iam_group_membership"},
		{family: familyIAMRoleAssign, config: map[string]string{"principal_name": "admin@writer.com", "principal_type": "user"}, kind: "aws.iam_role_assignment"},
		{family: familyIdentityCenterAssignment, kind: "aws.identity_center_account_assignment"},
		{family: familyIdentityCenterPermission, kind: "aws.identity_center_permission_set"},
		{family: familyIdentityStoreGroup, kind: "aws.identitystore_group"},
		{family: familyIdentityStoreMember, kind: "aws.identitystore_group_membership"},
		{family: familyIdentityStoreUser, kind: "aws.identitystore_user"},
		{family: familyOrganizationsAcct, kind: "aws.organizations_account"},
		{family: familyOrganizationsOU, kind: "aws.organizations_organizational_unit"},
		{family: familyOrganizationsPolicy, kind: "aws.organizations_policy"},
		{family: familyOrganizationsRoot, kind: "aws.organizations_root"},
		{family: familyCloudTrail, kind: "aws.cloudtrail"},
		{family: familyVPCFlowLog, kind: "aws.vpc_flow_log"},
		{family: familyPublicEndpoint, kind: "aws.public_endpoint"},
		{family: familyResourceExposure, kind: "aws.resource_exposure"},
		{family: familyRoute53ResolverEndpoint, kind: "aws.route53_resolver_endpoint"},
		{family: familyRoute53ResolverRule, kind: "aws.route53_resolver_rule"},
		{family: familySSOAssignment, kind: "aws.sso_account_assignment"},
		{family: familySSOInstance, kind: "aws.sso_instance"},
		{family: familySSOPermissionSet, kind: "aws.sso_permission_set"},
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

func TestReadAWSNetworkACLAndFlowLogEvents(t *testing.T) {
	source := newTestSource(t, fakeAWS{fakeAWSNetwork: fakeAWSNetwork{fakeAWSNetworkExposure: fakeAWSNetworkExposure{
		networkACLs: []ec2types.NetworkAcl{{
			NetworkAclId: awssdk.String("acl-123"),
			VpcId:        awssdk.String("vpc-123"),
			Associations: []ec2types.NetworkAclAssociation{{SubnetId: awssdk.String("subnet-123")}},
			Entries: []ec2types.NetworkAclEntry{
				{
					CidrBlock:  awssdk.String("0.0.0.0/0"),
					Egress:     awssdk.Bool(false),
					PortRange:  &ec2types.PortRange{From: awssdk.Int32(22), To: awssdk.Int32(22)},
					Protocol:   awssdk.String("6"),
					RuleAction: ec2types.RuleActionAllow,
				},
				{
					CidrBlock:  awssdk.String("10.0.0.0/8"),
					Egress:     awssdk.Bool(true),
					Protocol:   awssdk.String("-1"),
					RuleAction: ec2types.RuleActionAllow,
				},
			},
		}},
		flowLogs: []ec2types.FlowLog{{
			DeliverLogsStatus:      awssdk.String("SUCCESS"),
			DestinationOptions:     &ec2types.DestinationOptionsResponse{FileFormat: ec2types.DestinationFileFormatPlainText, HiveCompatiblePartitions: awssdk.Bool(true), PerHourPartition: awssdk.Bool(true)},
			FlowLogId:              awssdk.String("fl-123"),
			FlowLogStatus:          awssdk.String("ACTIVE"),
			LogDestination:         awssdk.String("arn:aws:logs:us-east-1:123456789012:log-group:/aws/vpc/flowlogs/prod"),
			LogDestinationType:     ec2types.LogDestinationTypeCloudWatchLogs,
			LogGroupName:           awssdk.String("/aws/vpc/flowlogs/prod"),
			MaxAggregationInterval: awssdk.Int32(60),
			ResourceId:             awssdk.String("vpc-123"),
			TrafficType:            ec2types.TrafficTypeAll,
		}},
	}}})

	for _, tt := range []struct {
		family string
		kind   string
		attr   string
		want   string
	}{
		{family: familyNetworkACL, kind: "aws.network_acl", attr: "allows_admin_ports_from_internet", want: "true"},
		{family: familyVPCFlowLog, kind: "aws.vpc_flow_log", attr: "log_destination_type", want: string(ec2types.LogDestinationTypeCloudWatchLogs)},
		{family: familyVPCFlowLog, kind: "aws.vpc_flow_log", attr: "vpc_id", want: "vpc-123"},
	} {
		t.Run(tt.family+"/"+tt.attr, func(t *testing.T) {
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

func TestReadAWSLegacyIdentityCenterInventoryEvents(t *testing.T) {
	instanceARN := "arn:aws:sso:::instance/ssoins-123"
	permissionSetARN := "arn:aws:sso:::permissionSet/ssoins-123/ps-admin"
	source := newTestSource(t, fakeAWS{
		fakeAWSGovernance: fakeAWSGovernance{
			ssoInstances:      []ssoadmintypes.InstanceMetadata{{InstanceArn: awssdk.String(instanceARN), IdentityStoreId: awssdk.String("d-1234567890"), OwnerAccountId: awssdk.String("123456789012")}},
			ssoPermissionSets: []ssoadmintypes.PermissionSet{{PermissionSetArn: awssdk.String(permissionSetARN), Name: awssdk.String("AdministratorAccess"), SessionDuration: awssdk.String("PT8H")}},
			ssoAssignments: map[string][]ssoadmintypes.AccountAssignment{
				"210987654321|" + permissionSetARN: {{AccountId: awssdk.String("210987654321"), PermissionSetArn: awssdk.String(permissionSetARN), PrincipalId: awssdk.String("u-123"), PrincipalType: ssoadmintypes.PrincipalTypeUser}},
			},
			identityUsers:  []identitystoretypes.User{{IdentityStoreId: awssdk.String("d-1234567890"), UserId: awssdk.String("u-123"), UserName: awssdk.String("alice"), DisplayName: awssdk.String("Alice Admin"), Emails: []identitystoretypes.Email{{Value: awssdk.String("alice@writer.com"), Primary: true}}, UserStatus: identitystoretypes.UserStatusEnabled}},
			identityGroups: []identitystoretypes.Group{{IdentityStoreId: awssdk.String("d-1234567890"), GroupId: awssdk.String("g-admins"), DisplayName: awssdk.String("Admins")}},
			identityMemberships: map[string][]identitystoretypes.GroupMembership{
				"g-admins": {{IdentityStoreId: awssdk.String("d-1234567890"), GroupId: awssdk.String("g-admins"), MembershipId: awssdk.String("m-123"), MemberId: &identitystoretypes.MemberIdMemberUserId{Value: "u-123"}}},
			},
		},
	})
	for _, tt := range []struct {
		family string
		kind   string
		attr   string
		want   string
	}{
		{family: familyIdentityCenterPermission, kind: "aws.identity_center_permission_set", attr: "permission_set_name", want: "AdministratorAccess"},
		{family: familyIdentityCenterAssignment, kind: "aws.identity_center_account_assignment", attr: "principal_id", want: "u-123"},
		{family: familyIdentityStoreUser, kind: "aws.identitystore_user", attr: "email", want: "alice@writer.com"},
		{family: familyIdentityStoreGroup, kind: "aws.identitystore_group", attr: "group_name", want: "Admins"},
		{family: familyIdentityStoreMember, kind: "aws.identitystore_group_membership", attr: "member_user_id", want: "u-123"},
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

func TestReadAWSIAMSAMLProviderInventoryEvent(t *testing.T) {
	providerARN := "arn:aws:iam::123456789012:saml-provider/Okta"
	createDate := time.Now().UTC().Add(-72 * time.Hour)
	validUntil := time.Now().UTC().Add(-48 * time.Hour)
	source := newTestSource(t, fakeAWS{
		samlProviders: []iamtypes.SAMLProviderListEntry{{
			Arn:        awssdk.String(providerARN),
			CreateDate: &createDate,
			ValidUntil: &validUntil,
		}},
		samlProviderDetails: map[string]iam.GetSAMLProviderOutput{
			providerARN: {
				AssertionEncryptionMode: iamtypes.AssertionEncryptionModeTypeAllowed,
				CreateDate:              &createDate,
				SAMLMetadataDocument:    awssdk.String("<EntityDescriptor entityID=\"https://idp.example.com\"/>"),
				SAMLProviderUUID:        awssdk.String("saml-uuid"),
				Tags:                    []iamtypes.Tag{{Key: awssdk.String("Owner"), Value: awssdk.String("identity@writer.com")}},
				ValidUntil:              &validUntil,
			},
		},
	})
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"account_id": "123456789012", "family": familyIAMSAMLProvider}), nil)
	if err != nil {
		t.Fatalf("Read(%s) error = %v", familyIAMSAMLProvider, err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if got := event.Kind; got != "aws.iam_saml_provider" {
		t.Fatalf("kind = %q, want aws.iam_saml_provider", got)
	}
	for key, want := range map[string]string{
		"assertion_encryption_mode": "Allowed",
		"expired":                   "true",
		"metadata_document_present": "true",
		"provider_arn":              providerARN,
		"provider_name":             "Okta",
		"provider_uuid":             "saml-uuid",
		"resource_type":             "iam_saml_provider",
	} {
		if got := event.Attributes[key]; got != want {
			t.Fatalf("%s = %q, want %q", key, got, want)
		}
	}
	days, err := strconv.Atoi(event.Attributes["valid_until_days"])
	if err != nil || days >= 0 {
		t.Fatalf("valid_until_days = %q, want negative integer", event.Attributes["valid_until_days"])
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
		fakeAWSNetwork: fakeAWSNetwork{
			fakeAWSNetworkExposure: fakeAWSNetworkExposure{
				networkInterfaces: []ec2types.NetworkInterface{{
					NetworkInterfaceId: awssdk.String("eni-task"),
					Groups:             []ec2types.GroupIdentifier{{GroupId: awssdk.String("sg-task")}},
					PrivateIpAddress:   awssdk.String("10.0.2.25"),
					SubnetId:           awssdk.String("subnet-task"),
					VpcId:              awssdk.String("vpc-1"),
				}},
			},
		},
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

func TestReadAWSBatchRuntimeEvents(t *testing.T) {
	computeEnvironmentARN := "arn:aws:batch:us-east-1:123456789012:compute-environment/prod-batch"
	jobQueueARN := "arn:aws:batch:us-east-1:123456789012:job-queue/prod-jobs"
	serviceRoleARN := "arn:aws:iam::123456789012:role/service-role/AWSBatchServiceRole"
	source := newTestSource(t, fakeAWS{compute: fakeAWSCompute{
		batchComputeEnvironments: []batchtypes.ComputeEnvironmentDetail{{
			ComputeEnvironmentArn:  awssdk.String(computeEnvironmentARN),
			ComputeEnvironmentName: awssdk.String("prod-batch"),
			ComputeResources: &batchtypes.ComputeResource{
				AllocationStrategy: batchtypes.CRAllocationStrategyBestFitProgressive,
				DesiredvCpus:       awssdk.Int32(4),
				InstanceRole:       awssdk.String("ecsInstanceRole"),
				InstanceTypes:      []string{"m7g.large"},
				MaxvCpus:           awssdk.Int32(32),
				MinvCpus:           awssdk.Int32(0),
				SecurityGroupIds:   []string{"sg-batch"},
				Subnets:            []string{"subnet-batch"},
				Type:               batchtypes.CRTypeEc2,
			},
			EcsClusterArn: awssdk.String("arn:aws:ecs:us-east-1:123456789012:cluster/AWSBatch-prod-batch"),
			ServiceRole:   awssdk.String(serviceRoleARN),
			State:         batchtypes.CEStateEnabled,
			Status:        batchtypes.CEStatusValid,
			Tags:          map[string]string{"Owner": "platform@writer.com"},
			Type:          batchtypes.CETypeManaged,
		}},
		batchJobQueues: []batchtypes.JobQueueDetail{{
			ComputeEnvironmentOrder: []batchtypes.ComputeEnvironmentOrder{{
				ComputeEnvironment: awssdk.String(computeEnvironmentARN),
				Order:              awssdk.Int32(1),
			}},
			JobQueueArn:  awssdk.String(jobQueueARN),
			JobQueueName: awssdk.String("prod-jobs"),
			Priority:     awssdk.Int32(10),
			State:        batchtypes.JQStateEnabled,
			Status:       batchtypes.JQStatusValid,
			Tags:         map[string]string{"Team": "platform"},
		}},
	}})
	for _, tt := range []struct {
		family string
		kind   string
		attr   string
		want   string
	}{
		{family: familyBatchComputeEnv, kind: "aws.batch_compute_environment", attr: "role_name", want: "service-role/AWSBatchServiceRole"},
		{family: familyBatchJobQueue, kind: "aws.batch_job_queue", attr: "compute_environment_arns", want: computeEnvironmentARN},
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

func TestReadAWSCloudAssetInventoryEvents(t *testing.T) {
	rdsARN := "arn:aws:rds:us-east-1:123456789012:db:orders-db"
	rdsSnapshotARN := "arn:aws:rds:us-east-1:123456789012:snapshot:orders-public-snapshot"
	redshiftARN := "arn:aws:redshift:us-east-1:123456789012:cluster:warehouse-prod"
	docdbClusterARN := "arn:aws:rds:us-east-1:123456789012:cluster:docdb-prod"
	docdbInstanceARN := "arn:aws:rds:us-east-1:123456789012:db:docdb-prod-1"
	neptuneClusterARN := "arn:aws:rds:us-east-1:123456789012:cluster:graph-prod"
	neptuneInstanceARN := "arn:aws:rds:us-east-1:123456789012:db:graph-prod-1"
	kmsARN := "arn:aws:kms:us-east-1:123456789012:key/key-123"
	secretARN := "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/api-key-AbCd" // #nosec G101 -- test ARN fixture, not credential material.
	sqsARN := "arn:aws:sqs:us-east-1:123456789012:orders"
	sqsURL := "https://sqs.us-east-1.amazonaws.com/123456789012/orders"
	snsARN := "arn:aws:sns:us-east-1:123456789012:orders"
	ecrARN := "arn:aws:ecr:us-east-1:123456789012:repository/orders"
	s3APARN := "arn:aws:s3:us-east-1:123456789012:accesspoint/prod-data-ap"
	mrapARN := "arn:aws:s3::123456789012:accesspoint/prod-global"
	datasyncTaskARN := "arn:aws:datasync:us-east-1:123456789012:task/task-123"
	datasyncSourceARN := "arn:aws:datasync:us-east-1:123456789012:location/loc-src"
	datasyncDestinationARN := "arn:aws:datasync:us-east-1:123456789012:location/loc-dst"
	source := newTestSource(t, fakeAWS{
		fakeAWSData: fakeAWSData{
			fakeAWSCoreData: fakeAWSCoreData{
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
			},
			fakeAWSRDSData: fakeAWSRDSData{
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
				rdsDBSnapshots: []rdstypes.DBSnapshot{{
					AllocatedStorage:     awssdk.Int32(100),
					DBInstanceIdentifier: awssdk.String("orders-db"),
					DBSnapshotArn:        awssdk.String(rdsSnapshotARN),
					DBSnapshotIdentifier: awssdk.String("orders-public-snapshot"),
					Engine:               awssdk.String("postgres"),
					Encrypted:            awssdk.Bool(true),
					KmsKeyId:             awssdk.String(kmsARN),
					SnapshotCreateTime:   timePtr("2026-04-23T00:00:00Z"),
					SnapshotType:         awssdk.String("manual"),
					Status:               awssdk.String("available"),
					TagList:              []rdstypes.Tag{{Key: awssdk.String("Owner"), Value: awssdk.String("database@writer.com")}},
					VpcId:                awssdk.String("vpc-data"),
				}},
				rdsDBSnapshotAttributes: map[string][]rdstypes.DBSnapshotAttribute{"orders-public-snapshot": {{
					AttributeName:   awssdk.String("restore"),
					AttributeValues: []string{"all"},
				}}},
			},
			fakeAWSDataWarehouseData: fakeAWSDataWarehouseData{
				redshiftClusters: []redshifttypes.Cluster{{
					ClusterIdentifier:                awssdk.String("warehouse-prod"),
					ClusterStatus:                    awssdk.String("available"),
					ClusterCreateTime:                timePtr("2026-04-23T00:00:00Z"),
					ClusterVersion:                   awssdk.String("1.0"),
					Encrypted:                        awssdk.Bool(true),
					EnhancedVpcRouting:               awssdk.Bool(true),
					KmsKeyId:                         awssdk.String(kmsARN),
					NodeType:                         awssdk.String("ra3.xlplus"),
					NumberOfNodes:                    awssdk.Int32(2),
					PubliclyAccessible:               awssdk.Bool(false),
					AutomatedSnapshotRetentionPeriod: awssdk.Int32(7),
					Tags:                             []redshifttypes.Tag{{Key: awssdk.String("Owner"), Value: awssdk.String("data@writer.com")}},
					VpcId:                            awssdk.String("vpc-data"),
					VpcSecurityGroups:                []redshifttypes.VpcSecurityGroupMembership{{VpcSecurityGroupId: awssdk.String("sg-redshift")}},
				}},
				docdbClusters: []docdbtypes.DBCluster{{
					DBClusterArn:          awssdk.String(docdbClusterARN),
					DBClusterIdentifier:   awssdk.String("docdb-prod"),
					BackupRetentionPeriod: awssdk.Int32(7),
					ClusterCreateTime:     timePtr("2026-04-23T00:00:00Z"),
					DBSubnetGroup:         awssdk.String("data-subnets"),
					DeletionProtection:    awssdk.Bool(true),
					Engine:                awssdk.String("docdb"),
					EngineVersion:         awssdk.String("5.0.0"),
					KmsKeyId:              awssdk.String(kmsARN),
					Port:                  awssdk.Int32(27017),
					Status:                awssdk.String("available"),
					StorageEncrypted:      awssdk.Bool(true),
					VpcSecurityGroups:     []docdbtypes.VpcSecurityGroupMembership{{VpcSecurityGroupId: awssdk.String("sg-docdb")}},
				}},
				docdbInstances: []docdbtypes.DBInstance{{
					DBClusterIdentifier:  awssdk.String("docdb-prod"),
					DBInstanceArn:        awssdk.String(docdbInstanceARN),
					DBInstanceClass:      awssdk.String("db.r6g.large"),
					DBInstanceIdentifier: awssdk.String("docdb-prod-1"),
					DBInstanceStatus:     awssdk.String("available"),
					Endpoint:             &docdbtypes.Endpoint{Address: awssdk.String("docdb-prod-1.cluster.local"), Port: awssdk.Int32(27017)},
					Engine:               awssdk.String("docdb"),
					EngineVersion:        awssdk.String("5.0.0"),
					InstanceCreateTime:   timePtr("2026-04-23T00:00:00Z"),
					VpcSecurityGroups:    []docdbtypes.VpcSecurityGroupMembership{{VpcSecurityGroupId: awssdk.String("sg-docdb")}},
				}},
				docdbTags: map[string][]docdbtypes.Tag{
					docdbClusterARN:  {{Key: awssdk.String("Owner"), Value: awssdk.String("database@writer.com")}},
					docdbInstanceARN: {{Key: awssdk.String("Owner"), Value: awssdk.String("database@writer.com")}},
				},
				neptuneClusters: []neptunetypes.DBCluster{{
					DBClusterArn:          awssdk.String(neptuneClusterARN),
					DBClusterIdentifier:   awssdk.String("graph-prod"),
					BackupRetentionPeriod: awssdk.Int32(7),
					ClusterCreateTime:     timePtr("2026-04-23T00:00:00Z"),
					DBSubnetGroup:         awssdk.String("data-subnets"),
					DeletionProtection:    awssdk.Bool(true),
					Engine:                awssdk.String("neptune"),
					EngineVersion:         awssdk.String("1.3.2.0"),
					KmsKeyId:              awssdk.String(kmsARN),
					Port:                  awssdk.Int32(8182),
					Status:                awssdk.String("available"),
					StorageEncrypted:      awssdk.Bool(true),
					VpcSecurityGroups:     []neptunetypes.VpcSecurityGroupMembership{{VpcSecurityGroupId: awssdk.String("sg-neptune")}},
				}},
				neptuneInstances: []neptunetypes.DBInstance{{
					DBClusterIdentifier:  awssdk.String("graph-prod"),
					DBInstanceArn:        awssdk.String(neptuneInstanceARN),
					DBInstanceClass:      awssdk.String("db.r6g.large"),
					DBInstanceIdentifier: awssdk.String("graph-prod-1"),
					DBInstanceStatus:     awssdk.String("available"),
					Endpoint:             &neptunetypes.Endpoint{Address: awssdk.String("graph-prod-1.cluster.local"), Port: awssdk.Int32(8182)},
					Engine:               awssdk.String("neptune"),
					EngineVersion:        awssdk.String("1.3.2.0"),
					InstanceCreateTime:   timePtr("2026-04-23T00:00:00Z"),
					VpcSecurityGroups:    []neptunetypes.VpcSecurityGroupMembership{{VpcSecurityGroupId: awssdk.String("sg-neptune")}},
				}},
				neptuneTags: map[string][]neptunetypes.Tag{
					neptuneClusterARN:  {{Key: awssdk.String("Owner"), Value: awssdk.String("database@writer.com")}},
					neptuneInstanceARN: {{Key: awssdk.String("Owner"), Value: awssdk.String("database@writer.com")}},
				},
			},
			fakeAWSStorageAccessData: fakeAWSStorageAccessData{
				s3AccessPoints: []s3controltypes.AccessPoint{{
					AccessPointArn: awssdk.String(s3APARN),
					Bucket:         awssdk.String("prod-data"),
					Name:           awssdk.String("prod-data-ap"),
					NetworkOrigin:  s3controltypes.NetworkOriginVpc,
					VpcConfiguration: &s3controltypes.VpcConfiguration{
						VpcId: awssdk.String("vpc-123"),
					},
				}},
				s3AccessPointDetails: map[string]*s3control.GetAccessPointOutput{"prod-data-ap": {
					AccessPointArn: awssdk.String(s3APARN),
					Bucket:         awssdk.String("prod-data"),
					CreationDate:   timePtr("2026-04-23T00:00:00Z"),
					Name:           awssdk.String("prod-data-ap"),
					NetworkOrigin:  s3controltypes.NetworkOriginVpc,
					PublicAccessBlockConfiguration: &s3controltypes.PublicAccessBlockConfiguration{
						BlockPublicAcls:       awssdk.Bool(true),
						BlockPublicPolicy:     awssdk.Bool(true),
						IgnorePublicAcls:      awssdk.Bool(true),
						RestrictPublicBuckets: awssdk.Bool(true),
					},
					VpcConfiguration: &s3controltypes.VpcConfiguration{VpcId: awssdk.String("vpc-123")},
				}},
				s3ControlTags:       map[string][]s3controltypes.Tag{s3APARN: {{Key: awssdk.String("Owner"), Value: awssdk.String("data@writer.com")}}, mrapARN: {{Key: awssdk.String("Owner"), Value: awssdk.String("data@writer.com")}}},
				s3AccessPointPublic: map[string]bool{"prod-data-ap": false},
				s3MultiRegionAccessPoints: []s3controltypes.MultiRegionAccessPointReport{{
					Alias:     awssdk.String("prod-global.mrap"),
					CreatedAt: timePtr("2026-04-23T00:00:00Z"),
					Name:      awssdk.String("prod-global"),
					PublicAccessBlock: &s3controltypes.PublicAccessBlockConfiguration{
						BlockPublicAcls:       awssdk.Bool(true),
						BlockPublicPolicy:     awssdk.Bool(true),
						IgnorePublicAcls:      awssdk.Bool(true),
						RestrictPublicBuckets: awssdk.Bool(true),
					},
					Regions: []s3controltypes.RegionReport{
						{Bucket: awssdk.String("prod-data"), Region: awssdk.String("us-east-1")},
						{Bucket: awssdk.String("prod-data-replica"), Region: awssdk.String("us-west-2")},
					},
					Status: s3controltypes.MultiRegionAccessPointStatusReady,
				}},
				s3MultiRegionAccessPointPublic: map[string]bool{"prod-global": false},
				fakeAWSEBSData: fakeAWSEBSData{
					ebsVolumes: []ec2types.Volume{{
						AvailabilityZone: awssdk.String("us-east-1a"),
						CreateTime:       timePtr("2026-04-23T00:00:00Z"),
						Encrypted:        awssdk.Bool(true),
						KmsKeyId:         awssdk.String(kmsARN),
						Size:             awssdk.Int32(100),
						SnapshotId:       awssdk.String("snap-123"),
						State:            ec2types.VolumeStateInUse,
						Tags:             []ec2types.Tag{{Key: awssdk.String("Name"), Value: awssdk.String("orders-data")}, {Key: awssdk.String("Owner"), Value: awssdk.String("storage@writer.com")}},
						VolumeId:         awssdk.String("vol-123"),
						VolumeType:       ec2types.VolumeTypeGp3,
					}},
					ebsSnapshots: []ec2types.Snapshot{{
						Description: awssdk.String("orders backup"),
						Encrypted:   awssdk.Bool(true),
						KmsKeyId:    awssdk.String(kmsARN),
						OwnerId:     awssdk.String("123456789012"),
						SnapshotId:  awssdk.String("snap-123"),
						StartTime:   timePtr("2026-04-23T00:00:00Z"),
						State:       ec2types.SnapshotStateCompleted,
						Tags:        []ec2types.Tag{{Key: awssdk.String("Name"), Value: awssdk.String("orders-snapshot")}, {Key: awssdk.String("Owner"), Value: awssdk.String("storage@writer.com")}},
						VolumeId:    awssdk.String("vol-123"),
						VolumeSize:  awssdk.Int32(100),
					}},
					ebsSnapshotPublic:      map[string]bool{"snap-123": false},
					ebsEncryptionByDefault: true,
				},
				datasyncTasks: []datasynctypes.TaskListEntry{{
					Name:     awssdk.String("copy-prod-data"),
					Status:   datasynctypes.TaskStatusAvailable,
					TaskArn:  awssdk.String(datasyncTaskARN),
					TaskMode: datasynctypes.TaskModeEnhanced,
				}},
				datasyncTaskDetails: map[string]*datasync.DescribeTaskOutput{datasyncTaskARN: {
					CreationTime:           timePtr("2026-04-23T00:00:00Z"),
					DestinationLocationArn: awssdk.String(datasyncDestinationARN),
					Name:                   awssdk.String("copy-prod-data"),
					Schedule:               &datasynctypes.TaskSchedule{ScheduleExpression: awssdk.String("rate(12 hours)")},
					SourceLocationArn:      awssdk.String(datasyncSourceARN),
					Status:                 datasynctypes.TaskStatusAvailable,
					TaskArn:                awssdk.String(datasyncTaskARN),
					TaskMode:               datasynctypes.TaskModeEnhanced,
				}},
				datasyncLocations: []datasynctypes.LocationListEntry{{
					LocationArn: awssdk.String(datasyncSourceARN),
					LocationUri: awssdk.String("s3://prod-data/export"),
				}},
				datasyncLocationS3: map[string]*datasync.DescribeLocationS3Output{datasyncSourceARN: {
					CreationTime:   timePtr("2026-04-23T00:00:00Z"),
					LocationArn:    awssdk.String(datasyncSourceARN),
					LocationUri:    awssdk.String("s3://prod-data/export"),
					S3Config:       &datasynctypes.S3Config{BucketAccessRoleArn: awssdk.String("arn:aws:iam::123456789012:role/DataSyncS3Access")},
					S3StorageClass: datasynctypes.S3StorageClassStandard,
				}},
				datasyncTags: map[string][]datasynctypes.TagListEntry{
					datasyncTaskARN:   {{Key: awssdk.String("Owner"), Value: awssdk.String("storage@writer.com")}},
					datasyncSourceARN: {{Key: awssdk.String("Owner"), Value: awssdk.String("storage@writer.com")}},
				},
			},
		},
	})
	for _, tt := range []struct {
		family string
		kind   string
		attr   string
		want   string
	}{
		{family: familyS3Bucket, kind: "aws.s3_bucket", attr: "versioning", want: "Enabled"},
		{family: familyS3AccessPoint, kind: "aws.s3_access_point", attr: "public", want: "false"},
		{family: familyS3MultiRegionAccessPoint, kind: "aws.s3_multi_region_access_point", attr: "backups", want: "true"},
		{family: familyEBSVolume, kind: "aws.ebs_volume", attr: "backups", want: "true"},
		{family: familyEBSSnapshot, kind: "aws.ebs_snapshot", attr: "encryption", want: "true"},
		{family: familyEC2EBSEncryptionByDefault, kind: "aws.ec2_ebs_encryption_by_default", attr: "ebs_encryption_enabled", want: "true"},
		{family: familyDataSyncTask, kind: "aws.datasync_task", attr: "backups", want: "true"},
		{family: familyDataSyncLocation, kind: "aws.datasync_location", attr: "location_type", want: "s3"},
		{family: familyRDSDBSnapshot, kind: "aws.rds_db_snapshot", attr: "restore", want: "all"},
		{family: familyRDSInstance, kind: "aws.rds_instance", attr: "deletion_protection", want: "true"},
		{family: familyRedshiftCluster, kind: "aws.redshift_cluster", attr: "arn", want: redshiftARN},
		{family: familyDocDBCluster, kind: "aws.docdb_cluster", attr: "deletion_protection", want: "true"},
		{family: familyDocDBInstance, kind: "aws.docdb_instance", attr: "cluster_name", want: "docdb-prod"},
		{family: familyNeptuneCluster, kind: "aws.neptune_cluster", attr: "deletion_protection", want: "true"},
		{family: familyNeptuneInstance, kind: "aws.neptune_instance", attr: "cluster_name", want: "graph-prod"},
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

func TestReadAWSEC2AMIInventoryEvent(t *testing.T) {
	source := newTestSource(t, fakeAWS{
		compute: fakeAWSCompute{
			images: []ec2types.Image{{
				Architecture:       ec2types.ArchitectureValuesX8664,
				CreationDate:       awssdk.String("2026-04-23T00:00:00Z"),
				Description:        awssdk.String("Golden web AMI"),
				ImageId:            awssdk.String("ami-123"),
				ImageType:          ec2types.ImageTypeValuesMachine,
				Name:               awssdk.String("golden-web"),
				OwnerId:            awssdk.String("123456789012"),
				Public:             awssdk.Bool(true),
				RootDeviceName:     awssdk.String("/dev/xvda"),
				RootDeviceType:     ec2types.DeviceTypeEbs,
				SourceImageId:      awssdk.String("ami-base"),
				SourceImageRegion:  awssdk.String("us-west-2"),
				SourceInstanceId:   awssdk.String("i-source"),
				State:              ec2types.ImageStateAvailable,
				Tags:               []ec2types.Tag{{Key: awssdk.String("Name"), Value: awssdk.String("golden-web")}},
				VirtualizationType: ec2types.VirtualizationTypeHvm,
			}},
		},
	})
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"account_id": "123456789012", "family": familyEC2AMI}), nil)
	if err != nil {
		t.Fatalf("Read(%s) error = %v", familyEC2AMI, err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if got := event.Kind; got != "aws.ec2_ami" {
		t.Fatalf("kind = %q, want aws.ec2_ami", got)
	}
	for key, want := range map[string]string{
		"architecture":        "x86_64",
		"image_id":            "ami-123",
		"is_public":           "true",
		"public":              "true",
		"resource_name":       "golden-web",
		"resource_type":       "ec2_ami",
		"root_device_type":    "ebs",
		"source_image_id":     "ami-base",
		"source_image_region": "us-west-2",
		"source_instance_id":  "i-source",
		"state":               "available",
		"virtualization_type": "hvm",
	} {
		if got := event.Attributes[key]; got != want {
			t.Fatalf("%s = %q, want %q", key, got, want)
		}
	}
}

func TestReadAWSCodeBuildProjectInventoryEvent(t *testing.T) {
	projectARN := "arn:aws:codebuild:us-east-1:123456789012:project/orders-build"
	source := newTestSource(t, fakeAWS{
		fakeAWSRuntime: fakeAWSRuntime{fakeAWSRuntimeApplication: fakeAWSRuntimeApplication{
			codeBuildProjects: []string{"orders-build"},
			codeBuildProjectDetail: map[string]codebuildtypes.Project{"orders-build": {
				Arn:               awssdk.String(projectARN),
				Created:           timePtr("2026-04-23T00:00:00Z"),
				EncryptionKey:     awssdk.String("arn:aws:kms:us-east-1:123456789012:key/key-123"),
				Name:              awssdk.String("orders-build"),
				ProjectVisibility: codebuildtypes.ProjectVisibilityTypePrivate,
				ServiceRole:       awssdk.String("arn:aws:iam::123456789012:role/service-role/codebuild-orders"),
				Source:            &codebuildtypes.ProjectSource{Type: codebuildtypes.SourceTypeGithub},
				Environment: &codebuildtypes.ProjectEnvironment{
					ComputeType:    codebuildtypes.ComputeTypeBuildGeneral1Small,
					Image:          awssdk.String("aws/codebuild/standard:7.0"),
					PrivilegedMode: awssdk.Bool(true),
					Type:           codebuildtypes.EnvironmentTypeLinuxContainer,
					EnvironmentVariables: []codebuildtypes.EnvironmentVariable{{
						Name: awssdk.String("API_TOKEN"), Type: codebuildtypes.EnvironmentVariableTypePlaintext, Value: awssdk.String("do-not-store-this-value"),
					}},
				},
				LogsConfig: &codebuildtypes.LogsConfig{
					CloudWatchLogs: &codebuildtypes.CloudWatchLogsConfig{Status: codebuildtypes.LogsConfigStatusTypeEnabled},
					S3Logs:         &codebuildtypes.S3LogsConfig{Status: codebuildtypes.LogsConfigStatusTypeEnabled, EncryptionDisabled: awssdk.Bool(true)},
				},
				Tags: []codebuildtypes.Tag{{Key: awssdk.String("Owner"), Value: awssdk.String("ci@writer.com")}},
				Webhook: &codebuildtypes.Webhook{
					FilterGroups: [][]codebuildtypes.WebhookFilter{{{
						Type: codebuildtypes.WebhookFilterTypeEvent, Pattern: awssdk.String("PULL_REQUEST_CREATED,PULL_REQUEST_UPDATED"),
					}}},
					Status: codebuildtypes.WebhookStatusActive,
				},
			}},
		}},
	})
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"account_id": "123456789012", "family": familyCodeBuildProject}), nil)
	if err != nil {
		t.Fatalf("Read(%s) error = %v", familyCodeBuildProject, err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if got := event.Kind; got != "aws.codebuild_project" {
		t.Fatalf("kind = %q, want aws.codebuild_project", got)
	}
	for key, want := range map[string]string{
		"environment_variable_names":           "API_TOKEN",
		"plaintext_environment_variable_names": "API_TOKEN",
		"privileged_mode":                      "true",
		"s3_logs_encryption_disabled":          "true",
		"source_type":                          "GITHUB",
		"webhook_public_trigger":               "true",
	} {
		if got := event.Attributes[key]; got != want {
			t.Fatalf("%s = %q, want %q", key, got, want)
		}
	}
	if strings.Contains(string(event.Payload), "do-not-store-this-value") {
		t.Fatal("payload contains environment variable value")
	}
}

func TestReadAWSCodeBuildSourceCredentialInventoryEvent(t *testing.T) {
	arn := "arn:aws:codebuild:us-east-1:123456789012:source/github"
	source := newTestSource(t, fakeAWS{
		fakeAWSRuntime: fakeAWSRuntime{fakeAWSRuntimeApplication: fakeAWSRuntimeApplication{
			codeBuildSourceCredentials: []codebuildtypes.SourceCredentialsInfo{{
				Arn:        awssdk.String(arn),
				AuthType:   codebuildtypes.AuthTypeBasicAuth,
				ServerType: codebuildtypes.ServerTypeGithub,
			}},
		}},
	})
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"account_id": "123456789012", "family": familyCodeBuildSourceCredential}), nil)
	if err != nil {
		t.Fatalf("Read(%s) error = %v", familyCodeBuildSourceCredential, err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if got := event.Kind; got != "aws.codebuild_source_credential" {
		t.Fatalf("kind = %q, want aws.codebuild_source_credential", got)
	}
	for key, want := range map[string]string{
		"arn":           arn,
		"auth_type":     "BASIC_AUTH",
		"resource_type": "codebuild_source_credential",
		"server_type":   "GITHUB",
	} {
		if got := event.Attributes[key]; got != want {
			t.Fatalf("%s = %q, want %q", key, got, want)
		}
	}
}

func TestReadAWSKMSKeysSkipsDeniedKeyDetails(t *testing.T) {
	source := newTestSource(t, fakeAWS{
		fakeAWSData: fakeAWSData{
			fakeAWSCoreData: fakeAWSCoreData{
				kmsKeys: []kmstypes.KeyMetadata{
					{Arn: awssdk.String("arn:aws:kms:us-east-1:123456789012:key/denied"), KeyId: awssdk.String("denied")},
					{Arn: awssdk.String("arn:aws:kms:us-east-1:123456789012:key/allowed"), KeyId: awssdk.String("allowed")},
				},
				kmsDescribeErrors: map[string]error{"denied": fmt.Errorf("AccessDeniedException: denied")},
				kmsTagErrors:      map[string]error{"allowed": fmt.Errorf("AccessDeniedException: denied")},
				kmsRotationErrors: map[string]error{"allowed": fmt.Errorf("AccessDeniedException: denied")},
			},
		},
	})

	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"account_id": "123456789012", "family": familyKMSKey}), nil)
	if err != nil {
		t.Fatalf("Read(kms_key) error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	if got := pull.Events[0].Attributes["key_id"]; got != "allowed" {
		t.Fatalf("key_id = %q, want allowed", got)
	}
}

func TestReadAWSDataManagerInventoryEvents(t *testing.T) {
	openSearchARN := "arn:aws:es:us-east-1:123456789012:domain/search-prod"
	aossCollectionARN := "arn:aws:aoss:us-east-1:123456789012:collection/col-123"
	elasticacheReplicationGroupARN := "arn:aws:elasticache:us-east-1:123456789012:replicationgroup:orders-rg"
	elasticacheClusterARN := "arn:aws:elasticache:us-east-1:123456789012:cluster:orders-001"
	elasticacheSubnetGroupARN := "arn:aws:elasticache:us-east-1:123456789012:subnetgroup:cache-subnets"
	fsxARN := "arn:aws:fsx:us-east-1:123456789012:file-system/fs-123"
	source := newTestSource(t, fakeAWS{
		fakeAWSData: fakeAWSData{
			fakeAWSDataManager: fakeAWSDataManager{
				openSearchDomains: []opensearchtypes.DomainStatus{{
					ARN:           awssdk.String(openSearchARN),
					Created:       awssdk.Bool(true),
					DomainId:      awssdk.String("123456789012/search-prod"),
					DomainName:    awssdk.String("search-prod"),
					Endpoint:      awssdk.String("search-prod.us-east-1.es.amazonaws.com"),
					EngineVersion: awssdk.String("OpenSearch_2.11"),
					ClusterConfig: &opensearchtypes.ClusterConfig{
						InstanceCount: awssdk.Int32(3),
					},
					DomainEndpointOptions:       &opensearchtypes.DomainEndpointOptions{EnforceHTTPS: awssdk.Bool(true)},
					EncryptionAtRestOptions:     &opensearchtypes.EncryptionAtRestOptions{Enabled: awssdk.Bool(true), KmsKeyId: awssdk.String("key-123")},
					NodeToNodeEncryptionOptions: &opensearchtypes.NodeToNodeEncryptionOptions{Enabled: awssdk.Bool(true)},
					VPCOptions:                  &opensearchtypes.VPCDerivedInfo{SecurityGroupIds: []string{"sg-search"}, SubnetIds: []string{"subnet-search"}, VPCId: awssdk.String("vpc-1")},
				}},
				openSearchTags: map[string][]opensearchtypes.Tag{openSearchARN: {{Key: awssdk.String("Owner"), Value: awssdk.String("search@writer.com")}}},
				aossCollections: []opensearchserverlesstypes.CollectionDetail{{
					Arn:                awssdk.String(aossCollectionARN),
					CollectionEndpoint: awssdk.String("https://col-123.us-east-1.aoss.amazonaws.com"),
					CreatedDate:        awssdk.Int64(1776902400000),
					Id:                 awssdk.String("col-123"),
					KmsKeyArn:          awssdk.String("arn:aws:kms:us-east-1:123456789012:key/key-123"),
					Name:               awssdk.String("vectors"),
					Status:             opensearchserverlesstypes.CollectionStatusActive,
					Type:               opensearchserverlesstypes.CollectionTypeVectorsearch,
				}},
				aossTags: map[string][]opensearchserverlesstypes.Tag{aossCollectionARN: {{Key: awssdk.String("Team"), Value: awssdk.String("ml")}}},
				aossSecurityPolicies: []opensearchserverlesstypes.SecurityPolicyDetail{{
					Name:          awssdk.String("vectors-encryption"),
					PolicyVersion: awssdk.String("v1"),
					Type:          opensearchserverlesstypes.SecurityPolicyTypeEncryption,
				}},
				elasticacheReplicationGroups: []elasticachetypes.ReplicationGroup{{
					ARN:                        awssdk.String(elasticacheReplicationGroupARN),
					AtRestEncryptionEnabled:    awssdk.Bool(true),
					CacheNodeType:              awssdk.String("cache.r7g.large"),
					Engine:                     awssdk.String("redis"),
					KmsKeyId:                   awssdk.String("key-123"),
					MemberClusters:             []string{"orders-001"},
					ReplicationGroupCreateTime: timePtr("2026-04-23T00:00:00Z"),
					ReplicationGroupId:         awssdk.String("orders-rg"),
					Status:                     awssdk.String("available"),
					TransitEncryptionEnabled:   awssdk.Bool(true),
				}},
				elasticacheClusters: []elasticachetypes.CacheCluster{{
					ARN:                      awssdk.String(elasticacheClusterARN),
					AtRestEncryptionEnabled:  awssdk.Bool(true),
					CacheClusterCreateTime:   timePtr("2026-04-23T00:00:00Z"),
					CacheClusterId:           awssdk.String("orders-001"),
					CacheClusterStatus:       awssdk.String("available"),
					CacheNodeType:            awssdk.String("cache.r7g.large"),
					CacheSubnetGroupName:     awssdk.String("cache-subnets"),
					Engine:                   awssdk.String("redis"),
					ReplicationGroupId:       awssdk.String("orders-rg"),
					SecurityGroups:           []elasticachetypes.SecurityGroupMembership{{SecurityGroupId: awssdk.String("sg-cache")}},
					TransitEncryptionEnabled: awssdk.Bool(true),
				}},
				elasticacheSubnetGroups: []elasticachetypes.CacheSubnetGroup{{
					ARN:                  awssdk.String(elasticacheSubnetGroupARN),
					CacheSubnetGroupName: awssdk.String("cache-subnets"),
					Subnets:              []elasticachetypes.Subnet{{SubnetIdentifier: awssdk.String("subnet-cache")}},
					VpcId:                awssdk.String("vpc-1"),
				}},
				elasticacheTags: map[string][]elasticachetypes.Tag{
					elasticacheReplicationGroupARN: {{Key: awssdk.String("Team"), Value: awssdk.String("payments")}},
					elasticacheClusterARN:          {{Key: awssdk.String("Team"), Value: awssdk.String("payments")}},
					elasticacheSubnetGroupARN:      {{Key: awssdk.String("Team"), Value: awssdk.String("payments")}},
				},
				fsxFileSystems: []fsxtypes.FileSystem{{
					CreationTime:        timePtr("2026-04-23T00:00:00Z"),
					DNSName:             awssdk.String("fs-123.fsx.us-east-1.amazonaws.com"),
					FileSystemId:        awssdk.String("fs-123"),
					FileSystemType:      fsxtypes.FileSystemTypeOpenzfs,
					KmsKeyId:            awssdk.String("key-123"),
					NetworkInterfaceIds: []string{"eni-fsx"},
					ResourceARN:         awssdk.String(fsxARN),
					StorageCapacity:     awssdk.Int32(1024),
					SubnetIds:           []string{"subnet-fsx"},
					VpcId:               awssdk.String("vpc-1"),
				}},
				fsxTags: map[string][]fsxtypes.Tag{fsxARN: {{Key: awssdk.String("Owner"), Value: awssdk.String("storage@writer.com")}}},
			},
		},
	})
	for _, tt := range []struct {
		family string
		kind   string
		attr   string
		want   string
	}{
		{family: familyOpenSearchDomain, kind: "aws.opensearch_domain", attr: "node_to_node_encryption", want: "true"},
		{family: familyOpenSearchServerlessCollection, kind: "aws.opensearch_serverless_collection", attr: "collection_type", want: "VECTORSEARCH"},
		{family: familyOpenSearchServerlessSecurityPolicy, kind: "aws.opensearch_serverless_security_policy", attr: "policy_type", want: "encryption"},
		{family: familyElastiCacheReplicationGroup, kind: "aws.elasticache_replication_group", attr: "transit_encryption", want: "true"},
		{family: familyElastiCacheCluster, kind: "aws.elasticache_cluster", attr: "replication_group_id", want: "orders-rg"},
		{family: familyElastiCacheSubnetGroup, kind: "aws.elasticache_subnet_group", attr: "subnet_ids", want: "subnet-cache"},
		{family: familyFSxFileSystem, kind: "aws.fsx_file_system", attr: "network_interface_ids", want: "eni-fsx"},
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

func TestReadAWSDynamoDBInventoryEvents(t *testing.T) {
	tableARN := "arn:aws:dynamodb:us-east-1:123456789012:table/orders"
	streamARN := "arn:aws:dynamodb:us-east-1:123456789012:table/orders/stream/2026-04-23T00:00:00.000"
	backupARN := "arn:aws:dynamodb:us-east-1:123456789012:table/orders/backup/01776902400000-example"
	source := newTestSource(t, fakeAWS{fakeAWSData: fakeAWSData{
		fakeAWSStorageAccessData: fakeAWSStorageAccessData{
			dynamoDBTables: []dynamodbtypes.TableDescription{{
				TableName:                 awssdk.String("orders"),
				TableArn:                  awssdk.String(tableARN),
				TableId:                   awssdk.String("table-123"),
				TableStatus:               dynamodbtypes.TableStatusActive,
				CreationDateTime:          timePtr("2026-04-23T00:00:00Z"),
				BillingModeSummary:        &dynamodbtypes.BillingModeSummary{BillingMode: dynamodbtypes.BillingModePayPerRequest},
				DeletionProtectionEnabled: awssdk.Bool(true),
				TableSizeBytes:            awssdk.Int64(2048),
				ItemCount:                 awssdk.Int64(42),
				LatestStreamArn:           awssdk.String(streamARN),
				LatestStreamLabel:         awssdk.String("2026-04-23T00:00:00.000"),
				StreamSpecification:       &dynamodbtypes.StreamSpecification{StreamEnabled: awssdk.Bool(true), StreamViewType: dynamodbtypes.StreamViewTypeNewAndOldImages},
				SSEDescription:            &dynamodbtypes.SSEDescription{Status: dynamodbtypes.SSEStatusEnabled, SSEType: dynamodbtypes.SSETypeKms, KMSMasterKeyArn: awssdk.String("arn:aws:kms:us-east-1:123456789012:key/key-123")},
			}},
			dynamoDBTags: map[string][]dynamodbtypes.Tag{tableARN: {{Key: awssdk.String("Owner"), Value: awssdk.String("data@writer.com")}}},
			dynamoDBContinuousBackups: map[string]dynamodbtypes.ContinuousBackupsDescription{"orders": {
				ContinuousBackupsStatus: dynamodbtypes.ContinuousBackupsStatusEnabled,
				PointInTimeRecoveryDescription: &dynamodbtypes.PointInTimeRecoveryDescription{
					PointInTimeRecoveryStatus: dynamodbtypes.PointInTimeRecoveryStatusEnabled,
					RecoveryPeriodInDays:      awssdk.Int32(35),
				},
			}},
			dynamoDBTimeToLive: map[string]dynamodbtypes.TimeToLiveDescription{"orders": {
				TimeToLiveStatus: dynamodbtypes.TimeToLiveStatusEnabled,
				AttributeName:    awssdk.String("expires_at"),
			}},
			dynamoDBBackups: []dynamodbtypes.BackupSummary{{
				BackupArn:              awssdk.String(backupARN),
				BackupName:             awssdk.String("orders-daily"),
				BackupStatus:           dynamodbtypes.BackupStatusAvailable,
				BackupType:             dynamodbtypes.BackupTypeUser,
				BackupSizeBytes:        awssdk.Int64(1024),
				BackupCreationDateTime: timePtr("2026-04-23T00:00:00Z"),
				TableArn:               awssdk.String(tableARN),
				TableName:              awssdk.String("orders"),
			}},
			dynamoDBStreams: []dynamodbstreamstypes.StreamDescription{{
				StreamArn:               awssdk.String(streamARN),
				StreamLabel:             awssdk.String("2026-04-23T00:00:00.000"),
				TableName:               awssdk.String("orders"),
				StreamStatus:            dynamodbstreamstypes.StreamStatusEnabled,
				StreamViewType:          dynamodbstreamstypes.StreamViewTypeNewAndOldImages,
				CreationRequestDateTime: timePtr("2026-04-23T00:00:00Z"),
				Shards:                  []dynamodbstreamstypes.Shard{{ShardId: awssdk.String("shard-1")}},
			}},
		},
	}})

	for _, tt := range []struct {
		family string
		kind   string
		attr   string
		want   string
	}{
		{family: familyDynamoDBTable, kind: "aws.dynamodb_table", attr: "point_in_time_recovery", want: "ENABLED"},
		{family: familyDynamoDBBackup, kind: "aws.dynamodb_backup", attr: "table_name", want: "orders"},
		{family: familyDynamoDBStream, kind: "aws.dynamodb_stream", attr: "view_type", want: "NEW_AND_OLD_IMAGES"},
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

func TestReadAWSEFSInventoryEvents(t *testing.T) {
	fsARN := "arn:aws:elasticfilesystem:us-east-1:123456789012:file-system/fs-123"
	apARN := "arn:aws:elasticfilesystem:us-east-1:123456789012:access-point/fsap-123"
	source := newTestSource(t, fakeAWS{fakeAWSData: fakeAWSData{
		fakeAWSStorageAccessData: fakeAWSStorageAccessData{
			efsFileSystems: []efstypes.FileSystemDescription{{
				FileSystemArn:        awssdk.String(fsARN),
				FileSystemId:         awssdk.String("fs-123"),
				Name:                 awssdk.String("orders-fs"),
				CreationTime:         timePtr("2026-04-23T00:00:00Z"),
				LifeCycleState:       efstypes.LifeCycleStateAvailable,
				OwnerId:              awssdk.String("123456789012"),
				PerformanceMode:      efstypes.PerformanceModeGeneralPurpose,
				ThroughputMode:       efstypes.ThroughputModeBursting,
				Encrypted:            awssdk.Bool(true),
				KmsKeyId:             awssdk.String("arn:aws:kms:us-east-1:123456789012:key/key-123"),
				NumberOfMountTargets: 1,
				SizeInBytes:          &efstypes.FileSystemSize{Value: 4096},
				Tags:                 []efstypes.Tag{{Key: awssdk.String("Owner"), Value: awssdk.String("storage@writer.com")}},
			}},
			efsMountTargets: map[string][]efstypes.MountTargetDescription{"fs-123": {{
				MountTargetId:      awssdk.String("fsmt-123"),
				FileSystemId:       awssdk.String("fs-123"),
				LifeCycleState:     efstypes.LifeCycleStateAvailable,
				SubnetId:           awssdk.String("subnet-123"),
				VpcId:              awssdk.String("vpc-123"),
				NetworkInterfaceId: awssdk.String("eni-123"),
			}}},
			efsMountTargetSecurityGroups: map[string][]string{"fsmt-123": {"sg-123", "sg-456"}},
			efsAccessPoints: []efstypes.AccessPointDescription{{
				AccessPointArn: awssdk.String(apARN),
				AccessPointId:  awssdk.String("fsap-123"),
				Name:           awssdk.String("orders-ap"),
				FileSystemId:   awssdk.String("fs-123"),
				LifeCycleState: efstypes.LifeCycleStateAvailable,
				OwnerId:        awssdk.String("123456789012"),
				PosixUser:      &efstypes.PosixUser{Uid: awssdk.Int64(1000), Gid: awssdk.Int64(1000), SecondaryGids: []int64{2000}},
				RootDirectory:  &efstypes.RootDirectory{Path: awssdk.String("/orders")},
				Tags:           []efstypes.Tag{{Key: awssdk.String("Team"), Value: awssdk.String("payments")}},
			}},
		},
	}})

	for _, tt := range []struct {
		family string
		kind   string
		attr   string
		want   string
	}{
		{family: familyEFSFileSystem, kind: "aws.efs_file_system", attr: "security_group_ids", want: "sg-123,sg-456"},
		{family: familyEFSAccessPoint, kind: "aws.efs_access_point", attr: "root_directory_path", want: "/orders"},
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

func TestReadAWSNetworkEdgeInventoryEvents(t *testing.T) {
	acceleratorARN := "arn:aws:globalaccelerator::123456789012:accelerator/ga-123"
	gaListenerARN := "arn:aws:globalaccelerator::123456789012:accelerator/ga-123/listener/listener-123"
	gaEndpointGroupARN := "arn:aws:globalaccelerator::123456789012:accelerator/ga-123/listener/listener-123/endpoint-group/us-east-1"
	latticeServiceARN := "arn:aws:vpc-lattice:us-east-1:123456789012:service/svc-123"
	latticeListenerARN := "arn:aws:vpc-lattice:us-east-1:123456789012:service/svc-123/listener/listener-123"
	latticeTargetARN := "arn:aws:vpc-lattice:us-east-1:123456789012:targetgroup/tg-123"
	elbListenerARN := "arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/app-lb/50dc6c495c0c9188/6d0ecf831eec9f09"
	elbTargetARN := "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/orders/6d0ecf831eec9f09"
	apiV2ID := "v2abc"
	source := newTestSource(t, fakeAWS{
		fakeAWSNetwork: fakeAWSNetwork{
			fakeAWSNetworkExposure: fakeAWSNetworkExposure{
				loadBalancers: []elbv2types.LoadBalancer{{
					LoadBalancerArn:  awssdk.String("arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/app-lb/50dc6c495c0c9188"),
					LoadBalancerName: awssdk.String("app-lb"),
					DNSName:          awssdk.String("app-lb-123.us-east-1.elb.amazonaws.com"),
					Scheme:           elbv2types.LoadBalancerSchemeEnumInternetFacing,
					Type:             elbv2types.LoadBalancerTypeEnumApplication,
				}},
				distributions: []cloudfronttypes.DistributionSummary{{
					ARN:        awssdk.String("arn:aws:cloudfront::123456789012:distribution/EDFDVBD632BHDS5"),
					Id:         awssdk.String("EDFDVBD632BHDS5"),
					DomainName: awssdk.String("d111111abcdef8.cloudfront.net"),
					Enabled:    awssdk.Bool(true),
					Status:     awssdk.String("Deployed"),
				}},
			},
			fakeAWSNetworkEdge: fakeAWSNetworkEdge{
				accelerators: []globalacceleratortypes.Accelerator{{
					AcceleratorArn: awssdk.String(acceleratorARN),
					DnsName:        awssdk.String("a123.awsglobalaccelerator.com"),
					Enabled:        awssdk.Bool(true),
					Name:           awssdk.String("prod-edge"),
					Status:         globalacceleratortypes.AcceleratorStatusDeployed,
				}},
				gaListeners: map[string][]globalacceleratortypes.Listener{acceleratorARN: {{
					ListenerArn: awssdk.String(gaListenerARN),
					PortRanges:  []globalacceleratortypes.PortRange{{FromPort: awssdk.Int32(443), ToPort: awssdk.Int32(443)}},
					Protocol:    globalacceleratortypes.ProtocolTcp,
				}}},
				gaEndpointGroups: map[string][]globalacceleratortypes.EndpointGroup{gaListenerARN: {{
					EndpointGroupArn:    awssdk.String(gaEndpointGroupARN),
					EndpointGroupRegion: awssdk.String("us-east-1"),
					EndpointDescriptions: []globalacceleratortypes.EndpointDescription{{
						EndpointId: awssdk.String(elbListenerARN),
					}},
				}}},
				latticeServices: []vpclatticetypes.ServiceSummary{{
					Arn:    awssdk.String(latticeServiceARN),
					Id:     awssdk.String("svc-123"),
					Name:   awssdk.String("orders"),
					Status: vpclatticetypes.ServiceStatusActive,
					DnsEntry: &vpclatticetypes.DnsEntry{
						DomainName:   awssdk.String("orders.123.vpc-lattice-svcs.us-east-1.on.aws"),
						HostedZoneId: awssdk.String("ZLATTICE"),
					},
				}},
				latticeListeners: map[string][]vpclatticetypes.ListenerSummary{"svc-123": {{
					Arn:      awssdk.String(latticeListenerARN),
					Id:       awssdk.String("listener-123"),
					Name:     awssdk.String("https"),
					Port:     awssdk.Int32(443),
					Protocol: vpclatticetypes.ListenerProtocolHttps,
				}}},
				latticeTargets: []vpclatticetypes.TargetGroupSummary{{
					Arn:           awssdk.String(latticeTargetARN),
					Id:            awssdk.String("tg-123"),
					Name:          awssdk.String("orders"),
					Port:          awssdk.Int32(8080),
					Protocol:      vpclatticetypes.TargetGroupProtocolHttp,
					ServiceArns:   []string{latticeServiceARN},
					Status:        vpclatticetypes.TargetGroupStatusActive,
					Type:          vpclatticetypes.TargetGroupTypeIp,
					VpcIdentifier: awssdk.String("vpc-123"),
				}},
				elbv2Listeners: []elbv2types.Listener{{
					ListenerArn:     awssdk.String(elbListenerARN),
					LoadBalancerArn: awssdk.String("arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/app-lb/50dc6c495c0c9188"),
					Port:            awssdk.Int32(443),
					Protocol:        elbv2types.ProtocolEnumHttps,
					DefaultActions:  []elbv2types.Action{{Type: elbv2types.ActionTypeEnumForward, TargetGroupArn: awssdk.String(elbTargetARN)}},
				}},
				elbv2TargetGroups: []elbv2types.TargetGroup{{
					TargetGroupArn:  awssdk.String(elbTargetARN),
					TargetGroupName: awssdk.String("orders"),
					Port:            awssdk.Int32(8080),
					Protocol:        elbv2types.ProtocolEnumHttp,
					TargetType:      elbv2types.TargetTypeEnumIp,
					VpcId:           awssdk.String("vpc-123"),
				}},
				originAccessCtrls: []cloudfronttypes.OriginAccessControlSummary{{
					Id:                            awssdk.String("oac-123"),
					Name:                          awssdk.String("prod-oac"),
					OriginAccessControlOriginType: cloudfronttypes.OriginAccessControlOriginTypesS3,
					SigningBehavior:               cloudfronttypes.OriginAccessControlSigningBehaviorsAlways,
					SigningProtocol:               cloudfronttypes.OriginAccessControlSigningProtocolsSigv4,
				}},
				keyGroups: []cloudfronttypes.KeyGroupSummary{{KeyGroup: &cloudfronttypes.KeyGroup{
					Id: awssdk.String("kg-123"),
					KeyGroupConfig: &cloudfronttypes.KeyGroupConfig{
						Name:  awssdk.String("prod-keys"),
						Items: []string{"pk-123"},
					},
				}}},
				publicKeys: []cloudfronttypes.PublicKeySummary{{
					Id:   awssdk.String("pk-123"),
					Name: awssdk.String("prod-public-key"),
				}},
				responsePolicies: []cloudfronttypes.ResponseHeadersPolicySummary{{ResponseHeadersPolicy: &cloudfronttypes.ResponseHeadersPolicy{
					Id: awssdk.String("rhp-123"),
					ResponseHeadersPolicyConfig: &cloudfronttypes.ResponseHeadersPolicyConfig{
						Name: awssdk.String("security-headers"),
					},
				}, Type: cloudfronttypes.ResponseHeadersPolicyTypeCustom}},
			},
			fakeAWSNetworkAPI: fakeAWSNetworkAPI{
				apiV2APIs: []apigatewayv2types.Api{{ApiId: awssdk.String(apiV2ID), Name: awssdk.String("events"), ProtocolType: apigatewayv2types.ProtocolTypeHttp}},
				apiV2Stages: map[string][]apigatewayv2types.Stage{apiV2ID: {{
					StageName:  awssdk.String("$default"),
					AutoDeploy: awssdk.Bool(true),
				}}},
				apiV2Routes: map[string][]apigatewayv2types.Route{apiV2ID: {{
					RouteId:           awssdk.String("route-123"),
					RouteKey:          awssdk.String("GET /events"),
					AuthorizationType: apigatewayv2types.AuthorizationTypeJwt,
					Target:            awssdk.String("integrations/integ-123"),
				}}},
				apiV2Integrations: map[string][]apigatewayv2types.Integration{apiV2ID: {{
					IntegrationId:   awssdk.String("integ-123"),
					IntegrationType: apigatewayv2types.IntegrationTypeHttpProxy,
					IntegrationUri:  awssdk.String("https://events.example.com"),
				}}},
			},
		},
	})
	for _, tt := range []struct {
		family string
		kind   string
		attr   string
		want   string
	}{
		{family: familyGlobalAccelerator, kind: "aws.globalaccelerator_accelerator", attr: "dns_name", want: "a123.awsglobalaccelerator.com"},
		{family: familyGAListener, kind: "aws.globalaccelerator_listener", attr: "port_ranges", want: "443"},
		{family: familyGAEndpointGroup, kind: "aws.globalaccelerator_endpoint_group", attr: "endpoint_ids", want: elbListenerARN},
		{family: familyVPCLatticeService, kind: "aws.vpclattice_service", attr: "dns_name", want: "orders.123.vpc-lattice-svcs.us-east-1.on.aws"},
		{family: familyVPCLatticeListener, kind: "aws.vpclattice_listener", attr: "service_arn", want: latticeServiceARN},
		{family: familyVPCLatticeTG, kind: "aws.vpclattice_target_group", attr: "vpc_id", want: "vpc-123"},
		{family: familyELBV2LoadBalancer, kind: "aws.elbv2_load_balancer", attr: "dns_name", want: "app-lb-123.us-east-1.elb.amazonaws.com"},
		{family: familyELBV2Listener, kind: "aws.elbv2_listener", attr: "target_group_arns", want: elbTargetARN},
		{family: familyELBV2TargetGroup, kind: "aws.elbv2_target_group", attr: "target_type", want: "ip"},
		{family: familyAPIGatewayStage, kind: "aws.apigateway_stage", attr: "stage_name", want: "$default"},
		{family: familyAPIGatewayRoute, kind: "aws.apigateway_route", attr: "route_key", want: "GET /events"},
		{family: familyAPIGatewayInteg, kind: "aws.apigateway_integration", attr: "integration_uri", want: "https://events.example.com"},
		{family: familyCloudFrontDistribution, kind: "aws.cloudfront_distribution", attr: "domain_name", want: "d111111abcdef8.cloudfront.net"},
		{family: familyCloudFrontOAC, kind: "aws.cloudfront_origin_access_control", attr: "signing_behavior", want: "always"},
		{family: familyCloudFrontKeyGroup, kind: "aws.cloudfront_key_group", attr: "public_key_ids", want: "pk-123"},
		{family: familyCloudFrontPublicKey, kind: "aws.cloudfront_public_key", attr: "public_key_id", want: "pk-123"},
		{family: familyCloudFrontRHP, kind: "aws.cloudfront_response_headers_policy", attr: "policy_type", want: "custom"},
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
func TestReadAWSBackupInventoryEvents(t *testing.T) {
	vaultARN := "arn:aws:backup:us-east-1:123456789012:backup-vault:prod-vault"
	planARN := "arn:aws:backup:us-east-1:123456789012:backup-plan:plan-123"
	recoveryPointARN := "arn:aws:backup:us-east-1:123456789012:recovery-point:rp-123"
	resourceARN := "arn:aws:rds:us-east-1:123456789012:db:orders-db"
	kmsARN := "arn:aws:kms:us-east-1:123456789012:key/key-123"
	source := newTestSource(t, fakeAWS{fakeAWSData: fakeAWSData{
		fakeAWSBackupData: fakeAWSBackupData{
			backupVaults: []backuptypes.BackupVaultListMember{{
				BackupVaultArn:         awssdk.String(vaultARN),
				BackupVaultName:        awssdk.String("prod-vault"),
				CreationDate:           timePtr("2026-04-23T00:00:00Z"),
				EncryptionKeyArn:       awssdk.String(kmsARN),
				EncryptionKeyType:      backuptypes.EncryptionKeyTypeCustomerManagedKmsKey,
				Locked:                 awssdk.Bool(true),
				MaxRetentionDays:       awssdk.Int64(365),
				MinRetentionDays:       awssdk.Int64(35),
				NumberOfRecoveryPoints: 3,
				VaultState:             backuptypes.VaultStateAvailable,
			}},
			backupVaultTags: map[string]map[string]string{vaultARN: {"Owner": "backup@writer.com"}},
			backupPlans: []backuptypes.BackupPlansListMember{{
				BackupPlanArn:  awssdk.String(planARN),
				BackupPlanId:   awssdk.String("plan-123"),
				BackupPlanName: awssdk.String("prod-plan"),
				CreationDate:   timePtr("2026-04-23T00:00:00Z"),
				VersionId:      awssdk.String("v1"),
			}},
			backupPlanDetails: map[string]backup.GetBackupPlanOutput{"plan-123": {
				BackupPlanArn: awssdk.String(planARN),
				BackupPlanId:  awssdk.String("plan-123"),
				BackupPlan: &backuptypes.BackupPlan{
					BackupPlanName: awssdk.String("prod-plan"),
					Rules: []backuptypes.BackupRule{{
						EnableContinuousBackup:  awssdk.Bool(true),
						Lifecycle:               &backuptypes.Lifecycle{DeleteAfterDays: awssdk.Int64(365), MoveToColdStorageAfterDays: awssdk.Int64(35)},
						RuleId:                  awssdk.String("rule-1"),
						RuleName:                awssdk.String("daily"),
						ScheduleExpression:      awssdk.String("cron(0 5 ? * * *)"),
						TargetBackupVaultName:   awssdk.String("prod-vault"),
						StartWindowMinutes:      awssdk.Int64(60),
						CompletionWindowMinutes: awssdk.Int64(180),
					}},
				},
			}},
			backupPlanTags: map[string]map[string]string{planARN: {"Team": "platform"}},
			backupProtectedResources: []backuptypes.ProtectedResource{{
				LastBackupTime:       timePtr("2026-04-24T00:00:00Z"),
				LastBackupVaultArn:   awssdk.String(vaultARN),
				LastRecoveryPointArn: awssdk.String(recoveryPointARN),
				ResourceArn:          awssdk.String(resourceARN),
				ResourceName:         awssdk.String("orders-db"),
				ResourceType:         awssdk.String("RDS"),
			}},
			backupRecoveryPoints: map[string][]backuptypes.RecoveryPointByBackupVault{"prod-vault": {{
				BackupVaultArn:   awssdk.String(vaultARN),
				BackupVaultName:  awssdk.String("prod-vault"),
				CreationDate:     timePtr("2026-04-24T00:00:00Z"),
				EncryptionKeyArn: awssdk.String(kmsARN),
				CreatedBy: &backuptypes.RecoveryPointCreator{
					BackupPlanArn: awssdk.String(planARN),
					BackupPlanId:  awssdk.String("plan-123"),
					BackupRuleId:  awssdk.String("rule-1"),
				},
				IamRoleArn:       awssdk.String("arn:aws:iam::123456789012:role/AWSBackupRole"),
				IsEncrypted:      true,
				Lifecycle:        &backuptypes.Lifecycle{DeleteAfterDays: awssdk.Int64(365), MoveToColdStorageAfterDays: awssdk.Int64(35)},
				RecoveryPointArn: awssdk.String(recoveryPointARN),
				ResourceArn:      awssdk.String(resourceARN),
				ResourceName:     awssdk.String("orders-db"),
				ResourceType:     awssdk.String("RDS"),
				Status:           backuptypes.RecoveryPointStatusCompleted,
			}}},
		},
	}})
	for _, tt := range []struct {
		family string
		kind   string
		attr   string
		want   string
	}{
		{family: familyBackupVault, kind: "aws.backup_vault", attr: "encryption_key_arn", want: kmsARN},
		{family: familyBackupPlan, kind: "aws.backup_plan", attr: "retention_days", want: "365"},
		{family: familyBackupProtected, kind: "aws.backup_protected_resource", attr: "last_recovery_point_arn", want: recoveryPointARN},
		{family: familyBackupRecoveryPoint, kind: "aws.backup_recovery_point", attr: "backup_plan_id", want: "plan-123"},
	} {
		t.Run(tt.family, func(t *testing.T) {
			pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"account_id": "123456789012", "family": tt.family}), nil)
			if err != nil {
				t.Fatalf("Read(%s) error = %v", tt.family, err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("len(events) = %d, want 1", len(pull.Events))
				t.Fatalf("len(Read(%s).Events) = %d, want 1", tt.family, len(pull.Events))
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

func TestReadAWSAnalyticsAndStreamingInventoryEvents(t *testing.T) {
	kmsARN := "arn:aws:kms:us-east-1:123456789012:key/key-123"
	kinesisARN := "arn:aws:kinesis:us-east-1:123456789012:stream/orders"
	firehoseARN := "arn:aws:firehose:us-east-1:123456789012:deliverystream/orders"
	mskARN := "arn:aws:kafka:us-east-1:123456789012:cluster/orders/uuid-1"
	glueDatabaseARN := "arn:aws:glue:us-east-1:123456789012:database/analytics"
	glueTableARN := "arn:aws:glue:us-east-1:123456789012:table/analytics/events"
	glueCrawlerARN := "arn:aws:glue:us-east-1:123456789012:crawler/analytics-crawler"
	glueJobARN := "arn:aws:glue:us-east-1:123456789012:job/analytics-etl"
	athenaWorkgroupARN := "arn:aws:athena:us-east-1:123456789012:workgroup/analytics"
	athenaCatalogARN := "arn:aws:athena:us-east-1:123456789012:datacatalog/AwsDataCatalog"
	source := newTestSource(t, fakeAWS{fakeAWSAnalytics: fakeAWSAnalytics{
		kinesisStreams: []kinesistypes.StreamDescriptionSummary{{
			StreamARN:               awssdk.String(kinesisARN),
			StreamName:              awssdk.String("orders"),
			StreamStatus:            kinesistypes.StreamStatusActive,
			EncryptionType:          kinesistypes.EncryptionTypeKms,
			KeyId:                   awssdk.String(kmsARN),
			RetentionPeriodHours:    awssdk.Int32(168),
			OpenShardCount:          awssdk.Int32(2),
			StreamCreationTimestamp: timePtr("2026-04-23T00:00:00Z"),
		}},
		kinesisTags:     map[string][]kinesistypes.Tag{kinesisARN: {{Key: awssdk.String("Team"), Value: awssdk.String("payments")}}},
		kinesisPolicies: map[string]string{kinesisARN: `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"kinesis:DescribeStream"}]}`},
		firehoseStreams: []firehosetypes.DeliveryStreamDescription{{
			DeliveryStreamARN:    awssdk.String(firehoseARN),
			DeliveryStreamName:   awssdk.String("orders"),
			DeliveryStreamStatus: firehosetypes.DeliveryStreamStatusActive,
			DeliveryStreamType:   firehosetypes.DeliveryStreamTypeKinesisStreamAsSource,
			CreateTimestamp:      timePtr("2026-04-23T00:00:00Z"),
			DeliveryStreamEncryptionConfiguration: &firehosetypes.DeliveryStreamEncryptionConfiguration{
				KeyARN:  awssdk.String(kmsARN),
				KeyType: firehosetypes.KeyTypeCustomerManagedCmk,
				Status:  firehosetypes.DeliveryStreamEncryptionStatusEnabled,
			},
			Destinations: []firehosetypes.DestinationDescription{{
				DestinationId: awssdk.String("destinationId-000000000001"),
				ExtendedS3DestinationDescription: &firehosetypes.ExtendedS3DestinationDescription{
					BucketARN: awssdk.String("arn:aws:s3:::prod-data"),
				},
			}},
			Source: &firehosetypes.SourceDescription{KinesisStreamSourceDescription: &firehosetypes.KinesisStreamSourceDescription{
				KinesisStreamARN: awssdk.String(kinesisARN),
			}},
		}},
		firehoseTags: map[string][]firehosetypes.Tag{"orders": {{Key: awssdk.String("Team"), Value: awssdk.String("analytics")}}},
		mskClusters: []kafkatypes.Cluster{{
			ClusterArn:   awssdk.String(mskARN),
			ClusterName:  awssdk.String("orders"),
			ClusterType:  kafkatypes.ClusterTypeProvisioned,
			CreationTime: timePtr("2026-04-23T00:00:00Z"),
			State:        kafkatypes.ClusterStateActive,
			Provisioned: &kafkatypes.Provisioned{
				BrokerNodeGroupInfo: &kafkatypes.BrokerNodeGroupInfo{
					ClientSubnets:  []string{"subnet-1", "subnet-2"},
					InstanceType:   awssdk.String("kafka.m5.large"),
					SecurityGroups: []string{"sg-msk"},
					ConnectivityInfo: &kafkatypes.ConnectivityInfo{
						PublicAccess: &kafkatypes.PublicAccess{Type: awssdk.String("SERVICE_PROVIDED_EIPS")},
					},
				},
				CurrentBrokerSoftwareInfo: &kafkatypes.BrokerSoftwareInfo{KafkaVersion: awssdk.String("3.6.0")},
				EncryptionInfo: &kafkatypes.EncryptionInfo{
					EncryptionAtRest: &kafkatypes.EncryptionAtRest{DataVolumeKMSKeyId: awssdk.String(kmsARN)},
					EncryptionInTransit: &kafkatypes.EncryptionInTransit{
						ClientBroker: kafkatypes.ClientBrokerTls,
						InCluster:    awssdk.Bool(true),
					},
				},
				NumberOfBrokerNodes: awssdk.Int32(3),
			},
			Tags: map[string]string{"Team": "streaming"},
		}},
		mskTags: map[string]map[string]string{mskARN: {"Owner": "streaming@writer.com"}},
		glueDatabases: []gluetypes.Database{{
			CatalogId:   awssdk.String("123456789012"),
			Name:        awssdk.String("analytics"),
			Description: awssdk.String("analytics warehouse"),
			LocationUri: awssdk.String("s3://prod-data/warehouse"),
			CreateTime:  timePtr("2026-04-23T00:00:00Z"),
		}},
		glueTables: map[string][]gluetypes.Table{"analytics": {{
			CatalogId:                     awssdk.String("123456789012"),
			DatabaseName:                  awssdk.String("analytics"),
			Name:                          awssdk.String("events"),
			Owner:                         awssdk.String("analytics@writer.com"),
			TableType:                     awssdk.String("EXTERNAL_TABLE"),
			CreateTime:                    timePtr("2026-04-23T00:00:00Z"),
			UpdateTime:                    timePtr("2026-04-24T00:00:00Z"),
			IsRegisteredWithLakeFormation: true,
			StorageDescriptor: &gluetypes.StorageDescriptor{
				Columns:      []gluetypes.Column{{Name: awssdk.String("event_id"), Type: awssdk.String("string")}},
				Compressed:   true,
				InputFormat:  awssdk.String("org.apache.hadoop.mapred.TextInputFormat"),
				Location:     awssdk.String("s3://prod-data/events"),
				OutputFormat: awssdk.String("org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"),
				SerdeInfo:    &gluetypes.SerDeInfo{SerializationLibrary: awssdk.String("org.openx.data.jsonserde.JsonSerDe")},
			},
		}}},
		glueCrawlers: []gluetypes.Crawler{{
			Name:         awssdk.String("analytics-crawler"),
			DatabaseName: awssdk.String("analytics"),
			Role:         awssdk.String("arn:aws:iam::123456789012:role/GlueCrawlerRole"),
			State:        gluetypes.CrawlerStateReady,
			CreationTime: timePtr("2026-04-23T00:00:00Z"),
			LastUpdated:  timePtr("2026-04-24T00:00:00Z"),
			Targets:      &gluetypes.CrawlerTargets{S3Targets: []gluetypes.S3Target{{Path: awssdk.String("s3://prod-data/events")}}},
			LastCrawl:    &gluetypes.LastCrawlInfo{Status: gluetypes.LastCrawlStatusSucceeded, StartTime: timePtr("2026-04-24T00:00:00Z")},
		}},
		glueJobs: []gluetypes.Job{{
			Name:              awssdk.String("analytics-etl"),
			Role:              awssdk.String("arn:aws:iam::123456789012:role/GlueJobRole"),
			GlueVersion:       awssdk.String("5.0"),
			WorkerType:        gluetypes.WorkerTypeG1x,
			NumberOfWorkers:   awssdk.Int32(2),
			ExecutionClass:    gluetypes.ExecutionClassStandard,
			JobMode:           gluetypes.JobModeScript,
			CreatedOn:         timePtr("2026-04-23T00:00:00Z"),
			LastModifiedOn:    timePtr("2026-04-24T00:00:00Z"),
			Command:           &gluetypes.JobCommand{Name: awssdk.String("glueetl"), ScriptLocation: awssdk.String("s3://prod-scripts/analytics.py")},
			ExecutionProperty: &gluetypes.ExecutionProperty{MaxConcurrentRuns: 2},
		}},
		glueTags: map[string]map[string]string{
			glueDatabaseARN: {"Owner": "data@writer.com"},
			glueTableARN:    {"DataClassification": "restricted"},
			glueCrawlerARN:  {"Team": "analytics"},
			glueJobARN:      {"Team": "analytics"},
		},
		athenaWorkgroups: []athenatypes.WorkGroup{{
			Name:         awssdk.String("analytics"),
			Description:  awssdk.String("analytics queries"),
			State:        athenatypes.WorkGroupStateEnabled,
			CreationTime: timePtr("2026-04-23T00:00:00Z"),
			Configuration: &athenatypes.WorkGroupConfiguration{
				EnforceWorkGroupConfiguration:   awssdk.Bool(true),
				PublishCloudWatchMetricsEnabled: awssdk.Bool(true),
				ResultConfiguration: &athenatypes.ResultConfiguration{
					OutputLocation: awssdk.String("s3://prod-athena-results/"),
					EncryptionConfiguration: &athenatypes.EncryptionConfiguration{
						EncryptionOption: athenatypes.EncryptionOptionSseKms,
						KmsKey:           awssdk.String(kmsARN),
					},
				},
			},
		}},
		athenaDataCatalogs: []athenatypes.DataCatalog{{
			Name:        awssdk.String("AwsDataCatalog"),
			Type:        athenatypes.DataCatalogTypeGlue,
			Description: awssdk.String("default glue catalog"),
			Parameters:  map[string]string{"catalog-id": "123456789012"},
			Status:      athenatypes.DataCatalogStatusCreateComplete,
		}},
		athenaTags: map[string][]athenatypes.Tag{
			athenaWorkgroupARN: {{Key: awssdk.String("Team"), Value: awssdk.String("analytics")}},
			athenaCatalogARN:   {{Key: awssdk.String("Owner"), Value: awssdk.String("data@writer.com")}},
		},
		lakeFormationResources: []lakeformationtypes.ResourceInfo{{
			ResourceArn:                  awssdk.String("arn:aws:s3:::prod-data"),
			RoleArn:                      awssdk.String("arn:aws:iam::123456789012:role/LakeFormationAccessRole"),
			ExpectedResourceOwnerAccount: awssdk.String("123456789012"),
			HybridAccessEnabled:          awssdk.Bool(true),
			WithPrivilegedAccess:         awssdk.Bool(true),
			VerificationStatus:           lakeformationtypes.VerificationStatusVerified,
			LastModified:                 timePtr("2026-04-24T00:00:00Z"),
		}},
		lakeFormationLFTags: []lakeformationtypes.LFTagPair{{
			CatalogId: awssdk.String("123456789012"),
			TagKey:    awssdk.String("sensitivity"),
			TagValues: []string{"restricted"},
		}},
		lakeFormationPermissions: []lakeformationtypes.PrincipalResourcePermissions{{
			Principal:   &lakeformationtypes.DataLakePrincipal{DataLakePrincipalIdentifier: awssdk.String("arn:aws:iam::123456789012:role/analyst")},
			Permissions: []lakeformationtypes.Permission{lakeformationtypes.PermissionSelect},
			Resource:    &lakeformationtypes.Resource{Database: &lakeformationtypes.DatabaseResource{Name: awssdk.String("analytics")}},
			LastUpdated: timePtr("2026-04-23T00:00:00Z"),
		}},
	}})
	for _, tt := range []struct {
		family string
		kind   string
		attr   string
		want   string
	}{
		{family: familyGlueDatabase, kind: "aws.glue_database", attr: "location_uri", want: "s3://prod-data/warehouse"},
		{family: familyGlueTable, kind: "aws.glue_table", attr: "is_registered_with_lakeformation", want: "true"},
		{family: familyGlueCrawler, kind: "aws.glue_crawler", attr: "role_name", want: "GlueCrawlerRole"},
		{family: familyGlueJob, kind: "aws.glue_job", attr: "command_name", want: "glueetl"},
		{family: familyAthenaWorkgroup, kind: "aws.athena_workgroup", attr: "encryption", want: "SSE_KMS"},
		{family: familyAthenaDataCatalog, kind: "aws.athena_data_catalog", attr: "glue_catalog_id", want: "123456789012"},
		{family: familyLakeFormationRes, kind: "aws.lakeformation_resource", attr: "verification_status", want: "VERIFIED"},
		{family: familyLakeFormationLFTag, kind: "aws.lakeformation_lf_tag", attr: "tag_values", want: "restricted"},
		{family: familyLakeFormationPerm, kind: "aws.lakeformation_permission", attr: "permissions", want: "SELECT"},
	} {
		t.Run(tt.family, func(t *testing.T) {
			pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"account_id": "123456789012", "family": tt.family}), nil)
			if err != nil {
				t.Fatalf("Read(%s) error = %v", tt.family, err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("len(Read(%s).Events) = %d, want 1", tt.family, len(pull.Events))
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

func TestReadAWSGovernanceInventoryEvents(t *testing.T) {
	instanceARN := "arn:aws:sso:::instance/ssoins-1234567890abcdef"
	permissionSetARN := "arn:aws:sso:::permissionSet/ssoins-1234567890abcdef/ps-admin"
	source := newTestSource(t, fakeAWS{
		fakeAWSGovernance: fakeAWSGovernance{
			organizationAccounts: []organizationstypes.Account{{
				Arn: awssdk.String("arn:aws:organizations::123456789012:account/o-example/210987654321"), Email: awssdk.String("prod@example.com"), Id: awssdk.String("210987654321"), Name: awssdk.String("Prod"), State: organizationstypes.AccountStateActive, Status: organizationstypes.AccountStatusActive,
			}},
			organizationRoots: []organizationstypes.Root{{
				Id:   awssdk.String("r-root"),
				Name: awssdk.String("Root"),
				PolicyTypes: []organizationstypes.PolicyTypeSummary{{
					Type:   organizationstypes.PolicyTypeServiceControlPolicy,
					Status: organizationstypes.PolicyTypeStatusEnabled,
				}},
			}},
			organizationOUs: map[string][]organizationstypes.OrganizationalUnit{"r-root": {{
				Arn: awssdk.String("arn:aws:organizations::123456789012:ou/o-example/ou-root-sec"), Id: awssdk.String("ou-root-sec"), Name: awssdk.String("Security"),
			}}},
			organizationParents: map[string]organizationstypes.Parent{
				"210987654321": {Id: awssdk.String("ou-root-sec"), Type: organizationstypes.ParentTypeOrganizationalUnit},
			},
			organizationPolicies: []organizationstypes.PolicySummary{{
				Arn: awssdk.String("arn:aws:organizations::123456789012:policy/o-example/service_control_policy/p-denyroot"), Id: awssdk.String("p-denyroot"), Name: awssdk.String("DenyRoot"), Type: organizationstypes.PolicyTypeServiceControlPolicy,
			}},
			organizationPolicyDetails: map[string]organizationstypes.Policy{
				"p-denyroot": {
					Content: awssdk.String(`{"Version":"2012-10-17","Statement":[]}`),
					PolicySummary: &organizationstypes.PolicySummary{
						Arn: awssdk.String("arn:aws:organizations::123456789012:policy/o-example/service_control_policy/p-denyroot"), Id: awssdk.String("p-denyroot"), Name: awssdk.String("DenyRoot"), Type: organizationstypes.PolicyTypeServiceControlPolicy,
					},
				},
			},
			organizationPolicyTargets: map[string][]organizationstypes.PolicyTargetSummary{"p-denyroot": {{TargetId: awssdk.String("210987654321"), Type: organizationstypes.TargetTypeAccount}}},
			ssoInstances:              []ssoadmintypes.InstanceMetadata{{InstanceArn: awssdk.String(instanceARN), IdentityStoreId: awssdk.String("d-1234567890"), Name: awssdk.String("writer-sso"), OwnerAccountId: awssdk.String("123456789012"), Status: ssoadmintypes.InstanceStatusActive}},
			ssoPermissionSets:         []ssoadmintypes.PermissionSet{{PermissionSetArn: awssdk.String(permissionSetARN), Name: awssdk.String("AdministratorAccess"), SessionDuration: awssdk.String("PT8H")}},
			ssoAssignments: map[string][]ssoadmintypes.AccountAssignment{
				"210987654321|" + permissionSetARN: {{AccountId: awssdk.String("210987654321"), PermissionSetArn: awssdk.String(permissionSetARN), PrincipalId: awssdk.String("user-1"), PrincipalType: ssoadmintypes.PrincipalTypeUser}},
			},
			identityUsers:  []identitystoretypes.User{{IdentityStoreId: awssdk.String("d-1234567890"), UserId: awssdk.String("user-1"), UserName: awssdk.String("alice"), DisplayName: awssdk.String("Alice Admin"), Emails: []identitystoretypes.Email{{Value: awssdk.String("alice@example.com"), Primary: true}}, UserStatus: identitystoretypes.UserStatusEnabled}},
			identityGroups: []identitystoretypes.Group{{IdentityStoreId: awssdk.String("d-1234567890"), GroupId: awssdk.String("group-1"), DisplayName: awssdk.String("Security Admins")}},
			identityMemberships: map[string][]identitystoretypes.GroupMembership{
				"group-1": {{IdentityStoreId: awssdk.String("d-1234567890"), GroupId: awssdk.String("group-1"), MembershipId: awssdk.String("membership-1"), MemberId: &identitystoretypes.MemberIdMemberUserId{Value: "user-1"}}},
			},
		},
	})
	for _, tt := range []struct {
		family string
		kind   string
		attr   string
		want   string
	}{
		{family: familyOrganizationsAcct, kind: "aws.organizations_account", attr: "organization_id", want: "o-example"},
		{family: familyOrganizationsOU, kind: "aws.organizations_organizational_unit", attr: "parent_id", want: "r-root"},
		{family: familyOrganizationsPolicy, kind: "aws.organizations_policy", attr: "target_account_ids", want: "210987654321"},
		{family: familyOrganizationsRoot, kind: "aws.organizations_root", attr: "policy_types", want: "SERVICE_CONTROL_POLICY:ENABLED"},
		{family: familySSOInstance, kind: "aws.sso_instance", attr: "identity_store_id", want: "d-1234567890"},
		{family: familySSOPermissionSet, kind: "aws.sso_permission_set", attr: "permission_set_name", want: "AdministratorAccess"},
		{family: familySSOAssignment, kind: "aws.sso_account_assignment", attr: "principal_id", want: "user-1"},
		{family: familyIdentityStoreUser, kind: "aws.identitystore_user", attr: "email", want: "alice@example.com"},
		{family: familyIdentityStoreGroup, kind: "aws.identitystore_group", attr: "group_name", want: "Security Admins"},
		{family: familyIdentityStoreMember, kind: "aws.identitystore_group_membership", attr: "member_user_id", want: "user-1"},
	} {
		t.Run(tt.family, func(t *testing.T) {
			pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"account_id": "123456789012", "family": tt.family}), nil)
			if err != nil {
				t.Fatalf("Read(%s) error = %v", tt.family, err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("len(events) = %d, want 1", len(pull.Events))
				t.Fatalf("len(Read(%s).Events) = %d, want 1", tt.family, len(pull.Events))
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

func TestReadAWSOrganizationsAccountsFallsBackWhenListDenied(t *testing.T) {
	source := newTestSource(t, fakeAWS{
		fakeAWSGovernance: fakeAWSGovernance{
			organizationAccountsError: fmt.Errorf("AccessDeniedException: denied"),
		},
	})

	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"account_id": "123456789012", "family": familyOrganizationsAcct}), nil)
	if err != nil {
		t.Fatalf("Read(organizations_account) error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	if got := pull.Events[0].Attributes["account_id"]; got != "123456789012" {
		t.Fatalf("account_id = %q, want 123456789012", got)
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

func TestListSNSTopicsDoesNotTruncateClientSide(t *testing.T) {
	topics := make([]snstypes.Topic, 0, 12)
	attributes := make(map[string]map[string]string, 12)
	for index := 0; index < 12; index++ {
		arn := "arn:aws:sns:us-east-1:123456789012:topic-" + strconv.Itoa(index)
		topics = append(topics, snstypes.Topic{TopicArn: awssdk.String(arn)})
		attributes[arn] = map[string]string{"TopicArn": arn}
	}
	records, _, err := listSNSTopics(context.Background(), awsClients{
		awsRuntimeClients: awsRuntimeClients{
			sns: fakeSNS{fake: &fakeAWS{
				fakeAWSData: fakeAWSData{
					fakeAWSCoreData: fakeAWSCoreData{
						snsTopics:     topics,
						snsAttributes: attributes,
					},
				},
			}},
		},
	}, settings{}, "", 10)
	if err != nil {
		t.Fatalf("listSNSTopics: %v", err)
	}
	if len(records) != 12 {
		t.Fatalf("len(records) = %d, want 12", len(records))
	}
}

func TestSQSQueueEventEncryptionHonorsManagedSSEValue(t *testing.T) {
	for _, tt := range []struct {
		name       string
		attrs      map[string]string
		encryption string
	}{
		{name: "kms key", attrs: map[string]string{"KmsMasterKeyId": "arn:aws:kms:us-east-1:123456789012:key/key-123"}, encryption: "true"},
		{name: "managed sse enabled", attrs: map[string]string{"SqsManagedSseEnabled": "true"}, encryption: "true"},
		{name: "managed sse disabled", attrs: map[string]string{"SqsManagedSseEnabled": "false"}, encryption: "false"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			event, err := sqsQueueEvent(settings{accountID: "123456789012", region: "us-east-1"}, awsSQSQueue{
				ARN:        "arn:aws:sqs:us-east-1:123456789012:orders",
				Name:       "orders",
				URL:        "https://sqs.us-east-1.amazonaws.com/123456789012/orders",
				Attributes: tt.attrs,
			})
			if err != nil {
				t.Fatalf("sqsQueueEvent: %v", err)
			}
			if got := event.Attributes["encryption"]; got != tt.encryption {
				t.Fatalf("encryption = %q, want %q", got, tt.encryption)
			}
		})
	}
}

func TestS3BucketLocationRegionHandlesLegacyEU(t *testing.T) {
	if got := s3BucketLocationRegion(s3types.BucketLocationConstraint("EU")); got != "eu-west-1" {
		t.Fatalf("legacy EU region = %q, want eu-west-1", got)
	}
}

func TestS3BucketPublicTreatsMissingPublicAccessBlockAsExposed(t *testing.T) {
	if !s3BucketPublic(awsS3Bucket{}) {
		t.Fatal("missing public access block should be treated as exposed")
	}
}

func TestListS3BucketsUsesBucketRegionForOptionalMetadata(t *testing.T) {
	base := fakeAWS{fakeAWSData: fakeAWSData{
		fakeAWSCoreData: fakeAWSCoreData{
			s3Buckets: []s3types.Bucket{{Name: awssdk.String("legacy-eu")}},
			s3BucketRegions: map[string]s3types.BucketLocationConstraint{
				"legacy-eu": s3types.BucketLocationConstraint("EU"),
			},
		},
	}}
	regional := fakeAWS{fakeAWSData: fakeAWSData{
		fakeAWSCoreData: fakeAWSCoreData{
			s3Tags: map[string][]s3types.Tag{"legacy-eu": {{Key: awssdk.String("owner"), Value: awssdk.String("security")}}},
			s3Encryption: map[string]*s3types.ServerSideEncryptionConfiguration{"legacy-eu": {Rules: []s3types.ServerSideEncryptionRule{{
				ApplyServerSideEncryptionByDefault: &s3types.ServerSideEncryptionByDefault{SSEAlgorithm: s3types.ServerSideEncryptionAes256},
			}}}},
			s3Versioning: map[string]s3types.BucketVersioningStatus{"legacy-eu": s3types.BucketVersioningStatusEnabled},
			s3Logging:    map[string]bool{"legacy-eu": true},
		},
	}}
	records, _, err := listS3Buckets(context.Background(), awsClients{
		awsPlatformClients: awsPlatformClients{
			cfg: awssdk.Config{Region: "us-east-1"},
			s3:  base,
			s3ByRegion: func(region string) awsS3API {
				if region != "eu-west-1" {
					t.Fatalf("regional client requested for %q, want eu-west-1", region)
				}
				return regional
			},
		},
	}, settings{region: "us-east-1"}, "", 0)
	if err != nil {
		t.Fatalf("listS3Buckets: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(records) = %d, want 1", len(records))
	}
	if records[0].Region != "eu-west-1" {
		t.Fatalf("region = %q, want eu-west-1", records[0].Region)
	}
	if records[0].Tags["owner"] != "security" {
		t.Fatalf("owner tag = %q, want security", records[0].Tags["owner"])
	}
	if records[0].Encryption != "AES256" {
		t.Fatalf("encryption = %q, want AES256", records[0].Encryption)
	}
	if records[0].Versioning != string(s3types.BucketVersioningStatusEnabled) {
		t.Fatalf("versioning = %q, want Enabled", records[0].Versioning)
	}
	if !records[0].LoggingEnabled {
		t.Fatalf("logging enabled = false, want true")
	}
}

func TestSecretEventReportsDefaultEncryption(t *testing.T) {
	event, err := secretEvent(settings{accountID: "123456789012", region: "us-east-1"}, secretsmanagertypes.SecretListEntry{
		ARN:  awssdk.String("arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/api-key-AbCd"),
		Name: awssdk.String("prod/api-key"),
	})
	if err != nil {
		t.Fatalf("secretEvent: %v", err)
	}
	if got := event.Attributes["encryption"]; got != "true" {
		t.Fatalf("encryption = %q, want true", got)
	}
	if got := event.Attributes["kms_key_id"]; got != "" {
		t.Fatalf("kms_key_id = %q, want empty for default key", got)
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
		fakeAWSNetwork: fakeAWSNetwork{
			fakeAWSNetworkExposure: fakeAWSNetworkExposure{
				securityGroups: []ec2types.SecurityGroup{{
					GroupId: awssdk.String("sg-1"), GroupName: awssdk.String("prod-web"), SecurityGroupArn: awssdk.String("arn:aws:ec2:us-east-1:123456789012:security-group/sg-1"), VpcId: awssdk.String("vpc-1"),
					IpPermissions: []ec2types.IpPermission{{
						IpProtocol: awssdk.String("tcp"), FromPort: awssdk.Int32(443), ToPort: awssdk.Int32(443), IpRanges: []ec2types.IpRange{{CidrIp: awssdk.String("0.0.0.0/0")}},
					}},
				}},
				addresses: []ec2types.Address{{AllocationId: awssdk.String("eipalloc-1"), PublicIp: awssdk.String("203.0.113.10"), NetworkInterfaceId: awssdk.String("eni-1"), InstanceId: awssdk.String("i-1")}},
			},
		},
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
		fake.samlProviders = []iamtypes.SAMLProviderListEntry{{Arn: awssdk.String("arn:aws:iam::123456789012:saml-provider/Okta")}}
		fake.samlProviderDetails = map[string]iam.GetSAMLProviderOutput{"arn:aws:iam::123456789012:saml-provider/Okta": {SAMLProviderUUID: awssdk.String("saml-uuid")}}
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
	batchData := func(fake *recordingAWS) {
		computeEnvironmentARN := "arn:aws:batch:us-east-1:123456789012:compute-environment/prod-batch"
		fake.compute.batchComputeEnvironments = []batchtypes.ComputeEnvironmentDetail{{
			ComputeEnvironmentArn:  awssdk.String(computeEnvironmentARN),
			ComputeEnvironmentName: awssdk.String("prod-batch"),
			ComputeResources:       &batchtypes.ComputeResource{MaxvCpus: awssdk.Int32(32), Subnets: []string{"subnet-batch"}, Type: batchtypes.CRTypeEc2},
			ServiceRole:            awssdk.String("arn:aws:iam::123456789012:role/service-role/AWSBatchServiceRole"),
			State:                  batchtypes.CEStateEnabled,
			Status:                 batchtypes.CEStatusValid,
			Type:                   batchtypes.CETypeManaged,
		}}
		fake.compute.batchJobQueues = []batchtypes.JobQueueDetail{{
			ComputeEnvironmentOrder: []batchtypes.ComputeEnvironmentOrder{{ComputeEnvironment: awssdk.String(computeEnvironmentARN), Order: awssdk.Int32(1)}},
			JobQueueArn:             awssdk.String("arn:aws:batch:us-east-1:123456789012:job-queue/prod-jobs"),
			JobQueueName:            awssdk.String("prod-jobs"),
			Priority:                awssdk.Int32(10),
			State:                   batchtypes.JQStateEnabled,
			Status:                  batchtypes.JQStatusValid,
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
		fake.compute.images = []ec2types.Image{{ImageId: awssdk.String("ami-123"), Name: awssdk.String("golden-web"), Public: awssdk.Bool(true)}}
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
	networkSubstrateData := func(fake *recordingAWS) {
		fake.vpcs = []ec2types.Vpc{{VpcId: awssdk.String("vpc-123")}}
		fake.subnets = []ec2types.Subnet{{SubnetId: awssdk.String("subnet-123"), VpcId: awssdk.String("vpc-123")}}
		fake.securityGroups = []ec2types.SecurityGroup{{GroupId: awssdk.String("sg-123"), VpcId: awssdk.String("vpc-123")}}
		fake.routeTables = []ec2types.RouteTable{{RouteTableId: awssdk.String("rtb-123"), VpcId: awssdk.String("vpc-123")}}
		fake.networkACLs = []ec2types.NetworkAcl{{
			NetworkAclId: awssdk.String("acl-123"),
			VpcId:        awssdk.String("vpc-123"),
			Associations: []ec2types.NetworkAclAssociation{{SubnetId: awssdk.String("subnet-123")}},
			Entries: []ec2types.NetworkAclEntry{{
				CidrBlock:  awssdk.String("0.0.0.0/0"),
				Egress:     awssdk.Bool(false),
				PortRange:  &ec2types.PortRange{From: awssdk.Int32(22), To: awssdk.Int32(22)},
				Protocol:   awssdk.String("6"),
				RuleAction: ec2types.RuleActionAllow,
			}},
		}}
		fake.internetGateways = []ec2types.InternetGateway{{InternetGatewayId: awssdk.String("igw-123")}}
		fake.natGateways = []ec2types.NatGateway{{NatGatewayId: awssdk.String("nat-123"), VpcId: awssdk.String("vpc-123"), SubnetId: awssdk.String("subnet-123")}}
		fake.flowLogs = []ec2types.FlowLog{{
			FlowLogId:              awssdk.String("fl-123"),
			FlowLogStatus:          awssdk.String("ACTIVE"),
			LogDestinationType:     ec2types.LogDestinationTypeCloudWatchLogs,
			LogGroupName:           awssdk.String("/aws/vpc/flowlogs/prod"),
			ResourceId:             awssdk.String("vpc-123"),
			TrafficType:            ec2types.TrafficTypeAll,
			DeliverLogsStatus:      awssdk.String("SUCCESS"),
			DestinationOptions:     &ec2types.DestinationOptionsResponse{FileFormat: ec2types.DestinationFileFormatPlainText},
			MaxAggregationInterval: awssdk.Int32(60),
		}}
		fake.vpcEndpoints = []ec2types.VpcEndpoint{{VpcEndpointId: awssdk.String("vpce-123"), VpcId: awssdk.String("vpc-123")}}
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
		fake.rdsDBSnapshots = []rdstypes.DBSnapshot{{DBSnapshotArn: awssdk.String("arn:aws:rds:us-east-1:123456789012:snapshot:orders-public-snapshot"), DBSnapshotIdentifier: awssdk.String("orders-public-snapshot")}}
		fake.rdsDBSnapshotAttributes = map[string][]rdstypes.DBSnapshotAttribute{"orders-public-snapshot": {{AttributeName: awssdk.String("restore"), AttributeValues: []string{"all"}}}}
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
		fake.codeBuildProjects = []string{"orders-build"}
		fake.codeBuildProjectDetail = map[string]codebuildtypes.Project{"orders-build": {
			Arn:         awssdk.String("arn:aws:codebuild:us-east-1:123456789012:project/orders-build"),
			Name:        awssdk.String("orders-build"),
			Source:      &codebuildtypes.ProjectSource{Type: codebuildtypes.SourceTypeGithub},
			Environment: &codebuildtypes.ProjectEnvironment{Type: codebuildtypes.EnvironmentTypeLinuxContainer},
		}}
		fake.codeBuildSourceCredentials = []codebuildtypes.SourceCredentialsInfo{{
			Arn:        awssdk.String("arn:aws:codebuild:us-east-1:123456789012:source/github"),
			AuthType:   codebuildtypes.AuthTypeBasicAuth,
			ServerType: codebuildtypes.ServerTypeGithub,
		}}
		openSearchARN := "arn:aws:es:us-east-1:123456789012:domain/search-prod"
		aossARN := "arn:aws:aoss:us-east-1:123456789012:collection/col-123"
		elasticacheReplicationGroupARN := "arn:aws:elasticache:us-east-1:123456789012:replicationgroup:orders-rg"
		elasticacheClusterARN := "arn:aws:elasticache:us-east-1:123456789012:cluster:orders-001"
		elasticacheSubnetGroupARN := "arn:aws:elasticache:us-east-1:123456789012:subnetgroup:cache-subnets"
		fsxARN := "arn:aws:fsx:us-east-1:123456789012:file-system/fs-123"
		fake.openSearchDomains = []opensearchtypes.DomainStatus{{ARN: awssdk.String(openSearchARN), DomainName: awssdk.String("search-prod")}}
		fake.openSearchTags = map[string][]opensearchtypes.Tag{openSearchARN: {{Key: awssdk.String("Team"), Value: awssdk.String("search")}}}
		fake.aossCollections = []opensearchserverlesstypes.CollectionDetail{{Arn: awssdk.String(aossARN), Id: awssdk.String("col-123"), Name: awssdk.String("vectors")}}
		fake.aossTags = map[string][]opensearchserverlesstypes.Tag{aossARN: {{Key: awssdk.String("Team"), Value: awssdk.String("ml")}}}
		fake.aossSecurityPolicies = []opensearchserverlesstypes.SecurityPolicyDetail{{Name: awssdk.String("vectors-encryption"), Type: opensearchserverlesstypes.SecurityPolicyTypeEncryption}}
		fake.elasticacheReplicationGroups = []elasticachetypes.ReplicationGroup{{ARN: awssdk.String(elasticacheReplicationGroupARN), ReplicationGroupId: awssdk.String("orders-rg")}}
		fake.elasticacheClusters = []elasticachetypes.CacheCluster{{ARN: awssdk.String(elasticacheClusterARN), CacheClusterId: awssdk.String("orders-001")}}
		fake.elasticacheSubnetGroups = []elasticachetypes.CacheSubnetGroup{{ARN: awssdk.String(elasticacheSubnetGroupARN), CacheSubnetGroupName: awssdk.String("cache-subnets")}}
		fake.elasticacheTags = map[string][]elasticachetypes.Tag{
			elasticacheReplicationGroupARN: {{Key: awssdk.String("Team"), Value: awssdk.String("payments")}},
			elasticacheClusterARN:          {{Key: awssdk.String("Team"), Value: awssdk.String("payments")}},
			elasticacheSubnetGroupARN:      {{Key: awssdk.String("Team"), Value: awssdk.String("payments")}},
		}
		fake.fsxFileSystems = []fsxtypes.FileSystem{{ResourceARN: awssdk.String(fsxARN), FileSystemId: awssdk.String("fs-123")}}
		fake.fsxTags = map[string][]fsxtypes.Tag{fsxARN: {{Key: awssdk.String("Team"), Value: awssdk.String("storage")}}}
		s3APARN := "arn:aws:s3:us-east-1:123456789012:accesspoint/prod-data-ap"
		mrapARN := "arn:aws:s3::123456789012:accesspoint/prod-global"
		fake.s3AccessPoints = []s3controltypes.AccessPoint{{AccessPointArn: awssdk.String(s3APARN), Bucket: awssdk.String("prod-data"), Name: awssdk.String("prod-data-ap"), NetworkOrigin: s3controltypes.NetworkOriginVpc}}
		fake.s3AccessPointDetails = map[string]*s3control.GetAccessPointOutput{"prod-data-ap": {AccessPointArn: awssdk.String(s3APARN), Bucket: awssdk.String("prod-data"), Name: awssdk.String("prod-data-ap"), NetworkOrigin: s3controltypes.NetworkOriginVpc}}
		fake.s3ControlTags = map[string][]s3controltypes.Tag{s3APARN: {{Key: awssdk.String("Owner"), Value: awssdk.String("data@writer.com")}}, mrapARN: {{Key: awssdk.String("Owner"), Value: awssdk.String("data@writer.com")}}}
		fake.s3AccessPointPublic = map[string]bool{"prod-data-ap": false}
		fake.s3MultiRegionAccessPoints = []s3controltypes.MultiRegionAccessPointReport{{Name: awssdk.String("prod-global"), Status: s3controltypes.MultiRegionAccessPointStatusReady}}
		fake.s3MultiRegionAccessPointPublic = map[string]bool{"prod-global": false}
		fake.ebsVolumes = []ec2types.Volume{{VolumeId: awssdk.String("vol-123"), State: ec2types.VolumeStateAvailable}}
		fake.ebsSnapshots = []ec2types.Snapshot{{SnapshotId: awssdk.String("snap-123"), State: ec2types.SnapshotStateCompleted}}
		fake.ebsSnapshotPublic = map[string]bool{"snap-123": false}
		fake.ebsEncryptionByDefault = true
		taskARN := "arn:aws:datasync:us-east-1:123456789012:task/task-123"
		locationARN := "arn:aws:datasync:us-east-1:123456789012:location/loc-src"
		fake.datasyncTasks = []datasynctypes.TaskListEntry{{TaskArn: awssdk.String(taskARN), Name: awssdk.String("copy-prod-data"), Status: datasynctypes.TaskStatusAvailable}}
		fake.datasyncTaskDetails = map[string]*datasync.DescribeTaskOutput{taskARN: {TaskArn: awssdk.String(taskARN), Name: awssdk.String("copy-prod-data"), Status: datasynctypes.TaskStatusAvailable}}
		fake.datasyncLocations = []datasynctypes.LocationListEntry{{LocationArn: awssdk.String(locationARN), LocationUri: awssdk.String("s3://prod-data/export")}}
		fake.datasyncLocationS3 = map[string]*datasync.DescribeLocationS3Output{locationARN: {LocationArn: awssdk.String(locationARN), LocationUri: awssdk.String("s3://prod-data/export")}}
		fake.datasyncTags = map[string][]datasynctypes.TagListEntry{taskARN: {{Key: awssdk.String("Owner"), Value: awssdk.String("storage@writer.com")}}, locationARN: {{Key: awssdk.String("Owner"), Value: awssdk.String("storage@writer.com")}}}
	}
	backupData := func(fake *recordingAWS) {
		vaultARN := "arn:aws:backup:us-east-1:123456789012:backup-vault:prod-vault"
		planARN := "arn:aws:backup:us-east-1:123456789012:backup-plan:plan-123"
		resourceARN := "arn:aws:rds:us-east-1:123456789012:db:orders-db"
		fake.backupVaults = []backuptypes.BackupVaultListMember{{BackupVaultArn: awssdk.String(vaultARN), BackupVaultName: awssdk.String("prod-vault")}}
		fake.backupVaultTags = map[string]map[string]string{vaultARN: {"Owner": "backup@writer.com"}}
		fake.backupPlans = []backuptypes.BackupPlansListMember{{BackupPlanArn: awssdk.String(planARN), BackupPlanId: awssdk.String("plan-123"), BackupPlanName: awssdk.String("prod-plan")}}
		fake.backupPlanDetails = map[string]backup.GetBackupPlanOutput{"plan-123": {BackupPlanArn: awssdk.String(planARN), BackupPlanId: awssdk.String("plan-123"), BackupPlan: &backuptypes.BackupPlan{BackupPlanName: awssdk.String("prod-plan"), Rules: []backuptypes.BackupRule{{TargetBackupVaultName: awssdk.String("prod-vault"), Lifecycle: &backuptypes.Lifecycle{DeleteAfterDays: awssdk.Int64(35)}}}}}}
		fake.backupPlanTags = map[string]map[string]string{planARN: {"Team": "platform"}}
		fake.backupProtectedResources = []backuptypes.ProtectedResource{{ResourceArn: awssdk.String(resourceARN), ResourceName: awssdk.String("orders-db"), ResourceType: awssdk.String("RDS")}}
		fake.backupRecoveryPoints = map[string][]backuptypes.RecoveryPointByBackupVault{"prod-vault": {{RecoveryPointArn: awssdk.String("arn:aws:backup:us-east-1:123456789012:recovery-point:rp-123"), BackupVaultArn: awssdk.String(vaultARN), BackupVaultName: awssdk.String("prod-vault"), ResourceArn: awssdk.String(resourceARN), ResourceType: awssdk.String("RDS")}}}
	}
	networkEdgeData := func(fake *recordingAWS) {
		acceleratorARN := "arn:aws:globalaccelerator::123456789012:accelerator/ga-123"
		gaListenerARN := "arn:aws:globalaccelerator::123456789012:accelerator/ga-123/listener/listener-123"
		latticeServiceARN := "arn:aws:vpc-lattice:us-east-1:123456789012:service/svc-123"
		restAPIID := "rest123"
		apiV2ID := "v2abc"
		fake.accelerators = []globalacceleratortypes.Accelerator{{AcceleratorArn: awssdk.String(acceleratorARN), Name: awssdk.String("prod-edge")}}
		fake.gaListeners = map[string][]globalacceleratortypes.Listener{acceleratorARN: {{ListenerArn: awssdk.String(gaListenerARN)}}}
		fake.gaEndpointGroups = map[string][]globalacceleratortypes.EndpointGroup{gaListenerARN: {{EndpointGroupArn: awssdk.String("arn:aws:globalaccelerator::123456789012:accelerator/ga-123/listener/listener-123/endpoint-group/us-east-1")}}}
		fake.latticeServices = []vpclatticetypes.ServiceSummary{{Arn: awssdk.String(latticeServiceARN), Id: awssdk.String("svc-123"), Name: awssdk.String("orders")}}
		fake.latticeListeners = map[string][]vpclatticetypes.ListenerSummary{"svc-123": {{Arn: awssdk.String("arn:aws:vpc-lattice:us-east-1:123456789012:service/svc-123/listener/listener-123"), Id: awssdk.String("listener-123")}}}
		fake.latticeTargets = []vpclatticetypes.TargetGroupSummary{{Arn: awssdk.String("arn:aws:vpc-lattice:us-east-1:123456789012:targetgroup/tg-123"), Id: awssdk.String("tg-123")}}
		fake.loadBalancers = []elbv2types.LoadBalancer{{LoadBalancerArn: awssdk.String("arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/app-lb/50dc6c495c0c9188")}}
		fake.elbv2Listeners = []elbv2types.Listener{{ListenerArn: awssdk.String("arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/app-lb/50dc6c495c0c9188/6d0ecf831eec9f09"), LoadBalancerArn: awssdk.String("arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/app-lb/50dc6c495c0c9188")}}
		fake.elbv2TargetGroups = []elbv2types.TargetGroup{{TargetGroupArn: awssdk.String("arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/orders/6d0ecf831eec9f09")}}
		fake.restAPIs = []apigatewaytypes.RestApi{{Id: awssdk.String(restAPIID), Name: awssdk.String("orders")}}
		fake.restStages = map[string][]apigatewaytypes.Stage{restAPIID: {{StageName: awssdk.String("prod")}}}
		fake.restResources = map[string][]apigatewaytypes.Resource{restAPIID: {{Id: awssdk.String("res-123"), Path: awssdk.String("/orders"), ResourceMethods: map[string]apigatewaytypes.Method{"GET": {HttpMethod: awssdk.String("GET")}}}}}
		fake.restIntegrations = map[string]apigateway.GetIntegrationOutput{awsTestAPIGatewayIntegrationKey(restAPIID, "res-123", "GET"): {Uri: awssdk.String("https://orders.internal")}}
		fake.apiV2APIs = []apigatewayv2types.Api{{ApiId: awssdk.String(apiV2ID), Name: awssdk.String("events"), ProtocolType: apigatewayv2types.ProtocolTypeHttp}}
		fake.apiV2Stages = map[string][]apigatewayv2types.Stage{apiV2ID: {{StageName: awssdk.String("$default")}}}
		fake.apiV2Routes = map[string][]apigatewayv2types.Route{apiV2ID: {{RouteId: awssdk.String("route-123"), RouteKey: awssdk.String("GET /events")}}}
		fake.apiV2Integrations = map[string][]apigatewayv2types.Integration{apiV2ID: {{IntegrationId: awssdk.String("integ-123")}}}
		fake.originAccessCtrls = []cloudfronttypes.OriginAccessControlSummary{{Id: awssdk.String("oac-123"), Name: awssdk.String("prod-oac")}}
		fake.keyGroups = []cloudfronttypes.KeyGroupSummary{{KeyGroup: &cloudfronttypes.KeyGroup{Id: awssdk.String("kg-123"), KeyGroupConfig: &cloudfronttypes.KeyGroupConfig{Name: awssdk.String("prod-keys")}}}}
		fake.publicKeys = []cloudfronttypes.PublicKeySummary{{Id: awssdk.String("pk-123"), Name: awssdk.String("prod-public-key")}}
		fake.responsePolicies = []cloudfronttypes.ResponseHeadersPolicySummary{{ResponseHeadersPolicy: &cloudfronttypes.ResponseHeadersPolicy{Id: awssdk.String("rhp-123"), ResponseHeadersPolicyConfig: &cloudfronttypes.ResponseHeadersPolicyConfig{Name: awssdk.String("security-headers")}}}}
	}
	governanceData := func(fake *recordingAWS) {
		instanceARN := "arn:aws:sso:::instance/ssoins-1234567890abcdef"
		permissionSetARN := "arn:aws:sso:::permissionSet/ssoins-1234567890abcdef/ps-admin"
		fake.organizationAccounts = []organizationstypes.Account{{Arn: awssdk.String("arn:aws:organizations::123456789012:account/o-example/210987654321"), Id: awssdk.String("210987654321"), Name: awssdk.String("Prod")}}
		fake.organizationRoots = []organizationstypes.Root{{Id: awssdk.String("r-root")}}
		fake.organizationOUs = map[string][]organizationstypes.OrganizationalUnit{"r-root": {{Id: awssdk.String("ou-root-sec"), Name: awssdk.String("Security")}}}
		fake.organizationParents = map[string]organizationstypes.Parent{"210987654321": {Id: awssdk.String("ou-root-sec"), Type: organizationstypes.ParentTypeOrganizationalUnit}}
		fake.organizationPolicies = []organizationstypes.PolicySummary{{Id: awssdk.String("p-denyroot"), Name: awssdk.String("DenyRoot"), Type: organizationstypes.PolicyTypeServiceControlPolicy}}
		fake.organizationPolicyDetails = map[string]organizationstypes.Policy{"p-denyroot": {PolicySummary: &organizationstypes.PolicySummary{Id: awssdk.String("p-denyroot"), Name: awssdk.String("DenyRoot"), Type: organizationstypes.PolicyTypeServiceControlPolicy}}}
		fake.organizationPolicyTargets = map[string][]organizationstypes.PolicyTargetSummary{"p-denyroot": {{TargetId: awssdk.String("210987654321"), Type: organizationstypes.TargetTypeAccount}}}
		fake.ssoInstances = []ssoadmintypes.InstanceMetadata{{InstanceArn: awssdk.String(instanceARN), IdentityStoreId: awssdk.String("d-1234567890")}}
		fake.ssoPermissionSets = []ssoadmintypes.PermissionSet{{PermissionSetArn: awssdk.String(permissionSetARN), Name: awssdk.String("AdministratorAccess")}}
		fake.ssoAssignments = map[string][]ssoadmintypes.AccountAssignment{"210987654321|" + permissionSetARN: {{AccountId: awssdk.String("210987654321"), PermissionSetArn: awssdk.String(permissionSetARN), PrincipalId: awssdk.String("user-1"), PrincipalType: ssoadmintypes.PrincipalTypeUser}}}
		fake.identityUsers = []identitystoretypes.User{{IdentityStoreId: awssdk.String("d-1234567890"), UserId: awssdk.String("user-1"), UserName: awssdk.String("alice"), Emails: []identitystoretypes.Email{{Value: awssdk.String("alice@example.com"), Primary: true}}}}
		fake.identityGroups = []identitystoretypes.Group{{IdentityStoreId: awssdk.String("d-1234567890"), GroupId: awssdk.String("group-1"), DisplayName: awssdk.String("Security Admins")}}
		fake.identityMemberships = map[string][]identitystoretypes.GroupMembership{"group-1": {{IdentityStoreId: awssdk.String("d-1234567890"), GroupId: awssdk.String("group-1"), MemberId: &identitystoretypes.MemberIdMemberUserId{Value: "user-1"}}}}
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
			family:  familyBatchComputeEnv,
			seed:    batchData,
			wantAPI: []string{"batch:DescribeComputeEnvironments"},
		},
		{
			family:  familyBatchJobQueue,
			seed:    batchData,
			wantAPI: []string{"batch:DescribeJobQueues"},
		},
		{
			family:  familyCodeBuildProject,
			seed:    cloudAssetData,
			wantAPI: []string{"codebuild:BatchGetProjects", "codebuild:ListProjects"},
		},
		{
			family:  familyCodeBuildSourceCredential,
			seed:    cloudAssetData,
			wantAPI: []string{"codebuild:ListSourceCredentials"},
		},
		{
			family:  familyBackupVault,
			seed:    backupData,
			wantAPI: []string{"backup:ListBackupVaults", "backup:ListTags"},
		},
		{
			family:  familyBackupPlan,
			seed:    backupData,
			wantAPI: []string{"backup:GetBackupPlan", "backup:ListBackupPlans", "backup:ListTags"},
		},
		{
			family:  familyBackupProtected,
			seed:    backupData,
			wantAPI: []string{"backup:ListProtectedResources"},
		},
		{
			family:  familyBackupRecoveryPoint,
			seed:    backupData,
			wantAPI: []string{"backup:ListBackupVaults", "backup:ListRecoveryPointsByBackupVault"},
		},
		{
			family:  familyEC2Instance,
			seed:    computeData,
			wantAPI: []string{"ec2:DescribeInstances", "iam:GetInstanceProfile"},
		},
		{
			family:  familyEC2AMI,
			seed:    computeData,
			wantAPI: []string{"ec2:DescribeImages"},
		},
		{
			family:  familyVPC,
			seed:    networkSubstrateData,
			wantAPI: []string{"ec2:DescribeVpcs"},
		},
		{
			family:  familySubnet,
			seed:    networkSubstrateData,
			wantAPI: []string{"ec2:DescribeSubnets"},
		},
		{
			family:  familySecurityGroup,
			seed:    networkSubstrateData,
			wantAPI: []string{"ec2:DescribeSecurityGroups"},
		},
		{
			family:  familyRouteTable,
			seed:    networkSubstrateData,
			wantAPI: []string{"ec2:DescribeRouteTables"},
		},
		{
			family:  familyNetworkACL,
			seed:    networkSubstrateData,
			wantAPI: []string{"ec2:DescribeNetworkAcls"},
		},
		{
			family:  familyInternetGateway,
			seed:    networkSubstrateData,
			wantAPI: []string{"ec2:DescribeInternetGateways"},
		},
		{
			family:  familyNATGateway,
			seed:    networkSubstrateData,
			wantAPI: []string{"ec2:DescribeNatGateways"},
		},
		{
			family:  familyVPCFlowLog,
			seed:    networkSubstrateData,
			wantAPI: []string{"ec2:DescribeFlowLogs"},
		},
		{
			family:  familyVPCEndpoint,
			seed:    networkSubstrateData,
			wantAPI: []string{"ec2:DescribeVpcEndpoints"},
		},
		{
			family:  familyS3Bucket,
			seed:    cloudAssetData,
			wantAPI: []string{"s3:GetBucketEncryption", "s3:GetBucketLocation", "s3:GetBucketLogging", "s3:GetBucketTagging", "s3:GetBucketVersioning", "s3:GetPublicAccessBlock", "s3:ListBuckets"},
		},
		{
			family:  familyS3AccessPoint,
			seed:    cloudAssetData,
			wantAPI: []string{"s3control:GetAccessPoint", "s3control:GetAccessPointPolicyStatus", "s3control:ListAccessPoints", "s3control:ListTagsForResource"},
		},
		{
			family:  familyS3MultiRegionAccessPoint,
			seed:    cloudAssetData,
			wantAPI: []string{"s3control:GetMultiRegionAccessPoint", "s3control:GetMultiRegionAccessPointPolicyStatus", "s3control:ListMultiRegionAccessPoints", "s3control:ListTagsForResource"},
		},
		{
			family:  familyEBSVolume,
			seed:    cloudAssetData,
			wantAPI: []string{"ec2:DescribeVolumes"},
		},
		{
			family:  familyEBSSnapshot,
			seed:    cloudAssetData,
			wantAPI: []string{"ec2:DescribeSnapshotAttribute", "ec2:DescribeSnapshots"},
		},
		{
			family:  familyEC2EBSEncryptionByDefault,
			seed:    cloudAssetData,
			wantAPI: []string{"ec2:GetEbsEncryptionByDefault"},
		},
		{
			family:  familyRDSInstance,
			seed:    cloudAssetData,
			wantAPI: []string{"rds:DescribeDBInstances"},
		},
		{
			family:  familyRDSDBSnapshot,
			seed:    cloudAssetData,
			wantAPI: []string{"rds:DescribeDBSnapshotAttributes", "rds:DescribeDBSnapshots"},
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
			family:  familyOpenSearchDomain,
			seed:    cloudAssetData,
			wantAPI: []string{"opensearch:DescribeDomains", "opensearch:ListDomainNames", "opensearch:ListTags"},
		},
		{
			family:  familyOpenSearchServerlessCollection,
			seed:    cloudAssetData,
			wantAPI: []string{"opensearchserverless:BatchGetCollection", "opensearchserverless:ListCollections", "opensearchserverless:ListTagsForResource"},
		},
		{
			family:  familyOpenSearchServerlessSecurityPolicy,
			seed:    cloudAssetData,
			wantAPI: []string{"opensearchserverless:GetSecurityPolicy", "opensearchserverless:ListSecurityPolicies"},
		},
		{
			family:  familyElastiCacheReplicationGroup,
			seed:    cloudAssetData,
			wantAPI: []string{"elasticache:DescribeReplicationGroups", "elasticache:ListTagsForResource"},
		},
		{
			family:  familyElastiCacheCluster,
			seed:    cloudAssetData,
			wantAPI: []string{"elasticache:DescribeCacheClusters", "elasticache:ListTagsForResource"},
		},
		{
			family:  familyElastiCacheSubnetGroup,
			seed:    cloudAssetData,
			wantAPI: []string{"elasticache:DescribeCacheSubnetGroups", "elasticache:ListTagsForResource"},
		},
		{
			family:  familyFSxFileSystem,
			seed:    cloudAssetData,
			wantAPI: []string{"fsx:DescribeFileSystems", "fsx:ListTagsForResource"},
		},
		{
			family:  familyDataSyncTask,
			seed:    cloudAssetData,
			wantAPI: []string{"datasync:DescribeTask", "datasync:ListTagsForResource", "datasync:ListTasks"},
		},
		{
			family:  familyDataSyncLocation,
			seed:    cloudAssetData,
			wantAPI: []string{"datasync:DescribeLocationS3", "datasync:ListLocations", "datasync:ListTagsForResource"},
		},
		{
			family:  familyOrganizationsAcct,
			seed:    governanceData,
			wantAPI: []string{"organizations:ListAccounts", "organizations:ListParents"},
		},
		{
			family:  familyOrganizationsOU,
			seed:    governanceData,
			wantAPI: []string{"organizations:ListOrganizationalUnitsForParent", "organizations:ListRoots"},
		},
		{
			family:  familyOrganizationsPolicy,
			seed:    governanceData,
			wantAPI: []string{"organizations:DescribePolicy", "organizations:ListPolicies", "organizations:ListTargetsForPolicy"},
		},
		{
			family:  familyOrganizationsRoot,
			seed:    governanceData,
			wantAPI: []string{"organizations:ListRoots"},
		},
		{
			family:  familySSOInstance,
			seed:    governanceData,
			wantAPI: []string{"sso:ListInstances"},
		},
		{
			family:  familySSOPermissionSet,
			seed:    governanceData,
			wantAPI: []string{"sso:DescribePermissionSet", "sso:ListInstances", "sso:ListPermissionSets"},
		},
		{
			family:  familySSOAssignment,
			seed:    governanceData,
			wantAPI: []string{"organizations:ListAccounts", "sso:DescribePermissionSet", "sso:ListAccountAssignments", "sso:ListInstances", "sso:ListPermissionSets"},
		},
		{
			family:  familyIdentityStoreUser,
			seed:    governanceData,
			wantAPI: []string{"identitystore:ListUsers", "sso:ListInstances"},
		},
		{
			family:  familyIdentityStoreGroup,
			seed:    governanceData,
			wantAPI: []string{"identitystore:ListGroups", "sso:ListInstances"},
		},
		{
			family:  familyIdentityStoreMember,
			seed:    governanceData,
			wantAPI: []string{"identitystore:ListGroupMemberships", "identitystore:ListGroups", "sso:ListInstances"},
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
			family:  familyGlobalAccelerator,
			seed:    networkEdgeData,
			wantAPI: []string{"globalaccelerator:ListAccelerators"},
		},
		{
			family:  familyGAListener,
			seed:    networkEdgeData,
			wantAPI: []string{"globalaccelerator:ListAccelerators", "globalaccelerator:ListListeners"},
		},
		{
			family:  familyGAEndpointGroup,
			seed:    networkEdgeData,
			wantAPI: []string{"globalaccelerator:ListAccelerators", "globalaccelerator:ListEndpointGroups", "globalaccelerator:ListListeners"},
		},
		{
			family:  familyVPCLatticeService,
			seed:    networkEdgeData,
			wantAPI: []string{"vpclattice:ListServices"},
		},
		{
			family:  familyVPCLatticeListener,
			seed:    networkEdgeData,
			wantAPI: []string{"vpclattice:ListListeners", "vpclattice:ListServices"},
		},
		{
			family:  familyVPCLatticeTG,
			seed:    networkEdgeData,
			wantAPI: []string{"vpclattice:ListTargetGroups"},
		},
		{
			family:  familyELBV2Listener,
			seed:    networkEdgeData,
			wantAPI: []string{"elasticloadbalancing:DescribeLoadBalancers", "elasticloadbalancing:DescribeListeners"},
		},
		{
			family:  familyELBV2TargetGroup,
			seed:    networkEdgeData,
			wantAPI: []string{"elasticloadbalancing:DescribeTargetGroups"},
		},
		{
			family:  familyAPIGatewayStage,
			seed:    networkEdgeData,
			wantAPI: []string{"apigateway:GetRestApis", "apigateway:GetStages", "apigatewayv2:GetApis", "apigatewayv2:GetStages"},
		},
		{
			family:  familyAPIGatewayRoute,
			seed:    networkEdgeData,
			wantAPI: []string{"apigateway:GetResources", "apigateway:GetRestApis", "apigatewayv2:GetApis", "apigatewayv2:GetRoutes"},
		},
		{
			family:  familyAPIGatewayInteg,
			seed:    networkEdgeData,
			wantAPI: []string{"apigateway:GetIntegration", "apigateway:GetResources", "apigateway:GetRestApis", "apigatewayv2:GetApis", "apigatewayv2:GetIntegrations"},
		},
		{
			family:  familyCloudFrontOAC,
			seed:    networkEdgeData,
			wantAPI: []string{"cloudfront:ListOriginAccessControls"},
		},
		{
			family:  familyCloudFrontKeyGroup,
			seed:    networkEdgeData,
			wantAPI: []string{"cloudfront:ListKeyGroups"},
		},
		{
			family:  familyCloudFrontPublicKey,
			seed:    networkEdgeData,
			wantAPI: []string{"cloudfront:ListPublicKeys"},
		},
		{
			family:  familyCloudFrontRHP,
			seed:    networkEdgeData,
			wantAPI: []string{"cloudfront:ListResponseHeadersPolicies"},
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
			family:  familyIAMSAMLProvider,
			seed:    basePrincipalData,
			wantAPI: []string{"iam:GetSAMLProvider", "iam:ListSAMLProviders"},
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

func TestListRouteTablesCapsMaxResultsAtAWSLimit(t *testing.T) {
	fake := &recordingAWS{}
	_, _, err := listRouteTables(context.Background(), awsClients{
		awsPlatformClients: awsPlatformClients{ec2: fake},
	}, settings{}, "", 200)
	if err != nil {
		t.Fatalf("listRouteTables() error = %v", err)
	}
	if len(fake.routeTableMaxResults) != 1 {
		t.Fatalf("DescribeRouteTables calls = %d, want 1", len(fake.routeTableMaxResults))
	}
	if got := fake.routeTableMaxResults[0]; got != 100 {
		t.Fatalf("DescribeRouteTables MaxResults = %d, want 100", got)
	}
}

func TestReadAWSNetworkInterfacePublicEndpointIncludesAttachedInstance(t *testing.T) {
	endpoints, _, err := listNetworkInterfacePublicEndpoints(context.Background(), awsClients{
		awsPlatformClients: awsPlatformClients{
			ec2: fakeAWS{
				fakeAWSNetwork: fakeAWSNetwork{
					fakeAWSNetworkExposure: fakeAWSNetworkExposure{
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
					},
				},
			},
		},
	}, settings{accountID: "123456789012", region: "us-east-1"}, publicEndpointCursor{}, 10)
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
		fakeAWSNetwork: fakeAWSNetwork{
			fakeAWSNetworkExposure: fakeAWSNetworkExposure{
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
			},
		},
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
		fakeAWSNetwork: fakeAWSNetwork{
			fakeAWSNetworkAPI: fakeAWSNetworkAPI{
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
			},
		},
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

func TestSSMDocumentEventSuppressesAccountIDOwner(t *testing.T) {
	baseSettings := settings{accountID: "123456789012", region: "us-east-1"}
	for _, tt := range []struct {
		name string
		doc  ssmtypes.DocumentIdentifier
		want string
	}{
		{
			name: "suppresses matching account id owner",
			doc: ssmtypes.DocumentIdentifier{
				Name:  awssdk.String("Cerebro-ConfigureAgent"),
				Owner: awssdk.String("123456789012"),
			},
			want: "",
		},
		{
			name: "suppresses other aws account id owner",
			doc: ssmtypes.DocumentIdentifier{
				Name:  awssdk.String("Cerebro-ConfigureAgent"),
				Owner: awssdk.String("210987654321"),
			},
			want: "",
		},
		{
			name: "keeps non-account owner",
			doc: ssmtypes.DocumentIdentifier{
				Name:  awssdk.String("Cerebro-ConfigureAgent"),
				Owner: awssdk.String("Amazon"),
			},
			want: "Amazon",
		},
		{
			name: "preserves owner from tags",
			doc: ssmtypes.DocumentIdentifier{
				Name:  awssdk.String("Cerebro-ConfigureAgent"),
				Owner: awssdk.String("123456789012"),
				Tags:  []ssmtypes.Tag{{Key: awssdk.String("Owner"), Value: awssdk.String("platform@writer.com")}},
			},
			want: "platform@writer.com",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			event, err := ssmDocumentEvent(baseSettings, awsSSMDocument{Document: tt.doc, Tags: ssmTagMap(tt.doc.Tags)})
			if err != nil {
				t.Fatalf("ssmDocumentEvent() error = %v", err)
			}
			if got := event.Attributes["owner"]; got != tt.want {
				t.Fatalf("owner = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSSMParameterARNNormalizesLeadingSlash(t *testing.T) {
	cfg := settings{accountID: "123456789012", region: "us-east-1"}
	for _, tt := range []struct {
		name string
		in   string
		want string
	}{
		{
			name: "keeps existing leading slash",
			in:   "/prod/api/db-password",
			want: "arn:aws:ssm:us-east-1:123456789012:parameter/prod/api/db-password",
		},
		{
			name: "adds missing leading slash",
			in:   "prod/api/db-password",
			want: "arn:aws:ssm:us-east-1:123456789012:parameter/prod/api/db-password",
		},
		{
			name: "trims whitespace before normalization",
			in:   "  prod/api/db-password  ",
			want: "arn:aws:ssm:us-east-1:123456789012:parameter/prod/api/db-password",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := ssmParameterARN(cfg, tt.in); got != tt.want {
				t.Fatalf("ssmParameterARN(%q) = %q, want %q", tt.in, got, tt.want)
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
		return awsClients{
			awsPlatformClients: awsPlatformClients{
				iam:          fake,
				cloudTrail:   fake,
				ec2:          fake,
				route53:      fake,
				cloudFront:   fake,
				elbv2:        fake,
				globalAccel:  fakeGlobalAccelerator{network: fake.fakeAWSNetwork},
				vpcLattice:   fakeVPCLattice{network: fake.fakeAWSNetwork},
				ecs:          fake,
				eks:          fakeEKS{compute: fake.compute},
				ecr:          fakeECR{fake: &fake},
				apiGateway:   fakeAPIGateway{network: fake.fakeAWSNetwork},
				apiGatewayV2: fakeAPIGatewayV2{network: fake.fakeAWSNetwork},
				lambda:       fake,
				tagging:      fake,
				s3:           fake,
			},
			awsRuntimeClients: awsRuntimeClients{
				batch:          fake,
				codeBuild:      fake,
				rds:            fake,
				kms:            fake,
				secrets:        fake,
				sqs:            fake,
				sns:            fakeSNS{fake: &fake},
				appRunner:      fakeAppRunner{runtime: fake.fakeAWSRuntime},
				stepFunctions:  fakeStepFunctions{runtime: fake.fakeAWSRuntime},
				eventBridge:    fakeEventBridge{runtime: fake.fakeAWSRuntime},
				pipes:          fakePipes{runtime: fake.fakeAWSRuntime},
				scheduler:      fakeScheduler{runtime: fake.fakeAWSRuntime},
				cloudWatch:     fakeCloudWatch{runtime: fake.fakeAWSRuntime},
				cloudWatchLogs: fakeCloudWatchLogs{runtime: fake.fakeAWSRuntime},
				ssm:            fakeSSM{runtime: fake.fakeAWSRuntime},
			},
			awsAnalyticsClients: awsAnalyticsClients{
				kinesis: fakeKinesis{fake: &fake}, firehose: fakeFirehose{fake: &fake}, kafka: fakeKafka{fake: &fake}, glue: fakeGlue{fake: &fake}, athena: fakeAthena{fake: &fake}, lake: fakeLakeFormation{fake: &fake}, redshift: fake, docdb: fakeDocDB{data: fake.fakeAWSData}, neptune: fakeNeptune{data: fake.fakeAWSData},
			},
			awsGovernanceClients: awsGovernanceClients{organizations: fake, sso: fake, identityStore: fakeIdentityStore{fake: &fake}},
			awsDataClients:       awsDataClients{elasticache: fakeElastiCache{fake: &fake}, fsx: fakeFSx{fake: &fake}, openSearch: fakeOpenSearch{fake: &fake}, openSearchServerless: fakeOpenSearchServerless{fake: &fake}},
			awsStorageClients:    awsStorageClients{s3control: fakeS3Control{fake: &fake}, datasync: fakeDataSync{fake: &fake}, backup: fake, dynamodb: fake, dynamodbStreams: fake, efs: fake},
		}, nil
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
		return awsClients{
			awsPlatformClients: awsPlatformClients{
				iam:          fake,
				cloudTrail:   fake,
				ec2:          fake,
				route53:      fake,
				cloudFront:   fake,
				elbv2:        fake,
				globalAccel:  recordingGlobalAccelerator{fake: fake},
				vpcLattice:   recordingVPCLattice{fake: fake},
				ecs:          fake,
				eks:          recordingEKS{fake: fake},
				ecr:          recordingECR{fake: fake},
				apiGateway:   recordingAPIGateway{fake: fake},
				apiGatewayV2: recordingAPIGatewayV2{fake: fake},
				lambda:       fake,
				tagging:      fake,
				s3:           fake,
			},
			awsRuntimeClients: awsRuntimeClients{
				batch:          fake,
				codeBuild:      fake,
				rds:            fake,
				kms:            fake,
				secrets:        fake,
				sqs:            fake,
				sns:            recordingSNS{fake: fake},
				appRunner:      fakeAppRunner{runtime: fake.fakeAWSRuntime},
				stepFunctions:  fakeStepFunctions{runtime: fake.fakeAWSRuntime},
				eventBridge:    fakeEventBridge{runtime: fake.fakeAWSRuntime},
				pipes:          fakePipes{runtime: fake.fakeAWSRuntime},
				scheduler:      fakeScheduler{runtime: fake.fakeAWSRuntime},
				cloudWatch:     fakeCloudWatch{runtime: fake.fakeAWSRuntime},
				cloudWatchLogs: fakeCloudWatchLogs{runtime: fake.fakeAWSRuntime},
				ssm:            fakeSSM{runtime: fake.fakeAWSRuntime},
			},
			awsAnalyticsClients: awsAnalyticsClients{
				kinesis: recordingKinesis{fake: fake}, firehose: recordingFirehose{fake: fake}, kafka: recordingKafka{fake: fake}, glue: recordingGlue{fake: fake}, athena: recordingAthena{fake: fake}, lake: recordingLakeFormation{fake: fake}, redshift: fake, docdb: recordingDocDB{fake: fake}, neptune: recordingNeptune{fake: fake},
			},
			awsGovernanceClients: awsGovernanceClients{organizations: fake, sso: fake, identityStore: recordingIdentityStore{fake: fake}},
			awsDataClients:       awsDataClients{elasticache: recordingElastiCache{fake: fake}, fsx: recordingFSx{fake: fake}, openSearch: recordingOpenSearch{fake: fake}, openSearchServerless: recordingOpenSearchServerless{fake: fake}},
			awsStorageClients:    awsStorageClients{s3control: recordingS3Control{fake: fake}, datasync: recordingDataSync{fake: fake}, backup: fake, dynamodb: fake, dynamodbStreams: fake, efs: fake},
		}, nil
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
	samlProviders          []iamtypes.SAMLProviderListEntry
	samlProviderDetails    map[string]iam.GetSAMLProviderOutput
	accessKeys             []iamtypes.AccessKeyMetadata
	accountSummary         map[string]int32
	accountPasswordPolicy  *iamtypes.PasswordPolicy
	credentialReport       fakeCredentialReport
	attachedPolicies       []iamtypes.AttachedPolicy
	managedPolicyDocuments map[string]string
	inlinePolicyNames      []string
	inlinePolicyDocuments  map[string]string
	cloudTrailEvents       []cloudtrailtypes.Event
	cloudTrailLookup       func(context.Context, *cloudtrail.LookupEventsInput) (*cloudtrail.LookupEventsOutput, error)
	compute                fakeAWSCompute
	fakeAWSNetwork
	taggedResources []resourcegroupstaggingapitypes.ResourceTagMapping
	getResources    func(context.Context, *resourcegroupstaggingapi.GetResourcesInput, ...func(*resourcegroupstaggingapi.Options)) (*resourcegroupstaggingapi.GetResourcesOutput, error)
	fakeAWSData
	fakeAWSRuntime
	fakeAWSAnalytics
	fakeAWSGovernance
}

type fakeCredentialReport struct {
	content       []byte
	err           error
	state         iamtypes.ReportStateType
	states        []iamtypes.ReportStateType
	stateIndex    *int
	generatedTime *time.Time
}

type fakeAWSNetwork struct {
	fakeAWSNetworkExposure
	fakeAWSNetworkEdge
	fakeAWSNetworkAPI
}

type fakeAWSNetworkExposure struct {
	securityGroups    []ec2types.SecurityGroup
	addresses         []ec2types.Address
	networkInterfaces []ec2types.NetworkInterface
	vpcs              []ec2types.Vpc
	subnets           []ec2types.Subnet
	routeTables       []ec2types.RouteTable
	networkACLs       []ec2types.NetworkAcl
	internetGateways  []ec2types.InternetGateway
	natGateways       []ec2types.NatGateway
	flowLogs          []ec2types.FlowLog
	vpcEndpoints      []ec2types.VpcEndpoint
	hostedZones       []route53types.HostedZone
	recordSets        []route53types.ResourceRecordSet
	distributions     []cloudfronttypes.DistributionSummary
	loadBalancers     []elbv2types.LoadBalancer
}

type fakeAWSNetworkEdge struct {
	originAccessCtrls []cloudfronttypes.OriginAccessControlSummary
	keyGroups         []cloudfronttypes.KeyGroupSummary
	publicKeys        []cloudfronttypes.PublicKeySummary
	responsePolicies  []cloudfronttypes.ResponseHeadersPolicySummary
	elbv2Listeners    []elbv2types.Listener
	elbv2TargetGroups []elbv2types.TargetGroup
	accelerators      []globalacceleratortypes.Accelerator
	gaListeners       map[string][]globalacceleratortypes.Listener
	gaEndpointGroups  map[string][]globalacceleratortypes.EndpointGroup
	latticeServices   []vpclatticetypes.ServiceSummary
	latticeListeners  map[string][]vpclatticetypes.ListenerSummary
	latticeTargets    []vpclatticetypes.TargetGroupSummary
}

type fakeAWSNetworkAPI struct {
	apiDomains        []apigatewaytypes.DomainName
	restAPIs          []apigatewaytypes.RestApi
	restStages        map[string][]apigatewaytypes.Stage
	restResources     map[string][]apigatewaytypes.Resource
	restIntegrations  map[string]apigateway.GetIntegrationOutput
	apiV2Domains      []apigatewayv2types.DomainName
	apiV2APIs         []apigatewayv2types.Api
	apiV2Stages       map[string][]apigatewayv2types.Stage
	apiV2Routes       map[string][]apigatewayv2types.Route
	apiV2Integrations map[string][]apigatewayv2types.Integration
}

// cerebro:lint:allow maxfields AWS fixture aggregates service-specific fake responses.
type fakeAWSData struct {
	fakeAWSCoreData
	fakeAWSRDSData
	fakeAWSBackupData
	fakeAWSStorageAccessData
	fakeAWSDataManager
	fakeAWSDataWarehouseData
}

type fakeAWSCoreData struct {
	s3Buckets            []s3types.Bucket
	s3BucketRegions      map[string]s3types.BucketLocationConstraint
	s3Tags               map[string][]s3types.Tag
	s3Encryption         map[string]*s3types.ServerSideEncryptionConfiguration
	s3Versioning         map[string]s3types.BucketVersioningStatus
	s3Logging            map[string]bool
	s3PublicAccessBlocks map[string]*s3types.PublicAccessBlockConfiguration
	s3OptionalError      error
	kmsKeys              []kmstypes.KeyMetadata
	kmsDescribeErrors    map[string]error
	kmsTagErrors         map[string]error
	kmsRotationErrors    map[string]error
	kmsTags              map[string][]kmstypes.Tag
	kmsRotation          map[string]bool
	secrets              []secretsmanagertypes.SecretListEntry
	sqsQueueURLs         []string
	sqsAttributes        map[string]map[string]string
	sqsTags              map[string]map[string]string
	snsTopics            []snstypes.Topic
	snsAttributes        map[string]map[string]string
	snsTags              map[string][]snstypes.Tag
	ecrRepositories      []ecrtypes.Repository
	ecrTags              map[string][]ecrtypes.Tag
}

type fakeAWSRDSData struct {
	rdsInstances            []rdstypes.DBInstance
	rdsDBSnapshots          []rdstypes.DBSnapshot
	rdsDBSnapshotAttributes map[string][]rdstypes.DBSnapshotAttribute
}

type fakeAWSBackupData struct {
	backupVaults             []backuptypes.BackupVaultListMember
	backupVaultTags          map[string]map[string]string
	backupPlans              []backuptypes.BackupPlansListMember
	backupPlanDetails        map[string]backup.GetBackupPlanOutput
	backupPlanTags           map[string]map[string]string
	backupProtectedResources []backuptypes.ProtectedResource
	backupRecoveryPoints     map[string][]backuptypes.RecoveryPointByBackupVault
}

type fakeAWSDataWarehouseData struct {
	redshiftClusters []redshifttypes.Cluster
	docdbClusters    []docdbtypes.DBCluster
	docdbInstances   []docdbtypes.DBInstance
	docdbTags        map[string][]docdbtypes.Tag
	neptuneClusters  []neptunetypes.DBCluster
	neptuneInstances []neptunetypes.DBInstance
	neptuneTags      map[string][]neptunetypes.Tag
}

type fakeAWSStorageAccessData struct {
	s3AccessPoints                 []s3controltypes.AccessPoint
	s3AccessPointDetails           map[string]*s3control.GetAccessPointOutput
	s3AccessPointPublic            map[string]bool
	s3ControlTags                  map[string][]s3controltypes.Tag
	s3MultiRegionAccessPoints      []s3controltypes.MultiRegionAccessPointReport
	s3MultiRegionAccessPointPublic map[string]bool
	fakeAWSEBSData
	dynamoDBTables               []dynamodbtypes.TableDescription
	dynamoDBTags                 map[string][]dynamodbtypes.Tag
	dynamoDBContinuousBackups    map[string]dynamodbtypes.ContinuousBackupsDescription
	dynamoDBTimeToLive           map[string]dynamodbtypes.TimeToLiveDescription
	dynamoDBBackups              []dynamodbtypes.BackupSummary
	dynamoDBStreams              []dynamodbstreamstypes.StreamDescription
	efsFileSystems               []efstypes.FileSystemDescription
	efsMountTargets              map[string][]efstypes.MountTargetDescription
	efsMountTargetSecurityGroups map[string][]string
	efsAccessPoints              []efstypes.AccessPointDescription
	datasyncTasks                []datasynctypes.TaskListEntry
	datasyncTaskDetails          map[string]*datasync.DescribeTaskOutput
	datasyncLocations            []datasynctypes.LocationListEntry
	datasyncLocationS3           map[string]*datasync.DescribeLocationS3Output
	datasyncTags                 map[string][]datasynctypes.TagListEntry
}

type fakeAWSEBSData struct {
	ebsVolumes             []ec2types.Volume
	ebsSnapshots           []ec2types.Snapshot
	ebsSnapshotPublic      map[string]bool
	ebsEncryptionByDefault bool
}

type fakeAWSDataManager struct {
	openSearchDomains            []opensearchtypes.DomainStatus
	openSearchTags               map[string][]opensearchtypes.Tag
	aossCollections              []opensearchserverlesstypes.CollectionDetail
	aossTags                     map[string][]opensearchserverlesstypes.Tag
	aossSecurityPolicies         []opensearchserverlesstypes.SecurityPolicyDetail
	elasticacheReplicationGroups []elasticachetypes.ReplicationGroup
	elasticacheClusters          []elasticachetypes.CacheCluster
	elasticacheSubnetGroups      []elasticachetypes.CacheSubnetGroup
	elasticacheTags              map[string][]elasticachetypes.Tag
	fsxFileSystems               []fsxtypes.FileSystem
	fsxTags                      map[string][]fsxtypes.Tag
}

type fakeAWSRuntime struct {
	fakeAWSRuntimeApplication
	fakeAWSRuntimeEventing
	fakeAWSRuntimeObservability
	fakeAWSRuntimeSystems
}

type fakeAWSRuntimeApplication struct {
	appRunnerSummaries         []apprunnertypes.ServiceSummary
	appRunnerServices          map[string]apprunnertypes.Service
	appRunnerTags              map[string][]apprunnertypes.Tag
	codeBuildProjects          []string
	codeBuildProjectDetail     map[string]codebuildtypes.Project
	codeBuildSourceCredentials []codebuildtypes.SourceCredentialsInfo
	sfnStateMachines           []sfntypes.StateMachineListItem
	sfnStateMachineDetails     map[string]sfn.DescribeStateMachineOutput
	sfnActivities              []sfntypes.ActivityListItem
	sfnTags                    map[string][]sfntypes.Tag
}

type fakeAWSRuntimeEventing struct {
	eventBuses         []eventbridgetypes.EventBus
	eventRules         map[string][]eventbridgetypes.Rule
	eventTargets       map[string][]eventbridgetypes.Target
	eventArchives      []eventbridgetypes.Archive
	eventTags          map[string][]eventbridgetypes.Tag
	pipes              []pipestypes.Pipe
	pipeDetails        map[string]pipes.DescribePipeOutput
	pipeTags           map[string]map[string]string
	schedulerSchedules []schedulertypes.ScheduleSummary
	schedulerGroups    []schedulertypes.ScheduleGroupSummary
	schedulerTags      map[string][]schedulertypes.Tag
}

type fakeAWSRuntimeObservability struct {
	cloudWatchMetricAlarms    []cloudwatchtypes.MetricAlarm
	cloudWatchCompositeAlarms []cloudwatchtypes.CompositeAlarm
	cloudWatchTags            map[string][]cloudwatchtypes.Tag
	logGroups                 []cloudwatchlogstypes.LogGroup
	logGroupTags              map[string]map[string]string
}

type fakeAWSRuntimeSystems struct {
	ssmInstances    []ssmtypes.InstanceInformation
	ssmDocuments    []ssmtypes.DocumentIdentifier
	ssmAssociations []ssmtypes.Association
	ssmParameters   []ssmtypes.ParameterMetadata
	ssmTags         map[string][]ssmtypes.Tag
}

type fakeAWSAnalytics struct {
	kinesisStreams           []kinesistypes.StreamDescriptionSummary
	kinesisTags              map[string][]kinesistypes.Tag
	kinesisPolicies          map[string]string
	firehoseStreams          []firehosetypes.DeliveryStreamDescription
	firehoseTags             map[string][]firehosetypes.Tag
	mskClusters              []kafkatypes.Cluster
	mskTags                  map[string]map[string]string
	glueDatabases            []gluetypes.Database
	glueTables               map[string][]gluetypes.Table
	glueCrawlers             []gluetypes.Crawler
	glueJobs                 []gluetypes.Job
	glueTags                 map[string]map[string]string
	athenaWorkgroups         []athenatypes.WorkGroup
	athenaDataCatalogs       []athenatypes.DataCatalog
	athenaTags               map[string][]athenatypes.Tag
	lakeFormationResources   []lakeformationtypes.ResourceInfo
	lakeFormationLFTags      []lakeformationtypes.LFTagPair
	lakeFormationPermissions []lakeformationtypes.PrincipalResourcePermissions
}

type fakeAWSGovernance struct {
	organizationAccounts      []organizationstypes.Account
	organizationAccountsError error
	organizationRoots         []organizationstypes.Root
	organizationOUs           map[string][]organizationstypes.OrganizationalUnit
	organizationParents       map[string]organizationstypes.Parent
	organizationPolicies      []organizationstypes.PolicySummary
	organizationPolicyDetails map[string]organizationstypes.Policy
	organizationPolicyTargets map[string][]organizationstypes.PolicyTargetSummary
	ssoInstances              []ssoadmintypes.InstanceMetadata
	ssoPermissionSets         []ssoadmintypes.PermissionSet
	ssoProvisionedAccounts    map[string][]string
	ssoAssignments            map[string][]ssoadmintypes.AccountAssignment
	identityUsers             []identitystoretypes.User
	identityGroups            []identitystoretypes.Group
	identityMemberships       map[string][]identitystoretypes.GroupMembership
}

type fakeAWSCompute struct {
	images                   []ec2types.Image
	instances                []ec2types.Instance
	instanceProfiles         map[string]iamtypes.InstanceProfile
	lambdaFunctions          []lambdatypes.FunctionConfiguration
	ecsClusters              []string
	ecsServiceARNs           map[string][]string
	ecsServices              map[string]ecstypes.Service
	ecsTaskARNs              map[string][]string
	ecsTasks                 map[string]ecstypes.Task
	ecsTaskDefinitionARNs    []string
	ecsTaskDefinitions       map[string]ecstypes.TaskDefinition
	eksClusters              []ekstypes.Cluster
	eksNodegroupNames        map[string][]string
	eksNodegroups            map[string]ekstypes.Nodegroup
	eksFargateNames          map[string][]string
	eksFargateProfiles       map[string]ekstypes.FargateProfile
	eksPodIdentityIDs        map[string][]string
	eksPodIdentities         map[string]ekstypes.PodIdentityAssociation
	batchComputeEnvironments []batchtypes.ComputeEnvironmentDetail
	batchJobQueues           []batchtypes.JobQueueDetail
}

type recordingAWS struct {
	fakeAWS
	calls                []string
	routeTableMaxResults []int32
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

func (f *recordingAWS) ListSAMLProviders(ctx context.Context, input *iam.ListSAMLProvidersInput, options ...func(*iam.Options)) (*iam.ListSAMLProvidersOutput, error) {
	f.record("iam:ListSAMLProviders")
	return f.fakeAWS.ListSAMLProviders(ctx, input, options...)
}

func (f *recordingAWS) GetSAMLProvider(ctx context.Context, input *iam.GetSAMLProviderInput, options ...func(*iam.Options)) (*iam.GetSAMLProviderOutput, error) {
	f.record("iam:GetSAMLProvider")
	return f.fakeAWS.GetSAMLProvider(ctx, input, options...)
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

func (f *recordingAWS) GetAccountSummary(ctx context.Context, input *iam.GetAccountSummaryInput, options ...func(*iam.Options)) (*iam.GetAccountSummaryOutput, error) {
	f.record("iam:GetAccountSummary")
	return f.fakeAWS.GetAccountSummary(ctx, input, options...)
}

func (f *recordingAWS) GetAccountPasswordPolicy(ctx context.Context, input *iam.GetAccountPasswordPolicyInput, options ...func(*iam.Options)) (*iam.GetAccountPasswordPolicyOutput, error) {
	f.record("iam:GetAccountPasswordPolicy")
	return f.fakeAWS.GetAccountPasswordPolicy(ctx, input, options...)
}

func (f *recordingAWS) GenerateCredentialReport(ctx context.Context, input *iam.GenerateCredentialReportInput, options ...func(*iam.Options)) (*iam.GenerateCredentialReportOutput, error) {
	f.record("iam:GenerateCredentialReport")
	return f.fakeAWS.GenerateCredentialReport(ctx, input, options...)
}

func (f *recordingAWS) GetCredentialReport(ctx context.Context, input *iam.GetCredentialReportInput, options ...func(*iam.Options)) (*iam.GetCredentialReportOutput, error) {
	f.record("iam:GetCredentialReport")
	return f.fakeAWS.GetCredentialReport(ctx, input, options...)
}

func (f *recordingAWS) ListAccounts(ctx context.Context, input *organizations.ListAccountsInput, options ...func(*organizations.Options)) (*organizations.ListAccountsOutput, error) {
	f.record("organizations:ListAccounts")
	return f.fakeAWS.ListAccounts(ctx, input, options...)
}

func (f *recordingAWS) ListRoots(ctx context.Context, input *organizations.ListRootsInput, options ...func(*organizations.Options)) (*organizations.ListRootsOutput, error) {
	f.record("organizations:ListRoots")
	return f.fakeAWS.ListRoots(ctx, input, options...)
}

func (f *recordingAWS) ListOrganizationalUnitsForParent(ctx context.Context, input *organizations.ListOrganizationalUnitsForParentInput, options ...func(*organizations.Options)) (*organizations.ListOrganizationalUnitsForParentOutput, error) {
	f.record("organizations:ListOrganizationalUnitsForParent")
	return f.fakeAWS.ListOrganizationalUnitsForParent(ctx, input, options...)
}

func (f *recordingAWS) ListParents(ctx context.Context, input *organizations.ListParentsInput, options ...func(*organizations.Options)) (*organizations.ListParentsOutput, error) {
	f.record("organizations:ListParents")
	return f.fakeAWS.ListParents(ctx, input, options...)
}

func (f *recordingAWS) ListPolicies(ctx context.Context, input *organizations.ListPoliciesInput, options ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error) {
	f.record("organizations:ListPolicies")
	return f.fakeAWS.ListPolicies(ctx, input, options...)
}

func (f *recordingAWS) DescribePolicy(ctx context.Context, input *organizations.DescribePolicyInput, options ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error) {
	f.record("organizations:DescribePolicy")
	return f.fakeAWS.DescribePolicy(ctx, input, options...)
}

func (f *recordingAWS) ListTargetsForPolicy(ctx context.Context, input *organizations.ListTargetsForPolicyInput, options ...func(*organizations.Options)) (*organizations.ListTargetsForPolicyOutput, error) {
	f.record("organizations:ListTargetsForPolicy")
	return f.fakeAWS.ListTargetsForPolicy(ctx, input, options...)
}

func (f *recordingAWS) ListInstances(ctx context.Context, input *ssoadmin.ListInstancesInput, options ...func(*ssoadmin.Options)) (*ssoadmin.ListInstancesOutput, error) {
	f.record("sso:ListInstances")
	return f.fakeAWS.ListInstances(ctx, input, options...)
}

func (f *recordingAWS) ListPermissionSets(ctx context.Context, input *ssoadmin.ListPermissionSetsInput, options ...func(*ssoadmin.Options)) (*ssoadmin.ListPermissionSetsOutput, error) {
	f.record("sso:ListPermissionSets")
	return f.fakeAWS.ListPermissionSets(ctx, input, options...)
}

func (f *recordingAWS) DescribePermissionSet(ctx context.Context, input *ssoadmin.DescribePermissionSetInput, options ...func(*ssoadmin.Options)) (*ssoadmin.DescribePermissionSetOutput, error) {
	f.record("sso:DescribePermissionSet")
	return f.fakeAWS.DescribePermissionSet(ctx, input, options...)
}

func (f *recordingAWS) ListAccountsForProvisionedPermissionSet(ctx context.Context, input *ssoadmin.ListAccountsForProvisionedPermissionSetInput, options ...func(*ssoadmin.Options)) (*ssoadmin.ListAccountsForProvisionedPermissionSetOutput, error) {
	f.record("sso:ListAccountsForProvisionedPermissionSet")
	return f.fakeAWS.ListAccountsForProvisionedPermissionSet(ctx, input, options...)
}

func (f *recordingAWS) ListAccountAssignments(ctx context.Context, input *ssoadmin.ListAccountAssignmentsInput, options ...func(*ssoadmin.Options)) (*ssoadmin.ListAccountAssignmentsOutput, error) {
	f.record("sso:ListAccountAssignments")
	return f.fakeAWS.ListAccountAssignments(ctx, input, options...)
}

func (f *recordingAWS) LookupEvents(ctx context.Context, input *cloudtrail.LookupEventsInput, options ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
	f.record("cloudtrail:LookupEvents")
	return f.fakeAWS.LookupEvents(ctx, input, options...)
}

func (f *recordingAWS) ListTables(ctx context.Context, input *dynamodb.ListTablesInput, options ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error) {
	f.record("dynamodb:ListTables")
	return f.fakeAWS.ListTables(ctx, input, options...)
}

func (f *recordingAWS) DescribeTable(ctx context.Context, input *dynamodb.DescribeTableInput, options ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
	f.record("dynamodb:DescribeTable")
	return f.fakeAWS.DescribeTable(ctx, input, options...)
}

func (f *recordingAWS) ListTagsOfResource(ctx context.Context, input *dynamodb.ListTagsOfResourceInput, options ...func(*dynamodb.Options)) (*dynamodb.ListTagsOfResourceOutput, error) {
	f.record("dynamodb:ListTagsOfResource")
	return f.fakeAWS.ListTagsOfResource(ctx, input, options...)
}

func (f *recordingAWS) DescribeContinuousBackups(ctx context.Context, input *dynamodb.DescribeContinuousBackupsInput, options ...func(*dynamodb.Options)) (*dynamodb.DescribeContinuousBackupsOutput, error) {
	f.record("dynamodb:DescribeContinuousBackups")
	return f.fakeAWS.DescribeContinuousBackups(ctx, input, options...)
}

func (f *recordingAWS) DescribeTimeToLive(ctx context.Context, input *dynamodb.DescribeTimeToLiveInput, options ...func(*dynamodb.Options)) (*dynamodb.DescribeTimeToLiveOutput, error) {
	f.record("dynamodb:DescribeTimeToLive")
	return f.fakeAWS.DescribeTimeToLive(ctx, input, options...)
}

func (f *recordingAWS) ListBackups(ctx context.Context, input *dynamodb.ListBackupsInput, options ...func(*dynamodb.Options)) (*dynamodb.ListBackupsOutput, error) {
	f.record("dynamodb:ListBackups")
	return f.fakeAWS.ListBackups(ctx, input, options...)
}

func (f *recordingAWS) ListStreams(ctx context.Context, input *dynamodbstreams.ListStreamsInput, options ...func(*dynamodbstreams.Options)) (*dynamodbstreams.ListStreamsOutput, error) {
	f.record("dynamodbstreams:ListStreams")
	return f.fakeAWS.ListStreams(ctx, input, options...)
}

func (f *recordingAWS) DescribeStream(ctx context.Context, input *dynamodbstreams.DescribeStreamInput, options ...func(*dynamodbstreams.Options)) (*dynamodbstreams.DescribeStreamOutput, error) {
	f.record("dynamodbstreams:DescribeStream")
	return f.fakeAWS.DescribeStream(ctx, input, options...)
}

func (f *recordingAWS) DescribeComputeEnvironments(ctx context.Context, input *batch.DescribeComputeEnvironmentsInput, options ...func(*batch.Options)) (*batch.DescribeComputeEnvironmentsOutput, error) {
	f.record("batch:DescribeComputeEnvironments")
	return f.fakeAWS.DescribeComputeEnvironments(ctx, input, options...)
}

func (f *recordingAWS) DescribeJobQueues(ctx context.Context, input *batch.DescribeJobQueuesInput, options ...func(*batch.Options)) (*batch.DescribeJobQueuesOutput, error) {
	f.record("batch:DescribeJobQueues")
	return f.fakeAWS.DescribeJobQueues(ctx, input, options...)
}

func (f *recordingAWS) ListProjects(ctx context.Context, input *codebuild.ListProjectsInput, options ...func(*codebuild.Options)) (*codebuild.ListProjectsOutput, error) {
	f.record("codebuild:ListProjects")
	return f.fakeAWS.ListProjects(ctx, input, options...)
}

func (f *recordingAWS) BatchGetProjects(ctx context.Context, input *codebuild.BatchGetProjectsInput, options ...func(*codebuild.Options)) (*codebuild.BatchGetProjectsOutput, error) {
	f.record("codebuild:BatchGetProjects")
	return f.fakeAWS.BatchGetProjects(ctx, input, options...)
}

func (f *recordingAWS) ListSourceCredentials(ctx context.Context, input *codebuild.ListSourceCredentialsInput, options ...func(*codebuild.Options)) (*codebuild.ListSourceCredentialsOutput, error) {
	f.record("codebuild:ListSourceCredentials")
	return f.fakeAWS.ListSourceCredentials(ctx, input, options...)
}

func (f *recordingAWS) DescribeSecurityGroups(ctx context.Context, input *ec2.DescribeSecurityGroupsInput, options ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	f.record("ec2:DescribeSecurityGroups")
	return f.fakeAWS.DescribeSecurityGroups(ctx, input, options...)
}

func (f *recordingAWS) DescribeVpcs(ctx context.Context, input *ec2.DescribeVpcsInput, options ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error) {
	f.record("ec2:DescribeVpcs")
	return f.fakeAWS.DescribeVpcs(ctx, input, options...)
}

func (f *recordingAWS) DescribeSubnets(ctx context.Context, input *ec2.DescribeSubnetsInput, options ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error) {
	f.record("ec2:DescribeSubnets")
	return f.fakeAWS.DescribeSubnets(ctx, input, options...)
}

func (f *recordingAWS) DescribeRouteTables(ctx context.Context, input *ec2.DescribeRouteTablesInput, options ...func(*ec2.Options)) (*ec2.DescribeRouteTablesOutput, error) {
	f.record("ec2:DescribeRouteTables")
	f.routeTableMaxResults = append(f.routeTableMaxResults, awssdk.ToInt32(input.MaxResults))
	return f.fakeAWS.DescribeRouteTables(ctx, input, options...)
}

func (f *recordingAWS) DescribeNetworkAcls(ctx context.Context, input *ec2.DescribeNetworkAclsInput, options ...func(*ec2.Options)) (*ec2.DescribeNetworkAclsOutput, error) {
	f.record("ec2:DescribeNetworkAcls")
	return f.fakeAWS.DescribeNetworkAcls(ctx, input, options...)
}

func (f *recordingAWS) DescribeInternetGateways(ctx context.Context, input *ec2.DescribeInternetGatewaysInput, options ...func(*ec2.Options)) (*ec2.DescribeInternetGatewaysOutput, error) {
	f.record("ec2:DescribeInternetGateways")
	return f.fakeAWS.DescribeInternetGateways(ctx, input, options...)
}

func (f *recordingAWS) DescribeNatGateways(ctx context.Context, input *ec2.DescribeNatGatewaysInput, options ...func(*ec2.Options)) (*ec2.DescribeNatGatewaysOutput, error) {
	f.record("ec2:DescribeNatGateways")
	return f.fakeAWS.DescribeNatGateways(ctx, input, options...)
}

func (f *recordingAWS) DescribeFlowLogs(ctx context.Context, input *ec2.DescribeFlowLogsInput, options ...func(*ec2.Options)) (*ec2.DescribeFlowLogsOutput, error) {
	f.record("ec2:DescribeFlowLogs")
	return f.fakeAWS.DescribeFlowLogs(ctx, input, options...)
}

func (f *recordingAWS) DescribeVpcEndpoints(ctx context.Context, input *ec2.DescribeVpcEndpointsInput, options ...func(*ec2.Options)) (*ec2.DescribeVpcEndpointsOutput, error) {
	f.record("ec2:DescribeVpcEndpoints")
	return f.fakeAWS.DescribeVpcEndpoints(ctx, input, options...)
}

func (f *recordingAWS) DescribeInstances(ctx context.Context, input *ec2.DescribeInstancesInput, options ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	f.record("ec2:DescribeInstances")
	return f.fakeAWS.DescribeInstances(ctx, input, options...)
}

func (f *recordingAWS) DescribeImages(ctx context.Context, input *ec2.DescribeImagesInput, options ...func(*ec2.Options)) (*ec2.DescribeImagesOutput, error) {
	f.record("ec2:DescribeImages")
	return f.fakeAWS.DescribeImages(ctx, input, options...)
}

func (f *recordingAWS) DescribeAddresses(ctx context.Context, input *ec2.DescribeAddressesInput, options ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
	f.record("ec2:DescribeAddresses")
	return f.fakeAWS.DescribeAddresses(ctx, input, options...)
}

func (f *recordingAWS) DescribeNetworkInterfaces(ctx context.Context, input *ec2.DescribeNetworkInterfacesInput, options ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
	f.record("ec2:DescribeNetworkInterfaces")
	return f.fakeAWS.DescribeNetworkInterfaces(ctx, input, options...)
}

func (f *recordingAWS) DescribeVolumes(ctx context.Context, input *ec2.DescribeVolumesInput, options ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error) {
	f.record("ec2:DescribeVolumes")
	return f.fakeAWS.DescribeVolumes(ctx, input, options...)
}

func (f *recordingAWS) DescribeSnapshots(ctx context.Context, input *ec2.DescribeSnapshotsInput, options ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error) {
	f.record("ec2:DescribeSnapshots")
	return f.fakeAWS.DescribeSnapshots(ctx, input, options...)
}

func (f *recordingAWS) DescribeSnapshotAttribute(ctx context.Context, input *ec2.DescribeSnapshotAttributeInput, options ...func(*ec2.Options)) (*ec2.DescribeSnapshotAttributeOutput, error) {
	f.record("ec2:DescribeSnapshotAttribute")
	return f.fakeAWS.DescribeSnapshotAttribute(ctx, input, options...)
}

func (f *recordingAWS) GetEbsEncryptionByDefault(ctx context.Context, input *ec2.GetEbsEncryptionByDefaultInput, options ...func(*ec2.Options)) (*ec2.GetEbsEncryptionByDefaultOutput, error) {
	f.record("ec2:GetEbsEncryptionByDefault")
	return f.fakeAWS.GetEbsEncryptionByDefault(ctx, input, options...)
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

func (f *recordingAWS) DescribeFileSystems(ctx context.Context, input *efs.DescribeFileSystemsInput, options ...func(*efs.Options)) (*efs.DescribeFileSystemsOutput, error) {
	f.record("efs:DescribeFileSystems")
	return f.fakeAWS.DescribeFileSystems(ctx, input, options...)
}

func (f *recordingAWS) DescribeMountTargets(ctx context.Context, input *efs.DescribeMountTargetsInput, options ...func(*efs.Options)) (*efs.DescribeMountTargetsOutput, error) {
	f.record("efs:DescribeMountTargets")
	return f.fakeAWS.DescribeMountTargets(ctx, input, options...)
}

func (f *recordingAWS) DescribeMountTargetSecurityGroups(ctx context.Context, input *efs.DescribeMountTargetSecurityGroupsInput, options ...func(*efs.Options)) (*efs.DescribeMountTargetSecurityGroupsOutput, error) {
	f.record("efs:DescribeMountTargetSecurityGroups")
	return f.fakeAWS.DescribeMountTargetSecurityGroups(ctx, input, options...)
}

func (f *recordingAWS) DescribeAccessPoints(ctx context.Context, input *efs.DescribeAccessPointsInput, options ...func(*efs.Options)) (*efs.DescribeAccessPointsOutput, error) {
	f.record("efs:DescribeAccessPoints")
	return f.fakeAWS.DescribeAccessPoints(ctx, input, options...)
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

func (f *recordingAWS) ListOriginAccessControls(ctx context.Context, input *cloudfront.ListOriginAccessControlsInput, options ...func(*cloudfront.Options)) (*cloudfront.ListOriginAccessControlsOutput, error) {
	f.record("cloudfront:ListOriginAccessControls")
	return f.fakeAWS.ListOriginAccessControls(ctx, input, options...)
}

func (f *recordingAWS) ListKeyGroups(ctx context.Context, input *cloudfront.ListKeyGroupsInput, options ...func(*cloudfront.Options)) (*cloudfront.ListKeyGroupsOutput, error) {
	f.record("cloudfront:ListKeyGroups")
	return f.fakeAWS.ListKeyGroups(ctx, input, options...)
}

func (f *recordingAWS) ListPublicKeys(ctx context.Context, input *cloudfront.ListPublicKeysInput, options ...func(*cloudfront.Options)) (*cloudfront.ListPublicKeysOutput, error) {
	f.record("cloudfront:ListPublicKeys")
	return f.fakeAWS.ListPublicKeys(ctx, input, options...)
}

func (f *recordingAWS) ListResponseHeadersPolicies(ctx context.Context, input *cloudfront.ListResponseHeadersPoliciesInput, options ...func(*cloudfront.Options)) (*cloudfront.ListResponseHeadersPoliciesOutput, error) {
	f.record("cloudfront:ListResponseHeadersPolicies")
	return f.fakeAWS.ListResponseHeadersPolicies(ctx, input, options...)
}

func (f *recordingAWS) DescribeLoadBalancers(ctx context.Context, input *elbv2.DescribeLoadBalancersInput, options ...func(*elbv2.Options)) (*elbv2.DescribeLoadBalancersOutput, error) {
	f.record("elasticloadbalancing:DescribeLoadBalancers")
	return f.fakeAWS.DescribeLoadBalancers(ctx, input, options...)
}

func (f *recordingAWS) DescribeListeners(ctx context.Context, input *elbv2.DescribeListenersInput, options ...func(*elbv2.Options)) (*elbv2.DescribeListenersOutput, error) {
	f.record("elasticloadbalancing:DescribeListeners")
	return f.fakeAWS.DescribeListeners(ctx, input, options...)
}

func (f *recordingAWS) DescribeTargetGroups(ctx context.Context, input *elbv2.DescribeTargetGroupsInput, options ...func(*elbv2.Options)) (*elbv2.DescribeTargetGroupsOutput, error) {
	f.record("elasticloadbalancing:DescribeTargetGroups")
	return f.fakeAWS.DescribeTargetGroups(ctx, input, options...)
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

func (f *recordingAWS) DescribeDBSnapshots(ctx context.Context, input *rds.DescribeDBSnapshotsInput, options ...func(*rds.Options)) (*rds.DescribeDBSnapshotsOutput, error) {
	f.record("rds:DescribeDBSnapshots")
	return f.fakeAWS.DescribeDBSnapshots(ctx, input, options...)
}

func (f *recordingAWS) DescribeDBSnapshotAttributes(ctx context.Context, input *rds.DescribeDBSnapshotAttributesInput, options ...func(*rds.Options)) (*rds.DescribeDBSnapshotAttributesOutput, error) {
	f.record("rds:DescribeDBSnapshotAttributes")
	return f.fakeAWS.DescribeDBSnapshotAttributes(ctx, input, options...)
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

type fakeAPIGateway struct {
	network fakeAWSNetwork
}

type recordingAPIGateway struct {
	fake *recordingAWS
}

func (f recordingAPIGateway) GetDomainNames(ctx context.Context, input *apigateway.GetDomainNamesInput, options ...func(*apigateway.Options)) (*apigateway.GetDomainNamesOutput, error) {
	f.fake.record("apigateway:GetDomainNames")
	return fakeAPIGateway{network: f.fake.fakeAWSNetwork}.GetDomainNames(ctx, input, options...)
}

func (f recordingAPIGateway) GetRestApis(ctx context.Context, input *apigateway.GetRestApisInput, options ...func(*apigateway.Options)) (*apigateway.GetRestApisOutput, error) {
	f.fake.record("apigateway:GetRestApis")
	return fakeAPIGateway{network: f.fake.fakeAWSNetwork}.GetRestApis(ctx, input, options...)
}

func (f recordingAPIGateway) GetStages(ctx context.Context, input *apigateway.GetStagesInput, options ...func(*apigateway.Options)) (*apigateway.GetStagesOutput, error) {
	f.fake.record("apigateway:GetStages")
	return fakeAPIGateway{network: f.fake.fakeAWSNetwork}.GetStages(ctx, input, options...)
}

func (f recordingAPIGateway) GetResources(ctx context.Context, input *apigateway.GetResourcesInput, options ...func(*apigateway.Options)) (*apigateway.GetResourcesOutput, error) {
	f.fake.record("apigateway:GetResources")
	return fakeAPIGateway{network: f.fake.fakeAWSNetwork}.GetResources(ctx, input, options...)
}

func (f recordingAPIGateway) GetIntegration(ctx context.Context, input *apigateway.GetIntegrationInput, options ...func(*apigateway.Options)) (*apigateway.GetIntegrationOutput, error) {
	f.fake.record("apigateway:GetIntegration")
	return fakeAPIGateway{network: f.fake.fakeAWSNetwork}.GetIntegration(ctx, input, options...)
}

func (f fakeAPIGateway) GetDomainNames(_ context.Context, _ *apigateway.GetDomainNamesInput, _ ...func(*apigateway.Options)) (*apigateway.GetDomainNamesOutput, error) {
	return &apigateway.GetDomainNamesOutput{Items: f.network.apiDomains}, nil
}

func (f fakeAPIGateway) GetRestApis(_ context.Context, _ *apigateway.GetRestApisInput, _ ...func(*apigateway.Options)) (*apigateway.GetRestApisOutput, error) {
	return &apigateway.GetRestApisOutput{Items: f.network.restAPIs}, nil
}

func (f fakeAPIGateway) GetStages(_ context.Context, input *apigateway.GetStagesInput, _ ...func(*apigateway.Options)) (*apigateway.GetStagesOutput, error) {
	return &apigateway.GetStagesOutput{Item: f.network.restStages[awssdk.ToString(input.RestApiId)]}, nil
}

func (f fakeAPIGateway) GetResources(_ context.Context, input *apigateway.GetResourcesInput, _ ...func(*apigateway.Options)) (*apigateway.GetResourcesOutput, error) {
	return &apigateway.GetResourcesOutput{Items: f.network.restResources[awssdk.ToString(input.RestApiId)]}, nil
}

func (f fakeAPIGateway) GetIntegration(_ context.Context, input *apigateway.GetIntegrationInput, _ ...func(*apigateway.Options)) (*apigateway.GetIntegrationOutput, error) {
	if f.network.restIntegrations != nil {
		out := f.network.restIntegrations[awsTestAPIGatewayIntegrationKey(awssdk.ToString(input.RestApiId), awssdk.ToString(input.ResourceId), awssdk.ToString(input.HttpMethod))]
		return &out, nil
	}
	return &apigateway.GetIntegrationOutput{}, nil
}
func (f *recordingAWS) ListBackupVaults(ctx context.Context, input *backup.ListBackupVaultsInput, options ...func(*backup.Options)) (*backup.ListBackupVaultsOutput, error) {
	f.record("backup:ListBackupVaults")
	return f.fakeAWS.ListBackupVaults(ctx, input, options...)
}

func (f *recordingAWS) ListBackupPlans(ctx context.Context, input *backup.ListBackupPlansInput, options ...func(*backup.Options)) (*backup.ListBackupPlansOutput, error) {
	f.record("backup:ListBackupPlans")
	return f.fakeAWS.ListBackupPlans(ctx, input, options...)
}

func (f *recordingAWS) GetBackupPlan(ctx context.Context, input *backup.GetBackupPlanInput, options ...func(*backup.Options)) (*backup.GetBackupPlanOutput, error) {
	f.record("backup:GetBackupPlan")
	return f.fakeAWS.GetBackupPlan(ctx, input, options...)
}

func (f *recordingAWS) ListProtectedResources(ctx context.Context, input *backup.ListProtectedResourcesInput, options ...func(*backup.Options)) (*backup.ListProtectedResourcesOutput, error) {
	f.record("backup:ListProtectedResources")
	return f.fakeAWS.ListProtectedResources(ctx, input, options...)
}

func (f *recordingAWS) ListRecoveryPointsByBackupVault(ctx context.Context, input *backup.ListRecoveryPointsByBackupVaultInput, options ...func(*backup.Options)) (*backup.ListRecoveryPointsByBackupVaultOutput, error) {
	f.record("backup:ListRecoveryPointsByBackupVault")
	return f.fakeAWS.ListRecoveryPointsByBackupVault(ctx, input, options...)
}

func (f *recordingAWS) ListTags(ctx context.Context, input *backup.ListTagsInput, options ...func(*backup.Options)) (*backup.ListTagsOutput, error) {
	f.record("backup:ListTags")
	return f.fakeAWS.ListTags(ctx, input, options...)
}

type recordingAPIGatewayV2 struct {
	fake *recordingAWS
}

func (f recordingAPIGatewayV2) GetApis(ctx context.Context, input *apigatewayv2.GetApisInput, options ...func(*apigatewayv2.Options)) (*apigatewayv2.GetApisOutput, error) {
	f.fake.record("apigatewayv2:GetApis")
	return fakeAPIGatewayV2{network: f.fake.fakeAWSNetwork}.GetApis(ctx, input, options...)
}

func (f recordingAPIGatewayV2) GetDomainNames(ctx context.Context, input *apigatewayv2.GetDomainNamesInput, options ...func(*apigatewayv2.Options)) (*apigatewayv2.GetDomainNamesOutput, error) {
	f.fake.record("apigatewayv2:GetDomainNames")
	return fakeAPIGatewayV2{network: f.fake.fakeAWSNetwork}.GetDomainNames(ctx, input, options...)
}

func (f recordingAPIGatewayV2) GetStages(ctx context.Context, input *apigatewayv2.GetStagesInput, options ...func(*apigatewayv2.Options)) (*apigatewayv2.GetStagesOutput, error) {
	f.fake.record("apigatewayv2:GetStages")
	return fakeAPIGatewayV2{network: f.fake.fakeAWSNetwork}.GetStages(ctx, input, options...)
}

func (f recordingAPIGatewayV2) GetRoutes(ctx context.Context, input *apigatewayv2.GetRoutesInput, options ...func(*apigatewayv2.Options)) (*apigatewayv2.GetRoutesOutput, error) {
	f.fake.record("apigatewayv2:GetRoutes")
	return fakeAPIGatewayV2{network: f.fake.fakeAWSNetwork}.GetRoutes(ctx, input, options...)
}

func (f recordingAPIGatewayV2) GetIntegrations(ctx context.Context, input *apigatewayv2.GetIntegrationsInput, options ...func(*apigatewayv2.Options)) (*apigatewayv2.GetIntegrationsOutput, error) {
	f.fake.record("apigatewayv2:GetIntegrations")
	return fakeAPIGatewayV2{network: f.fake.fakeAWSNetwork}.GetIntegrations(ctx, input, options...)
}

type fakeS3Control struct {
	fake *fakeAWS
}

type recordingS3Control struct {
	fake *recordingAWS
}

func (f recordingS3Control) ListAccessPoints(ctx context.Context, input *s3control.ListAccessPointsInput, options ...func(*s3control.Options)) (*s3control.ListAccessPointsOutput, error) {
	f.fake.record("s3control:ListAccessPoints")
	return fakeS3Control{fake: &f.fake.fakeAWS}.ListAccessPoints(ctx, input, options...)
}

func (f recordingS3Control) GetAccessPoint(ctx context.Context, input *s3control.GetAccessPointInput, options ...func(*s3control.Options)) (*s3control.GetAccessPointOutput, error) {
	f.fake.record("s3control:GetAccessPoint")
	return fakeS3Control{fake: &f.fake.fakeAWS}.GetAccessPoint(ctx, input, options...)
}

func (f recordingS3Control) GetAccessPointPolicyStatus(ctx context.Context, input *s3control.GetAccessPointPolicyStatusInput, options ...func(*s3control.Options)) (*s3control.GetAccessPointPolicyStatusOutput, error) {
	f.fake.record("s3control:GetAccessPointPolicyStatus")
	return fakeS3Control{fake: &f.fake.fakeAWS}.GetAccessPointPolicyStatus(ctx, input, options...)
}

func (f recordingS3Control) ListMultiRegionAccessPoints(ctx context.Context, input *s3control.ListMultiRegionAccessPointsInput, options ...func(*s3control.Options)) (*s3control.ListMultiRegionAccessPointsOutput, error) {
	f.fake.record("s3control:ListMultiRegionAccessPoints")
	return fakeS3Control{fake: &f.fake.fakeAWS}.ListMultiRegionAccessPoints(ctx, input, options...)
}

func (f recordingS3Control) GetMultiRegionAccessPoint(ctx context.Context, input *s3control.GetMultiRegionAccessPointInput, options ...func(*s3control.Options)) (*s3control.GetMultiRegionAccessPointOutput, error) {
	f.fake.record("s3control:GetMultiRegionAccessPoint")
	return fakeS3Control{fake: &f.fake.fakeAWS}.GetMultiRegionAccessPoint(ctx, input, options...)
}

func (f recordingS3Control) GetMultiRegionAccessPointPolicyStatus(ctx context.Context, input *s3control.GetMultiRegionAccessPointPolicyStatusInput, options ...func(*s3control.Options)) (*s3control.GetMultiRegionAccessPointPolicyStatusOutput, error) {
	f.fake.record("s3control:GetMultiRegionAccessPointPolicyStatus")
	return fakeS3Control{fake: &f.fake.fakeAWS}.GetMultiRegionAccessPointPolicyStatus(ctx, input, options...)
}

func (f recordingS3Control) ListTagsForResource(ctx context.Context, input *s3control.ListTagsForResourceInput, options ...func(*s3control.Options)) (*s3control.ListTagsForResourceOutput, error) {
	f.fake.record("s3control:ListTagsForResource")
	return fakeS3Control{fake: &f.fake.fakeAWS}.ListTagsForResource(ctx, input, options...)
}

func (f fakeS3Control) ListAccessPoints(_ context.Context, input *s3control.ListAccessPointsInput, _ ...func(*s3control.Options)) (*s3control.ListAccessPointsOutput, error) {
	records, next := paginateS3AccessPoints(f.fake.s3AccessPoints, awssdk.ToString(input.NextToken), int(input.MaxResults))
	return &s3control.ListAccessPointsOutput{AccessPointList: records, NextToken: stringPtr(next)}, nil
}

func (f fakeS3Control) GetAccessPoint(_ context.Context, input *s3control.GetAccessPointInput, _ ...func(*s3control.Options)) (*s3control.GetAccessPointOutput, error) {
	if f.fake.s3AccessPointDetails != nil {
		if detail := f.fake.s3AccessPointDetails[awssdk.ToString(input.Name)]; detail != nil {
			return detail, nil
		}
	}
	return &s3control.GetAccessPointOutput{Name: input.Name}, nil
}

func (f fakeS3Control) GetAccessPointPolicyStatus(_ context.Context, input *s3control.GetAccessPointPolicyStatusInput, _ ...func(*s3control.Options)) (*s3control.GetAccessPointPolicyStatusOutput, error) {
	return &s3control.GetAccessPointPolicyStatusOutput{PolicyStatus: &s3controltypes.PolicyStatus{IsPublic: f.fake.s3AccessPointPublic[awssdk.ToString(input.Name)]}}, nil
}

func (f fakeS3Control) ListMultiRegionAccessPoints(_ context.Context, input *s3control.ListMultiRegionAccessPointsInput, _ ...func(*s3control.Options)) (*s3control.ListMultiRegionAccessPointsOutput, error) {
	records, next := paginateS3MultiRegionAccessPoints(f.fake.s3MultiRegionAccessPoints, awssdk.ToString(input.NextToken), int(input.MaxResults))
	return &s3control.ListMultiRegionAccessPointsOutput{AccessPoints: records, NextToken: stringPtr(next)}, nil
}

func (f fakeS3Control) GetMultiRegionAccessPoint(_ context.Context, input *s3control.GetMultiRegionAccessPointInput, _ ...func(*s3control.Options)) (*s3control.GetMultiRegionAccessPointOutput, error) {
	name := awssdk.ToString(input.Name)
	for _, report := range f.fake.s3MultiRegionAccessPoints {
		if awssdk.ToString(report.Name) == name {
			copy := report
			return &s3control.GetMultiRegionAccessPointOutput{AccessPoint: &copy}, nil
		}
	}
	return &s3control.GetMultiRegionAccessPointOutput{}, nil
}

func (f fakeS3Control) GetMultiRegionAccessPointPolicyStatus(_ context.Context, input *s3control.GetMultiRegionAccessPointPolicyStatusInput, _ ...func(*s3control.Options)) (*s3control.GetMultiRegionAccessPointPolicyStatusOutput, error) {
	return &s3control.GetMultiRegionAccessPointPolicyStatusOutput{Established: &s3controltypes.PolicyStatus{IsPublic: f.fake.s3MultiRegionAccessPointPublic[awssdk.ToString(input.Name)]}}, nil
}

func (f fakeS3Control) ListTagsForResource(_ context.Context, input *s3control.ListTagsForResourceInput, _ ...func(*s3control.Options)) (*s3control.ListTagsForResourceOutput, error) {
	return &s3control.ListTagsForResourceOutput{Tags: f.fake.s3ControlTags[awssdk.ToString(input.ResourceArn)]}, nil
}

type fakeDataSync struct {
	fake *fakeAWS
}

type recordingDataSync struct {
	fake *recordingAWS
}

func (f recordingDataSync) ListTasks(ctx context.Context, input *datasync.ListTasksInput, options ...func(*datasync.Options)) (*datasync.ListTasksOutput, error) {
	f.fake.record("datasync:ListTasks")
	return fakeDataSync{fake: &f.fake.fakeAWS}.ListTasks(ctx, input, options...)
}

func (f recordingDataSync) DescribeTask(ctx context.Context, input *datasync.DescribeTaskInput, options ...func(*datasync.Options)) (*datasync.DescribeTaskOutput, error) {
	f.fake.record("datasync:DescribeTask")
	return fakeDataSync{fake: &f.fake.fakeAWS}.DescribeTask(ctx, input, options...)
}

func (f recordingDataSync) ListLocations(ctx context.Context, input *datasync.ListLocationsInput, options ...func(*datasync.Options)) (*datasync.ListLocationsOutput, error) {
	f.fake.record("datasync:ListLocations")
	return fakeDataSync{fake: &f.fake.fakeAWS}.ListLocations(ctx, input, options...)
}

func (f recordingDataSync) DescribeLocationS3(ctx context.Context, input *datasync.DescribeLocationS3Input, options ...func(*datasync.Options)) (*datasync.DescribeLocationS3Output, error) {
	f.fake.record("datasync:DescribeLocationS3")
	return fakeDataSync{fake: &f.fake.fakeAWS}.DescribeLocationS3(ctx, input, options...)
}

func (f recordingDataSync) DescribeLocationEfs(ctx context.Context, input *datasync.DescribeLocationEfsInput, options ...func(*datasync.Options)) (*datasync.DescribeLocationEfsOutput, error) {
	f.fake.record("datasync:DescribeLocationEfs")
	return fakeDataSync{fake: &f.fake.fakeAWS}.DescribeLocationEfs(ctx, input, options...)
}

func (f recordingDataSync) DescribeLocationFsxLustre(ctx context.Context, input *datasync.DescribeLocationFsxLustreInput, options ...func(*datasync.Options)) (*datasync.DescribeLocationFsxLustreOutput, error) {
	f.fake.record("datasync:DescribeLocationFsxLustre")
	return fakeDataSync{fake: &f.fake.fakeAWS}.DescribeLocationFsxLustre(ctx, input, options...)
}

func (f recordingDataSync) DescribeLocationFsxOntap(ctx context.Context, input *datasync.DescribeLocationFsxOntapInput, options ...func(*datasync.Options)) (*datasync.DescribeLocationFsxOntapOutput, error) {
	f.fake.record("datasync:DescribeLocationFsxOntap")
	return fakeDataSync{fake: &f.fake.fakeAWS}.DescribeLocationFsxOntap(ctx, input, options...)
}

func (f recordingDataSync) DescribeLocationFsxOpenZfs(ctx context.Context, input *datasync.DescribeLocationFsxOpenZfsInput, options ...func(*datasync.Options)) (*datasync.DescribeLocationFsxOpenZfsOutput, error) {
	f.fake.record("datasync:DescribeLocationFsxOpenZfs")
	return fakeDataSync{fake: &f.fake.fakeAWS}.DescribeLocationFsxOpenZfs(ctx, input, options...)
}

func (f recordingDataSync) DescribeLocationFsxWindows(ctx context.Context, input *datasync.DescribeLocationFsxWindowsInput, options ...func(*datasync.Options)) (*datasync.DescribeLocationFsxWindowsOutput, error) {
	f.fake.record("datasync:DescribeLocationFsxWindows")
	return fakeDataSync{fake: &f.fake.fakeAWS}.DescribeLocationFsxWindows(ctx, input, options...)
}

func (f recordingDataSync) DescribeLocationNfs(ctx context.Context, input *datasync.DescribeLocationNfsInput, options ...func(*datasync.Options)) (*datasync.DescribeLocationNfsOutput, error) {
	f.fake.record("datasync:DescribeLocationNfs")
	return fakeDataSync{fake: &f.fake.fakeAWS}.DescribeLocationNfs(ctx, input, options...)
}

func (f recordingDataSync) DescribeLocationSmb(ctx context.Context, input *datasync.DescribeLocationSmbInput, options ...func(*datasync.Options)) (*datasync.DescribeLocationSmbOutput, error) {
	f.fake.record("datasync:DescribeLocationSmb")
	return fakeDataSync{fake: &f.fake.fakeAWS}.DescribeLocationSmb(ctx, input, options...)
}

func (f recordingDataSync) DescribeLocationObjectStorage(ctx context.Context, input *datasync.DescribeLocationObjectStorageInput, options ...func(*datasync.Options)) (*datasync.DescribeLocationObjectStorageOutput, error) {
	f.fake.record("datasync:DescribeLocationObjectStorage")
	return fakeDataSync{fake: &f.fake.fakeAWS}.DescribeLocationObjectStorage(ctx, input, options...)
}

func (f recordingDataSync) DescribeLocationHdfs(ctx context.Context, input *datasync.DescribeLocationHdfsInput, options ...func(*datasync.Options)) (*datasync.DescribeLocationHdfsOutput, error) {
	f.fake.record("datasync:DescribeLocationHdfs")
	return fakeDataSync{fake: &f.fake.fakeAWS}.DescribeLocationHdfs(ctx, input, options...)
}

func (f recordingDataSync) DescribeLocationAzureBlob(ctx context.Context, input *datasync.DescribeLocationAzureBlobInput, options ...func(*datasync.Options)) (*datasync.DescribeLocationAzureBlobOutput, error) {
	f.fake.record("datasync:DescribeLocationAzureBlob")
	return fakeDataSync{fake: &f.fake.fakeAWS}.DescribeLocationAzureBlob(ctx, input, options...)
}

func (f recordingDataSync) ListTagsForResource(ctx context.Context, input *datasync.ListTagsForResourceInput, options ...func(*datasync.Options)) (*datasync.ListTagsForResourceOutput, error) {
	f.fake.record("datasync:ListTagsForResource")
	return fakeDataSync{fake: &f.fake.fakeAWS}.ListTagsForResource(ctx, input, options...)
}

func (f fakeDataSync) ListTasks(_ context.Context, input *datasync.ListTasksInput, _ ...func(*datasync.Options)) (*datasync.ListTasksOutput, error) {
	records, next := paginateDataSyncTasks(f.fake.datasyncTasks, awssdk.ToString(input.NextToken), int(awssdk.ToInt32(input.MaxResults)))
	return &datasync.ListTasksOutput{Tasks: records, NextToken: stringPtr(next)}, nil
}

func (f fakeDataSync) DescribeTask(_ context.Context, input *datasync.DescribeTaskInput, _ ...func(*datasync.Options)) (*datasync.DescribeTaskOutput, error) {
	if f.fake.datasyncTaskDetails != nil {
		if task := f.fake.datasyncTaskDetails[awssdk.ToString(input.TaskArn)]; task != nil {
			return task, nil
		}
	}
	return &datasync.DescribeTaskOutput{TaskArn: input.TaskArn}, nil
}

func (f fakeDataSync) ListLocations(_ context.Context, input *datasync.ListLocationsInput, _ ...func(*datasync.Options)) (*datasync.ListLocationsOutput, error) {
	records, next := paginateDataSyncLocations(f.fake.datasyncLocations, awssdk.ToString(input.NextToken), int(awssdk.ToInt32(input.MaxResults)))
	return &datasync.ListLocationsOutput{Locations: records, NextToken: stringPtr(next)}, nil
}

func (f fakeDataSync) DescribeLocationS3(_ context.Context, input *datasync.DescribeLocationS3Input, _ ...func(*datasync.Options)) (*datasync.DescribeLocationS3Output, error) {
	if f.fake.datasyncLocationS3 != nil {
		if location := f.fake.datasyncLocationS3[awssdk.ToString(input.LocationArn)]; location != nil {
			return location, nil
		}
	}
	return &datasync.DescribeLocationS3Output{LocationArn: input.LocationArn}, nil
}

func (f fakeDataSync) ListTagsForResource(_ context.Context, input *datasync.ListTagsForResourceInput, _ ...func(*datasync.Options)) (*datasync.ListTagsForResourceOutput, error) {
	return &datasync.ListTagsForResourceOutput{Tags: f.fake.datasyncTags[awssdk.ToString(input.ResourceArn)]}, nil
}

func (f fakeDataSync) DescribeLocationEfs(context.Context, *datasync.DescribeLocationEfsInput, ...func(*datasync.Options)) (*datasync.DescribeLocationEfsOutput, error) {
	return &datasync.DescribeLocationEfsOutput{}, nil
}

func (f fakeDataSync) DescribeLocationFsxLustre(context.Context, *datasync.DescribeLocationFsxLustreInput, ...func(*datasync.Options)) (*datasync.DescribeLocationFsxLustreOutput, error) {
	return &datasync.DescribeLocationFsxLustreOutput{}, nil
}

func (f fakeDataSync) DescribeLocationFsxOntap(context.Context, *datasync.DescribeLocationFsxOntapInput, ...func(*datasync.Options)) (*datasync.DescribeLocationFsxOntapOutput, error) {
	return &datasync.DescribeLocationFsxOntapOutput{}, nil
}

func (f fakeDataSync) DescribeLocationFsxOpenZfs(context.Context, *datasync.DescribeLocationFsxOpenZfsInput, ...func(*datasync.Options)) (*datasync.DescribeLocationFsxOpenZfsOutput, error) {
	return &datasync.DescribeLocationFsxOpenZfsOutput{}, nil
}

func (f fakeDataSync) DescribeLocationFsxWindows(context.Context, *datasync.DescribeLocationFsxWindowsInput, ...func(*datasync.Options)) (*datasync.DescribeLocationFsxWindowsOutput, error) {
	return &datasync.DescribeLocationFsxWindowsOutput{}, nil
}

func (f fakeDataSync) DescribeLocationNfs(context.Context, *datasync.DescribeLocationNfsInput, ...func(*datasync.Options)) (*datasync.DescribeLocationNfsOutput, error) {
	return &datasync.DescribeLocationNfsOutput{}, nil
}

func (f fakeDataSync) DescribeLocationSmb(context.Context, *datasync.DescribeLocationSmbInput, ...func(*datasync.Options)) (*datasync.DescribeLocationSmbOutput, error) {
	return &datasync.DescribeLocationSmbOutput{}, nil
}

func (f fakeDataSync) DescribeLocationObjectStorage(context.Context, *datasync.DescribeLocationObjectStorageInput, ...func(*datasync.Options)) (*datasync.DescribeLocationObjectStorageOutput, error) {
	return &datasync.DescribeLocationObjectStorageOutput{}, nil
}

func (f fakeDataSync) DescribeLocationHdfs(context.Context, *datasync.DescribeLocationHdfsInput, ...func(*datasync.Options)) (*datasync.DescribeLocationHdfsOutput, error) {
	return &datasync.DescribeLocationHdfsOutput{}, nil
}

func (f fakeDataSync) DescribeLocationAzureBlob(context.Context, *datasync.DescribeLocationAzureBlobInput, ...func(*datasync.Options)) (*datasync.DescribeLocationAzureBlobOutput, error) {
	return &datasync.DescribeLocationAzureBlobOutput{}, nil
}

type fakeSNS struct {
	fake *fakeAWS
}

type fakeGlobalAccelerator struct {
	network fakeAWSNetwork
}

type recordingGlobalAccelerator struct {
	fake *recordingAWS
}

func (f recordingGlobalAccelerator) ListAccelerators(ctx context.Context, input *globalaccelerator.ListAcceleratorsInput, options ...func(*globalaccelerator.Options)) (*globalaccelerator.ListAcceleratorsOutput, error) {
	f.fake.record("globalaccelerator:ListAccelerators")
	return fakeGlobalAccelerator{network: f.fake.fakeAWSNetwork}.ListAccelerators(ctx, input, options...)
}

func (f recordingGlobalAccelerator) ListListeners(ctx context.Context, input *globalaccelerator.ListListenersInput, options ...func(*globalaccelerator.Options)) (*globalaccelerator.ListListenersOutput, error) {
	f.fake.record("globalaccelerator:ListListeners")
	return fakeGlobalAccelerator{network: f.fake.fakeAWSNetwork}.ListListeners(ctx, input, options...)
}

func (f recordingGlobalAccelerator) ListEndpointGroups(ctx context.Context, input *globalaccelerator.ListEndpointGroupsInput, options ...func(*globalaccelerator.Options)) (*globalaccelerator.ListEndpointGroupsOutput, error) {
	f.fake.record("globalaccelerator:ListEndpointGroups")
	return fakeGlobalAccelerator{network: f.fake.fakeAWSNetwork}.ListEndpointGroups(ctx, input, options...)
}

func (f fakeGlobalAccelerator) ListAccelerators(context.Context, *globalaccelerator.ListAcceleratorsInput, ...func(*globalaccelerator.Options)) (*globalaccelerator.ListAcceleratorsOutput, error) {
	return &globalaccelerator.ListAcceleratorsOutput{Accelerators: f.network.accelerators}, nil
}

func (f fakeGlobalAccelerator) ListListeners(_ context.Context, input *globalaccelerator.ListListenersInput, _ ...func(*globalaccelerator.Options)) (*globalaccelerator.ListListenersOutput, error) {
	return &globalaccelerator.ListListenersOutput{Listeners: f.network.gaListeners[awssdk.ToString(input.AcceleratorArn)]}, nil
}

func (f fakeGlobalAccelerator) ListEndpointGroups(_ context.Context, input *globalaccelerator.ListEndpointGroupsInput, _ ...func(*globalaccelerator.Options)) (*globalaccelerator.ListEndpointGroupsOutput, error) {
	return &globalaccelerator.ListEndpointGroupsOutput{EndpointGroups: f.network.gaEndpointGroups[awssdk.ToString(input.ListenerArn)]}, nil
}

type fakeVPCLattice struct {
	network fakeAWSNetwork
}

type recordingVPCLattice struct {
	fake *recordingAWS
}

func (f recordingVPCLattice) ListServices(ctx context.Context, input *vpclattice.ListServicesInput, options ...func(*vpclattice.Options)) (*vpclattice.ListServicesOutput, error) {
	f.fake.record("vpclattice:ListServices")
	return fakeVPCLattice{network: f.fake.fakeAWSNetwork}.ListServices(ctx, input, options...)
}

func (f recordingVPCLattice) ListListeners(ctx context.Context, input *vpclattice.ListListenersInput, options ...func(*vpclattice.Options)) (*vpclattice.ListListenersOutput, error) {
	f.fake.record("vpclattice:ListListeners")
	return fakeVPCLattice{network: f.fake.fakeAWSNetwork}.ListListeners(ctx, input, options...)
}

func (f recordingVPCLattice) ListTargetGroups(ctx context.Context, input *vpclattice.ListTargetGroupsInput, options ...func(*vpclattice.Options)) (*vpclattice.ListTargetGroupsOutput, error) {
	f.fake.record("vpclattice:ListTargetGroups")
	return fakeVPCLattice{network: f.fake.fakeAWSNetwork}.ListTargetGroups(ctx, input, options...)
}

func (f fakeVPCLattice) ListServices(context.Context, *vpclattice.ListServicesInput, ...func(*vpclattice.Options)) (*vpclattice.ListServicesOutput, error) {
	return &vpclattice.ListServicesOutput{Items: f.network.latticeServices}, nil
}

func (f fakeVPCLattice) ListListeners(_ context.Context, input *vpclattice.ListListenersInput, _ ...func(*vpclattice.Options)) (*vpclattice.ListListenersOutput, error) {
	return &vpclattice.ListListenersOutput{Items: f.network.latticeListeners[awssdk.ToString(input.ServiceIdentifier)]}, nil
}

func (f fakeVPCLattice) ListTargetGroups(context.Context, *vpclattice.ListTargetGroupsInput, ...func(*vpclattice.Options)) (*vpclattice.ListTargetGroupsOutput, error) {
	return &vpclattice.ListTargetGroupsOutput{Items: f.network.latticeTargets}, nil
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

type fakeAppRunner struct {
	runtime fakeAWSRuntime
}

func (f fakeAppRunner) ListServices(context.Context, *apprunner.ListServicesInput, ...func(*apprunner.Options)) (*apprunner.ListServicesOutput, error) {
	return &apprunner.ListServicesOutput{ServiceSummaryList: f.runtime.appRunnerSummaries}, nil
}

func (f fakeAppRunner) DescribeService(_ context.Context, input *apprunner.DescribeServiceInput, _ ...func(*apprunner.Options)) (*apprunner.DescribeServiceOutput, error) {
	service := f.runtime.appRunnerServices[awssdk.ToString(input.ServiceArn)]
	return &apprunner.DescribeServiceOutput{Service: &service}, nil
}

func (f fakeAppRunner) ListTagsForResource(_ context.Context, input *apprunner.ListTagsForResourceInput, _ ...func(*apprunner.Options)) (*apprunner.ListTagsForResourceOutput, error) {
	return &apprunner.ListTagsForResourceOutput{Tags: f.runtime.appRunnerTags[awssdk.ToString(input.ResourceArn)]}, nil
}

type fakeStepFunctions struct {
	runtime fakeAWSRuntime
}

func (f fakeStepFunctions) ListStateMachines(context.Context, *sfn.ListStateMachinesInput, ...func(*sfn.Options)) (*sfn.ListStateMachinesOutput, error) {
	return &sfn.ListStateMachinesOutput{StateMachines: f.runtime.sfnStateMachines}, nil
}

func (f fakeStepFunctions) DescribeStateMachine(_ context.Context, input *sfn.DescribeStateMachineInput, _ ...func(*sfn.Options)) (*sfn.DescribeStateMachineOutput, error) {
	detail := f.runtime.sfnStateMachineDetails[awssdk.ToString(input.StateMachineArn)]
	return &detail, nil
}

func (f fakeStepFunctions) ListActivities(context.Context, *sfn.ListActivitiesInput, ...func(*sfn.Options)) (*sfn.ListActivitiesOutput, error) {
	return &sfn.ListActivitiesOutput{Activities: f.runtime.sfnActivities}, nil
}

func (f fakeStepFunctions) ListTagsForResource(_ context.Context, input *sfn.ListTagsForResourceInput, _ ...func(*sfn.Options)) (*sfn.ListTagsForResourceOutput, error) {
	return &sfn.ListTagsForResourceOutput{Tags: f.runtime.sfnTags[awssdk.ToString(input.ResourceArn)]}, nil
}

type fakeEventBridge struct {
	runtime fakeAWSRuntime
}

func (f fakeEventBridge) ListEventBuses(context.Context, *eventbridge.ListEventBusesInput, ...func(*eventbridge.Options)) (*eventbridge.ListEventBusesOutput, error) {
	return &eventbridge.ListEventBusesOutput{EventBuses: f.runtime.eventBuses}, nil
}

func (f fakeEventBridge) ListRules(_ context.Context, input *eventbridge.ListRulesInput, _ ...func(*eventbridge.Options)) (*eventbridge.ListRulesOutput, error) {
	return &eventbridge.ListRulesOutput{Rules: f.runtime.eventRules[awssdk.ToString(input.EventBusName)]}, nil
}

func (f fakeEventBridge) ListTargetsByRule(_ context.Context, input *eventbridge.ListTargetsByRuleInput, _ ...func(*eventbridge.Options)) (*eventbridge.ListTargetsByRuleOutput, error) {
	key := awssdk.ToString(input.EventBusName) + "/" + awssdk.ToString(input.Rule)
	return &eventbridge.ListTargetsByRuleOutput{Targets: f.runtime.eventTargets[key]}, nil
}

func (f fakeEventBridge) ListArchives(context.Context, *eventbridge.ListArchivesInput, ...func(*eventbridge.Options)) (*eventbridge.ListArchivesOutput, error) {
	return &eventbridge.ListArchivesOutput{Archives: f.runtime.eventArchives}, nil
}

func (f fakeEventBridge) ListTagsForResource(_ context.Context, input *eventbridge.ListTagsForResourceInput, _ ...func(*eventbridge.Options)) (*eventbridge.ListTagsForResourceOutput, error) {
	return &eventbridge.ListTagsForResourceOutput{Tags: f.runtime.eventTags[awssdk.ToString(input.ResourceARN)]}, nil
}

type fakePipes struct {
	runtime fakeAWSRuntime
}

func (f fakePipes) ListPipes(context.Context, *pipes.ListPipesInput, ...func(*pipes.Options)) (*pipes.ListPipesOutput, error) {
	return &pipes.ListPipesOutput{Pipes: f.runtime.pipes}, nil
}

func (f fakePipes) DescribePipe(_ context.Context, input *pipes.DescribePipeInput, _ ...func(*pipes.Options)) (*pipes.DescribePipeOutput, error) {
	detail := f.runtime.pipeDetails[awssdk.ToString(input.Name)]
	return &detail, nil
}

func (f fakePipes) ListTagsForResource(_ context.Context, input *pipes.ListTagsForResourceInput, _ ...func(*pipes.Options)) (*pipes.ListTagsForResourceOutput, error) {
	return &pipes.ListTagsForResourceOutput{Tags: f.runtime.pipeTags[awssdk.ToString(input.ResourceArn)]}, nil
}

type fakeScheduler struct {
	runtime fakeAWSRuntime
}

func (f fakeScheduler) ListSchedules(context.Context, *scheduler.ListSchedulesInput, ...func(*scheduler.Options)) (*scheduler.ListSchedulesOutput, error) {
	return &scheduler.ListSchedulesOutput{Schedules: f.runtime.schedulerSchedules}, nil
}

func (f fakeScheduler) ListScheduleGroups(context.Context, *scheduler.ListScheduleGroupsInput, ...func(*scheduler.Options)) (*scheduler.ListScheduleGroupsOutput, error) {
	return &scheduler.ListScheduleGroupsOutput{ScheduleGroups: f.runtime.schedulerGroups}, nil
}

func (f fakeScheduler) ListTagsForResource(_ context.Context, input *scheduler.ListTagsForResourceInput, _ ...func(*scheduler.Options)) (*scheduler.ListTagsForResourceOutput, error) {
	return &scheduler.ListTagsForResourceOutput{Tags: f.runtime.schedulerTags[awssdk.ToString(input.ResourceArn)]}, nil
}

type fakeCloudWatch struct {
	runtime fakeAWSRuntime
}

func (f fakeCloudWatch) DescribeAlarms(context.Context, *cloudwatch.DescribeAlarmsInput, ...func(*cloudwatch.Options)) (*cloudwatch.DescribeAlarmsOutput, error) {
	return &cloudwatch.DescribeAlarmsOutput{MetricAlarms: f.runtime.cloudWatchMetricAlarms, CompositeAlarms: f.runtime.cloudWatchCompositeAlarms}, nil
}

func (f fakeCloudWatch) ListTagsForResource(_ context.Context, input *cloudwatch.ListTagsForResourceInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.ListTagsForResourceOutput, error) {
	return &cloudwatch.ListTagsForResourceOutput{Tags: f.runtime.cloudWatchTags[awssdk.ToString(input.ResourceARN)]}, nil
}

type fakeCloudWatchLogs struct {
	runtime fakeAWSRuntime
}

func (f fakeCloudWatchLogs) DescribeLogGroups(context.Context, *cloudwatchlogs.DescribeLogGroupsInput, ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeLogGroupsOutput, error) {
	return &cloudwatchlogs.DescribeLogGroupsOutput{LogGroups: f.runtime.logGroups}, nil
}

func (f fakeCloudWatchLogs) ListTagsForResource(_ context.Context, input *cloudwatchlogs.ListTagsForResourceInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.ListTagsForResourceOutput, error) {
	return &cloudwatchlogs.ListTagsForResourceOutput{Tags: f.runtime.logGroupTags[awssdk.ToString(input.ResourceArn)]}, nil
}

type fakeSSM struct {
	runtime fakeAWSRuntime
}

func (f fakeSSM) DescribeInstanceInformation(context.Context, *ssm.DescribeInstanceInformationInput, ...func(*ssm.Options)) (*ssm.DescribeInstanceInformationOutput, error) {
	return &ssm.DescribeInstanceInformationOutput{InstanceInformationList: f.runtime.ssmInstances}, nil
}

func (f fakeSSM) ListDocuments(context.Context, *ssm.ListDocumentsInput, ...func(*ssm.Options)) (*ssm.ListDocumentsOutput, error) {
	return &ssm.ListDocumentsOutput{DocumentIdentifiers: f.runtime.ssmDocuments}, nil
}

func (f fakeSSM) ListAssociations(context.Context, *ssm.ListAssociationsInput, ...func(*ssm.Options)) (*ssm.ListAssociationsOutput, error) {
	return &ssm.ListAssociationsOutput{Associations: f.runtime.ssmAssociations}, nil
}

func (f fakeSSM) DescribeParameters(context.Context, *ssm.DescribeParametersInput, ...func(*ssm.Options)) (*ssm.DescribeParametersOutput, error) {
	return &ssm.DescribeParametersOutput{Parameters: f.runtime.ssmParameters}, nil
}

func (f fakeSSM) ListTagsForResource(_ context.Context, input *ssm.ListTagsForResourceInput, _ ...func(*ssm.Options)) (*ssm.ListTagsForResourceOutput, error) {
	return &ssm.ListTagsForResourceOutput{TagList: f.runtime.ssmTags[string(input.ResourceType)+"/"+awssdk.ToString(input.ResourceId)]}, nil
}

type fakeDocDB struct {
	data fakeAWSData
}

type recordingDocDB struct {
	fake *recordingAWS
}

func (f recordingDocDB) DescribeDBClusters(ctx context.Context, input *docdb.DescribeDBClustersInput, options ...func(*docdb.Options)) (*docdb.DescribeDBClustersOutput, error) {
	f.fake.record("docdb:DescribeDBClusters")
	return fakeDocDB{data: f.fake.fakeAWSData}.DescribeDBClusters(ctx, input, options...)
}

func (f recordingDocDB) DescribeDBInstances(ctx context.Context, input *docdb.DescribeDBInstancesInput, options ...func(*docdb.Options)) (*docdb.DescribeDBInstancesOutput, error) {
	f.fake.record("docdb:DescribeDBInstances")
	return fakeDocDB{data: f.fake.fakeAWSData}.DescribeDBInstances(ctx, input, options...)
}

func (f recordingDocDB) ListTagsForResource(ctx context.Context, input *docdb.ListTagsForResourceInput, options ...func(*docdb.Options)) (*docdb.ListTagsForResourceOutput, error) {
	f.fake.record("docdb:ListTagsForResource")
	return fakeDocDB{data: f.fake.fakeAWSData}.ListTagsForResource(ctx, input, options...)
}

func (f fakeDocDB) DescribeDBClusters(context.Context, *docdb.DescribeDBClustersInput, ...func(*docdb.Options)) (*docdb.DescribeDBClustersOutput, error) {
	return &docdb.DescribeDBClustersOutput{DBClusters: f.data.docdbClusters}, nil
}

func (f fakeDocDB) DescribeDBInstances(context.Context, *docdb.DescribeDBInstancesInput, ...func(*docdb.Options)) (*docdb.DescribeDBInstancesOutput, error) {
	return &docdb.DescribeDBInstancesOutput{DBInstances: f.data.docdbInstances}, nil
}

func (f fakeDocDB) ListTagsForResource(_ context.Context, input *docdb.ListTagsForResourceInput, _ ...func(*docdb.Options)) (*docdb.ListTagsForResourceOutput, error) {
	return &docdb.ListTagsForResourceOutput{TagList: f.data.docdbTags[awssdk.ToString(input.ResourceName)]}, nil
}

type fakeNeptune struct {
	data fakeAWSData
}

type recordingNeptune struct {
	fake *recordingAWS
}

func (f recordingNeptune) DescribeDBClusters(ctx context.Context, input *neptune.DescribeDBClustersInput, options ...func(*neptune.Options)) (*neptune.DescribeDBClustersOutput, error) {
	f.fake.record("neptune:DescribeDBClusters")
	return fakeNeptune{data: f.fake.fakeAWSData}.DescribeDBClusters(ctx, input, options...)
}

func (f recordingNeptune) DescribeDBInstances(ctx context.Context, input *neptune.DescribeDBInstancesInput, options ...func(*neptune.Options)) (*neptune.DescribeDBInstancesOutput, error) {
	f.fake.record("neptune:DescribeDBInstances")
	return fakeNeptune{data: f.fake.fakeAWSData}.DescribeDBInstances(ctx, input, options...)
}

func (f recordingNeptune) ListTagsForResource(ctx context.Context, input *neptune.ListTagsForResourceInput, options ...func(*neptune.Options)) (*neptune.ListTagsForResourceOutput, error) {
	f.fake.record("neptune:ListTagsForResource")
	return fakeNeptune{data: f.fake.fakeAWSData}.ListTagsForResource(ctx, input, options...)
}

func (f fakeNeptune) DescribeDBClusters(context.Context, *neptune.DescribeDBClustersInput, ...func(*neptune.Options)) (*neptune.DescribeDBClustersOutput, error) {
	return &neptune.DescribeDBClustersOutput{DBClusters: f.data.neptuneClusters}, nil
}

func (f fakeNeptune) DescribeDBInstances(context.Context, *neptune.DescribeDBInstancesInput, ...func(*neptune.Options)) (*neptune.DescribeDBInstancesOutput, error) {
	return &neptune.DescribeDBInstancesOutput{DBInstances: f.data.neptuneInstances}, nil
}

func (f fakeNeptune) ListTagsForResource(_ context.Context, input *neptune.ListTagsForResourceInput, _ ...func(*neptune.Options)) (*neptune.ListTagsForResourceOutput, error) {
	return &neptune.ListTagsForResourceOutput{TagList: f.data.neptuneTags[awssdk.ToString(input.ResourceName)]}, nil
}

type fakeKinesis struct {
	fake *fakeAWS
}

type recordingKinesis struct {
	fake *recordingAWS
}

func (f recordingKinesis) ListStreams(ctx context.Context, input *kinesis.ListStreamsInput, options ...func(*kinesis.Options)) (*kinesis.ListStreamsOutput, error) {
	f.fake.record("kinesis:ListStreams")
	return fakeKinesis{fake: &f.fake.fakeAWS}.ListStreams(ctx, input, options...)
}

func (f recordingKinesis) DescribeStreamSummary(ctx context.Context, input *kinesis.DescribeStreamSummaryInput, options ...func(*kinesis.Options)) (*kinesis.DescribeStreamSummaryOutput, error) {
	f.fake.record("kinesis:DescribeStreamSummary")
	return fakeKinesis{fake: &f.fake.fakeAWS}.DescribeStreamSummary(ctx, input, options...)
}

func (f recordingKinesis) ListTagsForStream(ctx context.Context, input *kinesis.ListTagsForStreamInput, options ...func(*kinesis.Options)) (*kinesis.ListTagsForStreamOutput, error) {
	f.fake.record("kinesis:ListTagsForStream")
	return fakeKinesis{fake: &f.fake.fakeAWS}.ListTagsForStream(ctx, input, options...)
}

func (f recordingKinesis) GetResourcePolicy(ctx context.Context, input *kinesis.GetResourcePolicyInput, options ...func(*kinesis.Options)) (*kinesis.GetResourcePolicyOutput, error) {
	f.fake.record("kinesis:GetResourcePolicy")
	return fakeKinesis{fake: &f.fake.fakeAWS}.GetResourcePolicy(ctx, input, options...)
}

func (f fakeKinesis) ListStreams(_ context.Context, input *kinesis.ListStreamsInput, _ ...func(*kinesis.Options)) (*kinesis.ListStreamsOutput, error) {
	names := make([]string, 0, len(f.fake.kinesisStreams))
	for _, stream := range f.fake.kinesisStreams {
		if name := awssdk.ToString(stream.StreamName); name != "" {
			names = append(names, name)
		}
	}
	values, truncated, marker := paginateStringValues(names, awssdk.ToString(input.ExclusiveStartStreamName), int(awssdk.ToInt32(input.Limit)))
	return &kinesis.ListStreamsOutput{StreamNames: values, HasMoreStreams: awssdk.Bool(truncated), NextToken: stringPtr(marker)}, nil
}

func (f fakeKinesis) DescribeStreamSummary(_ context.Context, input *kinesis.DescribeStreamSummaryInput, _ ...func(*kinesis.Options)) (*kinesis.DescribeStreamSummaryOutput, error) {
	name := awssdk.ToString(input.StreamName)
	for _, stream := range f.fake.kinesisStreams {
		if awssdk.ToString(stream.StreamName) == name || awssdk.ToString(stream.StreamARN) == awssdk.ToString(input.StreamARN) {
			copy := stream
			return &kinesis.DescribeStreamSummaryOutput{StreamDescriptionSummary: &copy}, nil
		}
	}
	return &kinesis.DescribeStreamSummaryOutput{}, nil
}

func (f fakeKinesis) ListTagsForStream(_ context.Context, input *kinesis.ListTagsForStreamInput, _ ...func(*kinesis.Options)) (*kinesis.ListTagsForStreamOutput, error) {
	key := firstNonEmpty(awssdk.ToString(input.StreamARN), awssdk.ToString(input.StreamName))
	return &kinesis.ListTagsForStreamOutput{Tags: f.fake.kinesisTags[key], HasMoreTags: awssdk.Bool(false)}, nil
}

func (f fakeKinesis) GetResourcePolicy(_ context.Context, input *kinesis.GetResourcePolicyInput, _ ...func(*kinesis.Options)) (*kinesis.GetResourcePolicyOutput, error) {
	return &kinesis.GetResourcePolicyOutput{Policy: awssdk.String(f.fake.kinesisPolicies[awssdk.ToString(input.ResourceARN)])}, nil
}

type fakeFirehose struct {
	fake *fakeAWS
}

type recordingFirehose struct {
	fake *recordingAWS
}

func (f recordingFirehose) ListDeliveryStreams(ctx context.Context, input *firehose.ListDeliveryStreamsInput, options ...func(*firehose.Options)) (*firehose.ListDeliveryStreamsOutput, error) {
	f.fake.record("firehose:ListDeliveryStreams")
	return fakeFirehose{fake: &f.fake.fakeAWS}.ListDeliveryStreams(ctx, input, options...)
}

func (f recordingFirehose) DescribeDeliveryStream(ctx context.Context, input *firehose.DescribeDeliveryStreamInput, options ...func(*firehose.Options)) (*firehose.DescribeDeliveryStreamOutput, error) {
	f.fake.record("firehose:DescribeDeliveryStream")
	return fakeFirehose{fake: &f.fake.fakeAWS}.DescribeDeliveryStream(ctx, input, options...)
}

func (f recordingFirehose) ListTagsForDeliveryStream(ctx context.Context, input *firehose.ListTagsForDeliveryStreamInput, options ...func(*firehose.Options)) (*firehose.ListTagsForDeliveryStreamOutput, error) {
	f.fake.record("firehose:ListTagsForDeliveryStream")
	return fakeFirehose{fake: &f.fake.fakeAWS}.ListTagsForDeliveryStream(ctx, input, options...)
}

func (f fakeFirehose) ListDeliveryStreams(_ context.Context, input *firehose.ListDeliveryStreamsInput, _ ...func(*firehose.Options)) (*firehose.ListDeliveryStreamsOutput, error) {
	names := make([]string, 0, len(f.fake.firehoseStreams))
	for _, stream := range f.fake.firehoseStreams {
		if name := awssdk.ToString(stream.DeliveryStreamName); name != "" {
			names = append(names, name)
		}
	}
	values, truncated, _ := paginateStringValues(names, awssdk.ToString(input.ExclusiveStartDeliveryStreamName), int(awssdk.ToInt32(input.Limit)))
	return &firehose.ListDeliveryStreamsOutput{DeliveryStreamNames: values, HasMoreDeliveryStreams: awssdk.Bool(truncated)}, nil
}

func (f fakeFirehose) DescribeDeliveryStream(_ context.Context, input *firehose.DescribeDeliveryStreamInput, _ ...func(*firehose.Options)) (*firehose.DescribeDeliveryStreamOutput, error) {
	name := awssdk.ToString(input.DeliveryStreamName)
	for _, stream := range f.fake.firehoseStreams {
		if awssdk.ToString(stream.DeliveryStreamName) == name {
			copy := stream
			return &firehose.DescribeDeliveryStreamOutput{DeliveryStreamDescription: &copy}, nil
		}
	}
	return &firehose.DescribeDeliveryStreamOutput{}, nil
}

func (f fakeFirehose) ListTagsForDeliveryStream(_ context.Context, input *firehose.ListTagsForDeliveryStreamInput, _ ...func(*firehose.Options)) (*firehose.ListTagsForDeliveryStreamOutput, error) {
	return &firehose.ListTagsForDeliveryStreamOutput{Tags: f.fake.firehoseTags[awssdk.ToString(input.DeliveryStreamName)], HasMoreTags: awssdk.Bool(false)}, nil
}

type fakeKafka struct {
	fake *fakeAWS
}

type recordingKafka struct {
	fake *recordingAWS
}

func (f recordingKafka) ListClustersV2(ctx context.Context, input *kafka.ListClustersV2Input, options ...func(*kafka.Options)) (*kafka.ListClustersV2Output, error) {
	f.fake.record("kafka:ListClustersV2")
	return fakeKafka{fake: &f.fake.fakeAWS}.ListClustersV2(ctx, input, options...)
}

func (f recordingKafka) DescribeClusterV2(ctx context.Context, input *kafka.DescribeClusterV2Input, options ...func(*kafka.Options)) (*kafka.DescribeClusterV2Output, error) {
	f.fake.record("kafka:DescribeClusterV2")
	return fakeKafka{fake: &f.fake.fakeAWS}.DescribeClusterV2(ctx, input, options...)
}

func (f recordingKafka) ListTagsForResource(ctx context.Context, input *kafka.ListTagsForResourceInput, options ...func(*kafka.Options)) (*kafka.ListTagsForResourceOutput, error) {
	f.fake.record("kafka:ListTagsForResource")
	return fakeKafka{fake: &f.fake.fakeAWS}.ListTagsForResource(ctx, input, options...)
}

func (f fakeKafka) ListClustersV2(context.Context, *kafka.ListClustersV2Input, ...func(*kafka.Options)) (*kafka.ListClustersV2Output, error) {
	return &kafka.ListClustersV2Output{ClusterInfoList: f.fake.mskClusters}, nil
}

func (f fakeKafka) DescribeClusterV2(_ context.Context, input *kafka.DescribeClusterV2Input, _ ...func(*kafka.Options)) (*kafka.DescribeClusterV2Output, error) {
	arn := awssdk.ToString(input.ClusterArn)
	for _, cluster := range f.fake.mskClusters {
		if awssdk.ToString(cluster.ClusterArn) == arn {
			copy := cluster
			return &kafka.DescribeClusterV2Output{ClusterInfo: &copy}, nil
		}
	}
	return &kafka.DescribeClusterV2Output{}, nil
}

func (f fakeKafka) ListTagsForResource(_ context.Context, input *kafka.ListTagsForResourceInput, _ ...func(*kafka.Options)) (*kafka.ListTagsForResourceOutput, error) {
	return &kafka.ListTagsForResourceOutput{Tags: f.fake.mskTags[awssdk.ToString(input.ResourceArn)]}, nil
}

type fakeGlue struct {
	fake *fakeAWS
}

type recordingGlue struct {
	fake *recordingAWS
}

func (f recordingGlue) GetDatabases(ctx context.Context, input *glue.GetDatabasesInput, options ...func(*glue.Options)) (*glue.GetDatabasesOutput, error) {
	f.fake.record("glue:GetDatabases")
	return fakeGlue{fake: &f.fake.fakeAWS}.GetDatabases(ctx, input, options...)
}

func (f recordingGlue) GetTables(ctx context.Context, input *glue.GetTablesInput, options ...func(*glue.Options)) (*glue.GetTablesOutput, error) {
	f.fake.record("glue:GetTables")
	return fakeGlue{fake: &f.fake.fakeAWS}.GetTables(ctx, input, options...)
}

func (f recordingGlue) ListCrawlers(ctx context.Context, input *glue.ListCrawlersInput, options ...func(*glue.Options)) (*glue.ListCrawlersOutput, error) {
	f.fake.record("glue:ListCrawlers")
	return fakeGlue{fake: &f.fake.fakeAWS}.ListCrawlers(ctx, input, options...)
}

func (f recordingGlue) GetCrawler(ctx context.Context, input *glue.GetCrawlerInput, options ...func(*glue.Options)) (*glue.GetCrawlerOutput, error) {
	f.fake.record("glue:GetCrawler")
	return fakeGlue{fake: &f.fake.fakeAWS}.GetCrawler(ctx, input, options...)
}

func (f recordingGlue) ListJobs(ctx context.Context, input *glue.ListJobsInput, options ...func(*glue.Options)) (*glue.ListJobsOutput, error) {
	f.fake.record("glue:ListJobs")
	return fakeGlue{fake: &f.fake.fakeAWS}.ListJobs(ctx, input, options...)
}

func (f recordingGlue) GetJob(ctx context.Context, input *glue.GetJobInput, options ...func(*glue.Options)) (*glue.GetJobOutput, error) {
	f.fake.record("glue:GetJob")
	return fakeGlue{fake: &f.fake.fakeAWS}.GetJob(ctx, input, options...)
}

func (f recordingGlue) GetTags(ctx context.Context, input *glue.GetTagsInput, options ...func(*glue.Options)) (*glue.GetTagsOutput, error) {
	f.fake.record("glue:GetTags")
	return fakeGlue{fake: &f.fake.fakeAWS}.GetTags(ctx, input, options...)
}

func (f fakeGlue) GetDatabases(context.Context, *glue.GetDatabasesInput, ...func(*glue.Options)) (*glue.GetDatabasesOutput, error) {
	return &glue.GetDatabasesOutput{DatabaseList: f.fake.glueDatabases}, nil
}

func (f fakeGlue) GetTables(_ context.Context, input *glue.GetTablesInput, _ ...func(*glue.Options)) (*glue.GetTablesOutput, error) {
	return &glue.GetTablesOutput{TableList: f.fake.glueTables[awssdk.ToString(input.DatabaseName)]}, nil
}

func (f fakeGlue) ListCrawlers(context.Context, *glue.ListCrawlersInput, ...func(*glue.Options)) (*glue.ListCrawlersOutput, error) {
	names := make([]string, 0, len(f.fake.glueCrawlers))
	for _, crawler := range f.fake.glueCrawlers {
		names = append(names, awssdk.ToString(crawler.Name))
	}
	return &glue.ListCrawlersOutput{CrawlerNames: names}, nil
}

func (f fakeGlue) GetCrawler(_ context.Context, input *glue.GetCrawlerInput, _ ...func(*glue.Options)) (*glue.GetCrawlerOutput, error) {
	name := awssdk.ToString(input.Name)
	for _, crawler := range f.fake.glueCrawlers {
		if awssdk.ToString(crawler.Name) == name {
			copy := crawler
			return &glue.GetCrawlerOutput{Crawler: &copy}, nil
		}
	}
	return &glue.GetCrawlerOutput{}, nil
}

func (f fakeGlue) ListJobs(context.Context, *glue.ListJobsInput, ...func(*glue.Options)) (*glue.ListJobsOutput, error) {
	names := make([]string, 0, len(f.fake.glueJobs))
	for _, job := range f.fake.glueJobs {
		names = append(names, awssdk.ToString(job.Name))
	}
	return &glue.ListJobsOutput{JobNames: names}, nil
}

func (f fakeGlue) GetJob(_ context.Context, input *glue.GetJobInput, _ ...func(*glue.Options)) (*glue.GetJobOutput, error) {
	name := awssdk.ToString(input.JobName)
	for _, job := range f.fake.glueJobs {
		if awssdk.ToString(job.Name) == name {
			copy := job
			return &glue.GetJobOutput{Job: &copy}, nil
		}
	}
	return &glue.GetJobOutput{}, nil
}

func (f fakeGlue) GetTags(_ context.Context, input *glue.GetTagsInput, _ ...func(*glue.Options)) (*glue.GetTagsOutput, error) {
	return &glue.GetTagsOutput{Tags: f.fake.glueTags[awssdk.ToString(input.ResourceArn)]}, nil
}

type fakeAthena struct {
	fake *fakeAWS
}

type recordingAthena struct {
	fake *recordingAWS
}

func (f recordingAthena) ListWorkGroups(ctx context.Context, input *athena.ListWorkGroupsInput, options ...func(*athena.Options)) (*athena.ListWorkGroupsOutput, error) {
	f.fake.record("athena:ListWorkGroups")
	return fakeAthena{fake: &f.fake.fakeAWS}.ListWorkGroups(ctx, input, options...)
}

func (f recordingAthena) GetWorkGroup(ctx context.Context, input *athena.GetWorkGroupInput, options ...func(*athena.Options)) (*athena.GetWorkGroupOutput, error) {
	f.fake.record("athena:GetWorkGroup")
	return fakeAthena{fake: &f.fake.fakeAWS}.GetWorkGroup(ctx, input, options...)
}

func (f recordingAthena) ListDataCatalogs(ctx context.Context, input *athena.ListDataCatalogsInput, options ...func(*athena.Options)) (*athena.ListDataCatalogsOutput, error) {
	f.fake.record("athena:ListDataCatalogs")
	return fakeAthena{fake: &f.fake.fakeAWS}.ListDataCatalogs(ctx, input, options...)
}

func (f recordingAthena) GetDataCatalog(ctx context.Context, input *athena.GetDataCatalogInput, options ...func(*athena.Options)) (*athena.GetDataCatalogOutput, error) {
	f.fake.record("athena:GetDataCatalog")
	return fakeAthena{fake: &f.fake.fakeAWS}.GetDataCatalog(ctx, input, options...)
}

func (f recordingAthena) ListTagsForResource(ctx context.Context, input *athena.ListTagsForResourceInput, options ...func(*athena.Options)) (*athena.ListTagsForResourceOutput, error) {
	f.fake.record("athena:ListTagsForResource")
	return fakeAthena{fake: &f.fake.fakeAWS}.ListTagsForResource(ctx, input, options...)
}

func (f fakeAthena) ListWorkGroups(context.Context, *athena.ListWorkGroupsInput, ...func(*athena.Options)) (*athena.ListWorkGroupsOutput, error) {
	summaries := make([]athenatypes.WorkGroupSummary, 0, len(f.fake.athenaWorkgroups))
	for _, workgroup := range f.fake.athenaWorkgroups {
		summaries = append(summaries, athenatypes.WorkGroupSummary{Name: workgroup.Name})
	}
	return &athena.ListWorkGroupsOutput{WorkGroups: summaries}, nil
}

func (f fakeAthena) GetWorkGroup(_ context.Context, input *athena.GetWorkGroupInput, _ ...func(*athena.Options)) (*athena.GetWorkGroupOutput, error) {
	name := awssdk.ToString(input.WorkGroup)
	for _, workgroup := range f.fake.athenaWorkgroups {
		if awssdk.ToString(workgroup.Name) == name {
			copy := workgroup
			return &athena.GetWorkGroupOutput{WorkGroup: &copy}, nil
		}
	}
	return &athena.GetWorkGroupOutput{}, nil
}

func (f fakeAthena) ListDataCatalogs(context.Context, *athena.ListDataCatalogsInput, ...func(*athena.Options)) (*athena.ListDataCatalogsOutput, error) {
	summaries := make([]athenatypes.DataCatalogSummary, 0, len(f.fake.athenaDataCatalogs))
	for _, catalog := range f.fake.athenaDataCatalogs {
		summaries = append(summaries, athenatypes.DataCatalogSummary{CatalogName: catalog.Name, Type: catalog.Type})
	}
	return &athena.ListDataCatalogsOutput{DataCatalogsSummary: summaries}, nil
}

func (f fakeAthena) GetDataCatalog(_ context.Context, input *athena.GetDataCatalogInput, _ ...func(*athena.Options)) (*athena.GetDataCatalogOutput, error) {
	name := awssdk.ToString(input.Name)
	for _, catalog := range f.fake.athenaDataCatalogs {
		if awssdk.ToString(catalog.Name) == name {
			copy := catalog
			return &athena.GetDataCatalogOutput{DataCatalog: &copy}, nil
		}
	}
	return &athena.GetDataCatalogOutput{}, nil
}

func (f fakeAthena) ListTagsForResource(_ context.Context, input *athena.ListTagsForResourceInput, _ ...func(*athena.Options)) (*athena.ListTagsForResourceOutput, error) {
	return &athena.ListTagsForResourceOutput{Tags: f.fake.athenaTags[awssdk.ToString(input.ResourceARN)]}, nil
}

type fakeLakeFormation struct {
	fake *fakeAWS
}

type recordingLakeFormation struct {
	fake *recordingAWS
}

func (f recordingLakeFormation) ListResources(ctx context.Context, input *lakeformation.ListResourcesInput, options ...func(*lakeformation.Options)) (*lakeformation.ListResourcesOutput, error) {
	f.fake.record("lakeformation:ListResources")
	return fakeLakeFormation{fake: &f.fake.fakeAWS}.ListResources(ctx, input, options...)
}

func (f recordingLakeFormation) ListLFTags(ctx context.Context, input *lakeformation.ListLFTagsInput, options ...func(*lakeformation.Options)) (*lakeformation.ListLFTagsOutput, error) {
	f.fake.record("lakeformation:ListLFTags")
	return fakeLakeFormation{fake: &f.fake.fakeAWS}.ListLFTags(ctx, input, options...)
}

func (f recordingLakeFormation) ListPermissions(ctx context.Context, input *lakeformation.ListPermissionsInput, options ...func(*lakeformation.Options)) (*lakeformation.ListPermissionsOutput, error) {
	f.fake.record("lakeformation:ListPermissions")
	return fakeLakeFormation{fake: &f.fake.fakeAWS}.ListPermissions(ctx, input, options...)
}

func (f fakeLakeFormation) ListResources(context.Context, *lakeformation.ListResourcesInput, ...func(*lakeformation.Options)) (*lakeformation.ListResourcesOutput, error) {
	return &lakeformation.ListResourcesOutput{ResourceInfoList: f.fake.lakeFormationResources}, nil
}

func (f fakeLakeFormation) ListLFTags(context.Context, *lakeformation.ListLFTagsInput, ...func(*lakeformation.Options)) (*lakeformation.ListLFTagsOutput, error) {
	return &lakeformation.ListLFTagsOutput{LFTags: f.fake.lakeFormationLFTags}, nil
}

func (f fakeLakeFormation) ListPermissions(context.Context, *lakeformation.ListPermissionsInput, ...func(*lakeformation.Options)) (*lakeformation.ListPermissionsOutput, error) {
	return &lakeformation.ListPermissionsOutput{PrincipalResourcePermissions: f.fake.lakeFormationPermissions}, nil
}

type fakeOpenSearch struct {
	fake *fakeAWS
}

type recordingOpenSearch struct {
	fake *recordingAWS
}

func (f recordingOpenSearch) ListDomainNames(ctx context.Context, input *opensearch.ListDomainNamesInput, options ...func(*opensearch.Options)) (*opensearch.ListDomainNamesOutput, error) {
	f.fake.record("opensearch:ListDomainNames")
	return fakeOpenSearch{fake: &f.fake.fakeAWS}.ListDomainNames(ctx, input, options...)
}

func (f recordingOpenSearch) DescribeDomains(ctx context.Context, input *opensearch.DescribeDomainsInput, options ...func(*opensearch.Options)) (*opensearch.DescribeDomainsOutput, error) {
	f.fake.record("opensearch:DescribeDomains")
	return fakeOpenSearch{fake: &f.fake.fakeAWS}.DescribeDomains(ctx, input, options...)
}

func (f recordingOpenSearch) ListTags(ctx context.Context, input *opensearch.ListTagsInput, options ...func(*opensearch.Options)) (*opensearch.ListTagsOutput, error) {
	f.fake.record("opensearch:ListTags")
	return fakeOpenSearch{fake: &f.fake.fakeAWS}.ListTags(ctx, input, options...)
}

func (f fakeOpenSearch) ListDomainNames(context.Context, *opensearch.ListDomainNamesInput, ...func(*opensearch.Options)) (*opensearch.ListDomainNamesOutput, error) {
	domains := make([]opensearchtypes.DomainInfo, 0, len(f.fake.openSearchDomains))
	for _, domain := range f.fake.openSearchDomains {
		domains = append(domains, opensearchtypes.DomainInfo{DomainName: domain.DomainName})
	}
	return &opensearch.ListDomainNamesOutput{DomainNames: domains}, nil
}

func (f fakeOpenSearch) DescribeDomains(_ context.Context, input *opensearch.DescribeDomainsInput, _ ...func(*opensearch.Options)) (*opensearch.DescribeDomainsOutput, error) {
	names := map[string]bool{}
	for _, name := range input.DomainNames {
		names[name] = true
	}
	domains := make([]opensearchtypes.DomainStatus, 0, len(f.fake.openSearchDomains))
	for _, domain := range f.fake.openSearchDomains {
		if names[awssdk.ToString(domain.DomainName)] {
			domains = append(domains, domain)
		}
	}
	return &opensearch.DescribeDomainsOutput{DomainStatusList: domains}, nil
}

func (f fakeOpenSearch) ListTags(_ context.Context, input *opensearch.ListTagsInput, _ ...func(*opensearch.Options)) (*opensearch.ListTagsOutput, error) {
	return &opensearch.ListTagsOutput{TagList: f.fake.openSearchTags[awssdk.ToString(input.ARN)]}, nil
}

type fakeOpenSearchServerless struct {
	fake *fakeAWS
}

type recordingOpenSearchServerless struct {
	fake *recordingAWS
}

func (f recordingOpenSearchServerless) ListCollections(ctx context.Context, input *opensearchserverless.ListCollectionsInput, options ...func(*opensearchserverless.Options)) (*opensearchserverless.ListCollectionsOutput, error) {
	f.fake.record("opensearchserverless:ListCollections")
	return fakeOpenSearchServerless{fake: &f.fake.fakeAWS}.ListCollections(ctx, input, options...)
}

func (f recordingOpenSearchServerless) BatchGetCollection(ctx context.Context, input *opensearchserverless.BatchGetCollectionInput, options ...func(*opensearchserverless.Options)) (*opensearchserverless.BatchGetCollectionOutput, error) {
	f.fake.record("opensearchserverless:BatchGetCollection")
	return fakeOpenSearchServerless{fake: &f.fake.fakeAWS}.BatchGetCollection(ctx, input, options...)
}

func (f recordingOpenSearchServerless) ListTagsForResource(ctx context.Context, input *opensearchserverless.ListTagsForResourceInput, options ...func(*opensearchserverless.Options)) (*opensearchserverless.ListTagsForResourceOutput, error) {
	f.fake.record("opensearchserverless:ListTagsForResource")
	return fakeOpenSearchServerless{fake: &f.fake.fakeAWS}.ListTagsForResource(ctx, input, options...)
}

func (f recordingOpenSearchServerless) ListSecurityPolicies(ctx context.Context, input *opensearchserverless.ListSecurityPoliciesInput, options ...func(*opensearchserverless.Options)) (*opensearchserverless.ListSecurityPoliciesOutput, error) {
	f.fake.record("opensearchserverless:ListSecurityPolicies")
	return fakeOpenSearchServerless{fake: &f.fake.fakeAWS}.ListSecurityPolicies(ctx, input, options...)
}

func (f recordingOpenSearchServerless) GetSecurityPolicy(ctx context.Context, input *opensearchserverless.GetSecurityPolicyInput, options ...func(*opensearchserverless.Options)) (*opensearchserverless.GetSecurityPolicyOutput, error) {
	f.fake.record("opensearchserverless:GetSecurityPolicy")
	return fakeOpenSearchServerless{fake: &f.fake.fakeAWS}.GetSecurityPolicy(ctx, input, options...)
}

func (f fakeOpenSearchServerless) ListCollections(context.Context, *opensearchserverless.ListCollectionsInput, ...func(*opensearchserverless.Options)) (*opensearchserverless.ListCollectionsOutput, error) {
	summaries := make([]opensearchserverlesstypes.CollectionSummary, 0, len(f.fake.aossCollections))
	for _, collection := range f.fake.aossCollections {
		summaries = append(summaries, opensearchserverlesstypes.CollectionSummary{Arn: collection.Arn, Id: collection.Id, Name: collection.Name, Status: collection.Status})
	}
	return &opensearchserverless.ListCollectionsOutput{CollectionSummaries: summaries}, nil
}

func (f fakeOpenSearchServerless) BatchGetCollection(_ context.Context, input *opensearchserverless.BatchGetCollectionInput, _ ...func(*opensearchserverless.Options)) (*opensearchserverless.BatchGetCollectionOutput, error) {
	ids := map[string]bool{}
	for _, id := range input.Ids {
		ids[id] = true
	}
	collections := make([]opensearchserverlesstypes.CollectionDetail, 0, len(f.fake.aossCollections))
	for _, collection := range f.fake.aossCollections {
		if ids[awssdk.ToString(collection.Id)] {
			collections = append(collections, collection)
		}
	}
	return &opensearchserverless.BatchGetCollectionOutput{CollectionDetails: collections}, nil
}

func (f fakeOpenSearchServerless) ListTagsForResource(_ context.Context, input *opensearchserverless.ListTagsForResourceInput, _ ...func(*opensearchserverless.Options)) (*opensearchserverless.ListTagsForResourceOutput, error) {
	return &opensearchserverless.ListTagsForResourceOutput{Tags: f.fake.aossTags[awssdk.ToString(input.ResourceArn)]}, nil
}

func (f fakeOpenSearchServerless) ListSecurityPolicies(_ context.Context, input *opensearchserverless.ListSecurityPoliciesInput, _ ...func(*opensearchserverless.Options)) (*opensearchserverless.ListSecurityPoliciesOutput, error) {
	summaries := make([]opensearchserverlesstypes.SecurityPolicySummary, 0, len(f.fake.aossSecurityPolicies))
	for _, policy := range f.fake.aossSecurityPolicies {
		if policy.Type == input.Type {
			summaries = append(summaries, opensearchserverlesstypes.SecurityPolicySummary{Name: policy.Name, Type: policy.Type, PolicyVersion: policy.PolicyVersion})
		}
	}
	return &opensearchserverless.ListSecurityPoliciesOutput{SecurityPolicySummaries: summaries}, nil
}

func (f fakeOpenSearchServerless) GetSecurityPolicy(_ context.Context, input *opensearchserverless.GetSecurityPolicyInput, _ ...func(*opensearchserverless.Options)) (*opensearchserverless.GetSecurityPolicyOutput, error) {
	for _, policy := range f.fake.aossSecurityPolicies {
		if awssdk.ToString(policy.Name) == awssdk.ToString(input.Name) && policy.Type == input.Type {
			copy := policy
			return &opensearchserverless.GetSecurityPolicyOutput{SecurityPolicyDetail: &copy}, nil
		}
	}
	return &opensearchserverless.GetSecurityPolicyOutput{}, nil
}

type fakeElastiCache struct {
	fake *fakeAWS
}

type recordingElastiCache struct {
	fake *recordingAWS
}

func (f recordingElastiCache) DescribeReplicationGroups(ctx context.Context, input *elasticache.DescribeReplicationGroupsInput, options ...func(*elasticache.Options)) (*elasticache.DescribeReplicationGroupsOutput, error) {
	f.fake.record("elasticache:DescribeReplicationGroups")
	return fakeElastiCache{fake: &f.fake.fakeAWS}.DescribeReplicationGroups(ctx, input, options...)
}

func (f recordingElastiCache) DescribeCacheClusters(ctx context.Context, input *elasticache.DescribeCacheClustersInput, options ...func(*elasticache.Options)) (*elasticache.DescribeCacheClustersOutput, error) {
	f.fake.record("elasticache:DescribeCacheClusters")
	return fakeElastiCache{fake: &f.fake.fakeAWS}.DescribeCacheClusters(ctx, input, options...)
}

func (f recordingElastiCache) DescribeCacheSubnetGroups(ctx context.Context, input *elasticache.DescribeCacheSubnetGroupsInput, options ...func(*elasticache.Options)) (*elasticache.DescribeCacheSubnetGroupsOutput, error) {
	f.fake.record("elasticache:DescribeCacheSubnetGroups")
	return fakeElastiCache{fake: &f.fake.fakeAWS}.DescribeCacheSubnetGroups(ctx, input, options...)
}

func (f recordingElastiCache) ListTagsForResource(ctx context.Context, input *elasticache.ListTagsForResourceInput, options ...func(*elasticache.Options)) (*elasticache.ListTagsForResourceOutput, error) {
	f.fake.record("elasticache:ListTagsForResource")
	return fakeElastiCache{fake: &f.fake.fakeAWS}.ListTagsForResource(ctx, input, options...)
}

func (f fakeElastiCache) DescribeReplicationGroups(context.Context, *elasticache.DescribeReplicationGroupsInput, ...func(*elasticache.Options)) (*elasticache.DescribeReplicationGroupsOutput, error) {
	return &elasticache.DescribeReplicationGroupsOutput{ReplicationGroups: f.fake.elasticacheReplicationGroups}, nil
}

func (f fakeElastiCache) DescribeCacheClusters(context.Context, *elasticache.DescribeCacheClustersInput, ...func(*elasticache.Options)) (*elasticache.DescribeCacheClustersOutput, error) {
	return &elasticache.DescribeCacheClustersOutput{CacheClusters: f.fake.elasticacheClusters}, nil
}

func (f fakeElastiCache) DescribeCacheSubnetGroups(context.Context, *elasticache.DescribeCacheSubnetGroupsInput, ...func(*elasticache.Options)) (*elasticache.DescribeCacheSubnetGroupsOutput, error) {
	return &elasticache.DescribeCacheSubnetGroupsOutput{CacheSubnetGroups: f.fake.elasticacheSubnetGroups}, nil
}

func (f fakeElastiCache) ListTagsForResource(_ context.Context, input *elasticache.ListTagsForResourceInput, _ ...func(*elasticache.Options)) (*elasticache.ListTagsForResourceOutput, error) {
	return &elasticache.ListTagsForResourceOutput{TagList: f.fake.elasticacheTags[awssdk.ToString(input.ResourceName)]}, nil
}

type fakeFSx struct {
	fake *fakeAWS
}

type recordingFSx struct {
	fake *recordingAWS
}

func (f recordingFSx) DescribeFileSystems(ctx context.Context, input *fsx.DescribeFileSystemsInput, options ...func(*fsx.Options)) (*fsx.DescribeFileSystemsOutput, error) {
	f.fake.record("fsx:DescribeFileSystems")
	return fakeFSx{fake: &f.fake.fakeAWS}.DescribeFileSystems(ctx, input, options...)
}

func (f recordingFSx) ListTagsForResource(ctx context.Context, input *fsx.ListTagsForResourceInput, options ...func(*fsx.Options)) (*fsx.ListTagsForResourceOutput, error) {
	f.fake.record("fsx:ListTagsForResource")
	return fakeFSx{fake: &f.fake.fakeAWS}.ListTagsForResource(ctx, input, options...)
}

func (f fakeFSx) DescribeFileSystems(context.Context, *fsx.DescribeFileSystemsInput, ...func(*fsx.Options)) (*fsx.DescribeFileSystemsOutput, error) {
	return &fsx.DescribeFileSystemsOutput{FileSystems: f.fake.fsxFileSystems}, nil
}

func (f fakeFSx) ListTagsForResource(_ context.Context, input *fsx.ListTagsForResourceInput, _ ...func(*fsx.Options)) (*fsx.ListTagsForResourceOutput, error) {
	return &fsx.ListTagsForResourceOutput{Tags: f.fake.fsxTags[awssdk.ToString(input.ResourceARN)]}, nil
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

func (f fakeAWS) ListSAMLProviders(context.Context, *iam.ListSAMLProvidersInput, ...func(*iam.Options)) (*iam.ListSAMLProvidersOutput, error) {
	return &iam.ListSAMLProvidersOutput{SAMLProviderList: f.samlProviders}, nil
}

func (f fakeAWS) GetSAMLProvider(_ context.Context, input *iam.GetSAMLProviderInput, _ ...func(*iam.Options)) (*iam.GetSAMLProviderOutput, error) {
	if f.samlProviderDetails != nil {
		if detail, ok := f.samlProviderDetails[awssdk.ToString(input.SAMLProviderArn)]; ok {
			return &detail, nil
		}
	}
	return &iam.GetSAMLProviderOutput{}, nil
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

func (f fakeAWS) GetAccountSummary(context.Context, *iam.GetAccountSummaryInput, ...func(*iam.Options)) (*iam.GetAccountSummaryOutput, error) {
	return &iam.GetAccountSummaryOutput{SummaryMap: f.accountSummary}, nil
}

func (f fakeAWS) GetAccountPasswordPolicy(context.Context, *iam.GetAccountPasswordPolicyInput, ...func(*iam.Options)) (*iam.GetAccountPasswordPolicyOutput, error) {
	if f.accountPasswordPolicy == nil {
		return nil, &iamtypes.NoSuchEntityException{}
	}
	return &iam.GetAccountPasswordPolicyOutput{PasswordPolicy: f.accountPasswordPolicy}, nil
}

func (f fakeAWS) GenerateCredentialReport(context.Context, *iam.GenerateCredentialReportInput, ...func(*iam.Options)) (*iam.GenerateCredentialReportOutput, error) {
	state := f.credentialReport.state
	if len(f.credentialReport.states) > 0 {
		index := 0
		if f.credentialReport.stateIndex != nil {
			index = *f.credentialReport.stateIndex
			if *f.credentialReport.stateIndex < len(f.credentialReport.states)-1 {
				*f.credentialReport.stateIndex = *f.credentialReport.stateIndex + 1
			}
		}
		if index >= len(f.credentialReport.states) {
			index = len(f.credentialReport.states) - 1
		}
		state = f.credentialReport.states[index]
	}
	if state == "" {
		state = iamtypes.ReportStateTypeComplete
	}
	return &iam.GenerateCredentialReportOutput{State: state}, nil
}

func (f fakeAWS) GetCredentialReport(context.Context, *iam.GetCredentialReportInput, ...func(*iam.Options)) (*iam.GetCredentialReportOutput, error) {
	if f.credentialReport.err != nil {
		return nil, f.credentialReport.err
	}
	return &iam.GetCredentialReportOutput{Content: f.credentialReport.content, GeneratedTime: f.credentialReport.generatedTime, ReportFormat: iamtypes.ReportFormatTypeTextCsv}, nil
}

func (f fakeAWS) ListAccounts(context.Context, *organizations.ListAccountsInput, ...func(*organizations.Options)) (*organizations.ListAccountsOutput, error) {
	if f.organizationAccountsError != nil {
		return nil, f.organizationAccountsError
	}
	return &organizations.ListAccountsOutput{Accounts: f.organizationAccounts}, nil
}

func (f fakeAWS) ListRoots(context.Context, *organizations.ListRootsInput, ...func(*organizations.Options)) (*organizations.ListRootsOutput, error) {
	return &organizations.ListRootsOutput{Roots: f.organizationRoots}, nil
}

func (f fakeAWS) ListOrganizationalUnitsForParent(_ context.Context, input *organizations.ListOrganizationalUnitsForParentInput, _ ...func(*organizations.Options)) (*organizations.ListOrganizationalUnitsForParentOutput, error) {
	return &organizations.ListOrganizationalUnitsForParentOutput{OrganizationalUnits: f.organizationOUs[awssdk.ToString(input.ParentId)]}, nil
}

func (f fakeAWS) ListParents(_ context.Context, input *organizations.ListParentsInput, _ ...func(*organizations.Options)) (*organizations.ListParentsOutput, error) {
	if parent, ok := f.organizationParents[awssdk.ToString(input.ChildId)]; ok {
		return &organizations.ListParentsOutput{Parents: []organizationstypes.Parent{parent}}, nil
	}
	return &organizations.ListParentsOutput{}, nil
}

func (f fakeAWS) ListPolicies(_ context.Context, input *organizations.ListPoliciesInput, _ ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error) {
	policies := make([]organizationstypes.PolicySummary, 0, len(f.organizationPolicies))
	for _, policy := range f.organizationPolicies {
		if input != nil && input.Filter != "" && policy.Type != input.Filter {
			continue
		}
		policies = append(policies, policy)
	}
	return &organizations.ListPoliciesOutput{Policies: policies}, nil
}

func (f fakeAWS) DescribePolicy(_ context.Context, input *organizations.DescribePolicyInput, _ ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error) {
	if policy, ok := f.organizationPolicyDetails[awssdk.ToString(input.PolicyId)]; ok {
		return &organizations.DescribePolicyOutput{Policy: &policy}, nil
	}
	return &organizations.DescribePolicyOutput{}, nil
}

func (f fakeAWS) ListTargetsForPolicy(_ context.Context, input *organizations.ListTargetsForPolicyInput, _ ...func(*organizations.Options)) (*organizations.ListTargetsForPolicyOutput, error) {
	return &organizations.ListTargetsForPolicyOutput{Targets: f.organizationPolicyTargets[awssdk.ToString(input.PolicyId)]}, nil
}

func (f fakeAWS) ListInstances(context.Context, *ssoadmin.ListInstancesInput, ...func(*ssoadmin.Options)) (*ssoadmin.ListInstancesOutput, error) {
	return &ssoadmin.ListInstancesOutput{Instances: f.ssoInstances}, nil
}

func (f fakeAWS) ListPermissionSets(context.Context, *ssoadmin.ListPermissionSetsInput, ...func(*ssoadmin.Options)) (*ssoadmin.ListPermissionSetsOutput, error) {
	arns := make([]string, 0, len(f.ssoPermissionSets))
	for _, permissionSet := range f.ssoPermissionSets {
		if arn := awssdk.ToString(permissionSet.PermissionSetArn); arn != "" {
			arns = append(arns, arn)
		}
	}
	return &ssoadmin.ListPermissionSetsOutput{PermissionSets: arns}, nil
}

func (f fakeAWS) DescribePermissionSet(_ context.Context, input *ssoadmin.DescribePermissionSetInput, _ ...func(*ssoadmin.Options)) (*ssoadmin.DescribePermissionSetOutput, error) {
	arn := awssdk.ToString(input.PermissionSetArn)
	for _, permissionSet := range f.ssoPermissionSets {
		if awssdk.ToString(permissionSet.PermissionSetArn) == arn {
			copy := permissionSet
			return &ssoadmin.DescribePermissionSetOutput{PermissionSet: &copy}, nil
		}
	}
	return &ssoadmin.DescribePermissionSetOutput{}, nil
}

func (f fakeAWS) ListAccountsForProvisionedPermissionSet(_ context.Context, input *ssoadmin.ListAccountsForProvisionedPermissionSetInput, _ ...func(*ssoadmin.Options)) (*ssoadmin.ListAccountsForProvisionedPermissionSetOutput, error) {
	permissionSetARN := awssdk.ToString(input.PermissionSetArn)
	key := awssdk.ToString(input.InstanceArn) + "|" + permissionSetARN
	accounts := append([]string(nil), f.ssoProvisionedAccounts[key]...)
	if len(accounts) == 0 {
		seen := map[string]bool{}
		for assignmentKey := range f.ssoAssignments {
			parts := strings.SplitN(assignmentKey, "|", 2)
			if len(parts) == 2 && parts[1] == permissionSetARN && !seen[parts[0]] {
				seen[parts[0]] = true
				accounts = append(accounts, parts[0])
			}
		}
		sort.Strings(accounts)
	}
	return &ssoadmin.ListAccountsForProvisionedPermissionSetOutput{AccountIds: accounts}, nil
}

func (f fakeAWS) ListAccountAssignments(_ context.Context, input *ssoadmin.ListAccountAssignmentsInput, _ ...func(*ssoadmin.Options)) (*ssoadmin.ListAccountAssignmentsOutput, error) {
	key := awssdk.ToString(input.AccountId) + "|" + awssdk.ToString(input.PermissionSetArn)
	return &ssoadmin.ListAccountAssignmentsOutput{AccountAssignments: f.ssoAssignments[key]}, nil
}

type fakeIdentityStore struct {
	fake *fakeAWS
}

type recordingIdentityStore struct {
	fake *recordingAWS
}

func (f recordingIdentityStore) ListUsers(ctx context.Context, input *identitystore.ListUsersInput, options ...func(*identitystore.Options)) (*identitystore.ListUsersOutput, error) {
	f.fake.record("identitystore:ListUsers")
	return fakeIdentityStore{fake: &f.fake.fakeAWS}.ListUsers(ctx, input, options...)
}

func (f recordingIdentityStore) ListGroups(ctx context.Context, input *identitystore.ListGroupsInput, options ...func(*identitystore.Options)) (*identitystore.ListGroupsOutput, error) {
	f.fake.record("identitystore:ListGroups")
	return fakeIdentityStore{fake: &f.fake.fakeAWS}.ListGroups(ctx, input, options...)
}

func (f recordingIdentityStore) ListGroupMemberships(ctx context.Context, input *identitystore.ListGroupMembershipsInput, options ...func(*identitystore.Options)) (*identitystore.ListGroupMembershipsOutput, error) {
	f.fake.record("identitystore:ListGroupMemberships")
	return fakeIdentityStore{fake: &f.fake.fakeAWS}.ListGroupMemberships(ctx, input, options...)
}

func (f fakeIdentityStore) ListUsers(context.Context, *identitystore.ListUsersInput, ...func(*identitystore.Options)) (*identitystore.ListUsersOutput, error) {
	return &identitystore.ListUsersOutput{Users: f.fake.identityUsers}, nil
}

func (f fakeIdentityStore) ListGroups(context.Context, *identitystore.ListGroupsInput, ...func(*identitystore.Options)) (*identitystore.ListGroupsOutput, error) {
	return &identitystore.ListGroupsOutput{Groups: f.fake.identityGroups}, nil
}

func (f fakeIdentityStore) ListGroupMemberships(_ context.Context, input *identitystore.ListGroupMembershipsInput, _ ...func(*identitystore.Options)) (*identitystore.ListGroupMembershipsOutput, error) {
	return &identitystore.ListGroupMembershipsOutput{GroupMemberships: f.fake.identityMemberships[awssdk.ToString(input.GroupId)]}, nil
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

func paginateEC2Images(values []ec2types.Image, marker string, limit int) ([]ec2types.Image, string) {
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

func paginateBatchComputeEnvironments(values []batchtypes.ComputeEnvironmentDetail, marker string, limit int) ([]batchtypes.ComputeEnvironmentDetail, string) {
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

func paginateEBSVolumes(values []ec2types.Volume, marker string, limit int) ([]ec2types.Volume, string) {
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

func paginateBatchJobQueues(values []batchtypes.JobQueueDetail, marker string, limit int) ([]batchtypes.JobQueueDetail, string) {
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

func paginateEBSSnapshots(values []ec2types.Snapshot, marker string, limit int) ([]ec2types.Snapshot, string) {
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

func paginateS3AccessPoints(values []s3controltypes.AccessPoint, marker string, limit int) ([]s3controltypes.AccessPoint, string) {
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

func paginateS3MultiRegionAccessPoints(values []s3controltypes.MultiRegionAccessPointReport, marker string, limit int) ([]s3controltypes.MultiRegionAccessPointReport, string) {
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

func paginateDataSyncTasks(values []datasynctypes.TaskListEntry, marker string, limit int) ([]datasynctypes.TaskListEntry, string) {
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

func paginateDataSyncLocations(values []datasynctypes.LocationListEntry, marker string, limit int) ([]datasynctypes.LocationListEntry, string) {
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

func (f fakeAWS) DescribeComputeEnvironments(_ context.Context, input *batch.DescribeComputeEnvironmentsInput, _ ...func(*batch.Options)) (*batch.DescribeComputeEnvironmentsOutput, error) {
	environments, next := paginateBatchComputeEnvironments(f.compute.batchComputeEnvironments, awssdk.ToString(input.NextToken), int(awssdk.ToInt32(input.MaxResults)))
	return &batch.DescribeComputeEnvironmentsOutput{ComputeEnvironments: environments, NextToken: stringPtr(next)}, nil
}

func (f fakeAWS) DescribeJobQueues(_ context.Context, input *batch.DescribeJobQueuesInput, _ ...func(*batch.Options)) (*batch.DescribeJobQueuesOutput, error) {
	queues, next := paginateBatchJobQueues(f.compute.batchJobQueues, awssdk.ToString(input.NextToken), int(awssdk.ToInt32(input.MaxResults)))
	return &batch.DescribeJobQueuesOutput{JobQueues: queues, NextToken: stringPtr(next)}, nil
}

func (f fakeAWS) ListProjects(context.Context, *codebuild.ListProjectsInput, ...func(*codebuild.Options)) (*codebuild.ListProjectsOutput, error) {
	return &codebuild.ListProjectsOutput{Projects: f.codeBuildProjects}, nil
}

func (f fakeAWS) BatchGetProjects(_ context.Context, input *codebuild.BatchGetProjectsInput, _ ...func(*codebuild.Options)) (*codebuild.BatchGetProjectsOutput, error) {
	projects := make([]codebuildtypes.Project, 0, len(input.Names))
	for _, name := range input.Names {
		if project, ok := f.codeBuildProjectDetail[name]; ok {
			projects = append(projects, project)
		}
	}
	return &codebuild.BatchGetProjectsOutput{Projects: projects}, nil
}

func (f fakeAWS) ListSourceCredentials(context.Context, *codebuild.ListSourceCredentialsInput, ...func(*codebuild.Options)) (*codebuild.ListSourceCredentialsOutput, error) {
	return &codebuild.ListSourceCredentialsOutput{SourceCredentialsInfos: f.codeBuildSourceCredentials}, nil
}

func (f fakeAWS) DescribeSecurityGroups(context.Context, *ec2.DescribeSecurityGroupsInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	return &ec2.DescribeSecurityGroupsOutput{SecurityGroups: f.securityGroups}, nil
}

func (f fakeAWS) DescribeVpcs(context.Context, *ec2.DescribeVpcsInput, ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error) {
	return &ec2.DescribeVpcsOutput{Vpcs: f.vpcs}, nil
}

func (f fakeAWS) DescribeSubnets(context.Context, *ec2.DescribeSubnetsInput, ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error) {
	return &ec2.DescribeSubnetsOutput{Subnets: f.subnets}, nil
}

func (f fakeAWS) DescribeRouteTables(context.Context, *ec2.DescribeRouteTablesInput, ...func(*ec2.Options)) (*ec2.DescribeRouteTablesOutput, error) {
	return &ec2.DescribeRouteTablesOutput{RouteTables: f.routeTables}, nil
}

func (f fakeAWS) DescribeNetworkAcls(context.Context, *ec2.DescribeNetworkAclsInput, ...func(*ec2.Options)) (*ec2.DescribeNetworkAclsOutput, error) {
	return &ec2.DescribeNetworkAclsOutput{NetworkAcls: f.networkACLs}, nil
}

func (f fakeAWS) DescribeInternetGateways(context.Context, *ec2.DescribeInternetGatewaysInput, ...func(*ec2.Options)) (*ec2.DescribeInternetGatewaysOutput, error) {
	return &ec2.DescribeInternetGatewaysOutput{InternetGateways: f.internetGateways}, nil
}

func (f fakeAWS) DescribeNatGateways(context.Context, *ec2.DescribeNatGatewaysInput, ...func(*ec2.Options)) (*ec2.DescribeNatGatewaysOutput, error) {
	return &ec2.DescribeNatGatewaysOutput{NatGateways: f.natGateways}, nil
}

func (f fakeAWS) DescribeFlowLogs(context.Context, *ec2.DescribeFlowLogsInput, ...func(*ec2.Options)) (*ec2.DescribeFlowLogsOutput, error) {
	return &ec2.DescribeFlowLogsOutput{FlowLogs: f.flowLogs}, nil
}

func (f fakeAWS) DescribeVpcEndpoints(context.Context, *ec2.DescribeVpcEndpointsInput, ...func(*ec2.Options)) (*ec2.DescribeVpcEndpointsOutput, error) {
	return &ec2.DescribeVpcEndpointsOutput{VpcEndpoints: f.vpcEndpoints}, nil
}

func (f fakeAWS) DescribeInstances(_ context.Context, input *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	instances, next := paginateEC2Instances(f.compute.instances, awssdk.ToString(input.NextToken), int(awssdk.ToInt32(input.MaxResults)))
	return &ec2.DescribeInstancesOutput{Reservations: []ec2types.Reservation{{Instances: instances}}, NextToken: stringPtr(next)}, nil
}

func (f fakeAWS) DescribeImages(_ context.Context, input *ec2.DescribeImagesInput, _ ...func(*ec2.Options)) (*ec2.DescribeImagesOutput, error) {
	images, next := paginateEC2Images(f.compute.images, awssdk.ToString(input.NextToken), int(awssdk.ToInt32(input.MaxResults)))
	return &ec2.DescribeImagesOutput{Images: images, NextToken: stringPtr(next)}, nil
}

func (f fakeAWS) DescribeAddresses(context.Context, *ec2.DescribeAddressesInput, ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
	return &ec2.DescribeAddressesOutput{Addresses: f.addresses}, nil
}

func (f fakeAWS) DescribeNetworkInterfaces(context.Context, *ec2.DescribeNetworkInterfacesInput, ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
	return &ec2.DescribeNetworkInterfacesOutput{NetworkInterfaces: f.networkInterfaces}, nil
}

func (f fakeAWS) DescribeVolumes(_ context.Context, input *ec2.DescribeVolumesInput, _ ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error) {
	volumes, next := paginateEBSVolumes(f.ebsVolumes, awssdk.ToString(input.NextToken), int(awssdk.ToInt32(input.MaxResults)))
	return &ec2.DescribeVolumesOutput{Volumes: volumes, NextToken: stringPtr(next)}, nil
}

func (f fakeAWS) DescribeSnapshots(_ context.Context, input *ec2.DescribeSnapshotsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error) {
	snapshots, next := paginateEBSSnapshots(f.ebsSnapshots, awssdk.ToString(input.NextToken), int(awssdk.ToInt32(input.MaxResults)))
	return &ec2.DescribeSnapshotsOutput{Snapshots: snapshots, NextToken: stringPtr(next)}, nil
}

func (f fakeAWS) DescribeSnapshotAttribute(_ context.Context, input *ec2.DescribeSnapshotAttributeInput, _ ...func(*ec2.Options)) (*ec2.DescribeSnapshotAttributeOutput, error) {
	var permissions []ec2types.CreateVolumePermission
	if f.ebsSnapshotPublic[awssdk.ToString(input.SnapshotId)] {
		permissions = append(permissions, ec2types.CreateVolumePermission{Group: ec2types.PermissionGroupAll})
	}
	return &ec2.DescribeSnapshotAttributeOutput{SnapshotId: input.SnapshotId, CreateVolumePermissions: permissions}, nil
}

func (f fakeAWS) GetEbsEncryptionByDefault(context.Context, *ec2.GetEbsEncryptionByDefaultInput, ...func(*ec2.Options)) (*ec2.GetEbsEncryptionByDefaultOutput, error) {
	return &ec2.GetEbsEncryptionByDefaultOutput{EbsEncryptionByDefault: awssdk.Bool(f.ebsEncryptionByDefault)}, nil
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

func (f fakeAWS) ListOriginAccessControls(context.Context, *cloudfront.ListOriginAccessControlsInput, ...func(*cloudfront.Options)) (*cloudfront.ListOriginAccessControlsOutput, error) {
	return &cloudfront.ListOriginAccessControlsOutput{OriginAccessControlList: &cloudfronttypes.OriginAccessControlList{Items: f.originAccessCtrls}}, nil
}

func (f fakeAWS) ListKeyGroups(context.Context, *cloudfront.ListKeyGroupsInput, ...func(*cloudfront.Options)) (*cloudfront.ListKeyGroupsOutput, error) {
	return &cloudfront.ListKeyGroupsOutput{KeyGroupList: &cloudfronttypes.KeyGroupList{Items: f.keyGroups}}, nil
}

func (f fakeAWS) ListPublicKeys(context.Context, *cloudfront.ListPublicKeysInput, ...func(*cloudfront.Options)) (*cloudfront.ListPublicKeysOutput, error) {
	return &cloudfront.ListPublicKeysOutput{PublicKeyList: &cloudfronttypes.PublicKeyList{Items: f.publicKeys}}, nil
}

func (f fakeAWS) ListResponseHeadersPolicies(context.Context, *cloudfront.ListResponseHeadersPoliciesInput, ...func(*cloudfront.Options)) (*cloudfront.ListResponseHeadersPoliciesOutput, error) {
	return &cloudfront.ListResponseHeadersPoliciesOutput{ResponseHeadersPolicyList: &cloudfronttypes.ResponseHeadersPolicyList{Items: f.responsePolicies}}, nil
}

func (f fakeAWS) DescribeLoadBalancers(context.Context, *elbv2.DescribeLoadBalancersInput, ...func(*elbv2.Options)) (*elbv2.DescribeLoadBalancersOutput, error) {
	return &elbv2.DescribeLoadBalancersOutput{LoadBalancers: f.loadBalancers}, nil
}

func (f fakeAWS) DescribeListeners(_ context.Context, input *elbv2.DescribeListenersInput, _ ...func(*elbv2.Options)) (*elbv2.DescribeListenersOutput, error) {
	loadBalancerARN := awssdk.ToString(input.LoadBalancerArn)
	if loadBalancerARN == "" {
		return &elbv2.DescribeListenersOutput{}, nil
	}
	listeners := make([]elbv2types.Listener, 0, len(f.elbv2Listeners))
	for _, listener := range f.elbv2Listeners {
		if awssdk.ToString(listener.LoadBalancerArn) == loadBalancerARN {
			listeners = append(listeners, listener)
		}
	}
	return &elbv2.DescribeListenersOutput{Listeners: listeners}, nil
}

func (f fakeAWS) DescribeTargetGroups(context.Context, *elbv2.DescribeTargetGroupsInput, ...func(*elbv2.Options)) (*elbv2.DescribeTargetGroupsOutput, error) {
	return &elbv2.DescribeTargetGroupsOutput{TargetGroups: f.elbv2TargetGroups}, nil
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

func (f fakeAWS) ListTables(context.Context, *dynamodb.ListTablesInput, ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error) {
	names := make([]string, 0, len(f.dynamoDBTables))
	for _, table := range f.dynamoDBTables {
		if name := awssdk.ToString(table.TableName); name != "" {
			names = append(names, name)
		}
	}
	return &dynamodb.ListTablesOutput{TableNames: names}, nil
}

func (f fakeAWS) DescribeTable(_ context.Context, input *dynamodb.DescribeTableInput, _ ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
	name := awssdk.ToString(input.TableName)
	for _, table := range f.dynamoDBTables {
		if awssdk.ToString(table.TableName) == name || awssdk.ToString(table.TableArn) == name {
			copy := table
			return &dynamodb.DescribeTableOutput{Table: &copy}, nil
		}
	}
	return &dynamodb.DescribeTableOutput{}, nil
}

func (f fakeAWS) ListTagsOfResource(_ context.Context, input *dynamodb.ListTagsOfResourceInput, _ ...func(*dynamodb.Options)) (*dynamodb.ListTagsOfResourceOutput, error) {
	return &dynamodb.ListTagsOfResourceOutput{Tags: f.dynamoDBTags[awssdk.ToString(input.ResourceArn)]}, nil
}

func (f fakeAWS) DescribeContinuousBackups(_ context.Context, input *dynamodb.DescribeContinuousBackupsInput, _ ...func(*dynamodb.Options)) (*dynamodb.DescribeContinuousBackupsOutput, error) {
	if f.dynamoDBContinuousBackups == nil {
		return &dynamodb.DescribeContinuousBackupsOutput{}, nil
	}
	description := f.dynamoDBContinuousBackups[awssdk.ToString(input.TableName)]
	return &dynamodb.DescribeContinuousBackupsOutput{ContinuousBackupsDescription: &description}, nil
}

func (f fakeAWS) DescribeTimeToLive(_ context.Context, input *dynamodb.DescribeTimeToLiveInput, _ ...func(*dynamodb.Options)) (*dynamodb.DescribeTimeToLiveOutput, error) {
	if f.dynamoDBTimeToLive == nil {
		return &dynamodb.DescribeTimeToLiveOutput{}, nil
	}
	description := f.dynamoDBTimeToLive[awssdk.ToString(input.TableName)]
	return &dynamodb.DescribeTimeToLiveOutput{TimeToLiveDescription: &description}, nil
}

func (f fakeAWS) ListBackups(context.Context, *dynamodb.ListBackupsInput, ...func(*dynamodb.Options)) (*dynamodb.ListBackupsOutput, error) {
	return &dynamodb.ListBackupsOutput{BackupSummaries: f.dynamoDBBackups}, nil
}

func (f fakeAWS) ListStreams(context.Context, *dynamodbstreams.ListStreamsInput, ...func(*dynamodbstreams.Options)) (*dynamodbstreams.ListStreamsOutput, error) {
	streams := make([]dynamodbstreamstypes.Stream, 0, len(f.dynamoDBStreams))
	for _, stream := range f.dynamoDBStreams {
		streams = append(streams, dynamodbstreamstypes.Stream{StreamArn: stream.StreamArn, StreamLabel: stream.StreamLabel, TableName: stream.TableName})
	}
	return &dynamodbstreams.ListStreamsOutput{Streams: streams}, nil
}

func (f fakeAWS) DescribeStream(_ context.Context, input *dynamodbstreams.DescribeStreamInput, _ ...func(*dynamodbstreams.Options)) (*dynamodbstreams.DescribeStreamOutput, error) {
	arn := awssdk.ToString(input.StreamArn)
	for _, stream := range f.dynamoDBStreams {
		if awssdk.ToString(stream.StreamArn) == arn {
			copy := stream
			return &dynamodbstreams.DescribeStreamOutput{StreamDescription: &copy}, nil
		}
	}
	return &dynamodbstreams.DescribeStreamOutput{}, nil
}

func (f fakeAWS) ListBuckets(context.Context, *s3.ListBucketsInput, ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	return &s3.ListBucketsOutput{Buckets: f.s3Buckets}, nil
}

func (f fakeAWS) GetBucketLocation(_ context.Context, input *s3.GetBucketLocationInput, _ ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error) {
	return &s3.GetBucketLocationOutput{LocationConstraint: f.s3BucketRegions[awssdk.ToString(input.Bucket)]}, nil
}

func (f fakeAWS) GetBucketTagging(_ context.Context, input *s3.GetBucketTaggingInput, _ ...func(*s3.Options)) (*s3.GetBucketTaggingOutput, error) {
	if f.s3OptionalError != nil {
		return nil, f.s3OptionalError
	}
	return &s3.GetBucketTaggingOutput{TagSet: f.s3Tags[awssdk.ToString(input.Bucket)]}, nil
}

func (f fakeAWS) GetBucketEncryption(_ context.Context, input *s3.GetBucketEncryptionInput, _ ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error) {
	if f.s3OptionalError != nil {
		return nil, f.s3OptionalError
	}
	return &s3.GetBucketEncryptionOutput{ServerSideEncryptionConfiguration: f.s3Encryption[awssdk.ToString(input.Bucket)]}, nil
}

func (f fakeAWS) GetBucketVersioning(_ context.Context, input *s3.GetBucketVersioningInput, _ ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error) {
	if f.s3OptionalError != nil {
		return nil, f.s3OptionalError
	}
	return &s3.GetBucketVersioningOutput{Status: f.s3Versioning[awssdk.ToString(input.Bucket)]}, nil
}

func (f fakeAWS) GetBucketLogging(_ context.Context, input *s3.GetBucketLoggingInput, _ ...func(*s3.Options)) (*s3.GetBucketLoggingOutput, error) {
	if f.s3OptionalError != nil {
		return nil, f.s3OptionalError
	}
	if f.s3Logging[awssdk.ToString(input.Bucket)] {
		return &s3.GetBucketLoggingOutput{LoggingEnabled: &s3types.LoggingEnabled{}}, nil
	}
	return &s3.GetBucketLoggingOutput{}, nil
}

func (f fakeAWS) GetPublicAccessBlock(_ context.Context, input *s3.GetPublicAccessBlockInput, _ ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
	if f.s3OptionalError != nil {
		return nil, f.s3OptionalError
	}
	return &s3.GetPublicAccessBlockOutput{PublicAccessBlockConfiguration: f.s3PublicAccessBlocks[awssdk.ToString(input.Bucket)]}, nil
}

func (f fakeAWS) DescribeDBInstances(context.Context, *rds.DescribeDBInstancesInput, ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error) {
	return &rds.DescribeDBInstancesOutput{DBInstances: f.rdsInstances}, nil
}

func (f fakeAWS) DescribeDBSnapshots(context.Context, *rds.DescribeDBSnapshotsInput, ...func(*rds.Options)) (*rds.DescribeDBSnapshotsOutput, error) {
	return &rds.DescribeDBSnapshotsOutput{DBSnapshots: f.rdsDBSnapshots}, nil
}

func (f fakeAWS) DescribeDBSnapshotAttributes(_ context.Context, input *rds.DescribeDBSnapshotAttributesInput, _ ...func(*rds.Options)) (*rds.DescribeDBSnapshotAttributesOutput, error) {
	snapshotID := awssdk.ToString(input.DBSnapshotIdentifier)
	return &rds.DescribeDBSnapshotAttributesOutput{
		DBSnapshotAttributesResult: &rdstypes.DBSnapshotAttributesResult{
			DBSnapshotAttributes: f.rdsDBSnapshotAttributes[snapshotID],
			DBSnapshotIdentifier: awssdk.String(snapshotID),
		},
	}, nil
}

func (f fakeAWS) DescribeClusters(context.Context, *redshift.DescribeClustersInput, ...func(*redshift.Options)) (*redshift.DescribeClustersOutput, error) {
	return &redshift.DescribeClustersOutput{Clusters: f.redshiftClusters}, nil
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
	if err := f.kmsDescribeErrors[keyID]; err != nil {
		return nil, err
	}
	for _, key := range f.kmsKeys {
		if awssdk.ToString(key.KeyId) == keyID || awssdk.ToString(key.Arn) == keyID {
			copy := key
			return &kms.DescribeKeyOutput{KeyMetadata: &copy}, nil
		}
	}
	return &kms.DescribeKeyOutput{}, nil
}

func (f fakeAWS) ListResourceTags(_ context.Context, input *kms.ListResourceTagsInput, _ ...func(*kms.Options)) (*kms.ListResourceTagsOutput, error) {
	keyID := awssdk.ToString(input.KeyId)
	if err := f.kmsTagErrors[keyID]; err != nil {
		return nil, err
	}
	return &kms.ListResourceTagsOutput{Tags: f.kmsTags[keyID]}, nil
}

func (f fakeAWS) GetKeyRotationStatus(_ context.Context, input *kms.GetKeyRotationStatusInput, _ ...func(*kms.Options)) (*kms.GetKeyRotationStatusOutput, error) {
	keyID := awssdk.ToString(input.KeyId)
	if err := f.kmsRotationErrors[keyID]; err != nil {
		return nil, err
	}
	return &kms.GetKeyRotationStatusOutput{KeyRotationEnabled: f.kmsRotation[keyID]}, nil
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

func (f fakeAWS) DescribeFileSystems(context.Context, *efs.DescribeFileSystemsInput, ...func(*efs.Options)) (*efs.DescribeFileSystemsOutput, error) {
	return &efs.DescribeFileSystemsOutput{FileSystems: f.efsFileSystems}, nil
}

func (f fakeAWS) DescribeMountTargets(_ context.Context, input *efs.DescribeMountTargetsInput, _ ...func(*efs.Options)) (*efs.DescribeMountTargetsOutput, error) {
	return &efs.DescribeMountTargetsOutput{MountTargets: f.efsMountTargets[awssdk.ToString(input.FileSystemId)]}, nil
}

func (f fakeAWS) DescribeMountTargetSecurityGroups(_ context.Context, input *efs.DescribeMountTargetSecurityGroupsInput, _ ...func(*efs.Options)) (*efs.DescribeMountTargetSecurityGroupsOutput, error) {
	return &efs.DescribeMountTargetSecurityGroupsOutput{SecurityGroups: f.efsMountTargetSecurityGroups[awssdk.ToString(input.MountTargetId)]}, nil
}

func (f fakeAWS) DescribeAccessPoints(context.Context, *efs.DescribeAccessPointsInput, ...func(*efs.Options)) (*efs.DescribeAccessPointsOutput, error) {
	return &efs.DescribeAccessPointsOutput{AccessPoints: f.efsAccessPoints}, nil
}

func (f fakeAWS) ListBackupVaults(context.Context, *backup.ListBackupVaultsInput, ...func(*backup.Options)) (*backup.ListBackupVaultsOutput, error) {
	return &backup.ListBackupVaultsOutput{BackupVaultList: f.backupVaults}, nil
}

func (f fakeAWS) ListBackupPlans(context.Context, *backup.ListBackupPlansInput, ...func(*backup.Options)) (*backup.ListBackupPlansOutput, error) {
	return &backup.ListBackupPlansOutput{BackupPlansList: f.backupPlans}, nil
}

func (f fakeAWS) GetBackupPlan(_ context.Context, input *backup.GetBackupPlanInput, _ ...func(*backup.Options)) (*backup.GetBackupPlanOutput, error) {
	if f.backupPlanDetails != nil {
		details := f.backupPlanDetails[awssdk.ToString(input.BackupPlanId)]
		return &details, nil
	}
	return &backup.GetBackupPlanOutput{BackupPlanId: input.BackupPlanId}, nil
}

func (f fakeAWS) ListProtectedResources(context.Context, *backup.ListProtectedResourcesInput, ...func(*backup.Options)) (*backup.ListProtectedResourcesOutput, error) {
	return &backup.ListProtectedResourcesOutput{Results: f.backupProtectedResources}, nil
}

func (f fakeAWS) ListRecoveryPointsByBackupVault(_ context.Context, input *backup.ListRecoveryPointsByBackupVaultInput, _ ...func(*backup.Options)) (*backup.ListRecoveryPointsByBackupVaultOutput, error) {
	return &backup.ListRecoveryPointsByBackupVaultOutput{RecoveryPoints: f.backupRecoveryPoints[awssdk.ToString(input.BackupVaultName)]}, nil
}

func (f fakeAWS) ListTags(_ context.Context, input *backup.ListTagsInput, _ ...func(*backup.Options)) (*backup.ListTagsOutput, error) {
	arn := awssdk.ToString(input.ResourceArn)
	if tags := f.backupVaultTags[arn]; tags != nil {
		return &backup.ListTagsOutput{Tags: tags}, nil
	}
	return &backup.ListTagsOutput{Tags: f.backupPlanTags[arn]}, nil
}

type fakeAPIGatewayV2 struct {
	network fakeAWSNetwork
}

func (f fakeAPIGatewayV2) GetApis(_ context.Context, _ *apigatewayv2.GetApisInput, _ ...func(*apigatewayv2.Options)) (*apigatewayv2.GetApisOutput, error) {
	return &apigatewayv2.GetApisOutput{Items: f.network.apiV2APIs}, nil
}

func (f fakeAPIGatewayV2) GetDomainNames(_ context.Context, _ *apigatewayv2.GetDomainNamesInput, _ ...func(*apigatewayv2.Options)) (*apigatewayv2.GetDomainNamesOutput, error) {
	return &apigatewayv2.GetDomainNamesOutput{Items: f.network.apiV2Domains}, nil
}

func (f fakeAPIGatewayV2) GetStages(_ context.Context, input *apigatewayv2.GetStagesInput, _ ...func(*apigatewayv2.Options)) (*apigatewayv2.GetStagesOutput, error) {
	return &apigatewayv2.GetStagesOutput{Items: f.network.apiV2Stages[awssdk.ToString(input.ApiId)]}, nil
}

func (f fakeAPIGatewayV2) GetRoutes(_ context.Context, input *apigatewayv2.GetRoutesInput, _ ...func(*apigatewayv2.Options)) (*apigatewayv2.GetRoutesOutput, error) {
	return &apigatewayv2.GetRoutesOutput{Items: f.network.apiV2Routes[awssdk.ToString(input.ApiId)]}, nil
}

func (f fakeAPIGatewayV2) GetIntegrations(_ context.Context, input *apigatewayv2.GetIntegrationsInput, _ ...func(*apigatewayv2.Options)) (*apigatewayv2.GetIntegrationsOutput, error) {
	return &apigatewayv2.GetIntegrationsOutput{Items: f.network.apiV2Integrations[awssdk.ToString(input.ApiId)]}, nil
}

func awsTestAPIGatewayIntegrationKey(apiID string, resourceID string, method string) string {
	return apiID + "/" + resourceID + "/" + method
}

func timePtr(value string) *time.Time {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		panic(err)
	}
	return &parsed
}
