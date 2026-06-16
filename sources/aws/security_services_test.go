package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	accessanalyzertypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	configtypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	guarddutytypes "github.com/aws/aws-sdk-go-v2/service/guardduty/types"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	inspector2types "github.com/aws/aws-sdk-go-v2/service/inspector2/types"
	"github.com/aws/aws-sdk-go-v2/service/macie2"
	macie2types "github.com/aws/aws-sdk-go-v2/service/macie2/types"
	"github.com/aws/aws-sdk-go-v2/service/networkfirewall"
	networkfirewalltypes "github.com/aws/aws-sdk-go-v2/service/networkfirewall/types"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	securityhubtypes "github.com/aws/aws-sdk-go-v2/service/securityhub/types"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	wafv2types "github.com/aws/aws-sdk-go-v2/service/wafv2/types"
	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestReadAWSSecurityServiceEvents(t *testing.T) {
	fake := &fakeAWSSecurityServices{
		analyzers: []accessanalyzertypes.AnalyzerSummary{{
			Arn:    awssdk.String("arn:aws:access-analyzer:us-east-1:123456789012:analyzer/account"),
			Name:   awssdk.String("account"),
			Status: accessanalyzertypes.AnalyzerStatus("ACTIVE"),
			Type:   accessanalyzertypes.TypeAccount,
		}},
		configRecorders: []configtypes.ConfigurationRecorder{{
			Arn:     awssdk.String("arn:aws:config:us-east-1:123456789012:configuration-recorder/default"),
			Name:    awssdk.String("default"),
			RoleARN: awssdk.String("arn:aws:iam::123456789012:role/aws-config"),
			RecordingGroup: &configtypes.RecordingGroup{
				AllSupported:               true,
				IncludeGlobalResourceTypes: true,
			},
		}},
		configStatuses: []configtypes.ConfigurationRecorderStatus{{
			Arn:       awssdk.String("arn:aws:config:us-east-1:123456789012:configuration-recorder/default"),
			Name:      awssdk.String("default"),
			Recording: true,
		}},
		guardDutyDetectorIDs: []string{"detector-1"},
		guardDutyDetectors: map[string]guardduty.GetDetectorOutput{"detector-1": {
			CreatedAt:                  awssdk.String("2026-04-23T00:00:00Z"),
			Features:                   []guarddutytypes.DetectorFeatureConfigurationResult{{Name: guarddutytypes.DetectorFeatureResultS3DataEvents, Status: guarddutytypes.FeatureStatusEnabled}},
			FindingPublishingFrequency: guarddutytypes.FindingPublishingFrequencyFifteenMinutes,
			ServiceRole:                awssdk.String("arn:aws:iam::123456789012:role/aws-guardduty"),
			Status:                     guarddutytypes.DetectorStatusEnabled,
			UpdatedAt:                  awssdk.String("2026-04-23T00:00:00Z"),
		}},
		guardDutyFindingIDs: map[string][]string{"detector-1": {"gd-finding-1"}},
		guardDutyFindings: map[string]guarddutytypes.Finding{"gd-finding-1": {
			AccountId: awssdk.String("123456789012"),
			Arn:       awssdk.String("arn:aws:guardduty:us-east-1:123456789012:detector/detector-1/finding/gd-finding-1"),
			Id:        awssdk.String("gd-finding-1"),
			Region:    awssdk.String("us-east-1"),
			Resource: &guarddutytypes.Resource{
				InstanceDetails: &guarddutytypes.InstanceDetails{InstanceId: awssdk.String("i-123")},
				ResourceType:    awssdk.String("Instance"),
			},
			Severity: awssdk.Float64(8),
			Title:    awssdk.String("Credential exfiltration"),
			Type:     awssdk.String("UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration"),
		}},
		securityHubFindings: []securityhubtypes.AwsSecurityFinding{{
			AwsAccountId: awssdk.String("123456789012"),
			Id:           awssdk.String("securityhub-finding-1"),
			Region:       awssdk.String("us-east-1"),
			Resources: []securityhubtypes.Resource{{
				Id:     awssdk.String("arn:aws:s3:::prod-data"),
				Region: awssdk.String("us-east-1"),
				Type:   awssdk.String("AwsS3Bucket"),
			}},
			Severity: &securityhubtypes.Severity{Label: securityhubtypes.SeverityLabel("HIGH"), Normalized: awssdk.Int32(70)},
			Title:    awssdk.String("S3 bucket allows public access"),
		}},
		inspector2Findings: []inspector2types.Finding{{
			AwsAccountId: awssdk.String("123456789012"),
			FindingArn:   awssdk.String("arn:aws:inspector2:us-east-1:123456789012:finding/inspector-finding-1"),
			Resources: []inspector2types.Resource{{
				Id:     awssdk.String("i-123"),
				Region: awssdk.String("us-east-1"),
				Type:   inspector2types.ResourceType("AWS_EC2_INSTANCE"),
			}},
			Severity: inspector2types.Severity("HIGH"),
			Status:   inspector2types.FindingStatus("ACTIVE"),
			Title:    awssdk.String("CVE finding"),
			Type:     inspector2types.FindingType("PACKAGE_VULNERABILITY"),
		}},
		macieFindingIDs: []string{"macie-finding-1"},
		macieFindings: []macie2types.Finding{{
			AccountId: awssdk.String("123456789012"),
			Id:        awssdk.String("macie-finding-1"),
			Region:    awssdk.String("us-east-1"),
			ResourcesAffected: &macie2types.ResourcesAffected{
				S3Bucket: &macie2types.S3Bucket{Name: awssdk.String("prod-data")},
				S3Object: &macie2types.S3Object{
					Key:          awssdk.String("exports/customer.csv"),
					PublicAccess: awssdk.Bool(true),
				},
			},
			Severity: &macie2types.Severity{Description: macie2types.SeverityDescription("HIGH"), Score: awssdk.Int64(8)},
			Title:    awssdk.String("Public sensitive data"),
		}},
		wafv2Summaries: []wafv2types.WebACLSummary{{
			ARN:  awssdk.String("arn:aws:wafv2:us-east-1:123456789012:regional/webacl/app/acl-1"),
			Id:   awssdk.String("acl-1"),
			Name: awssdk.String("app"),
		}},
		wafv2Details: map[string]wafv2types.WebACL{"arn:aws:wafv2:us-east-1:123456789012:regional/webacl/app/acl-1": {
			ARN:           awssdk.String("arn:aws:wafv2:us-east-1:123456789012:regional/webacl/app/acl-1"),
			Capacity:      25,
			DefaultAction: &wafv2types.DefaultAction{Block: &wafv2types.BlockAction{}},
			Id:            awssdk.String("acl-1"),
			Name:          awssdk.String("app"),
			VisibilityConfig: &wafv2types.VisibilityConfig{
				CloudWatchMetricsEnabled: true,
				MetricName:               awssdk.String("app"),
				SampledRequestsEnabled:   true,
			},
		}},
		firewalls: []networkfirewalltypes.FirewallMetadata{{
			FirewallArn:  awssdk.String("arn:aws:network-firewall:us-east-1:123456789012:firewall/prod-fw"),
			FirewallName: awssdk.String("prod-fw"),
		}},
		firewallDetails: map[string]networkfirewalltypes.Firewall{"arn:aws:network-firewall:us-east-1:123456789012:firewall/prod-fw": {
			FirewallArn:       awssdk.String("arn:aws:network-firewall:us-east-1:123456789012:firewall/prod-fw"),
			FirewallId:        awssdk.String("fw-1"),
			FirewallName:      awssdk.String("prod-fw"),
			FirewallPolicyArn: awssdk.String("arn:aws:network-firewall:us-east-1:123456789012:firewall-policy/prod"),
			SubnetMappings:    []networkfirewalltypes.SubnetMapping{{SubnetId: awssdk.String("subnet-1")}},
			VpcId:             awssdk.String("vpc-1"),
		}},
	}
	source := newSecurityTestSource(t, fake)

	for _, tt := range []struct {
		family string
		kind   string
		attr   string
		want   string
		config map[string]string
	}{
		{family: familyAccessAnalyzer, kind: "aws.access_analyzer", attr: "status", want: "ACTIVE"},
		{family: familyConfigRecorder, kind: "aws.config_recorder", attr: "recording", want: "true"},
		{family: familyGuardDutyDetector, kind: "aws.guardduty_detector", attr: "status", want: "ENABLED"},
		{family: familyGuardDutyFinding, kind: "aws.guardduty_finding", attr: "affected_resource_id", want: "i-123"},
		{family: familySecurityHubFinding, kind: "aws.securityhub_finding", attr: "affected_resource_id", want: "arn:aws:s3:::prod-data"},
		{family: familyInspector2Finding, kind: "aws.inspector2_finding", attr: "affected_resource_type", want: "AWS_EC2_INSTANCE"},
		{family: familyMacie2Finding, kind: "aws.macie2_finding", attr: "internet_exposed", want: "true"},
		{family: familyWAFV2WebACL, kind: "aws.wafv2_web_acl", attr: "default_action", want: "block", config: map[string]string{"wafv2_scope": "CLOUDFRONT"}},
		{family: familyNetworkFirewall, kind: "aws.network_firewall", attr: "vpc_id", want: "vpc-1"},
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
			event := pull.Events[0]
			if event.Kind != tt.kind {
				t.Fatalf("kind = %q, want %q", event.Kind, tt.kind)
			}
			if got := event.Attributes[tt.attr]; got != tt.want {
				t.Fatalf("attribute %s = %q, want %q", tt.attr, got, tt.want)
			}
		})
	}
	if fake.lastWAFV2Scope != wafv2types.ScopeCloudfront {
		t.Fatalf("wafv2 scope = %q, want CLOUDFRONT", fake.lastWAFV2Scope)
	}
}

func TestReadAWSGuardDutyDetectorMissingEmitsDisabled(t *testing.T) {
	source := newSecurityTestSource(t, &fakeAWSSecurityServices{})
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"account_id": "123456789012", "family": familyGuardDutyDetector}), nil)
	if err != nil {
		t.Fatalf("Read(guardduty_detector) error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if got := event.Attributes["status"]; got != "DISABLED" {
		t.Fatalf("status = %q, want DISABLED", got)
	}
	if got := event.Attributes["missing"]; got != "true" {
		t.Fatalf("missing = %q, want true", got)
	}
}

func TestReadAWSSecurityHubUnavailableReturnsEmpty(t *testing.T) {
	source := newSecurityTestSource(t, &fakeAWSSecurityServices{
		securityHubError: errors.New("InvalidAccessException: Security Hub is not enabled"),
	})

	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"account_id": "123456789012", "family": familySecurityHubFinding}), nil)
	if err != nil {
		t.Fatalf("Read(securityhub_finding) error = %v", err)
	}
	if len(pull.Events) != 0 {
		t.Fatalf("len(Events) = %d, want 0", len(pull.Events))
	}
}

func TestListSecurityHubFindingsRetriesExpiredCursor(t *testing.T) {
	fake := &fakeAWSSecurityServices{
		securityHubExpiredTokenError: errors.New("InvalidInputException: Invalid NextToken: token expired"),
		securityHubFindings:          []securityhubtypes.AwsSecurityFinding{{Id: awssdk.String("finding-1")}},
	}
	clients := awsClients{awsSecurityClients: awsSecurityClients{securityHub: fakeSecurityHubSecurity{fake: fake}}}

	records, next, err := listSecurityHubFindings(context.Background(), clients, settings{}, "expired-token", 10)
	if err != nil {
		t.Fatalf("listSecurityHubFindings() error = %v", err)
	}
	if next != "" {
		t.Fatalf("next = %q, want empty", next)
	}
	if len(records) != 1 {
		t.Fatalf("len(records) = %d, want 1", len(records))
	}
	if got := fake.securityHubTokens; len(got) != 2 || got[0] != "expired-token" || got[1] != "" {
		t.Fatalf("securityHubTokens = %#v, want expired-token then empty", got)
	}
}

func TestReadAWSFindingFamiliesWithCheckpointUseUpdatedTimeRequests(t *testing.T) {
	watermark := time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)
	checkpoint := awsSecurityTestCheckpoint(watermark)

	t.Run("securityhub", func(t *testing.T) {
		fake := &fakeAWSSecurityServices{
			securityHubFindings: []securityhubtypes.AwsSecurityFinding{
				{Id: awssdk.String("new-finding"), UpdatedAt: awssdk.String(watermark.Add(time.Hour).Format(time.RFC3339))},
				{Id: awssdk.String("old-finding"), UpdatedAt: awssdk.String(watermark.Add(-time.Hour).Format(time.RFC3339))},
			},
		}
		source := newSecurityTestSource(t, fake)
		pull, err := source.ReadWithCheckpoint(context.Background(), sourcecdk.NewConfig(map[string]string{"account_id": "123456789012", "family": familySecurityHubFinding}), nil, checkpoint)
		if err != nil {
			t.Fatalf("ReadWithCheckpoint(securityhub_finding) error = %v", err)
		}
		if len(pull.Events) != 1 || pull.Events[0].GetId() != "aws-securityhub-finding-new-finding" {
			t.Fatalf("events = %#v, want only new Security Hub finding", pull.Events)
		}
		if pull.ShortCircuitReason != sourcecdk.PullShortCircuitReasonWatermarkReached {
			t.Fatalf("ShortCircuitReason = %q, want watermark_reached", pull.ShortCircuitReason)
		}
		if len(fake.securityHubInputs) != 1 {
			t.Fatalf("len(securityHubInputs) = %d, want 1", len(fake.securityHubInputs))
		}
		input := fake.securityHubInputs[0]
		if len(input.SortCriteria) != 1 || awssdk.ToString(input.SortCriteria[0].Field) != "UpdatedAt" || input.SortCriteria[0].SortOrder != securityhubtypes.SortOrderDescending {
			t.Fatalf("Security Hub sort = %#v, want UpdatedAt desc", input.SortCriteria)
		}
		if input.Filters == nil || len(input.Filters.UpdatedAt) != 1 {
			t.Fatalf("Security Hub UpdatedAt filter = %#v, want one start filter", input.Filters)
		}
		assertAWSFindingFilterStart(t, awssdk.ToString(input.Filters.UpdatedAt[0].Start), watermark)
	})

	t.Run("guardduty", func(t *testing.T) {
		fake := &fakeAWSSecurityServices{
			guardDutyDetectorIDs: []string{"detector-1"},
			guardDutyFindingIDs:  map[string][]string{"detector-1": {"new-finding", "old-finding"}},
			guardDutyFindings: map[string]guarddutytypes.Finding{
				"new-finding": {Arn: awssdk.String("arn:aws:guardduty:us-east-1:123456789012:detector/detector-1/finding/new-finding"), Id: awssdk.String("new-finding"), UpdatedAt: awssdk.String(watermark.Add(time.Hour).Format(time.RFC3339))},
				"old-finding": {Arn: awssdk.String("arn:aws:guardduty:us-east-1:123456789012:detector/detector-1/finding/old-finding"), Id: awssdk.String("old-finding"), UpdatedAt: awssdk.String(watermark.Add(-time.Hour).Format(time.RFC3339))},
			},
		}
		source := newSecurityTestSource(t, fake)
		pull, err := source.ReadWithCheckpoint(context.Background(), sourcecdk.NewConfig(map[string]string{"account_id": "123456789012", "family": familyGuardDutyFinding}), nil, checkpoint)
		if err != nil {
			t.Fatalf("ReadWithCheckpoint(guardduty_finding) error = %v", err)
		}
		if len(pull.Events) != 1 || pull.Events[0].GetAttributes()["finding_id"] != "new-finding" {
			t.Fatalf("events = %#v, want only new GuardDuty finding", pull.Events)
		}
		if len(fake.guardDutyListInputs) != 1 {
			t.Fatalf("len(guardDutyListInputs) = %d, want 1", len(fake.guardDutyListInputs))
		}
		input := fake.guardDutyListInputs[0]
		if input.SortCriteria == nil || awssdk.ToString(input.SortCriteria.AttributeName) != "updatedAt" || input.SortCriteria.OrderBy != guarddutytypes.OrderByDesc {
			t.Fatalf("GuardDuty sort = %#v, want updatedAt DESC", input.SortCriteria)
		}
		condition := input.FindingCriteria.Criterion["updatedAt"]
		if condition.GreaterThanOrEqual == nil || *condition.GreaterThanOrEqual != watermark.Add(-awsFindingCheckpointLookback).UnixMilli() {
			t.Fatalf("GuardDuty updatedAt gte = %#v, want %d", condition.GreaterThanOrEqual, watermark.Add(-awsFindingCheckpointLookback).UnixMilli())
		}
	})

	t.Run("macie", func(t *testing.T) {
		newUpdatedAt := watermark.Add(time.Hour)
		oldUpdatedAt := watermark.Add(-time.Hour)
		fake := &fakeAWSSecurityServices{
			macieFindingIDs: []string{"new-finding", "old-finding"},
			macieFindings: []macie2types.Finding{
				{Id: awssdk.String("new-finding"), UpdatedAt: &newUpdatedAt},
				{Id: awssdk.String("old-finding"), UpdatedAt: &oldUpdatedAt},
			},
		}
		source := newSecurityTestSource(t, fake)
		pull, err := source.ReadWithCheckpoint(context.Background(), sourcecdk.NewConfig(map[string]string{"account_id": "123456789012", "family": familyMacie2Finding}), nil, checkpoint)
		if err != nil {
			t.Fatalf("ReadWithCheckpoint(macie2_finding) error = %v", err)
		}
		if len(pull.Events) != 1 || pull.Events[0].GetId() != "aws-macie2-finding-new-finding" {
			t.Fatalf("events = %#v, want only new Macie finding", pull.Events)
		}
		if len(fake.macieListInputs) != 1 {
			t.Fatalf("len(macieListInputs) = %d, want 1", len(fake.macieListInputs))
		}
		input := fake.macieListInputs[0]
		if input.SortCriteria == nil || awssdk.ToString(input.SortCriteria.AttributeName) != "updatedAt" || input.SortCriteria.OrderBy != macie2types.OrderByDesc {
			t.Fatalf("Macie sort = %#v, want updatedAt DESC", input.SortCriteria)
		}
		criterion := input.FindingCriteria.Criterion["updatedAt"]
		if criterion.Gte == nil || *criterion.Gte != watermark.Add(-awsFindingCheckpointLookback).UnixMilli() {
			t.Fatalf("Macie updatedAt gte = %#v, want %d", criterion.Gte, watermark.Add(-awsFindingCheckpointLookback).UnixMilli())
		}
	})

	t.Run("inspector2", func(t *testing.T) {
		newObservedAt := watermark.Add(time.Hour)
		oldObservedAt := watermark.Add(-time.Hour)
		fake := &fakeAWSSecurityServices{
			inspector2Findings: []inspector2types.Finding{
				{FindingArn: awssdk.String("arn:aws:inspector2:us-east-1:123456789012:finding/new-finding"), LastObservedAt: &newObservedAt},
				{FindingArn: awssdk.String("arn:aws:inspector2:us-east-1:123456789012:finding/old-finding"), LastObservedAt: &oldObservedAt},
			},
		}
		source := newSecurityTestSource(t, fake)
		pull, err := source.ReadWithCheckpoint(context.Background(), sourcecdk.NewConfig(map[string]string{"account_id": "123456789012", "family": familyInspector2Finding}), nil, checkpoint)
		if err != nil {
			t.Fatalf("ReadWithCheckpoint(inspector2_finding) error = %v", err)
		}
		if len(pull.Events) != 1 || pull.Events[0].GetAttributes()["finding_arn"] != "arn:aws:inspector2:us-east-1:123456789012:finding/new-finding" {
			t.Fatalf("events = %#v, want only new Inspector2 finding", pull.Events)
		}
		if len(fake.inspector2ListInputs) != 1 {
			t.Fatalf("len(inspector2ListInputs) = %d, want 1", len(fake.inspector2ListInputs))
		}
		input := fake.inspector2ListInputs[0]
		if input.SortCriteria == nil || input.SortCriteria.Field != inspector2types.SortFieldLastObservedAt || input.SortCriteria.SortOrder != inspector2types.SortOrderDesc {
			t.Fatalf("Inspector2 sort = %#v, want LastObservedAt DESC", input.SortCriteria)
		}
		if input.FilterCriteria == nil || len(input.FilterCriteria.LastObservedAt) != 1 {
			t.Fatalf("Inspector2 LastObservedAt filter = %#v, want one start filter", input.FilterCriteria)
		}
		if got := input.FilterCriteria.LastObservedAt[0].StartInclusive; got == nil || !got.Equal(watermark.Add(-awsFindingCheckpointLookback)) {
			t.Fatalf("Inspector2 LastObservedAt start = %#v, want %s", got, watermark.Add(-awsFindingCheckpointLookback))
		}
	})
}

func TestReadAWSSecurityHubCheckpointCursorKeepsOriginalWatermark(t *testing.T) {
	watermark := time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)
	firstUpdatedAt := watermark.Add(2 * time.Hour)
	secondUpdatedAt := watermark.Add(time.Hour)
	fake := &fakeAWSSecurityServices{
		securityHubFindings: []securityhubtypes.AwsSecurityFinding{{
			Id:        awssdk.String("first-page"),
			UpdatedAt: awssdk.String(firstUpdatedAt.Format(time.RFC3339)),
		}},
		securityHubNextToken: "token-2",
	}
	source := newSecurityTestSource(t, fake)
	cfg := sourcecdk.NewConfig(map[string]string{"account_id": "123456789012", "family": familySecurityHubFinding})

	first, err := source.ReadWithCheckpoint(context.Background(), cfg, nil, awsSecurityTestCheckpoint(watermark))
	if err != nil {
		t.Fatalf("ReadWithCheckpoint(first) error = %v", err)
	}
	if len(first.Events) != 1 || first.NextCursor == nil || first.Checkpoint == nil {
		t.Fatalf("first pull = %#v, want event, checkpoint, and next cursor", first)
	}
	if got := first.Checkpoint.GetWatermark().AsTime(); !got.Equal(firstUpdatedAt) {
		t.Fatalf("first checkpoint watermark = %s, want %s", got, firstUpdatedAt)
	}

	fake.securityHubFindings = []securityhubtypes.AwsSecurityFinding{{
		Id:        awssdk.String("second-page"),
		UpdatedAt: awssdk.String(secondUpdatedAt.Format(time.RFC3339)),
	}}
	fake.securityHubNextToken = ""
	second, err := source.ReadWithCheckpoint(context.Background(), cfg, first.NextCursor, first.Checkpoint)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint(second) error = %v", err)
	}
	if len(second.Events) != 1 || second.Events[0].GetId() != "aws-securityhub-finding-second-page" {
		t.Fatalf("second events = %#v, want second-page despite advanced runtime checkpoint", second.Events)
	}
	if len(fake.securityHubInputs) != 2 {
		t.Fatalf("len(securityHubInputs) = %d, want 2", len(fake.securityHubInputs))
	}
	if got := awssdk.ToString(fake.securityHubInputs[1].NextToken); got != "token-2" {
		t.Fatalf("second NextToken = %q, want token-2", got)
	}
	assertAWSFindingFilterStart(t, awssdk.ToString(fake.securityHubInputs[1].Filters.UpdatedAt[0].Start), watermark)
}

func awsSecurityTestCheckpoint(watermark time.Time) *cerebrov1.SourceCheckpoint {
	return &cerebrov1.SourceCheckpoint{Watermark: timestamppb.New(watermark.UTC())}
}

func assertAWSFindingFilterStart(t *testing.T, raw string, watermark time.Time) {
	t.Helper()
	got, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		t.Fatalf("parse filter start %q: %v", raw, err)
	}
	want := watermark.Add(-awsFindingCheckpointLookback)
	if !got.Equal(want) {
		t.Fatalf("filter start = %s, want %s", got, want)
	}
}

func newSecurityTestSource(t *testing.T, fake *fakeAWSSecurityServices) *Source {
	t.Helper()
	spec, err := loadSpec()
	if err != nil {
		t.Fatalf("loadSpec() error = %v", err)
	}
	source := &Source{spec: spec, clients: func(context.Context, settings) (awsClients, error) {
		return awsClients{awsSecurityClients: awsSecurityClients{
			accessAnalyzer: fake,
			configService:  fake,
			guardDuty:      fakeGuardDutySecurity{fake: fake},
			inspector2:     fakeInspector2Security{fake: fake},
			macie2:         fakeMacie2Security{fake: fake},
			networkFW:      fake,
			securityHub:    fakeSecurityHubSecurity{fake: fake},
			wafv2:          fake,
			wafv2Global:    fake,
		}}, nil
	}}
	source.families, err = source.newFamilyEngine()
	if err != nil {
		t.Fatalf("newFamilyEngine() error = %v", err)
	}
	return source
}

type fakeAWSSecurityServices struct {
	analyzers                    []accessanalyzertypes.AnalyzerSummary
	configRecorders              []configtypes.ConfigurationRecorder
	configStatuses               []configtypes.ConfigurationRecorderStatus
	guardDutyDetectorIDs         []string
	guardDutyDetectors           map[string]guardduty.GetDetectorOutput
	guardDutyFindingIDs          map[string][]string
	guardDutyFindings            map[string]guarddutytypes.Finding
	guardDutyListInputs          []guardduty.ListFindingsInput
	securityHubFindings          []securityhubtypes.AwsSecurityFinding
	securityHubError             error
	securityHubExpiredTokenError error
	securityHubNextToken         string
	securityHubInputs            []securityhub.GetFindingsInput
	securityHubTokens            []string
	inspector2Findings           []inspector2types.Finding
	inspector2ListInputs         []inspector2.ListFindingsInput
	macieFindingIDs              []string
	macieFindings                []macie2types.Finding
	macieListInputs              []macie2.ListFindingsInput
	macieNextToken               string
	wafv2Summaries               []wafv2types.WebACLSummary
	wafv2Details                 map[string]wafv2types.WebACL
	lastWAFV2Scope               wafv2types.Scope
	firewalls                    []networkfirewalltypes.FirewallMetadata
	firewallDetails              map[string]networkfirewalltypes.Firewall
}

func (f *fakeAWSSecurityServices) ListAnalyzers(context.Context, *accessanalyzer.ListAnalyzersInput, ...func(*accessanalyzer.Options)) (*accessanalyzer.ListAnalyzersOutput, error) {
	return &accessanalyzer.ListAnalyzersOutput{Analyzers: f.analyzers}, nil
}

func (f *fakeAWSSecurityServices) DescribeConfigurationRecorders(context.Context, *configservice.DescribeConfigurationRecordersInput, ...func(*configservice.Options)) (*configservice.DescribeConfigurationRecordersOutput, error) {
	return &configservice.DescribeConfigurationRecordersOutput{ConfigurationRecorders: f.configRecorders}, nil
}

func (f *fakeAWSSecurityServices) DescribeConfigurationRecorderStatus(context.Context, *configservice.DescribeConfigurationRecorderStatusInput, ...func(*configservice.Options)) (*configservice.DescribeConfigurationRecorderStatusOutput, error) {
	return &configservice.DescribeConfigurationRecorderStatusOutput{ConfigurationRecordersStatus: f.configStatuses}, nil
}

type fakeGuardDutySecurity struct {
	fake *fakeAWSSecurityServices
}

func (f fakeGuardDutySecurity) ListDetectors(context.Context, *guardduty.ListDetectorsInput, ...func(*guardduty.Options)) (*guardduty.ListDetectorsOutput, error) {
	return &guardduty.ListDetectorsOutput{DetectorIds: f.fake.guardDutyDetectorIDs}, nil
}

func (f fakeGuardDutySecurity) GetDetector(_ context.Context, input *guardduty.GetDetectorInput, _ ...func(*guardduty.Options)) (*guardduty.GetDetectorOutput, error) {
	detector := f.fake.guardDutyDetectors[awssdk.ToString(input.DetectorId)]
	return &detector, nil
}

func (f fakeGuardDutySecurity) ListFindings(_ context.Context, input *guardduty.ListFindingsInput, _ ...func(*guardduty.Options)) (*guardduty.ListFindingsOutput, error) {
	f.fake.guardDutyListInputs = append(f.fake.guardDutyListInputs, *input)
	return &guardduty.ListFindingsOutput{FindingIds: f.fake.guardDutyFindingIDs[awssdk.ToString(input.DetectorId)]}, nil
}

func (f fakeGuardDutySecurity) GetFindings(_ context.Context, input *guardduty.GetFindingsInput, _ ...func(*guardduty.Options)) (*guardduty.GetFindingsOutput, error) {
	findings := make([]guarddutytypes.Finding, 0, len(input.FindingIds))
	for _, id := range input.FindingIds {
		if finding, ok := f.fake.guardDutyFindings[id]; ok {
			findings = append(findings, finding)
		}
	}
	return &guardduty.GetFindingsOutput{Findings: findings}, nil
}

type fakeSecurityHubSecurity struct {
	fake *fakeAWSSecurityServices
}

func (f fakeSecurityHubSecurity) GetFindings(_ context.Context, input *securityhub.GetFindingsInput, _ ...func(*securityhub.Options)) (*securityhub.GetFindingsOutput, error) {
	f.fake.securityHubInputs = append(f.fake.securityHubInputs, *input)
	token := awssdk.ToString(input.NextToken)
	f.fake.securityHubTokens = append(f.fake.securityHubTokens, token)
	if token != "" && f.fake.securityHubExpiredTokenError != nil {
		return nil, f.fake.securityHubExpiredTokenError
	}
	if f.fake.securityHubError != nil {
		return nil, f.fake.securityHubError
	}
	return &securityhub.GetFindingsOutput{Findings: f.fake.securityHubFindings, NextToken: stringPtr(f.fake.securityHubNextToken)}, nil
}

type fakeInspector2Security struct {
	fake *fakeAWSSecurityServices
}

func (f fakeInspector2Security) ListFindings(_ context.Context, input *inspector2.ListFindingsInput, _ ...func(*inspector2.Options)) (*inspector2.ListFindingsOutput, error) {
	f.fake.inspector2ListInputs = append(f.fake.inspector2ListInputs, *input)
	return &inspector2.ListFindingsOutput{Findings: f.fake.inspector2Findings}, nil
}

type fakeMacie2Security struct {
	fake *fakeAWSSecurityServices
}

func (f fakeMacie2Security) ListFindings(_ context.Context, input *macie2.ListFindingsInput, _ ...func(*macie2.Options)) (*macie2.ListFindingsOutput, error) {
	f.fake.macieListInputs = append(f.fake.macieListInputs, *input)
	return &macie2.ListFindingsOutput{FindingIds: f.fake.macieFindingIDs, NextToken: stringPtr(f.fake.macieNextToken)}, nil
}

func (f fakeMacie2Security) GetFindings(context.Context, *macie2.GetFindingsInput, ...func(*macie2.Options)) (*macie2.GetFindingsOutput, error) {
	return &macie2.GetFindingsOutput{Findings: f.fake.macieFindings}, nil
}

func (f *fakeAWSSecurityServices) ListWebACLs(_ context.Context, input *wafv2.ListWebACLsInput, _ ...func(*wafv2.Options)) (*wafv2.ListWebACLsOutput, error) {
	f.lastWAFV2Scope = input.Scope
	return &wafv2.ListWebACLsOutput{WebACLs: f.wafv2Summaries}, nil
}

func (f *fakeAWSSecurityServices) GetWebACL(_ context.Context, input *wafv2.GetWebACLInput, _ ...func(*wafv2.Options)) (*wafv2.GetWebACLOutput, error) {
	webACL := f.wafv2Details[awssdk.ToString(input.ARN)]
	return &wafv2.GetWebACLOutput{WebACL: &webACL}, nil
}

func (f *fakeAWSSecurityServices) ListFirewalls(context.Context, *networkfirewall.ListFirewallsInput, ...func(*networkfirewall.Options)) (*networkfirewall.ListFirewallsOutput, error) {
	return &networkfirewall.ListFirewallsOutput{Firewalls: f.firewalls}, nil
}

func (f *fakeAWSSecurityServices) DescribeFirewall(_ context.Context, input *networkfirewall.DescribeFirewallInput, _ ...func(*networkfirewall.Options)) (*networkfirewall.DescribeFirewallOutput, error) {
	firewall := f.firewallDetails[awssdk.ToString(input.FirewallArn)]
	return &networkfirewall.DescribeFirewallOutput{Firewall: &firewall}, nil
}
