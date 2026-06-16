package aws

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
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

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/awssecurity"
)

const (
	familyAccessAnalyzer         = "access_analyzer"
	familyConfigRecorder         = "config_recorder"
	familyGuardDutyDetector      = "guardduty_detector"
	familyGuardDutyFinding       = "guardduty_finding"
	familyInspector2Finding      = "inspector2_finding"
	familyMacie2Finding          = "macie2_finding"
	familyNetworkFirewall        = "network_firewall"
	familySecurityHubFinding     = "securityhub_finding"
	familyWAFV2WebACL            = "wafv2_web_acl"
	accessAnalyzerMissing        = accessanalyzertypes.AnalyzerStatus("MISSING")
	configRecorderMissingName    = "missing-"
	awsFindingCheckpointLookback = 2 * time.Minute
)

type awsSecurityClients struct {
	accessAnalyzer awsAccessAnalyzerAPI
	configService  awsConfigServiceAPI
	guardDuty      awsGuardDutyAPI
	inspector2     awsInspector2API
	macie2         awsMacie2API
	networkFW      awsNetworkFirewallAPI
	securityHub    awsSecurityHubAPI
	wafv2          awsWAFV2API
	wafv2Global    awsWAFV2API
}

type awsAccessAnalyzerAPI interface {
	ListAnalyzers(context.Context, *accessanalyzer.ListAnalyzersInput, ...func(*accessanalyzer.Options)) (*accessanalyzer.ListAnalyzersOutput, error)
}

type awsConfigServiceAPI interface {
	DescribeConfigurationRecorders(context.Context, *configservice.DescribeConfigurationRecordersInput, ...func(*configservice.Options)) (*configservice.DescribeConfigurationRecordersOutput, error)
	DescribeConfigurationRecorderStatus(context.Context, *configservice.DescribeConfigurationRecorderStatusInput, ...func(*configservice.Options)) (*configservice.DescribeConfigurationRecorderStatusOutput, error)
}

type awsGuardDutyAPI interface {
	ListDetectors(context.Context, *guardduty.ListDetectorsInput, ...func(*guardduty.Options)) (*guardduty.ListDetectorsOutput, error)
	GetDetector(context.Context, *guardduty.GetDetectorInput, ...func(*guardduty.Options)) (*guardduty.GetDetectorOutput, error)
	ListFindings(context.Context, *guardduty.ListFindingsInput, ...func(*guardduty.Options)) (*guardduty.ListFindingsOutput, error)
	GetFindings(context.Context, *guardduty.GetFindingsInput, ...func(*guardduty.Options)) (*guardduty.GetFindingsOutput, error)
}

type awsInspector2API interface {
	ListFindings(context.Context, *inspector2.ListFindingsInput, ...func(*inspector2.Options)) (*inspector2.ListFindingsOutput, error)
}

type awsMacie2API interface {
	ListFindings(context.Context, *macie2.ListFindingsInput, ...func(*macie2.Options)) (*macie2.ListFindingsOutput, error)
	GetFindings(context.Context, *macie2.GetFindingsInput, ...func(*macie2.Options)) (*macie2.GetFindingsOutput, error)
}

type awsNetworkFirewallAPI interface {
	ListFirewalls(context.Context, *networkfirewall.ListFirewallsInput, ...func(*networkfirewall.Options)) (*networkfirewall.ListFirewallsOutput, error)
	DescribeFirewall(context.Context, *networkfirewall.DescribeFirewallInput, ...func(*networkfirewall.Options)) (*networkfirewall.DescribeFirewallOutput, error)
}

type awsSecurityHubAPI interface {
	GetFindings(context.Context, *securityhub.GetFindingsInput, ...func(*securityhub.Options)) (*securityhub.GetFindingsOutput, error)
}

type awsWAFV2API interface {
	ListWebACLs(context.Context, *wafv2.ListWebACLsInput, ...func(*wafv2.Options)) (*wafv2.ListWebACLsOutput, error)
	GetWebACL(context.Context, *wafv2.GetWebACLInput, ...func(*wafv2.Options)) (*wafv2.GetWebACLOutput, error)
}

type awsConfigRecorder struct {
	Recorder configtypes.ConfigurationRecorder
	Status   configtypes.ConfigurationRecorderStatus
	Missing  bool
}

type guardDutyPageCursor struct {
	DetectorIndex int    `json:"detector_index,omitempty"`
	FindingToken  string `json:"finding_token,omitempty"`
}

type awsGuardDutyFinding struct {
	DetectorID string
	Finding    guarddutytypes.Finding
}

type awsGuardDutyDetector struct {
	DetectorID string
	Detail     *guardduty.GetDetectorOutput
	Missing    bool
}

type awsWAFV2WebACL struct {
	Scope   wafv2types.Scope
	Summary wafv2types.WebACLSummary
	WebACL  *wafv2types.WebACL
}

type awsNetworkFirewall struct {
	Metadata networkfirewalltypes.FirewallMetadata
	Firewall *networkfirewalltypes.Firewall
	Status   *networkfirewalltypes.FirewallStatus
}

func newAWSSecurityClients(cfg awssdk.Config) awsSecurityClients {
	globalCfg := cfg.Copy()
	globalCfg.Region = "us-east-1"
	return awsSecurityClients{
		accessAnalyzer: accessanalyzer.NewFromConfig(cfg),
		configService:  configservice.NewFromConfig(cfg),
		guardDuty:      guardduty.NewFromConfig(cfg),
		inspector2:     inspector2.NewFromConfig(cfg),
		macie2:         macie2.NewFromConfig(cfg),
		networkFW:      networkfirewall.NewFromConfig(cfg),
		securityHub:    securityhub.NewFromConfig(cfg),
		wafv2:          wafv2.NewFromConfig(cfg),
		wafv2Global:    wafv2.NewFromConfig(globalCfg),
	}
}

func awsSecurityFamilies(clientFactory awsClientFactory) []sourcecdk.Family[settings] {
	return []sourcecdk.Family[settings]{
		awsFamily(clientFactory, awsFamilyOptions[accessanalyzertypes.AnalyzerSummary]{
			Name:  familyAccessAnalyzer,
			Label: "aws access analyzer analyzers",
			List:  listAccessAnalyzers,
			Event: accessAnalyzerEvent,
			URN: func(settings settings, analyzer accessanalyzertypes.AnalyzerSummary) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_access_analyzer:%s", settings.accountID, firstNonEmpty(awssdk.ToString(analyzer.Arn), awssdk.ToString(analyzer.Name), settings.region)), nil
			},
			CursorFallback: func(analyzer accessanalyzertypes.AnalyzerSummary) string {
				return firstNonEmpty(awssdk.ToString(analyzer.Arn), awssdk.ToString(analyzer.Name))
			},
		}),
		awsFamily(clientFactory, awsFamilyOptions[awsConfigRecorder]{
			Name:  familyConfigRecorder,
			Label: "aws config recorders",
			List:  listConfigRecorders,
			Event: configRecorderEvent,
			URN: func(settings settings, recorder awsConfigRecorder) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_config_recorder:%s", settings.accountID, firstNonEmpty(awssdk.ToString(recorder.Recorder.Arn), awssdk.ToString(recorder.Recorder.Name), settings.region)), nil
			},
			CursorFallback: func(recorder awsConfigRecorder) string {
				return firstNonEmpty(awssdk.ToString(recorder.Recorder.Arn), awssdk.ToString(recorder.Recorder.Name))
			},
		}),
		awsFamily(clientFactory, awsFamilyOptions[awsGuardDutyDetector]{
			Name:  familyGuardDutyDetector,
			Label: "aws guardduty detectors",
			List:  listGuardDutyDetectors,
			Event: guardDutyDetectorEvent,
			URN: func(settings settings, detector awsGuardDutyDetector) (string, error) {
				detectorID := firstNonEmpty(detector.DetectorID, guardDutyMissingDetectorID(settings))
				return fmt.Sprintf("urn:cerebro:%s:aws_guardduty_detector:%s", settings.accountID, firstNonEmpty(guardDutyDetectorARN(settings, detectorID), detectorID)), nil
			},
			CursorFallback: func(detector awsGuardDutyDetector) string { return detector.DetectorID },
		}),
		awsFamily(clientFactory, awsFamilyOptions[awsGuardDutyFinding]{
			Name:               familyGuardDutyFinding,
			Label:              "aws guardduty findings",
			List:               listGuardDutyFindings,
			ListWithCheckpoint: listGuardDutyFindingsWithCheckpoint,
			Event:              guardDutyFindingEvent,
			URN: func(settings settings, finding awsGuardDutyFinding) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_guardduty_finding:%s", settings.accountID, firstNonEmpty(awssdk.ToString(finding.Finding.Arn), awssdk.ToString(finding.Finding.Id))), nil
			},
			CursorFallback: func(finding awsGuardDutyFinding) string {
				return firstNonEmpty(awssdk.ToString(finding.Finding.Arn), awssdk.ToString(finding.Finding.Id))
			},
		}),
		awsFamily(clientFactory, awsFamilyOptions[securityhubtypes.AwsSecurityFinding]{
			Name:               familySecurityHubFinding,
			Label:              "aws security hub findings",
			List:               listSecurityHubFindings,
			ListWithCheckpoint: listSecurityHubFindingsWithCheckpoint,
			Event:              securityHubFindingEvent,
			URN: func(settings settings, finding securityhubtypes.AwsSecurityFinding) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_securityhub_finding:%s", settings.accountID, awssdk.ToString(finding.Id)), nil
			},
			CursorFallback: func(finding securityhubtypes.AwsSecurityFinding) string { return awssdk.ToString(finding.Id) },
		}),
		awsFamily(clientFactory, awsFamilyOptions[inspector2types.Finding]{
			Name:  familyInspector2Finding,
			Label: "aws inspector2 findings",
			List:  listInspector2Findings,
			Event: inspector2FindingEvent,
			URN: func(settings settings, finding inspector2types.Finding) (string, error) {
				resourceID := ""
				if resource := firstInspector2Resource(finding.Resources); resource != nil {
					resourceID = awssdk.ToString(resource.Id)
				}
				return fmt.Sprintf("urn:cerebro:%s:aws_inspector2_finding:%s", settings.accountID, firstNonEmpty(awssdk.ToString(finding.FindingArn), resourceID)), nil
			},
			CursorFallback: func(finding inspector2types.Finding) string { return awssdk.ToString(finding.FindingArn) },
		}),
		awsFamily(clientFactory, awsFamilyOptions[macie2types.Finding]{
			Name:               familyMacie2Finding,
			Label:              "aws macie2 findings",
			List:               listMacie2Findings,
			ListWithCheckpoint: listMacie2FindingsWithCheckpoint,
			Event:              macie2FindingEvent,
			URN: func(settings settings, finding macie2types.Finding) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_macie2_finding:%s", settings.accountID, awssdk.ToString(finding.Id)), nil
			},
			CursorFallback: func(finding macie2types.Finding) string { return awssdk.ToString(finding.Id) },
		}),
		awsFamily(clientFactory, awsFamilyOptions[awsWAFV2WebACL]{
			Name:  familyWAFV2WebACL,
			Label: "aws wafv2 web acls",
			List:  listWAFV2WebACLs,
			Event: wafv2WebACLEvent,
			URN: func(settings settings, record awsWAFV2WebACL) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_wafv2_web_acl:%s", settings.accountID, firstNonEmpty(awssdk.ToString(record.Summary.ARN), awssdk.ToString(record.Summary.Id))), nil
			},
			CursorFallback: func(record awsWAFV2WebACL) string {
				return firstNonEmpty(awssdk.ToString(record.Summary.ARN), awssdk.ToString(record.Summary.Id))
			},
		}),
		awsFamily(clientFactory, awsFamilyOptions[awsNetworkFirewall]{
			Name:  familyNetworkFirewall,
			Label: "aws network firewalls",
			List:  listNetworkFirewalls,
			Event: networkFirewallEvent,
			URN: func(settings settings, record awsNetworkFirewall) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_network_firewall:%s", settings.accountID, firstNonEmpty(awssdk.ToString(record.Metadata.FirewallArn), awssdk.ToString(record.Metadata.FirewallName))), nil
			},
			CursorFallback: func(record awsNetworkFirewall) string {
				return firstNonEmpty(awssdk.ToString(record.Metadata.FirewallArn), awssdk.ToString(record.Metadata.FirewallName))
			},
		}),
	}
}

func listAccessAnalyzers(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]accessanalyzertypes.AnalyzerSummary, string, error) {
	output, err := clients.accessAnalyzer.ListAnalyzers(ctx, &accessanalyzer.ListAnalyzersInput{
		MaxResults: awssdk.Int32(boundedAWSPageSizeInt32(limit, 1, 100)),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := output.Analyzers
	if len(records) == 0 && awssdk.ToString(output.NextToken) == "" && strings.TrimSpace(cursor) == "" {
		records = []accessanalyzertypes.AnalyzerSummary{missingAccessAnalyzer(settings)}
	}
	return records, awssdk.ToString(output.NextToken), nil
}

func listConfigRecorders(ctx context.Context, clients awsClients, settings settings, cursor string, _ int) ([]awsConfigRecorder, string, error) {
	if strings.TrimSpace(cursor) != "" {
		return nil, "", nil
	}
	recorders, err := clients.configService.DescribeConfigurationRecorders(ctx, &configservice.DescribeConfigurationRecordersInput{})
	if err != nil {
		return nil, "", err
	}
	statuses, err := clients.configService.DescribeConfigurationRecorderStatus(ctx, &configservice.DescribeConfigurationRecorderStatusInput{})
	if err != nil {
		return nil, "", err
	}
	statusByKey := configRecorderStatusMap(statuses.ConfigurationRecordersStatus)
	records := make([]awsConfigRecorder, 0, len(recorders.ConfigurationRecorders))
	for _, recorder := range recorders.ConfigurationRecorders {
		records = append(records, awsConfigRecorder{
			Recorder: recorder,
			Status:   statusByKey[configRecorderKey(awssdk.ToString(recorder.Arn), awssdk.ToString(recorder.Name), awssdk.ToString(recorder.ServicePrincipal))],
		})
	}
	if len(records) == 0 {
		name := configRecorderMissingNameFor(settings)
		records = append(records, awsConfigRecorder{
			Recorder: configtypes.ConfigurationRecorder{Name: awssdk.String(name)},
			Status:   configtypes.ConfigurationRecorderStatus{Name: awssdk.String(name), Recording: false},
			Missing:  true,
		})
	}
	return records, "", nil
}

func listGuardDutyDetectors(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]awsGuardDutyDetector, string, error) {
	output, err := clients.guardDuty.ListDetectors(ctx, &guardduty.ListDetectorsInput{
		MaxResults: awssdk.Int32(boundedAWSPageSizeInt32(limit, 1, 50)),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	if len(output.DetectorIds) == 0 && awssdk.ToString(output.NextToken) == "" && strings.TrimSpace(cursor) == "" {
		detectorID := guardDutyMissingDetectorID(settings)
		return []awsGuardDutyDetector{{
			DetectorID: detectorID,
			Detail:     &guardduty.GetDetectorOutput{Status: guarddutytypes.DetectorStatusDisabled},
			Missing:    true,
		}}, "", nil
	}
	records := make([]awsGuardDutyDetector, 0, len(output.DetectorIds))
	for _, detectorID := range output.DetectorIds {
		detail, err := clients.guardDuty.GetDetector(ctx, &guardduty.GetDetectorInput{DetectorId: awssdk.String(detectorID)})
		if err != nil {
			return nil, "", fmt.Errorf("get guardduty detector %q: %w", detectorID, err)
		}
		records = append(records, awsGuardDutyDetector{DetectorID: detectorID, Detail: detail})
	}
	return records, awssdk.ToString(output.NextToken), nil
}

func listGuardDutyFindings(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]awsGuardDutyFinding, string, error) {
	return listGuardDutyFindingsWithCheckpoint(ctx, clients, settings, cursor, limit, nil)
}

func listGuardDutyFindingsWithCheckpoint(ctx context.Context, clients awsClients, _ settings, cursor string, limit int, checkpoint *cerebrov1.SourceCheckpoint) ([]awsGuardDutyFinding, string, error) {
	detectors, err := listAllGuardDutyDetectors(ctx, clients)
	if err != nil {
		return nil, "", err
	}
	if len(detectors) == 0 {
		return nil, "", nil
	}
	state, err := decodeGuardDutyCursor(cursor)
	if err != nil {
		return nil, "", err
	}
	if state.DetectorIndex < 0 || state.DetectorIndex >= len(detectors) {
		state.DetectorIndex = 0
		state.FindingToken = ""
	}
	remaining := limit
	if remaining <= 0 {
		remaining = defaultPageSize
	}
	records := make([]awsGuardDutyFinding, 0, remaining)
	for state.DetectorIndex < len(detectors) && len(records) < remaining {
		detectorID := detectors[state.DetectorIndex]
		input := awssecurity.GuardDutyListFindingsInput(detectorID, boundedAWSPageSizeInt32(remaining-len(records), 1, 50), state.FindingToken, checkpoint, awsFindingCheckpointLookback)
		output, err := clients.guardDuty.ListFindings(ctx, input)
		if err != nil {
			return nil, "", fmt.Errorf("list guardduty findings for detector %q: %w", detectorID, err)
		}
		findings, err := getGuardDutyFindings(ctx, clients, detectorID, output.FindingIds)
		if err != nil {
			return nil, "", err
		}
		for _, finding := range findings {
			records = append(records, awsGuardDutyFinding{DetectorID: detectorID, Finding: finding})
		}
		if awssdk.ToString(output.NextToken) != "" {
			state.FindingToken = awssdk.ToString(output.NextToken)
			return records, encodeGuardDutyCursor(state), nil
		}
		state.DetectorIndex++
		state.FindingToken = ""
	}
	if state.DetectorIndex < len(detectors) {
		return records, encodeGuardDutyCursor(state), nil
	}
	return records, "", nil
}

func listSecurityHubFindings(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]securityhubtypes.AwsSecurityFinding, string, error) {
	return listSecurityHubFindingsWithCheckpoint(ctx, clients, settings, cursor, limit, nil)
}

func listSecurityHubFindingsWithCheckpoint(ctx context.Context, clients awsClients, _ settings, cursor string, limit int, checkpoint *cerebrov1.SourceCheckpoint) ([]securityhubtypes.AwsSecurityFinding, string, error) {
	input := awssecurity.SecurityHubGetFindingsInput(boundedAWSPageSizeInt32(limit, 1, 100), cursor, checkpoint, awsFindingCheckpointLookback)
	output, err := clients.securityHub.GetFindings(ctx, input)
	if cursor != "" && optionalAWSError(err, "InvalidInputException") && strings.Contains(fmt.Sprint(err), "NextToken") {
		input.NextToken = nil
		output, err = clients.securityHub.GetFindings(ctx, input)
	}
	if err != nil && optionalAWSError(err, "AccessDeniedException", "InvalidAccessException", "ResourceNotFoundException") {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	return output.Findings, awssdk.ToString(output.NextToken), nil
}

func listInspector2Findings(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]inspector2types.Finding, string, error) {
	out, err := clients.inspector2.ListFindings(ctx, &inspector2.ListFindingsInput{
		MaxResults: awssdk.Int32(boundedAWSPageSizeInt32(limit, 1, 100)),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	return out.Findings, awssdk.ToString(out.NextToken), nil
}

func listMacie2Findings(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]macie2types.Finding, string, error) {
	return listMacie2FindingsWithCheckpoint(ctx, clients, settings, cursor, limit, nil)
}

func listMacie2FindingsWithCheckpoint(ctx context.Context, clients awsClients, _ settings, cursor string, limit int, checkpoint *cerebrov1.SourceCheckpoint) ([]macie2types.Finding, string, error) {
	input := awssecurity.MacieListFindingsInput(boundedAWSPageSizeInt32(limit, 1, 50), cursor, checkpoint, awsFindingCheckpointLookback)
	out, err := clients.macie2.ListFindings(ctx, input)
	if err != nil {
		return nil, "", err
	}
	if len(out.FindingIds) == 0 {
		return nil, awssdk.ToString(out.NextToken), nil
	}
	findings, err := clients.macie2.GetFindings(ctx, &macie2.GetFindingsInput{FindingIds: out.FindingIds})
	if err != nil {
		return nil, "", fmt.Errorf("get macie findings: %w", err)
	}
	return findings.Findings, awssdk.ToString(out.NextToken), nil
}

func listWAFV2WebACLs(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]awsWAFV2WebACL, string, error) {
	scope := wafv2Scope(settings)
	wafClient := wafv2ClientForScope(clients, scope)
	out, err := wafClient.ListWebACLs(ctx, &wafv2.ListWebACLsInput{
		Scope:      scope,
		Limit:      awssdk.Int32(boundedAWSPageSizeInt32(limit, 1, 100)),
		NextMarker: stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsWAFV2WebACL, 0, len(out.WebACLs))
	for _, summary := range out.WebACLs {
		record := awsWAFV2WebACL{Scope: scope, Summary: summary}
		detail, err := wafClient.GetWebACL(ctx, &wafv2.GetWebACLInput{
			ARN:   summary.ARN,
			Id:    summary.Id,
			Name:  summary.Name,
			Scope: scope,
		})
		if err != nil {
			return nil, "", fmt.Errorf("get wafv2 web acl %q: %w", awssdk.ToString(summary.ARN), err)
		}
		record.WebACL = detail.WebACL
		records = append(records, record)
	}
	return records, awssdk.ToString(out.NextMarker), nil
}

func listNetworkFirewalls(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsNetworkFirewall, string, error) {
	out, err := clients.networkFW.ListFirewalls(ctx, &networkfirewall.ListFirewallsInput{
		MaxResults: awssdk.Int32(boundedAWSPageSizeInt32(limit, 1, 100)),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsNetworkFirewall, 0, len(out.Firewalls))
	for _, summary := range out.Firewalls {
		detail, err := clients.networkFW.DescribeFirewall(ctx, &networkfirewall.DescribeFirewallInput{
			FirewallArn:  summary.FirewallArn,
			FirewallName: summary.FirewallName,
		})
		if err != nil {
			return nil, "", fmt.Errorf("describe network firewall %q: %w", awssdk.ToString(summary.FirewallArn), err)
		}
		records = append(records, awsNetworkFirewall{Metadata: summary, Firewall: detail.Firewall, Status: detail.FirewallStatus})
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func accessAnalyzerEvent(settings settings, analyzer accessanalyzertypes.AnalyzerSummary) (*primitives.Event, error) {
	arn := awssdk.ToString(analyzer.Arn)
	name := firstNonEmpty(awssdk.ToString(analyzer.Name), "access-analyzer-"+settings.region)
	resourceID := firstNonEmpty(arn, settings.region+"/"+name)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyAccessAnalyzer, resourceID, name, "access_analyzer", analyzer.Tags)
	attributes["analyzer_arn"] = arn
	attributes["analyzer_name"] = name
	attributes["analyzer_type"] = string(analyzer.Type)
	attributes["arn"] = arn
	attributes["managed_by"] = awssdk.ToString(analyzer.ManagedBy)
	attributes["policy_resource_type"] = "aws_accessanalyzer_analyzers"
	attributes["resource_arn"] = arn
	attributes["status"] = string(analyzer.Status)
	attributes["status_reason_code"] = accessAnalyzerStatusReason(analyzer)
	attributes["last_resource_analyzed"] = awssdk.ToString(analyzer.LastResourceAnalyzed)
	addTimeAttribute(attributes, "created_at", analyzer.CreatedAt)
	addTimeAttribute(attributes, "last_resource_analyzed_at", analyzer.LastResourceAnalyzedAt)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "analyzer": analyzer})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-access-analyzer-"+resourceID, "aws.access_analyzer", "aws/access_analyzer/v1", payload, attributes, firstTime(analyzer.LastResourceAnalyzedAt, analyzer.CreatedAt))
}

func configRecorderEvent(settings settings, record awsConfigRecorder) (*primitives.Event, error) {
	recorder := record.Recorder
	status := record.Status
	arn := awssdk.ToString(recorder.Arn)
	name := firstNonEmpty(awssdk.ToString(recorder.Name), configRecorderMissingNameFor(settings))
	resourceID := firstNonEmpty(arn, settings.region+"/"+name)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyConfigRecorder, resourceID, name, "config_recorder", nil)
	attributes["arn"] = arn
	attributes["aws_resource_type"] = "AWS::Config::ConfigurationRecorder"
	attributes["config_resource_type"] = "AWS::Config::ConfigurationRecorder"
	attributes["configuration_recorder_arn"] = arn
	attributes["configuration_recorder_name"] = name
	attributes["include_global_resource_types"] = boolString(configRecordingGroup(recorder).IncludeGlobalResourceTypes)
	attributes["all_supported"] = boolString(configRecordingGroup(recorder).AllSupported)
	attributes["last_error_code"] = awssdk.ToString(status.LastErrorCode)
	attributes["last_error_message"] = awssdk.ToString(status.LastErrorMessage)
	attributes["last_status"] = string(status.LastStatus)
	attributes["missing"] = boolString(record.Missing)
	attributes["policy_resource_type"] = "aws::config::configuration_recorder"
	attributes["recording"] = boolString(status.Recording)
	attributes["recording_frequency"] = configRecordingFrequency(recorder)
	attributes["recording_scope"] = string(recorder.RecordingScope)
	attributes["recording_strategy"] = configRecordingStrategy(recorder)
	attributes["resource_arn"] = arn
	attributes["resource_types"] = strings.Join(configResourceTypes(configRecordingGroup(recorder).ResourceTypes), ",")
	attributes["role_arn"] = awssdk.ToString(recorder.RoleARN)
	attributes["role_name"] = roleNameFromARN(awssdk.ToString(recorder.RoleARN))
	attributes["service_principal"] = firstNonEmpty(awssdk.ToString(recorder.ServicePrincipal), awssdk.ToString(status.ServicePrincipal))
	addTimeAttribute(attributes, "last_started_at", status.LastStartTime)
	addTimeAttribute(attributes, "last_status_changed_at", status.LastStatusChangeTime)
	addTimeAttribute(attributes, "last_stopped_at", status.LastStopTime)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "recorder": recorder, "status": status, "missing": record.Missing})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-config-recorder-"+resourceID, "aws.config_recorder", "aws/config_recorder/v1", payload, attributes, firstTime(status.LastStatusChangeTime, status.LastStartTime, status.LastStopTime, timePtrFromBool(record.Missing)))
}

func guardDutyDetectorEvent(settings settings, record awsGuardDutyDetector) (*primitives.Event, error) {
	detail := record.Detail
	if detail == nil {
		detail = &guardduty.GetDetectorOutput{}
	}
	detectorID := firstNonEmpty(record.DetectorID, guardDutyMissingDetectorID(settings))
	arn := guardDutyDetectorARN(settings, detectorID)
	resourceID := firstNonEmpty(arn, detectorID)
	name := firstNonEmpty(detectorID, "guardduty-"+settings.region)
	status := string(detail.Status)
	enabled := detail.Status == guarddutytypes.DetectorStatusEnabled
	attributes := commonCloudAssetAttributes(settings, settings.region, familyGuardDutyDetector, resourceID, name, "guardduty_detector", detail.Tags)
	attributes["account_id"] = settings.accountID
	attributes["arn"] = arn
	attributes["detector_id"] = detectorID
	attributes["enabled"] = boolString(enabled)
	attributes["features"] = strings.Join(guardDutyFeatureStates(detail.Features), ",")
	attributes["finding_publishing_frequency"] = string(detail.FindingPublishingFrequency)
	attributes["missing"] = boolString(record.Missing)
	attributes["policy_resource_type"] = "aws::guardduty::detector"
	attributes["resource_arn"] = arn
	attributes["service_role"] = awssdk.ToString(detail.ServiceRole)
	attributes["status"] = status
	addAWSStringTimeAttribute(attributes, "created_at", awssdk.ToString(detail.CreatedAt))
	addAWSStringTimeAttribute(attributes, "updated_at", awssdk.ToString(detail.UpdatedAt))
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "detector_id": detectorID, "detector": detail, "missing": record.Missing})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-guardduty-detector-"+resourceID, "aws.guardduty_detector", "aws/guardduty_detector/v1", payload, attributes, firstParsedAWSTime(awssdk.ToString(detail.UpdatedAt), awssdk.ToString(detail.CreatedAt)))
}

func guardDutyFindingEvent(settings settings, record awsGuardDutyFinding) (*primitives.Event, error) {
	finding := record.Finding
	findingID := awssdk.ToString(finding.Id)
	findingARN := awssdk.ToString(finding.Arn)
	region := firstNonEmpty(awssdk.ToString(finding.Region), settings.region)
	attributes := commonCloudAssetAttributes(settings, region, familyGuardDutyFinding, firstNonEmpty(findingARN, findingID), firstNonEmpty(awssdk.ToString(finding.Title), awssdk.ToString(finding.Type), findingID), "guardduty_finding", nil)
	attributes["account_id"] = firstNonEmpty(awssdk.ToString(finding.AccountId), settings.accountID)
	attributes["arn"] = findingARN
	attributes["detector_id"] = record.DetectorID
	attributes["finding_arn"] = findingARN
	attributes["finding_id"] = findingID
	attributes["finding_type"] = awssdk.ToString(finding.Type)
	attributes["schema_version"] = awssdk.ToString(finding.SchemaVersion)
	attributes["severity"] = floatAttrString(finding.Severity)
	attributes["severity_label"] = guardDutySeverityLabel(finding.Severity)
	attributes["confidence"] = floatAttrString(finding.Confidence)
	attributes["title"] = awssdk.ToString(finding.Title)
	attributes["description"] = awssdk.ToString(finding.Description)
	if finding.Resource != nil {
		attributes["affected_resource_id"] = guardDutyResourceID(finding.Resource)
		attributes["affected_resource_type"] = awssdk.ToString(finding.Resource.ResourceType)
		attributes["principal_id"] = guardDutyPrincipalID(finding.Resource)
		attributes["principal_name"] = guardDutyPrincipalName(finding.Resource)
	}
	if finding.Service != nil {
		attributes["archived"] = boolPtrString(finding.Service.Archived)
		attributes["count"] = int32AttrString(finding.Service.Count)
		attributes["event_first_seen_at"] = awssdk.ToString(finding.Service.EventFirstSeen)
		attributes["event_last_seen_at"] = awssdk.ToString(finding.Service.EventLastSeen)
		attributes["feature_name"] = awssdk.ToString(finding.Service.FeatureName)
		attributes["resource_role"] = awssdk.ToString(finding.Service.ResourceRole)
		attributes["service_name"] = awssdk.ToString(finding.Service.ServiceName)
	}
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": region, "detector_id": record.DetectorID, "finding": finding})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-guardduty-finding-"+firstNonEmpty(findingARN, findingID), "aws.guardduty_finding", "aws/guardduty_finding/v1", payload, attributes, firstParsedAWSTime(awssdk.ToString(finding.UpdatedAt), awssdk.ToString(finding.CreatedAt)))
}

func securityHubFindingEvent(settings settings, finding securityhubtypes.AwsSecurityFinding) (*primitives.Event, error) {
	findingID := awssdk.ToString(finding.Id)
	region := firstNonEmpty(awssdk.ToString(finding.Region), settings.region)
	resource := firstSecurityHubResource(finding.Resources)
	attributes := commonCloudAssetAttributes(settings, region, familySecurityHubFinding, findingID, awssdk.ToString(finding.Title), "securityhub_finding", resource.Tags)
	attributes["account_id"] = firstNonEmpty(awssdk.ToString(finding.AwsAccountId), settings.accountID)
	attributes["aws_account_name"] = awssdk.ToString(finding.AwsAccountName)
	attributes["company_name"] = awssdk.ToString(finding.CompanyName)
	attributes["description"] = awssdk.ToString(finding.Description)
	attributes["finding_id"] = findingID
	attributes["generator_id"] = awssdk.ToString(finding.GeneratorId)
	attributes["product_arn"] = awssdk.ToString(finding.ProductArn)
	attributes["product_name"] = awssdk.ToString(finding.ProductName)
	attributes["schema_version"] = awssdk.ToString(finding.SchemaVersion)
	if finding.Severity != nil {
		attributes["severity_label"] = string(finding.Severity.Label)
		attributes["severity_normalized"] = int32AttrString(finding.Severity.Normalized)
		attributes["severity_original"] = awssdk.ToString(finding.Severity.Original)
	}
	attributes["source_url"] = awssdk.ToString(finding.SourceUrl)
	attributes["title"] = awssdk.ToString(finding.Title)
	attributes["types"] = strings.Join(cleanStrings(finding.Types), ",")
	attributes["record_state"] = string(finding.RecordState)
	attributes["verification_state"] = string(finding.VerificationState)
	attributes["sample"] = boolString(awssdk.ToBool(finding.Sample))
	if finding.Workflow != nil {
		attributes["workflow_status"] = string(finding.Workflow.Status)
		attributes["workflow_state"] = string(finding.Workflow.Status)
	}
	if finding.Compliance != nil {
		attributes["compliance_status"] = string(finding.Compliance.Status)
		attributes["security_control_id"] = awssdk.ToString(finding.Compliance.SecurityControlId)
		attributes["related_requirements"] = strings.Join(cleanStrings(finding.Compliance.RelatedRequirements), ",")
	}
	if resource.Id != nil || resource.Type != nil {
		attributes["affected_resource_id"] = awssdk.ToString(resource.Id)
		attributes["affected_resource_type"] = awssdk.ToString(resource.Type)
		attributes["affected_resource_region"] = awssdk.ToString(resource.Region)
		attributes["affected_resource_role"] = awssdk.ToString(resource.ResourceRole)
	}
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": region, "finding": finding})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-securityhub-finding-"+findingID, "aws.securityhub_finding", "aws/securityhub_finding/v1", payload, attributes, firstParsedAWSTime(awssdk.ToString(finding.UpdatedAt), awssdk.ToString(finding.CreatedAt)))
}

func inspector2FindingEvent(settings settings, finding inspector2types.Finding) (*primitives.Event, error) {
	resource := firstInspector2Resource(finding.Resources)
	tags := map[string]string{}
	region := settings.region
	affectedResourceID := ""
	affectedResourceType := ""
	if resource != nil {
		tags = resource.Tags
		region = firstNonEmpty(awssdk.ToString(resource.Region), region)
		affectedResourceID = awssdk.ToString(resource.Id)
		affectedResourceType = string(resource.Type)
	}
	findingARN := awssdk.ToString(finding.FindingArn)
	title := awssdk.ToString(finding.Title)
	attributes := commonCloudAssetAttributes(settings, region, familyInspector2Finding, firstNonEmpty(findingARN, affectedResourceID), title, "inspector2_finding", tags)
	attributes["account_id"] = firstNonEmpty(awssdk.ToString(finding.AwsAccountId), settings.accountID)
	attributes["affected_resource_id"] = affectedResourceID
	attributes["affected_resource_type"] = affectedResourceType
	attributes["description"] = awssdk.ToString(finding.Description)
	attributes["exploit_available"] = string(finding.ExploitAvailable)
	attributes["finding_arn"] = findingARN
	attributes["finding_type"] = string(finding.Type)
	attributes["fix_available"] = string(finding.FixAvailable)
	attributes["severity"] = string(finding.Severity)
	attributes["status"] = string(finding.Status)
	attributes["title"] = title
	if finding.InspectorScore != nil {
		attributes["inspector_score"] = strconv.FormatFloat(*finding.InspectorScore, 'f', -1, 64)
	}
	addTimeAttribute(attributes, "first_observed_at", finding.FirstObservedAt)
	addTimeAttribute(attributes, "last_observed_at", finding.LastObservedAt)
	addTimeAttribute(attributes, "updated_at", finding.UpdatedAt)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": region, "finding": finding})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-inspector2-finding-"+firstNonEmpty(findingARN, affectedResourceID), "aws.inspector2_finding", "aws/inspector2_finding/v1", payload, attributes, firstTime(finding.UpdatedAt, finding.LastObservedAt, finding.FirstObservedAt))
}

func macie2FindingEvent(settings settings, finding macie2types.Finding) (*primitives.Event, error) {
	bucketARN, bucketName, objectKey, objectPath, publicAccess := macie2AffectedS3(finding)
	region := firstNonEmpty(awssdk.ToString(finding.Region), settings.region)
	findingID := awssdk.ToString(finding.Id)
	attributes := commonCloudAssetAttributes(settings, region, familyMacie2Finding, findingID, awssdk.ToString(finding.Title), "macie2_finding", nil)
	attributes["account_id"] = firstNonEmpty(awssdk.ToString(finding.AccountId), settings.accountID)
	attributes["archived"] = boolPtrString(finding.Archived)
	attributes["bucket_arn"] = bucketARN
	attributes["bucket_name"] = bucketName
	attributes["category"] = string(finding.Category)
	attributes["count"] = int64PtrString(finding.Count)
	attributes["description"] = awssdk.ToString(finding.Description)
	attributes["finding_id"] = findingID
	attributes["finding_type"] = string(finding.Type)
	attributes["object_key"] = objectKey
	attributes["object_path"] = objectPath
	attributes["public"] = boolString(publicAccess)
	attributes["internet_exposed"] = boolString(publicAccess)
	attributes["sample"] = boolPtrString(finding.Sample)
	attributes["schema_version"] = awssdk.ToString(finding.SchemaVersion)
	attributes["severity"] = macie2SeverityDescription(finding.Severity)
	attributes["severity_score"] = macie2SeverityScore(finding.Severity)
	attributes["title"] = awssdk.ToString(finding.Title)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": region, "finding": finding})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-macie2-finding-"+findingID, "aws.macie2_finding", "aws/macie2_finding/v1", payload, attributes, firstTime(finding.UpdatedAt, finding.CreatedAt))
}

func wafv2WebACLEvent(settings settings, record awsWAFV2WebACL) (*primitives.Event, error) {
	webACL := record.WebACL
	arn := awssdk.ToString(record.Summary.ARN)
	name := awssdk.ToString(record.Summary.Name)
	id := awssdk.ToString(record.Summary.Id)
	if webACL != nil {
		arn = firstNonEmpty(awssdk.ToString(webACL.ARN), arn)
		name = firstNonEmpty(awssdk.ToString(webACL.Name), name)
		id = firstNonEmpty(awssdk.ToString(webACL.Id), id)
	}
	region := wafv2WebACLRegion(settings, record.Scope)
	attributes := commonCloudAssetAttributes(settings, region, familyWAFV2WebACL, firstNonEmpty(arn, id), name, "wafv2_web_acl", nil)
	attributes["arn"] = arn
	attributes["default_action"] = wafv2DefaultAction(webACL)
	attributes["description"] = awssdk.ToString(record.Summary.Description)
	attributes["scope"] = string(record.Scope)
	attributes["web_acl_arn"] = arn
	attributes["web_acl_id"] = id
	attributes["web_acl_name"] = name
	if webACL != nil {
		attributes["capacity"] = strconv.FormatInt(webACL.Capacity, 10)
		attributes["managed_by_firewall_manager"] = boolString(webACL.ManagedByFirewallManager)
		attributes["rule_count"] = strconv.Itoa(len(webACL.Rules))
		if webACL.VisibilityConfig != nil {
			attributes["cloudwatch_metrics_enabled"] = boolString(webACL.VisibilityConfig.CloudWatchMetricsEnabled)
			attributes["metric_name"] = awssdk.ToString(webACL.VisibilityConfig.MetricName)
			attributes["sampled_requests_enabled"] = boolString(webACL.VisibilityConfig.SampledRequestsEnabled)
		}
	}
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": region, "scope": record.Scope, "summary": record.Summary, "web_acl": webACL})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-wafv2-web-acl-"+firstNonEmpty(arn, id), "aws.wafv2_web_acl", "aws/wafv2_web_acl/v1", payload, attributes, time.Now().UTC())
}

func networkFirewallEvent(settings settings, record awsNetworkFirewall) (*primitives.Event, error) {
	firewall := record.Firewall
	arn := awssdk.ToString(record.Metadata.FirewallArn)
	name := awssdk.ToString(record.Metadata.FirewallName)
	tags := map[string]string{}
	if firewall != nil {
		arn = firstNonEmpty(awssdk.ToString(firewall.FirewallArn), arn)
		name = firstNonEmpty(awssdk.ToString(firewall.FirewallName), name)
		tags = networkFirewallTagMap(firewall.Tags)
	}
	attributes := commonCloudAssetAttributes(settings, settings.region, familyNetworkFirewall, firstNonEmpty(arn, name), name, "network_firewall", tags)
	attributes["arn"] = arn
	attributes["firewall_arn"] = arn
	attributes["firewall_name"] = name
	if firewall != nil {
		attributes["firewall_id"] = awssdk.ToString(firewall.FirewallId)
		attributes["firewall_policy_arn"] = awssdk.ToString(firewall.FirewallPolicyArn)
		attributes["subnet_ids"] = strings.Join(networkFirewallSubnetIDs(firewall.SubnetMappings), ",")
		attributes["transit_gateway_id"] = awssdk.ToString(firewall.TransitGatewayId)
		attributes["vpc_id"] = awssdk.ToString(firewall.VpcId)
	}
	if record.Status != nil {
		attributes["configuration_sync_state"] = string(record.Status.ConfigurationSyncStateSummary)
		attributes["status"] = string(record.Status.Status)
	}
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "metadata": record.Metadata, "firewall": firewall, "status": record.Status})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-network-firewall-"+firstNonEmpty(arn, name), "aws.network_firewall", "aws/network_firewall/v1", payload, attributes, time.Now().UTC())
}

func missingAccessAnalyzer(settings settings) accessanalyzertypes.AnalyzerSummary {
	return accessanalyzertypes.AnalyzerSummary{
		Name:   awssdk.String("missing-" + settings.region),
		Status: accessAnalyzerMissing,
		Type:   accessanalyzertypes.TypeAccount,
	}
}

func accessAnalyzerStatusReason(analyzer accessanalyzertypes.AnalyzerSummary) string {
	if analyzer.StatusReason == nil {
		return ""
	}
	return string(analyzer.StatusReason.Code)
}

func configRecorderStatusMap(statuses []configtypes.ConfigurationRecorderStatus) map[string]configtypes.ConfigurationRecorderStatus {
	out := make(map[string]configtypes.ConfigurationRecorderStatus, len(statuses)*3)
	for _, status := range statuses {
		for _, key := range []string{
			configRecorderKey(awssdk.ToString(status.Arn), "", ""),
			configRecorderKey("", awssdk.ToString(status.Name), ""),
			configRecorderKey("", "", awssdk.ToString(status.ServicePrincipal)),
		} {
			if key != "" {
				out[key] = status
			}
		}
	}
	return out
}

func configRecorderKey(arn string, name string, servicePrincipal string) string {
	if arn = strings.TrimSpace(arn); arn != "" {
		return "arn:" + arn
	}
	if name = strings.TrimSpace(name); name != "" {
		return "name:" + name
	}
	if servicePrincipal = strings.TrimSpace(servicePrincipal); servicePrincipal != "" {
		return "service:" + servicePrincipal
	}
	return ""
}

func configRecordingGroup(recorder configtypes.ConfigurationRecorder) configtypes.RecordingGroup {
	if recorder.RecordingGroup == nil {
		return configtypes.RecordingGroup{}
	}
	return *recorder.RecordingGroup
}

func configRecordingFrequency(recorder configtypes.ConfigurationRecorder) string {
	if recorder.RecordingMode == nil {
		return ""
	}
	return string(recorder.RecordingMode.RecordingFrequency)
}

func configRecordingStrategy(recorder configtypes.ConfigurationRecorder) string {
	group := configRecordingGroup(recorder)
	if group.RecordingStrategy == nil {
		return ""
	}
	return string(group.RecordingStrategy.UseOnly)
}

func configResourceTypes(values []configtypes.ResourceType) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, string(value))
	}
	return cleanStrings(out)
}

func configRecorderMissingNameFor(settings settings) string {
	return configRecorderMissingName + firstNonEmpty(settings.region, defaultRegion)
}

func timePtrFromBool(value bool) *time.Time {
	if !value {
		return nil
	}
	now := time.Now().UTC()
	return &now
}

func listAllGuardDutyDetectors(ctx context.Context, clients awsClients) ([]string, error) {
	var detectors []string
	var next *string
	for {
		output, err := clients.guardDuty.ListDetectors(ctx, &guardduty.ListDetectorsInput{MaxResults: awssdk.Int32(50), NextToken: next})
		if err != nil {
			return nil, err
		}
		detectors = append(detectors, output.DetectorIds...)
		if awssdk.ToString(output.NextToken) == "" {
			break
		}
		next = output.NextToken
	}
	sort.Strings(detectors)
	return detectors, nil
}

func guardDutyMissingDetectorID(settings settings) string {
	return "missing-" + firstNonEmpty(settings.region, defaultRegion)
}

func guardDutyDetectorARN(settings settings, detectorID string) string {
	if strings.TrimSpace(detectorID) == "" {
		return ""
	}
	return fmt.Sprintf("arn:aws:guardduty:%s:%s:detector/%s", settings.region, settings.accountID, strings.TrimSpace(detectorID))
}

func guardDutyFeatureStates(features []guarddutytypes.DetectorFeatureConfigurationResult) []string {
	values := make([]string, 0, len(features))
	for _, feature := range features {
		name := string(feature.Name)
		if name == "" {
			continue
		}
		values = append(values, name+"="+string(feature.Status))
	}
	sort.Strings(values)
	return values
}

func getGuardDutyFindings(ctx context.Context, clients awsClients, detectorID string, ids []string) ([]guarddutytypes.Finding, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	output, err := clients.guardDuty.GetFindings(ctx, &guardduty.GetFindingsInput{DetectorId: awssdk.String(detectorID), FindingIds: ids})
	if err != nil {
		return nil, fmt.Errorf("get guardduty findings for detector %q: %w", detectorID, err)
	}
	return output.Findings, nil
}

func decodeGuardDutyCursor(raw string) (guardDutyPageCursor, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return guardDutyPageCursor{}, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return guardDutyPageCursor{}, fmt.Errorf("decode guardduty cursor: %w", err)
	}
	var cursor guardDutyPageCursor
	if err := json.Unmarshal(decoded, &cursor); err != nil {
		return guardDutyPageCursor{}, fmt.Errorf("parse guardduty cursor: %w", err)
	}
	return cursor, nil
}

func encodeGuardDutyCursor(cursor guardDutyPageCursor) string {
	payload, err := json.Marshal(cursor)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(payload)
}

func guardDutyResourceID(resource *guarddutytypes.Resource) string {
	if resource == nil {
		return ""
	}
	if resource.InstanceDetails != nil {
		return awssdk.ToString(resource.InstanceDetails.InstanceId)
	}
	if resource.AccessKeyDetails != nil {
		return awssdk.ToString(resource.AccessKeyDetails.AccessKeyId)
	}
	return ""
}

func guardDutyPrincipalID(resource *guarddutytypes.Resource) string {
	if resource == nil || resource.AccessKeyDetails == nil {
		return ""
	}
	return awssdk.ToString(resource.AccessKeyDetails.PrincipalId)
}

func guardDutyPrincipalName(resource *guarddutytypes.Resource) string {
	if resource == nil || resource.AccessKeyDetails == nil {
		return ""
	}
	return awssdk.ToString(resource.AccessKeyDetails.UserName)
}

func firstSecurityHubResource(resources []securityhubtypes.Resource) securityhubtypes.Resource {
	if len(resources) == 0 {
		return securityhubtypes.Resource{}
	}
	return resources[0]
}

func guardDutySeverityLabel(value *float64) string {
	if value == nil {
		return ""
	}
	switch {
	case *value >= 9:
		return "critical"
	case *value >= 7:
		return "high"
	case *value >= 4:
		return "medium"
	case *value > 0:
		return "low"
	default:
		return "informational"
	}
}

func floatAttrString(value *float64) string {
	if value == nil {
		return ""
	}
	return strconv.FormatFloat(*value, 'f', -1, 64)
}

func int64PtrString(value *int64) string {
	if value == nil {
		return ""
	}
	return strconv.FormatInt(*value, 10)
}

func firstParsedAWSTime(values ...string) time.Time {
	for _, value := range values {
		if parsed := parseAWSStringTime(value); !parsed.IsZero() {
			return parsed
		}
	}
	return time.Now().UTC()
}

func wafv2Scope(settings settings) wafv2types.Scope {
	switch strings.ToUpper(strings.TrimSpace(settings.wafv2Scope)) {
	case string(wafv2types.ScopeCloudfront):
		return wafv2types.ScopeCloudfront
	default:
		return wafv2types.ScopeRegional
	}
}

func wafv2ClientForScope(clients awsClients, scope wafv2types.Scope) awsWAFV2API {
	if scope == wafv2types.ScopeCloudfront {
		return clients.wafv2Global
	}
	return clients.wafv2
}

func wafv2WebACLRegion(settings settings, scope wafv2types.Scope) string {
	if scope == wafv2types.ScopeCloudfront {
		return "us-east-1"
	}
	return settings.region
}

func firstInspector2Resource(resources []inspector2types.Resource) *inspector2types.Resource {
	for index := range resources {
		return &resources[index]
	}
	return nil
}

func macie2AffectedS3(finding macie2types.Finding) (string, string, string, string, bool) {
	if finding.ResourcesAffected == nil {
		return "", "", "", "", false
	}
	var bucketARN, bucketName, objectKey, objectPath string
	publicAccess := false
	if bucket := finding.ResourcesAffected.S3Bucket; bucket != nil {
		bucketARN = awssdk.ToString(bucket.Arn)
		bucketName = awssdk.ToString(bucket.Name)
		if bucket.PublicAccess != nil && bucket.PublicAccess.EffectivePermission == macie2types.EffectivePermissionPublic {
			publicAccess = true
		}
	}
	if object := finding.ResourcesAffected.S3Object; object != nil {
		bucketARN = firstNonEmpty(awssdk.ToString(object.BucketArn), bucketARN)
		objectKey = awssdk.ToString(object.Key)
		objectPath = awssdk.ToString(object.Path)
		publicAccess = publicAccess || awssdk.ToBool(object.PublicAccess)
	}
	return bucketARN, bucketName, objectKey, objectPath, publicAccess
}

func macie2SeverityDescription(severity *macie2types.Severity) string {
	if severity == nil {
		return ""
	}
	return string(severity.Description)
}

func macie2SeverityScore(severity *macie2types.Severity) string {
	if severity == nil || severity.Score == nil {
		return ""
	}
	return strconv.FormatInt(*severity.Score, 10)
}

func wafv2DefaultAction(webACL *wafv2types.WebACL) string {
	if webACL == nil || webACL.DefaultAction == nil {
		return ""
	}
	if webACL.DefaultAction.Allow != nil {
		return "allow"
	}
	if webACL.DefaultAction.Block != nil {
		return "block"
	}
	return ""
}

func networkFirewallSubnetIDs(mappings []networkfirewalltypes.SubnetMapping) []string {
	ids := make([]string, 0, len(mappings))
	for _, mapping := range mappings {
		ids = append(ids, awssdk.ToString(mapping.SubnetId))
	}
	return cleanStrings(ids)
}

func networkFirewallTagMap(tags []networkfirewalltypes.Tag) map[string]string {
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		if key := strings.TrimSpace(awssdk.ToString(tag.Key)); key != "" {
			out[key] = strings.TrimSpace(awssdk.ToString(tag.Value))
		}
	}
	return out
}
