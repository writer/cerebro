package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type connectorTestState struct {
	output                 string
	outputDir              string
	dryRun                 bool
	awsPrincipalARN        string
	awsExternalID          string
	awsRoleName            string
	awsTagKey              string
	awsTagValue            string
	awsRegion              string
	awsVolumeID            string
	awsSnapshotID          string
	awsInstanceID          string
	gcpProjectID           string
	gcpServiceAccountID    string
	gcpCustomRoleID        string
	gcpEnableWIF           bool
	gcpWIFPoolID           string
	gcpWIFProviderID       string
	gcpWIFIssuerURI        string
	gcpWIFAudience         string
	gcpPrincipalSubject    string
	azureSubscriptionID    string
	azureTenantID          string
	azureLocation          string
	azureDisplayName       string
	azureCustomRoleName    string
	syncAWSProfile         string
	syncAWSConfigFile      string
	syncAWSSharedCredsFile string
	syncAWSCredentialProc  string
	syncAWSWebIDTokenFile  string
	syncAWSWebIDRoleARN    string
	syncAWSRoleARN         string
	syncAWSRoleSession     string
	syncAWSRoleExternalID  string
	syncAWSRoleSourceID    string
	syncRegion             string
	syncGCPCredentialsFile string
	syncGCPImpersonateSA   string
	syncGCPImpersonateDel  string
	syncGCPImpersonateTTL  string
	syncAzureSubscription  string
	runAWS                 func(context.Context) (connectorValidationReport, error)
	runGCP                 func(context.Context) (connectorValidationReport, error)
	runAzure               func(context.Context) (connectorValidationReport, error)
}

func snapshotConnectorTestState() connectorTestState {
	return connectorTestState{
		output:                 connectorOutput,
		outputDir:              connectorScaffoldOutputDir,
		dryRun:                 connectorValidateDryRun,
		awsPrincipalARN:        connectorAWSPrincipalARN,
		awsExternalID:          connectorAWSExternalID,
		awsRoleName:            connectorAWSRoleName,
		awsTagKey:              connectorAWSTagKey,
		awsTagValue:            connectorAWSTagValue,
		awsRegion:              connectorAWSRegion,
		awsVolumeID:            connectorAWSVolumeID,
		awsSnapshotID:          connectorAWSSnapshotID,
		awsInstanceID:          connectorAWSInstanceID,
		gcpProjectID:           connectorGCPProjectID,
		gcpServiceAccountID:    connectorGCPServiceAccountID,
		gcpCustomRoleID:        connectorGCPCustomRoleID,
		gcpEnableWIF:           connectorGCPEnableWIF,
		gcpWIFPoolID:           connectorGCPWIFPoolID,
		gcpWIFProviderID:       connectorGCPWIFProviderID,
		gcpWIFIssuerURI:        connectorGCPWIFIssuerURI,
		gcpWIFAudience:         connectorGCPWIFAudience,
		gcpPrincipalSubject:    connectorGCPPrincipalSubject,
		azureSubscriptionID:    connectorAzureSubscriptionID,
		azureTenantID:          connectorAzureTenantID,
		azureLocation:          connectorAzureLocation,
		azureDisplayName:       connectorAzureDisplayName,
		azureCustomRoleName:    connectorAzureCustomRoleName,
		syncAWSProfile:         syncAWSProfile,
		syncAWSConfigFile:      syncAWSConfigFile,
		syncAWSSharedCredsFile: syncAWSSharedCredsFile,
		syncAWSCredentialProc:  syncAWSCredentialProc,
		syncAWSWebIDTokenFile:  syncAWSWebIDTokenFile,
		syncAWSWebIDRoleARN:    syncAWSWebIDRoleARN,
		syncAWSRoleARN:         syncAWSRoleARN,
		syncAWSRoleSession:     syncAWSRoleSession,
		syncAWSRoleExternalID:  syncAWSRoleExternalID,
		syncAWSRoleSourceID:    syncAWSRoleSourceID,
		syncRegion:             syncRegion,
		syncGCPCredentialsFile: syncGCPCredentialsFile,
		syncGCPImpersonateSA:   syncGCPImpersonateSA,
		syncGCPImpersonateDel:  syncGCPImpersonateDel,
		syncGCPImpersonateTTL:  syncGCPImpersonateTTL,
		syncAzureSubscription:  syncAzureSubscription,
		runAWS:                 runAWSConnectorValidateFn,
		runGCP:                 runGCPConnectorValidateFn,
		runAzure:               runAzureConnectorValidateFn,
	}
}

func restoreConnectorTestState(state connectorTestState) {
	connectorOutput = state.output
	connectorScaffoldOutputDir = state.outputDir
	connectorValidateDryRun = state.dryRun
	connectorAWSPrincipalARN = state.awsPrincipalARN
	connectorAWSExternalID = state.awsExternalID
	connectorAWSRoleName = state.awsRoleName
	connectorAWSTagKey = state.awsTagKey
	connectorAWSTagValue = state.awsTagValue
	connectorAWSRegion = state.awsRegion
	connectorAWSVolumeID = state.awsVolumeID
	connectorAWSSnapshotID = state.awsSnapshotID
	connectorAWSInstanceID = state.awsInstanceID
	connectorGCPProjectID = state.gcpProjectID
	connectorGCPServiceAccountID = state.gcpServiceAccountID
	connectorGCPCustomRoleID = state.gcpCustomRoleID
	connectorGCPEnableWIF = state.gcpEnableWIF
	connectorGCPWIFPoolID = state.gcpWIFPoolID
	connectorGCPWIFProviderID = state.gcpWIFProviderID
	connectorGCPWIFIssuerURI = state.gcpWIFIssuerURI
	connectorGCPWIFAudience = state.gcpWIFAudience
	connectorGCPPrincipalSubject = state.gcpPrincipalSubject
	connectorAzureSubscriptionID = state.azureSubscriptionID
	connectorAzureTenantID = state.azureTenantID
	connectorAzureLocation = state.azureLocation
	connectorAzureDisplayName = state.azureDisplayName
	connectorAzureCustomRoleName = state.azureCustomRoleName
	syncAWSProfile = state.syncAWSProfile
	syncAWSConfigFile = state.syncAWSConfigFile
	syncAWSSharedCredsFile = state.syncAWSSharedCredsFile
	syncAWSCredentialProc = state.syncAWSCredentialProc
	syncAWSWebIDTokenFile = state.syncAWSWebIDTokenFile
	syncAWSWebIDRoleARN = state.syncAWSWebIDRoleARN
	syncAWSRoleARN = state.syncAWSRoleARN
	syncAWSRoleSession = state.syncAWSRoleSession
	syncAWSRoleExternalID = state.syncAWSRoleExternalID
	syncAWSRoleSourceID = state.syncAWSRoleSourceID
	syncRegion = state.syncRegion
	syncGCPCredentialsFile = state.syncGCPCredentialsFile
	syncGCPImpersonateSA = state.syncGCPImpersonateSA
	syncGCPImpersonateDel = state.syncGCPImpersonateDel
	syncGCPImpersonateTTL = state.syncGCPImpersonateTTL
	syncAzureSubscription = state.syncAzureSubscription
	runAWSConnectorValidateFn = state.runAWS
	runGCPConnectorValidateFn = state.runGCP
	runAzureConnectorValidateFn = state.runAzure
}

func TestRunConnectorScaffoldWritesAWSBundle(t *testing.T) {
	state := snapshotConnectorTestState()
	defer restoreConnectorTestState(state)

	connectorOutput = FormatTable
	connectorScaffoldOutputDir = t.TempDir()
	connectorAWSRoleName = "CerebroScanRole"
	connectorAWSPrincipalARN = "arn:aws:iam::111122223333:role/Cerebro"
	connectorAWSExternalID = "ext-123"
	connectorAWSTagKey = "CerebroManagedBy"
	connectorAWSTagValue = "cerebro"

	if err := runConnectorScaffold(nil, []string{"aws"}); err != nil {
		t.Fatalf("runConnectorScaffold: %v", err)
	}
	for _, rel := range []string{"aws/stackset.yaml", "aws/parameters.example.json", "aws/README.md"} {
		if _, err := os.Stat(filepath.Join(connectorScaffoldOutputDir, filepath.FromSlash(rel))); err != nil {
			t.Fatalf("expected generated file %s: %v", rel, err)
		}
	}
}

func TestRunConnectorValidateDispatchesAWS(t *testing.T) {
	state := snapshotConnectorTestState()
	defer restoreConnectorTestState(state)

	called := false
	connectorOutput = FormatTable
	runAWSConnectorValidateFn = func(context.Context) (connectorValidationReport, error) {
		called = true
		return connectorValidationReport{
			Provider:    "aws",
			StartedAt:   time.Now().UTC(),
			CompletedAt: time.Now().UTC(),
			Duration:    "1ms",
			Success:     true,
			Checks:      []connectorValidationCheck{{ID: "auth", Status: "passed", Detail: "ok"}},
		}, nil
	}

	cmd := connectorValidateCmd
	cmd.SetContext(context.Background())
	if err := runConnectorValidate(cmd, []string{"aws"}); err != nil {
		t.Fatalf("runConnectorValidate: %v", err)
	}
	if !called {
		t.Fatal("expected AWS validation function to be called")
	}
}

func TestAzureActionMatchesWildcard(t *testing.T) {
	if !azureActionMatches("Microsoft.Compute/*/read", "Microsoft.Compute/virtualMachines/read") {
		t.Fatal("expected wildcard Azure action match")
	}
	if !azureActionMatches("*/read", "Microsoft.Compute/virtualMachines/read") {
		t.Fatal("expected global read Azure wildcard match")
	}
	if azureActionMatches("Microsoft.Compute/snapshots/delete", "Microsoft.Compute/snapshots/write") {
		t.Fatal("expected different Azure actions not to match")
	}
}

func TestAzurePermissionAllowedRespectsAdditiveGrants(t *testing.T) {
	grants := []struct {
		Actions    []string `json:"actions"`
		NotActions []string `json:"notActions"`
	}{
		{
			Actions:    []string{"Microsoft.Compute/*"},
			NotActions: []string{"Microsoft.Compute/snapshots/write"},
		},
		{
			Actions: []string{"Microsoft.Compute/snapshots/write"},
		},
	}
	if !azurePermissionAllowed("Microsoft.Compute/snapshots/write", grants) {
		t.Fatal("expected later additive Azure grant to restore snapshot write permission")
	}
}

func TestClassifyAWSDryRunResult(t *testing.T) {
	status, detail := classifyAWSDryRunResult(nil, "ec2:CreateSnapshot")
	if status != "passed" || !strings.Contains(detail, "succeeded") {
		t.Fatalf("unexpected nil dry-run result: %s %s", status, detail)
	}
	status, _ = classifyAWSDryRunResult(staticConnectorErr("DryRunOperation"), "ec2:CreateSnapshot")
	if status != "passed" {
		t.Fatalf("expected DryRunOperation to pass, got %s", status)
	}
	status, _ = classifyAWSDryRunResult(staticConnectorErr("UnauthorizedOperation"), "ec2:CreateSnapshot")
	if status != "failed" {
		t.Fatalf("expected UnauthorizedOperation to fail, got %s", status)
	}
}

func TestFoldConnectorStatusUnknownWinsOverKnown(t *testing.T) {
	if got := foldConnectorStatus("passed", "unexpected"); got != "unexpected" {
		t.Fatalf("expected unknown status to surface, got %q", got)
	}
	if got := foldConnectorStatus("unexpected", "failed"); got != "unexpected" {
		t.Fatalf("expected existing unknown status to remain highest severity, got %q", got)
	}
}

func TestAllConnectorChecksPassedRejectsUnknownStatus(t *testing.T) {
	checks := []connectorValidationCheck{{ID: "mystery", Status: "unexpected", Detail: "unknown"}}
	if allConnectorChecksPassed(checks) {
		t.Fatal("expected unknown connector check status to fail report success")
	}
}

func TestAWSDescribeInstancesInputOmitsMaxResultsWhenInstanceIDProvided(t *testing.T) {
	input := awsDescribeInstancesInput("i-0123456789abcdef0")
	if len(input.InstanceIds) != 1 || input.InstanceIds[0] != "i-0123456789abcdef0" {
		t.Fatalf("expected instance ID to be preserved, got %#v", input.InstanceIds)
	}
	if input.MaxResults != nil {
		t.Fatalf("expected MaxResults to be unset when InstanceIds are provided, got %v", *input.MaxResults)
	}
}

func TestAWSDescribeInstancesInputUsesMaxResultsWithoutInstanceID(t *testing.T) {
	input := awsDescribeInstancesInput("")
	if input.MaxResults == nil || *input.MaxResults != awsDescribeProbeMaxResults {
		t.Fatalf("expected MaxResults %d, got %#v", awsDescribeProbeMaxResults, input.MaxResults)
	}
	if len(input.InstanceIds) != 0 {
		t.Fatalf("expected no instance IDs when none provided, got %#v", input.InstanceIds)
	}
}

func TestConnectorValidateRegionUsesDedicatedDefault(t *testing.T) {
	state := snapshotConnectorTestState()
	defer restoreConnectorTestState(state)

	syncRegion = ""
	connectorAWSRegion = "us-east-1"

	flag := connectorValidateCmd.Flag("region")
	if flag == nil {
		t.Fatal("expected connector validate region flag to be registered")
	}
	if flag.DefValue != "us-east-1" {
		t.Fatalf("expected connector validate region default us-east-1, got %q", flag.DefValue)
	}
	if connectorAWSRegion != "us-east-1" {
		t.Fatalf("expected dedicated connector AWS region default to remain us-east-1, got %q", connectorAWSRegion)
	}
}

type staticErr string

func (e staticErr) Error() string { return string(e) }

func staticConnectorErr(msg string) error { return staticErr(msg) }
