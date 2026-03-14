package cli

import (
	"testing"

	"github.com/evalops/cerebro/internal/app"
)

type workloadScanAWSFlagState struct {
	targetAccountID         string
	scannerAccountID        string
	sourceProfile           string
	sourceRoleARN           string
	sourceRoleSession       string
	sourceRoleExternalID    string
	scannerProfile          string
	scannerRoleARN          string
	scannerRoleSession      string
	scannerRoleExternalID   string
	shareKMSKeyID           string
	scannerSnapshotKMSKeyID string
	trivyBinary             string
	gitleaksBinary          string
}

func snapshotWorkloadScanAWSFlagState() workloadScanAWSFlagState {
	return workloadScanAWSFlagState{
		targetAccountID:         workloadScanAWSAccountID,
		scannerAccountID:        workloadScanAWSScannerAccountID,
		sourceProfile:           workloadScanAWSSourceProfile,
		sourceRoleARN:           workloadScanAWSSourceRoleARN,
		sourceRoleSession:       workloadScanAWSSourceRoleSession,
		sourceRoleExternalID:    workloadScanAWSSourceRoleExternalID,
		scannerProfile:          workloadScanAWSScannerProfile,
		scannerRoleARN:          workloadScanAWSScannerRoleARN,
		scannerRoleSession:      workloadScanAWSScannerRoleSession,
		scannerRoleExternalID:   workloadScanAWSScannerRoleExternalID,
		shareKMSKeyID:           workloadScanAWSShareKMSKeyID,
		scannerSnapshotKMSKeyID: workloadScanAWSScannerSnapshotKMSKeyID,
		trivyBinary:             workloadScanTrivyBinary,
		gitleaksBinary:          workloadScanGitleaksBinary,
	}
}

func restoreWorkloadScanAWSFlagState(state workloadScanAWSFlagState) {
	workloadScanAWSAccountID = state.targetAccountID
	workloadScanAWSScannerAccountID = state.scannerAccountID
	workloadScanAWSSourceProfile = state.sourceProfile
	workloadScanAWSSourceRoleARN = state.sourceRoleARN
	workloadScanAWSSourceRoleSession = state.sourceRoleSession
	workloadScanAWSSourceRoleExternalID = state.sourceRoleExternalID
	workloadScanAWSScannerProfile = state.scannerProfile
	workloadScanAWSScannerRoleARN = state.scannerRoleARN
	workloadScanAWSScannerRoleSession = state.scannerRoleSession
	workloadScanAWSScannerRoleExternalID = state.scannerRoleExternalID
	workloadScanAWSShareKMSKeyID = state.shareKMSKeyID
	workloadScanAWSScannerSnapshotKMSKeyID = state.scannerSnapshotKMSKeyID
	workloadScanTrivyBinary = state.trivyBinary
	workloadScanGitleaksBinary = state.gitleaksBinary
}

func TestValidateWorkloadScanAWSFlagsRequiresAccountIDForScannerAccount(t *testing.T) {
	state := snapshotWorkloadScanAWSFlagState()
	t.Cleanup(func() { restoreWorkloadScanAWSFlagState(state) })

	workloadScanAWSAccountID = ""
	workloadScanAWSScannerAccountID = "222222222222"

	if err := validateWorkloadScanAWSFlags(); err == nil {
		t.Fatal("expected account id validation error")
	}
}

func TestValidateWorkloadScanAWSFlagsRequiresScannerAccountForScannerAuth(t *testing.T) {
	state := snapshotWorkloadScanAWSFlagState()
	t.Cleanup(func() { restoreWorkloadScanAWSFlagState(state) })

	workloadScanAWSAccountID = "111111111111"
	workloadScanAWSScannerAccountID = ""
	workloadScanAWSScannerProfile = "scanner"

	if err := validateWorkloadScanAWSFlags(); err == nil {
		t.Fatal("expected scanner account validation error")
	}
}

func TestValidateWorkloadScanAWSFlagsRequiresScannerCredentialsForCrossAccount(t *testing.T) {
	state := snapshotWorkloadScanAWSFlagState()
	t.Cleanup(func() { restoreWorkloadScanAWSFlagState(state) })

	workloadScanAWSAccountID = "111111111111"
	workloadScanAWSScannerAccountID = "222222222222"

	if err := validateWorkloadScanAWSFlags(); err == nil {
		t.Fatal("expected scanner credential validation error")
	}
}

func TestBuildWorkloadScanAWSSpecs(t *testing.T) {
	state := snapshotWorkloadScanAWSFlagState()
	t.Cleanup(func() { restoreWorkloadScanAWSFlagState(state) })

	workloadScanAWSSourceProfile = "source-profile"
	workloadScanAWSSourceRoleARN = "arn:aws:iam::111111111111:role/source"
	workloadScanAWSSourceRoleSession = "source-session"
	workloadScanAWSSourceRoleExternalID = "source-external"
	workloadScanAWSScannerProfile = "scanner-profile"
	workloadScanAWSScannerRoleARN = "arn:aws:iam::222222222222:role/scanner"
	workloadScanAWSScannerRoleSession = "scanner-session"
	workloadScanAWSScannerRoleExternalID = "scanner-external"

	sourceSpec := buildWorkloadScanSourceAWSSpec()
	if sourceSpec.AWSProfile != "source-profile" || sourceSpec.AWSRoleARN != "arn:aws:iam::111111111111:role/source" {
		t.Fatalf("unexpected source spec: %#v", sourceSpec)
	}
	scannerSpec := buildWorkloadScanScannerAWSSpec()
	if scannerSpec.AWSProfile != "scanner-profile" || scannerSpec.AWSRoleARN != "arn:aws:iam::222222222222:role/scanner" {
		t.Fatalf("unexpected scanner spec: %#v", scannerSpec)
	}
}

func TestWorkloadScanAWSFlagsRegistered(t *testing.T) {
	for _, name := range []string{
		"source-profile",
		"source-role-arn",
		"scanner-profile",
		"scanner-role-arn",
		"share-kms-key-id",
		"scanner-snapshot-kms-key-id",
	} {
		if flag := workloadScanCmd.PersistentFlags().Lookup(name); flag == nil {
			t.Fatalf("expected flag %s to be registered", name)
		}
	}
}

func TestResolveWorkloadScanTrivyBinaryFallsBackToDefaultOnWhitespaceConfig(t *testing.T) {
	state := snapshotWorkloadScanAWSFlagState()
	t.Cleanup(func() { restoreWorkloadScanAWSFlagState(state) })

	workloadScanTrivyBinary = ""

	got := resolveWorkloadScanTrivyBinary(&app.Config{WorkloadScanTrivyBinary: "   "})
	if got != "trivy" {
		t.Fatalf("expected default trivy binary, got %q", got)
	}
}

func TestResolveWorkloadScanTrivyBinaryPrefersCLIOverride(t *testing.T) {
	state := snapshotWorkloadScanAWSFlagState()
	t.Cleanup(func() { restoreWorkloadScanAWSFlagState(state) })

	workloadScanTrivyBinary = "/usr/local/bin/trivy"

	got := resolveWorkloadScanTrivyBinary(&app.Config{WorkloadScanTrivyBinary: "/opt/trivy"})
	if got != "/usr/local/bin/trivy" {
		t.Fatalf("expected CLI override to win, got %q", got)
	}
}

func TestResolveWorkloadScanGitleaksBinaryFallsBackToEmptyOnWhitespaceConfig(t *testing.T) {
	state := snapshotWorkloadScanAWSFlagState()
	t.Cleanup(func() { restoreWorkloadScanAWSFlagState(state) })

	workloadScanGitleaksBinary = ""

	got := resolveWorkloadScanGitleaksBinary(&app.Config{WorkloadScanGitleaksBinary: "   "})
	if got != "" {
		t.Fatalf("expected empty default gitleaks binary, got %q", got)
	}
}

func TestResolveWorkloadScanGitleaksBinaryPrefersCLIOverride(t *testing.T) {
	state := snapshotWorkloadScanAWSFlagState()
	t.Cleanup(func() { restoreWorkloadScanAWSFlagState(state) })

	workloadScanGitleaksBinary = "/usr/local/bin/gitleaks"

	got := resolveWorkloadScanGitleaksBinary(&app.Config{WorkloadScanGitleaksBinary: "/opt/gitleaks"})
	if got != "/usr/local/bin/gitleaks" {
		t.Fatalf("expected CLI override to win, got %q", got)
	}
}
