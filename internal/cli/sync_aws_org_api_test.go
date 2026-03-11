package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type syncAWSOrgState struct {
	region             string
	multiRegion        bool
	concurrency        int
	permissionLookback int
	awsPSInclude       string
	awsPSExclude       string
	table              string
	validate           bool
	output             string
	strictExit         bool
	awsProfile         string
	awsConfigFile      string
	awsSharedCredsFile string
	awsCredentialProc  string
	awsWebIDTokenFile  string
	awsWebIDRoleARN    string
	awsRoleARN         string
	awsRoleSession     string
	awsRoleExternalID  string
	awsRoleMFASerial   string
	awsRoleMFAToken    string
	awsRoleSourceID    string
	awsRoleDuration    string
	awsRoleTags        string
	awsRoleTransitive  string
	awsOrgRole         string
	awsOrgInclude      string
	awsOrgExclude      string
	awsOrgConcurrency  int
	directFn           func(context.Context, time.Time) error
}

func snapshotSyncAWSOrgState() syncAWSOrgState {
	return syncAWSOrgState{
		region:             syncRegion,
		multiRegion:        syncMultiRegion,
		concurrency:        syncConcurrency,
		permissionLookback: syncPermissionLookback,
		awsPSInclude:       syncAWSPSInclude,
		awsPSExclude:       syncAWSPSExclude,
		table:              syncTable,
		validate:           syncValidate,
		output:             syncOutput,
		strictExit:         syncStrictExit,
		awsProfile:         syncAWSProfile,
		awsConfigFile:      syncAWSConfigFile,
		awsSharedCredsFile: syncAWSSharedCredsFile,
		awsCredentialProc:  syncAWSCredentialProc,
		awsWebIDTokenFile:  syncAWSWebIDTokenFile,
		awsWebIDRoleARN:    syncAWSWebIDRoleARN,
		awsRoleARN:         syncAWSRoleARN,
		awsRoleSession:     syncAWSRoleSession,
		awsRoleExternalID:  syncAWSRoleExternalID,
		awsRoleMFASerial:   syncAWSRoleMFASerial,
		awsRoleMFAToken:    syncAWSRoleMFAToken,
		awsRoleSourceID:    syncAWSRoleSourceID,
		awsRoleDuration:    syncAWSRoleDuration,
		awsRoleTags:        syncAWSRoleTags,
		awsRoleTransitive:  syncAWSRoleTransitive,
		awsOrgRole:         syncAWSOrgRole,
		awsOrgInclude:      syncAWSOrgInclude,
		awsOrgExclude:      syncAWSOrgExclude,
		awsOrgConcurrency:  syncAWSOrgConcurrency,
		directFn:           runAWSOrgSyncDirectFn,
	}
}

func restoreSyncAWSOrgState(state syncAWSOrgState) {
	syncRegion = state.region
	syncMultiRegion = state.multiRegion
	syncConcurrency = state.concurrency
	syncPermissionLookback = state.permissionLookback
	syncAWSPSInclude = state.awsPSInclude
	syncAWSPSExclude = state.awsPSExclude
	syncTable = state.table
	syncValidate = state.validate
	syncOutput = state.output
	syncStrictExit = state.strictExit
	syncAWSProfile = state.awsProfile
	syncAWSConfigFile = state.awsConfigFile
	syncAWSSharedCredsFile = state.awsSharedCredsFile
	syncAWSCredentialProc = state.awsCredentialProc
	syncAWSWebIDTokenFile = state.awsWebIDTokenFile
	syncAWSWebIDRoleARN = state.awsWebIDRoleARN
	syncAWSRoleARN = state.awsRoleARN
	syncAWSRoleSession = state.awsRoleSession
	syncAWSRoleExternalID = state.awsRoleExternalID
	syncAWSRoleMFASerial = state.awsRoleMFASerial
	syncAWSRoleMFAToken = state.awsRoleMFAToken
	syncAWSRoleSourceID = state.awsRoleSourceID
	syncAWSRoleDuration = state.awsRoleDuration
	syncAWSRoleTags = state.awsRoleTags
	syncAWSRoleTransitive = state.awsRoleTransitive
	syncAWSOrgRole = state.awsOrgRole
	syncAWSOrgInclude = state.awsOrgInclude
	syncAWSOrgExclude = state.awsOrgExclude
	syncAWSOrgConcurrency = state.awsOrgConcurrency
	runAWSOrgSyncDirectFn = state.directFn
}

func TestRunAWSOrgSync_APIModeSuccess(t *testing.T) {
	state := snapshotSyncAWSOrgState()
	t.Cleanup(func() { restoreSyncAWSOrgState(state) })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/sync/aws-org" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req["profile"] != "prod-profile" {
			t.Fatalf("expected profile=prod-profile, got %#v", req["profile"])
		}
		if req["region"] != "us-west-2" {
			t.Fatalf("expected region=us-west-2, got %#v", req["region"])
		}
		if req["multi_region"] != true {
			t.Fatalf("expected multi_region=true, got %#v", req["multi_region"])
		}
		if req["concurrency"] != float64(4) {
			t.Fatalf("expected concurrency=4, got %#v", req["concurrency"])
		}
		if req["org_role"] != "OrganizationAccountAccessRole" {
			t.Fatalf("expected org_role=OrganizationAccountAccessRole, got %#v", req["org_role"])
		}
		if req["account_concurrency"] != float64(3) {
			t.Fatalf("expected account_concurrency=3, got %#v", req["account_concurrency"])
		}
		if req["permission_usage_lookback_days"] != float64(210) {
			t.Fatalf("expected permission_usage_lookback_days=210, got %#v", req["permission_usage_lookback_days"])
		}
		include, ok := req["aws_identity_center_permission_sets_include"].([]interface{})
		if !ok || len(include) != 1 || include[0] != "Admin" {
			t.Fatalf("unexpected permission set include payload: %#v", req["aws_identity_center_permission_sets_include"])
		}
		exclude, ok := req["aws_identity_center_permission_sets_exclude"].([]interface{})
		if !ok || len(exclude) != 1 || exclude[0] != "ReadOnly" {
			t.Fatalf("unexpected permission set exclude payload: %#v", req["aws_identity_center_permission_sets_exclude"])
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"provider": "aws_org",
			"validate": false,
			"results": []map[string]interface{}{
				{"table": "aws_iam_users", "synced": 10, "errors": 0, "duration": 1000000000},
			},
		})
	}))
	defer server.Close()

	directCalled := false
	runAWSOrgSyncDirectFn = func(context.Context, time.Time) error {
		directCalled = true
		return nil
	}

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAPI))
	t.Setenv(envCLIAPIURL, server.URL)
	syncRegion = "us-west-2"
	syncMultiRegion = true
	syncConcurrency = 4
	syncPermissionLookback = 210
	syncAWSPSInclude = "Admin"
	syncAWSPSExclude = "ReadOnly"
	syncTable = "aws_iam_users"
	syncValidate = false
	syncOutput = FormatTable
	syncStrictExit = false
	syncAWSProfile = "prod-profile"
	syncAWSConfigFile = ""
	syncAWSSharedCredsFile = ""
	syncAWSCredentialProc = ""
	syncAWSWebIDTokenFile = ""
	syncAWSWebIDRoleARN = ""
	syncAWSRoleARN = ""
	syncAWSRoleExternalID = ""
	syncAWSRoleMFASerial = ""
	syncAWSRoleMFAToken = ""
	syncAWSRoleSourceID = ""
	syncAWSRoleDuration = ""
	syncAWSRoleTags = ""
	syncAWSRoleTransitive = ""
	syncAWSOrgRole = "OrganizationAccountAccessRole"
	syncAWSOrgInclude = "111111111111,222222222222"
	syncAWSOrgExclude = "333333333333"
	syncAWSOrgConcurrency = 3

	output := captureStdout(t, func() {
		if err := runAWSOrgSync(context.Background(), time.Now()); err != nil {
			t.Fatalf("runAWSOrgSync failed: %v", err)
		}
	})

	if directCalled {
		t.Fatal("did not expect direct fallback in api mode success path")
	}
	if !strings.Contains(output, "AWS Org Sync Results") {
		t.Fatalf("expected sync summary output, got %q", output)
	}
}

func TestRunAWSOrgSync_AutoModeFallbackOnTransportError(t *testing.T) {
	state := snapshotSyncAWSOrgState()
	t.Cleanup(func() { restoreSyncAWSOrgState(state) })

	directCalled := false
	runAWSOrgSyncDirectFn = func(context.Context, time.Time) error {
		directCalled = true
		return nil
	}

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAuto))
	t.Setenv(envCLIAPIURL, "http://127.0.0.1:1")
	syncAWSConfigFile = ""
	syncAWSSharedCredsFile = ""
	syncAWSCredentialProc = ""
	syncAWSWebIDTokenFile = ""
	syncAWSWebIDRoleARN = ""
	syncAWSRoleARN = ""
	syncAWSRoleExternalID = ""
	syncAWSRoleMFASerial = ""
	syncAWSRoleMFAToken = ""
	syncAWSRoleSourceID = ""
	syncAWSRoleDuration = ""
	syncAWSRoleTags = ""
	syncAWSRoleTransitive = ""

	if err := runAWSOrgSync(context.Background(), time.Now()); err != nil {
		t.Fatalf("expected direct fallback success, got error: %v", err)
	}
	if !directCalled {
		t.Fatal("expected direct fallback function to be called")
	}
}

func TestRunAWSOrgSync_AutoModeNoFallbackOnUnauthorized(t *testing.T) {
	state := snapshotSyncAWSOrgState()
	t.Cleanup(func() { restoreSyncAWSOrgState(state) })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": "unauthorized"})
	}))
	defer server.Close()

	directCalled := false
	runAWSOrgSyncDirectFn = func(context.Context, time.Time) error {
		directCalled = true
		return nil
	}

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAuto))
	t.Setenv(envCLIAPIURL, server.URL)
	syncAWSConfigFile = ""
	syncAWSSharedCredsFile = ""
	syncAWSCredentialProc = ""
	syncAWSWebIDTokenFile = ""
	syncAWSWebIDRoleARN = ""
	syncAWSRoleARN = ""
	syncAWSRoleExternalID = ""
	syncAWSRoleMFASerial = ""
	syncAWSRoleMFAToken = ""
	syncAWSRoleSourceID = ""
	syncAWSRoleDuration = ""
	syncAWSRoleTags = ""
	syncAWSRoleTransitive = ""

	err := runAWSOrgSync(context.Background(), time.Now())
	if err == nil {
		t.Fatal("expected api error")
	}
	if !strings.Contains(err.Error(), "aws org sync via api failed") {
		t.Fatalf("unexpected error: %v", err)
	}
	if directCalled {
		t.Fatal("did not expect direct fallback on unauthorized response")
	}
}

func TestRunAWSOrgSync_APIModeIncompatibleFlagsError(t *testing.T) {
	state := snapshotSyncAWSOrgState()
	t.Cleanup(func() { restoreSyncAWSOrgState(state) })

	runAWSOrgSyncDirectFn = func(context.Context, time.Time) error {
		t.Fatal("did not expect direct fallback in api mode incompatibility path")
		return nil
	}

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAPI))
	syncAWSConfigFile = "/tmp/aws-config"

	err := runAWSOrgSync(context.Background(), time.Now())
	if err == nil {
		t.Fatal("expected api mode incompatibility error")
	}
	if !strings.Contains(err.Error(), "aws org sync API mode unsupported") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunAWSOrgSync_AutoModeIncompatibleFlagsFallbackToDirect(t *testing.T) {
	state := snapshotSyncAWSOrgState()
	t.Cleanup(func() { restoreSyncAWSOrgState(state) })

	directCalled := false
	runAWSOrgSyncDirectFn = func(context.Context, time.Time) error {
		directCalled = true
		return nil
	}

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAuto))
	syncAWSConfigFile = "/tmp/aws-config"

	if err := runAWSOrgSync(context.Background(), time.Now()); err != nil {
		t.Fatalf("expected direct fallback success, got error: %v", err)
	}
	if !directCalled {
		t.Fatal("expected direct fallback function to be called")
	}
}

func TestRunAWSOrgSync_APIModeAccountErrorsReturnNonZero(t *testing.T) {
	state := snapshotSyncAWSOrgState()
	t.Cleanup(func() { restoreSyncAWSOrgState(state) })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"provider": "aws_org",
			"validate": false,
			"results": []map[string]interface{}{
				{"table": "aws_iam_users", "synced": 2, "errors": 0, "duration": 1000000000},
			},
			"account_errors": []string{"account 999999999999: access denied"},
		})
	}))
	defer server.Close()

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAPI))
	t.Setenv(envCLIAPIURL, server.URL)
	syncAWSConfigFile = ""
	syncAWSSharedCredsFile = ""
	syncAWSCredentialProc = ""
	syncAWSWebIDTokenFile = ""
	syncAWSWebIDRoleARN = ""
	syncAWSRoleARN = ""
	syncAWSRoleExternalID = ""
	syncAWSRoleMFASerial = ""
	syncAWSRoleMFAToken = ""
	syncAWSRoleSourceID = ""
	syncAWSRoleDuration = ""
	syncAWSRoleTags = ""
	syncAWSRoleTransitive = ""

	err := runAWSOrgSync(context.Background(), time.Now())
	if err == nil {
		t.Fatal("expected account error summary")
	}
	if !strings.Contains(err.Error(), "AWS org sync") {
		t.Fatalf("unexpected error: %v", err)
	}
}
