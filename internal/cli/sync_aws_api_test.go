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

type syncAWSState struct {
	region             string
	multiRegion        bool
	concurrency        int
	table              string
	validate           bool
	scanAfter          bool
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
	directFn           func(context.Context, time.Time) error
}

func snapshotSyncAWSState() syncAWSState {
	return syncAWSState{
		region:             syncRegion,
		multiRegion:        syncMultiRegion,
		concurrency:        syncConcurrency,
		table:              syncTable,
		validate:           syncValidate,
		scanAfter:          syncScanAfter,
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
		directFn:           runNativeSyncDirectFn,
	}
}

func restoreSyncAWSState(state syncAWSState) {
	syncRegion = state.region
	syncMultiRegion = state.multiRegion
	syncConcurrency = state.concurrency
	syncTable = state.table
	syncValidate = state.validate
	syncScanAfter = state.scanAfter
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
	runNativeSyncDirectFn = state.directFn
}

func TestRunNativeSync_APIModeSuccess(t *testing.T) {
	state := snapshotSyncAWSState()
	t.Cleanup(func() { restoreSyncAWSState(state) })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/sync/aws" {
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
		if req["concurrency"] != float64(3) {
			t.Fatalf("expected concurrency=3, got %#v", req["concurrency"])
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"provider":                "aws",
			"validate":                false,
			"relationships_extracted": 12,
			"results": []map[string]interface{}{
				{"table": "aws_iam_users", "synced": 5, "errors": 0, "duration": 1000000000},
			},
		})
	}))
	defer server.Close()

	directCalled := false
	runNativeSyncDirectFn = func(context.Context, time.Time) error {
		directCalled = true
		return nil
	}

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAPI))
	t.Setenv(envCLIAPIURL, server.URL)
	syncRegion = "us-west-2"
	syncMultiRegion = true
	syncConcurrency = 3
	syncTable = ""
	syncValidate = false
	syncScanAfter = false
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

	output := captureStdout(t, func() {
		if err := runNativeSync(context.Background(), time.Now()); err != nil {
			t.Fatalf("runNativeSync failed: %v", err)
		}
	})

	if directCalled {
		t.Fatal("did not expect direct fallback in api mode success path")
	}
	if !strings.Contains(output, "AWS Sync Results") || !strings.Contains(output, "Extracted 12 relationships") {
		t.Fatalf("expected sync summary output, got %q", output)
	}
}

func TestRunNativeSync_AutoModeFallbackOnTransportError(t *testing.T) {
	state := snapshotSyncAWSState()
	t.Cleanup(func() { restoreSyncAWSState(state) })

	directCalled := false
	runNativeSyncDirectFn = func(context.Context, time.Time) error {
		directCalled = true
		return nil
	}

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAuto))
	t.Setenv(envCLIAPIURL, "http://127.0.0.1:1")
	syncAWSProfile = ""

	if err := runNativeSync(context.Background(), time.Now()); err != nil {
		t.Fatalf("expected direct fallback success, got error: %v", err)
	}
	if !directCalled {
		t.Fatal("expected direct fallback function to be called")
	}
}

func TestRunNativeSync_AutoModeNoFallbackOnUnauthorized(t *testing.T) {
	state := snapshotSyncAWSState()
	t.Cleanup(func() { restoreSyncAWSState(state) })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": "unauthorized"})
	}))
	defer server.Close()

	directCalled := false
	runNativeSyncDirectFn = func(context.Context, time.Time) error {
		directCalled = true
		return nil
	}

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAuto))
	t.Setenv(envCLIAPIURL, server.URL)
	syncAWSProfile = ""

	err := runNativeSync(context.Background(), time.Now())
	if err == nil {
		t.Fatal("expected api error")
	}
	if !strings.Contains(err.Error(), "aws sync via api failed") {
		t.Fatalf("unexpected error: %v", err)
	}
	if directCalled {
		t.Fatal("did not expect direct fallback on unauthorized response")
	}
}

func TestRunNativeSync_APIModeIncompatibleFlagsError(t *testing.T) {
	state := snapshotSyncAWSState()
	t.Cleanup(func() { restoreSyncAWSState(state) })

	runNativeSyncDirectFn = func(context.Context, time.Time) error {
		t.Fatal("did not expect direct fallback in api mode incompatibility path")
		return nil
	}

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAPI))
	syncAWSConfigFile = "/tmp/aws-config"

	err := runNativeSync(context.Background(), time.Now())
	if err == nil {
		t.Fatal("expected api mode incompatibility error")
	}
	if !strings.Contains(err.Error(), "aws sync API mode unsupported") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunNativeSync_AutoModeIncompatibleFlagsFallbackToDirect(t *testing.T) {
	state := snapshotSyncAWSState()
	t.Cleanup(func() { restoreSyncAWSState(state) })

	directCalled := false
	runNativeSyncDirectFn = func(context.Context, time.Time) error {
		directCalled = true
		return nil
	}

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAuto))
	syncAWSConfigFile = "/tmp/aws-config"

	if err := runNativeSync(context.Background(), time.Now()); err != nil {
		t.Fatalf("expected direct fallback success, got error: %v", err)
	}
	if !directCalled {
		t.Fatal("expected direct fallback function to be called")
	}
}
