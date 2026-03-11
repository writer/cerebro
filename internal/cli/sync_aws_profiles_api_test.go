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

type syncAWSProfilesState struct {
	profiles           string
	region             string
	multiRegion        bool
	concurrency        int
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
	awsRoleExternalID  string
	awsRoleMFASerial   string
	awsRoleMFAToken    string
	awsRoleSourceID    string
	awsRoleDuration    string
	awsRoleTags        string
	awsRoleTransitive  string
	directFn           func(context.Context, time.Time, []string) error
}

func snapshotSyncAWSProfilesState() syncAWSProfilesState {
	return syncAWSProfilesState{
		profiles:           syncAWSProfiles,
		region:             syncRegion,
		multiRegion:        syncMultiRegion,
		concurrency:        syncConcurrency,
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
		awsRoleExternalID:  syncAWSRoleExternalID,
		awsRoleMFASerial:   syncAWSRoleMFASerial,
		awsRoleMFAToken:    syncAWSRoleMFAToken,
		awsRoleSourceID:    syncAWSRoleSourceID,
		awsRoleDuration:    syncAWSRoleDuration,
		awsRoleTags:        syncAWSRoleTags,
		awsRoleTransitive:  syncAWSRoleTransitive,
		directFn:           runMultiAccountAWSSyncDirectFn,
	}
}

func restoreSyncAWSProfilesState(state syncAWSProfilesState) {
	syncAWSProfiles = state.profiles
	syncRegion = state.region
	syncMultiRegion = state.multiRegion
	syncConcurrency = state.concurrency
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
	syncAWSRoleExternalID = state.awsRoleExternalID
	syncAWSRoleMFASerial = state.awsRoleMFASerial
	syncAWSRoleMFAToken = state.awsRoleMFAToken
	syncAWSRoleSourceID = state.awsRoleSourceID
	syncAWSRoleDuration = state.awsRoleDuration
	syncAWSRoleTags = state.awsRoleTags
	syncAWSRoleTransitive = state.awsRoleTransitive
	runMultiAccountAWSSyncDirectFn = state.directFn
}

func TestRunMultiAccountAWSSync_APIModeSuccess(t *testing.T) {
	state := snapshotSyncAWSProfilesState()
	t.Cleanup(func() { restoreSyncAWSProfilesState(state) })

	seenProfiles := make([]string, 0, 2)
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
		profile, _ := req["profile"].(string)
		if profile == "" {
			t.Fatalf("expected profile in request, got %#v", req["profile"])
		}
		seenProfiles = append(seenProfiles, profile)

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"provider": "aws",
			"validate": false,
			"results": []map[string]interface{}{
				{
					"table":    "aws_iam_users",
					"synced":   3,
					"errors":   0,
					"duration": 1000000000,
				},
			},
		})
	}))
	defer server.Close()

	directCalled := false
	runMultiAccountAWSSyncDirectFn = func(context.Context, time.Time, []string) error {
		directCalled = true
		return nil
	}

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAPI))
	t.Setenv(envCLIAPIURL, server.URL)
	syncAWSProfiles = "profile-a,profile-b"
	syncRegion = "us-west-2"
	syncMultiRegion = false
	syncConcurrency = 4
	syncTable = "aws_iam_users"
	syncValidate = false
	syncOutput = FormatTable
	syncStrictExit = false
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
		if err := runMultiAccountAWSSync(context.Background(), time.Now()); err != nil {
			t.Fatalf("runMultiAccountAWSSync failed: %v", err)
		}
	})

	if directCalled {
		t.Fatal("did not expect direct fallback in api mode success path")
	}
	if len(seenProfiles) != 2 || seenProfiles[0] != "profile-a" || seenProfiles[1] != "profile-b" {
		t.Fatalf("unexpected profiles sent to API: %#v", seenProfiles)
	}
	if !strings.Contains(output, "AWS (2 profiles) Sync Results") {
		t.Fatalf("expected sync summary output, got %q", output)
	}
}

func TestRunMultiAccountAWSSync_AutoModeFallbackOnTransportError(t *testing.T) {
	state := snapshotSyncAWSProfilesState()
	t.Cleanup(func() { restoreSyncAWSProfilesState(state) })

	directCalled := false
	runMultiAccountAWSSyncDirectFn = func(_ context.Context, _ time.Time, profiles []string) error {
		directCalled = true
		if len(profiles) != 2 || profiles[0] != "profile-a" || profiles[1] != "profile-b" {
			t.Fatalf("unexpected fallback profiles: %#v", profiles)
		}
		return nil
	}

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAuto))
	t.Setenv(envCLIAPIURL, "http://127.0.0.1:1")
	syncAWSProfiles = "profile-a,profile-b"
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

	if err := runMultiAccountAWSSync(context.Background(), time.Now()); err != nil {
		t.Fatalf("expected direct fallback success, got error: %v", err)
	}
	if !directCalled {
		t.Fatal("expected direct fallback function to be called")
	}
}

func TestRunMultiAccountAWSSync_AutoModeNoFallbackOnUnauthorized(t *testing.T) {
	state := snapshotSyncAWSProfilesState()
	t.Cleanup(func() { restoreSyncAWSProfilesState(state) })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": "unauthorized"})
	}))
	defer server.Close()

	directCalled := false
	runMultiAccountAWSSyncDirectFn = func(context.Context, time.Time, []string) error {
		directCalled = true
		return nil
	}

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAuto))
	t.Setenv(envCLIAPIURL, server.URL)
	syncAWSProfiles = "profile-a,profile-b"
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

	err := runMultiAccountAWSSync(context.Background(), time.Now())
	if err == nil {
		t.Fatal("expected api error")
	}
	if !strings.Contains(err.Error(), "aws multi-account sync via api failed") {
		t.Fatalf("unexpected error: %v", err)
	}
	if directCalled {
		t.Fatal("did not expect direct fallback on unauthorized response")
	}
}

func TestRunMultiAccountAWSSync_APIModeIncompatibleFlagsError(t *testing.T) {
	state := snapshotSyncAWSProfilesState()
	t.Cleanup(func() { restoreSyncAWSProfilesState(state) })

	runMultiAccountAWSSyncDirectFn = func(context.Context, time.Time, []string) error {
		t.Fatal("did not expect direct fallback in api mode incompatibility path")
		return nil
	}

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAPI))
	syncAWSProfiles = "profile-a,profile-b"
	syncAWSConfigFile = "/tmp/aws-config"

	err := runMultiAccountAWSSync(context.Background(), time.Now())
	if err == nil {
		t.Fatal("expected api mode incompatibility error")
	}
	if !strings.Contains(err.Error(), "aws multi-account sync API mode unsupported") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunMultiAccountAWSSync_AutoModeIncompatibleFlagsFallbackToDirect(t *testing.T) {
	state := snapshotSyncAWSProfilesState()
	t.Cleanup(func() { restoreSyncAWSProfilesState(state) })

	directCalled := false
	runMultiAccountAWSSyncDirectFn = func(context.Context, time.Time, []string) error {
		directCalled = true
		return nil
	}

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAuto))
	syncAWSProfiles = "profile-a,profile-b"
	syncAWSConfigFile = "/tmp/aws-config"

	if err := runMultiAccountAWSSync(context.Background(), time.Now()); err != nil {
		t.Fatalf("expected direct fallback success, got error: %v", err)
	}
	if !directCalled {
		t.Fatal("expected direct fallback function to be called")
	}
}
