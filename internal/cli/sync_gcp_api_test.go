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

type syncGCPAPIState struct {
	table              string
	security           bool
	validate           bool
	concurrency        int
	permissionLookback int
	gcpIAMGroups       string
	output             string
	strictExit         bool
	useAssetAPI        bool
	credentialsFile    string
	impersonateSA      string
	impersonateDel     string
	impersonateTTL     string
	directFn           func(context.Context, time.Time, string, []string, []string, []string, bool, bool, map[string]struct{}) error
}

func snapshotSyncGCPAPIState() syncGCPAPIState {
	return syncGCPAPIState{
		table:              syncTable,
		security:           syncSecurity,
		validate:           syncValidate,
		concurrency:        syncConcurrency,
		permissionLookback: syncPermissionLookback,
		gcpIAMGroups:       syncGCPIAMGroups,
		output:             syncOutput,
		strictExit:         syncStrictExit,
		useAssetAPI:        syncUseAssetAPI,
		credentialsFile:    syncGCPCredentialsFile,
		impersonateSA:      syncGCPImpersonateSA,
		impersonateDel:     syncGCPImpersonateDel,
		impersonateTTL:     syncGCPImpersonateTTL,
		directFn:           runGCPSyncDirectFn,
	}
}

func restoreSyncGCPAPIState(state syncGCPAPIState) {
	syncTable = state.table
	syncSecurity = state.security
	syncValidate = state.validate
	syncConcurrency = state.concurrency
	syncPermissionLookback = state.permissionLookback
	syncGCPIAMGroups = state.gcpIAMGroups
	syncOutput = state.output
	syncStrictExit = state.strictExit
	syncUseAssetAPI = state.useAssetAPI
	syncGCPCredentialsFile = state.credentialsFile
	syncGCPImpersonateSA = state.impersonateSA
	syncGCPImpersonateDel = state.impersonateDel
	syncGCPImpersonateTTL = state.impersonateTTL
	runGCPSyncDirectFn = state.directFn
}

func TestRunGCPSync_APIModeSuccess(t *testing.T) {
	state := snapshotSyncGCPAPIState()
	t.Cleanup(func() { restoreSyncGCPAPIState(state) })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/sync/gcp" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req["project"] != "proj-123" {
			t.Fatalf("expected project=proj-123, got %#v", req["project"])
		}
		if req["concurrency"] != float64(6) {
			t.Fatalf("expected concurrency=6, got %#v", req["concurrency"])
		}
		if req["permission_usage_lookback_days"] != float64(120) {
			t.Fatalf("expected permission_usage_lookback_days=120, got %#v", req["permission_usage_lookback_days"])
		}
		targetGroups, ok := req["gcp_iam_target_groups"].([]interface{})
		if !ok || len(targetGroups) != 2 || targetGroups[0] != "eng@example.com" || targetGroups[1] != "ops@example.com" {
			t.Fatalf("unexpected gcp_iam_target_groups payload: %#v", req["gcp_iam_target_groups"])
		}
		tables, ok := req["tables"].([]interface{})
		if !ok || len(tables) != 2 || tables[0] != "gcp_compute_instances" || tables[1] != "gcp_storage_buckets" {
			t.Fatalf("unexpected tables payload: %#v", req["tables"])
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"provider": "gcp",
			"validate": false,
			"results": []map[string]interface{}{
				{"table": "gcp_compute_instances", "synced": 8, "errors": 0, "duration": 1000000000},
			},
		})
	}))
	defer server.Close()

	directCalled := false
	runGCPSyncDirectFn = func(context.Context, time.Time, string, []string, []string, []string, bool, bool, map[string]struct{}) error {
		directCalled = true
		return nil
	}

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAPI))
	t.Setenv(envCLIAPIURL, server.URL)
	syncTable = "gcp_compute_instances,gcp_storage_buckets"
	syncSecurity = false
	syncValidate = false
	syncConcurrency = 6
	syncPermissionLookback = 120
	syncGCPIAMGroups = "eng@example.com,ops@example.com"
	syncOutput = FormatTable
	syncStrictExit = false
	syncUseAssetAPI = false
	syncGCPCredentialsFile = ""
	syncGCPImpersonateSA = ""
	syncGCPImpersonateDel = ""
	syncGCPImpersonateTTL = ""

	output := captureStdout(t, func() {
		if err := runGCPSync(context.Background(), time.Now(), "proj-123"); err != nil {
			t.Fatalf("runGCPSync failed: %v", err)
		}
	})

	if directCalled {
		t.Fatal("did not expect direct fallback in api mode success path")
	}
	if !strings.Contains(output, "GCP Sync Results") || !strings.Contains(output, "gcp_compute_instances") {
		t.Fatalf("expected sync summary output, got %q", output)
	}
}

func TestRunGCPSync_AutoModeFallbackOnTransportError(t *testing.T) {
	state := snapshotSyncGCPAPIState()
	t.Cleanup(func() { restoreSyncGCPAPIState(state) })

	directCalled := false
	runGCPSyncDirectFn = func(_ context.Context, _ time.Time, projectID string, _ []string, native []string, _ []string, runNative bool, runSecurity bool, _ map[string]struct{}) error {
		directCalled = true
		if projectID != "proj-123" {
			t.Fatalf("unexpected fallback project id: %q", projectID)
		}
		if !runNative || runSecurity {
			t.Fatalf("unexpected fallback sync mode: runNative=%v runSecurity=%v", runNative, runSecurity)
		}
		if len(native) != 1 || native[0] != "gcp_compute_instances" {
			t.Fatalf("unexpected native table filter: %#v", native)
		}
		return nil
	}

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAuto))
	t.Setenv(envCLIAPIURL, "http://127.0.0.1:1")
	syncTable = "gcp_compute_instances"
	syncSecurity = false
	syncValidate = false
	syncConcurrency = 3
	syncUseAssetAPI = false
	syncGCPCredentialsFile = ""
	syncGCPImpersonateSA = ""
	syncGCPImpersonateDel = ""
	syncGCPImpersonateTTL = ""

	if err := runGCPSync(context.Background(), time.Now(), "proj-123"); err != nil {
		t.Fatalf("expected direct fallback success, got error: %v", err)
	}
	if !directCalled {
		t.Fatal("expected direct fallback function to be called")
	}
}

func TestRunGCPSync_AutoModeNoFallbackOnUnauthorized(t *testing.T) {
	state := snapshotSyncGCPAPIState()
	t.Cleanup(func() { restoreSyncGCPAPIState(state) })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": "unauthorized"})
	}))
	defer server.Close()

	directCalled := false
	runGCPSyncDirectFn = func(context.Context, time.Time, string, []string, []string, []string, bool, bool, map[string]struct{}) error {
		directCalled = true
		return nil
	}

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAuto))
	t.Setenv(envCLIAPIURL, server.URL)
	syncTable = "gcp_compute_instances"
	syncSecurity = false
	syncValidate = false
	syncUseAssetAPI = false
	syncGCPCredentialsFile = ""
	syncGCPImpersonateSA = ""
	syncGCPImpersonateDel = ""
	syncGCPImpersonateTTL = ""

	err := runGCPSync(context.Background(), time.Now(), "proj-123")
	if err == nil {
		t.Fatal("expected api error")
	}
	if !strings.Contains(err.Error(), "gcp sync via api failed") {
		t.Fatalf("unexpected error: %v", err)
	}
	if directCalled {
		t.Fatal("did not expect direct fallback on unauthorized response")
	}
}

func TestRunGCPSync_APIModeConfigError(t *testing.T) {
	state := snapshotSyncGCPAPIState()
	t.Cleanup(func() { restoreSyncGCPAPIState(state) })

	runGCPSyncDirectFn = func(context.Context, time.Time, string, []string, []string, []string, bool, bool, map[string]struct{}) error {
		t.Fatal("did not expect direct fallback in api mode config error path")
		return nil
	}

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAPI))
	t.Setenv(envCLIAPIURL, "://bad-url")
	syncTable = "gcp_compute_instances"
	syncSecurity = false
	syncValidate = false
	syncUseAssetAPI = false
	syncGCPCredentialsFile = ""
	syncGCPImpersonateSA = ""
	syncGCPImpersonateDel = ""
	syncGCPImpersonateTTL = ""

	if err := runGCPSync(context.Background(), time.Now(), "proj-123"); err == nil {
		t.Fatal("expected api mode config error")
	}
}

func TestRunGCPSync_APIModeIncompatibleFlagsError(t *testing.T) {
	state := snapshotSyncGCPAPIState()
	t.Cleanup(func() { restoreSyncGCPAPIState(state) })

	runGCPSyncDirectFn = func(context.Context, time.Time, string, []string, []string, []string, bool, bool, map[string]struct{}) error {
		t.Fatal("did not expect direct fallback in api mode incompatibility path")
		return nil
	}

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAPI))
	syncTable = "gcp_compute_instances"
	syncSecurity = false
	syncValidate = false
	syncUseAssetAPI = false
	syncGCPCredentialsFile = "/tmp/gcp-creds.json"
	syncGCPImpersonateSA = ""
	syncGCPImpersonateDel = ""
	syncGCPImpersonateTTL = ""

	err := runGCPSync(context.Background(), time.Now(), "proj-123")
	if err == nil {
		t.Fatal("expected api mode incompatibility error")
	}
	if !strings.Contains(err.Error(), "gcp sync API mode unsupported") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunGCPSync_AutoModeIncompatibleFlagsFallbackToDirect(t *testing.T) {
	state := snapshotSyncGCPAPIState()
	t.Cleanup(func() { restoreSyncGCPAPIState(state) })

	directCalled := false
	runGCPSyncDirectFn = func(context.Context, time.Time, string, []string, []string, []string, bool, bool, map[string]struct{}) error {
		directCalled = true
		return nil
	}

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAuto))
	syncTable = "gcp_compute_instances"
	syncSecurity = false
	syncValidate = false
	syncUseAssetAPI = false
	syncGCPCredentialsFile = ""
	syncGCPImpersonateSA = "svc@example-project.iam.gserviceaccount.com"
	syncGCPImpersonateDel = ""
	syncGCPImpersonateTTL = ""

	if err := runGCPSync(context.Background(), time.Now(), "proj-123"); err != nil {
		t.Fatalf("expected direct fallback success, got error: %v", err)
	}
	if !directCalled {
		t.Fatal("expected direct fallback function to be called")
	}
}
