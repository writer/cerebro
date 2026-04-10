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

type syncGCPAssetAPIState struct {
	table           string
	security        bool
	validate        bool
	concurrency     int
	output          string
	strictExit      bool
	credentialsFile string
	impersonateSA   string
	impersonateDel  string
	impersonateTTL  string
	directFn        func(context.Context, time.Time, []string, []string, []string, []string, bool, bool) error
}

func snapshotSyncGCPAssetAPIState() syncGCPAssetAPIState {
	return syncGCPAssetAPIState{
		table:           syncTable,
		security:        syncSecurity,
		validate:        syncValidate,
		concurrency:     syncConcurrency,
		output:          syncOutput,
		strictExit:      syncStrictExit,
		credentialsFile: syncGCPCredentialsFile,
		impersonateSA:   syncGCPImpersonateSA,
		impersonateDel:  syncGCPImpersonateDel,
		impersonateTTL:  syncGCPImpersonateTTL,
		directFn:        runGCPAssetAPISyncDirectFn,
	}
}

func restoreSyncGCPAssetAPIState(state syncGCPAssetAPIState) {
	syncTable = state.table
	syncSecurity = state.security
	syncValidate = state.validate
	syncConcurrency = state.concurrency
	syncOutput = state.output
	syncStrictExit = state.strictExit
	syncGCPCredentialsFile = state.credentialsFile
	syncGCPImpersonateSA = state.impersonateSA
	syncGCPImpersonateDel = state.impersonateDel
	syncGCPImpersonateTTL = state.impersonateTTL
	runGCPAssetAPISyncDirectFn = state.directFn
}

func TestRunGCPAssetAPISync_APIModeSuccess(t *testing.T) {
	state := snapshotSyncGCPAssetAPIState()
	t.Cleanup(func() { restoreSyncGCPAssetAPIState(state) })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/sync/gcp-asset" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		projects, ok := req["projects"].([]interface{})
		if !ok || len(projects) != 2 || projects[0] != "proj-a" || projects[1] != "proj-b" {
			t.Fatalf("unexpected projects payload: %#v", req["projects"])
		}
		if req["concurrency"] != float64(5) {
			t.Fatalf("expected concurrency=5, got %#v", req["concurrency"])
		}
		tables, ok := req["tables"].([]interface{})
		if !ok || len(tables) != 2 || tables[0] != "gcp_compute_instances" || tables[1] != "gcp_storage_buckets" {
			t.Fatalf("unexpected tables payload: %#v", req["tables"])
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"provider": "gcp_asset",
			"validate": false,
			"results": []map[string]interface{}{
				{"table": "gcp_compute_instances", "synced": 10, "errors": 0, "duration": 1000000000},
			},
		})
	}))
	defer server.Close()

	directCalled := false
	runGCPAssetAPISyncDirectFn = func(context.Context, time.Time, []string, []string, []string, []string, bool, bool) error {
		directCalled = true
		return nil
	}

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAPI))
	t.Setenv(envCLIAPIURL, server.URL)
	syncTable = "gcp_compute_instances,gcp_storage_buckets"
	syncSecurity = false
	syncValidate = false
	syncConcurrency = 5
	syncOutput = FormatTable
	syncStrictExit = false
	syncGCPCredentialsFile = ""
	syncGCPImpersonateSA = ""
	syncGCPImpersonateDel = ""
	syncGCPImpersonateTTL = ""

	output := captureStdout(t, func() {
		if err := runGCPAssetAPISync(context.Background(), time.Now(), []string{"proj-a", "proj-b"}); err != nil {
			t.Fatalf("runGCPAssetAPISync failed: %v", err)
		}
	})

	if directCalled {
		t.Fatal("did not expect direct fallback in api mode success path")
	}
	if !strings.Contains(output, "GCP (Asset API) Sync Results") || !strings.Contains(output, "gcp_compute_instances") {
		t.Fatalf("expected sync summary output, got %q", output)
	}
}

func TestRunGCPAssetAPISync_AutoModeFallbackOnTransportError(t *testing.T) {
	state := snapshotSyncGCPAssetAPIState()
	t.Cleanup(func() { restoreSyncGCPAssetAPIState(state) })

	directCalled := false
	runGCPAssetAPISyncDirectFn = func(_ context.Context, _ time.Time, projects []string, _ []string, native []string, _ []string, runNative bool, runSecurity bool) error {
		directCalled = true
		if len(projects) != 1 || projects[0] != "proj-a" {
			t.Fatalf("unexpected fallback projects: %#v", projects)
		}
		if !runNative || runSecurity {
			t.Fatalf("unexpected fallback sync mode: runNative=%v runSecurity=%v", runNative, runSecurity)
		}
		if len(native) != 1 || native[0] != "gcp_compute_instances" {
			t.Fatalf("unexpected native filter: %#v", native)
		}
		return nil
	}

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAuto))
	t.Setenv(envCLIAPIURL, "http://127.0.0.1:1")
	syncTable = "gcp_compute_instances"
	syncSecurity = false
	syncValidate = false
	syncConcurrency = 3
	syncGCPCredentialsFile = ""
	syncGCPImpersonateSA = ""
	syncGCPImpersonateDel = ""
	syncGCPImpersonateTTL = ""

	if err := runGCPAssetAPISync(context.Background(), time.Now(), []string{"proj-a"}); err != nil {
		t.Fatalf("expected direct fallback success, got error: %v", err)
	}
	if !directCalled {
		t.Fatal("expected direct fallback function to be called")
	}
}

func TestRunGCPAssetAPISync_AutoModeNoFallbackOnUnauthorized(t *testing.T) {
	state := snapshotSyncGCPAssetAPIState()
	t.Cleanup(func() { restoreSyncGCPAssetAPIState(state) })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": "unauthorized"})
	}))
	defer server.Close()

	directCalled := false
	runGCPAssetAPISyncDirectFn = func(context.Context, time.Time, []string, []string, []string, []string, bool, bool) error {
		directCalled = true
		return nil
	}

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAuto))
	t.Setenv(envCLIAPIURL, server.URL)
	syncTable = "gcp_compute_instances"
	syncSecurity = false
	syncValidate = false
	syncGCPCredentialsFile = ""
	syncGCPImpersonateSA = ""
	syncGCPImpersonateDel = ""
	syncGCPImpersonateTTL = ""

	err := runGCPAssetAPISync(context.Background(), time.Now(), []string{"proj-a"})
	if err == nil {
		t.Fatal("expected api error")
		return
	}
	if !strings.Contains(err.Error(), "gcp asset sync via api failed") {
		t.Fatalf("unexpected error: %v", err)
	}
	if directCalled {
		t.Fatal("did not expect direct fallback on unauthorized response")
	}
}

func TestRunGCPAssetAPISync_APIModeConfigError(t *testing.T) {
	state := snapshotSyncGCPAssetAPIState()
	t.Cleanup(func() { restoreSyncGCPAssetAPIState(state) })

	runGCPAssetAPISyncDirectFn = func(context.Context, time.Time, []string, []string, []string, []string, bool, bool) error {
		t.Fatal("did not expect direct fallback in api mode config error path")
		return nil
	}

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAPI))
	t.Setenv(envCLIAPIURL, "://bad-url")
	syncTable = "gcp_compute_instances"
	syncSecurity = false
	syncValidate = false
	syncGCPCredentialsFile = ""
	syncGCPImpersonateSA = ""
	syncGCPImpersonateDel = ""
	syncGCPImpersonateTTL = ""

	if err := runGCPAssetAPISync(context.Background(), time.Now(), []string{"proj-a"}); err == nil {
		t.Fatal("expected api mode config error")
		return
	}
}

func TestRunGCPAssetAPISync_APIModeIncompatibleFlagsError(t *testing.T) {
	state := snapshotSyncGCPAssetAPIState()
	t.Cleanup(func() { restoreSyncGCPAssetAPIState(state) })

	runGCPAssetAPISyncDirectFn = func(context.Context, time.Time, []string, []string, []string, []string, bool, bool) error {
		t.Fatal("did not expect direct fallback in api mode incompatibility path")
		return nil
	}

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAPI))
	syncTable = "gcp_compute_instances"
	syncSecurity = true
	syncValidate = false
	syncGCPCredentialsFile = ""
	syncGCPImpersonateSA = ""
	syncGCPImpersonateDel = ""
	syncGCPImpersonateTTL = ""

	err := runGCPAssetAPISync(context.Background(), time.Now(), []string{"proj-a"})
	if err == nil {
		t.Fatal("expected api mode incompatibility error")
		return
	}
	if !strings.Contains(err.Error(), "gcp asset sync API mode unsupported") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunGCPAssetAPISync_AutoModeIncompatibleFlagsFallbackToDirect(t *testing.T) {
	state := snapshotSyncGCPAssetAPIState()
	t.Cleanup(func() { restoreSyncGCPAssetAPIState(state) })

	directCalled := false
	runGCPAssetAPISyncDirectFn = func(context.Context, time.Time, []string, []string, []string, []string, bool, bool) error {
		directCalled = true
		return nil
	}

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAuto))
	syncTable = "gcp_compute_instances"
	syncSecurity = false
	syncValidate = false
	syncGCPCredentialsFile = ""
	syncGCPImpersonateSA = "svc@example-project.iam.gserviceaccount.com"
	syncGCPImpersonateDel = ""
	syncGCPImpersonateTTL = ""

	if err := runGCPAssetAPISync(context.Background(), time.Now(), []string{"proj-a"}); err != nil {
		t.Fatalf("expected direct fallback success, got error: %v", err)
	}
	if !directCalled {
		t.Fatal("expected direct fallback function to be called")
	}
}
