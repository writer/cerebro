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

type syncAzureState struct {
	subscription            string
	subscriptions           string
	managementGroup         string
	subscriptionConcurrency int
	concurrency             int
	table                   string
	validate                bool
	scanAfter               bool
	output                  string
	strictExit              bool
	directFn                func(context.Context, time.Time, []string) error
}

func snapshotSyncAzureState() syncAzureState {
	return syncAzureState{
		subscription:            syncAzureSubscription,
		subscriptions:           syncAzureSubscriptions,
		managementGroup:         syncAzureMgmtGroup,
		subscriptionConcurrency: syncAzureSubConcurrency,
		concurrency:             syncConcurrency,
		table:                   syncTable,
		validate:                syncValidate,
		scanAfter:               syncScanAfter,
		output:                  syncOutput,
		strictExit:              syncStrictExit,
		directFn:                runAzureSyncDirectFn,
	}
}

func restoreSyncAzureState(state syncAzureState) {
	syncAzureSubscription = state.subscription
	syncAzureSubscriptions = state.subscriptions
	syncAzureMgmtGroup = state.managementGroup
	syncAzureSubConcurrency = state.subscriptionConcurrency
	syncConcurrency = state.concurrency
	syncTable = state.table
	syncValidate = state.validate
	syncScanAfter = state.scanAfter
	syncOutput = state.output
	syncStrictExit = state.strictExit
	runAzureSyncDirectFn = state.directFn
}

func TestRunAzureSync_APIModeSuccess(t *testing.T) {
	state := snapshotSyncAzureState()
	t.Cleanup(func() { restoreSyncAzureState(state) })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/sync/azure" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req["subscription"] != "sub-123" {
			t.Fatalf("expected subscription=sub-123, got %#v", req["subscription"])
		}
		if req["concurrency"] != float64(5) {
			t.Fatalf("expected concurrency=5, got %#v", req["concurrency"])
		}
		tables, ok := req["tables"].([]interface{})
		if !ok || len(tables) != 2 || tables[0] != "azure_vm_instances" || tables[1] != "azure_storage_accounts" {
			t.Fatalf("unexpected tables payload: %#v", req["tables"])
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"provider": "azure",
			"validate": false,
			"results": []map[string]interface{}{
				{"table": "azure_vm_instances", "synced": 9, "errors": 0, "duration": 1000000000},
			},
		})
	}))
	defer server.Close()

	directCalled := false
	runAzureSyncDirectFn = func(context.Context, time.Time, []string) error {
		directCalled = true
		return nil
	}

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAPI))
	t.Setenv(envCLIAPIURL, server.URL)
	syncAzureSubscription = "sub-123"
	syncConcurrency = 5
	syncTable = "azure_vm_instances,azure_storage_accounts"
	syncValidate = false
	syncScanAfter = false
	syncOutput = FormatTable
	syncStrictExit = false

	output := captureStdout(t, func() {
		if err := runAzureSync(context.Background(), time.Now()); err != nil {
			t.Fatalf("runAzureSync failed: %v", err)
		}
	})

	if directCalled {
		t.Fatal("did not expect direct fallback in api mode success path")
	}
	if !strings.Contains(output, "Azure Sync Results") || !strings.Contains(output, "azure_vm_instances") {
		t.Fatalf("expected sync summary output, got %q", output)
	}
}

func TestRunAzureSync_AutoModeFallbackOnTransportError(t *testing.T) {
	state := snapshotSyncAzureState()
	t.Cleanup(func() { restoreSyncAzureState(state) })

	directCalled := false
	runAzureSyncDirectFn = func(_ context.Context, _ time.Time, tables []string) error {
		directCalled = true
		if len(tables) != 1 || tables[0] != "azure_vm_instances" {
			t.Fatalf("unexpected fallback tables: %#v", tables)
		}
		return nil
	}

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAuto))
	t.Setenv(envCLIAPIURL, "http://127.0.0.1:1")
	syncTable = "azure_vm_instances"
	syncScanAfter = false
	syncValidate = false

	if err := runAzureSync(context.Background(), time.Now()); err != nil {
		t.Fatalf("expected direct fallback success, got error: %v", err)
	}
	if !directCalled {
		t.Fatal("expected direct fallback function to be called")
	}
}

func TestRunAzureSync_AutoModeNoFallbackOnUnauthorized(t *testing.T) {
	state := snapshotSyncAzureState()
	t.Cleanup(func() { restoreSyncAzureState(state) })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": "unauthorized"})
	}))
	defer server.Close()

	directCalled := false
	runAzureSyncDirectFn = func(context.Context, time.Time, []string) error {
		directCalled = true
		return nil
	}

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAuto))
	t.Setenv(envCLIAPIURL, server.URL)
	syncTable = "azure_vm_instances"
	syncScanAfter = false
	syncValidate = false

	err := runAzureSync(context.Background(), time.Now())
	if err == nil {
		t.Fatal("expected api error")
	}
	if !strings.Contains(err.Error(), "azure sync via api failed") {
		t.Fatalf("unexpected error: %v", err)
	}
	if directCalled {
		t.Fatal("did not expect direct fallback on unauthorized response")
	}
}

func TestRunAzureSync_APIModeConfigError(t *testing.T) {
	state := snapshotSyncAzureState()
	t.Cleanup(func() { restoreSyncAzureState(state) })

	runAzureSyncDirectFn = func(context.Context, time.Time, []string) error {
		t.Fatal("did not expect direct fallback in api mode config error path")
		return nil
	}

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAPI))
	t.Setenv(envCLIAPIURL, "://bad-url")
	syncValidate = false
	syncScanAfter = false

	if err := runAzureSync(context.Background(), time.Now()); err == nil {
		t.Fatal("expected api mode config error")
	}
}

func TestRunAzureSync_APIModeManagementGroupScope(t *testing.T) {
	state := snapshotSyncAzureState()
	t.Cleanup(func() { restoreSyncAzureState(state) })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/sync/azure" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req["management_group"] != "mg-platform" {
			t.Fatalf("expected management_group mg-platform, got %#v", req["management_group"])
		}
		if req["subscription_concurrency"] != float64(6) {
			t.Fatalf("expected subscription_concurrency=6, got %#v", req["subscription_concurrency"])
		}
		if _, ok := req["subscription"]; ok {
			t.Fatalf("did not expect subscription in management-group request: %#v", req)
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"provider": "azure",
			"validate": false,
			"results": []map[string]interface{}{
				{"table": "azure_vm_instances", "region": "sub-123", "synced": 3, "errors": 0, "duration": 1000000000},
			},
		})
	}))
	defer server.Close()

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAPI))
	t.Setenv(envCLIAPIURL, server.URL)
	syncAzureMgmtGroup = "mg-platform"
	syncAzureSubConcurrency = 6
	syncScanAfter = false
	syncValidate = false
	syncOutput = FormatTable
	syncStrictExit = false

	if err := runAzureSync(context.Background(), time.Now()); err != nil {
		t.Fatalf("runAzureSync failed: %v", err)
	}
}
