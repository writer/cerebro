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

type syncK8sState struct {
	kubeconfig  string
	kubeCtx     string
	namespace   string
	concurrency int
	table       string
	validate    bool
	scanAfter   bool
	output      string
	strictExit  bool
	directFn    func(context.Context, time.Time, []string) error
}

func snapshotSyncK8sState() syncK8sState {
	return syncK8sState{
		kubeconfig:  syncK8sKubeconfig,
		kubeCtx:     syncK8sContext,
		namespace:   syncK8sNamespace,
		concurrency: syncConcurrency,
		table:       syncTable,
		validate:    syncValidate,
		scanAfter:   syncScanAfter,
		output:      syncOutput,
		strictExit:  syncStrictExit,
		directFn:    runK8sSyncDirectFn,
	}
}

func restoreSyncK8sState(state syncK8sState) {
	syncK8sKubeconfig = state.kubeconfig
	syncK8sContext = state.kubeCtx
	syncK8sNamespace = state.namespace
	syncConcurrency = state.concurrency
	syncTable = state.table
	syncValidate = state.validate
	syncScanAfter = state.scanAfter
	syncOutput = state.output
	syncStrictExit = state.strictExit
	runK8sSyncDirectFn = state.directFn
}

func TestRunK8sSync_APIModeSuccess(t *testing.T) {
	state := snapshotSyncK8sState()
	t.Cleanup(func() { restoreSyncK8sState(state) })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/sync/k8s" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req["kubeconfig"] != "/tmp/kubeconfig" {
			t.Fatalf("expected kubeconfig=/tmp/kubeconfig, got %#v", req["kubeconfig"])
		}
		if req["context"] != "prod-context" {
			t.Fatalf("expected context=prod-context, got %#v", req["context"])
		}
		if req["namespace"] != "payments" {
			t.Fatalf("expected namespace=payments, got %#v", req["namespace"])
		}
		if req["concurrency"] != float64(4) {
			t.Fatalf("expected concurrency=4, got %#v", req["concurrency"])
		}
		tables, ok := req["tables"].([]interface{})
		if !ok || len(tables) != 2 || tables[0] != "k8s_pods" || tables[1] != "k8s_services" {
			t.Fatalf("unexpected tables payload: %#v", req["tables"])
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"provider": "k8s",
			"validate": false,
			"results": []map[string]interface{}{
				{"table": "k8s_pods", "synced": 6, "errors": 0, "duration": 1000000000},
			},
		})
	}))
	defer server.Close()

	directCalled := false
	runK8sSyncDirectFn = func(context.Context, time.Time, []string) error {
		directCalled = true
		return nil
	}

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAPI))
	t.Setenv(envCLIAPIURL, server.URL)
	syncK8sKubeconfig = "/tmp/kubeconfig"
	syncK8sContext = "prod-context"
	syncK8sNamespace = "payments"
	syncConcurrency = 4
	syncTable = "k8s_pods,k8s_services"
	syncValidate = false
	syncScanAfter = false
	syncOutput = FormatTable
	syncStrictExit = false

	output := captureStdout(t, func() {
		if err := runK8sSync(context.Background(), time.Now()); err != nil {
			t.Fatalf("runK8sSync failed: %v", err)
		}
	})

	if directCalled {
		t.Fatal("did not expect direct fallback in api mode success path")
	}
	if !strings.Contains(output, "Kubernetes Sync Results") || !strings.Contains(output, "k8s_pods") {
		t.Fatalf("expected sync summary output, got %q", output)
	}
}

func TestRunK8sSync_AutoModeFallbackOnTransportError(t *testing.T) {
	state := snapshotSyncK8sState()
	t.Cleanup(func() { restoreSyncK8sState(state) })

	directCalled := false
	runK8sSyncDirectFn = func(_ context.Context, _ time.Time, tables []string) error {
		directCalled = true
		if len(tables) != 1 || tables[0] != "k8s_pods" {
			t.Fatalf("unexpected fallback tables: %#v", tables)
		}
		return nil
	}

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAuto))
	t.Setenv(envCLIAPIURL, "http://127.0.0.1:1")
	syncTable = "k8s_pods"
	syncScanAfter = false
	syncValidate = false

	if err := runK8sSync(context.Background(), time.Now()); err != nil {
		t.Fatalf("expected direct fallback success, got error: %v", err)
	}
	if !directCalled {
		t.Fatal("expected direct fallback function to be called")
	}
}

func TestRunK8sSync_AutoModeNoFallbackOnUnauthorized(t *testing.T) {
	state := snapshotSyncK8sState()
	t.Cleanup(func() { restoreSyncK8sState(state) })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": "unauthorized"})
	}))
	defer server.Close()

	directCalled := false
	runK8sSyncDirectFn = func(context.Context, time.Time, []string) error {
		directCalled = true
		return nil
	}

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAuto))
	t.Setenv(envCLIAPIURL, server.URL)
	syncTable = "k8s_pods"
	syncScanAfter = false
	syncValidate = false

	err := runK8sSync(context.Background(), time.Now())
	if err == nil {
		t.Fatal("expected api error")
		return
	}
	if !strings.Contains(err.Error(), "kubernetes sync via api failed") {
		t.Fatalf("unexpected error: %v", err)
	}
	if directCalled {
		t.Fatal("did not expect direct fallback on unauthorized response")
	}
}

func TestRunK8sSync_APIModeConfigError(t *testing.T) {
	state := snapshotSyncK8sState()
	t.Cleanup(func() { restoreSyncK8sState(state) })

	runK8sSyncDirectFn = func(context.Context, time.Time, []string) error {
		t.Fatal("did not expect direct fallback in api mode config error path")
		return nil
	}

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAPI))
	t.Setenv(envCLIAPIURL, "://bad-url")
	syncValidate = false
	syncScanAfter = false

	if err := runK8sSync(context.Background(), time.Now()); err == nil {
		t.Fatal("expected api mode config error")
		return
	}
}
