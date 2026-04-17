package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

type syncBackfillState struct {
	batchSize int
	directFn  func(*cobra.Command, []string) error
}

func snapshotSyncBackfillState() syncBackfillState {
	return syncBackfillState{
		batchSize: syncBackfillBatchSize,
		directFn:  runBackfillRelationshipsDirectFn,
	}
}

func restoreSyncBackfillState(state syncBackfillState) {
	syncBackfillBatchSize = state.batchSize
	runBackfillRelationshipsDirectFn = state.directFn
}

func TestRunBackfillRelationships_APIModeSuccess(t *testing.T) {
	state := snapshotSyncBackfillState()
	t.Cleanup(func() { restoreSyncBackfillState(state) })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/sync/backfill-relationships" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req["batch_size"] != float64(321) {
			t.Fatalf("expected batch_size=321, got %#v", req["batch_size"])
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"scanned": 12,
			"updated": 7,
			"deleted": 2,
			"skipped": 3,
		})
	}))
	defer server.Close()

	directCalled := false
	runBackfillRelationshipsDirectFn = func(*cobra.Command, []string) error {
		directCalled = true
		return nil
	}

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAPI))
	t.Setenv(envCLIAPIURL, server.URL)
	syncBackfillBatchSize = 321

	output := captureStdout(t, func() {
		if err := runBackfillRelationships(nil, nil); err != nil {
			t.Fatalf("runBackfillRelationships failed: %v", err)
		}
	})

	if directCalled {
		t.Fatal("did not expect direct fallback in api mode success path")
	}
	if !strings.Contains(output, "scanned 12, updated 7, deleted 2, skipped 3") {
		t.Fatalf("expected summary output, got %q", output)
	}
}

func TestRunBackfillRelationships_AutoModeFallbackOnTransportError(t *testing.T) {
	state := snapshotSyncBackfillState()
	t.Cleanup(func() { restoreSyncBackfillState(state) })

	directCalled := false
	runBackfillRelationshipsDirectFn = func(*cobra.Command, []string) error {
		directCalled = true
		return nil
	}

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAuto))
	t.Setenv(envCLIAPIURL, "http://127.0.0.1:1")
	syncBackfillBatchSize = 100

	if err := runBackfillRelationships(nil, nil); err != nil {
		t.Fatalf("expected direct fallback success, got error: %v", err)
	}
	if !directCalled {
		t.Fatal("expected direct fallback function to be called")
	}
}

func TestRunBackfillRelationships_AutoModeNoFallbackOnUnauthorized(t *testing.T) {
	state := snapshotSyncBackfillState()
	t.Cleanup(func() { restoreSyncBackfillState(state) })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": "unauthorized"})
	}))
	defer server.Close()

	directCalled := false
	runBackfillRelationshipsDirectFn = func(*cobra.Command, []string) error {
		directCalled = true
		return nil
	}

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAuto))
	t.Setenv(envCLIAPIURL, server.URL)
	syncBackfillBatchSize = 100

	err := runBackfillRelationships(nil, nil)
	if err == nil {
		t.Fatal("expected api error")
		return
	}
	if !strings.Contains(err.Error(), "backfill relationship IDs via api failed") {
		t.Fatalf("unexpected error: %v", err)
	}
	if directCalled {
		t.Fatal("did not expect direct fallback on unauthorized response")
	}
}

func TestRenderBackfillRelationshipStats_NilStats(t *testing.T) {
	output := captureStdout(t, func() {
		renderBackfillRelationshipStats(nil)
	})
	if !strings.Contains(output, "scanned 0, updated 0, deleted 0, skipped 0") {
		t.Fatalf("expected zero-valued summary output, got %q", output)
	}
}

func TestRunBackfillRelationshipsDirectFn_IsOverridable(t *testing.T) {
	state := snapshotSyncBackfillState()
	t.Cleanup(func() { restoreSyncBackfillState(state) })

	called := false
	runBackfillRelationshipsDirectFn = func(*cobra.Command, []string) error {
		called = true
		return nil
	}

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeDirect))
	if err := runBackfillRelationships(nil, nil); err != nil {
		t.Fatalf("runBackfillRelationships failed: %v", err)
	}
	if !called {
		t.Fatal("expected direct function override to be called")
	}
}

func TestRunBackfillRelationships_APIModeConfigError(t *testing.T) {
	state := snapshotSyncBackfillState()
	t.Cleanup(func() { restoreSyncBackfillState(state) })

	runBackfillRelationshipsDirectFn = func(*cobra.Command, []string) error {
		t.Fatal("did not expect direct fallback in api mode config error path")
		return nil
	}

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAPI))
	t.Setenv(envCLIAPIURL, "://bad-url")

	if err := runBackfillRelationships(nil, nil); err == nil {
		t.Fatal("expected api mode config error")
		return
	}
}
