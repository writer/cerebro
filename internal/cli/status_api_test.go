package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

type statusCLIState struct {
	output string
}

func snapshotStatusCLIState() statusCLIState {
	return statusCLIState{output: statusOutput}
}

func restoreStatusCLIState(state statusCLIState) {
	statusOutput = state.output
}

func TestRunStatus_APIModeJSON(t *testing.T) {
	state := snapshotStatusCLIState()
	t.Cleanup(func() { restoreStatusCLIState(state) })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/admin/health" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer cli-api-key" {
			t.Fatalf("expected authorization header, got %q", got)
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"timestamp": "2026-03-08T16:00:00Z",
			"snowflake": map[string]interface{}{"status": "healthy", "latency_ms": 4},
			"policies":  map[string]interface{}{"loaded": 9, "path": "policies"},
			"findings":  map[string]interface{}{"total": 11, "open": 7, "critical": 2, "high": 3},
			"agents":    map[string]interface{}{"registered": 4},
			"providers": map[string]interface{}{"registered": 5},
		})
	}))
	defer server.Close()

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAPI))
	t.Setenv(envCLIAPIURL, server.URL)
	t.Setenv(envCLIAPIKey, "cli-api-key")

	statusOutput = FormatJSON
	output := captureStdout(t, func() {
		if err := runStatus(statusCmd, nil); err != nil {
			t.Fatalf("runStatus failed: %v", err)
		}
	})

	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(output), &payload); err != nil {
		t.Fatalf("decode output: %v (output=%s)", err, output)
	}
	if payload["version"] != Version {
		t.Fatalf("expected version %q, got %#v", Version, payload["version"])
	}
	snowflake, ok := payload["snowflake"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected snowflake object, got %#v", payload["snowflake"])
	}
	if snowflake["status"] != "healthy" {
		t.Fatalf("expected healthy status, got %#v", snowflake["status"])
	}
}

func TestRunStatus_AutoModeFallbacksToDirectOnTransportError(t *testing.T) {
	state := snapshotStatusCLIState()
	t.Cleanup(func() { restoreStatusCLIState(state) })

	originalDirectFn := runStatusDirectFn
	t.Cleanup(func() { runStatusDirectFn = originalDirectFn })

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAuto))
	t.Setenv(envCLIAPIURL, "http://127.0.0.1:1")

	called := false
	runStatusDirectFn = func(cmd *cobra.Command, args []string) error {
		called = true
		return nil
	}

	if err := runStatus(statusCmd, nil); err != nil {
		t.Fatalf("expected direct fallback success, got error: %v", err)
	}
	if !called {
		t.Fatal("expected direct fallback function to be called")
	}
}

func TestRunStatus_AutoModeDoesNotFallbackOnUnauthorized(t *testing.T) {
	state := snapshotStatusCLIState()
	t.Cleanup(func() { restoreStatusCLIState(state) })

	originalDirectFn := runStatusDirectFn
	t.Cleanup(func() { runStatusDirectFn = originalDirectFn })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized","code":"unauthorized"}`))
	}))
	defer server.Close()

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAuto))
	t.Setenv(envCLIAPIURL, server.URL)

	called := false
	runStatusDirectFn = func(cmd *cobra.Command, args []string) error {
		called = true
		return nil
	}

	err := runStatus(statusCmd, nil)
	if err == nil {
		t.Fatal("expected error when API responds unauthorized")
		return
	}
	if !strings.Contains(err.Error(), "status via api failed") {
		t.Fatalf("expected api failure context, got %v", err)
	}
	if called {
		t.Fatal("did not expect direct fallback on unauthorized response")
	}
}
