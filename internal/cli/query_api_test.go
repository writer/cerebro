package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

type queryCLIState struct {
	format string
	limit  int
}

func snapshotQueryCLIState() queryCLIState {
	return queryCLIState{
		format: queryFormat,
		limit:  queryLimit,
	}
}

func restoreQueryCLIState(state queryCLIState) {
	queryFormat = state.format
	queryLimit = state.limit
}

func TestRunQuery_APIModeJSON(t *testing.T) {
	state := snapshotQueryCLIState()
	t.Cleanup(func() { restoreQueryCLIState(state) })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/query" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer cli-api-key" {
			t.Fatalf("expected authorization header, got %q", got)
		}

		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		if req["query"] != "SELECT * FROM aws_s3_buckets" {
			t.Fatalf("unexpected query payload: %#v", req["query"])
		}
		if req["limit"] != float64(25) {
			t.Fatalf("expected limit=25, got %#v", req["limit"])
		}
		if req["timeout_seconds"] != float64(60) {
			t.Fatalf("expected timeout_seconds=60, got %#v", req["timeout_seconds"])
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"columns": []string{"name"},
			"rows": []map[string]interface{}{
				{"name": "bucket-a"},
			},
			"count": 1,
		})
	}))
	defer server.Close()

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAPI))
	t.Setenv(envCLIAPIURL, server.URL)
	t.Setenv(envCLIAPIKey, "cli-api-key")

	queryFormat = FormatJSON
	queryLimit = 25

	output := captureStdout(t, func() {
		if err := runQuery(queryCmd, []string{"SELECT * FROM aws_s3_buckets"}); err != nil {
			t.Fatalf("runQuery failed: %v", err)
		}
	})

	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(output), &payload); err != nil {
		t.Fatalf("decode output: %v (output=%s)", err, output)
	}
	if payload["count"].(float64) != 1 {
		t.Fatalf("expected count=1, got %v", payload["count"])
	}
}

func TestRunQuery_AutoModeFallbacksToDirectOnTransportError(t *testing.T) {
	state := snapshotQueryCLIState()
	t.Cleanup(func() { restoreQueryCLIState(state) })

	originalDirectFn := runQueryDirectFn
	t.Cleanup(func() { runQueryDirectFn = originalDirectFn })

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAuto))
	t.Setenv(envCLIAPIURL, "http://127.0.0.1:1")

	queryFormat = FormatJSON
	queryLimit = 10

	called := false
	runQueryDirectFn = func(cmd *cobra.Command, args []string) error {
		called = true
		return nil
	}

	if err := runQuery(queryCmd, []string{"SELECT 1"}); err != nil {
		t.Fatalf("expected direct fallback success, got error: %v", err)
	}
	if !called {
		t.Fatal("expected direct fallback function to be called")
	}
}

func TestRunQuery_AutoModeDoesNotFallbackOnUnauthorized(t *testing.T) {
	state := snapshotQueryCLIState()
	t.Cleanup(func() { restoreQueryCLIState(state) })

	originalDirectFn := runQueryDirectFn
	t.Cleanup(func() { runQueryDirectFn = originalDirectFn })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized","code":"unauthorized"}`))
	}))
	defer server.Close()

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAuto))
	t.Setenv(envCLIAPIURL, server.URL)

	called := false
	runQueryDirectFn = func(cmd *cobra.Command, args []string) error {
		called = true
		return nil
	}

	err := runQuery(queryCmd, []string{"SELECT 1"})
	if err == nil {
		t.Fatal("expected error when API responds unauthorized")
	}
	if !strings.Contains(err.Error(), "query via api failed") {
		t.Fatalf("expected api failure context, got %v", err)
	}
	if called {
		t.Fatal("did not expect direct fallback on unauthorized response")
	}
}
