package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

type findingsCLIState struct {
	severity   string
	status     string
	policyID   string
	limit      int
	output     string
	exportFmt  string
	exportFile string
	pretty     bool
	useColor   bool
}

func snapshotFindingsCLIState() findingsCLIState {
	return findingsCLIState{
		severity:   findingsSeverity,
		status:     findingsStatus,
		policyID:   findingsPolicyID,
		limit:      findingsLimit,
		output:     findingsOutput,
		exportFmt:  findingsExportFmt,
		exportFile: findingsExportFile,
		pretty:     findingsPretty,
		useColor:   useColor,
	}
}

func restoreFindingsCLIState(state findingsCLIState) {
	findingsSeverity = state.severity
	findingsStatus = state.status
	findingsPolicyID = state.policyID
	findingsLimit = state.limit
	findingsOutput = state.output
	findingsExportFmt = state.exportFmt
	findingsExportFile = state.exportFile
	findingsPretty = state.pretty
	useColor = state.useColor
}

func TestRunFindingsList_APIModeJSON(t *testing.T) {
	state := snapshotFindingsCLIState()
	t.Cleanup(func() { restoreFindingsCLIState(state) })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/findings/" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer cli-api-key" {
			t.Fatalf("expected authorization header, got %q", got)
		}
		if got := r.URL.Query().Get("status"); got != "OPEN" {
			t.Fatalf("expected status query filter, got %q", got)
		}
		if got := r.URL.Query().Get("limit"); got != "2" {
			t.Fatalf("expected limit query filter, got %q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"findings": []map[string]interface{}{
				{
					"id":          "finding-a",
					"policy_id":   "policy-a",
					"resource_id": "resource-a",
					"severity":    "high",
					"status":      "OPEN",
				},
			},
			"count": 1,
		})
	}))
	defer server.Close()

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAPI))
	t.Setenv(envCLIAPIURL, server.URL)
	t.Setenv(envCLIAPIKey, "cli-api-key")
	useColor = false
	findingsStatus = "OPEN"
	findingsLimit = 2
	findingsOutput = FormatJSON
	findingsSeverity = ""
	findingsPolicyID = ""

	output := captureStdout(t, func() {
		if err := runFindingsList(findingsListCmd, nil); err != nil {
			t.Fatalf("runFindingsList failed: %v", err)
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

func TestRunFindingsResolve_APIMode(t *testing.T) {
	state := snapshotFindingsCLIState()
	t.Cleanup(func() { restoreFindingsCLIState(state) })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/findings/finding-1/resolve" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"status":"resolved"}`))
	}))
	defer server.Close()

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAPI))
	t.Setenv(envCLIAPIURL, server.URL)
	useColor = false

	output := captureStdout(t, func() {
		if err := runFindingsResolve(findingsResolveCmd, []string{"finding-1"}); err != nil {
			t.Fatalf("runFindingsResolve failed: %v", err)
		}
	})

	if !strings.Contains(output, "marked as resolved") {
		t.Fatalf("unexpected resolve output: %q", output)
	}
}

func TestRunFindingsList_AutoFallbacksToDirectOnTransportError(t *testing.T) {
	state := snapshotFindingsCLIState()
	t.Cleanup(func() { restoreFindingsCLIState(state) })

	originalDirectFn := runFindingsListDirectFn
	t.Cleanup(func() { runFindingsListDirectFn = originalDirectFn })

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAuto))
	t.Setenv(envCLIAPIURL, "http://127.0.0.1:1")
	useColor = false

	called := false
	runFindingsListDirectFn = func(cmd *cobra.Command, args []string) error {
		called = true
		return nil
	}

	if err := runFindingsList(findingsListCmd, nil); err != nil {
		t.Fatalf("expected direct fallback success, got error: %v", err)
	}
	if !called {
		t.Fatal("expected direct fallback function to be called")
	}
}

func TestRunFindingsList_AutoModeDoesNotFallbackOnUnauthorized(t *testing.T) {
	state := snapshotFindingsCLIState()
	t.Cleanup(func() { restoreFindingsCLIState(state) })

	originalDirectFn := runFindingsListDirectFn
	t.Cleanup(func() { runFindingsListDirectFn = originalDirectFn })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized","code":"unauthorized"}`))
	}))
	defer server.Close()

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAuto))
	t.Setenv(envCLIAPIURL, server.URL)
	useColor = false

	called := false
	runFindingsListDirectFn = func(cmd *cobra.Command, args []string) error {
		called = true
		return nil
	}

	err := runFindingsList(findingsListCmd, nil)
	if err == nil {
		t.Fatal("expected error when API responds unauthorized")
		return
	}
	if called {
		t.Fatal("did not expect direct fallback on unauthorized response")
	}
}

func TestRunFindingsExport_APIModeWritesFile(t *testing.T) {
	state := snapshotFindingsCLIState()
	t.Cleanup(func() { restoreFindingsCLIState(state) })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/findings/export" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "text/csv")
		_, _ = w.Write([]byte("ID,Severity\nfinding-1,high\n"))
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "findings.csv")

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAPI))
	t.Setenv(envCLIAPIURL, server.URL)
	useColor = false
	findingsExportFmt = "csv"
	findingsExportFile = outputFile

	if err := runFindingsExport(findingsExportCmd, nil); err != nil {
		t.Fatalf("runFindingsExport failed: %v", err)
	}

	data, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("read export file: %v", err)
	}
	if string(data) != "ID,Severity\nfinding-1,high\n" {
		t.Fatalf("unexpected export file payload: %s", string(data))
	}
}
