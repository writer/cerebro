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

type policyTestCLIState struct {
	output string
}

func snapshotPolicyTestCLIState() policyTestCLIState {
	return policyTestCLIState{output: policyTestOutput}
}

func restorePolicyTestCLIState(state policyTestCLIState) {
	policyTestOutput = state.output
}

func writePolicyTestJSONFile(t *testing.T, data string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "asset.json")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("write test json file: %v", err)
	}
	return path
}

func TestRunPolicyTest_APIModeJSON(t *testing.T) {
	state := snapshotPolicyTestCLIState()
	t.Cleanup(func() { restorePolicyTestCLIState(state) })

	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		switch r.URL.Path {
		case "/api/v1/policies/policy-1":
			if r.Method != http.MethodGet {
				t.Fatalf("expected GET, got %s", r.Method)
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"id":       "policy-1",
				"name":     "Policy 1",
				"effect":   "forbid",
				"resource": "aws::s3::bucket",
				"severity": "high",
			})
		case "/api/v1/policies/policy-1/dry-run":
			if r.Method != http.MethodPost {
				t.Fatalf("expected POST, got %s", r.Method)
			}
			var req map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode request body: %v", err)
			}
			if _, ok := req["policy"]; !ok {
				t.Fatalf("expected policy payload, got %#v", req)
			}
			assets, ok := req["assets"].([]interface{})
			if !ok || len(assets) != 1 {
				t.Fatalf("expected one asset payload, got %#v", req["assets"])
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"dry_run":      true,
				"policy_id":    "policy-1",
				"asset_source": "request",
				"diff": map[string]interface{}{
					"changed": false,
				},
				"impact": map[string]interface{}{
					"asset_count":    1,
					"before_matches": 1,
					"after_matches":  1,
				},
			})
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	assetFile := writePolicyTestJSONFile(t, `{"_cq_id":"asset-1","public":true}`)

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAPI))
	t.Setenv(envCLIAPIURL, server.URL)
	policyTestOutput = FormatJSON

	output := captureStdout(t, func() {
		if err := runPolicyTest(policyTestCmd, []string{"policy-1", assetFile}); err != nil {
			t.Fatalf("runPolicyTest failed: %v", err)
		}
	})

	if requestCount != 2 {
		t.Fatalf("expected two API requests, got %d", requestCount)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(output), &payload); err != nil {
		t.Fatalf("decode output: %v (output=%s)", err, output)
	}
	if passed, _ := payload["passed"].(bool); passed {
		t.Fatalf("expected passed=false, got payload %#v", payload)
	}
	violations, ok := payload["violations"].([]interface{})
	if !ok || len(violations) != 1 {
		t.Fatalf("expected one violation, got %#v", payload["violations"])
	}
}

func TestRunPolicyTest_AutoFallbacksToDirectOnTransportError(t *testing.T) {
	state := snapshotPolicyTestCLIState()
	t.Cleanup(func() { restorePolicyTestCLIState(state) })

	originalDirectFn := runPolicyTestDirectFn
	t.Cleanup(func() { runPolicyTestDirectFn = originalDirectFn })

	assetFile := writePolicyTestJSONFile(t, `{"_cq_id":"asset-1"}`)
	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAuto))
	t.Setenv(envCLIAPIURL, "http://127.0.0.1:1")

	called := false
	runPolicyTestDirectFn = func(cmd *cobra.Command, args []string) error {
		called = true
		return nil
	}

	if err := runPolicyTest(policyTestCmd, []string{"policy-1", assetFile}); err != nil {
		t.Fatalf("expected direct fallback success, got error: %v", err)
	}
	if !called {
		t.Fatal("expected direct fallback function to be called")
	}
}

func TestRunPolicyTest_AutoModeDoesNotFallbackOnUnauthorized(t *testing.T) {
	state := snapshotPolicyTestCLIState()
	t.Cleanup(func() { restorePolicyTestCLIState(state) })

	originalDirectFn := runPolicyTestDirectFn
	t.Cleanup(func() { runPolicyTestDirectFn = originalDirectFn })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized","code":"unauthorized"}`))
	}))
	defer server.Close()

	assetFile := writePolicyTestJSONFile(t, `{"_cq_id":"asset-1"}`)
	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAuto))
	t.Setenv(envCLIAPIURL, server.URL)

	called := false
	runPolicyTestDirectFn = func(cmd *cobra.Command, args []string) error {
		called = true
		return nil
	}

	err := runPolicyTest(policyTestCmd, []string{"policy-1", assetFile})
	if err == nil {
		t.Fatal("expected error when API responds unauthorized")
	}
	if !strings.Contains(err.Error(), "policy test via api failed") {
		t.Fatalf("expected api failure context, got %v", err)
	}
	if called {
		t.Fatal("did not expect direct fallback on unauthorized response")
	}
}

func TestRunPolicyTestDirect_FiltersSelectedPolicyOnly(t *testing.T) {
	state := snapshotPolicyTestCLIState()
	t.Cleanup(func() { restorePolicyTestCLIState(state) })

	policiesDir := t.TempDir()
	policyA := `{"id":"policy-target","name":"Target","description":"target policy","effect":"forbid","resource":"aws::s3::bucket","conditions":["resource.public == false"],"severity":"high"}`
	policyB := `{"id":"policy-other","name":"Other","description":"other policy","effect":"forbid","resource":"aws::s3::bucket","conditions":["resource.public == true"],"severity":"high"}`
	if err := os.WriteFile(filepath.Join(policiesDir, "policy-target.json"), []byte(policyA), 0o600); err != nil {
		t.Fatalf("write policy target: %v", err)
	}
	if err := os.WriteFile(filepath.Join(policiesDir, "policy-other.json"), []byte(policyB), 0o600); err != nil {
		t.Fatalf("write policy other: %v", err)
	}

	assetFile := writePolicyTestJSONFile(t, `{"_cq_id":"asset-1","public":true}`)
	t.Setenv("POLICIES_PATH", "")
	t.Setenv("CEDAR_POLICIES_PATH", policiesDir)
	policyTestOutput = FormatJSON

	output := captureStdout(t, func() {
		if err := runPolicyTestDirect(policyTestCmd, []string{"policy-target", assetFile}); err != nil {
			t.Fatalf("runPolicyTestDirect failed: %v", err)
		}
	})

	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(output), &payload); err != nil {
		t.Fatalf("decode output: %v (output=%s)", err, output)
	}
	if passed, _ := payload["passed"].(bool); !passed {
		t.Fatalf("expected selected policy to pass, got payload %#v", payload)
	}
	violations, ok := payload["violations"].([]interface{})
	if !ok || len(violations) != 0 {
		t.Fatalf("expected zero violations for selected policy, got %#v", payload["violations"])
	}
}
