package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

type policyValidateCLIState struct {
	output   string
	useColor bool
}

func snapshotPolicyValidateCLIState() policyValidateCLIState {
	return policyValidateCLIState{
		output:   policyValidateOutput,
		useColor: useColor,
	}
}

func restorePolicyValidateCLIState(state policyValidateCLIState) {
	policyValidateOutput = state.output
	useColor = state.useColor
}

func TestRunPolicyValidate_APIModeJSON(t *testing.T) {
	state := snapshotPolicyValidateCLIState()
	t.Cleanup(func() { restorePolicyValidateCLIState(state) })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/policies/" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"policies": []map[string]interface{}{
				{
					"id":       "policy-1",
					"name":     "Policy 1",
					"severity": "high",
					"resource": "aws::s3::bucket",
				},
				{
					"id":       "policy-2",
					"name":     "Policy 2",
					"severity": "low",
					"resource": "aws::s3::bucket",
				},
			},
			"count": 2,
		})
	}))
	defer server.Close()

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAPI))
	t.Setenv(envCLIAPIURL, server.URL)
	policyValidateOutput = FormatJSON
	useColor = false

	output := captureStdout(t, func() {
		if err := runPolicyValidate(policyValidateCmd, nil); err != nil {
			t.Fatalf("runPolicyValidate failed: %v", err)
		}
	})

	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(output), &payload); err != nil {
		t.Fatalf("decode output: %v (output=%s)", err, output)
	}
	if valid, _ := payload["valid"].(bool); !valid {
		t.Fatalf("expected valid=true, got %#v", payload["valid"])
	}
	if count, _ := payload["count"].(float64); count != 2 {
		t.Fatalf("expected count=2, got %#v", payload["count"])
	}
	severityCounts, _ := payload["severity_counts"].(map[string]interface{})
	if got := severityCounts["high"]; got != float64(1) {
		t.Fatalf("expected high=1, got %#v", got)
	}
	if got := severityCounts["low"]; got != float64(1) {
		t.Fatalf("expected low=1, got %#v", got)
	}
}

func TestRunPolicyValidate_AutoFallbacksToDirectOnTransportError(t *testing.T) {
	state := snapshotPolicyValidateCLIState()
	t.Cleanup(func() { restorePolicyValidateCLIState(state) })

	originalDirectFn := runPolicyValidateDirectFn
	t.Cleanup(func() { runPolicyValidateDirectFn = originalDirectFn })

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAuto))
	t.Setenv(envCLIAPIURL, "http://127.0.0.1:1")
	useColor = false

	called := false
	runPolicyValidateDirectFn = func(cmd *cobra.Command, args []string) error {
		called = true
		return nil
	}

	if err := runPolicyValidate(policyValidateCmd, nil); err != nil {
		t.Fatalf("expected direct fallback success, got error: %v", err)
	}
	if !called {
		t.Fatal("expected direct fallback function to be called")
	}
}

func TestRunPolicyValidate_AutoModeDoesNotFallbackOnUnauthorized(t *testing.T) {
	state := snapshotPolicyValidateCLIState()
	t.Cleanup(func() { restorePolicyValidateCLIState(state) })

	originalDirectFn := runPolicyValidateDirectFn
	t.Cleanup(func() { runPolicyValidateDirectFn = originalDirectFn })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized","code":"unauthorized"}`))
	}))
	defer server.Close()

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAuto))
	t.Setenv(envCLIAPIURL, server.URL)
	useColor = false

	called := false
	runPolicyValidateDirectFn = func(cmd *cobra.Command, args []string) error {
		called = true
		return nil
	}

	err := runPolicyValidate(policyValidateCmd, nil)
	if err == nil {
		t.Fatal("expected error when API responds unauthorized")
	}
	if !strings.Contains(err.Error(), "policy validate via api failed") {
		t.Fatalf("expected api failure context, got %v", err)
	}
	if called {
		t.Fatal("did not expect direct fallback on unauthorized response")
	}
}
