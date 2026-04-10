package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/spf13/cobra"
)

type policyCLIState struct {
	output   string
	useColor bool
}

func snapshotPolicyCLIState() policyCLIState {
	return policyCLIState{
		output:   policyOutput,
		useColor: useColor,
	}
}

func restorePolicyCLIState(state policyCLIState) {
	policyOutput = state.output
	useColor = state.useColor
}

func TestRunPolicyList_APIModeJSON(t *testing.T) {
	state := snapshotPolicyCLIState()
	t.Cleanup(func() { restorePolicyCLIState(state) })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			},
			"count": 1,
		})
	}))
	defer server.Close()

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAPI))
	t.Setenv(envCLIAPIURL, server.URL)
	policyOutput = FormatJSON
	useColor = false

	output := captureStdout(t, func() {
		if err := runPolicyList(policyListCmd, nil); err != nil {
			t.Fatalf("runPolicyList failed: %v", err)
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

func TestRunPolicyList_AutoFallbacksToDirectOnTransportError(t *testing.T) {
	state := snapshotPolicyCLIState()
	t.Cleanup(func() { restorePolicyCLIState(state) })

	originalDirectFn := runPolicyListDirectFn
	t.Cleanup(func() { runPolicyListDirectFn = originalDirectFn })

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAuto))
	t.Setenv(envCLIAPIURL, "http://127.0.0.1:1")
	useColor = false

	called := false
	runPolicyListDirectFn = func(cmd *cobra.Command, args []string) error {
		called = true
		return nil
	}

	if err := runPolicyList(policyListCmd, nil); err != nil {
		t.Fatalf("expected direct fallback success, got error: %v", err)
	}
	if !called {
		t.Fatal("expected direct fallback function to be called")
	}
}

func TestRunPolicyList_AutoModeDoesNotFallbackOnUnauthorized(t *testing.T) {
	state := snapshotPolicyCLIState()
	t.Cleanup(func() { restorePolicyCLIState(state) })

	originalDirectFn := runPolicyListDirectFn
	t.Cleanup(func() { runPolicyListDirectFn = originalDirectFn })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized","code":"unauthorized"}`))
	}))
	defer server.Close()

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAuto))
	t.Setenv(envCLIAPIURL, server.URL)
	useColor = false

	called := false
	runPolicyListDirectFn = func(cmd *cobra.Command, args []string) error {
		called = true
		return nil
	}

	err := runPolicyList(policyListCmd, nil)
	if err == nil {
		t.Fatal("expected error when API responds unauthorized")
		return
	}
	if called {
		t.Fatal("did not expect direct fallback on unauthorized response")
	}
}
