package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
)

type policyDiffCLIState struct {
	output string
	assets string
}

func snapshotPolicyDiffCLIState() policyDiffCLIState {
	return policyDiffCLIState{
		output: policyDiffOutput,
		assets: policyDiffAssetFile,
	}
}

func restorePolicyDiffCLIState(state policyDiffCLIState) {
	policyDiffOutput = state.output
	policyDiffAssetFile = state.assets
}

func TestRunPolicyDiff_APIModeJSON(t *testing.T) {
	state := snapshotPolicyDiffCLIState()
	t.Cleanup(func() { restorePolicyDiffCLIState(state) })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/policies/policy-diff/dry-run" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"dry_run":      true,
			"policy_id":    "policy-diff",
			"asset_source": "request",
			"diff": map[string]interface{}{
				"changed": true,
				"field_diffs": []map[string]interface{}{
					{"field": "conditions", "before": []string{"a"}, "after": []string{"b"}},
				},
			},
			"impact": map[string]interface{}{
				"asset_count":         1,
				"before_matches":      1,
				"after_matches":       1,
				"added_finding_ids":   []string{},
				"removed_finding_ids": []string{},
				"new_findings":        []map[string]interface{}{},
			},
		})
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	candidatePath := filepath.Join(tmpDir, "candidate.json")
	assetsPath := filepath.Join(tmpDir, "assets.json")
	if err := os.WriteFile(candidatePath, []byte(`{
		"id":"policy-diff",
		"name":"Candidate",
		"effect":"forbid",
		"resource":"aws::s3::bucket",
		"conditions":["public == false"],
		"severity":"high"
	}`), 0o600); err != nil {
		t.Fatalf("write candidate policy: %v", err)
	}
	if err := os.WriteFile(assetsPath, []byte(`[{"_cq_id":"bucket-a","_cq_table":"aws_s3_buckets"}]`), 0o600); err != nil {
		t.Fatalf("write assets fixture: %v", err)
	}

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAPI))
	t.Setenv(envCLIAPIURL, server.URL)
	policyDiffOutput = FormatJSON
	policyDiffAssetFile = assetsPath

	output := captureStdout(t, func() {
		if err := runPolicyDiff(policyDiffCmd, []string{"policy-diff", candidatePath}); err != nil {
			t.Fatalf("runPolicyDiff failed: %v", err)
		}
	})

	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(output), &payload); err != nil {
		t.Fatalf("decode output: %v (output=%s)", err, output)
	}
	if payload["changed"] != true {
		t.Fatalf("expected changed=true, got %v", payload["changed"])
	}
	if payload["assets_file"] != assetsPath {
		t.Fatalf("expected assets_file=%q, got %v", assetsPath, payload["assets_file"])
	}
}

func TestRunPolicyDiff_AutoFallbacksToDirectOnTransportError(t *testing.T) {
	state := snapshotPolicyDiffCLIState()
	t.Cleanup(func() { restorePolicyDiffCLIState(state) })

	originalDirectFn := runPolicyDiffDirectFn
	t.Cleanup(func() { runPolicyDiffDirectFn = originalDirectFn })

	tmpDir := t.TempDir()
	candidatePath := filepath.Join(tmpDir, "candidate.json")
	if err := os.WriteFile(candidatePath, []byte(`{"id":"policy-diff","name":"Candidate","effect":"forbid","resource":"aws::s3::bucket","conditions":["public == false"],"severity":"high"}`), 0o600); err != nil {
		t.Fatalf("write candidate policy: %v", err)
	}

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAuto))
	t.Setenv(envCLIAPIURL, "http://127.0.0.1:1")

	called := false
	runPolicyDiffDirectFn = func(cmd *cobra.Command, args []string) error {
		called = true
		return nil
	}

	if err := runPolicyDiff(policyDiffCmd, []string{"policy-diff", candidatePath}); err != nil {
		t.Fatalf("expected direct fallback success, got error: %v", err)
	}
	if !called {
		t.Fatal("expected direct fallback function to be called")
	}
}

func TestRunPolicyDiff_AutoModeDoesNotFallbackOnUnauthorized(t *testing.T) {
	state := snapshotPolicyDiffCLIState()
	t.Cleanup(func() { restorePolicyDiffCLIState(state) })

	originalDirectFn := runPolicyDiffDirectFn
	t.Cleanup(func() { runPolicyDiffDirectFn = originalDirectFn })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized","code":"unauthorized"}`))
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	candidatePath := filepath.Join(tmpDir, "candidate.json")
	if err := os.WriteFile(candidatePath, []byte(`{"id":"policy-diff","name":"Candidate","effect":"forbid","resource":"aws::s3::bucket","conditions":["public == false"],"severity":"high"}`), 0o600); err != nil {
		t.Fatalf("write candidate policy: %v", err)
	}

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAuto))
	t.Setenv(envCLIAPIURL, server.URL)

	called := false
	runPolicyDiffDirectFn = func(cmd *cobra.Command, args []string) error {
		called = true
		return nil
	}

	err := runPolicyDiff(policyDiffCmd, []string{"policy-diff", candidatePath})
	if err == nil {
		t.Fatal("expected error when API responds unauthorized")
		return
	}
	if called {
		t.Fatal("did not expect direct fallback on unauthorized response")
	}
}
