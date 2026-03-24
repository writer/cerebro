package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRunPolicyDiff_JSONWithDryRunAssets(t *testing.T) {
	t.Setenv(envCLIExecutionMode, string(cliExecutionModeDirect))

	workDir := t.TempDir()
	policiesDir := filepath.Join(workDir, "policies")
	if err := os.MkdirAll(policiesDir, 0o755); err != nil {
		t.Fatalf("mkdir policies dir: %v", err)
	}
	policyPath := filepath.Join(policiesDir, "policy.json")
	candidatePath := filepath.Join(workDir, "candidate.json")
	assetsPath := filepath.Join(workDir, "assets.json")

	currentPolicy := `{
		"id": "policy-diff",
		"name": "Current",
		"description": "current",
		"effect": "forbid",
		"resource": "aws::s3::bucket",
		"conditions": ["resource.public == true"],
		"severity": "high"
	}`
	candidatePolicy := `{
		"id": "policy-diff",
		"name": "Candidate",
		"description": "candidate",
		"effect": "forbid",
		"resource": "aws::s3::bucket",
		"conditions": ["resource.public == false"],
		"severity": "high"
	}`
	assetsFixture := `[
		{"_cq_id":"bucket-a","_cq_table":"aws_s3_buckets","public":true},
		{"_cq_id":"bucket-b","_cq_table":"aws_s3_buckets","public":false}
	]`

	if err := os.WriteFile(policyPath, []byte(currentPolicy), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	if err := os.WriteFile(candidatePath, []byte(candidatePolicy), 0o644); err != nil {
		t.Fatalf("write candidate: %v", err)
	}
	if err := os.WriteFile(assetsPath, []byte(assetsFixture), 0o644); err != nil {
		t.Fatalf("write assets: %v", err)
	}

	t.Setenv("POLICIES_PATH", policiesDir)

	prevOutput := policyDiffOutput
	prevAssets := policyDiffAssetFile
	t.Cleanup(func() {
		policyDiffOutput = prevOutput
		policyDiffAssetFile = prevAssets
	})

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
	impact, ok := payload["impact"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected impact object, got %T", payload["impact"])
	}
	if impact["before_matches"].(float64) != 1 {
		t.Fatalf("expected before_matches=1, got %v", impact["before_matches"])
	}
	if impact["after_matches"].(float64) != 1 {
		t.Fatalf("expected after_matches=1, got %v", impact["after_matches"])
	}
}
