package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunPolicyConvert_JSONOutput(t *testing.T) {
	stateOutput := policyConvertOutput
	stateWrite := policyConvertWrite
	t.Cleanup(func() {
		policyConvertOutput = stateOutput
		policyConvertWrite = stateWrite
	})

	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(policyPath, []byte(`{
  "id": "legacy-policy",
  "name": "Legacy Policy",
  "description": "test",
  "severity": "high",
  "effect": "forbid",
  "resource": "aws::s3::bucket",
  "conditions": ["public == true"]
}`), 0644); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	policyConvertOutput = FormatJSON
	policyConvertWrite = false

	output := captureStdout(t, func() {
		if err := runPolicyConvert(policyConvertCmd, []string{policyPath}); err != nil {
			t.Fatalf("runPolicyConvert failed: %v", err)
		}
	})

	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(output), &payload); err != nil {
		t.Fatalf("parse converted json: %v\noutput=%s", err, output)
	}
	if payload["condition_format"] != "cel" {
		t.Fatalf("expected condition_format cel, got %v", payload["condition_format"])
	}
	conditions, ok := payload["conditions"].([]interface{})
	if !ok || len(conditions) != 1 {
		t.Fatalf("expected one converted condition, got %T %#v", payload["conditions"], payload["conditions"])
	}
	if strings.Contains(conditions[0].(string), "public == true") {
		t.Fatalf("expected converted CEL condition, got %q", conditions[0].(string))
	}
}

func TestRunPolicyConvert_WriteInPlace(t *testing.T) {
	stateOutput := policyConvertOutput
	stateWrite := policyConvertWrite
	t.Cleanup(func() {
		policyConvertOutput = stateOutput
		policyConvertWrite = stateWrite
	})

	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(policyPath, []byte(`{
  "id": "legacy-policy",
  "name": "Legacy Policy",
  "description": "test",
  "severity": "high",
  "effect": "forbid",
  "resource": "aws::s3::bucket",
  "conditions": ["metadata.annotations['missing'] not exists"]
}`), 0644); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	policyConvertOutput = FormatJSON
	policyConvertWrite = true

	output := captureStdout(t, func() {
		if err := runPolicyConvert(policyConvertCmd, []string{policyPath}); err != nil {
			t.Fatalf("runPolicyConvert failed: %v", err)
		}
	})

	var response map[string]interface{}
	if err := json.Unmarshal([]byte(output), &response); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if response["written_in_place"] != true {
		t.Fatalf("expected written_in_place true, got %v", response["written_in_place"])
	}

	updated, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatalf("read rewritten file: %v", err)
	}
	if !strings.Contains(string(updated), `"condition_format": "cel"`) {
		t.Fatalf("expected rewritten file to contain CEL condition_format, got %s", string(updated))
	}
}
