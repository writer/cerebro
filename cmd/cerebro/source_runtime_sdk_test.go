package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestParseSourceRuntimeSDKNewArgs(t *testing.T) {
	request, err := parseSourceRuntimeSDKNewArgs([]string{
		"demo_source",
		"auth_model=api_token",
		"asset_schemas=host,repository",
		"finding_schemas=vulnerability",
		"freshness_expectation=4h",
		"failure_modes=auth_error,rate_limit",
		"health_path=/readyz",
		"output_dir=/tmp/demo",
		"dry_run=true",
		"force=true",
	})
	if err != nil {
		t.Fatalf("parseSourceRuntimeSDKNewArgs() error = %v", err)
	}
	if request.SourceID != "demo_source" || request.AuthModel != "api_token" || request.FreshnessExpectation != "4h" {
		t.Fatalf("request = %#v", request)
	}
	if len(request.AssetSchemas) != 2 || request.AssetSchemas[0] != "host" || request.AssetSchemas[1] != "repository" {
		t.Fatalf("AssetSchemas = %#v", request.AssetSchemas)
	}
	if len(request.FailureModes) != 2 || request.FailureModes[1] != "rate_limit" {
		t.Fatalf("FailureModes = %#v", request.FailureModes)
	}
	if !request.DryRun || !request.Force {
		t.Fatalf("DryRun/Force = %v/%v, want true/true", request.DryRun, request.Force)
	}
}

func TestParseSourceRuntimeSDKNewArgsCatalogDefinition(t *testing.T) {
	request, err := parseSourceRuntimeSDKNewArgs([]string{
		"jumpcloud",
		"catalog=true",
		"dry_run=true",
	})
	if err != nil {
		t.Fatalf("parseSourceRuntimeSDKNewArgs() error = %v", err)
	}
	if request.SourceID != "jumpcloud" || !request.CatalogDefinition || !request.DryRun {
		t.Fatalf("request = %#v, want catalog dry-run for jumpcloud", request)
	}
}

func TestParseSourceRuntimeSDKNewArgsRequiresKeyValue(t *testing.T) {
	_, err := parseSourceRuntimeSDKNewArgs([]string{"demo_source", "not-key-value"})
	if err == nil {
		t.Fatal("parseSourceRuntimeSDKNewArgs() error = nil, want error")
	}
}

func TestParseSourceRuntimeSDKNewArgsRejectsBadArguments(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "missing source id", args: nil},
		{name: "empty key", args: []string{"demo_source", "=value"}},
		{name: "unknown key", args: []string{"demo_source", "asset_schema=host"}},
		{name: "bad dry run bool", args: []string{"demo_source", "dry_run=maybe"}},
		{name: "bad force bool", args: []string{"demo_source", "force=maybe"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseSourceRuntimeSDKNewArgs(test.args); err == nil {
				t.Fatal("parseSourceRuntimeSDKNewArgs() error = nil, want error")
			}
		})
	}
}

func TestRunSourceRuntimeSDKRequiresSubcommand(t *testing.T) {
	err := runSourceRuntimeSDK(nil)
	var usage usageError
	if !errors.As(err, &usage) {
		t.Fatalf("runSourceRuntimeSDK(nil) error = %v, want usageError", err)
	}
}

func TestRunSourceRuntimeSDKDryRunThroughSourceRuntimeCommand(t *testing.T) {
	stdout := captureCommandStdout(t, func() {
		err := runSourceRuntime([]string{"sdk", "new", "demo_source", "asset_schemas=host", "dry_run=true"})
		if err != nil {
			t.Fatalf("runSourceRuntime sdk dry-run error = %v", err)
		}
	})
	var payload struct {
		SourceID string   `json:"source_id"`
		DryRun   bool     `json:"dry_run"`
		Files    []string `json:"files"`
	}
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("unmarshal dry-run output: %v\n%s", err, stdout)
	}
	if payload.SourceID != "demo_source" || !payload.DryRun || len(payload.Files) == 0 {
		t.Fatalf("dry-run payload = %#v", payload)
	}
}

func TestRunSourceRuntimeSDKNewFromDefinitionDryRun(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "definition.json")
	payload := []byte(`{
		"schema_version": "cerebro.integration/v1",
		"id": "tenant-a-example_idp",
		"tenant_id": "tenant-a",
		"source_id": "example_idp",
		"display_name": "Example IDP",
		"auth": {
			"model": "bearer_token",
			"credential_fields": [{"key": "token", "secret": true, "reference_only": true}]
		},
		"transport": {
			"base_url": "https://api.example.test",
			"verification": {"path": "/v1/me"}
		},
		"resource_families": [{
			"id": "users",
			"path": "/v1/users",
			"record_selector": "$.data[*]",
			"id_field": "id",
			"event": {"kind": "example_idp.user", "schema_ref": "example_idp/user/v1"},
			"projection": {"template": "identity_user"},
			"coverage": [{"type": "entity_family", "support": "supported"}]
		}]
	}`)
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("write definition: %v", err)
	}
	stdout := captureCommandStdout(t, func() {
		err := runSourceRuntime([]string{"sdk", "new", "example_idp", "definition=" + path, "dry_run=true"})
		if err != nil {
			t.Fatalf("runSourceRuntime sdk new definition dry-run error = %v", err)
		}
	})
	var result struct {
		SourceID  string   `json:"source_id"`
		AuthModel string   `json:"auth_model"`
		DryRun    bool     `json:"dry_run"`
		Files     []string `json:"files"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("unmarshal definition dry-run output: %v\n%s", err, stdout)
	}
	if result.SourceID != "example_idp" || result.AuthModel != "bearer_token" || !result.DryRun || len(result.Files) == 0 {
		t.Fatalf("definition dry-run result = %#v", result)
	}
}

func TestRunSourceRuntimeSDKPlanFromDefinition(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "definition.json")
	payload := []byte(`{
		"schema_version": "cerebro.integration/v1",
		"id": "tenant-a-example_idp",
		"tenant_id": "tenant-a",
		"source_id": "example_idp",
		"display_name": "Example IDP",
		"auth": {
			"model": "bearer_token",
			"credential_fields": [{"key": "token", "secret": true, "reference_only": true}]
		},
		"transport": {
			"base_url": "https://api.example.test",
			"verification": {"path": "/v1/me"}
		},
		"resource_families": [{
			"id": "users",
			"path": "/v1/users",
			"record_selector": "$.data[*]",
			"id_field": "id",
			"event": {"kind": "example_idp.user", "schema_ref": "example_idp/user/v1"},
			"projection": {"template": "identity_user"},
			"coverage": [{"type": "entity_family", "support": "supported"}]
		}]
	}`)
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("write definition: %v", err)
	}
	stdout := captureCommandStdout(t, func() {
		err := runSourceRuntime([]string{"sdk", "plan", path, "freshness_expectation=2h", "output_dir=" + dir})
		if err != nil {
			t.Fatalf("runSourceRuntime sdk plan error = %v", err)
		}
	})
	var plan struct {
		Status    string `json:"status"`
		NextStage string `json:"next_stage"`
		Scaffold  struct {
			SourceID string   `json:"source_id"`
			Files    []string `json:"files"`
		} `json:"scaffold"`
	}
	if err := json.Unmarshal([]byte(stdout), &plan); err != nil {
		t.Fatalf("unmarshal plan output: %v\n%s", err, stdout)
	}
	if plan.Status != "ready" || plan.NextStage != "sandbox" || plan.Scaffold.SourceID != "example_idp" || len(plan.Scaffold.Files) == 0 {
		t.Fatalf("plan = %#v, want ready example_idp scaffold", plan)
	}
}

func TestRunSourceRuntimeSDKNewFromDefinitionComparesNormalizedSourceID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "definition.json")
	payload := []byte(`{
		"schema_version": "cerebro.integration/v1",
		"id": "tenant-a-example_idp",
		"tenant_id": "tenant-a",
		"source_id": "Example IDP",
		"display_name": "Example IDP",
		"auth": {
			"model": "bearer_token",
			"credential_fields": [{"key": "token", "secret": true, "reference_only": true}]
		},
		"transport": {
			"base_url": "https://api.example.test",
			"verification": {"path": "/v1/me"}
		},
		"resource_families": [{
			"id": "users",
			"path": "/v1/users",
			"record_selector": "$.data[*]",
			"id_field": "id",
			"event": {"kind": "example_idp.user", "schema_ref": "example_idp/user/v1"},
			"projection": {"template": "identity_user"},
			"coverage": [{"type": "entity_family", "support": "supported"}]
		}]
	}`)
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("write definition: %v", err)
	}
	stdout := captureCommandStdout(t, func() {
		err := runSourceRuntime([]string{"sdk", "new", "example_idp", "definition=" + path, "dry_run=true"})
		if err != nil {
			t.Fatalf("runSourceRuntime sdk new definition dry-run error = %v", err)
		}
	})
	var result struct {
		SourceID string `json:"source_id"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("unmarshal definition dry-run output: %v\n%s", err, stdout)
	}
	if result.SourceID != "example_idp" {
		t.Fatalf("SourceID = %q, want example_idp", result.SourceID)
	}
}

func TestRunSourceRuntimeSDKNewFromBuiltinCatalogDryRun(t *testing.T) {
	stdout := captureCommandStdout(t, func() {
		err := runSourceRuntime([]string{"sdk", "new", "jumpcloud", "catalog=true", "dry_run=true"})
		if err != nil {
			t.Fatalf("runSourceRuntime sdk new catalog dry-run error = %v", err)
		}
	})
	var result struct {
		SourceID  string   `json:"source_id"`
		AuthModel string   `json:"auth_model"`
		DryRun    bool     `json:"dry_run"`
		Files     []string `json:"files"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("unmarshal catalog dry-run output: %v\n%s", err, stdout)
	}
	if result.SourceID != "jumpcloud" || result.AuthModel != "api_key" || !result.DryRun || len(result.Files) == 0 {
		t.Fatalf("catalog dry-run result = %#v", result)
	}
}

func TestRunSourceRuntimeSDKNewRejectsCatalogAndDefinition(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "definition.json")
	if err := os.WriteFile(path, []byte(`{"source_id":"jumpcloud"}`), 0o600); err != nil {
		t.Fatalf("write definition: %v", err)
	}
	err := runSourceRuntime([]string{"sdk", "new", "jumpcloud", "catalog=true", "definition=" + path, "dry_run=true"})
	if err == nil {
		t.Fatal("runSourceRuntime sdk new catalog+definition error = nil, want error")
	}
	if got := err.Error(); got != "catalog=true cannot be combined with definition" {
		t.Fatalf("error = %q, want catalog/definition conflict", got)
	}
}

func TestRunSourceRuntimeSDKClassify(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "definition.json")
	payload := []byte(`{
		"schema_version": "cerebro.integration/v1",
		"id": "example",
		"tenant_id": "tenant-a",
		"source_id": "example",
		"display_name": "Example",
		"auth": {
			"model": "bearer_token",
			"credential_fields": [{"key": "token", "secret": true, "reference_only": true}]
		},
		"transport": {
			"base_url": "https://api.example.test",
			"verification": {"path": "/v1/me"}
		},
		"resource_families": [{
			"id": "users",
			"path": "/v1/users",
			"record_selector": "$.data[*]",
			"id_field": "id",
			"event": {"kind": "example.user", "schema_ref": "example/user/v1"},
			"pagination": {"type": "cursor"},
			"projection": {"template": "identity_user"},
			"coverage": [{"type": "entity_family", "support": "supported"}]
		}]
	}`)
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("write definition: %v", err)
	}
	stdout := captureCommandStdout(t, func() {
		err := runSourceRuntime([]string{"sdk", "classify", path})
		if err != nil {
			t.Fatalf("runSourceRuntime sdk classify error = %v", err)
		}
	})
	var report struct {
		Verdict  string `json:"verdict"`
		SourceID string `json:"source_id"`
	}
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("unmarshal classify output: %v\n%s", err, stdout)
	}
	if report.SourceID != "example" || report.Verdict != "supported" {
		t.Fatalf("classify report = %#v", report)
	}
}

func captureCommandStdout(t *testing.T, fn func()) string {
	t.Helper()
	oldStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe stdout: %v", err)
	}
	os.Stdout = writer
	defer func() {
		os.Stdout = oldStdout
	}()
	fn()
	if err := writer.Close(); err != nil {
		t.Fatalf("close stdout writer: %v", err)
	}
	payload, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	return string(payload)
}
