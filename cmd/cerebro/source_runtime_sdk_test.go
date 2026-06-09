package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
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
