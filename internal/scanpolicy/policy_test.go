package scanpolicy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadSupportsYAMLAndHCLPolicies(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "image-policy.yaml"), []byte(`
version: 1
policies:
  - id: image-guardrails
    scan_kinds: [image]
    teams: [platform]
    require_requested_by: true
    requested_by_patterns:
      - "^user:[a-z0-9._-]+$"
    required_metadata: [team, change_ticket]
    allow_dry_run: false
    allow_keep_filesystem: false
`), 0o644); err != nil {
		t.Fatalf("write yaml policy: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "workload-policy.hcl"), []byte(`
version = 1

policy {
  id = "workload-guardrails"
  scan_kinds = ["workload"]
  teams = ["platform"]
  providers = ["aws"]
  required_metadata = ["team"]
  max_concurrent_snapshots = 2
}
`), 0o644); err != nil {
		t.Fatalf("write hcl policy: %v", err)
	}

	engine, err := Load(dir)
	if err != nil {
		t.Fatalf("load policies: %v", err)
	}

	if err := engine.Validate(Request{
		Kind:        KindImage,
		Team:        "platform",
		RequestedBy: "user:alice",
		Metadata: map[string]string{
			"team":          "platform",
			"change_ticket": "SEC-123",
		},
	}); err != nil {
		t.Fatalf("expected image request to pass loaded policies, got %v", err)
	}

	err = engine.Validate(Request{
		Kind:                   KindWorkload,
		Team:                   "platform",
		Provider:               "aws",
		RequestedBy:            "user:alice",
		MaxConcurrentSnapshots: 4,
		Metadata: map[string]string{
			"team": "platform",
		},
	})
	if err == nil {
		t.Fatal("expected workload policy violation")
	}

	var validationErr *ValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("expected validation error, got %T", err)
	}
	if len(validationErr.Violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(validationErr.Violations))
	}
	if validationErr.Violations[0].PolicyID != "workload-guardrails" {
		t.Fatalf("expected workload policy id, got %#v", validationErr.Violations[0])
	}
	if validationErr.Violations[0].Field != "max_concurrent_snapshots" {
		t.Fatalf("expected max_concurrent_snapshots violation, got %#v", validationErr.Violations[0])
	}
}

func TestEngineValidateReportsStructuredViolations(t *testing.T) {
	allowDryRun := false
	allowKeepFilesystem := false
	engine, err := NewEngine([]Policy{{
		ID:                  "platform-image-policy",
		ScanKinds:           []Kind{KindImage},
		Teams:               []string{"platform"},
		RequireRequestedBy:  true,
		RequestedByPatterns: []string{`^user:[a-z0-9._-]+$`},
		RequiredMetadata:    []string{"team", "change_ticket"},
		AllowDryRun:         &allowDryRun,
		AllowKeepFilesystem: &allowKeepFilesystem,
	}})
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	err = engine.Validate(Request{
		Kind:           KindImage,
		Team:           "platform",
		DryRun:         true,
		KeepFilesystem: true,
		Metadata: map[string]string{
			"team": "platform",
		},
	})
	if err == nil {
		t.Fatal("expected validation error")
	}

	var validationErr *ValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("expected validation error, got %T", err)
	}
	if len(validationErr.Violations) != 4 {
		t.Fatalf("expected 4 violations, got %d", len(validationErr.Violations))
	}
	if got := validationErr.Error(); !strings.Contains(got, "platform-image-policy") || !strings.Contains(got, "requested_by") {
		t.Fatalf("expected formatted error to include policy and field details, got %q", got)
	}
}

func TestEngineValidateSkipsNonMatchingPolicies(t *testing.T) {
	allowDryRun := false
	engine, err := NewEngine([]Policy{{
		ID:          "payments-workload-policy",
		ScanKinds:   []Kind{KindWorkload},
		Teams:       []string{"payments"},
		Providers:   []string{"aws"},
		AllowDryRun: &allowDryRun,
	}})
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	if err := engine.Validate(Request{
		Kind:     KindImage,
		Team:     "platform",
		Provider: "aws",
		DryRun:   true,
		Metadata: map[string]string{
			"team": "platform",
		},
	}); err != nil {
		t.Fatalf("expected non-matching policy to be skipped, got %v", err)
	}
}

func TestLoadRejectsSymlinkedPolicyOutsideRoot(t *testing.T) {
	dir := t.TempDir()
	outsideDir := t.TempDir()
	outsidePolicyPath := filepath.Join(outsideDir, "outside-policy.yaml")
	if err := os.WriteFile(outsidePolicyPath, []byte(`
version: 1
policies:
  - id: escaped-policy
    scan_kinds: [image]
`), 0o644); err != nil {
		t.Fatalf("write outside policy: %v", err)
	}
	symlinkPath := filepath.Join(dir, "escaped.yaml")
	if err := os.Symlink(outsidePolicyPath, symlinkPath); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}

	_, err := Load(dir)
	if err == nil {
		t.Fatal("expected symlinked policy outside root to be rejected")
	}
	if !strings.Contains(err.Error(), "read scan policy file") {
		t.Fatalf("expected read failure for escaped symlink, got %v", err)
	}
}
