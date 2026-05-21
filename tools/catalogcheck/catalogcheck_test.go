package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestCheckRepositoryAcceptsMinimalCatalogs(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "policies/github/test.json", `{
  "id": "github-test",
  "name": "GitHub Test",
  "description": "Test policy",
  "effect": "forbid",
  "resource": "github::repository",
  "conditions": ["cmp_eq(path(resource, \"visibility\"), \"public\")"],
  "condition_format": "cel",
  "severity": "high",
  "tags": ["github"],
  "frameworks": [{"name": "SOC 2", "controls": ["CC6"]}]
}`)
	writeFile(t, root, "policies/cerebro/control-mapping.json", `{"version":"1.0.0","controls":{}}`)
	writeFile(t, root, "sources/github/catalog.yaml", `
id: github
name: GitHub
description: GitHub source
emitted_kinds:
  - github.audit
kind_lifecycle:
  - kind: github.secret_scanning
    status: planned
`)

	issues, err := checkRepository(root)
	if err != nil {
		t.Fatalf("checkRepository() error = %v", err)
	}
	if len(issues) != 0 {
		t.Fatalf("issues = %#v, want none", issues)
	}
}

func TestCheckRepositoryRejectsPolicyMissingMetadata(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "policies/github/test.json", `{"id":"github-test","conditions":["true"]}`)
	writeFile(t, root, "sources/sdk/catalog.yaml", `id: sdk
name: SDK
emitted_kinds: []
`)

	issues, err := checkRepository(root)
	if err != nil {
		t.Fatalf("checkRepository() error = %v", err)
	}
	if len(issues) == 0 {
		t.Fatal("issues = 0, want policy metadata issue")
	}
}

func TestCheckRepositoryRejectsUnprojectedEmittedKind(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "policies/github/test.json", `{
  "id": "github-test",
  "name": "GitHub Test",
  "description": "Test policy",
  "query": "SELECT 1",
  "severity": "LOW"
}`)
	writeFile(t, root, "sources/custom/catalog.yaml", `
id: custom
name: Custom
emitted_kinds:
  - custom.audit
`)

	issues, err := checkRepository(root)
	if err != nil {
		t.Fatalf("checkRepository() error = %v", err)
	}
	if len(issues) == 0 {
		t.Fatal("issues = 0, want unprojected emitted kind issue")
	}
}

func TestValidateFixtureContractsSkipsSymlinkFixtures(t *testing.T) {
	root := t.TempDir()
	sourceDir := filepath.Join(root, "sources", "custom")
	if err := os.MkdirAll(filepath.Join(sourceDir, "testdata"), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	linkPath := filepath.Join(sourceDir, "testdata", "outside.json")
	if err := os.Symlink(filepath.Join(root, "missing.json"), linkPath); err != nil {
		t.Skipf("Symlink() unsupported: %v", err)
	}
	issues := validateFixtureContracts(root, sourceDir, []sourcecdk.EventContract{
		{Kind: "custom.event", RequiredAttributes: []string{"required_attribute"}},
	})
	if len(issues) != 0 {
		t.Fatalf("issues = %#v, want none for symlink fixture", issues)
	}
}

func writeFile(t *testing.T, root string, rel string, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
}
