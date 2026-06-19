package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMigratePolicyFilesRefusesExistingYAML(t *testing.T) {
	root := t.TempDir()
	writeToolTestFile(t, root, "policies/aws/example.json", `{
  "id": "aws-example",
  "name": "AWS Example",
  "description": "Example policy",
  "effect": "forbid",
  "resource": "aws::s3::bucket",
  "conditions": ["cmp_eq(path(resource, \"public\"), true)"],
  "condition_format": "cel",
  "severity": "high",
  "tags": ["aws"],
  "frameworks": [{"name": "SOC 2", "controls": ["CC6"]}]
}`)
	writeToolTestFile(t, root, "policies/aws/example.yaml", "existing: true\n")

	err := migratePolicyFiles(root, true)
	if err == nil || !strings.Contains(err.Error(), "destination already exists") {
		t.Fatalf("migratePolicyFiles() error = %v, want destination exists error", err)
	}
	content, readErr := os.ReadFile(filepath.Join(root, "policies/aws/example.yaml"))
	if readErr != nil {
		t.Fatalf("ReadFile() error = %v", readErr)
	}
	if string(content) != "existing: true\n" {
		t.Fatalf("existing YAML content = %q, want unchanged", content)
	}
	if _, statErr := os.Stat(filepath.Join(root, "policies/aws/example.json")); statErr != nil {
		t.Fatalf("legacy JSON stat error = %v, want preserved source", statErr)
	}
}

func writeToolTestFile(t *testing.T, root string, rel string, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
}
