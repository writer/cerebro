package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/findingdsl"
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

func TestRunNewWritesGraphPolicy(t *testing.T) {
	root := t.TempDir()
	err := runNew([]string{
		"--root", root,
		"--write",
		"--domain", "graph",
		"--id", "graph-example",
		"--name", "Graph Example",
		"--description", "Example graph policy",
		"--severity", "low",
		"--graph-query", "MATCH (entity:Entity {tenant_id: $tenant_id}) RETURN entity.urn AS primary_urn, entity.urn AS fingerprint_key LIMIT $row_limit",
		"--graph-row-limit", "200",
		"--graph-param", "minimum_count=2",
		"--graph-param", "enabled=true",
		"--graph-required-column", "primary_urn",
		"--graph-required-column", "fingerprint_key",
		"--framework", "SOC 2:CC7.1",
		"--reference", "https://www.iso.org/standard/27001",
		"--tag", "graph",
	})
	if err != nil {
		t.Fatalf("runNew() error = %v", err)
	}
	path := filepath.Join(root, "policies/graph/graph-example.yaml")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if strings.Contains(string(content), "effect:") || strings.Contains(string(content), "match:") {
		t.Fatalf("graph policy YAML should not contain condition-only fields:\n%s", content)
	}
	rule, issues, err := findingdsl.LoadPolicyRuleFile(root, path)
	if err != nil {
		t.Fatalf("LoadPolicyRuleFile() error = %v", err)
	}
	if len(issues) != 0 {
		t.Fatalf("LoadPolicyRuleFile() issues = %#v", issues)
	}
	if got := strings.Join(rule.Metadata.References, ","); got != "https://www.iso.org/standard/27001" {
		t.Fatalf("Metadata.References = %q, want ISO reference", got)
	}
	if rule.Spec.Graph.RowLimit != 200 || rule.Spec.Graph.Params["minimum_count"] != 2 {
		t.Fatalf("graph config = %#v, want row limit and parsed params", rule.Spec.Graph)
	}
	if rule.Spec.Graph.Params["enabled"] != true {
		t.Fatalf("enabled param = %#v, want true", rule.Spec.Graph.Params["enabled"])
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
