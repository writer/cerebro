package findingdsl

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadPolicyRulesLoadsValidatedYAML(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "policies/aws/example.yaml", `
apiVersion: cerebro.writer.com/v1alpha1
kind: PolicyFindingRule
metadata:
  id: aws-example
  name: AWS Example
  description: Example policy
  tags: [aws]
spec:
  severity: high
  effect: forbid
  resource: aws::s3::bucket
  match:
    conditionFormat: cel
    conditions:
      - cmp_eq(path(resource, "public"), true)
  frameworks:
    - name: SOC 2
      controls: [CC6]
`)
	writeTestFile(t, root, ControlMappingRelPath, `{"version":"1.0.0","controls":{}}`)

	rules, issues, err := LoadPolicyRules(root)
	if err != nil {
		t.Fatalf("LoadPolicyRules() error = %v", err)
	}
	if len(issues) != 0 {
		t.Fatalf("issues = %#v, want none", issues)
	}
	if got := len(rules); got != 1 {
		t.Fatalf("len(rules) = %d, want 1", got)
	}
	rule := rules[0]
	if rule.Metadata.ID != "aws-example" || rule.Domain != "aws" || rule.RelPath != "policies/aws/example.yaml" {
		t.Fatalf("loaded rule = %#v", rule)
	}
}

func TestLoadPolicyRulesRejectsLegacyJSONPolicies(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "policies/aws/example.json", `{"id":"aws-example"}`)

	_, issues, err := LoadPolicyRules(root)
	if err != nil {
		t.Fatalf("LoadPolicyRules() error = %v", err)
	}
	if len(issues) != 1 || !strings.Contains(issues[0].Message, "legacy JSON") {
		t.Fatalf("issues = %#v, want legacy JSON rejection", issues)
	}
}

func TestLegacyPolicyRoundTrip(t *testing.T) {
	rule := FromLegacyPolicy("policies/aws/example.yaml", LegacyPolicy{
		ID:              "aws-example",
		Name:            "AWS Example",
		Description:     "Example policy",
		Severity:        "medium",
		Effect:          "forbid",
		Resource:        "aws::s3::bucket",
		Conditions:      []string{"true"},
		ConditionFormat: "cel",
		Tags:            []string{"aws"},
		Frameworks:      []PolicyFramework{{Name: "SOC 2", Controls: []string{"CC6"}}},
	})
	if issues := ValidatePolicyRule(rule); len(issues) != 0 {
		t.Fatalf("ValidatePolicyRule() issues = %#v", issues)
	}
	legacy := rule.LegacyPolicy()
	if legacy.ID != "aws-example" || legacy.Resource != "aws::s3::bucket" || legacy.ConditionFormat != "cel" {
		t.Fatalf("LegacyPolicy() = %#v", legacy)
	}
}

func writeTestFile(t *testing.T, root string, rel string, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
}
