package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseFindingRuleNewArgsAppliesDefaults(t *testing.T) {
	request, err := parseFindingRuleNewArgs([]string{
		"github-secret-scanning-disabled",
		"source_id=github",
		"event_kinds=github.audit",
		"required_attributes=action,repository",
		"tags=github,secret-scanning",
		"dry_run=true",
	})
	if err != nil {
		t.Fatalf("parseFindingRuleNewArgs() error = %v", err)
	}
	if got := request.Definition.OutputKind; got != "finding.github_secret_scanning_disabled" {
		t.Fatalf("OutputKind = %q, want finding.github_secret_scanning_disabled", got)
	}
	if got := request.Definition.Name; got != "Github Secret Scanning Disabled" {
		t.Fatalf("Name = %q, want Github Secret Scanning Disabled", got)
	}
	if got := request.Definition.FingerprintFields[0]; got != "event_id" {
		t.Fatalf("FingerprintFields[0] = %q, want event_id", got)
	}
	if !request.DryRun {
		t.Fatal("DryRun = false, want true")
	}
}

func TestParseFindingRuleNewArgsRejectsUnsafeRuleID(t *testing.T) {
	if _, err := parseFindingRuleNewArgs([]string{
		"../bad",
		"source_id=github",
		"event_kinds=github.audit",
	}); err == nil {
		t.Fatal("parseFindingRuleNewArgs() error = nil, want unsafe rule id error")
	}
}

func TestScaffoldFindingRuleWritesRuleTestAndFixture(t *testing.T) {
	outputDir := t.TempDir()
	request, err := parseFindingRuleNewArgs([]string{
		"github-secret-scanning-disabled",
		"source_id=github",
		"event_kinds=github.audit",
		"output_kind=finding.github_secret_scanning_disabled",
		"name=GitHub Secret Scanning Disabled",
		"severity=HIGH",
		"tags=github,secret-scanning",
		"required_attributes=action,repository",
		"fingerprint_fields=repository,action",
		"output_dir=" + outputDir,
	})
	if err != nil {
		t.Fatalf("parseFindingRuleNewArgs() error = %v", err)
	}
	result, err := scaffoldFindingRule(request)
	if err != nil {
		t.Fatalf("scaffoldFindingRule() error = %v", err)
	}
	if len(result.Files) != 3 {
		t.Fatalf("len(Files) = %d, want 3", len(result.Files))
	}
	rulePath := filepath.Join(outputDir, "internal", "findings", "github_secret_scanning_disabled_rule.go")
	rulePayload, err := os.ReadFile(rulePath)
	if err != nil {
		t.Fatalf("read generated rule: %v", err)
	}
	if !strings.Contains(string(rulePayload), "githubSecretScanningDisabledDefinition") {
		t.Fatalf("generated rule missing definition: %s", rulePayload)
	}
	testPath := filepath.Join(outputDir, "internal", "findings", "github_secret_scanning_disabled_rule_test.go")
	if _, err := os.Stat(testPath); err != nil {
		t.Fatalf("stat generated test: %v", err)
	}
	fixturePath := filepath.Join(outputDir, "internal", "findings", "testdata", "rules", "github-secret-scanning-disabled.json")
	fixturePayload, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read generated fixture: %v", err)
	}
	if !strings.Contains(string(fixturePayload), "\"rule_id\": \"github-secret-scanning-disabled\"") {
		t.Fatalf("generated fixture missing rule id: %s", fixturePayload)
	}
}

func TestScaffoldFindingRulePrefixesNumericIdentifiers(t *testing.T) {
	outputDir := t.TempDir()
	request, err := parseFindingRuleNewArgs([]string{
		"123-github-rule",
		"source_id=github",
		"event_kinds=github.audit",
		"output_dir=" + outputDir,
	})
	if err != nil {
		t.Fatalf("parseFindingRuleNewArgs() error = %v", err)
	}
	if _, err := scaffoldFindingRule(request); err != nil {
		t.Fatalf("scaffoldFindingRule() error = %v", err)
	}
	rulePath := filepath.Join(outputDir, "internal", "findings", "rule_123_github_rule_rule.go")
	rulePayload, err := os.ReadFile(rulePath)
	if err != nil {
		t.Fatalf("read generated rule: %v", err)
	}
	if !strings.Contains(string(rulePayload), "func newRule123GithubRuleRule() Rule") {
		t.Fatalf("generated rule did not prefix numeric identifier: %s", rulePayload)
	}
}

func TestScaffoldFindingRuleRefusesOverwriteWithoutForce(t *testing.T) {
	outputDir := t.TempDir()
	request, err := parseFindingRuleNewArgs([]string{
		"github-secret-scanning-disabled",
		"source_id=github",
		"event_kinds=github.audit",
		"output_dir=" + outputDir,
	})
	if err != nil {
		t.Fatalf("parseFindingRuleNewArgs() error = %v", err)
	}
	if _, err := scaffoldFindingRule(request); err != nil {
		t.Fatalf("first scaffoldFindingRule() error = %v", err)
	}
	if _, err := scaffoldFindingRule(request); err == nil {
		t.Fatal("second scaffoldFindingRule() error = nil, want overwrite error")
	}
}
