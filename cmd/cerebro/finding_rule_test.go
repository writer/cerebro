package main

import (
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/ports"
	"google.golang.org/protobuf/types/known/timestamppb"
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
	if request.Definition.Description == "" || request.Definition.Runbook == "" {
		t.Fatalf("metadata defaults missing: %+v", request.Definition)
	}
	if got := strings.Join(request.Definition.Tags, ","); got != "github,secret-scanning" {
		t.Fatalf("Tags = %q, want explicit tags preserved", got)
	}
	if len(request.Definition.References) == 0 || len(request.Definition.FalsePositives) == 0 {
		t.Fatalf("metadata list defaults missing: %+v", request.Definition)
	}
	if !request.DryRun {
		t.Fatal("DryRun = false, want true")
	}
}

func TestParseFindingRuleNewArgsParsesControlRefsAndMetadataComplete(t *testing.T) {
	request, err := parseFindingRuleNewArgs([]string{
		"github-secret-scanning-disabled",
		"source_id=github",
		"event_kinds=github.audit",
		"required_attributes=repository,action",
		"fingerprint_fields=repository,action",
		"control_refs=SOC 2:CC7.1,ISO 27001:2022:A.8.8",
	})
	if err != nil {
		t.Fatalf("parseFindingRuleNewArgs() error = %v", err)
	}
	if got := len(request.Definition.ControlRefs); got != 2 {
		t.Fatalf("ControlRefs = %d, want 2", got)
	}
	if got := request.Definition.ControlRefs[1].FrameworkName; got != "ISO 27001:2022" {
		t.Fatalf("ControlRefs[1].FrameworkName = %q, want ISO 27001:2022", got)
	}
	if errs := findings.ValidateRuleMetadataCompleteness([]findings.RuleDefinition{request.Definition}); len(errs) != 0 {
		t.Fatalf("ValidateRuleMetadataCompleteness() errors = %v", errs)
	}
	rendered := renderFindingRuleGo(newFindingRuleTemplateData(request))
	for _, want := range []string{
		`{FrameworkName: "SOC 2", ControlID: "CC7.1"}`,
		`{FrameworkName: "ISO 27001:2022", ControlID: "A.8.8"}`,
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("rendered control refs missing %q:\n%s", want, rendered)
		}
	}
	fixture := renderFindingRuleFixture(newFindingRuleTemplateData(request))
	for _, want := range []string{
		`"expected_no_match"`,
		`"fixture-event-unrelated-kind"`,
		`"fixture-event-missing-required-attribute"`,
	} {
		if !strings.Contains(fixture, want) {
			t.Fatalf("generated fixture missing %q:\n%s", want, fixture)
		}
	}
}

func TestParseFindingRuleGraphEvaluateArgs(t *testing.T) {
	options, err := parseFindingRuleGraphEvaluateArgs([]string{"runtime-1", "rule_id=cloud-exposed-privileged-compute-role"})
	if err != nil {
		t.Fatalf("parseFindingRuleGraphEvaluateArgs() error = %v", err)
	}
	if options.RuntimeID != "runtime-1" || options.RuleID != "cloud-exposed-privileged-compute-role" {
		t.Fatalf("options = %+v", options)
	}

	tests := []struct {
		name string
		args []string
	}{
		{name: "missing runtime", args: []string{"rule_id=cloud-exposed-privileged-compute-role"}},
		{name: "missing rule id", args: []string{"runtime-1"}},
		{name: "blank rule id", args: []string{"runtime-1", "rule_id="}},
		{name: "duplicate rule id", args: []string{"runtime-1", "rule_id=one", "rule_id=two"}},
		{name: "unknown key", args: []string{"runtime-1", "rule_id=one", "event_limit=100"}},
		{name: "non key value", args: []string{"runtime-1", "rule_id=one", "extra"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseFindingRuleGraphEvaluateArgs(tt.args); err == nil {
				t.Fatalf("parseFindingRuleGraphEvaluateArgs(%v) error = nil, want error", tt.args)
			}
		})
	}
}

func TestSummarizeFindingRuleGraphEvaluation(t *testing.T) {
	started := time.Date(2026, 6, 3, 4, 5, 6, 0, time.UTC)
	finished := started.Add(2 * time.Second)
	summary := summarizeFindingRuleGraphEvaluation(&findings.EvaluateGraphRulesResult{
		Runtime: &cerebrov1.SourceRuntime{Id: "runtime-1", SourceId: "aws", TenantId: "writer"},
		Evaluations: []*findings.GraphRuleEvaluationResult{
			{
				Rule: &cerebrov1.RuleSpec{Id: "cloud-exposed-privileged-compute-role"},
				Run: &cerebrov1.FindingEvaluationRun{
					Id:         "run-1",
					Status:     "completed",
					StartedAt:  timestamppb.New(started),
					FinishedAt: timestamppb.New(finished),
				},
				RowsRead:  3,
				Truncated: true,
				Findings: []*ports.FindingRecord{
					{ID: "finding-1"},
					{ID: "finding-2"},
				},
				Evidence: []*cerebrov1.FindingEvidence{
					{Id: "evidence-1"},
				},
			},
		},
	})
	if summary.RuntimeID != "runtime-1" || summary.SourceID != "aws" || summary.TenantID != "writer" {
		t.Fatalf("runtime summary = %+v", summary)
	}
	if len(summary.Evaluations) != 1 {
		t.Fatalf("len(Evaluations) = %d, want 1", len(summary.Evaluations))
	}
	evaluation := summary.Evaluations[0]
	if evaluation.RuleID != "cloud-exposed-privileged-compute-role" || evaluation.RunID != "run-1" || evaluation.Status != "completed" {
		t.Fatalf("evaluation metadata = %+v", evaluation)
	}
	if evaluation.RowsRead != 3 || !evaluation.Truncated || evaluation.FindingsEmitted != 2 || evaluation.EvidenceCount != 1 {
		t.Fatalf("evaluation counts = %+v", evaluation)
	}
	if strings.Join(evaluation.FindingIDs, ",") != "finding-1,finding-2" {
		t.Fatalf("FindingIDs = %#v", evaluation.FindingIDs)
	}
	if evaluation.StartedAt == "" || evaluation.FinishedAt == "" {
		t.Fatalf("timestamps missing: %+v", evaluation)
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
	rulePayload, err := os.ReadFile(rulePath) // #nosec G304 -- generated file path is anchored under the test temp output directory.
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
	fixturePayload, err := os.ReadFile(fixturePath) // #nosec G304 -- generated file path is anchored under the test temp output directory.
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
	rulePayload, err := os.ReadFile(rulePath) // #nosec G304 -- generated file path is anchored under the test temp output directory.
	if err != nil {
		t.Fatalf("read generated rule: %v", err)
	}
	if !strings.Contains(string(rulePayload), "func newRule123GithubRuleRule() Rule") {
		t.Fatalf("generated rule did not prefix numeric identifier: %s", rulePayload)
	}
}

func TestFindingRuleScaffold_RendersLifecycle_DurableState(t *testing.T) {
	rendered := renderScaffoldedRule(t, []string{
		"github-public-repo",
		"source_id=github",
		"event_kinds=github.audit",
		"required_attributes=repository",
		"fingerprint_fields=repository",
		"lifecycle_kind=durable_state",
		"lifecycle_anchor=graph_anchored",
	})
	if !strings.Contains(rendered, "Lifecycle: Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorGraphAnchored}") {
		t.Fatalf("rendered output missing durable_state Lifecycle literal:\n%s", rendered)
	}
	requireLifecycleField(t, rendered, "LifecycleDurableState", "AnchorGraphAnchored", false)
}

func TestFindingRuleScaffold_RendersLifecycle_AuditEvidence(t *testing.T) {
	rendered := renderScaffoldedRule(t, []string{
		"github-secret-scanning-disabled",
		"source_id=github",
		"event_kinds=github.audit",
		"lifecycle_kind=audit_evidence",
		"lifecycle_anchor=none",
	})
	if !strings.Contains(rendered, "Lifecycle: Lifecycle{Kind: LifecycleAuditEvidence, Anchor: AnchorNone}") {
		t.Fatalf("rendered output missing audit_evidence Lifecycle literal:\n%s", rendered)
	}
	requireLifecycleField(t, rendered, "LifecycleAuditEvidence", "AnchorNone", false)
}

func TestFindingRuleScaffold_RendersLifecycle_TTLEvidence(t *testing.T) {
	rendered := renderScaffoldedRule(t, []string{
		"runtime-active-threat-evidence",
		"source_id=sentinelone",
		"event_kinds=sentinelone.threat",
		"lifecycle_kind=ttl_evidence",
		"lifecycle_anchor=source_state",
		"lifecycle_ttl=24h",
	})
	expected := "Lifecycle: Lifecycle{Kind: LifecycleTTLEvidence, Anchor: AnchorSourceState, TTL: time.Duration(86400000000000)}"
	if !strings.Contains(rendered, expected) {
		t.Fatalf("rendered output missing ttl_evidence Lifecycle literal:\n%s", rendered)
	}
	requireLifecycleField(t, rendered, "LifecycleTTLEvidence", "AnchorSourceState", true)
}

func TestFindingRuleScaffold_RendersLifecycle_Retired(t *testing.T) {
	rendered := renderScaffoldedRule(t, []string{
		"github-critical-resource-deleted",
		"source_id=github",
		"event_kinds=github.audit",
		"lifecycle_kind=retired",
		"lifecycle_anchor=none",
	})
	if !strings.Contains(rendered, "Lifecycle: Lifecycle{Kind: LifecycleRetired, Anchor: AnchorNone}") {
		t.Fatalf("rendered output missing retired Lifecycle literal:\n%s", rendered)
	}
	requireLifecycleField(t, rendered, "LifecycleRetired", "AnchorNone", false)
}

func TestRenderFindingRuleGo_RetiredEmitsRetiredEventRule(t *testing.T) {
	rendered := renderScaffoldedRule(t, []string{
		"github-critical-resource-deleted",
		"source_id=github",
		"event_kinds=github.audit",
		"lifecycle_kind=retired",
		"lifecycle_anchor=none",
	})
	if !strings.Contains(rendered, "return newRetiredEventRule(githubCriticalResourceDeletedDefinition)") {
		t.Fatalf("retired scaffold should use newRetiredEventRule constructor:\n%s", rendered)
	}
	if strings.Contains(rendered, "return newEventRule(eventRuleConfig{") {
		t.Fatalf("retired scaffold should not render a plain newEventRule constructor:\n%s", rendered)
	}
	requireLifecycleField(t, rendered, "LifecycleRetired", "AnchorNone", false)
}

func TestScaffoldFindingRule_RetiredGeneratedTestPasses(t *testing.T) {
	repoRoot := testRepoRoot(t)
	outputDir := shadowRepoForFindingRuleScaffold(t, repoRoot)
	request, err := parseFindingRuleNewArgs([]string{
		"retired-scaffold-contract",
		"source_id=github",
		"event_kinds=github.audit",
		"name=Retired Scaffold Contract",
		"required_attributes=action,repository",
		"lifecycle_kind=retired",
		"lifecycle_anchor=none",
		"output_dir=" + outputDir,
	})
	if err != nil {
		t.Fatalf("parseFindingRuleNewArgs() error = %v", err)
	}
	if _, err := scaffoldFindingRule(request); err != nil {
		t.Fatalf("scaffoldFindingRule() error = %v", err)
	}

	testPath := filepath.Join(outputDir, "internal", "findings", "retired_scaffold_contract_rule_test.go")
	testPayload, err := os.ReadFile(testPath) // #nosec G304 -- generated file path is anchored under the test temp output directory.
	if err != nil {
		t.Fatalf("read generated test: %v", err)
	}
	if !strings.Contains(string(testPayload), "assertRetiredEventRuleFixture") {
		t.Fatalf("generated retired test does not use retired fixture helper:\n%s", testPayload)
	}
	if strings.Contains(string(testPayload), "assertRuleFixture") {
		t.Fatalf("generated retired test still uses positive fixture helper:\n%s", testPayload)
	}

	fixturePath := filepath.Join(outputDir, "internal", "findings", "testdata", "rules", "retired-scaffold-contract.json")
	fixturePayload, err := os.ReadFile(fixturePath) // #nosec G304 -- generated file path is anchored under the test temp output directory.
	if err != nil {
		t.Fatalf("read generated fixture: %v", err)
	}
	var fixture struct {
		ExpectedFindings []any `json:"expected_findings"`
	}
	if err := json.Unmarshal(fixturePayload, &fixture); err != nil {
		t.Fatalf("unmarshal generated fixture: %v\n%s", err, fixturePayload)
	}
	if fixture.ExpectedFindings == nil {
		t.Fatalf("generated retired fixture missing explicit expected_findings array:\n%s", fixturePayload)
	}
	if len(fixture.ExpectedFindings) != 0 {
		t.Fatalf("generated retired fixture expected_findings length = %d, want 0:\n%s", len(fixture.ExpectedFindings), fixturePayload)
	}

	cmd := exec.Command("go", "test", "./internal/findings", "-run", "^TestRetiredScaffoldContractFixture$", "-count=1", "-v")
	cmd.Dir = outputDir
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=-mod=readonly")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("generated retired test failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "--- PASS: TestRetiredScaffoldContractFixture") {
		t.Fatalf("generated retired test output did not include the expected passing test:\n%s", output)
	}
}

func TestParseFindingRuleNewArgs_DurableStateRejectsDefaultFingerprint(t *testing.T) {
	if _, err := parseFindingRuleNewArgs([]string{
		"github-public-repo",
		"source_id=github",
		"event_kinds=github.audit",
		"lifecycle_kind=durable_state",
	}); !errors.Is(err, errScaffoldDurableStateDefaultFingerprint) {
		t.Fatalf("parseFindingRuleNewArgs() error = %v, want durable-state default fingerprint error", err)
	}

	ttlRequest, err := parseFindingRuleNewArgs([]string{
		"runtime-active-threat-evidence",
		"source_id=sentinelone",
		"event_kinds=sentinelone.threat",
		"lifecycle_kind=ttl_evidence",
		"lifecycle_ttl=24h",
	})
	if err != nil {
		t.Fatalf("ttl_evidence parseFindingRuleNewArgs() error = %v, want default event_id accepted", err)
	}
	if got := strings.Join(ttlRequest.Definition.FingerprintFields, ","); got != "event_id" {
		t.Fatalf("ttl_evidence FingerprintFields = %q, want event_id", got)
	}

	if _, err := parseFindingRuleNewArgs([]string{
		"github-public-repo",
		"source_id=github",
		"event_kinds=github.audit",
		"required_attributes=repository",
		"fingerprint_fields=repository",
		"lifecycle_kind=durable_state",
	}); err != nil {
		t.Fatalf("durable_state with stable fingerprint parseFindingRuleNewArgs() error = %v", err)
	}
}

func TestRenderFindingRuleGo_BuilderUsesRequiredAttributeValueHelper(t *testing.T) {
	rendered := renderScaffoldedRule(t, []string{
		"github-runner-scope",
		"source_id=github",
		"event_kinds=github.audit",
		"required_attributes=scope",
		"fingerprint_fields=tenant_id,source_id,scope",
	})
	for _, want := range []string{
		`requiredAttributeValue(event, "event_id")`,
		`requiredAttributeValue(event, ports.EventAttributeSourceRuntimeID)`,
		`requiredAttributeValue(event, key)`,
		`requiredAttributeValue(event, field)`,
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("generated builder missing %q:\n%s", want, rendered)
		}
	}
	for _, forbidden := range []string{
		`attributes[key]`,
		`attributes[field]`,
		`event.GetAttributes()[ports.EventAttributeSourceRuntimeID]`,
	} {
		if strings.Contains(rendered, forbidden) {
			t.Fatalf("generated builder used raw attribute lookup %q:\n%s", forbidden, rendered)
		}
	}
}

func renderScaffoldedRule(t *testing.T, args []string) string {
	t.Helper()
	request, err := parseFindingRuleNewArgs(args)
	if err != nil {
		t.Fatalf("parseFindingRuleNewArgs() error = %v", err)
	}
	return renderFindingRuleGo(newFindingRuleTemplateData(request))
}

func testRepoRoot(t *testing.T) string {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd() error = %v", err)
	}
	root, err := filepath.Abs(filepath.Join(cwd, "..", ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("repo root %q missing go.mod: %v", root, err)
	}
	return root
}

func shadowRepoForFindingRuleScaffold(t *testing.T, repoRoot string) string {
	t.Helper()
	outputDir := t.TempDir()
	linkRepoEntries(t, repoRoot, outputDir, map[string]bool{
		".git":     true,
		"internal": true,
	})

	internalDir := filepath.Join(outputDir, "internal")
	if err := os.MkdirAll(internalDir, 0o750); err != nil {
		t.Fatalf("mkdir shadow internal dir: %v", err)
	}
	linkRepoEntries(t, filepath.Join(repoRoot, "internal"), internalDir, map[string]bool{
		"findings": true,
	})

	findingsDir := filepath.Join(internalDir, "findings")
	if err := os.MkdirAll(filepath.Join(findingsDir, "testdata", "rules"), 0o750); err != nil {
		t.Fatalf("mkdir shadow findings testdata: %v", err)
	}
	linkRepoEntries(t, filepath.Join(repoRoot, "internal", "findings"), findingsDir, map[string]bool{
		"correlation_patterns": true,
		"testdata":             true,
	})
	copyRepoTree(t, filepath.Join(repoRoot, "internal", "findings", "correlation_patterns"), filepath.Join(findingsDir, "correlation_patterns"))
	linkRepoEntries(t, filepath.Join(repoRoot, "internal", "findings", "testdata"), filepath.Join(findingsDir, "testdata"), map[string]bool{
		"rules": true,
	})
	return outputDir
}

func linkRepoEntries(t *testing.T, srcDir, dstDir string, skip map[string]bool) {
	t.Helper()
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		t.Fatalf("read dir %q: %v", srcDir, err)
	}
	if err := os.MkdirAll(dstDir, 0o750); err != nil {
		t.Fatalf("mkdir dir %q: %v", dstDir, err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if skip[name] {
			continue
		}
		if err := os.Symlink(filepath.Join(srcDir, name), filepath.Join(dstDir, name)); err != nil {
			t.Fatalf("symlink %q into %q: %v", filepath.Join(srcDir, name), dstDir, err)
		}
	}
}

func copyRepoTree(t *testing.T, srcDir, dstDir string) {
	t.Helper()
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		t.Fatalf("read dir %q: %v", srcDir, err)
	}
	if err := os.MkdirAll(dstDir, 0o750); err != nil {
		t.Fatalf("mkdir dir %q: %v", dstDir, err)
	}
	for _, entry := range entries {
		src := filepath.Join(srcDir, entry.Name())
		dst := filepath.Join(dstDir, entry.Name())
		if rel, err := filepath.Rel(dstDir, dst); err != nil || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || rel == ".." {
			t.Fatalf("copy destination %q escaped %q", dst, dstDir)
		}
		if entry.IsDir() {
			copyRepoTree(t, src, dst)
			continue
		}
		payload, err := os.ReadFile(src) // #nosec G304 -- source path is a repository fixture copied into a temp shadow repo.
		if err != nil {
			t.Fatalf("read file %q: %v", src, err)
		}
		info, err := entry.Info()
		if err != nil {
			t.Fatalf("stat file %q: %v", src, err)
		}
		if err := os.WriteFile(dst, payload, info.Mode().Perm()&0o600); err != nil { // #nosec G703 -- destination is validated to remain under dstDir above.
			t.Fatalf("write file %q: %v", dst, err)
		}
	}
}

func requireLifecycleField(t *testing.T, source, wantKind, wantAnchor string, wantTTL bool) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "scaffolded_rule.go", source, parser.AllErrors)
	if err != nil {
		t.Fatalf("parser.ParseFile() error = %v\nsource:\n%s", err, source)
	}
	var lifecycle *ast.KeyValueExpr
	ast.Inspect(file, func(n ast.Node) bool {
		composite, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		if ident, ok := composite.Type.(*ast.Ident); !ok || ident.Name != "RuleDefinition" {
			return true
		}
		for _, element := range composite.Elts {
			kv, ok := element.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok || key.Name != "Lifecycle" {
				continue
			}
			lifecycle = kv
			return false
		}
		return true
	})
	if lifecycle == nil {
		t.Fatalf("RuleDefinition composite literal missing Lifecycle field:\n%s", source)
	}
	value, ok := lifecycle.Value.(*ast.CompositeLit)
	if !ok {
		t.Fatalf("Lifecycle field is not a composite literal: %T", lifecycle.Value)
	}
	if ident, ok := value.Type.(*ast.Ident); !ok || ident.Name != "Lifecycle" {
		t.Fatalf("Lifecycle composite literal type = %T, want findings.Lifecycle", value.Type)
	}
	seen := map[string]ast.Expr{}
	for _, element := range value.Elts {
		kv, ok := element.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		seen[key.Name] = kv.Value
	}
	kindExpr, ok := seen["Kind"]
	if !ok {
		t.Fatalf("Lifecycle composite literal missing Kind field; have %v", keys(seen))
	}
	if ident, ok := kindExpr.(*ast.Ident); !ok || ident.Name != wantKind {
		t.Fatalf("Lifecycle Kind = %v, want %s", kindExpr, wantKind)
	}
	anchorExpr, ok := seen["Anchor"]
	if !ok {
		t.Fatalf("Lifecycle composite literal missing Anchor field; have %v", keys(seen))
	}
	if ident, ok := anchorExpr.(*ast.Ident); !ok || ident.Name != wantAnchor {
		t.Fatalf("Lifecycle Anchor = %v, want %s", anchorExpr, wantAnchor)
	}
	if wantTTL {
		if _, ok := seen["TTL"]; !ok {
			t.Fatalf("Lifecycle composite literal missing TTL field; have %v", keys(seen))
		}
	}
}

func keys(m map[string]ast.Expr) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
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
