package findingdsl

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/writer/cerebro/internal/ports"
	"gopkg.in/yaml.v3"
)

const KindPolicyFindingRuleTest = "PolicyFindingRuleTest"

type PolicyRuleTestSuite struct {
	APIVersion string               `json:"apiVersion" yaml:"apiVersion"`
	Kind       string               `json:"kind" yaml:"kind"`
	Policy     string               `json:"policy,omitempty" yaml:"policy,omitempty"`
	Cases      []PolicyRuleTestCase `json:"cases" yaml:"cases"`
	RelPath    string               `json:"-" yaml:"-"`
}

type PolicyRuleTestCase struct {
	Name             string              `json:"name" yaml:"name"`
	Resource         map[string]any      `json:"resource,omitempty" yaml:"resource,omitempty"`
	QueryRows        []map[string]any    `json:"queryRows,omitempty" yaml:"queryRows,omitempty"`
	GraphFixture     *PolicyGraphFixture `json:"graphFixture,omitempty" yaml:"graphFixture,omitempty"`
	WantEvidenceURNs []string            `json:"wantEvidenceUrns,omitempty" yaml:"wantEvidenceUrns,omitempty"`
	WantFinding      bool                `json:"wantFinding" yaml:"wantFinding"`
}

// PolicyGraphFixture is a deterministic projected graph used to execute a
// policy's real Cypher. Multi-hop fixtures require a connected path spanning
// at least two edges; precomputed query rows do not satisfy this contract.
type PolicyGraphFixture struct {
	TenantID string                   `json:"tenantId" yaml:"tenantId"`
	Nodes    []PolicyGraphFixtureNode `json:"nodes" yaml:"nodes"`
	Edges    []PolicyGraphFixtureEdge `json:"edges" yaml:"edges"`
}

type PolicyGraphFixtureNode struct {
	URN        string            `json:"urn" yaml:"urn"`
	SourceID   string            `json:"sourceId" yaml:"sourceId"`
	RuntimeID  string            `json:"runtimeId,omitempty" yaml:"runtimeId,omitempty"`
	EntityType string            `json:"entityType" yaml:"entityType"`
	Label      string            `json:"label,omitempty" yaml:"label,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty" yaml:"attributes,omitempty"`
}

type PolicyGraphFixtureEdge struct {
	FromURN    string            `json:"fromUrn" yaml:"fromUrn"`
	ToURN      string            `json:"toUrn" yaml:"toUrn"`
	SourceID   string            `json:"sourceId" yaml:"sourceId"`
	RuntimeID  string            `json:"runtimeId,omitempty" yaml:"runtimeId,omitempty"`
	Relation   string            `json:"relation" yaml:"relation"`
	Attributes map[string]string `json:"attributes,omitempty" yaml:"attributes,omitempty"`
}

type PolicyGraphTestStore interface {
	ports.RawCypherQueryStore
	ports.ProjectionGraphStore
	ports.ProjectionEntityDeleter
}

func DiscoverPolicyTestSuites(root string) ([]string, error) {
	root = filepath.Clean(root)
	var suites []string
	err := filepath.WalkDir(filepath.Join(root, "policies"), func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if isPolicyTestRelPath(filepath.ToSlash(path)) {
			rel, err := safeRel(root, path)
			if err != nil {
				return err
			}
			suites = append(suites, rel)
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return suites, nil
}

func LoadPolicyRuleTestSuite(root string, path string) (PolicyRuleTestSuite, []Issue, error) {
	root = filepath.Clean(root)
	rel, err := safeRel(root, path)
	if err != nil {
		return PolicyRuleTestSuite{}, nil, err
	}
	content, err := fs.ReadFile(os.DirFS(root), rel)
	if err != nil {
		return PolicyRuleTestSuite{}, nil, fmt.Errorf("read %s: %w", rel, err)
	}
	var suite PolicyRuleTestSuite
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	decoder.KnownFields(true)
	if parseErr := decoder.Decode(&suite); parseErr != nil {
		return policyRuleTestSuiteIssue(rel, "invalid PolicyFindingRuleTest YAML: "+parseErr.Error())
	}
	suite.RelPath = rel
	return suite, ValidatePolicyRuleTestSuite(suite), nil
}

func policyRuleTestSuiteIssue(path string, message string) (PolicyRuleTestSuite, []Issue, error) {
	return PolicyRuleTestSuite{}, []Issue{{Path: path, Message: message}}, nil
}

func ValidatePolicyRuleTestSuite(suite PolicyRuleTestSuite) []Issue {
	path := suite.RelPath
	if path == "" {
		path = "<policy-test-suite>"
	}
	var issues []Issue
	if strings.TrimSpace(suite.APIVersion) != APIVersion {
		issues = append(issues, Issue{Path: path, Message: fmt.Sprintf("apiVersion must be %q", APIVersion)})
	}
	if strings.TrimSpace(suite.Kind) != KindPolicyFindingRuleTest {
		issues = append(issues, Issue{Path: path, Message: fmt.Sprintf("kind must be %q", KindPolicyFindingRuleTest)})
	}
	if len(suite.Cases) == 0 {
		issues = append(issues, Issue{Path: path, Message: "cases is required"})
	}
	for idx, testCase := range suite.Cases {
		if strings.TrimSpace(testCase.Name) == "" {
			issues = append(issues, Issue{Path: path, Message: fmt.Sprintf("cases[%d].name is required", idx)})
		}
		if len(testCase.Resource) == 0 && len(testCase.QueryRows) == 0 && testCase.GraphFixture == nil {
			issues = append(issues, Issue{Path: path, Message: fmt.Sprintf("cases[%d] must include resource, queryRows, or graphFixture", idx)})
		}
		if testCase.GraphFixture != nil {
			issues = append(issues, validatePolicyGraphFixture(path, idx, testCase)...)
			if testCase.WantFinding && len(testCase.WantEvidenceURNs) < 2 {
				issues = append(issues, Issue{Path: path, Message: fmt.Sprintf("cases[%d] %q graph finding cases require at least two wantEvidenceUrns", idx, testCase.Name)})
			}
			if !testCase.WantFinding && len(testCase.WantEvidenceURNs) != 0 {
				issues = append(issues, Issue{Path: path, Message: fmt.Sprintf("cases[%d] %q passing graph cases must not declare wantEvidenceUrns", idx, testCase.Name)})
			}
		}
	}
	issues = append(issues, validatePolicyGraphMutationPair(path, suite.Cases)...)
	return issues
}

// ValidatePolicyRuleTestSuiteAgainstRule validates an already-loaded suite
// against an already-loaded rule. It is the filesystem-free validation seam
// used by durable evaluation datasets and other authoring workflows.
func ValidatePolicyRuleTestSuiteAgainstRule(rule PolicyFindingRule, suite PolicyRuleTestSuite) []Issue {
	if issues := ValidatePolicyRule(rule); len(issues) != 0 {
		out := make([]Issue, 0, len(issues))
		for _, issue := range issues {
			out = append(out, Issue{Path: suitePath(suite), Message: "policy " + issue.Path + ": " + issue.Message})
		}
		return out
	}
	if issues := ValidatePolicyRuleTestSuite(suite); len(issues) != 0 {
		return issues
	}
	var out []Issue
	for idx, testCase := range suite.Cases {
		out = append(out, validatePolicyRuleTestCaseAgainstRule(suitePath(suite), rule, idx, testCase)...)
	}
	return out
}

func suitePath(suite PolicyRuleTestSuite) string {
	if path := strings.TrimSpace(suite.RelPath); path != "" {
		return path
	}
	return "<policy-test-suite>"
}

func FormatPolicyRuleTestSuiteYAML(suite PolicyRuleTestSuite) ([]byte, error) {
	suite.RelPath = ""
	return yaml.Marshal(suite)
}

func RunPolicyRuleTestSuite(root string, suitePath string) []Issue {
	suite, issues, err := LoadPolicyRuleTestSuite(root, suitePath)
	if err != nil {
		return []Issue{{Path: suitePath, Message: err.Error()}}
	}
	if len(issues) != 0 {
		return issues
	}
	policyRel := strings.TrimSpace(suite.Policy)
	if policyRel == "" {
		policyRel = policyRelForSuite(suite.RelPath)
	}
	rule, ruleIssues, err := LoadPolicyRuleFile(root, filepath.Join(root, filepath.FromSlash(policyRel)))
	if err != nil {
		return []Issue{{Path: suite.RelPath, Message: err.Error()}}
	}
	if len(ruleIssues) != 0 {
		out := make([]Issue, 0, len(ruleIssues))
		for _, issue := range ruleIssues {
			out = append(out, Issue{Path: suite.RelPath, Message: "policy " + issue.Path + ": " + issue.Message})
		}
		return out
	}
	var out []Issue
	for idx, testCase := range suite.Cases {
		if caseIssues := validatePolicyRuleTestCaseAgainstRule(suite.RelPath, rule, idx, testCase); len(caseIssues) != 0 {
			out = append(out, caseIssues...)
			continue
		}
		if testCase.GraphFixture != nil {
			// The normal policy test lane validates the topology contract. The
			// graph integration lane executes these cases against Neo4j.
			continue
		}
		got, err := EvaluatePolicyRuleTestCase(rule, testCase)
		if err != nil {
			out = append(out, Issue{Path: suite.RelPath, Message: fmt.Sprintf("cases[%d] %q: %v", idx, testCase.Name, err)})
			continue
		}
		if got != testCase.WantFinding {
			out = append(out, Issue{Path: suite.RelPath, Message: fmt.Sprintf("cases[%d] %q: finding = %t, want %t", idx, testCase.Name, got, testCase.WantFinding)})
		}
	}
	return out
}

// RunPolicyRuleTestSuiteWithGraphStore projects each authored topology and
// executes the policy's real Cypher through the production graph boundary.
func RunPolicyRuleTestSuiteWithGraphStore(ctx context.Context, root string, suitePath string, store PolicyGraphTestStore) []Issue {
	suite, issues, err := LoadPolicyRuleTestSuite(root, suitePath)
	if err != nil {
		return []Issue{{Path: suitePath, Message: err.Error()}}
	}
	if len(issues) != 0 {
		return issues
	}
	policyRel := strings.TrimSpace(suite.Policy)
	if policyRel == "" {
		policyRel = policyRelForSuite(suite.RelPath)
	}
	rule, ruleIssues, err := LoadPolicyRuleFile(root, filepath.Join(root, filepath.FromSlash(policyRel)))
	if err != nil {
		return []Issue{{Path: suite.RelPath, Message: err.Error()}}
	}
	if len(ruleIssues) != 0 {
		return ruleIssues
	}
	if strings.TrimSpace(rule.Spec.Graph.Query) == "" {
		return []Issue{{Path: suite.RelPath, Message: "graphFixture requires spec.graph.query"}}
	}
	var out []Issue
	for idx, testCase := range suite.Cases {
		if testCase.GraphFixture == nil {
			continue
		}
		if err := runPolicyGraphFixture(ctx, store, rule, testCase); err != nil {
			out = append(out, Issue{Path: suite.RelPath, Message: fmt.Sprintf("cases[%d] %q: %v", idx, testCase.Name, err)})
		}
	}
	return out
}

func EvaluatePolicyRuleTestCase(rule PolicyFindingRule, testCase PolicyRuleTestCase) (bool, error) {
	if strings.TrimSpace(rule.Spec.Graph.Query) != "" {
		for _, row := range testCase.QueryRows {
			if strings.TrimSpace(fmt.Sprintf("%v", row["primary_urn"])) != "" {
				return true, nil
			}
		}
		return false, nil
	}
	if strings.TrimSpace(rule.Spec.Match.Query) != "" {
		return len(testCase.QueryRows) != 0, nil
	}
	conditions := trimStrings(rule.Spec.Match.Conditions)
	if len(conditions) == 0 {
		return false, fmt.Errorf("policy has no conditions to evaluate")
	}
	return EvaluatePolicyConditions(conditions, PolicyResource(testCase.Resource))
}

func validatePolicyRuleTestCaseAgainstRule(path string, rule PolicyFindingRule, idx int, testCase PolicyRuleTestCase) []Issue {
	if testCase.GraphFixture != nil {
		if strings.TrimSpace(rule.Spec.Graph.Query) == "" {
			return []Issue{{Path: path, Message: fmt.Sprintf("cases[%d] %q graphFixture requires spec.graph.query", idx, testCase.Name)}}
		}
		if len(testCase.Resource) != 0 || len(testCase.QueryRows) != 0 {
			return []Issue{{Path: path, Message: fmt.Sprintf("cases[%d] %q graphFixture cannot be combined with resource or queryRows", idx, testCase.Name)}}
		}
		return nil
	}
	if strings.TrimSpace(rule.Spec.Graph.Query) == "" {
		return nil
	}
	var issues []Issue
	findingRows := 0
	requiredColumns := graphFixtureRequiredColumns(rule.Spec.Graph)
	for rowIdx, row := range testCase.QueryRows {
		if len(row) == 0 {
			issues = append(issues, Issue{Path: path, Message: fmt.Sprintf("cases[%d] %q queryRows[%d] must not be empty", idx, testCase.Name, rowIdx)})
			continue
		}
		if !testFixtureValuePresent(row["primary_urn"]) {
			issues = append(issues, Issue{Path: path, Message: fmt.Sprintf("cases[%d] %q queryRows[%d].primary_urn is required for graph rows", idx, testCase.Name, rowIdx)})
			continue
		}
		findingRows++
		for _, column := range requiredColumns {
			value, ok := row[column]
			if !ok {
				if graphFixtureSystemRequiredColumn(column) {
					issues = append(issues, Issue{Path: path, Message: fmt.Sprintf("cases[%d] %q queryRows[%d].%s is a required graph return alias", idx, testCase.Name, rowIdx, column)})
				} else {
					issues = append(issues, Issue{Path: path, Message: fmt.Sprintf("cases[%d] %q queryRows[%d].%s is required by spec.graph.requiredColumns", idx, testCase.Name, rowIdx, column)})
				}
				continue
			}
			if graphFixtureColumnRequiresValue(column) && !testFixtureValuePresent(value) {
				issues = append(issues, Issue{Path: path, Message: fmt.Sprintf("cases[%d] %q queryRows[%d].%s must be non-empty", idx, testCase.Name, rowIdx, column)})
			}
		}
		if severity := strings.TrimSpace(fmt.Sprintf("%v", row["severity"])); severity != "" && severity != "<nil>" {
			if !stringSetContains([]string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}, strings.ToUpper(severity)) {
				issues = append(issues, Issue{Path: path, Message: fmt.Sprintf("cases[%d] %q queryRows[%d].severity must be one of info, low, medium, high, critical", idx, testCase.Name, rowIdx)})
			}
		}
		if value, ok := row["resource_urns"]; ok && !testFixtureStringList(value) {
			issues = append(issues, Issue{Path: path, Message: fmt.Sprintf("cases[%d] %q queryRows[%d].resource_urns must be a list of strings", idx, testCase.Name, rowIdx)})
		}
		if value, ok := row["evidence"]; ok && !testFixtureEvidenceList(value) {
			issues = append(issues, Issue{Path: path, Message: fmt.Sprintf("cases[%d] %q queryRows[%d].evidence must be a list of maps with urn fields", idx, testCase.Name, rowIdx)})
		}
	}
	if testCase.WantFinding && findingRows == 0 {
		issues = append(issues, Issue{Path: path, Message: fmt.Sprintf("cases[%d] %q must include at least one graph query row with primary_urn", idx, testCase.Name)})
	}
	if !testCase.WantFinding && findingRows != 0 {
		issues = append(issues, Issue{Path: path, Message: fmt.Sprintf("cases[%d] %q is a passing graph case but includes %d finding row(s)", idx, testCase.Name, findingRows)})
	}
	return issues
}

func graphFixtureRequiredColumns(graph PolicyRuleGraphFinding) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, column := range append(requiredGraphReturnAliases(), graph.RequiredColumns...) {
		column = strings.TrimSpace(column)
		if column == "" {
			continue
		}
		if _, ok := seen[column]; ok {
			continue
		}
		seen[column] = struct{}{}
		out = append(out, column)
	}
	return out
}

func graphFixtureColumnRequiresValue(column string) bool {
	switch strings.TrimSpace(column) {
	case "primary_urn", "fingerprint_key", "summary":
		return true
	default:
		return false
	}
}

func graphFixtureSystemRequiredColumn(column string) bool {
	for _, required := range requiredGraphReturnAliases() {
		if column == required {
			return true
		}
	}
	return false
}

func testFixtureValuePresent(value any) bool {
	if value == nil {
		return false
	}
	text := strings.TrimSpace(fmt.Sprintf("%v", value))
	return text != "" && text != "<nil>"
}

func testFixtureStringList(value any) bool {
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			if !testFixtureValuePresent(item) {
				return false
			}
		}
		return true
	case []string:
		for _, item := range typed {
			if strings.TrimSpace(item) == "" {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func testFixtureEvidenceList(value any) bool {
	items, ok := value.([]any)
	if !ok {
		return false
	}
	for _, item := range items {
		entry, ok := item.(map[string]any)
		if !ok {
			return false
		}
		if !testFixtureValuePresent(entry["urn"]) {
			return false
		}
	}
	return true
}

func isPolicyTestRelPath(path string) bool {
	return strings.HasSuffix(path, ".test.yaml") || strings.HasSuffix(path, ".test.yml")
}

func policyRelForSuite(path string) string {
	if strings.HasSuffix(path, ".test.yaml") {
		return strings.TrimSuffix(path, ".test.yaml") + ".yaml"
	}
	return strings.TrimSuffix(path, ".test.yml") + ".yml"
}
