package findingdsl

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

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
	Name        string           `json:"name" yaml:"name"`
	Resource    map[string]any   `json:"resource,omitempty" yaml:"resource,omitempty"`
	QueryRows   []map[string]any `json:"queryRows,omitempty" yaml:"queryRows,omitempty"`
	WantFinding bool             `json:"wantFinding" yaml:"wantFinding"`
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
		if len(testCase.Resource) == 0 && len(testCase.QueryRows) == 0 {
			issues = append(issues, Issue{Path: path, Message: fmt.Sprintf("cases[%d] must include resource or queryRows", idx)})
		}
	}
	return issues
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

func EvaluatePolicyRuleTestCase(rule PolicyFindingRule, testCase PolicyRuleTestCase) (bool, error) {
	if strings.TrimSpace(rule.Spec.Match.Query) != "" {
		return len(testCase.QueryRows) != 0, nil
	}
	conditions := trimStrings(rule.Spec.Match.Conditions)
	if len(conditions) == 0 {
		return false, fmt.Errorf("policy has no conditions to evaluate")
	}
	return EvaluatePolicyConditions(conditions, PolicyResource(testCase.Resource))
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
