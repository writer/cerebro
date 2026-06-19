package findingdsl

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// LintPolicyRules runs semantic authoring checks that go beyond schema and
// structural validation. It returns validation issues first when the catalog
// cannot be safely linted.
func LintPolicyRules(root string) ([]Issue, error) {
	root = filepath.Clean(root)
	rules, issues, err := LoadPolicyRules(root)
	if err != nil {
		return nil, err
	}
	if len(issues) != 0 {
		return issues, nil
	}
	for _, rule := range rules {
		issues = append(issues, LintPolicyRule(rule)...)
		if policyGraphConfigured(rule.Spec.Graph) {
			issues = append(issues, lintGraphPolicyTestSuite(root, rule)...)
		}
	}
	return issues, nil
}

func LintPolicyRule(rule PolicyFindingRule) []Issue {
	path := rule.RelPath
	if path == "" {
		path = "<policy-rule>"
	}
	if !policyGraphConfigured(rule.Spec.Graph) {
		return nil
	}
	return lintGraphPolicyRule(path, rule.Spec.Graph)
}

func lintGraphPolicyRule(path string, graph PolicyRuleGraphFinding) []Issue {
	var issues []Issue
	query := strings.TrimSpace(graph.Query)
	if query == "" {
		return nil
	}
	if graph.RowLimit == 0 {
		issues = append(issues, Issue{Path: path, Message: "spec.graph.rowLimit should be set explicitly for deterministic graph evaluation"})
	}
	if cypherHasKeyword(query, "LIMIT") && !cypherKeywordAppearsBefore(query, "ORDER BY", "LIMIT") {
		issues = append(issues, Issue{Path: path, Message: "spec.graph.query should ORDER BY stable keys before LIMIT"})
	}
	for _, alias := range recommendedGraphReturnAliases() {
		if !cypherReturnsAlias(query, alias) {
			issues = append(issues, Issue{Path: path, Message: fmt.Sprintf("spec.graph.query should return standard alias %s", alias)})
		}
	}
	return issues
}

func lintGraphPolicyTestSuite(root string, rule PolicyFindingRule) []Issue {
	suiteRel := policyTestRelForRule(rule.RelPath)
	if suiteRel == "" {
		return []Issue{{Path: rule.RelPath, Message: "spec.graph policies must live in a policy YAML file so a fixture suite can be discovered"}}
	}
	info, err := fs.Stat(os.DirFS(root), suiteRel)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []Issue{{Path: rule.RelPath, Message: fmt.Sprintf("spec.graph policies must have a fixture suite at %s", suiteRel)}}
		}
		return []Issue{{Path: rule.RelPath, Message: fmt.Sprintf("read graph fixture suite %s: %v", suiteRel, err)}}
	}
	if info.IsDir() {
		return []Issue{{Path: rule.RelPath, Message: fmt.Sprintf("graph fixture suite %s is a directory", suiteRel)}}
	}
	suite, issues, err := LoadPolicyRuleTestSuite(root, filepath.Join(root, filepath.FromSlash(suiteRel)))
	if err != nil {
		return []Issue{{Path: suiteRel, Message: err.Error()}}
	}
	if len(issues) != 0 {
		return issues
	}
	hasFinding := false
	hasPass := false
	for _, testCase := range suite.Cases {
		if testCase.WantFinding {
			hasFinding = true
		} else {
			hasPass = true
		}
	}
	var out []Issue
	if !hasFinding {
		out = append(out, Issue{Path: suiteRel, Message: "graph fixture suite must include at least one finding case"})
	}
	if !hasPass {
		out = append(out, Issue{Path: suiteRel, Message: "graph fixture suite must include at least one passing case"})
	}
	return out
}

func policyTestRelForRule(rel string) string {
	rel = strings.TrimSpace(rel)
	switch {
	case strings.HasSuffix(rel, ".yaml"):
		return strings.TrimSuffix(rel, ".yaml") + ".test.yaml"
	case strings.HasSuffix(rel, ".yml"):
		return strings.TrimSuffix(rel, ".yml") + ".test.yml"
	default:
		return ""
	}
}
