package policy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/writer/cerebro/internal/findingdsl"
)

var domainPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

type Intent struct {
	ID               string                       `json:"id" yaml:"id"`
	Domain           string                       `json:"domain" yaml:"domain"`
	Name             string                       `json:"name" yaml:"name"`
	Description      string                       `json:"description" yaml:"description"`
	Severity         string                       `json:"severity" yaml:"severity"`
	Resource         string                       `json:"resource" yaml:"resource"`
	Conditions       []string                     `json:"conditions" yaml:"conditions"`
	References       []string                     `json:"references,omitempty" yaml:"references,omitempty"`
	Tags             []string                     `json:"tags,omitempty" yaml:"tags,omitempty"`
	RiskCategories   []string                     `json:"riskCategories,omitempty" yaml:"riskCategories,omitempty"`
	Frameworks       []findingdsl.PolicyFramework `json:"frameworks" yaml:"frameworks"`
	Remediation      string                       `json:"remediation" yaml:"remediation"`
	RemediationSteps []string                     `json:"remediationSteps,omitempty" yaml:"remediationSteps,omitempty"`
}

type Artifacts struct {
	PolicyPath string
	PolicyYAML []byte
	TestPath   string
	TestYAML   []byte
	Rule       findingdsl.PolicyFindingRule
	Suite      findingdsl.PolicyRuleTestSuite
}

func Author(intent Intent) (Artifacts, error) {
	rule := findingdsl.NewPolicyRule(findingdsl.NewPolicyRuleInput{
		ID: intent.ID, Domain: intent.Domain, Name: intent.Name, Description: intent.Description,
		Severity: intent.Severity, Resource: intent.Resource, Conditions: intent.Conditions,
		References: intent.References, Tags: intent.Tags, RiskCategories: intent.RiskCategories,
		Frameworks: intent.Frameworks, Remediation: intent.Remediation, RemediationStep: intent.RemediationSteps,
	})
	return ArtifactsForRule(intent.Domain, rule)
}

func ArtifactsForRule(domain string, rule findingdsl.PolicyFindingRule) (Artifacts, error) {
	return artifactsForRule(domain, rule, SuiteForRule)
}

// ArtifactsForRuleWithGraphEvidence derives deterministic multi-hop fixtures
// from typed evidence. Evidence node IDs are local handles: authored fixtures
// never copy source URNs, labels, or other resource identifiers.
func ArtifactsForRuleWithGraphEvidence(ctx context.Context, domain string, rule findingdsl.PolicyFindingRule, evidence *GraphEvidence) (Artifacts, error) {
	return artifactsForRule(domain, rule, func(rule findingdsl.PolicyFindingRule) (findingdsl.PolicyRuleTestSuite, error) {
		if evidence == nil {
			return findingdsl.PolicyRuleTestSuite{}, ErrGraphEvidenceRequired
		}
		if strings.TrimSpace(rule.Spec.Graph.Query) == "" {
			return findingdsl.PolicyRuleTestSuite{}, errors.New("graph evidence requires a policy with spec.graph.query")
		}
		return SuiteForGraphRule(ctx, rule, *evidence)
	})
}

func artifactsForRule(domain string, rule findingdsl.PolicyFindingRule, buildSuite func(findingdsl.PolicyFindingRule) (findingdsl.PolicyRuleTestSuite, error)) (Artifacts, error) {
	domain = strings.TrimSpace(domain)
	if !domainPattern.MatchString(domain) {
		return Artifacts{}, fmt.Errorf("policy domain %q must use lowercase dash-separated alphanumeric segments", domain)
	}
	rule = findingdsl.NormalizePolicyRule(rule)
	rule.Domain = domain
	rule.RelPath = findingdsl.PolicyRuleRelPath(domain, rule.Metadata.ID)
	if issues := findingdsl.ValidatePolicyRule(rule); len(issues) != 0 {
		return Artifacts{}, fmt.Errorf("authored policy is invalid: %s", joinIssues(issues))
	}
	suite, err := buildSuite(rule)
	if err != nil {
		return Artifacts{}, err
	}
	policyYAML, err := findingdsl.FormatPolicyRuleYAML(rule)
	if err != nil {
		return Artifacts{}, err
	}
	testYAML, err := findingdsl.FormatPolicyRuleTestSuiteYAML(suite)
	if err != nil {
		return Artifacts{}, err
	}
	policyCheck, err := findingdsl.FormatPolicyRuleYAML(rule)
	if err != nil {
		return Artifacts{}, err
	}
	testCheck, err := findingdsl.FormatPolicyRuleTestSuiteYAML(suite)
	if err != nil {
		return Artifacts{}, err
	}
	if !bytes.Equal(policyYAML, policyCheck) || !bytes.Equal(testYAML, testCheck) {
		return Artifacts{}, errors.New("authored policy artifacts are not reproducible")
	}
	testPath := strings.TrimSuffix(rule.RelPath, filepath.Ext(rule.RelPath)) + ".test.yaml"
	return Artifacts{PolicyPath: rule.RelPath, PolicyYAML: policyYAML, TestPath: testPath, TestYAML: testYAML, Rule: rule, Suite: suite}, nil
}

func SuiteForRule(rule findingdsl.PolicyFindingRule) (findingdsl.PolicyRuleTestSuite, error) {
	if strings.TrimSpace(rule.Spec.Graph.Query) != "" {
		return findingdsl.PolicyRuleTestSuite{}, ErrGraphEvidenceRequired
	}
	finding, passing, err := findingdsl.SynthesizeEqualityConditionFixtures(rule.Spec.Match.Conditions)
	if err != nil {
		return findingdsl.PolicyRuleTestSuite{}, fmt.Errorf("author policy tests: %w", err)
	}
	suite := findingdsl.PolicyRuleTestSuite{APIVersion: findingdsl.APIVersion, Kind: findingdsl.KindPolicyFindingRuleTest, Cases: []findingdsl.PolicyRuleTestCase{
		{Name: "matching resource produces a finding", Resource: finding, WantFinding: true},
		{Name: "non-matching resource passes", Resource: passing, WantFinding: false},
	}}
	if issues := findingdsl.ValidatePolicyRuleTestSuite(suite); len(issues) != 0 {
		return suite, fmt.Errorf("authored test suite is invalid: %s", joinIssues(issues))
	}
	for _, testCase := range suite.Cases {
		got, evalErr := findingdsl.EvaluatePolicyRuleTestCase(rule, testCase)
		if evalErr != nil {
			return suite, fmt.Errorf("prove authored case %q: %w", testCase.Name, evalErr)
		}
		if got != testCase.WantFinding {
			return suite, fmt.Errorf("prove authored case %q: finding=%t want=%t", testCase.Name, got, testCase.WantFinding)
		}
	}
	return suite, nil
}

func joinIssues(issues []findingdsl.Issue) string {
	messages := make([]string, 0, len(issues))
	for _, issue := range issues {
		messages = append(messages, issue.Path+": "+issue.Message)
	}
	return strings.Join(messages, "; ")
}

func IsSupported(rule findingdsl.PolicyFindingRule) bool {
	if strings.TrimSpace(rule.Spec.Graph.Query) != "" {
		return false
	}
	_, _, err := findingdsl.SynthesizeEqualityConditionFixtures(rule.Spec.Match.Conditions)
	return err == nil
}

var ErrExistingTestSuite = errors.New("policy already has a test suite")
