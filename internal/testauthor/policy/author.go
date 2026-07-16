package policy

import (
	"bytes"
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
	domain := strings.TrimSpace(intent.Domain)
	if !domainPattern.MatchString(domain) {
		return Artifacts{}, fmt.Errorf("policy domain %q must use lowercase dash-separated alphanumeric segments", intent.Domain)
	}
	rule := findingdsl.NewPolicyRule(findingdsl.NewPolicyRuleInput{
		ID: intent.ID, Domain: domain, Name: intent.Name, Description: intent.Description,
		Severity: intent.Severity, Resource: intent.Resource, Conditions: intent.Conditions,
		References: intent.References, Tags: intent.Tags, RiskCategories: intent.RiskCategories,
		Frameworks: intent.Frameworks, Remediation: intent.Remediation, RemediationStep: intent.RemediationSteps,
	})
	if issues := findingdsl.ValidatePolicyRule(rule); len(issues) != 0 {
		return Artifacts{}, fmt.Errorf("authored policy is invalid: %s", joinIssues(issues))
	}
	suite, err := SuiteForRule(rule)
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
		if evalErr != nil || got != testCase.WantFinding {
			return suite, fmt.Errorf("prove authored case %q: finding=%t want=%t: %w", testCase.Name, got, testCase.WantFinding, evalErr)
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
	_, _, err := findingdsl.SynthesizeEqualityConditionFixtures(rule.Spec.Match.Conditions)
	return err == nil
}

var ErrExistingTestSuite = errors.New("policy already has a test suite")
