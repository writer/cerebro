package policy

import (
	"bytes"
	"testing"

	"github.com/writer/cerebro/internal/findingdsl"
)

func TestAuthorWritesRunnablePolicyAndTestsDeterministically(t *testing.T) {
	intent := Intent{ID: "aws-s3-public-access", Domain: "aws", Name: "S3 public access", Description: "Flags buckets with public access enabled.", Severity: "high", Resource: "aws::s3::bucket", Conditions: []string{`cmp_eq(path(resource, "public"), true)`}, Frameworks: []findingdsl.PolicyFramework{{Name: "CIS", Controls: []string{"2.1.5"}}}, Remediation: "Block public access."}
	first, err := Author(intent)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Author(intent)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.PolicyYAML, second.PolicyYAML) || !bytes.Equal(first.TestYAML, second.TestYAML) {
		t.Fatal("authored artifacts are not deterministic")
	}
	if first.PolicyPath != "policies/aws/aws-s3-public-access.yaml" || first.TestPath != "policies/aws/aws-s3-public-access.test.yaml" {
		t.Fatalf("unexpected paths: %s %s", first.PolicyPath, first.TestPath)
	}
	for _, testCase := range first.Suite.Cases {
		got, err := findingdsl.EvaluatePolicyRuleTestCase(first.Rule, testCase)
		if err != nil || got != testCase.WantFinding {
			t.Fatalf("case %q got %t want %t err %v", testCase.Name, got, testCase.WantFinding, err)
		}
	}
}

func TestAuthorRejectsUnsupportedPolicySemantics(t *testing.T) {
	intent := Intent{ID: "complex", Domain: "aws", Name: "Complex", Description: "Complex policy.", Severity: "high", Conditions: []string{`matches_value(path(resource, "state"), "unsafe.*")`}, Frameworks: []findingdsl.PolicyFramework{{Name: "CIS", Controls: []string{"1"}}}}
	if _, err := Author(intent); err == nil {
		t.Fatal("Author() error = nil")
	}
}

func TestAuthorRejectsDomainOutsidePolicyDirectory(t *testing.T) {
	intent := Intent{ID: "example", Domain: "../docs", Name: "Example", Description: "Example policy.", Severity: "high", Conditions: []string{`cmp_eq(path(resource, "enabled"), false)`}, Frameworks: []findingdsl.PolicyFramework{{Name: "CIS", Controls: []string{"1"}}}}
	if _, err := Author(intent); err == nil {
		t.Fatal("Author() error = nil")
	}
}

func TestAuthorBuildsNestedResourceFixtures(t *testing.T) {
	intent := Intent{ID: "nested", Domain: "aws", Name: "Nested", Description: "Nested policy.", Severity: "high", Conditions: []string{`cmp_eq(path(resource, "authentication.type"), "API_KEY")`, `cmp_eq(path(resource, "providers.length"), 0)`}, Frameworks: []findingdsl.PolicyFramework{{Name: "CIS", Controls: []string{"1"}}}}
	artifacts, err := Author(intent)
	if err != nil {
		t.Fatal(err)
	}
	for _, testCase := range artifacts.Suite.Cases {
		got, err := findingdsl.EvaluatePolicyRuleTestCase(artifacts.Rule, testCase)
		if err != nil || got != testCase.WantFinding {
			t.Fatalf("case %q got %t want %t err %v", testCase.Name, got, testCase.WantFinding, err)
		}
	}
	if _, flat := artifacts.Suite.Cases[0].Resource["authentication.type"]; flat {
		t.Fatalf("fixture used a flat nested path: %#v", artifacts.Suite.Cases[0].Resource)
	}
}

func TestAuthorBuildsScalarComparisonFixtures(t *testing.T) {
	tests := []struct{ name, condition string }{
		{name: "not equal", condition: `cmp_ne(path(resource, "compliant"), true)`},
		{name: "greater", condition: `cmp_gt(path(resource, "age_days"), 90)`},
		{name: "less", condition: `cmp_lt(path(resource, "score"), 10)`},
		{name: "greater equal", condition: `cmp_ge(path(resource, "count"), 2)`},
		{name: "less equal", condition: `cmp_le(path(resource, "count"), 2)`},
		{name: "membership", condition: `in_list(path(resource, "state"), ["open","pending"])`},
		{name: "null equality", condition: `cmp_eq(path(resource, "key_id"), null)`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			intent := Intent{ID: "scalar", Domain: "aws", Name: "Scalar", Description: "Scalar policy.", Severity: "high", Conditions: []string{test.condition}, Frameworks: []findingdsl.PolicyFramework{{Name: "CIS", Controls: []string{"1"}}}}
			artifacts, err := Author(intent)
			if err != nil {
				t.Fatal(err)
			}
			for _, testCase := range artifacts.Suite.Cases {
				got, err := findingdsl.EvaluatePolicyRuleTestCase(artifacts.Rule, testCase)
				if err != nil || got != testCase.WantFinding {
					t.Fatalf("case %q got %t want %t err %v", testCase.Name, got, testCase.WantFinding, err)
				}
			}
		})
	}
}
