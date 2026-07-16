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
	intent := Intent{ID: "complex", Domain: "aws", Name: "Complex", Description: "Complex policy.", Severity: "high", Conditions: []string{`cmp_ne(path(resource, "state"), "safe")`}, Frameworks: []findingdsl.PolicyFramework{{Name: "CIS", Controls: []string{"1"}}}}
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
