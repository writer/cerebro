package policy

import (
	"testing"

	"github.com/writer/cerebro/internal/findingdsl"
)

func TestProvePassesProtectedAndRejectsWeakenedPolicy(t *testing.T) {
	artifacts, err := Author(Intent{ID: "public-bucket", Domain: "aws", Name: "Public bucket", Description: "Flags public buckets.", Severity: "high", Conditions: []string{`cmp_eq(path(resource, "public"), true)`, `cmp_eq(path(resource, "approved"), false)`}, Frameworks: []findingdsl.PolicyFramework{{Name: "CIS", Controls: []string{"1"}}}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := Prove(artifacts)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Receipts) != 2 || !result.Receipts[0].Passed || !result.Receipts[1].Passed {
		t.Fatalf("receipts = %#v", result.Receipts)
	}
	if result.PolicyDigest == "" || result.TestDigest == "" {
		t.Fatalf("missing digests: %#v", result)
	}
}

func TestProveRejectsSuiteThatSurvivesMutation(t *testing.T) {
	artifacts, err := Author(Intent{ID: "public-bucket", Domain: "aws", Name: "Public bucket", Description: "Flags public buckets.", Severity: "high", Conditions: []string{`cmp_eq(path(resource, "public"), true)`, `cmp_eq(path(resource, "approved"), false)`}, Frameworks: []findingdsl.PolicyFramework{{Name: "CIS", Controls: []string{"1"}}}})
	if err != nil {
		t.Fatal(err)
	}
	artifacts.Suite.Cases = artifacts.Suite.Cases[:1]
	result, err := Prove(artifacts)
	if err == nil {
		t.Fatal("Prove() error = nil")
	}
	if len(result.Receipts) != 2 || result.Receipts[1].Passed {
		t.Fatalf("receipts = %#v", result.Receipts)
	}
}
