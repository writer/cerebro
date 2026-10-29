package cloudidentity

import (
	"testing"
)

func testReference() Reference {
	return Reference{Repository: "example/repo", Revision: "abc123", Path: "main.tf", Digest: "sha256:test"}
}

func TestParseAWSPolicyIdentityStatement(t *testing.T) {
	doc := []byte(`{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Sid": "ReadBucket",
				"Effect": "Allow",
				"Action": ["s3:GetObject", "s3:ListBucket"],
				"Resource": "arn:aws:s3:::my-bucket/*"
			}
		]
	}`)
	grants, err := ParseAWSPolicy(doc, testReference())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(grants) != 1 {
		t.Fatalf("expected 1 grant, got %d", len(grants))
	}
	g := grants[0]
	if g.ID != "ReadBucket" {
		t.Errorf("ID = %q, want ReadBucket", g.ID)
	}
	if g.Effect != "Allow" {
		t.Errorf("Effect = %q, want Allow", g.Effect)
	}
	if len(g.Actions) != 2 || g.Actions[0] != "s3:GetObject" {
		t.Errorf("Actions = %v", g.Actions)
	}
	if len(g.Resources) != 1 || g.Resources[0] != "arn:aws:s3:::my-bucket/*" {
		t.Errorf("Resources = %v", g.Resources)
	}
	if len(g.References) != 1 || g.References[0].Digest != "sha256:test" {
		t.Errorf("References not preserved: %v", g.References)
	}
}

func TestParseAWSPolicySingleStatementObject(t *testing.T) {
	doc := []byte(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}`)
	grants, err := ParseAWSPolicy(doc, testReference())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(grants) != 1 {
		t.Fatalf("expected 1 grant, got %d", len(grants))
	}
	if grants[0].ID != "statement-0" {
		t.Errorf("ID = %q, want synthesized statement-0", grants[0].ID)
	}
}

func TestParseAWSPolicyNotActionNotResourcePreserved(t *testing.T) {
	doc := []byte(`{
		"Statement": [{
			"Sid": "DenyDangerous",
			"Effect": "Deny",
			"NotAction": ["s3:GetObject"],
			"NotResource": ["arn:aws:s3:::safe-bucket/*"]
		}]
	}`)
	grants, err := ParseAWSPolicy(doc, testReference())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	g := grants[0]
	if len(g.Actions) != 0 {
		t.Errorf("Actions should be empty, got %v", g.Actions)
	}
	if len(g.NotActions) != 1 || g.NotActions[0] != "s3:GetObject" {
		t.Errorf("NotActions = %v", g.NotActions)
	}
	if len(g.NotResources) != 1 || g.NotResources[0] != "arn:aws:s3:::safe-bucket/*" {
		t.Errorf("NotResources = %v", g.NotResources)
	}
	if len(g.Resources) != 0 {
		t.Errorf("Resources should be empty, got %v", g.Resources)
	}
}

func TestParseAWSPolicyConditionPreserved(t *testing.T) {
	doc := []byte(`{
		"Statement": [{
			"Effect": "Allow",
			"Action": "s3:GetObject",
			"Resource": "*",
			"Condition": {
				"StringEquals": {"aws:PrincipalTag/env": ["prod", "staging"]}
			}
		}]
	}`)
	grants, err := ParseAWSPolicy(doc, testReference())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	g := grants[0]
	if len(g.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d: %+v", len(g.Conditions), g.Conditions)
	}
	c := g.Conditions[0]
	if c.Operator != "StringEquals" || c.Key != "aws:PrincipalTag/env" {
		t.Errorf("condition = %+v", c)
	}
	if len(c.Values) != 2 {
		t.Errorf("condition values = %v", c.Values)
	}
}

func TestParseAWSPolicyTrustPrincipalMembers(t *testing.T) {
	doc := []byte(`{
		"Statement": [{
			"Effect": "Allow",
			"Action": "sts:AssumeRoleWithWebIdentity",
			"Principal": {"Federated": "arn:aws:iam::111111111111:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE"},
			"Condition": {
				"StringEquals": {"oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE:sub": "system:serviceaccount:ns1:sa1"}
			}
		}]
	}`)
	grants, err := ParseAWSPolicy(doc, testReference())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	g := grants[0]
	if len(g.Members) != 1 || g.Members[0] != "Federated:arn:aws:iam::111111111111:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE" {
		t.Errorf("Members = %v", g.Members)
	}
	if len(g.Resources) != 0 {
		t.Errorf("trust statement Resources should stay empty, got %v", g.Resources)
	}
}

func TestParseAWSPolicyWildcardPrincipal(t *testing.T) {
	doc := []byte(`{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Principal":"*"}]}`)
	grants, err := ParseAWSPolicy(doc, testReference())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(grants[0].Members) != 1 || grants[0].Members[0] != "*" {
		t.Errorf("Members = %v, want untyped wildcard", grants[0].Members)
	}
}

func TestParseAWSPolicyNotPrincipalBecomesUnsupportedCondition(t *testing.T) {
	doc := []byte(`{
		"Statement": [{
			"Effect": "Allow",
			"Action": "s3:GetObject",
			"Resource": "*",
			"NotPrincipal": {"AWS": "arn:aws:iam::222222222222:root"}
		}]
	}`)
	grants, err := ParseAWSPolicy(doc, testReference())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	g := grants[0]
	found := false
	for _, c := range g.Conditions {
		if c.Operator == "Unsupported" && c.Key == "aws:NotPrincipal" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a synthetic Unsupported condition flagging NotPrincipal, got %+v", g.Conditions)
	}
}

func TestParseAWSPolicyResourceOmissionNeverDefaultsToWildcard(t *testing.T) {
	// An identity-shaped statement (no Principal) that omits Resource must
	// never be silently treated as "*".
	doc := []byte(`{"Statement":[{"Effect":"Allow","Action":"s3:GetObject"}]}`)
	grants, err := ParseAWSPolicy(doc, testReference())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if grants[0].Resources != nil {
		t.Errorf("Resources = %v, want nil/empty (never defaulted to *)", grants[0].Resources)
	}
}

func TestParseAWSPolicyMissingActionAndNotActionErrors(t *testing.T) {
	doc := []byte(`{"Statement":[{"Effect":"Allow","Resource":"*"}]}`)
	if _, err := ParseAWSPolicy(doc, testReference()); err == nil {
		t.Fatal("expected error for statement with neither Action nor NotAction")
	}
}

func TestParseAWSPolicyUnsupportedEffectErrors(t *testing.T) {
	doc := []byte(`{"Statement":[{"Effect":"Maybe","Action":"s3:GetObject","Resource":"*"}]}`)
	if _, err := ParseAWSPolicy(doc, testReference()); err == nil {
		t.Fatal("expected error for unsupported Effect")
	}
}

func TestParseAWSPolicyInvalidJSONErrors(t *testing.T) {
	if _, err := ParseAWSPolicy([]byte("not json"), testReference()); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParseAWSPolicyNoStatementsErrors(t *testing.T) {
	if _, err := ParseAWSPolicy([]byte(`{"Version":"2012-10-17"}`), testReference()); err == nil {
		t.Fatal("expected error for missing Statement")
	}
}
