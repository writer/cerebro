package main

import "testing"

func TestInferRiskCategories(t *testing.T) {
	policy := &Policy{
		Name:        "Public bucket",
		Description: "Unencrypted data exposure",
		Tags:        []string{"public", "s3"},
	}

	categories := inferRiskCategories(policy)
	if !containsString(categories, "EXTERNAL_EXPOSURE") {
		t.Fatalf("expected EXTERNAL_EXPOSURE, got %v", categories)
	}
	if !containsString(categories, "UNPROTECTED_DATA") {
		t.Fatalf("expected UNPROTECTED_DATA, got %v", categories)
	}
}

func TestInferFrameworksFromTags(t *testing.T) {
	policy := &Policy{
		Tags: []string{"cis-aws-1.2", "cis-k8s-4.1"},
	}

	frameworks := inferFrameworks(policy)
	aws := findFramework(frameworks, "CIS AWS Foundations Benchmark v2.0")
	if aws == nil || !containsString(aws.Controls, "1.2") {
		t.Fatalf("expected CIS AWS control 1.2, got %v", frameworks)
	}
	k8s := findFramework(frameworks, "CIS Kubernetes Benchmark")
	if k8s == nil || !containsString(k8s.Controls, "4.1") {
		t.Fatalf("expected CIS K8s control 4.1, got %v", frameworks)
	}
}

func TestEnhancePolicyAddsMetadata(t *testing.T) {
	policy := &Policy{
		Name:        "Public bucket",
		Description: "Public exposure for sensitive data",
		Severity:    "high",
		Tags:        []string{"public", "cis-aws-1.1"},
	}

	if !enhancePolicy(policy) {
		t.Fatalf("expected policy to be enhanced")
	}
	if len(policy.RiskCategories) == 0 {
		t.Fatalf("expected risk categories to be populated")
	}
	if len(policy.Frameworks) == 0 {
		t.Fatalf("expected frameworks to be populated")
	}
	if len(policy.MitreAttack) == 0 {
		t.Fatalf("expected MITRE mappings to be populated")
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func findFramework(values []FrameworkMapping, name string) *FrameworkMapping {
	for i := range values {
		if values[i].Name == name {
			return &values[i]
		}
	}
	return nil
}
