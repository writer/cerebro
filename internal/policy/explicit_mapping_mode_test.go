package policy

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestEngineUnmappedPolicyResources(t *testing.T) {
	engine := NewEngine()
	engine.AddPolicy(&Policy{ID: "mapped", Resource: "aws::s3::bucket"})
	engine.AddPolicy(&Policy{ID: "unmapped", Resource: "unknown::resource|aws_ec2_instances|*"})

	got := engine.UnmappedPolicyResources()
	want := []string{"aws_ec2_instances", "unknown::resource"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected unmapped resources: got %v want %v", got, want)
	}
}

func TestEngineLoadPolicies_ExplicitMappingsOnlyFailsForUnmapped(t *testing.T) {
	t.Setenv("CEREBRO_POLICY_EXPLICIT_MAPPINGS_ONLY", "true")

	dir := t.TempDir()
	policyJSON := `{
		"id": "test-unmapped",
		"name": "Test Unmapped",
		"description": "Policy for explicit mapping mode test",
		"effect": "forbid",
		"resource": "unknown::resource",
		"conditions": ["resource.enabled == true"],
		"severity": "high"
	}`

	if err := os.WriteFile(filepath.Join(dir, "test.json"), []byte(policyJSON), 0644); err != nil {
		t.Fatal(err)
	}

	engine := NewEngine()
	err := engine.LoadPolicies(dir)
	if err == nil {
		t.Fatal("expected explicit mapping mode to fail for unmapped resources")
	}
	if !strings.Contains(err.Error(), "unmapped policy resources") {
		t.Fatalf("expected unmapped policy resources error, got: %v", err)
	}
}

func TestEngineLoadPolicies_ExplicitMappingsOnlyAllowsMapped(t *testing.T) {
	t.Setenv("CEREBRO_POLICY_EXPLICIT_MAPPINGS_ONLY", "true")

	dir := t.TempDir()
	policyJSON := `{
		"id": "test-mapped",
		"name": "Test Mapped",
		"description": "Policy for explicit mapping mode test",
		"effect": "forbid",
		"resource": "aws::s3::bucket",
		"conditions": ["resource.public == true"],
		"severity": "high"
	}`

	if err := os.WriteFile(filepath.Join(dir, "test.json"), []byte(policyJSON), 0644); err != nil {
		t.Fatal(err)
	}

	engine := NewEngine()
	if err := engine.LoadPolicies(dir); err != nil {
		t.Fatalf("expected policy load to succeed, got: %v", err)
	}
}
