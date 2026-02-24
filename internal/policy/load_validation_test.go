package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writePolicyFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func TestEngineLoadPolicies_SkipsMetadataFiles(t *testing.T) {
	dir := t.TempDir()

	writePolicyFile(t, dir, "control-mapping.json", `{
		"version": "1.0.0",
		"description": "control mapping metadata",
		"controls": {
			"wc-id-1": {"title": "example"}
		}
	}`)

	writePolicyFile(t, dir, "policy.json", `{
		"id": "test-policy",
		"name": "Test Policy",
		"description": "test",
		"severity": "high",
		"effect": "forbid",
		"resource": "aws::s3::bucket",
		"conditions": ["public == true"]
	}`)

	engine := NewEngine()
	if err := engine.LoadPolicies(dir); err != nil {
		t.Fatalf("LoadPolicies failed: %v", err)
	}

	if _, ok := engine.GetPolicy("test-policy"); !ok {
		t.Fatal("expected executable policy to load")
	}

	if len(engine.ListPolicies()) != 1 {
		t.Fatalf("expected 1 loaded policy, got %d", len(engine.ListPolicies()))
	}
}

func TestEngineLoadPolicies_RejectsMissingRequiredFields(t *testing.T) {
	dir := t.TempDir()

	writePolicyFile(t, dir, "invalid.json", `{
		"id": "missing-description",
		"name": "Missing Description",
		"severity": "high",
		"resource": "aws::s3::bucket",
		"conditions": ["public == true"]
	}`)

	engine := NewEngine()
	err := engine.LoadPolicies(dir)
	if err == nil {
		t.Fatal("expected missing required field validation error")
	}
	if !strings.Contains(err.Error(), "missing required field(s): description") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEngineLoadPolicies_RejectsMixedQueryAndConditions(t *testing.T) {
	dir := t.TempDir()

	writePolicyFile(t, dir, "invalid-shape.json", `{
		"id": "mixed-shape",
		"name": "Mixed Shape",
		"description": "invalid shape",
		"severity": "high",
		"resource": "aws::s3::bucket",
		"conditions": ["public == true"],
		"query": "SELECT * FROM aws_s3_buckets"
	}`)

	engine := NewEngine()
	err := engine.LoadPolicies(dir)
	if err == nil {
		t.Fatal("expected mixed shape validation error")
	}
	if !strings.Contains(err.Error(), "query policies cannot include resource or conditions") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEngineLoadPolicies_RejectsDuplicatePolicyIDs(t *testing.T) {
	dir := t.TempDir()

	writePolicyFile(t, dir, "a.json", `{
		"id": "duplicate-id",
		"name": "First",
		"description": "first",
		"severity": "high",
		"resource": "aws::s3::bucket",
		"conditions": ["public == true"]
	}`)

	writePolicyFile(t, dir, "b.json", `{
		"id": "duplicate-id",
		"name": "Second",
		"description": "second",
		"severity": "high",
		"resource": "aws::ec2::instance",
		"conditions": ["public_ip exists"]
	}`)

	engine := NewEngine()
	err := engine.LoadPolicies(dir)
	if err == nil {
		t.Fatal("expected duplicate policy id error")
	}
	if !strings.Contains(err.Error(), "duplicate policy id") || !strings.Contains(err.Error(), "a.json") || !strings.Contains(err.Error(), "b.json") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEngineLoadPolicies_NormalizesSeverity(t *testing.T) {
	dir := t.TempDir()

	writePolicyFile(t, dir, "policy.json", `{
		"id": "severity-normalization",
		"name": "Severity Normalization",
		"description": "test",
		"severity": "CRITICAL",
		"resource": "aws::s3::bucket",
		"conditions": ["public == true"]
	}`)

	engine := NewEngine()
	if err := engine.LoadPolicies(dir); err != nil {
		t.Fatalf("LoadPolicies failed: %v", err)
	}

	p, ok := engine.GetPolicy("severity-normalization")
	if !ok {
		t.Fatal("expected policy to load")
	}
	if p.Severity != "critical" {
		t.Fatalf("expected normalized severity critical, got %q", p.Severity)
	}
}

func TestEngineLoadPolicies_RejectsUnsupportedSeverity(t *testing.T) {
	dir := t.TempDir()

	writePolicyFile(t, dir, "invalid-severity.json", `{
		"id": "invalid-severity",
		"name": "Invalid Severity",
		"description": "test",
		"severity": "urgent",
		"resource": "aws::s3::bucket",
		"conditions": ["public == true"]
	}`)

	engine := NewEngine()
	err := engine.LoadPolicies(dir)
	if err == nil {
		t.Fatal("expected unsupported severity error")
	}
	if !strings.Contains(err.Error(), "unsupported severity") {
		t.Fatalf("unexpected error: %v", err)
	}
}
