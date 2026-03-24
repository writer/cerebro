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
		"condition_format": "cel",
		"conditions": ["resource.public == true"]
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
		"condition_format": "cel",
		"conditions": ["resource.public == true"]
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
		"condition_format": "cel",
		"conditions": ["resource.public == true"],
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
		"condition_format": "cel",
		"conditions": ["resource.public == true"]
	}`)

	writePolicyFile(t, dir, "b.json", `{
		"id": "duplicate-id",
		"name": "Second",
		"description": "second",
		"severity": "high",
		"resource": "aws::ec2::instance",
		"condition_format": "cel",
		"conditions": ["resource.public_ip != null"]
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
		"condition_format": "cel",
		"conditions": ["resource.public == true"]
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
		"condition_format": "cel",
		"conditions": ["resource.public == true"]
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

func TestEngineLoadPolicies_NormalizesConditionFormat(t *testing.T) {
	dir := t.TempDir()

	writePolicyFile(t, dir, "policy.json", `{
		"id": "cel-format",
		"name": "CEL Format",
		"description": "test",
		"severity": "high",
		"resource": "aws::s3::bucket",
		"condition_format": "CEL",
		"conditions": ["resource.public == true"]
	}`)

	engine := NewEngine()
	if err := engine.LoadPolicies(dir); err != nil {
		t.Fatalf("LoadPolicies failed: %v", err)
	}

	p, ok := engine.GetPolicy("cel-format")
	if !ok {
		t.Fatal("expected policy to load")
	}
	if p.ConditionFormat != ConditionFormatCEL {
		t.Fatalf("expected condition format %q, got %q", ConditionFormatCEL, p.ConditionFormat)
	}
}

func TestEngineLoadPolicies_DefaultsConditionFormatToCEL(t *testing.T) {
	dir := t.TempDir()

	writePolicyFile(t, dir, "policy.json", `{
		"id": "default-cel-format",
		"name": "Default CEL Format",
		"description": "test",
		"severity": "high",
		"resource": "aws::s3::bucket",
		"conditions": ["resource.public == true"]
	}`)

	engine := NewEngine()
	if err := engine.LoadPolicies(dir); err != nil {
		t.Fatalf("LoadPolicies failed: %v", err)
	}

	p, ok := engine.GetPolicy("default-cel-format")
	if !ok {
		t.Fatal("expected policy to load")
	}
	if p.ConditionFormat != ConditionFormatCEL {
		t.Fatalf("expected default condition format %q, got %q", ConditionFormatCEL, p.ConditionFormat)
	}
}

func TestEngineLoadPolicies_RejectsLegacyConditionFormat(t *testing.T) {
	dir := t.TempDir()

	writePolicyFile(t, dir, "policy.json", `{
		"id": "legacy-format",
		"name": "Legacy Format",
		"description": "test",
		"severity": "high",
		"resource": "aws::s3::bucket",
		"condition_format": "legacy",
		"conditions": ["public == true"]
	}`)

	engine := NewEngine()
	err := engine.LoadPolicies(dir)
	if err == nil {
		t.Fatal("expected legacy condition format error")
	}
	if !strings.Contains(err.Error(), "legacy condition_format is no longer supported") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEngineLoadPolicies_RejectsUnsupportedConditionFormat(t *testing.T) {
	dir := t.TempDir()

	writePolicyFile(t, dir, "policy.json", `{
		"id": "invalid-format",
		"name": "Invalid Format",
		"description": "test",
		"severity": "high",
		"resource": "aws::s3::bucket",
		"condition_format": "rego",
		"conditions": ["public == true"]
	}`)

	engine := NewEngine()
	err := engine.LoadPolicies(dir)
	if err == nil {
		t.Fatal("expected unsupported condition format error")
	}
	if !strings.Contains(err.Error(), "unsupported condition_format") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEngineLoadPolicies_RejectsInvalidCELCondition(t *testing.T) {
	dir := t.TempDir()

	writePolicyFile(t, dir, "policy.json", `{
		"id": "invalid-cel",
		"name": "Invalid CEL",
		"description": "test",
		"severity": "high",
		"resource": "aws::s3::bucket",
		"condition_format": "cel",
		"conditions": ["resource.public =="]
	}`)

	engine := NewEngine()
	err := engine.LoadPolicies(dir)
	if err == nil {
		t.Fatal("expected invalid CEL condition error")
	}
	if !strings.Contains(err.Error(), "invalid CEL condition") {
		t.Fatalf("unexpected error: %v", err)
	}
}
