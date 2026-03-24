package policy

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestEngineLoadPolicies(t *testing.T) {
	dir := t.TempDir()

	policyJSON := `{
		"id": "test-policy",
		"name": "Test Policy",
		"description": "Test description",
		"effect": "forbid",
		"resource": "aws::s3::bucket",
		"condition_format": "cel",
		"conditions": ["resource.public == true"],
		"severity": "high",
		"tags": ["test"]
	}`

	if err := os.WriteFile(filepath.Join(dir, "test.json"), []byte(policyJSON), 0644); err != nil {
		t.Fatal(err)
	}

	engine := NewEngine()
	if err := engine.LoadPolicies(dir); err != nil {
		t.Fatalf("LoadPolicies failed: %v", err)
	}

	policies := engine.ListPolicies()
	if len(policies) != 1 {
		t.Errorf("expected 1 policy, got %d", len(policies))
	}

	p, ok := engine.GetPolicy("test-policy")
	if !ok {
		t.Fatal("policy not found")
	}
	if p.Name != "Test Policy" {
		t.Errorf("expected name 'Test Policy', got '%s'", p.Name)
	}
	if p.Severity != "high" {
		t.Errorf("expected severity 'high', got '%s'", p.Severity)
	}
}

func TestEngineEvaluateAsset(t *testing.T) {
	engine := NewEngine()
	engine.AddPolicy(&Policy{
		ID:              "no-public-buckets",
		Name:            "No Public Buckets",
		Description:     "S3 buckets should not be public",
		Effect:          "forbid",
		ConditionFormat: ConditionFormatCEL,
		Conditions:      []string{"resource.public == true"},
		Severity:        "critical",
	})

	tests := []struct {
		name         string
		asset        map[string]interface{}
		wantFindings int
	}{
		{
			name:         "public bucket - violation",
			asset:        map[string]interface{}{"_cq_id": "123", "name": "my-bucket", "public": true},
			wantFindings: 1,
		},
		{
			name:         "private bucket - no violation",
			asset:        map[string]interface{}{"_cq_id": "456", "name": "private-bucket", "public": false},
			wantFindings: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, err := engine.EvaluateAsset(context.Background(), tt.asset)
			if err != nil {
				t.Fatalf("EvaluateAsset failed: %v", err)
			}
			if len(findings) != tt.wantFindings {
				t.Errorf("expected %d findings, got %d", tt.wantFindings, len(findings))
			}
		})
	}
}

func TestEngineEvaluate(t *testing.T) {
	engine := NewEngine()
	engine.AddPolicy(&Policy{
		ID:          "deny-delete",
		Name:        "Deny Delete",
		Description: "Deny delete actions",
		Effect:      "forbid",
		Action:      "delete",
	})

	resp, err := engine.Evaluate(context.Background(), &EvalRequest{
		Action:   "delete",
		Resource: map[string]interface{}{"type": "bucket"},
	})
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	if resp.Decision != "deny" {
		t.Errorf("expected decision 'deny', got '%s'", resp.Decision)
	}
	if len(resp.Matched) != 1 {
		t.Errorf("expected 1 matched policy, got %d", len(resp.Matched))
	}
}

func TestConditionEvaluation(t *testing.T) {
	tests := []struct {
		condition string
		asset     map[string]interface{}
		want      bool
	}{
		{"cmp_eq(path(resource, \"enabled\"), true)", map[string]interface{}{"enabled": "true"}, true},
		{"cmp_eq(path(resource, \"enabled\"), true)", map[string]interface{}{"enabled": "false"}, false},
		{"cmp_ne(path(resource, \"enabled\"), true)", map[string]interface{}{"enabled": "false"}, true},
		{"cmp_ne(path(resource, \"enabled\"), true)", map[string]interface{}{"enabled": "true"}, false},
		{"cmp_eq(path(resource, \"missing\"), true)", map[string]interface{}{"other": "value"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.condition, func(t *testing.T) {
			got, err := evaluateConditionExpression(tt.condition, tt.asset)
			if err != nil {
				t.Fatalf("evaluateConditionExpression(%q) failed: %v", tt.condition, err)
			}
			if got != tt.want {
				t.Errorf("evaluateConditionExpression(%q, %v) = %v, want %v", tt.condition, tt.asset, got, tt.want)
			}
		})
	}
}
