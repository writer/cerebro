package policy

import (
	"context"
	"testing"
)

func TestEvaluateAssetReportsViolationsWithEmptyDescription(t *testing.T) {
	engine := NewEngine()
	engine.AddPolicy(&Policy{
		ID:              "no-desc",
		Name:            "No description policy",
		Effect:          "forbid",
		Resource:        "aws::s3::bucket",
		ConditionFormat: ConditionFormatCEL,
		Conditions:      []string{`cmp_eq(path(resource, "public"), true)`},
		Severity:        "high",
	})
	engine.AddPolicy(&Policy{
		ID:              "has-desc",
		Name:            "Has description policy",
		Description:     "Public bucket detected",
		Effect:          "forbid",
		Resource:        "aws::s3::bucket",
		ConditionFormat: ConditionFormatCEL,
		Conditions:      []string{`cmp_eq(path(resource, "public"), true)`},
		Severity:        "high",
	})

	findings, err := engine.EvaluateAsset(context.Background(), map[string]interface{}{
		"_cq_id":    "res-1",
		"_cq_table": "aws_s3_buckets",
		"public":    true,
	})
	if err != nil {
		t.Fatalf("EvaluateAsset() error = %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings for matching policies, got %d", len(findings))
	}
}

func TestEvaluatePolicyAgainstAssetsCountsViolationsWithEmptyDescription(t *testing.T) {
	engine := NewEngine()
	assets := []map[string]interface{}{
		{
			"_cq_id":    "res-1",
			"_cq_table": "aws_s3_buckets",
			"public":    true,
		},
	}

	result, err := engine.evaluatePolicyAgainstAssets(context.Background(), &Policy{
		ID:              "no-desc",
		Name:            "No description policy",
		Effect:          "forbid",
		Resource:        "aws::s3::bucket",
		ConditionFormat: ConditionFormatCEL,
		Conditions:      []string{`cmp_eq(path(resource, "public"), true)`},
		Severity:        "high",
	}, assets)
	if err != nil {
		t.Fatalf("evaluatePolicyAgainstAssets() error = %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 matching asset, got %d", len(result))
	}
}
