package scanner

import (
	"context"
	"testing"

	"github.com/writer/cerebro/internal/policy"
	"github.com/writer/cerebro/internal/testutil"
)

type fakePolicyEvaluator struct {
	findings []policy.Finding
	policies []*policy.Policy
}

func (f *fakePolicyEvaluator) EvaluateAsset(_ context.Context, _ map[string]interface{}) ([]policy.Finding, error) {
	return append([]policy.Finding(nil), f.findings...), nil
}

func (f *fakePolicyEvaluator) ListPolicies() []*policy.Policy {
	return append([]*policy.Policy(nil), f.policies...)
}

func TestNewScannerAcceptsPolicyEvaluatorInterface(t *testing.T) {
	scanner := NewScanner(&fakePolicyEvaluator{
		findings: []policy.Finding{{ID: "finding-1"}},
		policies: []*policy.Policy{{ID: "policy-1"}},
	}, ScanConfig{Workers: 1, BatchSize: 1}, testutil.Logger())

	result := scanner.ScanAssets(context.Background(), []map[string]interface{}{
		{"_cq_id": "asset-1"},
	})
	if result.Scanned != 1 {
		t.Fatalf("scanned = %d, want 1", result.Scanned)
	}
	if len(result.Findings) != 1 || result.Findings[0].ID != "finding-1" {
		t.Fatalf("unexpected findings: %+v", result.Findings)
	}
}
