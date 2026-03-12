package agents

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/writer/cerebro/internal/policy"
)

type fakePolicyEvaluator struct {
	findings []policy.Finding
	assets   []map[string]interface{}
}

func (f *fakePolicyEvaluator) EvaluateAsset(_ context.Context, asset map[string]interface{}) ([]policy.Finding, error) {
	f.assets = append(f.assets, asset)
	return append([]policy.Finding(nil), f.findings...), nil
}

func TestSecurityToolsEvaluatePolicyUsesPolicyEvaluatorInterface(t *testing.T) {
	evaluator := &fakePolicyEvaluator{
		findings: []policy.Finding{{ID: "finding-1", PolicyID: "policy-1"}},
	}
	st := NewSecurityTools(nil, nil, evaluator, nil)

	out, err := st.evaluatePolicy(context.Background(), json.RawMessage(`{
		"policy_id": "policy-1",
		"asset": {"id": "asset-1", "public": true}
	}`))
	if err != nil {
		t.Fatalf("evaluate policy: %v", err)
	}
	if len(evaluator.assets) != 1 {
		t.Fatalf("evaluated assets = %d, want 1", len(evaluator.assets))
	}

	var findings []policy.Finding
	if err := json.Unmarshal([]byte(out), &findings); err != nil {
		t.Fatalf("decode findings: %v", err)
	}
	if len(findings) != 1 || findings[0].ID != "finding-1" {
		t.Fatalf("unexpected findings payload: %+v", findings)
	}
}
