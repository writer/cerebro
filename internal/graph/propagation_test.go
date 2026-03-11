package graph

import (
	"strings"
	"testing"
)

func TestPropagationEngineEvaluate_NeedsApprovalForHighARR(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "user-1", Kind: NodeKindUser, Name: "user-1"})
	g.AddNode(&Node{ID: "svc-1", Kind: NodeKindApplication, Name: "svc-1"})
	g.AddNode(&Node{ID: "customer-1", Kind: NodeKindCustomer, Name: "BigCo", Properties: map[string]any{"arr": 2000000.0}})
	g.AddEdge(&Edge{ID: "user-svc", Source: "user-1", Target: "svc-1", Kind: EdgeKindCanAdmin, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "svc-customer", Source: "svc-1", Target: "customer-1", Kind: EdgeKindOwns, Effect: EdgeEffectAllow})
	g.BuildIndex()

	engine := NewPropagationEngine(g)
	result, err := engine.Evaluate(&ChangeProposal{
		ID:     "proposal-1",
		Source: "unit-test",
		Reason: "test high arr approval",
		Delta: GraphDelta{Nodes: []NodeMutation{{
			Action:     "modify",
			ID:         "user-1",
			Properties: map[string]any{"mfa_enabled": false},
		}}},
	})
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if result.Decision != DecisionNeedsApproval {
		t.Fatalf("expected decision %q, got %q", DecisionNeedsApproval, result.Decision)
	}
	if result.AffectedARR <= 1000000 {
		t.Fatalf("expected affected ARR above threshold, got %.2f", result.AffectedARR)
	}

	joined := strings.Join(result.ApprovalReasons, " ")
	if !strings.Contains(joined, "ARR") && !strings.Contains(strings.ToLower(joined), "threshold") {
		t.Fatalf("expected ARR-based approval reason, got %v", result.ApprovalReasons)
	}
}

func TestPropagationEngineDeriveDecision_BlocksCriticalCombination(t *testing.T) {
	engine := NewPropagationEngine(New())
	result := &PropagationResult{
		Simulation: &GraphSimulationResult{
			Delta: GraphSimulationDiff{
				ToxicCombosAdded: []*ToxicCombination{{
					ID:       "tc-critical",
					Name:     "Critical Combo",
					Severity: SeverityCritical,
				}},
			},
		},
	}

	engine.deriveDecision(result)
	if result.Decision != DecisionBlocked {
		t.Fatalf("expected decision %q, got %q", DecisionBlocked, result.Decision)
	}
	if len(result.BlockReasons) == 0 {
		t.Fatal("expected block reason for critical toxic combination")
	}
}

func TestPropagationEngineDeriveDecision_SafeWhenRiskImproves(t *testing.T) {
	engine := NewPropagationEngine(New())
	result := &PropagationResult{
		Simulation: &GraphSimulationResult{
			Delta: GraphSimulationDiff{
				RiskScoreDelta:     -5,
				ToxicCombosAdded:   nil,
				AttackPathsCreated: nil,
			},
		},
	}

	engine.deriveDecision(result)
	if result.Decision != DecisionSafe {
		t.Fatalf("expected decision %q, got %q", DecisionSafe, result.Decision)
	}
}
