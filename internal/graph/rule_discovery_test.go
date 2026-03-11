package graph

import (
	"testing"
	"time"
)

func TestRiskEngineDiscoverRulesAndApprovalFlow(t *testing.T) {
	g := New()
	g.AddNode(&Node{
		ID:   "customer:acme",
		Kind: NodeKindCustomer,
		Name: "Acme",
		Properties: map[string]any{
			"failed_payment_count":     3,
			"open_p1_tickets":          2,
			"days_since_last_activity": 40,
		},
	})
	g.AddNode(&Node{
		ID:   "deal:renewal",
		Kind: NodeKindDeal,
		Name: "Acme Renewal",
		Properties: map[string]any{
			"amount":                   200000,
			"days_since_last_activity": 35,
		},
	})
	g.AddEdge(&Edge{
		ID:     "customer-deal",
		Source: "customer:acme",
		Target: "deal:renewal",
		Kind:   EdgeKindOwns,
		Effect: EdgeEffectAllow,
	})

	engine := NewRiskEngine(g)
	for i := 0; i < 5; i++ {
		_ = engine.Analyze()
	}
	if _, err := engine.RecordOutcome(OutcomeEvent{
		EntityID:   "customer:acme",
		Outcome:    "churn",
		OccurredAt: time.Now().UTC().Add(4 * time.Hour),
	}); err != nil {
		t.Fatalf("record outcome: %v", err)
	}

	candidates := engine.DiscoverRules(RuleDiscoveryRequest{
		WindowDays:               365,
		MinDetections:            3,
		MaxCandidates:            20,
		IncludePolicies:          true,
		IncludeToxicCombinations: true,
	})
	if len(candidates) == 0 {
		t.Fatal("expected discovered candidates")
	}

	foundPending := false
	for _, candidate := range candidates {
		if candidate.Status == RuleCandidateStatusPendingApproval {
			foundPending = true
			break
		}
	}
	if !foundPending {
		t.Fatalf("expected pending approval candidates, got %+v", candidates)
	}

	first := candidates[0]
	approved, err := engine.DecideDiscoveredRule(first.ID, RuleDecisionRequest{
		Approve:  true,
		Reviewer: "security-architect",
		Notes:    "looks predictive and actionable",
	})
	if err != nil {
		t.Fatalf("approve candidate: %v", err)
	}
	if approved.Status != RuleCandidateStatusApproved || !approved.Activated {
		t.Fatalf("expected approved+activated candidate, got %+v", approved)
	}
	if approved.PromotionStatus == "" {
		t.Fatalf("expected promotion status to be populated, got %+v", approved)
	}

	approvedList := engine.ListDiscoveredRules(RuleCandidateStatusApproved)
	if len(approvedList) == 0 {
		t.Fatal("expected approved candidates list")
	}
	if approvedList[0].ReviewedBy == "" {
		t.Fatalf("expected reviewer metadata, got %+v", approvedList[0])
	}
}

func TestRiskEngineDecideDiscoveredRule_NotFound(t *testing.T) {
	engine := NewRiskEngine(New())
	_, err := engine.DecideDiscoveredRule("discover:missing", RuleDecisionRequest{Approve: true})
	if err == nil {
		t.Fatal("expected not found error")
	}
}
