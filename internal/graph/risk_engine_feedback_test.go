package graph

import (
	"testing"
	"time"
)

func TestRiskEngineRecordOutcome_ValidatesEntity(t *testing.T) {
	engine := NewRiskEngine(New())
	if _, err := engine.RecordOutcome(OutcomeEvent{
		EntityID: "customer:missing",
		Outcome:  "churn",
	}); err == nil {
		t.Fatal("expected error for unknown entity")
	}
}

func TestRiskEngineOutcomeFeedback_TracksOutcomesAndSignals(t *testing.T) {
	g := New()
	g.AddNode(&Node{
		ID:   "customer:acme",
		Kind: NodeKindCustomer,
		Name: "Acme",
		Properties: map[string]any{
			"failed_payment_count":     3,
			"open_p1_tickets":          2,
			"days_since_last_activity": 35,
		},
	})
	g.AddNode(&Node{
		ID:   "deal:renewal",
		Kind: NodeKindDeal,
		Name: "Acme Renewal",
		Properties: map[string]any{
			"amount":                   180000,
			"days_since_last_activity": 45,
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
	for i := 0; i < 6; i++ {
		_ = engine.Analyze()
	}

	recorded, err := engine.RecordOutcome(OutcomeEvent{
		EntityID:   "customer:acme",
		Outcome:    "churn",
		OccurredAt: time.Now().UTC().Add(4 * time.Hour),
	})
	if err != nil {
		t.Fatalf("record outcome: %v", err)
	}
	if recorded.ID == "" {
		t.Fatal("expected generated outcome id")
	}

	report := engine.OutcomeFeedback(365*24*time.Hour, "revenue-heavy")
	if report.OutcomeCount == 0 {
		t.Fatal("expected outcome count in report")
	}
	if report.RuleSignalCount == 0 {
		t.Fatal("expected rule signal count in report")
	}
	if len(report.RuleEffectiveness) == 0 {
		t.Fatal("expected rule effectiveness metrics")
	}

	foundTruePositive := false
	for _, metric := range report.RuleEffectiveness {
		if metric.TruePositives > 0 {
			foundTruePositive = true
			break
		}
	}
	if !foundTruePositive {
		t.Fatalf("expected at least one true positive, got %+v", report.RuleEffectiveness)
	}

	if len(report.SignalWeightAdjustments) == 0 {
		t.Fatalf("expected signal weight recommendations, got %+v", report)
	}
}

func TestBuildSeverityAdjustmentsAndRetirementSuggestions(t *testing.T) {
	metrics := []RuleEffectiveness{
		{
			RuleID:         "rule:promote",
			Severity:       SeverityMedium,
			Detections:     6,
			Precision:      0.90,
			Recall:         0.70,
			FalsePositives: 1,
		},
		{
			RuleID:         "rule:demote",
			Severity:       SeverityHigh,
			Detections:     9,
			Precision:      0.10,
			Recall:         0.05,
			FalsePositives: 8,
		},
	}

	severitySuggestions := buildSeverityAdjustments(metrics)
	if len(severitySuggestions) == 0 {
		t.Fatal("expected severity adjustment suggestions")
	}

	foundPromote := false
	foundDemote := false
	for _, suggestion := range severitySuggestions {
		if suggestion.RuleID == "rule:promote" && suggestion.SuggestedSeverity == SeverityHigh {
			foundPromote = true
		}
		if suggestion.RuleID == "rule:demote" && suggestion.SuggestedSeverity == SeverityMedium {
			foundDemote = true
		}
	}
	if !foundPromote || !foundDemote {
		t.Fatalf("expected promote+demote suggestions, got %+v", severitySuggestions)
	}

	retirement := buildRetirementSuggestions(metrics)
	if len(retirement) == 0 {
		t.Fatal("expected retirement suggestion")
	}
	if retirement[0].RuleID != "rule:demote" {
		t.Fatalf("expected demote rule retirement suggestion, got %+v", retirement)
	}
}

func TestBuildSignalWeightRecommendations(t *testing.T) {
	base := time.Now().UTC()
	factors := []FactorObservation{
		{EntityID: "customer:acme", Signal: "stripe", Score: 90, ObservedAt: base.Add(-4 * time.Hour)},
		{EntityID: "customer:acme", Signal: "stripe", Score: 88, ObservedAt: base.Add(-3 * time.Hour)},
		{EntityID: "customer:acme", Signal: "stripe", Score: 91, ObservedAt: base.Add(-2 * time.Hour)},
		{EntityID: "customer:beta", Signal: "support", Score: 20, ObservedAt: base.Add(-2 * time.Hour)},
		{EntityID: "customer:beta", Signal: "support", Score: 18, ObservedAt: base.Add(-90 * time.Minute)},
		{EntityID: "customer:beta", Signal: "support", Score: 19, ObservedAt: base.Add(-1 * time.Hour)},
	}
	outcomes := []OutcomeEvent{
		{ID: "o-1", EntityID: "customer:acme", Outcome: "churn", OccurredAt: base.Add(-30 * time.Minute)},
	}

	recommendations := buildSignalWeightRecommendations(factors, outcomes, DefaultRiskProfile("default"), 48*time.Hour)
	if len(recommendations) == 0 {
		t.Fatal("expected signal recommendations")
	}

	foundStripeIncrease := false
	foundSupportDecrease := false
	for _, recommendation := range recommendations {
		if recommendation.Signal == "stripe" && recommendation.Direction == "increase" {
			foundStripeIncrease = true
		}
		if recommendation.Signal == "support" && recommendation.Direction == "decrease" {
			foundSupportDecrease = true
		}
	}
	if !foundStripeIncrease || !foundSupportDecrease {
		t.Fatalf("expected stripe increase and support decrease, got %+v", recommendations)
	}
}
