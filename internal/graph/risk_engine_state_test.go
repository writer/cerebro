package graph

import (
	"testing"
	"time"
)

func TestRiskEngineSnapshotRestoreRoundTrip(t *testing.T) {
	g := New()
	g.AddNode(&Node{
		ID:   "customer:acme",
		Kind: NodeKindCustomer,
		Name: "Acme",
		Properties: map[string]any{
			"failed_payment_count":     3,
			"open_p1_tickets":          2,
			"days_since_last_activity": 38,
		},
	})
	g.AddNode(&Node{
		ID:   "deal:acme-renewal",
		Kind: NodeKindDeal,
		Name: "Acme Renewal",
		Properties: map[string]any{
			"amount":                   220000,
			"days_since_last_activity": 35,
		},
	})
	g.AddEdge(&Edge{
		ID:     "customer-deal",
		Source: "customer:acme",
		Target: "deal:acme-renewal",
		Kind:   EdgeKindOwns,
		Effect: EdgeEffectAllow,
	})

	engine := NewRiskEngine(g)
	engine.SetCrossTenantPrivacyConfig(CrossTenantPrivacyConfig{
		MinTenantCount:    2,
		MinPatternSupport: 2,
	})
	for i := 0; i < 5; i++ {
		_ = engine.Analyze()
	}
	if _, err := engine.RecordOutcome(OutcomeEvent{
		EntityID:   "customer:acme",
		Outcome:    "churn",
		OccurredAt: time.Now().UTC().Add(6 * time.Hour),
	}); err != nil {
		t.Fatalf("record outcome: %v", err)
	}

	candidates := engine.DiscoverRules(RuleDiscoveryRequest{
		WindowDays:               365,
		MinDetections:            3,
		IncludePolicies:          true,
		IncludeToxicCombinations: true,
	})
	if len(candidates) == 0 {
		t.Fatal("expected discovered candidates")
	}
	if _, err := engine.DecideDiscoveredRule(candidates[0].ID, RuleDecisionRequest{
		Approve:  true,
		Reviewer: "security-reviewer",
	}); err != nil {
		t.Fatalf("approve discovered rule: %v", err)
	}

	samplesA, err := engine.BuildAnonymizedPatternSamples("tenant-alpha", 365*24*time.Hour)
	if err != nil {
		t.Fatalf("build tenant alpha samples: %v", err)
	}
	samplesB, err := engine.BuildAnonymizedPatternSamples("tenant-beta", 365*24*time.Hour)
	if err != nil {
		t.Fatalf("build tenant beta samples: %v", err)
	}
	engine.IngestAnonymizedPatternSamples(samplesA)
	engine.IngestAnonymizedPatternSamples(samplesB)

	snapshot := engine.Snapshot()
	if snapshot.Version != riskEngineSnapshotVersion {
		t.Fatalf("expected snapshot version %d, got %d", riskEngineSnapshotVersion, snapshot.Version)
	}
	if len(snapshot.OutcomeEvents) == 0 || len(snapshot.DiscoveredRules) == 0 || len(snapshot.PatternLibrary) == 0 {
		t.Fatalf("expected non-empty snapshot state, got %+v", snapshot)
	}

	rehydrated := NewRiskEngine(g)
	if err := rehydrated.RestoreSnapshot(snapshot); err != nil {
		t.Fatalf("restore snapshot: %v", err)
	}

	if got := rehydrated.OutcomeEvents("", ""); len(got) == 0 {
		t.Fatal("expected restored outcomes")
	}
	if approved := rehydrated.ListDiscoveredRules(RuleCandidateStatusApproved); len(approved) == 0 {
		t.Fatal("expected restored approved discovered rules")
	}
	if patterns := rehydrated.CrossTenantPatterns(1); len(patterns) == 0 {
		t.Fatal("expected restored cross-tenant patterns")
	}
	if len(rehydrated.rulePromotions) == 0 {
		t.Fatal("expected restored rule promotion events")
	}
}

func TestRiskEngineRestoreSnapshot_ValidatesVersion(t *testing.T) {
	engine := NewRiskEngine(New())
	err := engine.RestoreSnapshot(RiskEngineSnapshot{Version: 999})
	if err == nil {
		t.Fatal("expected version validation error")
	}
}

func TestRiskEngineRestoreSnapshot_RestoresPrivacyConfig(t *testing.T) {
	engine := NewRiskEngine(New())
	engine.SetCrossTenantPrivacyConfig(CrossTenantPrivacyConfig{
		MinTenantCount:    5,
		MinPatternSupport: 7,
	})

	snapshot := engine.Snapshot()
	rehydrated := NewRiskEngine(New())
	if err := rehydrated.RestoreSnapshot(snapshot); err != nil {
		t.Fatalf("restore snapshot: %v", err)
	}

	cfg := rehydrated.crossTenantPrivacyConfigLocked()
	if cfg.MinTenantCount != 5 {
		t.Fatalf("expected min tenant count 5, got %d", cfg.MinTenantCount)
	}
	if cfg.MinPatternSupport != 7 {
		t.Fatalf("expected min pattern support 7, got %d", cfg.MinPatternSupport)
	}
}
