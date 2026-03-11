package graph

import (
	"strings"
	"testing"
	"time"
)

func TestCrossTenantPatternBuildIngestAndMatch(t *testing.T) {
	g := New()
	g.AddNode(&Node{
		ID:   "customer:acme",
		Kind: NodeKindCustomer,
		Name: "Acme",
		Properties: map[string]any{
			"failed_payment_count":     3,
			"open_p1_tickets":          2,
			"days_since_last_activity": 45,
		},
	})
	g.AddNode(&Node{
		ID:   "deal:acme-renewal",
		Kind: NodeKindDeal,
		Name: "Acme Renewal",
		Properties: map[string]any{
			"amount":                   220000,
			"days_since_last_activity": 38,
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

	samplesA, err := engine.BuildAnonymizedPatternSamples("tenant-alpha", 365*24*time.Hour)
	if err != nil {
		t.Fatalf("build samples tenant-alpha: %v", err)
	}
	if len(samplesA) == 0 {
		t.Fatal("expected anonymized samples")
	}
	if strings.Contains(samplesA[0].Fingerprint, "customer:acme") {
		t.Fatalf("fingerprint should not include entity identifiers: %q", samplesA[0].Fingerprint)
	}
	if samplesA[0].TenantHash == "" {
		t.Fatalf("expected tenant hash in sample, got %+v", samplesA[0])
	}

	samplesB, err := engine.BuildAnonymizedPatternSamples("tenant-beta", 365*24*time.Hour)
	if err != nil {
		t.Fatalf("build samples tenant-beta: %v", err)
	}
	if len(samplesB) == 0 {
		t.Fatal("expected anonymized samples for second tenant")
	}

	summaryA := engine.IngestAnonymizedPatternSamples(samplesA)
	summaryB := engine.IngestAnonymizedPatternSamples(samplesB)
	if summaryA.Added+summaryA.Updated == 0 || summaryB.Added+summaryB.Updated == 0 {
		t.Fatalf("expected ingest updates, got A=%+v B=%+v", summaryA, summaryB)
	}

	patterns := engine.CrossTenantPatterns(2)
	if len(patterns) == 0 {
		t.Fatal("expected cross-tenant patterns with min_tenants=2")
	}
	if patterns[0].OutcomeProbability <= 0 {
		t.Fatalf("expected positive outcome probability, got %+v", patterns[0])
	}

	matches := engine.MatchCrossTenantPatterns(0.5, 10)
	if len(matches) == 0 {
		t.Fatal("expected cross-tenant matches")
	}
	if matches[0].EntityID == "" || matches[0].SuggestedAction == "" {
		t.Fatalf("expected actionable match payload, got %+v", matches[0])
	}
}

func TestBuildAnonymizedPatternSamples_RequiresTenantID(t *testing.T) {
	engine := NewRiskEngine(New())
	if _, err := engine.BuildAnonymizedPatternSamples("", 90*24*time.Hour); err == nil {
		t.Fatal("expected tenant_id validation error")
	}
}
