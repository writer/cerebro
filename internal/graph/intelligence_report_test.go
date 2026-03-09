package graph

import (
	"reflect"
	"testing"
)

func TestBuildIntelligenceReport(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "user:alice", Kind: NodeKindUser, Name: "Alice"})
	g.AddNode(&Node{ID: "role:ops", Kind: NodeKindRole, Name: "Ops"})
	g.AddNode(&Node{ID: "db:prod", Kind: NodeKindDatabase, Name: "Prod DB", Risk: RiskCritical})
	g.AddNode(&Node{ID: "node:unknown", Kind: NodeKind("test_intelligence_unknown_kind_v1"), Name: "Unknown"})
	g.AddEdge(&Edge{ID: "alice-role", Source: "user:alice", Target: "role:ops", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "role-db", Source: "role:ops", Target: "db:prod", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})

	engine := NewRiskEngine(g)
	if _, err := engine.RecordOutcome(OutcomeEvent{EntityID: "db:prod", Outcome: "incident"}); err != nil {
		t.Fatalf("record outcome: %v", err)
	}

	report := BuildIntelligenceReport(g, engine, IntelligenceReportOptions{
		EntityID:              "db:prod",
		SchemaHistoryLimit:    20,
		IncludeCounterfactual: true,
		MaxInsights:           6,
	})

	if report.GeneratedAt.IsZero() {
		t.Fatal("expected generated timestamp")
	}
	if report.Coverage <= 0 {
		t.Fatalf("expected positive coverage, got %f", report.Coverage)
	}
	if report.Confidence <= 0 {
		t.Fatalf("expected positive confidence, got %f", report.Confidence)
	}
	if len(report.Insights) == 0 {
		t.Fatal("expected at least one insight")
	}

	foundEntity := false
	foundCounterfactual := false
	for _, insight := range report.Insights {
		if insight.Type == "entity_risk" {
			foundEntity = true
		}
		if insight.Counterfactual != nil {
			foundCounterfactual = true
		}
		if insight.Priority < 1 {
			t.Fatalf("expected positive priority, got %d", insight.Priority)
		}
	}
	if !foundEntity {
		t.Fatalf("expected entity_risk insight, got %#v", report.Insights)
	}
	if !foundCounterfactual {
		t.Fatalf("expected at least one counterfactual insight, got %#v", report.Insights)
	}
}

func TestBuildIntelligenceReport_TemporalDiffInsight(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "user:alice", Kind: NodeKindUser, Name: "Alice"})
	g.AddNode(&Node{ID: "db:prod", Kind: NodeKindDatabase, Name: "Prod DB", Risk: RiskCritical})
	g.AddEdge(&Edge{ID: "alice-db", Source: "user:alice", Target: "db:prod", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})

	diff := &GraphDiff{
		NodesAdded: []*Node{{ID: "node:new", Kind: NodeKindBucket}},
		EdgesAdded: []*Edge{{ID: "edge:new", Source: "user:alice", Target: "db:prod", Kind: EdgeKindCanWrite}},
	}
	report := BuildIntelligenceReport(g, NewRiskEngine(g), IntelligenceReportOptions{
		TemporalDiff: diff,
		MaxInsights:  10,
	})

	foundTemporal := false
	for _, insight := range report.Insights {
		if insight.Type == "temporal_drift" {
			foundTemporal = true
			break
		}
	}
	if !foundTemporal {
		t.Fatalf("expected temporal_drift insight, got %#v", report.Insights)
	}
}

func TestBuildIntelligenceReport_DeterministicInsightOrderAndIDs(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "user:alice", Kind: NodeKindUser, Name: "Alice"})
	g.AddNode(&Node{ID: "role:admin", Kind: NodeKindRole, Name: "Admin"})
	g.AddNode(&Node{ID: "db:prod", Kind: NodeKindDatabase, Name: "Prod DB", Risk: RiskCritical})
	g.AddEdge(&Edge{ID: "alice-admin", Source: "user:alice", Target: "role:admin", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "admin-db", Source: "role:admin", Target: "db:prod", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})

	opts := IntelligenceReportOptions{
		EntityID:              "db:prod",
		SchemaHistoryLimit:    20,
		IncludeCounterfactual: false,
		MaxInsights:           8,
	}

	reportA := BuildIntelligenceReport(g, NewRiskEngine(g), opts)
	reportB := BuildIntelligenceReport(g, NewRiskEngine(g), opts)

	idsA := make([]string, 0, len(reportA.Insights))
	idsB := make([]string, 0, len(reportB.Insights))
	for _, insight := range reportA.Insights {
		if insight.ID == "" {
			t.Fatalf("expected non-empty insight ID in reportA: %#v", reportA.Insights)
		}
		idsA = append(idsA, insight.ID)
	}
	for _, insight := range reportB.Insights {
		if insight.ID == "" {
			t.Fatalf("expected non-empty insight ID in reportB: %#v", reportB.Insights)
		}
		idsB = append(idsB, insight.ID)
	}
	if !reflect.DeepEqual(idsA, idsB) {
		t.Fatalf("expected deterministic insight ID order, got %v vs %v", idsA, idsB)
	}
}
