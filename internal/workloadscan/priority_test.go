package workloadscan

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/graph"
)

func TestPrioritizeTargetsOrdersByRiskSignalsAndSkipsFreshTargetsByDefault(t *testing.T) {
	now := time.Date(2026, 3, 13, 12, 0, 0, 0, time.UTC)
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "workload-priority.db"))
	if err != nil {
		t.Fatalf("NewSQLiteRunStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	if err := store.SaveRun(context.Background(), &RunRecord{
		ID:          "workload_scan:recent",
		Provider:    ProviderAWS,
		Status:      RunStatusSucceeded,
		Stage:       RunStageCompleted,
		Target:      VMTarget{Provider: ProviderAWS, Region: "us-east-1", InstanceID: "i-recent"},
		SubmittedAt: now.Add(-2 * time.Hour),
		UpdatedAt:   now.Add(-90 * time.Minute),
		CompletedAt: timePtr(now.Add(-90 * time.Minute)),
	}); err != nil {
		t.Fatalf("SaveRun recent: %v", err)
	}

	g := graph.New()
	g.AddNode(&graph.Node{ID: "internet", Kind: graph.NodeKindInternet, Name: "Internet", Provider: "external"})
	g.AddNode(&graph.Node{
		ID:       "arn:aws:ec2:us-east-1:123456789012:instance/i-public",
		Kind:     graph.NodeKindInstance,
		Name:     "i-public",
		Provider: "aws",
		Account:  "123456789012",
		Region:   "us-east-1",
		Properties: map[string]any{
			"instance_id":      "i-public",
			"public_ip":        "34.42.10.9",
			"criticality":      "high",
			"compliance_scope": "pci",
		},
	})
	g.AddNode(&graph.Node{
		ID:       "arn:aws:ec2:us-east-1:123456789012:instance/i-backlog",
		Kind:     graph.NodeKindInstance,
		Name:     "i-backlog",
		Provider: "aws",
		Account:  "123456789012",
		Region:   "us-east-1",
		Properties: map[string]any{
			"instance_id": "i-backlog",
		},
	})
	g.AddNode(&graph.Node{
		ID:       "arn:aws:ec2:us-east-1:123456789012:instance/i-recent",
		Kind:     graph.NodeKindInstance,
		Name:     "i-recent",
		Provider: "aws",
		Account:  "123456789012",
		Region:   "us-east-1",
		Properties: map[string]any{
			"instance_id": "i-recent",
		},
	})
	g.AddNode(&graph.Node{ID: "role:admin", Kind: graph.NodeKindRole, Name: "AdminRole", Provider: "aws", Risk: graph.RiskHigh})
	g.AddNode(&graph.Node{ID: "db:prod", Kind: graph.NodeKindDatabase, Name: "Prod DB", Provider: "aws", Risk: graph.RiskCritical, Properties: map[string]any{"data_classification": "restricted"}})
	g.AddEdge(&graph.Edge{ID: "internet->public", Source: "internet", Target: "arn:aws:ec2:us-east-1:123456789012:instance/i-public", Kind: graph.EdgeKindExposedTo, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "public->role", Source: "arn:aws:ec2:us-east-1:123456789012:instance/i-public", Target: "role:admin", Kind: graph.EdgeKindCanAssume, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "role->db", Source: "role:admin", Target: "db:prod", Kind: graph.EdgeKindCanRead, Effect: graph.EdgeEffectAllow})
	g.BuildIndex()

	targets, err := PrioritizeTargets(context.Background(), g, store, PrioritizationOptions{
		Now:             func() time.Time { return now },
		IncludeDeferred: false,
	})
	if err != nil {
		t.Fatalf("PrioritizeTargets: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("expected 2 actionable targets, got %d", len(targets))
	}
	if got := targets[0].Target.InstanceID; got != "i-public" {
		t.Fatalf("expected public instance first, got %s", got)
	}
	if targets[0].Assessment.Priority != ScanPriorityCritical {
		t.Fatalf("expected public instance critical priority, got %+v", targets[0].Assessment)
	}
	if got := targets[1].Target.InstanceID; got != "i-backlog" {
		t.Fatalf("expected backlog instance second, got %s", got)
	}

	allTargets, err := PrioritizeTargets(context.Background(), g, store, PrioritizationOptions{
		Now:             func() time.Time { return now },
		IncludeDeferred: true,
	})
	if err != nil {
		t.Fatalf("PrioritizeTargets include deferred: %v", err)
	}
	if len(allTargets) != 3 {
		t.Fatalf("expected all 3 targets with deferred included, got %d", len(allTargets))
	}
	if got := allTargets[2].Target.InstanceID; got != "i-recent" {
		t.Fatalf("expected fresh instance last, got %s", got)
	}
	if allTargets[2].Assessment.Eligible {
		t.Fatalf("expected fresh instance to be deferred, got %+v", allTargets[2].Assessment)
	}
	if allTargets[2].Assessment.Staleness != "fresh" {
		t.Fatalf("expected fresh staleness bucket, got %+v", allTargets[2].Assessment)
	}
}

func TestPrioritizeTargetsHonorsGraphPriorityOverride(t *testing.T) {
	now := time.Date(2026, 3, 13, 12, 0, 0, 0, time.UTC)
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "workload-priority-override.db"))
	if err != nil {
		t.Fatalf("NewSQLiteRunStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	if err := store.SaveRun(context.Background(), &RunRecord{
		ID:          "workload_scan:override",
		Provider:    ProviderAWS,
		Status:      RunStatusSucceeded,
		Stage:       RunStageCompleted,
		Target:      VMTarget{Provider: ProviderAWS, Region: "us-east-1", InstanceID: "i-override"},
		SubmittedAt: now.Add(-30 * time.Minute),
		UpdatedAt:   now.Add(-20 * time.Minute),
		CompletedAt: timePtr(now.Add(-20 * time.Minute)),
	}); err != nil {
		t.Fatalf("SaveRun override: %v", err)
	}

	g := graph.New()
	g.AddNode(&graph.Node{
		ID:       "arn:aws:ec2:us-east-1:123456789012:instance/i-override",
		Kind:     graph.NodeKindInstance,
		Name:     "i-override",
		Provider: "aws",
		Account:  "123456789012",
		Region:   "us-east-1",
		Properties: map[string]any{
			"instance_id":            "i-override",
			"scan_priority_override": "critical",
		},
	})

	targets, err := PrioritizeTargets(context.Background(), g, store, PrioritizationOptions{
		Now:             func() time.Time { return now },
		IncludeDeferred: false,
	})
	if err != nil {
		t.Fatalf("PrioritizeTargets: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("expected override target to remain actionable, got %d", len(targets))
	}
	assessment := targets[0].Assessment
	if assessment.Priority != ScanPriorityCritical {
		t.Fatalf("expected critical override priority, got %+v", assessment)
	}
	if !assessment.Eligible {
		t.Fatalf("expected override priority to stay eligible, got %+v", assessment)
	}
	if assessment.Source != prioritySourceGraphOverride {
		t.Fatalf("expected graph override source, got %+v", assessment)
	}
}

func timePtr(value time.Time) *time.Time {
	copy := value.UTC()
	return &copy
}
