package app

import (
	"context"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/policy"
)

func TestScanOrgTopologyPolicies_ProducesFindingsFromGraphSignals(t *testing.T) {
	engine := policy.NewEngine()
	addOrgTestPolicy(t, engine, &policy.Policy{
		ID:          "org-bus-factor-critical",
		Name:        "Critical System With Bus Factor 1",
		Description: "criticality high with single owner",
		Severity:    "high",
		Resource:    "org::system",
		Conditions: []string{
			"resource.criticality == 'high'",
			"resource.bus_factor <= 1",
		},
	})
	addOrgTestPolicy(t, engine, &policy.Policy{
		ID:          "org-silo-shared-dependency",
		Name:        "Teams Sharing Dependencies With No Communication",
		Description: "team pair shared dependencies without communication",
		Severity:    "medium",
		Resource:    "org::team_pair",
		Conditions: []string{
			"resource.shared_dependencies > 2",
			"resource.interaction_edges == 0",
		},
	})
	addOrgTestPolicy(t, engine, &policy.Policy{
		ID:          "org-relationship-decay-customer",
		Name:        "Customer Relationship Weakening",
		Description: "customer relationship decay before renewal",
		Severity:    "high",
		Resource:    "org::customer_relationship",
		Conditions: []string{
			"resource.relationship_strength < 0.3",
			"resource.previous_strength > 0.7",
			"resource.renewal_days < 90",
		},
	})
	addOrgTestPolicy(t, engine, &policy.Policy{
		ID:          "org-bottleneck-critical",
		Name:        "Single Person Bridges Multiple Teams",
		Description: "high-centrality communication bridge",
		Severity:    "medium",
		Resource:    "org::person",
		Conditions: []string{
			"resource.betweenness_centrality > 0.8",
			"resource.bridged_teams > 1",
		},
	})
	addOrgTestPolicy(t, engine, &policy.Policy{
		ID:          "org-tenure-risk",
		Name:        "Long-Tenured Sole Expert Showing Disengagement",
		Description: "tenured person owns bus-factor-1 systems with declining trend",
		Severity:    "high",
		Resource:    "org::person",
		Conditions: []string{
			"resource.bus_factor_1_systems > 0",
			"resource.activity_trend == 'declining'",
			"resource.tenure_years > 2",
		},
	})
	addOrgTestPolicy(t, engine, &policy.Policy{
		ID:          "org-customer-relationship-health-low",
		Name:        "Customer Relationship Structural Health Low",
		Description: "customer relationship topology health is weak",
		Severity:    "high",
		Resource:    "org::customer_relationship",
		Conditions: []string{
			"resource.health_score < 60",
			"resource.touchpoint_count < 2",
		},
	})

	app := &App{
		Policy:        engine,
		SecurityGraph: orgTopologyTestGraph(time.Now().UTC()),
	}

	result := app.ScanOrgTopologyPolicies(context.Background())
	if len(result.Errors) != 0 {
		t.Fatalf("expected no scan errors, got %v", result.Errors)
	}
	if result.Assets == 0 {
		t.Fatal("expected synthesized org-topology assets")
	}
	if len(result.Findings) < 5 {
		t.Fatalf("expected at least 5 findings, got %d", len(result.Findings))
	}

	policyIDs := make([]string, 0, len(result.Findings))
	for _, finding := range result.Findings {
		policyIDs = append(policyIDs, finding.PolicyID)
	}

	wantPolicies := []string{
		"org-bus-factor-critical",
		"org-silo-shared-dependency",
		"org-relationship-decay-customer",
		"org-bottleneck-critical",
		"org-tenure-risk",
		"org-customer-relationship-health-low",
	}
	for _, policyID := range wantPolicies {
		if !slices.Contains(policyIDs, policyID) {
			t.Fatalf("expected finding for policy %q, got %v", policyID, policyIDs)
		}
	}
}

func TestScanOrgTopologyPolicies_EmptyWhenGraphUnavailable(t *testing.T) {
	result := (&App{Policy: policy.NewEngine()}).ScanOrgTopologyPolicies(context.Background())
	if result.Assets != 0 {
		t.Fatalf("expected zero assets without graph, got %d", result.Assets)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected zero findings without graph, got %d", len(result.Findings))
	}
}

func TestScanOrgTopologyPolicies_UsesConfiguredStoreWhenLiveGraphUnavailable(t *testing.T) {
	engine := policy.NewEngine()
	addOrgTestPolicy(t, engine, &policy.Policy{
		ID:          "org-bus-factor-critical",
		Name:        "Critical System With Bus Factor 1",
		Description: "criticality high with single owner",
		Severity:    "high",
		Resource:    "org::system",
		Conditions: []string{
			"resource.criticality == 'high'",
			"resource.bus_factor <= 1",
		},
	})

	app := &App{Policy: engine}
	setConfiguredSnapshotGraphFromGraph(t, app, orgTopologyTestGraph(time.Now().UTC()))

	result := app.ScanOrgTopologyPolicies(context.Background())
	if len(result.Errors) != 0 {
		t.Fatalf("expected no scan errors, got %v", result.Errors)
	}
	if result.Assets == 0 {
		t.Fatal("expected synthesized org-topology assets from configured graph")
	}
	if !slices.ContainsFunc(result.Findings, func(f policy.Finding) bool { return f.PolicyID == "org-bus-factor-critical" }) {
		t.Fatalf("expected configured graph finding, got %v", result.Findings)
	}
}

func TestScanOrgTopologyPolicies_EmptyWhenSnapshotStoreHasNoSnapshots(t *testing.T) {
	store, err := graph.NewGraphPersistenceStore(graph.GraphPersistenceOptions{
		LocalPath:    filepath.Join(t.TempDir(), "graph-snapshots"),
		MaxSnapshots: 4,
	})
	if err != nil {
		t.Fatalf("NewGraphPersistenceStore() error = %v", err)
	}

	app := &App{
		Policy:         policy.NewEngine(),
		GraphSnapshots: store,
	}

	result := app.ScanOrgTopologyPolicies(context.Background())
	if len(result.Errors) != 0 {
		t.Fatalf("expected no scan errors, got %v", result.Errors)
	}
	if result.Assets != 0 {
		t.Fatalf("expected zero assets, got %d", result.Assets)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected zero findings, got %v", result.Findings)
	}
}

func addOrgTestPolicy(t *testing.T, engine *policy.Engine, p *policy.Policy) {
	t.Helper()
	engine.AddPolicy(p)
	if _, ok := engine.GetPolicy(p.ID); !ok {
		t.Fatalf("expected test policy %q to be registered", p.ID)
	}
}

func orgTopologyTestGraph(now time.Time) *graph.Graph {
	g := graph.New()

	g.AddNode(&graph.Node{
		ID:   "person:alex@example.com",
		Kind: graph.NodeKindPerson,
		Name: "Alex",
		Properties: map[string]any{
			"start_date":     "2020-01-01",
			"activity_trend": "declining",
		},
	})
	g.AddNode(&graph.Node{ID: "person:beth@example.com", Kind: graph.NodeKindPerson, Name: "Beth"})
	g.AddNode(&graph.Node{ID: "person:charlie@example.com", Kind: graph.NodeKindPerson, Name: "Charlie"})

	g.AddNode(&graph.Node{ID: "department:eng", Kind: graph.NodeKindDepartment, Name: "Engineering"})
	g.AddNode(&graph.Node{ID: "department:ops", Kind: graph.NodeKindDepartment, Name: "Operations"})
	g.AddNode(&graph.Node{ID: "department:support", Kind: graph.NodeKindDepartment, Name: "Support"})

	g.AddNode(&graph.Node{
		ID:   "svc:core",
		Kind: graph.NodeKindApplication,
		Name: "core",
		Properties: map[string]any{
			"criticality": "high",
		},
	})
	g.AddNode(&graph.Node{ID: "dep:a", Kind: graph.NodeKindApplication, Name: "dep-a"})
	g.AddNode(&graph.Node{ID: "dep:b", Kind: graph.NodeKindApplication, Name: "dep-b"})
	g.AddNode(&graph.Node{ID: "dep:c", Kind: graph.NodeKindApplication, Name: "dep-c"})
	g.AddNode(&graph.Node{
		ID:   "customer:acme",
		Kind: graph.NodeKindCustomer,
		Name: "Acme",
		Properties: map[string]any{
			"renewal_days": 30,
		},
	})

	g.AddEdge(&graph.Edge{ID: "alex-eng", Source: "person:alex@example.com", Target: "department:eng", Kind: graph.EdgeKindMemberOf})
	g.AddEdge(&graph.Edge{ID: "beth-ops", Source: "person:beth@example.com", Target: "department:ops", Kind: graph.EdgeKindMemberOf})
	g.AddEdge(&graph.Edge{ID: "charlie-support", Source: "person:charlie@example.com", Target: "department:support", Kind: graph.EdgeKindMemberOf})

	g.AddEdge(&graph.Edge{
		ID:     "alex-core",
		Source: "person:alex@example.com",
		Target: "svc:core",
		Kind:   graph.EdgeKindCanAdmin,
		Properties: map[string]any{
			"last_seen": now.Add(-2 * 24 * time.Hour),
		},
	})

	for _, depID := range []string{"dep:a", "dep:b", "dep:c"} {
		g.AddEdge(&graph.Edge{ID: "beth-" + depID, Source: "person:beth@example.com", Target: depID, Kind: graph.EdgeKindCanRead})
		g.AddEdge(&graph.Edge{ID: "charlie-" + depID, Source: "person:charlie@example.com", Target: depID, Kind: graph.EdgeKindCanRead})
	}

	g.AddEdge(&graph.Edge{
		ID:     "beth-alex",
		Source: "person:beth@example.com",
		Target: "person:alex@example.com",
		Kind:   graph.EdgeKindInteractedWith,
		Properties: map[string]any{
			"frequency": 4,
			"last_seen": now.Add(-24 * time.Hour),
		},
	})
	g.AddEdge(&graph.Edge{
		ID:     "alex-charlie",
		Source: "person:alex@example.com",
		Target: "person:charlie@example.com",
		Kind:   graph.EdgeKindInteractedWith,
		Properties: map[string]any{
			"frequency": 5,
			"last_seen": now.Add(-24 * time.Hour),
		},
	})

	g.AddEdge(&graph.Edge{
		ID:     "alex-acme",
		Source: "person:alex@example.com",
		Target: "customer:acme",
		Kind:   graph.EdgeKindManagedBy,
		Properties: map[string]any{
			"strength":          0.2,
			"previous_strength": 0.9,
		},
	})

	return g
}
