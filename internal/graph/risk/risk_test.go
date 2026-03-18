package risk

import (
	"strings"
	"testing"

	graph "github.com/writer/cerebro/internal/graph"
)

func testRiskGraph() *graph.Graph {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "internet", Kind: graph.NodeKindInternet, Name: "Internet", Provider: "external"})
	g.AddNode(&graph.Node{ID: "user:alice", Kind: graph.NodeKindUser, Name: "Alice", Provider: "aws"})
	g.AddNode(&graph.Node{ID: "db:prod", Kind: graph.NodeKindDatabase, Name: "Prod DB", Provider: "aws", Risk: graph.RiskCritical})

	g.AddEdge(&graph.Edge{
		ID:     "edge:user-db",
		Source: "user:alice",
		Target: "db:prod",
		Kind:   graph.EdgeKindCanRead,
		Effect: graph.EdgeEffectAllow,
	})
	g.AddEdge(&graph.Edge{
		ID:     "edge:internet-db",
		Source: "internet",
		Target: "db:prod",
		Kind:   graph.EdgeKindExposedTo,
		Effect: graph.EdgeEffectAllow,
	})

	return g
}

func TestRiskWrappersReachabilityAndPaths(t *testing.T) {
	g := testRiskGraph()

	blast := BlastRadius(g, "user:alice", 3)
	if blast == nil {
		t.Fatal("expected blast radius result")
	}
	if blast.TotalCount != 1 {
		t.Fatalf("expected 1 reachable node, got %d", blast.TotalCount)
	}
	if blast.ReachableNodes[0].Node == nil || blast.ReachableNodes[0].Node.ID != "db:prod" {
		t.Fatalf("expected reachable database node, got %#v", blast.ReachableNodes[0].Node)
	}

	reverse := ReverseAccess(g, "db:prod", 3)
	if reverse == nil {
		t.Fatal("expected reverse access result")
	}
	if reverse.TotalCount != 1 {
		t.Fatalf("expected 1 accessor, got %d", reverse.TotalCount)
	}
	if reverse.AccessibleBy[0].Node == nil || reverse.AccessibleBy[0].Node.ID != "user:alice" {
		t.Fatalf("expected accessor user:alice, got %#v", reverse.AccessibleBy[0].Node)
	}

	simulator := NewAttackPathSimulator(g)
	result := simulator.Simulate(4)
	if result == nil {
		t.Fatal("expected attack path result")
	}
	if len(result.Paths) == 0 {
		t.Fatal("expected at least one attack path")
	}
	if result.Paths[0].EntryPoint == nil || result.Paths[0].Target == nil {
		t.Fatalf("expected populated attack path endpoints, got %#v", result.Paths[0])
	}

	fix := simulator.SimulateFix(result, "db:prod")
	if fix == nil {
		t.Fatal("expected fix simulation")
	}
	if fix.FixedNode != "db:prod" {
		t.Fatalf("expected fixed node db:prod, got %q", fix.FixedNode)
	}
	if fix.BlockedCount == 0 {
		t.Fatal("expected fix simulation to block at least one path")
	}
}

func TestRiskWrappersRiskEngineAndToxicCombos(t *testing.T) {
	g := testRiskGraph()

	engine := NewRiskEngine(g)
	report := engine.Analyze()
	if report == nil {
		t.Fatal("expected security report")
	}
	if report.AttackPaths == nil || len(report.AttackPaths.Paths) == 0 {
		t.Fatalf("expected analyzed attack paths, got %#v", report.AttackPaths)
	}
	if report.RiskScore <= 0 {
		t.Fatalf("expected positive risk score, got %f", report.RiskScore)
	}

	entityRisk := engine.ScoreEntity("db:prod")
	if entityRisk == nil {
		t.Fatal("expected entity risk score for db:prod")
	}
	if entityRisk.EntityID != "db:prod" {
		t.Fatalf("expected entity risk for db:prod, got %#v", entityRisk)
	}
	if entityRisk.EntityKind != graph.NodeKindDatabase {
		t.Fatalf("expected database entity kind, got %#v", entityRisk)
	}

	combinations := NewToxicCombinationEngine().Analyze(g)
	if len(combinations) == 0 {
		t.Fatal("expected toxic combinations")
	}
	foundPublicDB := false
	for _, combo := range combinations {
		if combo == nil {
			continue
		}
		if strings.HasPrefix(combo.ID, "TC009-") {
			foundPublicDB = true
			break
		}
	}
	if !foundPublicDB {
		t.Fatalf("expected public database toxic combination, got %#v", combinations)
	}
}
