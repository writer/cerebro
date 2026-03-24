package graph

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestShortestInformationPath_TeamSelectors(t *testing.T) {
	g := buildInformationFlowFixtureGraph(time.Date(2026, 3, 8, 12, 0, 0, 0, time.UTC))
	path := ShortestInformationPath(g, "team/support", "team/engineering")
	if path == nil {
		t.Fatalf("expected path, got nil")
	}
	if path.Source != "team/support" || path.Destination != "team/engineering" {
		t.Fatalf("unexpected endpoint labels: %q -> %q", path.Source, path.Destination)
	}
	if len(path.Path) < 3 {
		t.Fatalf("expected at least 3 nodes in path, got %d", len(path.Path))
	}
	if path.Hops < 1 {
		t.Fatalf("expected at least one intermediate hop, got %d", path.Hops)
	}
	if strings.TrimSpace(path.EstimatedLatency) == "" || path.EstimatedLatency == "0s" {
		t.Fatalf("expected non-zero estimated latency, got %q", path.EstimatedLatency)
	}
	if len(path.Bottlenecks) == 0 {
		t.Fatalf("expected bottleneck nodes on path")
	}
}

func TestComputeClockSpeed_Aggregates(t *testing.T) {
	fixedNow := time.Date(2026, 3, 8, 12, 0, 0, 0, time.UTC)
	previousNow := orgHealthNowUTC
	orgHealthNowUTC = func() time.Time { return fixedNow }
	t.Cleanup(func() { orgHealthNowUTC = previousNow })

	g := buildInformationFlowFixtureGraph(fixedNow)
	clock := ComputeClockSpeed(g)

	if clock.CustomerIssueToResolver.PathCount == 0 {
		t.Fatalf("expected customer issue flow paths")
	}
	if clock.SecurityFindingToRemediator.PathCount == 0 {
		t.Fatalf("expected security finding flow paths")
	}
	if clock.SalesInsightToProduct.PathCount == 0 {
		t.Fatalf("expected sales insight flow paths")
	}
	if clock.IncidentToExecVisibility.PathCount == 0 {
		t.Fatalf("expected incident flow paths")
	}
	if clock.AverageHops <= 0 {
		t.Fatalf("expected positive average hops, got %f", clock.AverageHops)
	}
	if clock.MedianLatency == "" || clock.MedianLatency == "0s" {
		t.Fatalf("expected non-zero median latency, got %q", clock.MedianLatency)
	}
	if len(clock.LongestPaths) == 0 {
		t.Fatalf("expected longest paths to be populated")
	}
	if len(clock.MostOverloadedNodes) == 0 {
		t.Fatalf("expected overloaded nodes to be populated")
	}
}

func TestRecommendEdges_ReturnsSharedContextBridge(t *testing.T) {
	g := buildInformationFlowFixtureGraph(time.Date(2026, 3, 8, 12, 0, 0, 0, time.UTC))
	recs := RecommendEdges(g, 3)
	if len(recs) == 0 {
		t.Fatalf("expected recommendations, got none")
	}

	top := recs[0]
	pair := top.PersonA + "|" + top.PersonB
	if pair != "person:alice@example.com|person:carol@example.com" {
		t.Fatalf("expected alice-carol as top recommendation, got %s", pair)
	}
	if top.PathsImproved < 2 {
		t.Fatalf("expected at least 2 improved paths, got %d", top.PathsImproved)
	}
	if top.AvgHopsReduced <= 0 {
		t.Fatalf("expected positive average hops reduction")
	}
	if top.Suggestion == "" {
		t.Fatalf("expected suggestion text")
	}
}

func TestShortestPathBetweenSetsHandlesWideOrdinalPath(t *testing.T) {
	adjacency := make(map[string]map[string]struct{})
	link := func(source, target string) {
		if adjacency[source] == nil {
			adjacency[source] = make(map[string]struct{})
		}
		adjacency[source][target] = struct{}{}
	}

	const chainLen = 70
	link("source", "node-0")
	for i := 0; i < chainLen-1; i++ {
		link(fmt.Sprintf("node-%d", i), fmt.Sprintf("node-%d", i+1))
	}
	link(fmt.Sprintf("node-%d", chainLen-1), "target")
	link(fmt.Sprintf("node-%d", chainLen-1), "node-10")

	sources := map[string]struct{}{"source": {}}
	targets := map[string]struct{}{"target": {}}

	single := runShortestPathBetweenSetsWithWorkers(adjacency, sources, targets, 1)
	parallel := runShortestPathBetweenSetsWithWorkers(adjacency, sources, targets, 8)

	if !reflect.DeepEqual(single, parallel) {
		t.Fatalf("parallel shortest path mismatch: single=%v parallel=%v", single, parallel)
	}
	if len(parallel) != chainLen+2 {
		t.Fatalf("expected %d path nodes, got %d", chainLen+2, len(parallel))
	}
	if parallel[0] != "source" || parallel[len(parallel)-1] != "target" {
		t.Fatalf("unexpected endpoints: %#v", parallel)
	}
	if parallel[65] != "node-64" || parallel[70] != "node-69" {
		t.Fatalf("unexpected wide path reconstruction: %#v", parallel)
	}
}

func runShortestPathBetweenSetsWithWorkers(adjacency map[string]map[string]struct{}, sources, targets map[string]struct{}, workers int) []string {
	previous := parallelTraversalWorkerOverride
	parallelTraversalWorkerOverride = workers
	defer func() {
		parallelTraversalWorkerOverride = previous
	}()
	return shortestPathBetweenSets(adjacency, sources, targets)
}

func buildInformationFlowFixtureGraph(now time.Time) *Graph {
	g := New()

	g.AddNode(&Node{ID: "department:support", Kind: NodeKindDepartment, Name: "Support"})
	g.AddNode(&Node{ID: "department:engineering", Kind: NodeKindDepartment, Name: "Engineering"})
	g.AddNode(&Node{ID: "department:product", Kind: NodeKindDepartment, Name: "Product"})

	g.AddNode(&Node{ID: "person:alice@example.com", Kind: NodeKindPerson, Name: "Alice", Properties: map[string]any{"department": "support", "title": "Support Lead"}})
	g.AddNode(&Node{ID: "person:bob@example.com", Kind: NodeKindPerson, Name: "Bob", Properties: map[string]any{"title": "Support Engineer"}})
	g.AddNode(&Node{ID: "person:carol@example.com", Kind: NodeKindPerson, Name: "Carol", Properties: map[string]any{"department": "engineering", "title": "Senior Engineer"}})
	g.AddNode(&Node{ID: "person:dave@example.com", Kind: NodeKindPerson, Name: "Dave", Properties: map[string]any{"department": "product", "title": "Product Manager"}})
	g.AddNode(&Node{ID: "person:erin@example.com", Kind: NodeKindPerson, Name: "Erin", Properties: map[string]any{"title": "VP Engineering"}})

	g.AddNode(&Node{ID: "system:payment-service", Kind: NodeKindApplication, Name: "payment-service", Risk: RiskHigh})
	g.AddNode(&Node{ID: "customer:northwind", Kind: NodeKindCustomer, Name: "Northwind"})
	g.AddNode(&Node{ID: "ticket:incident-1", Kind: NodeKindTicket, Name: "Incident P1", Properties: map[string]any{"severity": "high"}})
	g.AddNode(&Node{ID: "lead:expansion-1", Kind: NodeKindLead, Name: "Northwind Expansion"})

	g.AddEdge(&Edge{ID: "m1", Source: "person:alice@example.com", Target: "department:support", Kind: EdgeKindMemberOf, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "m2", Source: "person:carol@example.com", Target: "department:engineering", Kind: EdgeKindMemberOf, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "m3", Source: "person:dave@example.com", Target: "department:product", Kind: EdgeKindMemberOf, Effect: EdgeEffectAllow})

	g.AddEdge(&Edge{ID: "ia", Source: "person:alice@example.com", Target: "person:bob@example.com", Kind: EdgeKindInteractedWith, Effect: EdgeEffectAllow, Properties: map[string]any{"frequency": 18, "last_seen": now.Add(-2 * time.Hour)}})
	g.AddEdge(&Edge{ID: "ib", Source: "person:bob@example.com", Target: "person:carol@example.com", Kind: EdgeKindInteractedWith, Effect: EdgeEffectAllow, Properties: map[string]any{"frequency": 12, "last_seen": now.Add(-4 * time.Hour)}})
	g.AddEdge(&Edge{ID: "ic", Source: "person:carol@example.com", Target: "person:dave@example.com", Kind: EdgeKindInteractedWith, Effect: EdgeEffectAllow, Properties: map[string]any{"frequency": 8, "last_seen": now.Add(-6 * time.Hour)}})
	g.AddEdge(&Edge{ID: "id", Source: "person:dave@example.com", Target: "person:erin@example.com", Kind: EdgeKindInteractedWith, Effect: EdgeEffectAllow, Properties: map[string]any{"frequency": 6, "last_seen": now.Add(-8 * time.Hour)}})

	g.AddEdge(&Edge{ID: "resolver-a", Source: "person:alice@example.com", Target: "system:payment-service", Kind: EdgeKindManagedBy, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "resolver-c", Source: "person:carol@example.com", Target: "system:payment-service", Kind: EdgeKindOwns, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "cust-a", Source: "person:alice@example.com", Target: "customer:northwind", Kind: EdgeKindAssignedTo, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "cust-c", Source: "person:carol@example.com", Target: "customer:northwind", Kind: EdgeKindManagedBy, Effect: EdgeEffectAllow})

	g.AddEdge(&Edge{ID: "ticket-escalate", Source: "ticket:incident-1", Target: "person:alice@example.com", Kind: EdgeKindEscalatedTo, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "customer-ticket", Source: "customer:northwind", Target: "ticket:incident-1", Kind: EdgeKindRefers, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "lead-customer", Source: "lead:expansion-1", Target: "customer:northwind", Kind: EdgeKindRefers, Effect: EdgeEffectAllow})

	return g
}
