package app

import (
	"testing"

	"github.com/writer/cerebro/internal/graph"
)

func TestCurrentOrStoredEventRoutingGraphUsesConfiguredStoreWhenLiveGraphUnavailable(t *testing.T) {
	configured := graph.New()
	configured.AddNode(&graph.Node{ID: "service:payments", Kind: graph.NodeKindService, Name: "payments"})
	configured.BuildIndex()

	application := &App{Config: &Config{}}
	setConfiguredSnapshotGraphFromGraph(t, application, configured)

	resolved := application.currentOrStoredEventRoutingGraph()
	if resolved == nil {
		t.Fatal("expected configured graph for event routing")
	}
	if _, ok := resolved.GetNode("service:payments"); !ok {
		t.Fatal("expected configured graph node to be available for event routing")
	}
}

func TestCurrentOrStoredEventRoutingGraphPrefersLiveGraph(t *testing.T) {
	live := graph.New()
	live.AddNode(&graph.Node{ID: "service:live", Kind: graph.NodeKindService, Name: "live"})
	live.BuildIndex()

	persisted := graph.New()
	persisted.AddNode(&graph.Node{ID: "service:stored", Kind: graph.NodeKindService, Name: "stored"})
	persisted.BuildIndex()

	application := &App{
		Config:        &Config{},
		SecurityGraph: live,
	}
	setConfiguredSnapshotGraphFromGraph(t, application, persisted)

	resolved := application.currentOrStoredEventRoutingGraph()
	if resolved != live {
		t.Fatal("expected event routing to prefer the live graph")
	}
	if _, ok := resolved.GetNode("service:live"); !ok {
		t.Fatal("expected live graph node to be available for event routing")
	}
	if _, ok := resolved.GetNode("service:stored"); ok {
		t.Fatal("expected configured graph to be ignored when live graph is present")
	}
}
