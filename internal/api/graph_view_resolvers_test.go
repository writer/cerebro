package api

import (
	"context"
	"errors"
	"testing"

	"github.com/evalops/cerebro/internal/graph"
)

type countingGraphViewStore struct {
	graph.GraphStore
	snapshots int
}

func (s *countingGraphViewStore) Snapshot(ctx context.Context) (*graph.Snapshot, error) {
	s.snapshots++
	return s.GraphStore.Snapshot(ctx)
}

func TestCurrentOrStoredGraphViewPrefersLiveGraph(t *testing.T) {
	live := graph.New()
	live.AddNode(&graph.Node{ID: "service:live", Kind: graph.NodeKindService})
	store := &countingGraphViewStore{GraphStore: graph.New()}

	view, err := currentOrStoredGraphView(context.Background(), live, store)
	if err != nil {
		t.Fatalf("currentOrStoredGraphView() error = %v", err)
	}
	if view != live {
		t.Fatalf("expected live graph pointer, got %p want %p", view, live)
	}
	if store.snapshots != 0 {
		t.Fatalf("expected no store snapshots, got %d", store.snapshots)
	}
}

func TestCurrentOrStoredGraphViewFallsBackToStoreSnapshot(t *testing.T) {
	storeGraph := graph.New()
	storeGraph.AddNode(&graph.Node{ID: "service:store", Kind: graph.NodeKindService})
	store := &countingGraphViewStore{GraphStore: storeGraph}

	view, err := currentOrStoredGraphView(context.Background(), nil, store)
	if err != nil {
		t.Fatalf("currentOrStoredGraphView() error = %v", err)
	}
	if _, ok := view.GetNode("service:store"); !ok {
		t.Fatalf("expected store-backed view to include restored node, got %#v", view)
	}
	if store.snapshots != 1 {
		t.Fatalf("expected one store snapshot lookup, got %d", store.snapshots)
	}
}

func TestSnapshotBackedGraphViewPrefersStoreSnapshot(t *testing.T) {
	live := graph.New()
	live.AddNode(&graph.Node{ID: "service:live", Kind: graph.NodeKindService})
	storeGraph := graph.New()
	storeGraph.AddNode(&graph.Node{ID: "service:store", Kind: graph.NodeKindService})
	store := &countingGraphViewStore{GraphStore: storeGraph}

	view, err := snapshotBackedGraphView(context.Background(), live, store)
	if err != nil {
		t.Fatalf("snapshotBackedGraphView() error = %v", err)
	}
	if _, ok := view.GetNode("service:store"); !ok {
		t.Fatalf("expected store-backed snapshot view, got %#v", view)
	}
	if _, ok := view.GetNode("service:live"); ok {
		t.Fatalf("expected store-backed snapshot view to ignore live-only nodes, got %#v", view)
	}
	if store.snapshots != 1 {
		t.Fatalf("expected one store snapshot lookup, got %d", store.snapshots)
	}
}

func TestSnapshotBackedGraphViewFallsBackToLiveSnapshot(t *testing.T) {
	live := graph.New()
	live.AddNode(&graph.Node{ID: "service:live", Kind: graph.NodeKindService})

	view, err := snapshotBackedGraphView(context.Background(), live, nil)
	if err != nil {
		t.Fatalf("snapshotBackedGraphView() error = %v", err)
	}
	if view == live {
		t.Fatal("expected snapshot-backed view to be isolated from the live graph")
	}
	if _, ok := view.GetNode("service:live"); !ok {
		t.Fatalf("expected live snapshot view to include restored node, got %#v", view)
	}
}

func TestCurrentOrStoredGraphViewReturnsUnavailableWithoutSources(t *testing.T) {
	_, err := currentOrStoredGraphView(context.Background(), nil, nil)
	if !errors.Is(err, graph.ErrStoreUnavailable) {
		t.Fatalf("currentOrStoredGraphView() error = %v, want ErrStoreUnavailable", err)
	}
}

func TestGraphRiskServiceRiskReportUsesStoreBackedGraphWithoutServer(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "service:store", Kind: graph.NodeKindService})

	service := serverGraphRiskService{
		deps: &serverDependencies{
			graphRuntime: stubGraphRuntime{store: g},
		},
	}

	report, err := service.RiskReport(context.Background())
	if err != nil {
		t.Fatalf("RiskReport() error = %v", err)
	}
	if report == nil {
		t.Fatal("expected store-backed risk report")
	}
}
