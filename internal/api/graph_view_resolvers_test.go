package api

import (
	"context"
	"errors"
	"testing"

	"github.com/writer/cerebro/internal/graph"
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

func TestCurrentOrStoredGraphSnapshotRecordPrefersLiveRecord(t *testing.T) {
	live := buildPlatformGraphSnapshotCatalogTestGraph()
	store := &countingGraphViewStore{GraphStore: buildPlatformGraphSnapshotCatalogTestGraph()}

	record, err := currentOrStoredGraphSnapshotRecord(context.Background(), live, store)
	if err != nil {
		t.Fatalf("currentOrStoredGraphSnapshotRecord() error = %v", err)
	}
	if record == nil {
		t.Fatal("expected live snapshot record")
	}
	if got := record.NodeCount; got != 1 {
		t.Fatalf("record node_count = %d, want 1", got)
	}
	if store.snapshots != 0 {
		t.Fatalf("expected no store snapshots, got %d", store.snapshots)
	}
}

func TestCurrentOrStoredGraphSnapshotRecordFallsBackToStoreRecord(t *testing.T) {
	live := graph.New()
	store := &countingGraphViewStore{GraphStore: buildPlatformGraphSnapshotCatalogTestGraph()}

	record, err := currentOrStoredGraphSnapshotRecord(context.Background(), live, store)
	if err != nil {
		t.Fatalf("currentOrStoredGraphSnapshotRecord() error = %v", err)
	}
	if record == nil {
		t.Fatal("expected store-backed snapshot record")
	}
	if got := record.NodeCount; got != 1 {
		t.Fatalf("record node_count = %d, want 1", got)
	}
	if store.snapshots != 1 {
		t.Fatalf("expected one store snapshot lookup, got %d", store.snapshots)
	}
}

func TestCurrentOrStoredGraphSnapshotRecordReturnsNilWhenStoreSnapshotHasNoCurrentRecord(t *testing.T) {
	live := graph.New()
	storeGraph := graph.New()
	storeGraph.AddNode(&graph.Node{ID: "service:store", Kind: graph.NodeKindService})
	store := &countingGraphViewStore{GraphStore: storeGraph}

	record, err := currentOrStoredGraphSnapshotRecord(context.Background(), live, store)
	if err != nil {
		t.Fatalf("currentOrStoredGraphSnapshotRecord() error = %v", err)
	}
	if record != nil {
		t.Fatalf("expected nil snapshot record, got %#v", record)
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

func TestCurrentOrStoredGraphSnapshotRecordReturnsUnavailableWithoutSources(t *testing.T) {
	_, err := currentOrStoredGraphSnapshotRecord(context.Background(), nil, nil)
	if !errors.Is(err, graph.ErrStoreUnavailable) {
		t.Fatalf("currentOrStoredGraphSnapshotRecord() error = %v, want ErrStoreUnavailable", err)
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

func TestCurrentOrStoredTenantGraphViewUsesTenantRuntimeGraph(t *testing.T) {
	live := graph.New()
	live.AddNode(&graph.Node{ID: "service:live", Kind: graph.NodeKindService})
	store := &countingGraphViewStore{GraphStore: graph.New()}
	deps := &serverDependencies{
		graphRuntime: stubGraphRuntime{
			graph: live,
			store: store,
		},
	}

	ctx := context.WithValue(context.Background(), contextKeyTenant, "tenant-a")
	view, err := currentOrStoredTenantGraphView(ctx, deps)
	if err != nil {
		t.Fatalf("currentOrStoredTenantGraphView() error = %v", err)
	}
	if _, ok := view.GetNode("service:live"); !ok {
		t.Fatalf("expected live tenant graph view to include restored node, got %#v", view)
	}
	if store.snapshots != 0 {
		t.Fatalf("expected no store snapshots, got %d", store.snapshots)
	}
}

func TestCurrentOrStoredTenantGraphViewFallsBackToTenantStore(t *testing.T) {
	storeGraph := graph.New()
	storeGraph.AddNode(&graph.Node{ID: "service:store", Kind: graph.NodeKindService})
	store := &countingGraphViewStore{GraphStore: storeGraph}
	deps := &serverDependencies{
		graphRuntime: stubGraphRuntime{
			store: store,
		},
	}

	ctx := context.WithValue(context.Background(), contextKeyTenant, "tenant-a")
	view, err := currentOrStoredTenantGraphView(ctx, deps)
	if err != nil {
		t.Fatalf("currentOrStoredTenantGraphView() error = %v", err)
	}
	if _, ok := view.GetNode("service:store"); !ok {
		t.Fatalf("expected tenant store-backed view to include restored node, got %#v", view)
	}
	if store.snapshots != 1 {
		t.Fatalf("expected one tenant store snapshot lookup, got %d", store.snapshots)
	}
}
