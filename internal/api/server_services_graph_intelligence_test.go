package api

import (
	"context"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/graph"
)

type temporalEntityGraphStore struct {
	graph.GraphStore
	snapshotCount  int
	temporalCount  int
	lastEntityID   string
	lastValidAt    time.Time
	lastRecordedAt time.Time
}

func (s *temporalEntityGraphStore) Snapshot(ctx context.Context) (*graph.Snapshot, error) {
	s.snapshotCount++
	return s.GraphStore.Snapshot(ctx)
}

func (s *temporalEntityGraphStore) ExtractSubgraphBitemporal(ctx context.Context, entityID string, opts graph.ExtractSubgraphOptions, validAt, recordedAt time.Time) (*graph.Graph, error) {
	s.temporalCount++
	s.lastEntityID = entityID
	s.lastValidAt = validAt
	s.lastRecordedAt = recordedAt
	return s.ExtractSubgraph(ctx, entityID, opts)
}

type temporalFullGraphStore struct {
	graph.GraphStore
	view          *graph.Graph
	temporalCount int
}

func (s *temporalFullGraphStore) GraphView(context.Context) (*graph.Graph, error) {
	return s.view, nil
}

func (s *temporalFullGraphStore) ExtractSubgraphBitemporal(ctx context.Context, entityID string, opts graph.ExtractSubgraphOptions, validAt, recordedAt time.Time) (*graph.Graph, error) {
	s.temporalCount++
	return s.ExtractSubgraph(ctx, entityID, opts)
}

func TestGraphIntelligenceServiceCurrentEntityGraphPrefersLiveGraph(t *testing.T) {
	fullGraph := buildGraphStorePlatformEntitiesTestGraph(t)
	store := &countingSnapshotStore{GraphStore: fullGraph}
	service := newGraphIntelligenceService(&serverDependencies{
		graphRuntime: stubGraphRuntime{graph: fullGraph, store: store},
	})

	current, err := service.CurrentEntityGraph(context.Background(), "arn:aws:s3:::audit-logs", time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("CurrentEntityGraph() error = %v", err)
	}
	if current == nil {
		t.Fatal("CurrentEntityGraph() returned nil graph")
		return
	}
	if current != fullGraph {
		t.Fatal("CurrentEntityGraph() should return the live graph when it is available")
	}
	if got := store.count.Load(); got != 0 {
		t.Fatalf("expected live graph reads to avoid snapshot materialization, got %d snapshot calls", got)
	}
}

func TestGraphIntelligenceServiceCurrentEntityGraphUsesSnapshotFallback(t *testing.T) {
	fullGraph := buildGraphStorePlatformEntitiesTestGraph(t)
	store := &countingSnapshotStore{GraphStore: fullGraph}
	service := newGraphIntelligenceService(&serverDependencies{
		graphRuntime: stubGraphRuntime{store: store},
	})

	at := time.Date(2026, 3, 10, 10, 0, 0, 0, time.UTC)
	view, err := service.CurrentEntityGraph(context.Background(), "arn:aws:s3:::audit-logs", at, at)
	if err != nil {
		t.Fatalf("CurrentEntityGraph() error = %v", err)
	}
	if view == nil {
		t.Fatal("CurrentEntityGraph() returned nil graph")
		return
	}
	if _, ok := view.GetNode("arn:aws:s3:::audit-logs"); !ok {
		t.Fatal("expected snapshot fallback to include requested entity")
	}
	if _, ok := view.GetNode("person:alice@example.com"); !ok {
		t.Fatal("expected snapshot fallback to preserve unrelated nodes needed by report facets")
	}
	if got := store.count.Load(); got != 1 {
		t.Fatalf("expected one snapshot materialization for temporal fallback, got %d", got)
	}
}

func TestGraphIntelligenceServiceCurrentEntityGraphUsesBitemporalStoreQueries(t *testing.T) {
	fullGraph := buildGraphStorePlatformEntitiesTestGraph(t)
	store := &temporalEntityGraphStore{GraphStore: nilSnapshotGraphStore{GraphStore: fullGraph}}
	service := newGraphIntelligenceService(&serverDependencies{
		graphRuntime: stubGraphRuntime{store: store},
	})

	validAt := time.Date(2026, 3, 10, 10, 0, 0, 0, time.UTC)
	recordedAt := validAt.Add(5 * time.Minute)
	view, err := service.CurrentEntityGraph(context.Background(), "arn:aws:s3:::audit-logs", validAt, recordedAt)
	if err != nil {
		t.Fatalf("CurrentEntityGraph() error = %v", err)
	}
	if view == nil {
		t.Fatal("CurrentEntityGraph() returned nil graph")
		return
	}
	if store.temporalCount != 1 {
		t.Fatalf("expected one bitemporal store lookup, got %d", store.temporalCount)
	}
	if store.snapshotCount != 1 {
		t.Fatalf("expected one snapshot attempt before bitemporal fallback, got %d snapshot calls", store.snapshotCount)
	}
	if store.lastEntityID != "arn:aws:s3:::audit-logs" {
		t.Fatalf("entityID = %q, want arn:aws:s3:::audit-logs", store.lastEntityID)
	}
	if !store.lastValidAt.Equal(validAt) || !store.lastRecordedAt.Equal(recordedAt) {
		t.Fatalf("unexpected temporal bounds: validAt=%s recordedAt=%s", store.lastValidAt, store.lastRecordedAt)
	}
}

func TestGraphIntelligenceServiceCurrentEntityGraphPrefersFullGraphViewForTemporalReads(t *testing.T) {
	fullGraph := buildGraphStorePlatformEntitiesTestGraph(t)
	fullGraph.AddNode(&graph.Node{ID: "service:isolated", Kind: graph.NodeKindService, Name: "Isolated"})
	fullGraph.BuildIndex()

	store := &temporalFullGraphStore{GraphStore: fullGraph, view: fullGraph}
	service := newGraphIntelligenceService(&serverDependencies{
		graphRuntime: stubGraphRuntime{store: store},
	})

	at := time.Date(2026, 3, 10, 10, 0, 0, 0, time.UTC)
	view, err := service.CurrentEntityGraph(context.Background(), "arn:aws:s3:::audit-logs", at, at)
	if err != nil {
		t.Fatalf("CurrentEntityGraph() error = %v", err)
	}
	if view == nil {
		t.Fatal("CurrentEntityGraph() returned nil graph")
	}
	if _, ok := view.GetNode("service:isolated"); !ok {
		t.Fatal("expected temporal entity graph to preserve unrelated nodes from the full graph view")
	}
	if store.temporalCount != 0 {
		t.Fatalf("expected temporal entity graph to avoid subgraph extraction when a full graph view is available, got %d extraction calls", store.temporalCount)
	}
}

func TestGraphIntelligenceServiceCurrentEntityGraphUsesGraphViewFallbackWhenTemporalSnapshotsUnavailable(t *testing.T) {
	fullGraph := buildGraphStorePlatformEntitiesTestGraph(t)
	service := newGraphIntelligenceService(&serverDependencies{
		graphRuntime: stubGraphRuntime{store: nilSnapshotGraphStore{GraphStore: fullGraph}},
	})

	at := time.Date(2026, 3, 10, 10, 0, 0, 0, time.UTC)
	view, err := service.CurrentEntityGraph(context.Background(), "arn:aws:s3:::audit-logs", at, at)
	if err != nil {
		t.Fatalf("CurrentEntityGraph() error = %v", err)
	}
	if view == nil {
		t.Fatal("CurrentEntityGraph() returned nil graph")
	}
	if _, ok := view.GetNode("arn:aws:s3:::audit-logs"); !ok {
		t.Fatal("expected graph-view fallback to include requested entity")
	}
	if _, ok := view.GetNode("person:alice@example.com"); !ok {
		t.Fatal("expected graph-view fallback to preserve unrelated nodes needed by report facets")
	}
}
