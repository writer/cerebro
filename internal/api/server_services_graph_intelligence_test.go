package api

import (
	"context"
	"testing"
	"time"
)

func TestGraphIntelligenceServiceCurrentEntityGraphScopesLiveGraph(t *testing.T) {
	fullGraph := buildGraphStorePlatformEntitiesTestGraph(t)
	store := &countingSnapshotStore{GraphStore: fullGraph}
	service := newGraphIntelligenceService(&serverDependencies{
		graphRuntime: stubGraphRuntime{graph: fullGraph, store: store},
	})

	scoped, err := service.CurrentEntityGraph(context.Background(), "arn:aws:s3:::audit-logs", time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("CurrentEntityGraph() error = %v", err)
	}
	if scoped == nil {
		t.Fatal("CurrentEntityGraph() returned nil graph")
	}
	if scoped == fullGraph {
		t.Fatal("CurrentEntityGraph() returned the full live graph instead of a scoped subgraph")
	}
	if _, ok := scoped.GetNode("arn:aws:s3:::audit-logs"); !ok {
		t.Fatal("expected scoped graph to include requested entity")
	}
	if _, ok := scoped.GetNode("person:alice@example.com"); ok {
		t.Fatal("expected scoped graph to exclude unrelated nodes")
	}
	if got := store.count.Load(); got != 0 {
		t.Fatalf("expected live graph extraction to avoid snapshot materialization, got %d snapshot calls", got)
	}
}

func TestGraphIntelligenceServiceCurrentEntityGraphScopesSnapshotFallback(t *testing.T) {
	fullGraph := buildGraphStorePlatformEntitiesTestGraph(t)
	store := &countingSnapshotStore{GraphStore: fullGraph}
	service := newGraphIntelligenceService(&serverDependencies{
		graphRuntime: stubGraphRuntime{store: store},
	})

	at := time.Date(2026, 3, 10, 10, 0, 0, 0, time.UTC)
	scoped, err := service.CurrentEntityGraph(context.Background(), "arn:aws:s3:::audit-logs", at, at)
	if err != nil {
		t.Fatalf("CurrentEntityGraph() error = %v", err)
	}
	if scoped == nil {
		t.Fatal("CurrentEntityGraph() returned nil graph")
	}
	if _, ok := scoped.GetNode("arn:aws:s3:::audit-logs"); !ok {
		t.Fatal("expected snapshot fallback to include requested entity")
	}
	if _, ok := scoped.GetNode("person:alice@example.com"); ok {
		t.Fatal("expected snapshot fallback to exclude unrelated nodes")
	}
	if got := store.count.Load(); got != 1 {
		t.Fatalf("expected one snapshot materialization for temporal fallback, got %d", got)
	}
}
