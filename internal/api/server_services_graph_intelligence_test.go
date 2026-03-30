package api

import (
	"context"
	"testing"
	"time"
)

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
