package app

import (
	"context"
	"testing"

	"github.com/writer/cerebro/internal/graph"
)

func mustSnapshotGraphStore(t *testing.T, g *graph.Graph) *graph.SnapshotGraphStore {
	t.Helper()
	snapshot, err := g.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	return graph.NewSnapshotGraphStore(snapshot)
}

func mustConfiguredGraphStore(t *testing.T, g *graph.Graph) *graph.Graph {
	t.Helper()
	store := g.Clone()
	store.BuildIndex()
	return store
}

func setConfiguredGraphStore(t *testing.T, application *App, store graph.GraphStore) {
	t.Helper()
	if application == nil {
		t.Fatal("expected app")
		return
	}
	application.configuredSecurityGraphStore = store
	application.configuredSecurityGraphReady = true
}

func setConfiguredGraphFromGraph(t *testing.T, application *App, g *graph.Graph) graph.GraphStore {
	t.Helper()
	store := mustConfiguredGraphStore(t, g)
	setConfiguredGraphStore(t, application, store)
	return store
}

func setConfiguredSnapshotGraphFromGraph(t *testing.T, application *App, g *graph.Graph) *graph.SnapshotGraphStore {
	t.Helper()
	store := mustSnapshotGraphStore(t, g)
	setConfiguredGraphStore(t, application, store)
	return store
}
