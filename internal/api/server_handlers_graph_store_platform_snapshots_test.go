package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/app"
	"github.com/evalops/cerebro/internal/graph"
)

func newStoreBackedPlatformSnapshotServer(t *testing.T, store graph.GraphStore) *Server {
	t.Helper()
	s := NewServerWithDependencies(serverDependencies{
		Config:       &app.Config{GraphSnapshotPath: t.TempDir()},
		graphRuntime: stubGraphRuntime{store: store},
	})
	t.Cleanup(func() { s.Close() })
	return s
}

func buildPlatformGraphSnapshotCatalogTestGraph() *graph.Graph {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "service:payments", Kind: graph.NodeKindService, Name: "Payments"})
	g.SetMetadata(graph.Metadata{
		BuiltAt:       time.Date(2026, 3, 18, 13, 45, 0, 0, time.UTC),
		NodeCount:     1,
		EdgeCount:     0,
		Providers:     []string{"github"},
		Accounts:      []string{"acct-a"},
		BuildDuration: 2 * time.Second,
	})
	return g
}

func TestPlatformGraphSnapshotCatalogUsesGraphStoreWhenRawGraphUnavailable(t *testing.T) {
	s := newStoreBackedPlatformSnapshotServer(t, buildPlatformGraphSnapshotCatalogTestGraph())

	resp := do(t, s, http.MethodGet, "/api/v1/platform/graph/snapshots", nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected snapshot catalog 200, got %d: %s", resp.Code, resp.Body.String())
	}
	body := decodeJSON(t, resp)
	if got := body["count"]; got != float64(1) {
		t.Fatalf("expected one snapshot from graph store, got %#v", got)
	}
	snapshots, ok := body["snapshots"].([]any)
	if !ok || len(snapshots) != 1 {
		t.Fatalf("expected one snapshot entry, got %#v", body["snapshots"])
	}
	snapshot, ok := snapshots[0].(map[string]any)
	if !ok {
		t.Fatalf("expected snapshot object, got %#v", snapshots[0])
	}
	if got := snapshot["current"]; got != true {
		t.Fatalf("expected current snapshot flag, got %#v", got)
	}
	if got := snapshot["node_count"]; got != float64(1) {
		t.Fatalf("expected node_count=1, got %#v", got)
	}
}

func TestPlatformGraphSnapshotGetUsesGraphStoreWhenRawGraphUnavailable(t *testing.T) {
	s := newStoreBackedPlatformSnapshotServer(t, buildPlatformGraphSnapshotCatalogTestGraph())

	list := do(t, s, http.MethodGet, "/api/v1/platform/graph/snapshots", nil)
	if list.Code != http.StatusOK {
		t.Fatalf("expected snapshot catalog 200, got %d: %s", list.Code, list.Body.String())
	}
	listBody := decodeJSON(t, list)
	snapshots, ok := listBody["snapshots"].([]any)
	if !ok || len(snapshots) != 1 {
		t.Fatalf("expected one snapshot entry, got %#v", listBody["snapshots"])
	}
	snapshot, ok := snapshots[0].(map[string]any)
	if !ok {
		t.Fatalf("expected snapshot object, got %#v", snapshots[0])
	}
	snapshotID, _ := snapshot["id"].(string)
	if snapshotID == "" {
		t.Fatalf("expected snapshot id, got %#v", snapshot["id"])
	}

	get := do(t, s, http.MethodGet, "/api/v1/platform/graph/snapshots/"+snapshotID, nil)
	if get.Code != http.StatusOK {
		t.Fatalf("expected snapshot get 200, got %d: %s", get.Code, get.Body.String())
	}
	getBody := decodeJSON(t, get)
	if got := getBody["id"]; got != snapshotID {
		t.Fatalf("expected snapshot id %q, got %#v", snapshotID, got)
	}
	if got := getBody["current"]; got != true {
		t.Fatalf("expected current snapshot flag, got %#v", got)
	}
}
