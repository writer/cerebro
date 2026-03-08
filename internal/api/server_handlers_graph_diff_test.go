package api

import (
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/graph"
)

func TestGraphDiffEndpoint_ReturnsSnapshotDiff(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GRAPH_SNAPSHOT_PATH", dir)

	base := time.Date(2026, 3, 7, 0, 0, 0, 0, time.UTC)
	mustSaveGraphSnapshot(t, dir, &graph.Snapshot{
		Version:   "1.0",
		CreatedAt: base,
		Nodes: []*graph.Node{
			{ID: "node-a", Kind: graph.NodeKindUser, Name: "a"},
		},
	})
	mustSaveGraphSnapshot(t, dir, &graph.Snapshot{
		Version:   "1.0",
		CreatedAt: base.Add(1 * time.Hour),
		Nodes: []*graph.Node{
			{ID: "node-a", Kind: graph.NodeKindUser, Name: "a"},
			{ID: "node-b", Kind: graph.NodeKindBucket, Name: "b"},
		},
	})

	s := newTestServer(t)
	path := fmt.Sprintf(
		"/api/v1/graph/diff?from=%s&to=%s",
		url.QueryEscape(base.Add(10*time.Minute).Format(time.RFC3339)),
		url.QueryEscape(base.Add(70*time.Minute).Format(time.RFC3339)),
	)
	w := do(t, s, http.MethodGet, path, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	nodesAdded, ok := body["nodes_added"].([]any)
	if !ok {
		t.Fatalf("expected nodes_added array, got %T", body["nodes_added"])
	}
	if len(nodesAdded) != 1 {
		t.Fatalf("expected 1 added node, got %d", len(nodesAdded))
	}
	node, ok := nodesAdded[0].(map[string]any)
	if !ok {
		t.Fatalf("expected added node object, got %T", nodesAdded[0])
	}
	if node["id"] != "node-b" {
		t.Fatalf("expected added node-b, got %v", node["id"])
	}
}

func TestGraphDiffEndpoint_InvalidQueryParams(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, http.MethodGet, "/api/v1/graph/diff?from=bad&to=2026-03-07T00:00:00Z", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestGraphDiffEndpoint_NoSnapshots(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GRAPH_SNAPSHOT_PATH", dir)

	s := newTestServer(t)
	w := do(t, s, http.MethodGet, "/api/v1/graph/diff?from=2026-03-07T00:00:00Z&to=2026-03-07T01:00:00Z", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func mustSaveGraphSnapshot(t *testing.T, dir string, snapshot *graph.Snapshot) {
	t.Helper()
	path := filepath.Join(dir, fmt.Sprintf("graph-%s.json.gz", snapshot.CreatedAt.Format("20060102-150405")))
	if err := snapshot.SaveToFile(path); err != nil {
		t.Fatalf("save snapshot: %v", err)
	}
}
