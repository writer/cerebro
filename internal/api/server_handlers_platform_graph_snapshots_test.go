package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/webhooks"
)

func TestPlatformGraphSnapshotAncestryAndDiffEndpoints(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GRAPH_SNAPSHOT_PATH", dir)

	base := time.Now().UTC().Add(-6 * 24 * time.Hour).Truncate(time.Minute)
	older := &graph.Snapshot{
		Version:   "1.0",
		CreatedAt: base.Add(5 * time.Minute),
		Metadata: graph.Metadata{
			BuiltAt:   base,
			NodeCount: 1,
			EdgeCount: 0,
			Providers: []string{"aws"},
			Accounts:  []string{"acct-a"},
		},
		Nodes: []*graph.Node{
			{ID: "node-a", Kind: graph.NodeKindUser, Name: "a"},
		},
	}
	newer := &graph.Snapshot{
		Version:   "1.0",
		CreatedAt: base.Add(65 * time.Minute),
		Metadata: graph.Metadata{
			BuiltAt:   base.Add(1 * time.Hour),
			NodeCount: 2,
			EdgeCount: 1,
			Providers: []string{"aws"},
			Accounts:  []string{"acct-a"},
		},
		Nodes: []*graph.Node{
			{ID: "node-a", Kind: graph.NodeKindUser, Name: "a"},
			{ID: "node-b", Kind: graph.NodeKindBucket, Name: "b"},
		},
		Edges: []*graph.Edge{
			{ID: "edge-1", Source: "node-a", Target: "node-b", Kind: graph.EdgeKindCanRead},
		},
	}
	mustSaveGraphSnapshot(t, dir, older)
	mustSaveGraphSnapshot(t, dir, newer)

	s := newTestServer(t)
	list := do(t, s, http.MethodGet, "/api/v1/platform/graph/snapshots", nil)
	if list.Code != http.StatusOK {
		t.Fatalf("expected 200 for snapshot catalog, got %d: %s", list.Code, list.Body.String())
	}
	listBody := decodeJSON(t, list)
	snapshots, ok := listBody["snapshots"].([]any)
	if !ok || len(snapshots) != 2 {
		t.Fatalf("expected two file-backed snapshot entries, got %#v", listBody["snapshots"])
	}
	newerSnapshot := snapshots[0].(map[string]any)
	olderSnapshot := snapshots[1].(map[string]any)
	newerID, _ := newerSnapshot["id"].(string)
	olderID, _ := olderSnapshot["id"].(string)
	if newerID == "" || olderID == "" {
		t.Fatalf("expected snapshot ids, got newer=%#v older=%#v", newerSnapshot["id"], olderSnapshot["id"])
	}
	if got := newerSnapshot["diffable"]; got != true {
		t.Fatalf("expected newer snapshot diffable=true, got %#v", got)
	}
	if got := newerSnapshot["materialized"]; got != true {
		t.Fatalf("expected newer snapshot materialized=true, got %#v", got)
	}
	if got := newerSnapshot["storage_class"]; got != "local_snapshot_store" {
		t.Fatalf("expected local snapshot storage class, got %#v", got)
	}
	if got := newerSnapshot["retention_class"]; got != "local_retained" {
		t.Fatalf("expected local snapshot retention class, got %#v", got)
	}
	if got := newerSnapshot["parent_snapshot_id"]; got != olderID {
		t.Fatalf("expected parent snapshot id %s, got %#v", olderID, got)
	}
	if got, ok := newerSnapshot["integrity_hash"].(string); !ok || got == "" {
		t.Fatalf("expected integrity_hash on snapshot resource, got %#v", newerSnapshot["integrity_hash"])
	}

	ancestry := do(t, s, http.MethodGet, "/api/v1/platform/graph/snapshots/"+newerID+"/ancestry", nil)
	if ancestry.Code != http.StatusOK {
		t.Fatalf("expected 200 for snapshot ancestry, got %d: %s", ancestry.Code, ancestry.Body.String())
	}
	ancestryBody := decodeJSON(t, ancestry)
	if got := ancestryBody["count"]; got != float64(2) {
		t.Fatalf("expected ancestry count=2, got %#v", got)
	}
	previous, ok := ancestryBody["previous"].(map[string]any)
	if !ok {
		t.Fatalf("expected previous snapshot reference, got %#v", ancestryBody["previous"])
	}
	if got := previous["id"]; got != olderID {
		t.Fatalf("expected previous snapshot id %s, got %#v", olderID, got)
	}
	parent, ok := ancestryBody["parent"].(map[string]any)
	if !ok {
		t.Fatalf("expected explicit parent snapshot reference, got %#v", ancestryBody["parent"])
	}
	if got := parent["id"]; got != olderID {
		t.Fatalf("expected parent snapshot id %s, got %#v", olderID, got)
	}

	diffByPath := do(t, s, http.MethodGet, "/api/v1/platform/graph/snapshots/"+olderID+"/diffs/"+newerID, nil)
	if diffByPath.Code != http.StatusOK {
		t.Fatalf("expected 200 for snapshot diff path, got %d: %s", diffByPath.Code, diffByPath.Body.String())
	}
	diffByPathBody := decodeJSON(t, diffByPath)
	summary, ok := diffByPathBody["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected diff summary, got %#v", diffByPathBody["summary"])
	}
	if got := summary["nodes_added"]; got != float64(1) {
		t.Fatalf("expected nodes_added=1, got %#v", got)
	}
	if got := summary["edges_added"]; got != float64(1) {
		t.Fatalf("expected edges_added=1, got %#v", got)
	}
	diff, ok := diffByPathBody["diff"].(map[string]any)
	if !ok {
		t.Fatalf("expected diff payload, got %#v", diffByPathBody["diff"])
	}
	nodesAdded, ok := diff["nodes_added"].([]any)
	if !ok || len(nodesAdded) != 1 {
		t.Fatalf("expected one added node, got %#v", diff["nodes_added"])
	}
	if got := nodesAdded[0].(map[string]any)["id"]; got != "node-b" {
		t.Fatalf("expected node-b added, got %#v", got)
	}

	diffByPost := do(t, s, http.MethodPost, "/api/v1/platform/graph/diffs", map[string]any{
		"from_snapshot_id": olderID,
		"to_snapshot_id":   newerID,
	})
	if diffByPost.Code != http.StatusOK {
		t.Fatalf("expected 200 for snapshot diff POST, got %d: %s", diffByPost.Code, diffByPost.Body.String())
	}
	diffByPostBody := decodeJSON(t, diffByPost)
	if got := diffByPostBody["id"]; got == "" {
		t.Fatalf("expected typed diff resource id, got %#v", got)
	}
}

func TestPlatformGraphSnapshotAsyncDiffArtifactEndpoint(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GRAPH_SNAPSHOT_PATH", dir)

	base := time.Date(2026, 3, 7, 2, 0, 0, 0, time.UTC)
	older := &graph.Snapshot{
		Version:   "1.0",
		CreatedAt: base.Add(5 * time.Minute),
		Metadata: graph.Metadata{
			BuiltAt:   base,
			NodeCount: 1,
			EdgeCount: 0,
			Providers: []string{"aws"},
			Accounts:  []string{"acct-a"},
		},
		Nodes: []*graph.Node{
			{ID: "node-a", Kind: graph.NodeKindUser, Name: "a"},
		},
	}
	newer := &graph.Snapshot{
		Version:   "1.0",
		CreatedAt: base.Add(65 * time.Minute),
		Metadata: graph.Metadata{
			BuiltAt:   base.Add(1 * time.Hour),
			NodeCount: 2,
			EdgeCount: 1,
			Providers: []string{"aws"},
			Accounts:  []string{"acct-a"},
		},
		Nodes: []*graph.Node{
			{ID: "node-a", Kind: graph.NodeKindUser, Name: "a"},
			{ID: "node-b", Kind: graph.NodeKindBucket, Name: "b"},
		},
		Edges: []*graph.Edge{
			{ID: "edge-1", Source: "node-a", Target: "node-b", Kind: graph.EdgeKindCanRead},
		},
	}
	mustSaveGraphSnapshot(t, dir, older)
	mustSaveGraphSnapshot(t, dir, newer)

	s := newTestServer(t)
	list := do(t, s, http.MethodGet, "/api/v1/platform/graph/snapshots", nil)
	if list.Code != http.StatusOK {
		t.Fatalf("expected 200 for snapshot catalog, got %d: %s", list.Code, list.Body.String())
	}
	body := decodeJSON(t, list)
	snapshots, ok := body["snapshots"].([]any)
	if !ok || len(snapshots) != 2 {
		t.Fatalf("expected two snapshots, got %#v", body["snapshots"])
	}
	newerID, _ := snapshots[0].(map[string]any)["id"].(string)
	olderID, _ := snapshots[1].(map[string]any)["id"].(string)

	create := do(t, s, http.MethodPost, "/api/v1/platform/graph/diffs", map[string]any{
		"from_snapshot_id": olderID,
		"to_snapshot_id":   newerID,
		"execution_mode":   "async",
	})
	if create.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for async diff creation, got %d: %s", create.Code, create.Body.String())
	}
	job := decodeJSON(t, create)
	statusURL, _ := job["status_url"].(string)
	jobID, _ := job["id"].(string)
	if statusURL == "" || jobID == "" {
		t.Fatalf("expected async platform job metadata, got %#v", job)
	}

	statusBody := waitForPlatformJobState(t, s, statusURL, "succeeded")
	result, ok := statusBody["result"].(map[string]any)
	if !ok {
		t.Fatalf("expected job result payload, got %#v", statusBody["result"])
	}
	diffURL, _ := result["diff_url"].(string)
	diffID, _ := result["diff_id"].(string)
	if diffURL == "" || diffID == "" {
		t.Fatalf("expected diff artifact metadata, got %#v", result)
	}
	if got := result["job_id"]; got != jobID {
		t.Fatalf("expected result job_id %s, got %#v", jobID, got)
	}

	diff := do(t, s, http.MethodGet, diffURL, nil)
	if diff.Code != http.StatusOK {
		t.Fatalf("expected 200 for diff artifact lookup, got %d: %s", diff.Code, diff.Body.String())
	}
	diffBody := decodeJSON(t, diff)
	if got := diffBody["id"]; got != diffID {
		t.Fatalf("expected diff artifact id %s, got %#v", diffID, got)
	}
	if got := diffBody["materialized"]; got != true {
		t.Fatalf("expected materialized diff artifact, got %#v", got)
	}
	if got := diffBody["storage_class"]; got != "local_diff_store" {
		t.Fatalf("expected diff storage class local_diff_store, got %#v", got)
	}
	if got := diffBody["job_id"]; got != jobID {
		t.Fatalf("expected diff job id %s, got %#v", jobID, got)
	}
	if got, ok := diffBody["integrity_hash"].(string); !ok || got == "" {
		t.Fatalf("expected diff integrity_hash, got %#v", diffBody["integrity_hash"])
	}

	diffFiles, err := filepath.Glob(filepath.Join(dir, "diffs", "*.json"))
	if err != nil {
		t.Fatalf("glob diff artifacts: %v", err)
	}
	if len(diffFiles) != 1 {
		t.Fatalf("expected one materialized diff artifact, got %d", len(diffFiles))
	}
}

func TestPlatformGraphDiffRequiresMaterializedSnapshots(t *testing.T) {
	s := newTestServer(t)
	now := time.Date(2026, 3, 10, 12, 30, 0, 0, time.UTC)
	s.app.SecurityGraph.SetMetadata(graph.Metadata{
		BuiltAt:   now,
		NodeCount: 1,
		EdgeCount: 0,
	})

	list := do(t, s, http.MethodGet, "/api/v1/platform/graph/snapshots", nil)
	if list.Code != http.StatusOK {
		t.Fatalf("expected 200 for snapshot catalog, got %d: %s", list.Code, list.Body.String())
	}
	body := decodeJSON(t, list)
	snapshots, ok := body["snapshots"].([]any)
	if !ok || len(snapshots) != 1 {
		t.Fatalf("expected one current snapshot, got %#v", body["snapshots"])
	}
	snapshotID, _ := snapshots[0].(map[string]any)["id"].(string)
	diff := do(t, s, http.MethodPost, "/api/v1/platform/graph/diffs", map[string]any{
		"from_snapshot_id": snapshotID,
		"to_snapshot_id":   snapshotID,
	})
	if diff.Code != http.StatusConflict {
		t.Fatalf("expected 409 for non-materialized snapshot diff, got %d: %s", diff.Code, diff.Body.String())
	}
}

func TestPlatformGraphDiffMaterializationIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GRAPH_SNAPSHOT_PATH", dir)

	base := time.Date(2026, 3, 7, 3, 0, 0, 0, time.UTC)
	older := &graph.Snapshot{
		Version:   "1.0",
		CreatedAt: base.Add(5 * time.Minute),
		Metadata: graph.Metadata{
			BuiltAt:   base,
			NodeCount: 1,
			EdgeCount: 0,
			Providers: []string{"aws"},
			Accounts:  []string{"acct-a"},
		},
		Nodes: []*graph.Node{
			{ID: "node-a", Kind: graph.NodeKindUser, Name: "a"},
		},
	}
	newer := &graph.Snapshot{
		Version:   "1.0",
		CreatedAt: base.Add(65 * time.Minute),
		Metadata: graph.Metadata{
			BuiltAt:   base.Add(1 * time.Hour),
			NodeCount: 2,
			EdgeCount: 1,
			Providers: []string{"aws"},
			Accounts:  []string{"acct-a"},
		},
		Nodes: []*graph.Node{
			{ID: "node-a", Kind: graph.NodeKindUser, Name: "a"},
			{ID: "node-b", Kind: graph.NodeKindBucket, Name: "b"},
		},
		Edges: []*graph.Edge{
			{ID: "edge-1", Source: "node-a", Target: "node-b", Kind: graph.EdgeKindCanRead},
		},
	}
	mustSaveGraphSnapshot(t, dir, older)
	mustSaveGraphSnapshot(t, dir, newer)

	s := newTestServer(t)
	body := decodeJSON(t, do(t, s, http.MethodGet, "/api/v1/platform/graph/snapshots", nil))
	snapshots := body["snapshots"].([]any)
	newerID, _ := snapshots[0].(map[string]any)["id"].(string)
	olderID, _ := snapshots[1].(map[string]any)["id"].(string)

	changelogEvents := make(chan webhooks.Event, 2)
	s.app.Webhooks.Subscribe(func(_ context.Context, event webhooks.Event) error {
		if event.Type == webhooks.EventPlatformGraphChangelogComputed {
			changelogEvents <- event
		}
		return nil
	})

	first := do(t, s, http.MethodPost, "/api/v1/platform/graph/diffs", map[string]any{
		"from_snapshot_id":   olderID,
		"to_snapshot_id":     newerID,
		"materialize_result": true,
	})
	if first.Code != http.StatusOK {
		t.Fatalf("expected 200 for first diff materialization, got %d: %s", first.Code, first.Body.String())
	}
	firstBody := decodeJSON(t, first)
	firstStoredAt, _ := firstBody["stored_at"].(string)
	if firstStoredAt == "" {
		t.Fatalf("expected stored_at on materialized diff, got %#v", firstBody)
	}

	select {
	case <-changelogEvents:
	case <-time.After(2 * time.Second):
		t.Fatal("expected webhook emission for first materialization")
	}

	second := do(t, s, http.MethodPost, "/api/v1/platform/graph/diffs", map[string]any{
		"from_snapshot_id":   olderID,
		"to_snapshot_id":     newerID,
		"materialize_result": true,
	})
	if second.Code != http.StatusOK {
		t.Fatalf("expected 200 for repeated diff materialization, got %d: %s", second.Code, second.Body.String())
	}
	secondBody := decodeJSON(t, second)
	if got := secondBody["id"]; got != firstBody["id"] {
		t.Fatalf("expected repeated materialization to reuse diff id %#v, got %#v", firstBody["id"], got)
	}
	if got := secondBody["stored_at"]; got != firstStoredAt {
		t.Fatalf("expected repeated materialization to reuse stored_at %q, got %#v", firstStoredAt, got)
	}

	select {
	case event := <-changelogEvents:
		t.Fatalf("expected repeated materialization to avoid duplicate webhook emission, got %#v", event)
	default:
	}
}

func TestPlatformGraphChangelogAndDiffDetailsEndpoints(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GRAPH_SNAPSHOT_PATH", dir)

	base := time.Now().UTC().Add(-6 * 24 * time.Hour).Truncate(time.Minute)
	older := &graph.Snapshot{
		Version:   "1.0",
		CreatedAt: base.Add(5 * time.Minute),
		Metadata: graph.Metadata{
			BuiltAt:   base,
			NodeCount: 1,
			EdgeCount: 0,
			Providers: []string{"aws"},
			Accounts:  []string{"acct-a"},
		},
		Nodes: []*graph.Node{
			{ID: "service:payments", Kind: graph.NodeKindService, Name: "Payments", Provider: "aws", Account: "acct-a"},
		},
	}
	newer := &graph.Snapshot{
		Version:   "1.0",
		CreatedAt: base.Add(65 * time.Minute),
		Metadata: graph.Metadata{
			BuiltAt:   base.Add(1 * time.Hour),
			NodeCount: 2,
			EdgeCount: 1,
			Providers: []string{"aws"},
			Accounts:  []string{"acct-a"},
		},
		Nodes: []*graph.Node{
			{ID: "service:payments", Kind: graph.NodeKindService, Name: "Payments", Provider: "aws", Account: "acct-a"},
			{ID: "bucket:logs", Kind: graph.NodeKindBucket, Name: "Logs", Provider: "aws", Account: "acct-a", Properties: map[string]any{"source_system": "aws"}},
		},
		Edges: []*graph.Edge{
			{ID: "service:payments->bucket:logs:targets", Source: "service:payments", Target: "bucket:logs", Kind: graph.EdgeKindTargets},
		},
	}
	latest := &graph.Snapshot{
		Version:   "1.0",
		CreatedAt: base.Add(125 * time.Minute),
		Metadata: graph.Metadata{
			BuiltAt:   base.Add(2 * time.Hour),
			NodeCount: 2,
			EdgeCount: 1,
			Providers: []string{"aws"},
			Accounts:  []string{"acct-a"},
		},
		Nodes: []*graph.Node{
			{ID: "service:payments", Kind: graph.NodeKindService, Name: "Payments Core", Provider: "aws", Account: "acct-a"},
			{ID: "bucket:logs", Kind: graph.NodeKindBucket, Name: "Logs", Provider: "aws", Account: "acct-a", Properties: map[string]any{"source_system": "aws"}},
		},
		Edges: []*graph.Edge{
			{ID: "service:payments->bucket:logs:targets", Source: "service:payments", Target: "bucket:logs", Kind: graph.EdgeKindTargets},
		},
	}
	mustSaveGraphSnapshot(t, dir, older)
	mustSaveGraphSnapshot(t, dir, newer)
	mustSaveGraphSnapshot(t, dir, latest)

	s := newTestServer(t)
	changelogEvents := make(chan webhooks.Event, 2)
	s.app.Webhooks.Subscribe(func(_ context.Context, event webhooks.Event) error {
		if event.Type == webhooks.EventPlatformGraphChangelogComputed {
			changelogEvents <- event
		}
		return nil
	})
	changelog := do(t, s, http.MethodGet, "/api/v1/platform/graph/changelog?since=2026-03-07T00:00:00Z&provider=aws&limit=1", nil)
	if changelog.Code != http.StatusOK {
		t.Fatalf("expected 200 for graph changelog, got %d: %s", changelog.Code, changelog.Body.String())
	}
	changelogBody := decodeJSON(t, changelog)
	if changelogBody["count"] != float64(1) {
		t.Fatalf("expected one changelog entry, got %#v", changelogBody["count"])
	}
	entries, ok := changelogBody["entries"].([]any)
	if !ok || len(entries) != 1 {
		t.Fatalf("expected one changelog entry, got %#v", changelogBody["entries"])
	}
	entry := entries[0].(map[string]any)
	diffID, _ := entry["diff_id"].(string)
	if diffID == "" {
		t.Fatalf("expected diff_id on changelog entry, got %#v", entry)
	}
	toSnapshot := entry["to"].(map[string]any)
	if got := toSnapshot["captured_at"]; got != latest.CreatedAt.Format(time.RFC3339) {
		t.Fatalf("expected newest changelog entry, got to=%#v", toSnapshot)
	}
	summary := entry["summary"].(map[string]any)
	if summary["nodes_modified"] != float64(1) || summary["nodes_added"] != float64(0) {
		t.Fatalf("expected newest diff summary with one modified node, got %#v", summary)
	}
	attribution := entry["attribution"].(map[string]any)
	if providers, ok := attribution["providers"].([]any); !ok || len(providers) != 1 || providers[0] != "aws" {
		t.Fatalf("expected aws attribution, got %#v", attribution)
	}
	if got := entry["materialized"]; got != nil && got != false {
		t.Fatalf("expected changelog read to stay non-materialized, got %#v", got)
	}
	diffURL, _ := entry["diff_url"].(string)
	if diffURL == "" ||
		!strings.HasPrefix(diffURL, "/api/v1/platform/graph/snapshots/") ||
		!strings.Contains(diffURL, "/diffs/") {
		t.Fatalf("expected changelog diff_url to use snapshot diff path, got %#v", diffURL)
	}

	artifact := do(t, s, http.MethodGet, "/api/v1/platform/graph/diffs/"+diffID, nil)
	if artifact.Code != http.StatusNotFound {
		t.Fatalf("expected changelog read to avoid diff artifact materialization, got %d: %s", artifact.Code, artifact.Body.String())
	}

	details := do(t, s, http.MethodGet, "/api/v1/platform/graph/diffs/"+diffID+"/details?provider=aws&kind=service", nil)
	if details.Code != http.StatusOK {
		t.Fatalf("expected 200 for diff details, got %d: %s", details.Code, details.Body.String())
	}
	detailsBody := decodeJSON(t, details)
	detailSummary := detailsBody["summary"].(map[string]any)
	if detailSummary["nodes_modified"] != float64(1) || detailSummary["nodes_added"] != float64(0) {
		t.Fatalf("unexpected filtered detail summary: %#v", detailSummary)
	}
	filter := detailsBody["filter"].(map[string]any)
	if filter["provider"] != "aws" || filter["kind"] != string(graph.NodeKindService) {
		t.Fatalf("unexpected detail filter echo: %#v", filter)
	}
	select {
	case event := <-changelogEvents:
		t.Fatalf("expected changelog reads to avoid webhook emission, got %#v", event)
	default:
	}
}

func TestPlatformGraphChangelogUsesExplicitParentSnapshotLineage(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GRAPH_SNAPSHOT_PATH", dir)

	base := time.Now().UTC().Add(-6 * 24 * time.Hour).Truncate(time.Minute)
	root := &graph.Snapshot{
		Version:   "1.0",
		CreatedAt: base.Add(5 * time.Minute),
		Metadata:  graph.Metadata{BuiltAt: base, NodeCount: 1, Providers: []string{"aws"}, Accounts: []string{"acct-a"}},
		Nodes:     []*graph.Node{{ID: "node-root", Kind: graph.NodeKindService, Name: "Root", Provider: "aws", Account: "acct-a"}},
	}
	branchA := &graph.Snapshot{
		Version:   "1.0",
		CreatedAt: base.Add(65 * time.Minute),
		Metadata:  graph.Metadata{BuiltAt: base.Add(1 * time.Hour), NodeCount: 2, Providers: []string{"aws"}, Accounts: []string{"acct-a"}},
		Nodes: []*graph.Node{
			{ID: "node-root", Kind: graph.NodeKindService, Name: "Root", Provider: "aws", Account: "acct-a"},
			{ID: "node-a", Kind: graph.NodeKindBucket, Name: "Branch A", Provider: "aws", Account: "acct-a"},
		},
	}
	branchB := &graph.Snapshot{
		Version:   "1.0",
		CreatedAt: base.Add(125 * time.Minute),
		Metadata:  graph.Metadata{BuiltAt: base.Add(2 * time.Hour), NodeCount: 2, Providers: []string{"aws"}, Accounts: []string{"acct-a"}},
		Nodes: []*graph.Node{
			{ID: "node-root", Kind: graph.NodeKindService, Name: "Root", Provider: "aws", Account: "acct-a"},
			{ID: "node-b", Kind: graph.NodeKindDatabase, Name: "Branch B", Provider: "aws", Account: "acct-a"},
		},
	}
	mustSaveGraphSnapshot(t, dir, root)
	mustSaveGraphSnapshot(t, dir, branchA)
	mustSaveGraphSnapshot(t, dir, branchB)

	store := graph.NewSnapshotStore(dir, 10)
	records, err := store.ListGraphSnapshotRecords()
	if err != nil {
		t.Fatalf("list graph snapshot records: %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("expected three snapshot records, got %d", len(records))
	}
	rootID := records[0].ID
	branchAID := records[1].ID
	branchBID := records[2].ID
	mustRewriteGraphSnapshotIndexParents(t, dir, map[string]string{
		branchAID: rootID,
		branchBID: rootID,
	})

	s := newTestServer(t)
	changelog := do(t, s, http.MethodGet, "/api/v1/platform/graph/changelog?last=7d&provider=aws&limit=1", nil)
	if changelog.Code != http.StatusOK {
		t.Fatalf("expected 200 for graph changelog, got %d: %s", changelog.Code, changelog.Body.String())
	}
	body := decodeJSON(t, changelog)
	entries, ok := body["entries"].([]any)
	if !ok || len(entries) != 1 {
		t.Fatalf("expected one changelog entry, got %#v", body["entries"])
	}
	entry := entries[0].(map[string]any)
	fromSnapshot := entry["from"].(map[string]any)
	toSnapshot := entry["to"].(map[string]any)
	if got := fromSnapshot["id"]; got != rootID {
		t.Fatalf("expected explicit root parent %s, got %#v", rootID, got)
	}
	if got := toSnapshot["id"]; got != branchBID {
		t.Fatalf("expected branch-b target %s, got %#v", branchBID, got)
	}
	summary := entry["summary"].(map[string]any)
	if summary["nodes_added"] != float64(1) || summary["nodes_removed"] != float64(0) {
		t.Fatalf("expected explicit parent diff summary, got %#v", summary)
	}
	diffURL, _ := entry["diff_url"].(string)
	if !strings.Contains(diffURL, rootID) || !strings.Contains(diffURL, branchBID) {
		t.Fatalf("expected diff URL to use explicit parent/child ids, got %q", diffURL)
	}
}

func TestPlatformGraphDiffLookupByIDUsesExplicitParentSnapshotLineage(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GRAPH_SNAPSHOT_PATH", dir)

	base := time.Date(2026, 3, 7, 10, 0, 0, 0, time.UTC)
	root := &graph.Snapshot{
		Version:   "1.0",
		CreatedAt: base.Add(5 * time.Minute),
		Metadata:  graph.Metadata{BuiltAt: base, NodeCount: 1, Providers: []string{"aws"}, Accounts: []string{"acct-a"}},
		Nodes:     []*graph.Node{{ID: "node-root", Kind: graph.NodeKindService, Name: "Root", Provider: "aws", Account: "acct-a"}},
	}
	branchA := &graph.Snapshot{
		Version:   "1.0",
		CreatedAt: base.Add(65 * time.Minute),
		Metadata:  graph.Metadata{BuiltAt: base.Add(1 * time.Hour), NodeCount: 2, Providers: []string{"aws"}, Accounts: []string{"acct-a"}},
		Nodes: []*graph.Node{
			{ID: "node-root", Kind: graph.NodeKindService, Name: "Root", Provider: "aws", Account: "acct-a"},
			{ID: "node-a", Kind: graph.NodeKindBucket, Name: "Branch A", Provider: "aws", Account: "acct-a"},
		},
	}
	branchB := &graph.Snapshot{
		Version:   "1.0",
		CreatedAt: base.Add(125 * time.Minute),
		Metadata:  graph.Metadata{BuiltAt: base.Add(2 * time.Hour), NodeCount: 2, Providers: []string{"aws"}, Accounts: []string{"acct-a"}},
		Nodes: []*graph.Node{
			{ID: "node-root", Kind: graph.NodeKindService, Name: "Root", Provider: "aws", Account: "acct-a"},
			{ID: "node-b", Kind: graph.NodeKindDatabase, Name: "Branch B", Provider: "aws", Account: "acct-a"},
		},
	}
	mustSaveGraphSnapshot(t, dir, root)
	mustSaveGraphSnapshot(t, dir, branchA)
	mustSaveGraphSnapshot(t, dir, branchB)

	store := graph.NewSnapshotStore(dir, 10)
	records, err := store.ListGraphSnapshotRecords()
	if err != nil {
		t.Fatalf("list graph snapshot records: %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("expected three snapshot records, got %d", len(records))
	}
	rootID := records[0].ID
	branchAID := records[1].ID
	branchBID := records[2].ID
	mustRewriteGraphSnapshotIndexParents(t, dir, map[string]string{
		branchAID: rootID,
		branchBID: rootID,
	})
	expected := graph.BuildGraphSnapshotDiffRecord(
		graph.GraphSnapshotRecord{ID: rootID},
		graph.GraphSnapshotRecord{ID: branchBID},
		&graph.GraphDiff{},
		time.Time{},
	)
	if expected == nil {
		t.Fatal("expected diff id")
	}

	s := newTestServer(t)
	diff := do(t, s, http.MethodGet, "/api/v1/platform/graph/diffs/"+expected.ID+"/details", nil)
	if diff.Code != http.StatusOK {
		t.Fatalf("expected 200 for explicit-parent diff details lookup, got %d: %s", diff.Code, diff.Body.String())
	}
	body := decodeJSON(t, diff)
	fromSnapshot := body["from"].(map[string]any)
	toSnapshot := body["to"].(map[string]any)
	if got := fromSnapshot["id"]; got != rootID {
		t.Fatalf("expected diff lookup from snapshot %s, got %#v", rootID, got)
	}
	if got := toSnapshot["id"]; got != branchBID {
		t.Fatalf("expected diff lookup to snapshot %s, got %#v", branchBID, got)
	}
	summary := body["summary"].(map[string]any)
	if summary["nodes_added"] != float64(1) || summary["nodes_removed"] != float64(0) {
		t.Fatalf("expected explicit parent diff summary, got %#v", summary)
	}
}

func mustSaveGraphSnapshot(t *testing.T, dir string, snapshot *graph.Snapshot) {
	t.Helper()
	path := filepath.Join(dir, fmt.Sprintf("graph-%s.json.gz", snapshot.CreatedAt.Format("20060102-150405")))
	if err := snapshot.SaveToFile(path); err != nil {
		t.Fatalf("save snapshot: %v", err)
	}
}

func mustRewriteGraphSnapshotIndexParents(t *testing.T, dir string, parents map[string]string) {
	t.Helper()
	indexPath := filepath.Join(dir, "index.json")
	payload, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatalf("read snapshot index: %v", err)
	}
	var index map[string]any
	if err := json.Unmarshal(payload, &index); err != nil {
		t.Fatalf("decode snapshot index: %v", err)
	}
	manifests, ok := index["snapshots"].([]any)
	if !ok {
		t.Fatalf("expected snapshot manifests in index, got %#v", index["snapshots"])
	}
	for _, raw := range manifests {
		manifest, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		record, ok := manifest["record"].(map[string]any)
		if !ok {
			continue
		}
		snapshotID, _ := record["id"].(string)
		parentID, ok := parents[snapshotID]
		if !ok {
			continue
		}
		record["parent_snapshot_id"] = parentID
		manifest["parent_snapshot_id"] = parentID
	}
	encoded, err := json.Marshal(index)
	if err != nil {
		t.Fatalf("encode snapshot index: %v", err)
	}
	if err := os.WriteFile(indexPath, encoded, 0o600); err != nil {
		t.Fatalf("write snapshot index: %v", err)
	}
}

func waitForPlatformJobState(t *testing.T, s *Server, statusURL, want string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		status := do(t, s, http.MethodGet, statusURL, nil)
		if status.Code != http.StatusOK {
			t.Fatalf("expected 200 for platform job lookup, got %d: %s", status.Code, status.Body.String())
		}
		body := decodeJSON(t, status)
		if got, _ := body["status"].(string); got == want {
			return body
		}
		if got, _ := body["status"].(string); got == "failed" || got == "canceled" {
			t.Fatalf("expected platform job to reach %q, got terminal state %#v", want, body)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for platform job state %q", want)
	return nil
}
