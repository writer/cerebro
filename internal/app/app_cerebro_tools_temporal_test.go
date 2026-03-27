package app

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/graph"
)

func TestCerebroEntityHistoryTool(t *testing.T) {
	base := time.Date(2026, 3, 10, 9, 0, 0, 0, time.UTC)
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:       "service:payments",
		Kind:     graph.NodeKindService,
		Name:     "Payments",
		Provider: "aws",
		Properties: map[string]any{
			"status":           "degraded",
			"owner":            "team-payments",
			"observed_at":      base.Add(2 * time.Hour).Format(time.RFC3339),
			"valid_from":       base.Format(time.RFC3339),
			"recorded_at":      base.Format(time.RFC3339),
			"transaction_from": base.Format(time.RFC3339),
		},
	})
	node, ok := g.GetNode("service:payments")
	if !ok || node == nil {
		t.Fatal("expected seeded service node")
	}
	node.PropertyHistory = map[string][]graph.PropertySnapshot{
		"status": []graph.PropertySnapshot{
			{Timestamp: base, Value: "healthy"},
			{Timestamp: base.Add(2 * time.Hour), Value: "degraded"},
		},
		"owner": []graph.PropertySnapshot{
			{Timestamp: base.Add(2 * time.Hour), Value: "team-payments"},
		},
	}

	application := &App{SecurityGraph: g, Config: &Config{}}
	tool := findCerebroTool(application.AgentSDKTools(), "cerebro.entity_history")
	if tool == nil {
		t.Fatal("expected cerebro.entity_history tool")
	}

	atResult, err := tool.Handler(context.Background(), json.RawMessage(`{
		"entity_id":"service:payments",
		"timestamp":"2026-03-10T09:30:00Z"
	}`))
	if err != nil {
		t.Fatalf("entity_history at returned error: %v", err)
	}
	var atPayload map[string]any
	if err := json.Unmarshal([]byte(atResult), &atPayload); err != nil {
		t.Fatalf("decode entity_history at payload: %v", err)
	}
	entity := atPayload["entity"].(map[string]any)
	properties := entity["properties"].(map[string]any)
	if got := properties["status"]; got != "healthy" {
		t.Fatalf("expected reconstructed status healthy, got %#v", got)
	}
	reconstruction := atPayload["reconstruction"].(map[string]any)
	if reconstruction["historical_core_fields"] != false {
		t.Fatalf("expected historical_core_fields=false, got %#v", reconstruction["historical_core_fields"])
	}

	diffResult, err := tool.Handler(context.Background(), json.RawMessage(`{
		"entity_id":"service:payments",
		"from":"2026-03-10T09:00:00Z",
		"to":"2026-03-10T11:30:00Z"
	}`))
	if err != nil {
		t.Fatalf("entity_history diff returned error: %v", err)
	}
	var diffPayload map[string]any
	if err := json.Unmarshal([]byte(diffResult), &diffPayload); err != nil {
		t.Fatalf("decode entity_history diff payload: %v", err)
	}
	if diffPayload["entity_id"] != "service:payments" {
		t.Fatalf("expected entity_id service:payments, got %#v", diffPayload["entity_id"])
	}
	changedKeys, ok := diffPayload["changed_keys"].([]any)
	if !ok || len(changedKeys) < 2 {
		t.Fatalf("expected changed_keys, got %#v", diffPayload["changed_keys"])
	}
}

func TestCerebroTemporalAliasTools(t *testing.T) {
	base := time.Date(2026, 3, 10, 9, 0, 0, 0, time.UTC)
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:       "service:payments",
		Kind:     graph.NodeKindService,
		Name:     "Payments",
		Provider: "aws",
		Properties: map[string]any{
			"status":           "degraded",
			"owner":            "team-payments",
			"observed_at":      base.Add(2 * time.Hour).Format(time.RFC3339),
			"valid_from":       base.Format(time.RFC3339),
			"recorded_at":      base.Format(time.RFC3339),
			"transaction_from": base.Format(time.RFC3339),
		},
	})
	node, ok := g.GetNode("service:payments")
	if !ok || node == nil {
		t.Fatal("expected seeded service node")
	}
	node.CreatedAt = base
	node.UpdatedAt = base.Add(2 * time.Hour)
	node.PropertyHistory = map[string][]graph.PropertySnapshot{
		"status": {
			{Timestamp: base, Value: "healthy"},
			{Timestamp: base.Add(2 * time.Hour), Value: "degraded"},
		},
		"owner": {
			{Timestamp: base.Add(2 * time.Hour), Value: "team-payments"},
		},
	}

	application := &App{SecurityGraph: g, Config: &Config{}}

	reconstructTool := findCerebroTool(application.AgentSDKTools(), "cerebro.reconstruct")
	if reconstructTool == nil {
		t.Fatal("expected cerebro.reconstruct tool")
	}
	reconstructResult, err := reconstructTool.Handler(context.Background(), json.RawMessage(`{
		"entity_id":"service:payments",
		"timestamp":"2026-03-10T09:30:00Z"
	}`))
	if err != nil {
		t.Fatalf("reconstruct returned error: %v", err)
	}
	var reconstructPayload map[string]any
	if err := json.Unmarshal([]byte(reconstructResult), &reconstructPayload); err != nil {
		t.Fatalf("decode reconstruct payload: %v", err)
	}
	reconstructEntity := reconstructPayload["entity"].(map[string]any)
	reconstructProperties := reconstructEntity["properties"].(map[string]any)
	if got := reconstructProperties["status"]; got != "healthy" {
		t.Fatalf("expected reconstruct status healthy, got %#v", got)
	}

	timelineTool := findCerebroTool(application.AgentSDKTools(), "cerebro.timeline")
	if timelineTool == nil {
		t.Fatal("expected cerebro.timeline tool")
	}
	timelineResult, err := timelineTool.Handler(context.Background(), json.RawMessage(`{
		"entity_id":"service:payments",
		"from":"2026-03-10T09:00:00Z",
		"to":"2026-03-10T12:00:00Z"
	}`))
	if err != nil {
		t.Fatalf("timeline returned error: %v", err)
	}
	var timelinePayload map[string]any
	if err := json.Unmarshal([]byte(timelineResult), &timelinePayload); err != nil {
		t.Fatalf("decode timeline payload: %v", err)
	}
	events, ok := timelinePayload["events"].([]any)
	if !ok || len(events) < 3 {
		t.Fatalf("expected timeline events, got %#v", timelinePayload["events"])
	}

	diffTool := findCerebroTool(application.AgentSDKTools(), "cerebro.diff")
	if diffTool == nil {
		t.Fatal("expected cerebro.diff tool")
	}
	diffResult, err := diffTool.Handler(context.Background(), json.RawMessage(`{
		"entity_id":"service:payments",
		"from":"2026-03-10T09:00:00Z",
		"to":"2026-03-10T11:30:00Z"
	}`))
	if err != nil {
		t.Fatalf("diff returned error: %v", err)
	}
	var diffPayload map[string]any
	if err := json.Unmarshal([]byte(diffResult), &diffPayload); err != nil {
		t.Fatalf("decode diff payload: %v", err)
	}
	if diffPayload["entity_id"] != "service:payments" {
		t.Fatalf("expected diff entity_id service:payments, got %#v", diffPayload["entity_id"])
	}
}

func TestCerebroEntityHistoryToolUsesConfiguredStoreWhenLiveGraphUnavailable(t *testing.T) {
	base := time.Date(2026, 3, 10, 9, 0, 0, 0, time.UTC)
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:       "service:payments",
		Kind:     graph.NodeKindService,
		Name:     "Payments",
		Provider: "aws",
		Properties: map[string]any{
			"status":           "degraded",
			"owner":            "team-payments",
			"observed_at":      base.Add(2 * time.Hour).Format(time.RFC3339),
			"valid_from":       base.Format(time.RFC3339),
			"recorded_at":      base.Format(time.RFC3339),
			"transaction_from": base.Format(time.RFC3339),
		},
	})
	node, ok := g.GetNode("service:payments")
	if !ok || node == nil {
		t.Fatal("expected seeded service node")
	}
	node.PropertyHistory = map[string][]graph.PropertySnapshot{
		"status": {
			{Timestamp: base, Value: "healthy"},
			{Timestamp: base.Add(2 * time.Hour), Value: "degraded"},
		},
	}

	application := &App{
		Config: &Config{},
	}
	setConfiguredSnapshotGraphFromGraph(t, application, g)
	tool := findCerebroTool(application.AgentSDKTools(), "cerebro.entity_history")
	if tool == nil {
		t.Fatal("expected cerebro.entity_history tool")
	}

	result, err := tool.Handler(context.Background(), json.RawMessage(`{
		"entity_id":"service:payments",
		"timestamp":"2026-03-10T09:30:00Z"
	}`))
	if err != nil {
		t.Fatalf("entity_history returned error: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(result), &payload); err != nil {
		t.Fatalf("decode entity_history payload: %v", err)
	}
	entity := payload["entity"].(map[string]any)
	properties := entity["properties"].(map[string]any)
	if got := properties["status"]; got != "healthy" {
		t.Fatalf("expected reconstructed status healthy, got %#v", got)
	}
}

func TestCerebroGraphChangelogTool(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GRAPH_SNAPSHOT_PATH", dir)

	base := time.Now().UTC().Add(-6 * 24 * time.Hour).Truncate(time.Second)
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
			{ID: "bucket:logs", Kind: graph.NodeKindBucket, Name: "Logs", Provider: "aws", Account: "acct-a"},
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
			{ID: "bucket:logs", Kind: graph.NodeKindBucket, Name: "Logs", Provider: "aws", Account: "acct-a"},
		},
		Edges: []*graph.Edge{
			{ID: "service:payments->bucket:logs:targets", Source: "service:payments", Target: "bucket:logs", Kind: graph.EdgeKindTargets},
		},
	}
	mustSaveGraphSnapshotForTool(t, dir, older)
	mustSaveGraphSnapshotForTool(t, dir, newer)
	mustSaveGraphSnapshotForTool(t, dir, latest)

	application := &App{SecurityGraph: graph.New(), Config: &Config{GraphSnapshotPath: dir}}
	tool := findCerebroTool(application.AgentSDKTools(), "cerebro.graph_changelog")
	if tool == nil {
		t.Fatal("expected cerebro.graph_changelog tool")
	}

	result, err := tool.Handler(context.Background(), json.RawMessage(`{"since":"2026-03-07T00:00:00Z","provider":"aws","limit":1}`))
	if err != nil {
		t.Fatalf("graph_changelog returned error: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(result), &payload); err != nil {
		t.Fatalf("decode graph_changelog payload: %v", err)
	}
	if got := payload["count"]; got != float64(1) {
		t.Fatalf("expected one changelog entry, got %#v", got)
	}
	entries, ok := payload["entries"].([]any)
	if !ok || len(entries) != 1 {
		t.Fatalf("expected one changelog entry, got %#v", payload["entries"])
	}
	entry := entries[0].(map[string]any)
	diffID, _ := entry["diff_id"].(string)
	if diffID == "" {
		t.Fatalf("expected diff_id, got %#v", entry)
	}
	if got := entry["materialized"]; got != nil && got != false {
		t.Fatalf("expected read-only changelog entry, got materialized=%#v", got)
	}
	if got := entry["stored_at"]; got != nil {
		t.Fatalf("expected no stored_at for unmaterialized diff, got %#v", got)
	}
	diffURL, _ := entry["diff_url"].(string)
	if diffURL == "" ||
		!strings.HasPrefix(diffURL, "/api/v1/platform/graph/snapshots/") ||
		!strings.Contains(diffURL, "/diffs/") {
		t.Fatalf("expected snapshot diff URL for unmaterialized changelog, got %#v", diffURL)
	}
	toSnapshot := entry["to"].(map[string]any)
	if got := toSnapshot["captured_at"]; got != latest.CreatedAt.Format(time.RFC3339) {
		t.Fatalf("expected newest changelog entry, got to=%#v", toSnapshot)
	}
	if got := toSnapshot["current"]; got != nil {
		t.Fatalf("expected no current snapshot marker without live/configured graph, got %#v", got)
	}
	summary := entry["summary"].(map[string]any)
	if summary["nodes_modified"] != float64(1) || summary["nodes_added"] != float64(0) {
		t.Fatalf("unexpected changelog summary: %#v", summary)
	}

	detailResult, err := tool.Handler(context.Background(), json.RawMessage(fmt.Sprintf(`{
		"diff_id":%q,
		"provider":"aws"
	}`, diffID)))
	if err != nil {
		t.Fatalf("graph_changelog detail returned error: %v", err)
	}
	var detailPayload map[string]any
	if err := json.Unmarshal([]byte(detailResult), &detailPayload); err != nil {
		t.Fatalf("decode graph_changelog detail payload: %v", err)
	}
	detailSummary := detailPayload["summary"].(map[string]any)
	if detailSummary["nodes_modified"] != float64(1) {
		t.Fatalf("expected filtered detail nodes_added=1, got %#v", detailSummary)
	}
	detailTo := detailPayload["to"].(map[string]any)
	if got := detailTo["current"]; got != nil {
		t.Fatalf("expected no detail current snapshot marker without live/configured graph, got %#v", got)
	}

	diffDir := filepath.Join(dir, "diffs")
	entriesOnDisk, err := os.ReadDir(diffDir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("read diff dir: %v", err)
	}
	if len(entriesOnDisk) != 0 {
		t.Fatalf("expected tool reads to avoid diff materialization, got %d artifacts", len(entriesOnDisk))
	}
}

func TestCerebroGraphChangelogToolOmitsCurrentMarkerWithoutLiveGraph(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GRAPH_SNAPSHOT_PATH", dir)

	base := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Second)
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
	latest := &graph.Snapshot{
		Version:   "1.0",
		CreatedAt: base.Add(65 * time.Minute),
		Metadata: graph.Metadata{
			NodeCount: 2,
			EdgeCount: 1,
			Providers: []string{"aws"},
			Accounts:  []string{"acct-a"},
		},
		Nodes: []*graph.Node{
			{ID: "service:payments", Kind: graph.NodeKindService, Name: "Payments Core", Provider: "aws", Account: "acct-a"},
			{ID: "bucket:logs", Kind: graph.NodeKindBucket, Name: "Logs", Provider: "aws", Account: "acct-a"},
		},
		Edges: []*graph.Edge{
			{ID: "service:payments->bucket:logs:targets", Source: "service:payments", Target: "bucket:logs", Kind: graph.EdgeKindTargets},
		},
	}
	mustSaveGraphSnapshotForTool(t, dir, older)
	mustSaveGraphSnapshotForTool(t, dir, latest)

	application := &App{Config: &Config{GraphSnapshotPath: dir}}
	tool := findCerebroTool(application.AgentSDKTools(), "cerebro.graph_changelog")
	if tool == nil {
		t.Fatal("expected cerebro.graph_changelog tool")
	}

	result, err := tool.Handler(context.Background(), json.RawMessage(`{"since":"2026-03-07T00:00:00Z","provider":"aws","limit":1}`))
	if err != nil {
		t.Fatalf("graph_changelog returned error: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(result), &payload); err != nil {
		t.Fatalf("decode graph_changelog payload: %v", err)
	}
	entries, ok := payload["entries"].([]any)
	if !ok || len(entries) != 1 {
		t.Fatalf("expected one changelog entry, got %#v", payload["entries"])
	}
	entry := entries[0].(map[string]any)
	toSnapshot := entry["to"].(map[string]any)
	if got := toSnapshot["captured_at"]; got != latest.CreatedAt.Format(time.RFC3339) {
		t.Fatalf("expected latest persisted snapshot in changelog, got %#v", toSnapshot)
	}
	if got := toSnapshot["current"]; got != nil {
		t.Fatalf("expected latest persisted snapshot to omit current marker without live graph, got %#v", got)
	}
}

func mustSaveGraphSnapshotForTool(t *testing.T, dir string, snapshot *graph.Snapshot) {
	t.Helper()
	path := filepath.Join(dir, fmt.Sprintf("graph-%s.json.gz", snapshot.CreatedAt.Format("20060102-150405")))
	if err := snapshot.SaveToFile(path); err != nil {
		t.Fatalf("save snapshot: %v", err)
	}
}
