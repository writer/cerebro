package app

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/graph"
	reports "github.com/writer/cerebro/internal/graph/reports"
	"github.com/writer/cerebro/internal/health"
	"github.com/writer/cerebro/internal/warehouse"
)

func TestEvaluateGraphOntologySLOStatus(t *testing.T) {
	thresholds := graphOntologySLOThresholds{
		FallbackWarn:        12,
		FallbackCritical:    25,
		SchemaValidWarn:     98,
		SchemaValidCritical: 92,
	}

	healthyStatus, _ := evaluateGraphOntologySLOStatus(reports.GraphOntologySLO{
		FallbackActivityPercent: 4,
		SchemaValidWritePercent: 99.5,
	}, thresholds)
	if healthyStatus != health.StatusHealthy {
		t.Fatalf("expected healthy status, got %s", healthyStatus)
	}

	degradedStatus, degradedMsg := evaluateGraphOntologySLOStatus(reports.GraphOntologySLO{
		FallbackActivityPercent: 15,
		SchemaValidWritePercent: 99.5,
	}, thresholds)
	if degradedStatus != health.StatusDegraded {
		t.Fatalf("expected degraded status, got %s", degradedStatus)
	}
	if !strings.Contains(degradedMsg, "fallback_activity_percent") {
		t.Fatalf("expected fallback degradation message, got %q", degradedMsg)
	}

	unhealthyStatus, unhealthyMsg := evaluateGraphOntologySLOStatus(reports.GraphOntologySLO{
		FallbackActivityPercent: 10,
		SchemaValidWritePercent: 90,
	}, thresholds)
	if unhealthyStatus != health.StatusUnhealthy {
		t.Fatalf("expected unhealthy status, got %s", unhealthyStatus)
	}
	if !strings.Contains(unhealthyMsg, "schema_valid_write_percent") {
		t.Fatalf("expected schema validity unhealthy message, got %q", unhealthyMsg)
	}
}

func TestEvaluateGraphOntologySLOStatus_BurnRateDegraded(t *testing.T) {
	thresholds := graphOntologySLOThresholds{
		FallbackWarn:        12,
		FallbackCritical:    25,
		SchemaValidWarn:     98,
		SchemaValidCritical: 92,
	}
	status, msg := evaluateGraphOntologySLOStatus(reports.GraphOntologySLO{
		FallbackActivityPercent: 10,
		SchemaValidWritePercent: 99,
		Trend: []reports.GraphOntologySLOPoint{
			{Date: "2026-03-07", FallbackActivityPercent: 24, SchemaValidWritePercent: 99, Samples: 20},
			{Date: "2026-03-08", FallbackActivityPercent: 24, SchemaValidWritePercent: 99, Samples: 20},
			{Date: "2026-03-09", FallbackActivityPercent: 24, SchemaValidWritePercent: 99, Samples: 20},
		},
	}, thresholds)
	if status != health.StatusDegraded {
		t.Fatalf("expected degraded due to burn rate, got %s (%s)", status, msg)
	}
	if !strings.Contains(msg, "burn_rate") {
		t.Fatalf("expected burn-rate message, got %q", msg)
	}
}

func TestGraphOntologySLOHealthCheck(t *testing.T) {
	g := graph.New()
	now := time.Date(2026, 3, 9, 10, 0, 0, 0, time.UTC)
	g.AddNode(&graph.Node{
		ID:   "activity:test",
		Kind: graph.NodeKindActivity,
		Name: "Legacy Activity",
		Properties: map[string]any{
			"source_system": "github",
			"observed_at":   now.Format(time.RFC3339),
			"valid_from":    now.Format(time.RFC3339),
		},
	})

	application := &App{
		Config: &Config{
			GraphOntologyFallbackWarnPct:        10,
			GraphOntologyFallbackCriticalPct:    50,
			GraphOntologySchemaValidWarnPct:     98,
			GraphOntologySchemaValidCriticalPct: 92,
		},
		SecurityGraph: g,
	}

	result := application.graphOntologySLOHealthCheck()(context.Background())
	if result.Status != health.StatusUnhealthy {
		t.Fatalf("expected unhealthy status from high fallback activity, got %s (%s)", result.Status, result.Message)
	}
	if !strings.Contains(result.Message, "fallback_activity_percent") {
		t.Fatalf("expected fallback issue in message, got %q", result.Message)
	}
}

func TestGraphOntologySLOHealthCheckWithoutGraph(t *testing.T) {
	application := &App{}
	result := application.graphOntologySLOHealthCheck()(context.Background())
	if result.Status != health.StatusUnknown {
		t.Fatalf("expected unknown when graph is missing, got %s", result.Status)
	}
}

func TestGraphOntologySLOHealthCheckUsesPersistedSnapshotWhenLiveGraphUnavailable(t *testing.T) {
	g := graph.New()
	now := time.Date(2026, 3, 9, 10, 0, 0, 0, time.UTC)
	g.AddNode(&graph.Node{
		ID:   "activity:test",
		Kind: graph.NodeKindActivity,
		Name: "Legacy Activity",
		Properties: map[string]any{
			"source_system": "github",
			"observed_at":   now.Format(time.RFC3339),
			"valid_from":    now.Format(time.RFC3339),
		},
	})
	g.BuildIndex()

	application := &App{
		Config: &Config{
			GraphOntologyFallbackWarnPct:        10,
			GraphOntologyFallbackCriticalPct:    50,
			GraphOntologySchemaValidWarnPct:     98,
			GraphOntologySchemaValidCriticalPct: 92,
		},
		GraphSnapshots: mustPersistToolGraph(t, g),
	}

	result := application.graphOntologySLOHealthCheck()(context.Background())
	if result.Status != health.StatusUnhealthy {
		t.Fatalf("expected unhealthy status from persisted snapshot fallback activity, got %s (%s)", result.Status, result.Message)
	}
	if !strings.Contains(result.Message, "fallback_activity_percent") {
		t.Fatalf("expected fallback issue in message, got %q", result.Message)
	}
}

func TestInitHealthRegistersGraphBuildCheck(t *testing.T) {
	application := &App{
		Config:    &Config{},
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Warehouse: &warehouse.MemoryWarehouse{},
	}
	application.initHealth()
	application.setGraphBuildState(GraphBuildFailed, time.Date(2026, 3, 10, 9, 0, 0, 0, time.UTC), context.DeadlineExceeded)

	results := application.Health.RunAll(context.Background())
	check, ok := results["graph_build"]
	if !ok {
		t.Fatal("expected graph_build health check to be registered")
	}
	if check.Status != health.StatusUnhealthy {
		t.Fatalf("expected graph_build health to be unhealthy, got %s", check.Status)
	}
	if !strings.Contains(check.Message, context.DeadlineExceeded.Error()) {
		t.Fatalf("expected graph_build health message to include build error, got %q", check.Message)
	}
}

func TestInitHealthRegistersGraphPersistenceCheck(t *testing.T) {
	dir := t.TempDir()
	store, err := graph.NewGraphPersistenceStore(graph.GraphPersistenceOptions{
		LocalPath: dir,
	})
	if err != nil {
		t.Fatalf("new graph persistence store: %v", err)
	}

	application := &App{
		Config:         &Config{},
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		Warehouse:      &warehouse.MemoryWarehouse{},
		GraphSnapshots: store,
	}
	application.initHealth()

	results := application.Health.RunAll(context.Background())
	check, ok := results["graph_persistence"]
	if !ok {
		t.Fatal("expected graph_persistence health check to be registered")
	}
	if check.Status != health.StatusHealthy {
		t.Fatalf("expected graph_persistence health to be healthy, got %#v", check)
	}
}

func TestGraphPersistenceHealthDegradesOnReplicaSyncFailure(t *testing.T) {
	localDir := t.TempDir()
	badReplicaBase := filepath.Join(t.TempDir(), "replica-file")
	if err := os.WriteFile(badReplicaBase, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("seed bad replica path: %v", err)
	}
	store, err := graph.NewGraphPersistenceStore(graph.GraphPersistenceOptions{
		LocalPath:    localDir,
		MaxSnapshots: 4,
		ReplicaURI:   badReplicaBase,
	})
	if err != nil {
		t.Fatalf("new graph persistence store: %v", err)
	}

	g := graph.New()
	g.AddNode(&graph.Node{ID: "service:payments", Kind: graph.NodeKindService, Name: "payments"})
	g.SetMetadata(graph.Metadata{
		BuiltAt:       time.Date(2026, 3, 12, 23, 5, 0, 0, time.UTC),
		NodeCount:     1,
		EdgeCount:     0,
		Providers:     []string{"aws"},
		Accounts:      []string{"prod"},
		BuildDuration: time.Second,
	})
	if _, err := store.SaveGraph(g); err == nil {
		t.Fatal("expected replica sync failure")
	}

	application := &App{
		Config:         &Config{},
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		Warehouse:      &warehouse.MemoryWarehouse{},
		GraphSnapshots: store,
	}
	application.initHealth()

	results := application.Health.RunAll(context.Background())
	check := results["graph_persistence"]
	if check.Status != health.StatusDegraded {
		t.Fatalf("expected degraded graph persistence health, got %#v", check)
	}
	if check.Message != "local snapshot persistence healthy; replica sync failing" {
		t.Fatalf("expected replica sync message, got %#v", check)
	}
	if strings.Contains(check.Message, badReplicaBase) || strings.Contains(strings.ToLower(check.Message), "not a directory") {
		t.Fatalf("expected sanitized replica failure message, got %#v", check)
	}
}

func TestGraphPersistenceHealthDoesNotDegradeWhenReplicaAlreadySeeded(t *testing.T) {
	localDir := t.TempDir()
	replicaDir := t.TempDir()
	seedStore, err := graph.NewGraphPersistenceStore(graph.GraphPersistenceOptions{
		LocalPath:    localDir,
		MaxSnapshots: 4,
		ReplicaURI:   replicaDir,
	})
	if err != nil {
		t.Fatalf("new seed graph persistence store: %v", err)
	}
	g := graph.New()
	g.AddNode(&graph.Node{ID: "service:seeded", Kind: graph.NodeKindService, Name: "seeded"})
	g.SetMetadata(graph.Metadata{
		BuiltAt:       time.Date(2026, 3, 12, 23, 10, 0, 0, time.UTC),
		NodeCount:     1,
		EdgeCount:     0,
		Providers:     []string{"aws"},
		Accounts:      []string{"prod"},
		BuildDuration: time.Second,
	})
	if _, err := seedStore.SaveGraph(g); err != nil {
		t.Fatalf("seed graph snapshot: %v", err)
	}

	restartedStore, err := graph.NewGraphPersistenceStore(graph.GraphPersistenceOptions{
		LocalPath:    localDir,
		MaxSnapshots: 4,
		ReplicaURI:   replicaDir,
	})
	if err != nil {
		t.Fatalf("new restarted graph persistence store: %v", err)
	}

	application := &App{
		Config:         &Config{},
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		Warehouse:      &warehouse.MemoryWarehouse{},
		GraphSnapshots: restartedStore,
	}
	application.initHealth()

	results := application.Health.RunAll(context.Background())
	check := results["graph_persistence"]
	if check.Status != health.StatusHealthy {
		t.Fatalf("expected healthy graph persistence health, got %#v", check)
	}
}

func TestActivateBuiltSecurityGraphDoesNotReplaceLiveGraphWithNil(t *testing.T) {
	liveGraph := graph.New()
	liveGraph.AddNode(&graph.Node{ID: "service:payments", Kind: graph.NodeKindService, Name: "payments"})

	application := &App{
		Config:        &Config{},
		SecurityGraph: liveGraph,
	}

	if _, err := application.activateBuiltSecurityGraph(context.Background(), nil); err == nil {
		t.Fatal("expected nil built graph to return an error")
	}
	if got := application.CurrentSecurityGraph(); got != liveGraph {
		t.Fatal("expected existing live graph to remain in place when built graph is nil")
	}
	if snapshot := application.GraphBuildSnapshot(); snapshot.State != GraphBuildFailed {
		t.Fatalf("expected graph build state failed, got %#v", snapshot)
	}
}

func TestActivateBuiltSecurityGraphPersistsSnapshot(t *testing.T) {
	dir := t.TempDir()
	store, err := graph.NewGraphPersistenceStore(graph.GraphPersistenceOptions{
		LocalPath:    dir,
		MaxSnapshots: 4,
	})
	if err != nil {
		t.Fatalf("new graph persistence store: %v", err)
	}

	builtGraph := graph.New()
	builtGraph.AddNode(&graph.Node{ID: "service:payments", Kind: graph.NodeKindService, Name: "payments"})
	builtGraph.SetMetadata(graph.Metadata{
		BuiltAt:       time.Date(2026, 3, 12, 22, 5, 0, 0, time.UTC),
		NodeCount:     1,
		EdgeCount:     0,
		Providers:     []string{"aws"},
		Accounts:      []string{"prod"},
		BuildDuration: 1500 * time.Millisecond,
	})

	application := &App{
		Config:         &Config{GraphSnapshotPath: dir, GraphSnapshotMaxRetained: 4},
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		GraphSnapshots: store,
	}

	if _, err := application.activateBuiltSecurityGraph(context.Background(), builtGraph); err != nil {
		t.Fatalf("activateBuiltSecurityGraph failed: %v", err)
	}

	records, err := store.ListGraphSnapshotRecords()
	if err != nil {
		t.Fatalf("list persisted graph snapshots: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected one persisted graph snapshot, got %#v", records)
	}
	if records[0].ID == "" {
		t.Fatalf("expected persisted graph snapshot id, got %#v", records[0])
	}
	if status := store.Status(); status.LastPersistedSnapshot == "" {
		t.Fatalf("expected persistence status to track last persisted snapshot, got %#v", status)
	}
}

func TestGraphBuildSnapshotIncludesNodeCountWithoutHoldingBuildLock(t *testing.T) {
	liveGraph := graph.New()
	liveGraph.AddNode(&graph.Node{ID: "service:payments", Kind: graph.NodeKindService, Name: "payments"})
	liveGraph.AddNode(&graph.Node{ID: "service:billing", Kind: graph.NodeKindService, Name: "billing"})

	application := &App{
		Config:        &Config{},
		SecurityGraph: liveGraph,
	}
	application.setGraphBuildState(GraphBuildSuccess, time.Now().UTC(), nil)

	snapshot := application.GraphBuildSnapshot()
	if snapshot.State != GraphBuildSuccess {
		t.Fatalf("expected graph build state success, got %#v", snapshot)
	}
	if snapshot.NodeCount != 2 {
		t.Fatalf("expected graph node count 2, got %d", snapshot.NodeCount)
	}
}

func TestGraphBuildSnapshotUsesPersistedSnapshotNodeCountWhenLiveGraphUnavailable(t *testing.T) {
	persisted := graph.New()
	persisted.AddNode(&graph.Node{ID: "service:payments", Kind: graph.NodeKindService, Name: "payments"})
	persisted.AddNode(&graph.Node{ID: "service:billing", Kind: graph.NodeKindService, Name: "billing"})
	store := mustPersistToolGraph(t, persisted)

	application := &App{
		Config:         &Config{},
		GraphSnapshots: store,
	}
	application.setGraphBuildState(GraphBuildSuccess, time.Now().UTC(), nil)

	snapshot := application.GraphBuildSnapshot()
	if snapshot.State != GraphBuildSuccess {
		t.Fatalf("expected graph build state success, got %#v", snapshot)
	}
	if snapshot.NodeCount != 2 {
		t.Fatalf("expected persisted graph node count 2, got %d", snapshot.NodeCount)
	}
	if status := store.Status(); status.LastRecoveredAt != nil {
		t.Fatalf("expected build snapshot read to avoid recovery bookkeeping, got %#v", status)
	}
}

func TestGraphFreshnessStatusSnapshotUsesPersistedSnapshotWhenLiveGraphUnavailable(t *testing.T) {
	now := time.Date(2026, 3, 18, 12, 0, 0, 0, time.UTC)
	persisted := graph.New()
	persisted.AddNode(&graph.Node{
		ID:       "service:payments",
		Kind:     graph.NodeKindService,
		Name:     "payments",
		Provider: "aws",
		Properties: map[string]any{
			"observed_at": now.Add(-12 * time.Hour).Format(time.RFC3339),
		},
	})
	store := mustPersistToolGraph(t, persisted)

	application := &App{
		Config: &Config{
			GraphFreshnessDefaultSLA: 6 * time.Hour,
		},
		GraphSnapshots: store,
	}

	status := application.GraphFreshnessStatusSnapshot(now)
	if status.Healthy {
		t.Fatalf("expected persisted snapshot freshness breach, got %#v", status)
	}
	if len(status.Breaches) != 1 {
		t.Fatalf("expected one freshness breach, got %#v", status.Breaches)
	}
	if got := status.Breaches[0].Provider; got != "aws" {
		t.Fatalf("expected aws freshness breach, got %#v", got)
	}
	if len(status.Breakdown.Providers) != 1 {
		t.Fatalf("expected one provider freshness scope, got %#v", status.Breakdown.Providers)
	}
	if persistence := store.Status(); persistence.LastRecoveredAt != nil {
		t.Fatalf("expected freshness status read to avoid recovery bookkeeping, got %#v", persistence)
	}
}

func TestInitHealthRegistersGraphFreshnessCheckUsesPersistedSnapshotWhenLiveGraphUnavailable(t *testing.T) {
	now := time.Date(2026, 3, 18, 12, 0, 0, 0, time.UTC)
	persisted := graph.New()
	persisted.AddNode(&graph.Node{
		ID:       "service:payments",
		Kind:     graph.NodeKindService,
		Name:     "payments",
		Provider: "aws",
		Properties: map[string]any{
			"observed_at": now.Add(-12 * time.Hour).Format(time.RFC3339),
		},
	})
	store := mustPersistToolGraph(t, persisted)

	application := &App{
		Config: &Config{
			GraphFreshnessDefaultSLA: 6 * time.Hour,
		},
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		Warehouse:      &warehouse.MemoryWarehouse{},
		GraphSnapshots: store,
	}
	application.initHealth()

	results := application.Health.RunAll(context.Background())
	check, ok := results["graph_freshness"]
	if !ok {
		t.Fatal("expected graph_freshness health check to be registered")
	}
	if check.Status != health.StatusUnhealthy {
		t.Fatalf("expected unhealthy persisted graph freshness check, got %s (%s)", check.Status, check.Message)
	}
	if !strings.Contains(check.Message, "aws") {
		t.Fatalf("expected persisted provider breach in message, got %q", check.Message)
	}
	if persistence := store.Status(); persistence.LastRecoveredAt != nil {
		t.Fatalf("expected graph freshness health check to avoid recovery bookkeeping, got %#v", persistence)
	}
}

func TestMutateSecurityGraphSwapsCloneAfterMutationCompletes(t *testing.T) {
	liveGraph := graph.New()
	liveGraph.AddNode(&graph.Node{ID: "service:payments", Kind: graph.NodeKindService, Name: "payments"})

	application := &App{
		Config:        &Config{},
		SecurityGraph: liveGraph,
	}

	started := make(chan *graph.Graph, 1)
	release := make(chan struct{})
	errCh := make(chan error, 1)

	go func() {
		_, err := application.MutateSecurityGraph(context.Background(), func(candidate *graph.Graph) error {
			started <- candidate
			<-release
			candidate.AddNode(&graph.Node{ID: "service:billing", Kind: graph.NodeKindService, Name: "billing"})
			return nil
		})
		errCh <- err
	}()

	candidate := <-started
	if candidate == liveGraph {
		t.Fatal("expected mutation to operate on a cloned graph")
	}
	if got := application.CurrentSecurityGraph(); got != liveGraph {
		t.Fatal("expected live graph pointer to remain unchanged until swap")
	}
	if got := liveGraph.NodeCount(); got != 1 {
		t.Fatalf("expected original live graph node count 1 during in-flight mutation, got %d", got)
	}

	close(release)
	if err := <-errCh; err != nil {
		t.Fatalf("mutateSecurityGraph failed: %v", err)
	}

	current := application.CurrentSecurityGraph()
	if current == liveGraph {
		t.Fatal("expected live graph pointer to swap after mutation")
	}
	if got := current.NodeCount(); got != 2 {
		t.Fatalf("expected swapped graph node count 2, got %d", got)
	}
	if got := liveGraph.NodeCount(); got != 1 {
		t.Fatalf("expected original graph to remain unchanged after swap, got %d", got)
	}
}

func TestMutateSecurityGraphUsesPersistedSnapshotWhenLiveGraphUnavailable(t *testing.T) {
	base := graph.New()
	base.AddNode(&graph.Node{ID: "service:payments", Kind: graph.NodeKindService, Name: "payments"})
	base.AddNode(&graph.Node{ID: "bucket:prod", Kind: graph.NodeKindBucket, Name: "prod"})
	base.AddEdge(&graph.Edge{ID: "payments-prod", Source: "service:payments", Target: "bucket:prod", Kind: graph.EdgeKindOwns, Effect: graph.EdgeEffectAllow})
	base.BuildIndex()

	application := &App{
		Config:         &Config{},
		GraphSnapshots: mustPersistToolGraph(t, base),
	}

	mutated, err := application.MutateSecurityGraph(context.Background(), func(candidate *graph.Graph) error {
		if _, ok := candidate.GetNode("service:payments"); !ok {
			return fmt.Errorf("persisted base node missing")
		}
		if _, ok := candidate.GetNode("bucket:prod"); !ok {
			return fmt.Errorf("persisted base resource missing")
		}
		candidate.AddNode(&graph.Node{ID: "service:billing", Kind: graph.NodeKindService, Name: "billing"})
		return nil
	})
	if err != nil {
		t.Fatalf("MutateSecurityGraph() error = %v", err)
	}
	if _, ok := mutated.GetNode("service:payments"); !ok {
		t.Fatal("expected persisted base node to be preserved")
	}
	if _, ok := mutated.GetNode("bucket:prod"); !ok {
		t.Fatal("expected persisted base resource to be preserved")
	}
	if _, ok := mutated.GetNode("service:billing"); !ok {
		t.Fatal("expected new node to be added on top of persisted base")
	}
	if got := application.CurrentSecurityGraph(); got != mutated {
		t.Fatal("expected mutated graph to become the live graph")
	}
}

func TestRefreshCurrentEventCorrelationsSwapsGraphInsteadOfMutatingLiveInstance(t *testing.T) {
	base := time.Date(2026, 3, 12, 10, 0, 0, 0, time.UTC)
	liveGraph := graph.New()
	liveGraph.AddNode(&graph.Node{ID: "service:payments", Kind: graph.NodeKindService, Name: "payments"})
	liveGraph.AddNode(&graph.Node{
		ID:   "pull_request:payments:42",
		Kind: graph.NodeKindPullRequest,
		Name: "payments pr",
		Properties: map[string]any{
			"state":       "merged",
			"observed_at": base.Format(time.RFC3339),
			"valid_from":  base.Format(time.RFC3339),
		},
	})
	liveGraph.AddNode(&graph.Node{
		ID:   "deployment:payments:deploy-1",
		Kind: graph.NodeKindDeploymentRun,
		Name: "deploy-1",
		Properties: map[string]any{
			"service_id":  "payments",
			"status":      "succeeded",
			"observed_at": base.Add(5 * time.Minute).Format(time.RFC3339),
			"valid_from":  base.Add(5 * time.Minute).Format(time.RFC3339),
		},
	})
	liveGraph.AddEdge(&graph.Edge{ID: "pr->service", Source: "pull_request:payments:42", Target: "service:payments", Kind: graph.EdgeKindTargets, Effect: graph.EdgeEffectAllow})
	liveGraph.AddEdge(&graph.Edge{ID: "deploy->service", Source: "deployment:payments:deploy-1", Target: "service:payments", Kind: graph.EdgeKindTargets, Effect: graph.EdgeEffectAllow})

	application := &App{
		Config:        &Config{},
		SecurityGraph: liveGraph,
		graphCtx:      context.Background(),
	}

	if graphEdgeExists(liveGraph.GetOutEdges("deployment:payments:deploy-1"), graph.EdgeKindTriggeredBy, "pull_request:payments:42") {
		t.Fatal("expected no correlation edge on original live graph before refresh")
	}

	application.refreshCurrentEventCorrelations("test")

	current := application.CurrentSecurityGraph()
	if current == liveGraph {
		t.Fatal("expected live graph pointer to swap after correlation refresh")
	}
	if graphEdgeExists(liveGraph.GetOutEdges("deployment:payments:deploy-1"), graph.EdgeKindTriggeredBy, "pull_request:payments:42") {
		t.Fatal("expected original live graph to remain unchanged after refresh")
	}
	if !graphEdgeExists(current.GetOutEdges("deployment:payments:deploy-1"), graph.EdgeKindTriggeredBy, "pull_request:payments:42") {
		t.Fatal("expected swapped graph to include correlated deployment edge")
	}
}

func TestBurnRatesFastWindowUsesCurrentSnapshot(t *testing.T) {
	trend := []reports.GraphOntologySLOPoint{
		{Date: "2026-03-08", FallbackActivityPercent: 12, SchemaValidWritePercent: 97, Samples: 20},
		{Date: "2026-03-09", FallbackActivityPercent: 12, SchemaValidWritePercent: 97, Samples: 20},
	}

	fastHigher, _ := burnRatesForHigherIsWorse(20, 10, 30, trend)
	if fastHigher != 0.5 {
		t.Fatalf("expected higher-is-worse fast burn from current snapshot, got %.4f", fastHigher)
	}

	fastLower, _ := burnRatesForLowerIsWorse(90, 98, 92, trend)
	if fastLower != (8.0 / 6.0) {
		t.Fatalf("expected lower-is-worse fast burn from current snapshot, got %.4f", fastLower)
	}
}
