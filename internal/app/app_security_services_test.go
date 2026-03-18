package app

import (
	"context"
	"io"
	"log/slog"
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
