package api

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/app"
	"github.com/evalops/cerebro/internal/graph"
	risk "github.com/evalops/cerebro/internal/graph/risk"
	"github.com/evalops/cerebro/internal/snowflake"
)

func buildGraphStoreRiskEngineStateTestGraph() *graph.Graph {
	g := graph.New()
	seedGraphRiskFeedbackGraph(g)
	return g
}

func buildGraphStoreRiskEngineAlternateTestGraph() *graph.Graph {
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:   "customer:beta",
		Kind: graph.NodeKindCustomer,
		Name: "Beta",
		Properties: map[string]any{
			"failed_payment_count":     3,
			"open_p1_tickets":          2,
			"days_since_last_activity": 42,
		},
	})
	g.AddNode(&graph.Node{
		ID:   "deal:beta-renewal",
		Kind: graph.NodeKindDeal,
		Name: "Beta Renewal",
		Properties: map[string]any{
			"amount":                   180000,
			"days_since_last_activity": 35,
		},
	})
	g.AddEdge(&graph.Edge{
		ID:     "customer-beta-deal",
		Source: "customer:beta",
		Target: "deal:beta-renewal",
		Kind:   graph.EdgeKindOwns,
		Effect: graph.EdgeEffectAllow,
	})
	return g
}

type countingSnapshotStore struct {
	graph.GraphStore
	count atomic.Int32
}

func (s *countingSnapshotStore) Snapshot(ctx context.Context) (*graph.Snapshot, error) {
	s.count.Add(1)
	return s.GraphStore.Snapshot(ctx)
}

type blockingSnapshotStore struct {
	graph.GraphStore
	started chan struct{}
	release chan struct{}
}

func (s *blockingSnapshotStore) Snapshot(ctx context.Context) (*graph.Snapshot, error) {
	select {
	case <-s.started:
	default:
		close(s.started)
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.release:
	}
	return s.GraphStore.Snapshot(ctx)
}

type scriptedSnapshotStore struct {
	graph.GraphStore
	snapshots []*graph.Snapshot
	index     atomic.Int32
}

func (s *scriptedSnapshotStore) Snapshot(context.Context) (*graph.Snapshot, error) {
	if len(s.snapshots) == 0 {
		return nil, nil
	}
	idx := int(s.index.Add(1)) - 1
	if idx >= len(s.snapshots) {
		idx = len(s.snapshots) - 1
	}
	return s.snapshots[idx], nil
}

func primeStoreBackedRiskEngine(t *testing.T, s *Server, analyses int) {
	t.Helper()
	for i := 0; i < analyses; i++ {
		resp := do(t, s, http.MethodGet, "/api/v1/graph/risk-report", nil)
		if resp.Code != http.StatusOK {
			t.Fatalf("expected risk report 200, got %d: %s", resp.Code, resp.Body.String())
		}
	}
}

func TestGraphOutcomeAndFeedbackUseGraphStoreWhenRawGraphUnavailable(t *testing.T) {
	s := newStoreBackedGraphServer(t, buildGraphStoreRiskEngineStateTestGraph())
	primeStoreBackedRiskEngine(t, s, 5)

	record := do(t, s, http.MethodPost, "/api/v1/graph/outcomes", map[string]any{
		"entity_id":   "customer:acme",
		"outcome":     "churn",
		"occurred_at": time.Now().UTC().Add(4 * time.Hour),
		"metadata": map[string]any{
			"source": "crm",
		},
	})
	if record.Code != http.StatusOK {
		t.Fatalf("expected outcomes POST 200, got %d: %s", record.Code, record.Body.String())
	}

	list := do(t, s, http.MethodGet, "/api/v1/graph/outcomes?entity_id=customer:acme", nil)
	if list.Code != http.StatusOK {
		t.Fatalf("expected outcomes list 200, got %d: %s", list.Code, list.Body.String())
	}
	listBody := decodeJSON(t, list)
	if count, ok := listBody["count"].(float64); !ok || count < 1 {
		t.Fatalf("expected store-backed outcomes, got %#v", listBody)
	}

	feedback := do(t, s, http.MethodGet, "/api/v1/graph/risk-feedback?window_days=365&profile=revenue-heavy", nil)
	if feedback.Code != http.StatusOK {
		t.Fatalf("expected risk feedback 200, got %d: %s", feedback.Code, feedback.Body.String())
	}
	feedbackBody := decodeJSON(t, feedback)
	if count, ok := feedbackBody["outcome_count"].(float64); !ok || count < 1 {
		t.Fatalf("expected store-backed feedback outcomes, got %#v", feedbackBody)
	}
}

func TestGraphRuleDiscoveryUsesGraphStoreWhenRawGraphUnavailable(t *testing.T) {
	s := newStoreBackedGraphServer(t, buildGraphStoreRiskEngineStateTestGraph())
	primeStoreBackedRiskEngine(t, s, 5)

	record := do(t, s, http.MethodPost, "/api/v1/graph/outcomes", map[string]any{
		"entity_id":   "customer:acme",
		"outcome":     "churn",
		"occurred_at": time.Now().UTC().Add(4 * time.Hour),
	})
	if record.Code != http.StatusOK {
		t.Fatalf("expected outcomes POST 200, got %d: %s", record.Code, record.Body.String())
	}

	run := do(t, s, http.MethodPost, "/api/v1/graph/rule-discovery/run", map[string]any{
		"window_days":                365,
		"min_detections":             3,
		"max_candidates":             10,
		"include_policies":           true,
		"include_toxic_combinations": true,
	})
	if run.Code != http.StatusOK {
		t.Fatalf("expected rule discovery run 200, got %d: %s", run.Code, run.Body.String())
	}
	runBody := decodeJSON(t, run)
	candidates, ok := runBody["candidates"].([]any)
	if !ok || len(candidates) == 0 {
		t.Fatalf("expected store-backed discovery candidates, got %#v", runBody)
	}

	candidateID, _ := candidates[0].(map[string]any)["id"].(string)
	if candidateID == "" {
		t.Fatalf("expected candidate id, got %#v", candidates[0])
	}

	list := do(t, s, http.MethodGet, "/api/v1/graph/rule-discovery/candidates?status=pending_approval", nil)
	if list.Code != http.StatusOK {
		t.Fatalf("expected candidate list 200, got %d: %s", list.Code, list.Body.String())
	}

	decision := do(t, s, http.MethodPost, "/api/v1/graph/rule-discovery/candidates/"+candidateID+"/decision", map[string]any{
		"approve":  true,
		"reviewer": "security-lead",
	})
	if decision.Code != http.StatusOK {
		t.Fatalf("expected candidate decision 200, got %d: %s", decision.Code, decision.Body.String())
	}
}

func TestGraphCrossTenantPatternsUseGraphStoreWhenRawGraphUnavailable(t *testing.T) {
	s := newStoreBackedGraphServer(t, buildGraphStoreRiskEngineStateTestGraph())
	primeStoreBackedRiskEngine(t, s, 5)

	record := do(t, s, http.MethodPost, "/api/v1/graph/outcomes", map[string]any{
		"entity_id":   "customer:acme",
		"outcome":     "churn",
		"occurred_at": time.Now().UTC().Add(4 * time.Hour),
	})
	if record.Code != http.StatusOK {
		t.Fatalf("expected outcomes POST 200, got %d: %s", record.Code, record.Body.String())
	}

	buildA := do(t, s, http.MethodPost, "/api/v1/graph/cross-tenant/patterns/build", map[string]any{
		"tenant_id":   "tenant-alpha",
		"window_days": 365,
	})
	if buildA.Code != http.StatusOK {
		t.Fatalf("expected build A 200, got %d: %s", buildA.Code, buildA.Body.String())
	}
	samplesA, ok := decodeJSON(t, buildA)["samples"].([]any)
	if !ok || len(samplesA) == 0 {
		t.Fatalf("expected store-backed tenant-alpha samples, got %#v", decodeJSON(t, buildA))
	}

	buildB := do(t, s, http.MethodPost, "/api/v1/graph/cross-tenant/patterns/build", map[string]any{
		"tenant_id":   "tenant-beta",
		"window_days": 365,
	})
	if buildB.Code != http.StatusOK {
		t.Fatalf("expected build B 200, got %d: %s", buildB.Code, buildB.Body.String())
	}
	samplesB, ok := decodeJSON(t, buildB)["samples"].([]any)
	if !ok || len(samplesB) == 0 {
		t.Fatalf("expected store-backed tenant-beta samples, got %#v", decodeJSON(t, buildB))
	}

	ingest := do(t, s, http.MethodPost, "/api/v1/graph/cross-tenant/patterns/ingest", map[string]any{
		"samples": append(append([]any{}, samplesA...), samplesB...),
	})
	if ingest.Code != http.StatusOK {
		t.Fatalf("expected ingest 200, got %d: %s", ingest.Code, ingest.Body.String())
	}

	patterns := do(t, s, http.MethodGet, "/api/v1/graph/cross-tenant/patterns?min_tenants=2", nil)
	if patterns.Code != http.StatusOK {
		t.Fatalf("expected patterns 200, got %d: %s", patterns.Code, patterns.Body.String())
	}
	patternBody := decodeJSON(t, patterns)
	if count, ok := patternBody["count"].(float64); !ok || count < 1 {
		t.Fatalf("expected store-backed cross-tenant patterns, got %#v", patternBody)
	}

	matches := do(t, s, http.MethodGet, "/api/v1/graph/cross-tenant/matches?min_probability=0.5&limit=5", nil)
	if matches.Code != http.StatusOK {
		t.Fatalf("expected matches 200, got %d: %s", matches.Code, matches.Body.String())
	}
	matchBody := decodeJSON(t, matches)
	if count, ok := matchBody["count"].(float64); !ok || count < 1 {
		t.Fatalf("expected store-backed cross-tenant matches, got %#v", matchBody)
	}
}

func TestGraphRiskEngineReusesStoreBackedEngineForStableSnapshot(t *testing.T) {
	store := &countingSnapshotStore{GraphStore: buildGraphStoreRiskEngineStateTestGraph()}
	s := newStoreBackedGraphServer(t, store)

	first := s.graphRiskEngine(context.Background())
	second := s.graphRiskEngine(context.Background())
	if first == nil || second == nil {
		t.Fatal("expected store-backed risk engine")
	}
	if first != second {
		t.Fatalf("expected store-backed risk engine to be reused, got %p then %p", first, second)
	}
	if got := store.count.Load(); got < 2 {
		t.Fatalf("expected snapshot lookups while checking for store updates, got %d", got)
	}
}

func TestGraphRiskEngineUsesGraphRuntimeWithoutStoredSecurityGraphField(t *testing.T) {
	runtime := &stubGraphRuntime{graph: buildGraphStoreRiskEngineStateTestGraph()}
	s := NewServerWithDependencies(serverDependencies{
		Config:       &app.Config{},
		graphRuntime: runtime,
	})
	t.Cleanup(func() { s.Close() })

	if s.app.SecurityGraph != nil {
		t.Fatalf("expected dependency bundle to start without a direct security graph, got %p", s.app.SecurityGraph)
	}

	engine := s.graphRiskEngine(context.Background())
	if engine == nil {
		t.Fatal("expected graph risk engine to use graphRuntime.CurrentSecurityGraph()")
	}
	if report := engine.Analyze(); report == nil {
		t.Fatal("expected runtime-backed risk engine report")
	}
}

func TestGraphRiskEngineRefreshesWhenGraphRuntimeGraphChanges(t *testing.T) {
	runtime := &stubGraphRuntime{graph: buildGraphStoreRiskEngineStateTestGraph()}
	s := NewServerWithDependencies(serverDependencies{
		Config:       &app.Config{},
		graphRuntime: runtime,
	})
	t.Cleanup(func() { s.Close() })

	first := s.graphRiskEngine(context.Background())
	if first == nil {
		t.Fatal("expected initial runtime-backed risk engine")
	}

	runtime.graph = buildGraphStoreRiskEngineAlternateTestGraph()
	second := s.graphRiskEngine(context.Background())
	if second == nil {
		t.Fatal("expected refreshed runtime-backed risk engine")
	}
	if second == first {
		t.Fatal("expected a new risk engine after runtime graph swap")
	}
	if s.riskEngineSource != runtime.graph {
		t.Fatalf("expected cached risk engine source to track the latest runtime graph, got %p want %p", s.riskEngineSource, runtime.graph)
	}
}

func TestRiskEngineSnapshotKeyDiffersForDifferentZeroBuiltAtSnapshots(t *testing.T) {
	first := graph.CreateSnapshot(buildGraphStoreRiskEngineStateTestGraph())
	second := graph.CreateSnapshot(buildGraphStoreRiskEngineAlternateTestGraph())

	if !first.Metadata.BuiltAt.IsZero() || !second.Metadata.BuiltAt.IsZero() {
		t.Fatalf("expected zero built_at metadata for collision regression, got %v and %v", first.Metadata.BuiltAt, second.Metadata.BuiltAt)
	}
	if len(first.Nodes) != len(second.Nodes) || len(first.Edges) != len(second.Edges) {
		t.Fatalf("expected equal counts for collision regression, got %d/%d vs %d/%d", len(first.Nodes), len(first.Edges), len(second.Nodes), len(second.Edges))
	}
	if riskEngineSnapshotKey(first) == riskEngineSnapshotKey(second) {
		t.Fatal("expected different snapshot keys for distinct zero-built_at graphs with matching counts")
	}
}

func TestGraphRiskEngineDoesNotRestoreStaleInMemoryStateAcrossChangedStoreSnapshot(t *testing.T) {
	firstSnapshot := graph.CreateSnapshot(buildGraphStoreRiskEngineStateTestGraph())
	secondSnapshot := graph.CreateSnapshot(buildGraphStoreRiskEngineAlternateTestGraph())
	store := &scriptedSnapshotStore{
		GraphStore: buildGraphStoreRiskEngineStateTestGraph(),
		snapshots:  []*graph.Snapshot{firstSnapshot, secondSnapshot},
	}
	s := newStoreBackedGraphServer(t, store)
	s.app.RiskEngineStateRepo = &snowflake.RiskEngineStateRepository{}

	first := s.graphRiskEngine(context.Background())
	if first == nil {
		t.Fatal("expected initial store-backed risk engine")
	}
	if _, err := first.RecordOutcome(risk.OutcomeEvent{
		EntityID:   "customer:acme",
		Outcome:    "churn",
		OccurredAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("RecordOutcome() error = %v", err)
	}

	second := s.graphRiskEngine(context.Background())
	if second == nil {
		t.Fatal("expected refreshed store-backed risk engine")
	}
	if second == first {
		t.Fatal("expected a new risk engine for a changed snapshot topology")
	}
	if got := len(second.OutcomeEvents("", "")); got != 0 {
		t.Fatalf("expected no stale in-memory outcomes after topology change, got %d", got)
	}
}

func TestGraphRiskEngineStoreSnapshotDoesNotHoldMutex(t *testing.T) {
	store := &blockingSnapshotStore{
		GraphStore: buildGraphStoreRiskEngineStateTestGraph(),
		started:    make(chan struct{}),
		release:    make(chan struct{}),
	}
	s := newStoreBackedGraphServer(t, store)

	done := make(chan struct{}, 1)
	go func() {
		if s.graphRiskEngine(context.Background()) == nil {
			t.Error("expected graphRiskEngine to initialize after snapshot release")
		}
		done <- struct{}{}
	}()

	select {
	case <-store.started:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for store snapshot to start")
	}

	locked := make(chan struct{})
	go func() {
		s.riskEngineMu.Lock()
		close(locked)
		s.riskEngineMu.Unlock()
	}()

	select {
	case <-locked:
	case <-time.After(time.Second):
		t.Fatal("expected riskEngineMu to remain available while store snapshot is in progress")
	}

	close(store.release)

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for graphRiskEngine to finish")
	}
}

func TestGraphRiskEngineStoreSnapshotUsesCallerContext(t *testing.T) {
	store := &blockingSnapshotStore{
		GraphStore: buildGraphStoreRiskEngineStateTestGraph(),
		started:    make(chan struct{}),
		release:    make(chan struct{}),
	}
	s := newStoreBackedGraphServer(t, store)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan *risk.RiskEngine, 1)
	go func() {
		done <- s.graphRiskEngine(ctx)
	}()

	select {
	case <-store.started:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for store snapshot to start")
	}

	cancel()

	select {
	case engine := <-done:
		if engine != nil {
			t.Fatalf("expected nil risk engine after caller cancellation, got %p", engine)
		}
	case <-time.After(time.Second):
		t.Fatal("expected graphRiskEngine to stop waiting after caller cancellation")
	}
}

func TestRiskEngineStateRestoreContextIgnoresCallerCancellation(t *testing.T) {
	s := NewServerWithDependencies(serverDependencies{
		Config: &app.Config{GraphRiskEngineStateTimeout: 250 * time.Millisecond},
	})
	t.Cleanup(func() { s.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	restoreCtx, restoreCancel := s.riskEngineStateRestoreContext(ctx)
	defer restoreCancel()

	select {
	case <-restoreCtx.Done():
		t.Fatalf("expected restore context to detach caller cancellation, got %v", restoreCtx.Err())
	default:
	}
}
