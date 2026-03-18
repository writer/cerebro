package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/graph"
	"github.com/evalops/cerebro/internal/metrics"
	"github.com/evalops/cerebro/internal/snowflake"
	dto "github.com/prometheus/client_model/go"
)

func doWithTenantContext(t *testing.T, s *Server, method, path string, body any, tenantID string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		reader = bytes.NewReader(payload)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req = req.WithContext(context.WithValue(req.Context(), contextKeyTenant, tenantID))
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	return w
}

func TestGraphRiskHandlersUseTenantScopedGraph(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph
	g.AddNode(&graph.Node{ID: "user:shared", Kind: graph.NodeKindUser, Name: "Shared User"})
	g.AddNode(&graph.Node{ID: "service:tenant-a", Kind: graph.NodeKindService, Name: "Tenant A", TenantID: "tenant-a"})
	g.AddNode(&graph.Node{ID: "service:tenant-b", Kind: graph.NodeKindService, Name: "Tenant B", TenantID: "tenant-b"})
	g.AddEdge(&graph.Edge{ID: "shared-a", Source: "user:shared", Target: "service:tenant-a", Kind: graph.EdgeKindCanRead, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "shared-b", Source: "user:shared", Target: "service:tenant-b", Kind: graph.EdgeKindCanRead, Effect: graph.EdgeEffectAllow})

	resp := doWithTenantContext(t, s, http.MethodGet, "/api/v1/graph/blast-radius/user:shared?max_depth=2", nil, "tenant-a")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected tenant-scoped blast radius 200, got %d: %s", resp.Code, resp.Body.String())
	}
	body := decodeJSON(t, resp)
	reachable, ok := body["reachable_nodes"].([]any)
	if !ok || len(reachable) != 1 {
		t.Fatalf("expected one tenant-visible reachable node, got %#v", body["reachable_nodes"])
	}
	node := reachable[0].(map[string]any)["node"].(map[string]any)
	if node["id"] != "service:tenant-a" {
		t.Fatalf("expected tenant-a node only, got %#v", node)
	}
}

func TestCurrentTenantSecurityGraphReusesTenantShard(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph
	g.AddNode(&graph.Node{ID: "service:shared", Kind: graph.NodeKindService, Name: "Shared"})
	g.AddNode(&graph.Node{ID: "service:tenant-a", Kind: graph.NodeKindService, Name: "Tenant A", TenantID: "tenant-a"})
	g.AddNode(&graph.Node{ID: "service:tenant-b", Kind: graph.NodeKindService, Name: "Tenant B", TenantID: "tenant-b"})
	g.AddEdge(&graph.Edge{ID: "shared-a", Source: "service:shared", Target: "service:tenant-a", Kind: graph.EdgeKindDependsOn})
	g.AddEdge(&graph.Edge{ID: "shared-b", Source: "service:shared", Target: "service:tenant-b", Kind: graph.EdgeKindDependsOn})

	ctx := context.WithValue(context.Background(), contextKeyTenant, "tenant-a")
	first := s.currentTenantSecurityGraph(ctx)
	second := s.currentTenantSecurityGraph(ctx)
	if first == nil || second == nil {
		t.Fatal("expected tenant-scoped live graph")
	}
	if first != second {
		t.Fatalf("expected live tenant graph reuse, got %p then %p", first, second)
	}
	if first == g {
		t.Fatal("expected tenant-scoped graph to differ from the global live graph")
	}
	if _, ok := first.GetNode("service:tenant-b"); ok {
		t.Fatal("expected tenant shard to exclude foreign-tenant nodes")
	}
}

func TestCurrentTenantSecurityGraphSnapshotViewIsIsolatedFromLiveShard(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph
	g.AddNode(&graph.Node{ID: "service:shared", Kind: graph.NodeKindService, Name: "Shared"})
	g.AddNode(&graph.Node{ID: "service:tenant-a", Kind: graph.NodeKindService, Name: "Tenant A", TenantID: "tenant-a"})
	g.AddEdge(&graph.Edge{ID: "shared-a", Source: "service:shared", Target: "service:tenant-a", Kind: graph.EdgeKindDependsOn})

	ctx := context.WithValue(context.Background(), contextKeyTenant, "tenant-a")
	live := s.currentTenantSecurityGraph(ctx)
	snapshot, err := s.currentTenantSecurityGraphSnapshotView(ctx)
	if err != nil {
		t.Fatalf("expected snapshot-backed tenant graph, got error: %v", err)
	}
	if live == nil || snapshot == nil {
		t.Fatal("expected both live and snapshot tenant graphs")
	}
	if snapshot == live {
		t.Fatal("expected snapshot-backed tenant graph to differ from the live tenant shard")
	}

	snapshot.AddNode(&graph.Node{ID: "service:snapshot-only", Kind: graph.NodeKindService, Name: "Snapshot Only", TenantID: "tenant-a"})
	if _, ok := live.GetNode("service:snapshot-only"); ok {
		t.Fatal("expected snapshot-backed tenant graph mutations to stay isolated from the live tenant shard")
	}
}

func TestGraphIntelligenceHandlersUseTenantScopedGraph(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph
	base := time.Date(2026, 3, 12, 10, 0, 0, 0, time.UTC)
	g.AddNode(&graph.Node{ID: "service:tenant-a", Kind: graph.NodeKindService, Name: "Tenant A", TenantID: "tenant-a"})
	g.AddNode(&graph.Node{ID: "service:tenant-b", Kind: graph.NodeKindService, Name: "Tenant B", TenantID: "tenant-b"})
	g.AddNode(&graph.Node{
		ID:       "pull_request:tenant-b:42",
		Kind:     graph.NodeKindPullRequest,
		TenantID: "tenant-b",
		Properties: map[string]any{
			"repository":  "tenant-b",
			"number":      "42",
			"state":       "merged",
			"observed_at": base.Format(time.RFC3339),
			"valid_from":  base.Format(time.RFC3339),
		},
	})
	g.AddNode(&graph.Node{
		ID:       "deployment:tenant-b:deploy-1",
		Kind:     graph.NodeKindDeploymentRun,
		TenantID: "tenant-b",
		Properties: map[string]any{
			"deploy_id":   "deploy-1",
			"service_id":  "tenant-b",
			"environment": "prod",
			"status":      "succeeded",
			"observed_at": base.Add(5 * time.Minute).Format(time.RFC3339),
			"valid_from":  base.Add(5 * time.Minute).Format(time.RFC3339),
		},
	})
	g.AddNode(&graph.Node{
		ID:       "incident:tenant-b:1",
		Kind:     graph.NodeKindIncident,
		TenantID: "tenant-b",
		Properties: map[string]any{
			"incident_id": "incident-b-1",
			"service_id":  "tenant-b",
			"observed_at": base.Add(7 * time.Minute).Format(time.RFC3339),
			"valid_from":  base.Add(7 * time.Minute).Format(time.RFC3339),
		},
	})
	g.AddEdge(&graph.Edge{ID: "pr-b-service", Source: "pull_request:tenant-b:42", Target: "service:tenant-b", Kind: graph.EdgeKindTargets, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "deploy-b-service", Source: "deployment:tenant-b:deploy-1", Target: "service:tenant-b", Kind: graph.EdgeKindTargets, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "incident-b-service", Source: "incident:tenant-b:1", Target: "service:tenant-b", Kind: graph.EdgeKindTargets, Effect: graph.EdgeEffectAllow})
	graph.MaterializeEventCorrelations(g, base.Add(10*time.Minute))

	resp := doWithTenantContext(t, s, http.MethodGet, "/api/v1/platform/intelligence/event-correlations?event_id=incident:tenant-b:1&limit=10", nil, "tenant-a")
	if resp.Code != http.StatusNotFound {
		t.Fatalf("expected tenant-scoped event correlation lookup to hide foreign tenant event, got %d: %s", resp.Code, resp.Body.String())
	}
}

func TestCrossTenantReadOperationsEmitAuditAndMetrics(t *testing.T) {
	s := newTestServer(t)
	s.auditLogger = &captureAuditLogger{}
	seedGraphRiskFeedbackGraph(s.app.SecurityGraph)

	for i := 0; i < 5; i++ {
		w := do(t, s, http.MethodGet, "/api/v1/graph/risk-report", nil)
		if w.Code != http.StatusOK {
			t.Fatalf("expected risk report 200, got %d: %s", w.Code, w.Body.String())
		}
	}
	record := do(t, s, http.MethodPost, "/api/v1/graph/outcomes", map[string]any{
		"entity_id":   "customer:acme",
		"outcome":     "churn",
		"occurred_at": time.Now().UTC().Add(4 * time.Hour),
	})
	if record.Code != http.StatusOK {
		t.Fatalf("expected outcome record 200, got %d: %s", record.Code, record.Body.String())
	}

	build := doWithTenantContext(t, s, http.MethodPost, "/api/v1/graph/cross-tenant/patterns/build", map[string]any{
		"tenant_id":   "tenant-beta",
		"window_days": 365,
	}, "tenant-admin")
	if build.Code != http.StatusOK {
		t.Fatalf("expected build response 200, got %d: %s", build.Code, build.Body.String())
	}
	list := doWithTenantContext(t, s, http.MethodGet, "/api/v1/graph/cross-tenant/patterns", nil, "tenant-admin")
	if list.Code != http.StatusOK {
		t.Fatalf("expected list response 200, got %d: %s", list.Code, list.Body.String())
	}

	logger := s.auditLogger.(*captureAuditLogger)
	if len(logger.entries) != 2 {
		t.Fatalf("expected two cross-tenant audit entries, got %d", len(logger.entries))
	}
	entry := logger.entries[0]
	if entry.Action != "graph.cross_tenant.read" {
		t.Fatalf("expected cross-tenant audit action, got %#v", entry.Action)
	}
	if entry.Details["requesting_tenant"] != "tenant-admin" || entry.Details["target_tenant"] != "tenant-beta" {
		t.Fatalf("unexpected audit details: %#v", entry.Details)
	}
	if logger.entries[1].Details["target_tenant"] != "aggregate_library" {
		t.Fatalf("expected aggregate-library audit detail, got %#v", logger.entries[1].Details)
	}

	metric := metrics.GraphCrossTenantReadsTotal.WithLabelValues("build_samples", "tenant", "tenant", "allowed")
	snapshot := &dto.Metric{}
	if err := metric.Write(snapshot); err != nil {
		t.Fatalf("read metric: %v", err)
	}
	if got := snapshot.GetCounter().GetValue(); got < 1 {
		t.Fatalf("expected cross-tenant metric increment, got %f", got)
	}

	aggregateMetric := metrics.GraphCrossTenantReadsTotal.WithLabelValues("list_patterns", "tenant", "aggregate", "allowed")
	aggregateSnapshot := &dto.Metric{}
	if err := aggregateMetric.Write(aggregateSnapshot); err != nil {
		t.Fatalf("read aggregate metric: %v", err)
	}
	if got := aggregateSnapshot.GetCounter().GetValue(); got < 1 {
		t.Fatalf("expected aggregate cross-tenant metric increment, got %f", got)
	}
}

func TestRiskReportPersistsOnlyForGlobalRequests(t *testing.T) {
	s := newTestServer(t)
	seedGraphRiskFeedbackGraph(s.app.SecurityGraph)
	s.app.RiskEngineStateRepo = &snowflake.RiskEngineStateRepository{}

	saveFailed := metrics.GraphStatePersistenceTotal.WithLabelValues("save_failed")
	before := &dto.Metric{}
	if err := saveFailed.Write(before); err != nil {
		t.Fatalf("read initial persistence metric: %v", err)
	}

	global := do(t, s, http.MethodGet, "/api/v1/graph/risk-report", nil)
	if global.Code != http.StatusOK {
		t.Fatalf("expected global risk report 200, got %d: %s", global.Code, global.Body.String())
	}

	afterGlobal := &dto.Metric{}
	if err := saveFailed.Write(afterGlobal); err != nil {
		t.Fatalf("read global persistence metric: %v", err)
	}
	if afterGlobal.GetCounter().GetValue() <= before.GetCounter().GetValue() {
		t.Fatalf("expected global risk report to attempt persistence, before=%f after=%f", before.GetCounter().GetValue(), afterGlobal.GetCounter().GetValue())
	}

	tenant := doWithTenantContext(t, s, http.MethodGet, "/api/v1/graph/risk-report", nil, "tenant-a")
	if tenant.Code != http.StatusOK {
		t.Fatalf("expected tenant risk report 200, got %d: %s", tenant.Code, tenant.Body.String())
	}

	afterTenant := &dto.Metric{}
	if err := saveFailed.Write(afterTenant); err != nil {
		t.Fatalf("read tenant persistence metric: %v", err)
	}
	if afterTenant.GetCounter().GetValue() != afterGlobal.GetCounter().GetValue() {
		t.Fatalf("expected tenant-scoped risk report to skip persistence, global=%f tenant=%f", afterGlobal.GetCounter().GetValue(), afterTenant.GetCounter().GetValue())
	}
}
