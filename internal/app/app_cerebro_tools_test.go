package app

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/actionengine"
	"github.com/evalops/cerebro/internal/agents"
	"github.com/evalops/cerebro/internal/autonomous"
	"github.com/evalops/cerebro/internal/executionstore"
	"github.com/evalops/cerebro/internal/findings"
	"github.com/evalops/cerebro/internal/graph"
	"github.com/evalops/cerebro/internal/imagescan"
	"github.com/evalops/cerebro/internal/policy"
	"github.com/evalops/cerebro/internal/runtime"
)

type recordingAutonomousActionHandler struct {
	principalID string
	provider    string
	calls       int
}

type blockingAutonomousActionHandler struct {
	started chan struct{}
	release chan struct{}
	calls   atomic.Int32
	once    sync.Once
}

func (h *recordingAutonomousActionHandler) KillProcess(context.Context, string, int) error {
	return nil
}

func (h *recordingAutonomousActionHandler) IsolateContainer(context.Context, string, string) error {
	return nil
}

func (h *recordingAutonomousActionHandler) IsolateHost(context.Context, string, string) error {
	return nil
}

func (h *recordingAutonomousActionHandler) QuarantineFile(context.Context, string, string) error {
	return nil
}

func (h *recordingAutonomousActionHandler) BlockIP(context.Context, string) error {
	return nil
}

func (h *recordingAutonomousActionHandler) BlockDomain(context.Context, string) error {
	return nil
}

func (h *recordingAutonomousActionHandler) RevokeCredentials(_ context.Context, principalID, provider string) error {
	h.principalID = principalID
	h.provider = provider
	h.calls++
	return nil
}

func (h *recordingAutonomousActionHandler) ScaleDown(context.Context, string, int) error {
	return nil
}

func (h *blockingAutonomousActionHandler) KillProcess(context.Context, string, int) error {
	return nil
}

func (h *blockingAutonomousActionHandler) IsolateContainer(context.Context, string, string) error {
	return nil
}

func (h *blockingAutonomousActionHandler) IsolateHost(context.Context, string, string) error {
	return nil
}

func (h *blockingAutonomousActionHandler) QuarantineFile(context.Context, string, string) error {
	return nil
}

func (h *blockingAutonomousActionHandler) BlockIP(context.Context, string) error {
	return nil
}

func (h *blockingAutonomousActionHandler) BlockDomain(context.Context, string) error {
	return nil
}

func (h *blockingAutonomousActionHandler) RevokeCredentials(context.Context, string, string) error {
	h.calls.Add(1)
	h.once.Do(func() {
		close(h.started)
	})
	<-h.release
	return nil
}

func (h *blockingAutonomousActionHandler) ScaleDown(context.Context, string, int) error {
	return nil
}

func autonomousCredentialWorkflowGraph() *graph.Graph {
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:   "secret:public-repo:1",
		Kind: graph.NodeKindSecret,
		Name: "exposed-secret",
		Properties: map[string]any{
			"provider":           "aws",
			"workload_target_id": "workload:payments-api",
			"finding_id":         "finding:secret:1",
		},
	})
	g.AddNode(&graph.Node{ID: "workload:payments-api", Kind: graph.NodeKindWorkload, Name: "payments-api", Provider: "aws"})
	g.AddNode(&graph.Node{ID: "service_account:payments-prod", Kind: graph.NodeKindServiceAccount, Name: "payments-prod", Provider: "aws"})
	g.AddNode(&graph.Node{ID: "bucket:payments-prod", Kind: graph.NodeKindBucket, Name: "payments-prod", Provider: "aws"})
	g.AddEdge(&graph.Edge{
		ID:     "workload:payments-api->bucket:payments-prod:has_credential_for",
		Source: "workload:payments-api",
		Target: "bucket:payments-prod",
		Kind:   graph.EdgeKindHasCredentialFor,
		Effect: graph.EdgeEffectAllow,
		Properties: map[string]any{
			"secret_node_id":   "secret:public-repo:1",
			"via_principal_id": "service_account:payments-prod",
		},
	})
	g.BuildIndex()
	return g
}

func TestCerebroToolsApprovalFlags(t *testing.T) {
	application := &App{Config: &Config{
		CerebroSimulateNeedsApproval:     false,
		CerebroAccessReviewNeedsApproval: true,
	}}

	tools := application.cerebroTools()
	simulate := findCerebroTool(tools, "cerebro.simulate")
	if simulate == nil {
		t.Fatal("expected cerebro.simulate tool")
	}
	if simulate.RequiresApproval {
		t.Fatal("simulate should not require approval with current config")
	}
	scenarioSimulate := findCerebroTool(tools, "simulate")
	if scenarioSimulate == nil {
		t.Fatal("expected simulate tool")
	}
	if scenarioSimulate.RequiresApproval {
		t.Fatal("simulate should not require approval with current config")
	}
	insightCard := findCerebroTool(tools, "insight_card")
	if insightCard == nil {
		t.Fatal("expected insight_card tool")
	}

	accessReview := findCerebroTool(tools, "cerebro.access_review")
	if accessReview == nil {
		t.Fatal("expected cerebro.access_review tool")
	}
	if !accessReview.RequiresApproval {
		t.Fatal("access_review should require approval with current config")
	}

	autonomousApprove := findCerebroTool(tools, "cerebro.autonomous_workflow_approve")
	if autonomousApprove == nil {
		t.Fatal("expected cerebro.autonomous_workflow_approve tool")
	}
	if !autonomousApprove.RequiresApproval {
		t.Fatal("autonomous_workflow_approve should require approval")
	}
}

func TestCerebroBlastRadiusTool(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "user:alice", Kind: graph.NodeKindUser, Name: "Alice"})
	g.AddNode(&graph.Node{ID: "bucket:prod", Kind: graph.NodeKindBucket, Name: "Prod Bucket", Risk: graph.RiskHigh})
	g.AddEdge(&graph.Edge{ID: "alice-bucket", Source: "user:alice", Target: "bucket:prod", Kind: graph.EdgeKindCanRead, Effect: graph.EdgeEffectAllow})

	application := &App{SecurityGraph: g}
	tool := findCerebroTool(application.cerebroTools(), "cerebro.blast_radius")
	if tool == nil {
		t.Fatal("expected blast radius tool")
	}

	result, err := tool.Handler(context.Background(), json.RawMessage(`{"principal_id":"user:alice","max_depth":3}`))
	if err != nil {
		t.Fatalf("tool returned error: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(result), &payload); err != nil {
		t.Fatalf("decode tool payload: %v", err)
	}
	if payload["principal_id"] != "user:alice" {
		t.Fatalf("expected principal_id user:alice, got %#v", payload["principal_id"])
	}
	if total, ok := payload["total_count"].(float64); !ok || total < 1 {
		t.Fatalf("expected reachable nodes, got %#v", payload["total_count"])
	}
}

func TestCerebroAnalysisToolsUsePersistedSnapshotWhenLiveGraphUnavailable(t *testing.T) {
	base := time.Date(2026, 3, 12, 10, 0, 0, 0, time.UTC)
	g := graph.New()
	g.AddNode(&graph.Node{ID: "user:alice", Kind: graph.NodeKindUser, Name: "Alice"})
	g.AddNode(&graph.Node{ID: "role:ops", Kind: graph.NodeKindRole, Name: "Ops"})
	g.AddNode(&graph.Node{ID: "db:prod", Kind: graph.NodeKindDatabase, Name: "Prod DB", Risk: graph.RiskCritical})
	g.AddNode(&graph.Node{
		ID:   "person:alice@example.com",
		Kind: graph.NodeKindPerson,
		Name: "Alice",
		Properties: map[string]any{
			"email":       "alice@example.com",
			"observed_at": base.Add(-1 * time.Hour).Format(time.RFC3339),
			"valid_from":  base.Add(-1 * time.Hour).Format(time.RFC3339),
		},
	})
	g.AddNode(&graph.Node{
		ID:   "identity_alias:github:alice",
		Kind: graph.NodeKindIdentityAlias,
		Name: "alice",
		Properties: map[string]any{
			"source_system": "github",
			"external_id":   "alice",
			"email":         "alice@example.com",
			"observed_at":   base.Add(-1 * time.Hour).Format(time.RFC3339),
			"valid_from":    base.Add(-1 * time.Hour).Format(time.RFC3339),
		},
	})
	g.AddNode(&graph.Node{ID: "svc:payments", Kind: graph.NodeKindApplication, Name: "Payments"})
	g.AddNode(&graph.Node{
		ID:   "customer:acme",
		Kind: graph.NodeKindCustomer,
		Name: "Acme",
		Properties: map[string]any{
			"arr":             500000.0,
			"usage_declining": true,
			"nps_score":       22,
		},
	})
	g.AddEdge(&graph.Edge{ID: "alice-role", Source: "user:alice", Target: "role:ops", Kind: graph.EdgeKindCanAssume, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "role-db", Source: "role:ops", Target: "db:prod", Kind: graph.EdgeKindCanRead, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "alias-link", Source: "identity_alias:github:alice", Target: "person:alice@example.com", Kind: graph.EdgeKindAliasOf, Effect: graph.EdgeEffectAllow, Properties: map[string]any{
		"observed_at": base.Add(-1 * time.Hour).Format(time.RFC3339),
		"valid_from":  base.Add(-1 * time.Hour).Format(time.RFC3339),
	}})
	g.AddEdge(&graph.Edge{ID: "alice-customer", Source: "person:alice@example.com", Target: "customer:acme", Kind: graph.EdgeKindInteractedWith, Effect: graph.EdgeEffectAllow, Properties: map[string]any{
		"last_seen": base.Format(time.RFC3339),
	}})
	g.AddEdge(&graph.Edge{ID: "svc-customer", Source: "svc:payments", Target: "customer:acme", Kind: graph.EdgeKindOwns, Effect: graph.EdgeEffectAllow})
	g.BuildIndex()

	application := &App{GraphSnapshots: mustPersistToolGraph(t, g)}
	tests := []struct {
		name   string
		tool   string
		args   string
		assert func(*testing.T, map[string]any)
	}{
		{
			name: "blast radius",
			tool: "cerebro.blast_radius",
			args: `{"principal_id":"user:alice","max_depth":3}`,
			assert: func(t *testing.T, payload map[string]any) {
				t.Helper()
				if payload["principal_id"] != "user:alice" {
					t.Fatalf("expected principal_id user:alice, got %#v", payload["principal_id"])
				}
				if total, ok := payload["total_count"].(float64); !ok || total < 1 {
					t.Fatalf("expected reachable nodes, got %#v", payload["total_count"])
				}
			},
		},
		{
			name: "graph query",
			tool: "cerebro.graph_query",
			args: `{"mode":"paths","node_id":"user:alice","target_id":"db:prod","k":2,"max_depth":6}`,
			assert: func(t *testing.T, payload map[string]any) {
				t.Helper()
				if payload["mode"] != "paths" {
					t.Fatalf("expected paths mode, got %#v", payload["mode"])
				}
				if count, ok := payload["count"].(float64); !ok || count < 1 {
					t.Fatalf("expected at least one path, got %#v", payload["count"])
				}
			},
		},
		{
			name: "intelligence report",
			tool: "cerebro.intelligence_report",
			args: `{"entity_id":"db:prod","include_counterfactual":false}`,
			assert: func(t *testing.T, payload map[string]any) {
				t.Helper()
				if _, ok := payload["risk_score"].(float64); !ok {
					t.Fatalf("expected risk_score, got %#v", payload["risk_score"])
				}
				if insights, ok := payload["insights"].([]any); !ok || len(insights) == 0 {
					t.Fatalf("expected insights, got %#v", payload["insights"])
				}
			},
		},
		{
			name: "graph quality report",
			tool: "cerebro.graph_quality_report",
			args: `{"history_limit":10,"stale_after_hours":24}`,
			assert: func(t *testing.T, payload map[string]any) {
				t.Helper()
				summary, ok := payload["summary"].(map[string]any)
				if !ok {
					t.Fatalf("expected summary object, got %#v", payload["summary"])
				}
				if _, ok := summary["maturity_score"].(float64); !ok {
					t.Fatalf("expected maturity_score, got %#v", summary["maturity_score"])
				}
			},
		},
		{
			name: "graph leverage report",
			tool: "cerebro.graph_leverage_report",
			args: `{"recent_window_hours":24}`,
			assert: func(t *testing.T, payload map[string]any) {
				t.Helper()
				summary, ok := payload["summary"].(map[string]any)
				if !ok {
					t.Fatalf("expected summary object, got %#v", payload["summary"])
				}
				if _, ok := summary["leverage_score"].(float64); !ok {
					t.Fatalf("expected leverage score, got %#v", summary["leverage_score"])
				}
			},
		},
		{
			name: "scenario simulate",
			tool: "simulate",
			args: `{"scenario":"customer_churn","target":"customer:acme","parameters":{"include_cascade":true,"depth":3}}`,
			assert: func(t *testing.T, payload map[string]any) {
				t.Helper()
				if payload["scenario"] != "customer_churn" {
					t.Fatalf("expected customer_churn, got %#v", payload["scenario"])
				}
				if strings.TrimSpace(stringValue(payload["recommendation"])) == "" {
					t.Fatalf("expected recommendation, got %#v", payload["recommendation"])
				}
			},
		},
		{
			name: "insight card",
			tool: "insight_card",
			args: `{"entity":"customer:acme"}`,
			assert: func(t *testing.T, payload map[string]any) {
				t.Helper()
				if payload["entity_id"] != "customer:acme" {
					t.Fatalf("expected customer:acme, got %#v", payload["entity_id"])
				}
				if _, ok := payload["risk_score"]; !ok {
					t.Fatalf("expected risk_score, got %#v", payload)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tool := findCerebroTool(application.cerebroTools(), tc.tool)
			if tool == nil {
				t.Fatalf("expected %s tool", tc.tool)
			}
			result, err := tool.Handler(context.Background(), json.RawMessage(tc.args))
			if err != nil {
				t.Fatalf("tool returned error: %v", err)
			}
			var payload map[string]any
			if err := json.Unmarshal([]byte(result), &payload); err != nil {
				t.Fatalf("decode tool payload: %v", err)
			}
			tc.assert(t, payload)
		})
	}
}

func TestCerebroAnalysisToolsSanitizeSnapshotLoadErrors(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "user:alice", Kind: graph.NodeKindUser, Name: "Alice"})
	g.AddNode(&graph.Node{ID: "bucket:prod", Kind: graph.NodeKindBucket, Name: "Prod Bucket", Risk: graph.RiskHigh})
	g.AddEdge(&graph.Edge{ID: "alice-bucket", Source: "user:alice", Target: "bucket:prod", Kind: graph.EdgeKindCanRead, Effect: graph.EdgeEffectAllow})

	basePath := filepath.Join(t.TempDir(), "graph-snapshots")
	store, err := graph.NewGraphPersistenceStore(graph.GraphPersistenceOptions{
		LocalPath:    basePath,
		MaxSnapshots: 4,
	})
	if err != nil {
		t.Fatalf("NewGraphPersistenceStore() error = %v", err)
	}
	if _, err := store.SaveGraph(g); err != nil {
		t.Fatalf("SaveGraph() error = %v", err)
	}
	matches, err := filepath.Glob(filepath.Join(basePath, "graph-*.json.gz"))
	if err != nil {
		t.Fatalf("Glob() error = %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected one snapshot artifact, got %v", matches)
	}
	if err := os.WriteFile(matches[0], []byte("not-a-valid-snapshot"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	application := &App{GraphSnapshots: store}
	tool := findCerebroTool(application.cerebroTools(), "cerebro.blast_radius")
	if tool == nil {
		t.Fatal("expected blast radius tool")
	}

	_, err = tool.Handler(context.Background(), json.RawMessage(`{"principal_id":"user:alice","max_depth":3}`))
	if err == nil {
		t.Fatal("expected snapshot load error")
	}
	if !strings.Contains(err.Error(), "security graph not initialized") {
		t.Fatalf("expected sanitized graph error, got %v", err)
	}
	if strings.Contains(err.Error(), basePath) {
		t.Fatalf("expected sanitized error without snapshot path, got %v", err)
	}
}

func TestCerebroGraphQueryPathsTool(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "user:alice", Kind: graph.NodeKindUser, Name: "Alice"})
	g.AddNode(&graph.Node{ID: "role:admin", Kind: graph.NodeKindRole, Name: "Admin Role"})
	g.AddNode(&graph.Node{ID: "db:prod", Kind: graph.NodeKindDatabase, Name: "Prod DB", Risk: graph.RiskCritical})
	g.AddEdge(&graph.Edge{ID: "alice-role", Source: "user:alice", Target: "role:admin", Kind: graph.EdgeKindCanAssume, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "role-db", Source: "role:admin", Target: "db:prod", Kind: graph.EdgeKindCanRead, Effect: graph.EdgeEffectAllow})

	application := &App{SecurityGraph: g}
	tool := findCerebroTool(application.cerebroTools(), "cerebro.graph_query")
	if tool == nil {
		t.Fatal("expected graph_query tool")
	}

	result, err := tool.Handler(context.Background(), json.RawMessage(`{"mode":"paths","node_id":"user:alice","target_id":"db:prod","k":2,"max_depth":6}`))
	if err != nil {
		t.Fatalf("tool returned error: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(result), &payload); err != nil {
		t.Fatalf("decode tool payload: %v", err)
	}
	if payload["mode"] != "paths" {
		t.Fatalf("expected paths mode, got %#v", payload["mode"])
	}
	if count, ok := payload["count"].(float64); !ok || count < 1 {
		t.Fatalf("expected at least one path, got %#v", payload["count"])
	}
}

func TestCerebroCorrelateEventsTool(t *testing.T) {
	g := graph.New()
	base := time.Date(2026, 3, 12, 10, 0, 0, 0, time.UTC)

	g.AddNode(&graph.Node{ID: "service:payments", Kind: graph.NodeKindService, Name: "Payments"})
	g.AddNode(&graph.Node{
		ID:   "pull_request:payments:42",
		Kind: graph.NodeKindPullRequest,
		Name: "payments pr",
		Properties: map[string]any{
			"repository":  "payments",
			"number":      "42",
			"state":       "merged",
			"observed_at": base.Format(time.RFC3339),
			"valid_from":  base.Format(time.RFC3339),
		},
	})
	g.AddNode(&graph.Node{
		ID:   "deployment:payments:deploy-1",
		Kind: graph.NodeKindDeploymentRun,
		Name: "deploy-1",
		Properties: map[string]any{
			"deploy_id":   "deploy-1",
			"service_id":  "payments",
			"environment": "prod",
			"status":      "succeeded",
			"observed_at": base.Add(5 * time.Minute).Format(time.RFC3339),
			"valid_from":  base.Add(5 * time.Minute).Format(time.RFC3339),
		},
	})
	g.AddNode(&graph.Node{
		ID:   "incident:inc-1",
		Kind: graph.NodeKindIncident,
		Name: "inc-1",
		Properties: map[string]any{
			"incident_id": "inc-1",
			"status":      "open",
			"severity":    "high",
			"service_id":  "payments",
			"observed_at": base.Add(7 * time.Minute).Format(time.RFC3339),
			"valid_from":  base.Add(7 * time.Minute).Format(time.RFC3339),
		},
	})
	g.AddEdge(&graph.Edge{ID: "pr->service", Source: "pull_request:payments:42", Target: "service:payments", Kind: graph.EdgeKindTargets, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "deploy->service", Source: "deployment:payments:deploy-1", Target: "service:payments", Kind: graph.EdgeKindTargets, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "incident->service", Source: "incident:inc-1", Target: "service:payments", Kind: graph.EdgeKindTargets, Effect: graph.EdgeEffectAllow})
	graph.MaterializeEventCorrelations(g, base.Add(10*time.Minute))

	application := &App{SecurityGraph: g}
	tool := findCerebroTool(application.cerebroTools(), "cerebro.correlate_events")
	if tool == nil {
		t.Fatal("expected correlate_events tool")
	}

	result, err := tool.Handler(context.Background(), json.RawMessage(`{"event_id":"incident:inc-1","limit":10}`))
	if err != nil {
		t.Fatalf("tool returned error: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(result), &payload); err != nil {
		t.Fatalf("decode tool payload: %v", err)
	}
	summary, ok := payload["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary object, got %#v", payload["summary"])
	}
	if got, ok := summary["correlation_count"].(float64); !ok || int(got) != 2 {
		t.Fatalf("expected 2 correlations, got %#v", payload)
	}

	if _, err := tool.Handler(context.Background(), json.RawMessage(`{"pattern_id":"pr_deploy_chain"}`)); err == nil {
		t.Fatal("expected scope validation error for correlate_events without event_id or entity_id")
	}
}

func TestCerebroIntelligenceReportTool(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "user:alice", Kind: graph.NodeKindUser, Name: "Alice"})
	g.AddNode(&graph.Node{ID: "role:ops", Kind: graph.NodeKindRole, Name: "Ops"})
	g.AddNode(&graph.Node{ID: "db:prod", Kind: graph.NodeKindDatabase, Name: "Prod DB", Risk: graph.RiskCritical})
	g.AddEdge(&graph.Edge{ID: "alice-role", Source: "user:alice", Target: "role:ops", Kind: graph.EdgeKindCanAssume, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "role-db", Source: "role:ops", Target: "db:prod", Kind: graph.EdgeKindCanRead, Effect: graph.EdgeEffectAllow})

	application := &App{SecurityGraph: g}
	tool := findCerebroTool(application.cerebroTools(), "cerebro.intelligence_report")
	if tool == nil {
		t.Fatal("expected intelligence report tool")
	}

	result, err := tool.Handler(context.Background(), json.RawMessage(`{"entity_id":"db:prod","include_counterfactual":false}`))
	if err != nil {
		t.Fatalf("tool returned error: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(result), &payload); err != nil {
		t.Fatalf("decode tool payload: %v", err)
	}
	if _, ok := payload["risk_score"].(float64); !ok {
		t.Fatalf("expected risk_score, got %#v", payload["risk_score"])
	}
	insights, ok := payload["insights"].([]any)
	if !ok || len(insights) == 0 {
		t.Fatalf("expected insights, got %#v", payload["insights"])
	}
}

func TestCerebroGraphQualityReportTool(t *testing.T) {
	g := graph.New()
	now := time.Date(2026, 3, 9, 16, 0, 0, 0, time.UTC)
	g.AddNode(&graph.Node{
		ID:   "person:alice@example.com",
		Kind: graph.NodeKindPerson,
		Name: "Alice",
		Properties: map[string]any{
			"email":       "alice@example.com",
			"observed_at": now.Add(-1 * time.Hour).Format(time.RFC3339),
			"valid_from":  now.Add(-1 * time.Hour).Format(time.RFC3339),
		},
	})
	g.AddNode(&graph.Node{
		ID:   "identity_alias:github:alice",
		Kind: graph.NodeKindIdentityAlias,
		Name: "alice",
		Properties: map[string]any{
			"source_system": "github",
			"external_id":   "alice",
			"observed_at":   now.Add(-1 * time.Hour).Format(time.RFC3339),
			"valid_from":    now.Add(-1 * time.Hour).Format(time.RFC3339),
		},
	})
	g.AddEdge(&graph.Edge{ID: "alias-link", Source: "identity_alias:github:alice", Target: "person:alice@example.com", Kind: graph.EdgeKindAliasOf, Effect: graph.EdgeEffectAllow, Properties: map[string]any{
		"observed_at": now.Add(-1 * time.Hour).Format(time.RFC3339),
		"valid_from":  now.Add(-1 * time.Hour).Format(time.RFC3339),
	}})

	application := &App{SecurityGraph: g}
	tool := findCerebroTool(application.cerebroTools(), "cerebro.graph_quality_report")
	if tool == nil {
		t.Fatal("expected graph quality report tool")
	}

	result, err := tool.Handler(context.Background(), json.RawMessage(`{"history_limit":10,"stale_after_hours":24}`))
	if err != nil {
		t.Fatalf("tool returned error: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(result), &payload); err != nil {
		t.Fatalf("decode tool payload: %v", err)
	}
	summary, ok := payload["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary object, got %#v", payload["summary"])
	}
	if _, ok := summary["maturity_score"].(float64); !ok {
		t.Fatalf("expected maturity_score, got %#v", summary["maturity_score"])
	}
	temporal, ok := payload["temporal"].(map[string]any)
	if !ok {
		t.Fatalf("expected temporal object, got %#v", payload["temporal"])
	}
	if hours, ok := temporal["stale_after_hours"].(float64); !ok || int(hours) != 24 {
		t.Fatalf("expected stale_after_hours=24, got %#v", temporal["stale_after_hours"])
	}
}

func TestCerebroGraphQualityReportToolValidation(t *testing.T) {
	application := &App{SecurityGraph: graph.New()}
	tool := findCerebroTool(application.cerebroTools(), "cerebro.graph_quality_report")
	if tool == nil {
		t.Fatal("expected graph quality report tool")
	}

	if _, err := tool.Handler(context.Background(), json.RawMessage(`{"since_version":-1}`)); err == nil {
		t.Fatal("expected since_version validation error")
	}
}

func TestCerebroGraphLeverageAndQueryTemplateTools(t *testing.T) {
	g := graph.New()
	now := time.Date(2026, 3, 9, 17, 0, 0, 0, time.UTC)
	g.AddNode(&graph.Node{
		ID:   "person:alice@example.com",
		Kind: graph.NodeKindPerson,
		Name: "Alice",
		Properties: map[string]any{
			"email":         "alice@example.com",
			"source_system": "github",
			"observed_at":   now.Add(-1 * time.Hour).Format(time.RFC3339),
			"valid_from":    now.Add(-1 * time.Hour).Format(time.RFC3339),
		},
	})
	g.AddNode(&graph.Node{
		ID:   "identity_alias:github:alice",
		Kind: graph.NodeKindIdentityAlias,
		Name: "alice",
		Properties: map[string]any{
			"source_system": "github",
			"external_id":   "alice",
			"email":         "alice@example.com",
			"observed_at":   now.Add(-1 * time.Hour).Format(time.RFC3339),
			"valid_from":    now.Add(-1 * time.Hour).Format(time.RFC3339),
		},
	})
	g.AddEdge(&graph.Edge{ID: "alias-link", Source: "identity_alias:github:alice", Target: "person:alice@example.com", Kind: graph.EdgeKindAliasOf, Effect: graph.EdgeEffectAllow, Properties: map[string]any{
		"observed_at": now.Add(-1 * time.Hour).Format(time.RFC3339),
		"valid_from":  now.Add(-1 * time.Hour).Format(time.RFC3339),
	}})

	application := &App{SecurityGraph: g}

	leverageTool := findCerebroTool(application.cerebroTools(), "cerebro.graph_leverage_report")
	if leverageTool == nil {
		t.Fatal("expected graph leverage report tool")
	}
	leverageResult, err := leverageTool.Handler(context.Background(), json.RawMessage(`{"recent_window_hours":24}`))
	if err != nil {
		t.Fatalf("graph leverage tool returned error: %v", err)
	}
	var leveragePayload map[string]any
	if err := json.Unmarshal([]byte(leverageResult), &leveragePayload); err != nil {
		t.Fatalf("decode leverage payload: %v", err)
	}
	summary, ok := leveragePayload["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary object, got %#v", leveragePayload["summary"])
	}
	if _, ok := summary["leverage_score"].(float64); !ok {
		t.Fatalf("expected leverage score, got %#v", summary["leverage_score"])
	}

	templatesTool := findCerebroTool(application.cerebroTools(), "cerebro.graph_query_templates")
	if templatesTool == nil {
		t.Fatal("expected graph query templates tool")
	}
	templatesResult, err := templatesTool.Handler(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("graph query templates tool returned error: %v", err)
	}
	var templatesPayload map[string]any
	if err := json.Unmarshal([]byte(templatesResult), &templatesPayload); err != nil {
		t.Fatalf("decode templates payload: %v", err)
	}
	if count, ok := templatesPayload["count"].(float64); !ok || count < 1 {
		t.Fatalf("expected template count >0, got %#v", templatesPayload["count"])
	}
}

func TestCerebroIdentityReviewCalibrationAndActuationTools(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:   "person:alice@example.com",
		Kind: graph.NodeKindPerson,
		Name: "Alice",
		Properties: map[string]any{
			"email": "alice@example.com",
		},
	})
	g.AddNode(&graph.Node{
		ID:   "identity_alias:github:alice",
		Kind: graph.NodeKindIdentityAlias,
		Name: "alice",
		Properties: map[string]any{
			"source_system": "github",
			"external_id":   "alice",
			"email":         "alice@example.com",
			"observed_at":   "2026-03-09T00:00:00Z",
			"valid_from":    "2026-03-09T00:00:00Z",
		},
	})
	g.AddNode(&graph.Node{
		ID:   "service:payments",
		Kind: graph.NodeKindService,
		Name: "Payments",
		Properties: map[string]any{
			"service_id": "payments",
		},
	})
	g.AddNode(&graph.Node{
		ID:   "decision:rollback",
		Kind: graph.NodeKindDecision,
		Name: "Rollback",
		Properties: map[string]any{
			"decision_type": "rollback",
		},
	})

	application := &App{SecurityGraph: g}

	reviewTool := findCerebroTool(application.cerebroTools(), "cerebro.identity_review")
	if reviewTool == nil {
		t.Fatal("expected identity review tool")
	}
	reviewResult, err := reviewTool.Handler(context.Background(), json.RawMessage(`{
		"alias_node_id":"identity_alias:github:alice",
		"canonical_node_id":"person:alice@example.com",
		"verdict":"accepted",
		"reviewer":"analyst@company.com",
		"reason":"exact email"
	}`))
	if err != nil {
		t.Fatalf("identity_review returned error: %v", err)
	}
	var reviewPayload map[string]any
	if err := json.Unmarshal([]byte(reviewResult), &reviewPayload); err != nil {
		t.Fatalf("decode review payload: %v", err)
	}
	if verdict, _ := reviewPayload["verdict"].(string); verdict != "accepted" {
		t.Fatalf("expected accepted verdict, got %#v", reviewPayload["verdict"])
	}

	calibrationTool := findCerebroTool(application.cerebroTools(), "cerebro.identity_calibration")
	if calibrationTool == nil {
		t.Fatal("expected identity calibration tool")
	}
	calibrationResult, err := calibrationTool.Handler(context.Background(), json.RawMessage(`{"include_queue":true}`))
	if err != nil {
		t.Fatalf("identity_calibration returned error: %v", err)
	}
	var calibrationPayload map[string]any
	if err := json.Unmarshal([]byte(calibrationResult), &calibrationPayload); err != nil {
		t.Fatalf("decode calibration payload: %v", err)
	}
	if reviewed, ok := calibrationPayload["reviewed_aliases"].(float64); !ok || reviewed < 1 {
		t.Fatalf("expected reviewed_aliases >=1, got %#v", calibrationPayload["reviewed_aliases"])
	}

	actuationTool := findCerebroTool(application.cerebroTools(), "cerebro.actuate_recommendation")
	if actuationTool == nil {
		t.Fatal("expected actuate recommendation tool")
	}
	actuationResult, err := actuationTool.Handler(context.Background(), json.RawMessage(`{
		"recommendation_id":"rec-1",
		"insight_type":"graph_freshness",
		"title":"Increase scanner cadence",
		"decision_id":"decision:rollback",
		"target_ids":["service:payments"],
		"source_system":"conductor"
	}`))
	if err != nil {
		t.Fatalf("actuate_recommendation returned error: %v", err)
	}
	var actuationPayload map[string]any
	if err := json.Unmarshal([]byte(actuationResult), &actuationPayload); err != nil {
		t.Fatalf("decode actuation payload: %v", err)
	}
	actionID, _ := actuationPayload["action_id"].(string)
	if actionID == "" {
		t.Fatalf("expected action_id, got %#v", actuationPayload)
	}
	if node, ok := application.CurrentSecurityGraph().GetNode(actionID); !ok || node == nil || node.Kind != graph.NodeKindAction {
		t.Fatalf("expected action node to exist, got %#v", node)
	}
}

func TestCerebroGraphWritebackTools(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:   "service:payments",
		Kind: graph.NodeKindService,
		Name: "Payments",
		Properties: map[string]any{
			"service_id":  "payments",
			"observed_at": "2026-03-08T00:00:00Z",
			"valid_from":  "2026-03-08T00:00:00Z",
		},
	})
	g.AddNode(&graph.Node{
		ID:   "person:alice@example.com",
		Kind: graph.NodeKindPerson,
		Name: "Alice",
		Properties: map[string]any{
			"email": "alice@example.com",
		},
	})
	g.AddNode(&graph.Node{
		ID:   "action:rollback",
		Kind: graph.NodeKindAction,
		Name: "Rollback",
		Properties: map[string]any{
			"action_type": "rollback",
			"status":      "pending",
			"observed_at": "2026-03-08T00:00:00Z",
			"valid_from":  "2026-03-08T00:00:00Z",
		},
	})

	application := &App{SecurityGraph: g}

	recordObservation := findCerebroTool(application.cerebroTools(), "cerebro.record_observation")
	if recordObservation == nil {
		t.Fatal("expected cerebro.record_observation tool")
	}
	observationPayload, err := recordObservation.Handler(context.Background(), json.RawMessage(`{
		"entity_id":"service:payments",
		"observation":"deploy_risk_increase",
		"summary":"Error rate increased after deploy"
	}`))
	if err != nil {
		t.Fatalf("record_observation returned error: %v", err)
	}
	var observationBody map[string]any
	if err := json.Unmarshal([]byte(observationPayload), &observationBody); err != nil {
		t.Fatalf("decode observation payload: %v", err)
	}
	observationID, _ := observationBody["observation_id"].(string)
	if observationID == "" {
		t.Fatalf("expected observation_id, got %#v", observationBody)
	}
	observationNode, ok := application.CurrentSecurityGraph().GetNode(observationID)
	if !ok || observationNode == nil {
		t.Fatalf("expected observation node %q", observationID)
	}
	if observationNode.Kind != graph.NodeKindObservation {
		t.Fatalf("expected observation node, got %q", observationNode.Kind)
	}
	if got, ok := observationNode.PropertyValue("source_system"); !ok || stringValue(got) != "agent" {
		t.Fatalf("expected default source_system=agent, got %#v ok=%t", got, ok)
	}

	annotateEntity := findCerebroTool(application.cerebroTools(), "cerebro.annotate_entity")
	if annotateEntity == nil {
		t.Fatal("expected cerebro.annotate_entity tool")
	}
	if _, err := annotateEntity.Handler(context.Background(), json.RawMessage(`{
		"entity_id":"service:payments",
		"annotation":"Rollback candidate if p95 latency increases",
		"tags":["incident","latency","incident"],
		"source_system":"analyst"
	}`)); err != nil {
		t.Fatalf("annotate_entity returned error: %v", err)
	}
	serviceNode, _ := application.CurrentSecurityGraph().GetNode("service:payments")
	if serviceNode == nil {
		t.Fatal("expected service node")
	}
	annotations, ok := serviceNode.Properties["annotations"].([]map[string]any)
	if !ok {
		if raw, rawOK := serviceNode.Properties["annotations"].([]any); !rawOK || len(raw) == 0 {
			t.Fatalf("expected annotations, got %#v", serviceNode.Properties["annotations"])
		}
	}
	if ok && len(annotations) == 0 {
		t.Fatalf("expected annotations, got %#v", annotations)
	}

	recordDecision := findCerebroTool(application.cerebroTools(), "cerebro.record_decision")
	if recordDecision == nil {
		t.Fatal("expected cerebro.record_decision tool")
	}
	decisionPayload, err := recordDecision.Handler(context.Background(), json.RawMessage(fmt.Sprintf(`{
		"decision_type":"rollback",
		"status":"approved",
		"made_by":"person:alice@example.com",
		"rationale":"error budget burn exceeded threshold",
		"target_ids":["service:payments"],
		"evidence_ids":["%s"],
		"action_ids":["action:rollback"]
	}`, observationID)))
	if err != nil {
		t.Fatalf("record_decision returned error: %v", err)
	}
	var decisionBody map[string]any
	if err := json.Unmarshal([]byte(decisionPayload), &decisionBody); err != nil {
		t.Fatalf("decode decision payload: %v", err)
	}
	decisionID, _ := decisionBody["decision_id"].(string)
	if decisionID == "" {
		t.Fatalf("expected decision_id, got %#v", decisionBody)
	}
	if decisionNode, ok := application.CurrentSecurityGraph().GetNode(decisionID); !ok || decisionNode == nil {
		t.Fatalf("expected decision node %q", decisionID)
	}

	recordOutcome := findCerebroTool(application.cerebroTools(), "cerebro.record_outcome")
	if recordOutcome == nil {
		t.Fatal("expected cerebro.record_outcome tool")
	}
	outcomePayload, err := recordOutcome.Handler(context.Background(), json.RawMessage(fmt.Sprintf(`{
		"decision_id":"%s",
		"outcome_type":"deployment_result",
		"verdict":"positive",
		"impact_score":0.72,
		"target_ids":["service:payments"]
	}`, decisionID)))
	if err != nil {
		t.Fatalf("record_outcome returned error: %v", err)
	}
	var outcomeBody map[string]any
	if err := json.Unmarshal([]byte(outcomePayload), &outcomeBody); err != nil {
		t.Fatalf("decode outcome payload: %v", err)
	}
	outcomeID, _ := outcomeBody["outcome_id"].(string)
	if outcomeID == "" {
		t.Fatalf("expected outcome_id, got %#v", outcomeBody)
	}
	if outcomeNode, ok := application.CurrentSecurityGraph().GetNode(outcomeID); !ok || outcomeNode == nil || outcomeNode.Kind != graph.NodeKindOutcome {
		t.Fatalf("expected outcome node %q, got %#v", outcomeID, outcomeNode)
	}

	resolveIdentity := findCerebroTool(application.cerebroTools(), "cerebro.resolve_identity")
	if resolveIdentity == nil {
		t.Fatal("expected cerebro.resolve_identity tool")
	}
	resolvePayload, err := resolveIdentity.Handler(context.Background(), json.RawMessage(`{
		"source_system":"github",
		"external_id":"alice-handle",
		"email":"alice@example.com",
		"name":"Alice"
	}`))
	if err != nil {
		t.Fatalf("resolve_identity returned error: %v", err)
	}
	var resolveBody map[string]any
	if err := json.Unmarshal([]byte(resolvePayload), &resolveBody); err != nil {
		t.Fatalf("decode resolve payload: %v", err)
	}
	aliasID, _ := resolveBody["alias_node_id"].(string)
	if aliasID == "" {
		t.Fatalf("expected alias_node_id, got %#v", resolveBody)
	}
	if aliasNode, ok := application.CurrentSecurityGraph().GetNode(aliasID); !ok || aliasNode == nil || aliasNode.Kind != graph.NodeKindIdentityAlias {
		t.Fatalf("expected identity_alias node %q, got %#v", aliasID, aliasNode)
	}

	splitIdentity := findCerebroTool(application.cerebroTools(), "cerebro.split_identity")
	if splitIdentity == nil {
		t.Fatal("expected cerebro.split_identity tool")
	}
	splitPayload, err := splitIdentity.Handler(context.Background(), json.RawMessage(fmt.Sprintf(`{
		"alias_node_id":"%s",
		"canonical_node_id":"person:alice@example.com",
		"reason":"manual correction"
	}`, aliasID)))
	if err != nil {
		t.Fatalf("split_identity returned error: %v", err)
	}
	var splitBody map[string]any
	if err := json.Unmarshal([]byte(splitPayload), &splitBody); err != nil {
		t.Fatalf("decode split payload: %v", err)
	}
	if removed, ok := splitBody["removed"].(bool); !ok || !removed {
		t.Fatalf("expected removed=true, got %#v", splitBody)
	}
}

func TestCerebroGraphWritebackToolsValidation(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:   "service:payments",
		Kind: graph.NodeKindService,
		Name: "Payments",
		Properties: map[string]any{
			"service_id":  "payments",
			"observed_at": "2026-03-08T00:00:00Z",
			"valid_from":  "2026-03-08T00:00:00Z",
		},
	})
	application := &App{SecurityGraph: g}

	recordObservation := findCerebroTool(application.cerebroTools(), "cerebro.record_observation")
	if recordObservation == nil {
		t.Fatal("expected cerebro.record_observation tool")
	}
	if _, err := recordObservation.Handler(context.Background(), json.RawMessage(`{"observation":"x"}`)); err == nil {
		t.Fatal("expected entity_id validation error")
	}

	recordDecision := findCerebroTool(application.cerebroTools(), "cerebro.record_decision")
	if recordDecision == nil {
		t.Fatal("expected cerebro.record_decision tool")
	}
	if _, err := recordDecision.Handler(context.Background(), json.RawMessage(`{"decision_type":"rollback","target_ids":["service:missing"]}`)); err == nil {
		t.Fatal("expected target not found error")
	}

	recordOutcome := findCerebroTool(application.cerebroTools(), "cerebro.record_outcome")
	if recordOutcome == nil {
		t.Fatal("expected cerebro.record_outcome tool")
	}
	if _, err := recordOutcome.Handler(context.Background(), json.RawMessage(`{"decision_id":"decision:missing","outcome_type":"result","verdict":"positive"}`)); err == nil {
		t.Fatal("expected decision not found error")
	}

	resolveIdentity := findCerebroTool(application.cerebroTools(), "cerebro.resolve_identity")
	if resolveIdentity == nil {
		t.Fatal("expected cerebro.resolve_identity tool")
	}
	if _, err := resolveIdentity.Handler(context.Background(), json.RawMessage(`{"external_id":"alice-handle"}`)); err == nil {
		t.Fatal("expected source_system validation error")
	}

	splitIdentity := findCerebroTool(application.cerebroTools(), "cerebro.split_identity")
	if splitIdentity == nil {
		t.Fatal("expected cerebro.split_identity tool")
	}
	if _, err := splitIdentity.Handler(context.Background(), json.RawMessage(`{"alias_node_id":"alias:github:alice"}`)); err == nil {
		t.Fatal("expected canonical_node_id validation error")
	}
}

func TestAgentSDKToolsExportMatchesCuratedTools(t *testing.T) {
	application := &App{Config: &Config{}}

	curated := application.cerebroTools()
	exported := application.AgentSDKTools()
	if len(curated) != len(exported) {
		t.Fatalf("expected AgentSDKTools to expose the curated catalog, got %d tools vs %d", len(exported), len(curated))
	}
}

func TestCerebroEvaluatePolicyTool(t *testing.T) {
	pe := policy.NewEngine()
	pe.AddPolicy(&policy.Policy{
		ID:          "policy.refund.approval",
		Name:        "Refund approval required",
		Effect:      "forbid",
		Action:      "refund.create",
		Resource:    "business::refund",
		Description: "Refunds must pass approval policy",
		Severity:    "high",
	})

	application := &App{Policy: pe, SecurityGraph: graph.New()}
	tool := findCerebroTool(application.AgentSDKTools(), "evaluate_policy")
	if tool == nil {
		t.Fatal("expected evaluate_policy tool")
	}

	result, err := tool.Handler(context.Background(), json.RawMessage(`{
		"principal": {"id":"agent:sales-assistant"},
		"action":"refund.create",
		"resource":{"type":"refund","id":"refund:123"},
		"context":{"amount":6500}
	}`))
	if err != nil {
		t.Fatalf("evaluate_policy returned error: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(result), &payload); err != nil {
		t.Fatalf("decode tool payload: %v", err)
	}
	if payload["decision"] != "deny" {
		t.Fatalf("expected deny decision, got %#v", payload["decision"])
	}
	if _, ok := payload["request_id"].(string); !ok {
		t.Fatalf("expected request_id, got %#v", payload["request_id"])
	}
	if _, ok := payload["matched_policies"].([]any); !ok {
		t.Fatalf("expected matched_policies array, got %#v", payload["matched_policies"])
	}
}

func TestCerebroEvaluatePolicyToolUsesPersistedSnapshotWhenLiveGraphUnavailable(t *testing.T) {
	store, err := graph.NewGraphPersistenceStore(graph.GraphPersistenceOptions{
		LocalPath:    filepath.Join(t.TempDir(), "graph-snapshots"),
		MaxSnapshots: 4,
	})
	if err != nil {
		t.Fatalf("NewGraphPersistenceStore() error = %v", err)
	}
	if _, err := store.SaveGraph(graph.New()); err != nil {
		t.Fatalf("SaveGraph() error = %v", err)
	}

	application := &App{
		Policy:         policy.NewEngine(),
		GraphSnapshots: store,
	}
	tool := findCerebroTool(application.AgentSDKTools(), "evaluate_policy")
	if tool == nil {
		t.Fatal("expected evaluate_policy tool")
	}

	result, err := tool.Handler(context.Background(), json.RawMessage(`{
		"principal": {"id":"agent:sales-assistant"},
		"action":"refund.create",
		"resource":{"type":"refund","id":"refund:123"},
		"proposed_change":{
			"id":"chg-1",
			"source":"tool",
			"reason":"test snapshot fallback",
			"nodes":[{"action":"add","node":{"id":"service:payments","kind":"service","name":"payments"}}]
		}
	}`))
	if err != nil {
		t.Fatalf("evaluate_policy returned error: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(result), &payload); err != nil {
		t.Fatalf("decode tool payload: %v", err)
	}
	if payload["decision"] != "allow" {
		t.Fatalf("expected allow decision, got %#v", payload["decision"])
	}
	if _, ok := payload["propagation"].(map[string]any); !ok {
		t.Fatalf("expected propagation payload, got %#v", payload["propagation"])
	}
}

func TestCerebroEvaluatePolicyToolRequiresGraphSourceForProposedChange(t *testing.T) {
	application := &App{Policy: policy.NewEngine()}
	tool := findCerebroTool(application.AgentSDKTools(), "evaluate_policy")
	if tool == nil {
		t.Fatal("expected evaluate_policy tool")
	}

	_, err := tool.Handler(context.Background(), json.RawMessage(`{
		"principal": {"id":"agent:sales-assistant"},
		"action":"refund.create",
		"resource":{"type":"refund","id":"refund:123"},
		"proposed_change":{
			"id":"chg-1",
			"source":"tool",
			"reason":"test missing graph",
			"nodes":[{"action":"add","node":{"id":"service:payments","kind":"service","name":"payments"}}]
		}
	}`))
	if err == nil || !strings.Contains(err.Error(), "graph platform not initialized") {
		t.Fatalf("expected missing graph error, got %v", err)
	}
}

func TestCerebroEvaluatePolicyToolSanitizesSnapshotLoadErrors(t *testing.T) {
	basePath := filepath.Join(t.TempDir(), "graph-snapshots")
	store, err := graph.NewGraphPersistenceStore(graph.GraphPersistenceOptions{
		LocalPath:    basePath,
		MaxSnapshots: 4,
	})
	if err != nil {
		t.Fatalf("NewGraphPersistenceStore() error = %v", err)
	}
	if _, err := store.SaveGraph(graph.New()); err != nil {
		t.Fatalf("SaveGraph() error = %v", err)
	}
	matches, err := filepath.Glob(filepath.Join(basePath, "graph-*.json.gz"))
	if err != nil {
		t.Fatalf("Glob() error = %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected one snapshot artifact, got %v", matches)
	}
	if err := os.WriteFile(matches[0], []byte("not-a-gzip-snapshot"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	application := &App{
		Policy:         policy.NewEngine(),
		GraphSnapshots: store,
	}
	tool := findCerebroTool(application.AgentSDKTools(), "evaluate_policy")
	if tool == nil {
		t.Fatal("expected evaluate_policy tool")
	}

	_, err = tool.Handler(context.Background(), json.RawMessage(`{
		"principal": {"id":"agent:sales-assistant"},
		"action":"refund.create",
		"resource":{"type":"refund","id":"refund:123"},
		"proposed_change":{
			"id":"chg-1",
			"source":"tool",
			"reason":"test snapshot load failure",
			"nodes":[{"action":"add","node":{"id":"service:payments","kind":"service","name":"payments"}}]
		}
	}`))
	if err == nil {
		t.Fatal("expected snapshot load error")
	}
	if !strings.Contains(err.Error(), "graph platform not initialized") {
		t.Fatalf("expected sanitized graph error, got %v", err)
	}
	if strings.Contains(err.Error(), basePath) {
		t.Fatalf("expected sanitized error without filesystem path, got %v", err)
	}
}

func TestCerebroWriteClaimTool(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "customer:acme", Kind: graph.NodeKindCustomer, Name: "Acme"})
	g.AddNode(&graph.Node{ID: "evidence:signal", Kind: graph.NodeKindEvidence, Name: "Signal"})

	if _, err := graph.WriteClaim(g, graph.ClaimWriteRequest{
		SubjectID:    "customer:acme",
		Predicate:    "churning",
		ObjectValue:  "false",
		SourceSystem: "existing",
		ObservedAt:   time.Date(2026, 3, 9, 12, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("seed conflicting claim: %v", err)
	}

	application := &App{SecurityGraph: g}
	tool := findCerebroTool(application.AgentSDKTools(), "cerebro.write_claim")
	if tool == nil {
		t.Fatal("expected cerebro.write_claim tool")
	}

	result, err := tool.Handler(context.Background(), json.RawMessage(`{
		"subject_id":"customer:acme",
		"predicate":"churning",
		"object_value":"true",
		"status":"asserted",
		"evidence_ids":["evidence:signal"],
		"source_system":"agent"
	}`))
	if err != nil {
		t.Fatalf("write_claim returned error: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(result), &payload); err != nil {
		t.Fatalf("decode tool payload: %v", err)
	}
	if _, ok := payload["claim_id"].(string); !ok {
		t.Fatalf("expected claim_id, got %#v", payload["claim_id"])
	}
	conflicts, ok := payload["conflicts_detected"].([]any)
	if !ok || len(conflicts) == 0 {
		t.Fatalf("expected conflicts_detected, got %#v", payload["conflicts_detected"])
	}
}

func TestCerebroExecutionStatusTool(t *testing.T) {
	dir := t.TempDir()
	store, err := executionstore.NewSQLiteStore(filepath.Join(dir, "executions.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	run := imagescan.RunRecord{
		ID:          "image_scan:test-tool",
		Registry:    imagescan.RegistryECR,
		Status:      imagescan.RunStatusRunning,
		Stage:       imagescan.RunStageAnalyze,
		Target:      imagescan.ScanTarget{Registry: imagescan.RegistryECR, Repository: "payments/app", Tag: "latest"},
		RequestedBy: "alice",
		SubmittedAt: time.Date(2026, 3, 12, 8, 0, 0, 0, time.UTC),
		UpdatedAt:   time.Date(2026, 3, 12, 8, 1, 0, 0, time.UTC),
	}
	payload, err := json.Marshal(run)
	if err != nil {
		t.Fatalf("marshal image run: %v", err)
	}
	if err := store.UpsertRun(context.Background(), executionstore.RunEnvelope{
		Namespace:   executionstore.NamespaceImageScan,
		RunID:       run.ID,
		Kind:        string(run.Registry),
		Status:      string(run.Status),
		Stage:       string(run.Stage),
		SubmittedAt: run.SubmittedAt,
		UpdatedAt:   run.UpdatedAt,
		Payload:     payload,
	}); err != nil {
		t.Fatalf("UpsertRun: %v", err)
	}

	application := &App{
		Config:         &Config{ExecutionStoreFile: filepath.Join(dir, "executions.db")},
		ExecutionStore: store,
	}
	tool := findCerebroTool(application.AgentSDKTools(), "cerebro.execution_status")
	if tool == nil {
		t.Fatal("expected cerebro.execution_status tool")
	}
	result, err := tool.Handler(context.Background(), json.RawMessage(`{"namespace":["image_scan"],"limit":5}`))
	if err != nil {
		t.Fatalf("execution_status returned error: %v", err)
	}

	var body map[string]any
	if err := json.Unmarshal([]byte(result), &body); err != nil {
		t.Fatalf("decode tool payload: %v", err)
	}
	if got := int(body["count"].(float64)); got != 1 {
		t.Fatalf("expected one execution, got %#v", body)
	}
	execs, ok := body["executions"].([]any)
	if !ok || len(execs) != 1 {
		t.Fatalf("expected executions array, got %#v", body["executions"])
	}
	entry := execs[0].(map[string]any)
	if entry["namespace"] != executionstore.NamespaceImageScan {
		t.Fatalf("expected image_scan namespace, got %#v", entry)
	}
}

func TestCerebroFindingsTool(t *testing.T) {
	store := policyBackedFindingStore(t)
	application := &App{Findings: store}
	tool := findCerebroTool(application.cerebroTools(), "cerebro.findings")
	if tool == nil {
		t.Fatal("expected findings tool")
	}

	result, err := tool.Handler(context.Background(), json.RawMessage(`{"status":"open","query":"public","limit":10}`))
	if err != nil {
		t.Fatalf("tool returned error: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(result), &payload); err != nil {
		t.Fatalf("decode tool payload: %v", err)
	}
	if count, ok := payload["count"].(float64); !ok || count != 1 {
		t.Fatalf("expected one finding, got %#v", payload["count"])
	}
}

func TestCerebroAccessReviewTool(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "user:alice", Kind: graph.NodeKindUser, Name: "Alice"})
	g.AddNode(&graph.Node{ID: "bucket:prod", Kind: graph.NodeKindBucket, Name: "Prod Bucket", Risk: graph.RiskHigh})
	g.AddEdge(&graph.Edge{ID: "alice-bucket", Source: "user:alice", Target: "bucket:prod", Kind: graph.EdgeKindCanRead, Effect: graph.EdgeEffectAllow})

	application := &App{SecurityGraph: g}
	tool := findCerebroTool(application.cerebroTools(), "cerebro.access_review")
	if tool == nil {
		t.Fatal("expected access_review tool")
	}

	result, err := tool.Handler(context.Background(), json.RawMessage(`{"identity_id":"user:alice"}`))
	if err != nil {
		t.Fatalf("tool returned error: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(result), &payload); err != nil {
		t.Fatalf("decode tool payload: %v", err)
	}
	if payload["status"] != "pending" {
		t.Fatalf("expected pending review status, got %#v", payload["status"])
	}
	if payload["created_by"] != "ensemble" {
		t.Fatalf("expected created_by ensemble, got %#v", payload["created_by"])
	}
}

func TestCerebroAutonomousCredentialResponseTool_AwaitingApproval(t *testing.T) {
	dir := t.TempDir()
	store, err := executionstore.NewSQLiteStore(filepath.Join(dir, "executions.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	application := &App{
		Config:         &Config{ExecutionStoreFile: filepath.Join(dir, "executions.db")},
		ExecutionStore: store,
		SecurityGraph:  autonomousCredentialWorkflowGraph(),
	}
	tool := findCerebroTool(application.cerebroTools(), "cerebro.autonomous_credential_response")
	if tool == nil {
		t.Fatal("expected autonomous credential response tool")
	}

	result, err := tool.Handler(context.Background(), json.RawMessage(`{
		"secret_node_id":"secret:public-repo:1",
		"require_approval":true,
		"requested_by":"analyst@example.com"
	}`))
	if err != nil {
		t.Fatalf("tool returned error: %v", err)
	}

	var body map[string]any
	if err := json.Unmarshal([]byte(result), &body); err != nil {
		t.Fatalf("decode tool payload: %v", err)
	}
	if body["status"] != string(autonomous.RunStatusAwaitingApproval) {
		t.Fatalf("expected awaiting approval status, got %#v", body["status"])
	}
	if body["stage"] != string(autonomous.RunStageAwaitingApproval) {
		t.Fatalf("expected approval stage, got %#v", body["stage"])
	}
	runID, ok := body["run_id"].(string)
	if !ok || strings.TrimSpace(runID) == "" {
		t.Fatalf("expected run_id, got %#v", body["run_id"])
	}

	runStore := autonomous.NewSQLiteRunStoreWithExecutionStore(store)
	run, err := runStore.LoadRun(context.Background(), runID)
	if err != nil {
		t.Fatalf("LoadRun: %v", err)
	}
	if run == nil {
		t.Fatal("expected persisted autonomous run")
	}
	if run.RequestedBy != "ensemble" {
		t.Fatalf("expected durable actor ensemble, got %q", run.RequestedBy)
	}
	if got := fmt.Sprintf("%v", run.Metadata["requested_by_hint"]); got != "analyst@example.com" {
		t.Fatalf("expected requested_by_hint analyst@example.com, got %#v", run.Metadata["requested_by_hint"])
	}
	if run.ActionExecutionID == "" || run.ObservationID == "" || run.DetectionClaimID == "" || run.DecisionID == "" {
		t.Fatalf("expected workflow artifacts to be persisted, got %#v", run)
	}

	actionStore := actionengine.NewSQLiteStoreWithExecutionStore(store, actionengine.DefaultNamespace)
	execution, err := actionStore.LoadExecution(context.Background(), run.ActionExecutionID)
	if err != nil {
		t.Fatalf("LoadExecution: %v", err)
	}
	if execution == nil {
		t.Fatal("expected persisted action execution")
	}
	if execution.Status != actionengine.StatusAwaitingApproval {
		t.Fatalf("expected awaiting approval action execution, got %q", execution.Status)
	}

	current := application.CurrentSecurityGraph()
	if _, ok := current.GetNode(run.ObservationID); !ok {
		t.Fatalf("expected observation node %q", run.ObservationID)
	}
	if _, ok := current.GetNode(run.DetectionClaimID); !ok {
		t.Fatalf("expected detection claim node %q", run.DetectionClaimID)
	}
	if _, ok := current.GetNode(run.DecisionID); !ok {
		t.Fatalf("expected decision node %q", run.DecisionID)
	}
}

func TestCerebroAutonomousCredentialResponseTool_IgnoresCallerApprovalPreference(t *testing.T) {
	dir := t.TempDir()
	store, err := executionstore.NewSQLiteStore(filepath.Join(dir, "executions.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	application := &App{
		Config:         &Config{ExecutionStoreFile: filepath.Join(dir, "executions.db")},
		ExecutionStore: store,
		SecurityGraph:  autonomousCredentialWorkflowGraph(),
	}
	tool := findCerebroTool(application.cerebroTools(), "cerebro.autonomous_credential_response")
	if tool == nil {
		t.Fatal("expected autonomous credential response tool")
	}

	result, err := tool.Handler(context.Background(), json.RawMessage(`{
		"secret_node_id":"secret:public-repo:1",
		"require_approval":false
	}`))
	if err != nil {
		t.Fatalf("tool returned error: %v", err)
	}

	var body map[string]any
	if err := json.Unmarshal([]byte(result), &body); err != nil {
		t.Fatalf("decode tool payload: %v", err)
	}
	if body["status"] != string(autonomous.RunStatusAwaitingApproval) {
		t.Fatalf("expected awaiting approval status, got %#v", body["status"])
	}
	if value, ok := body["require_approval"].(bool); !ok || !value {
		t.Fatalf("expected server-owned require_approval=true, got %#v", body["require_approval"])
	}
}

func TestCerebroAutonomousWorkflowApproveTool_CompletesRun(t *testing.T) {
	dir := t.TempDir()
	store, err := executionstore.NewSQLiteStore(filepath.Join(dir, "executions.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	handler := &recordingAutonomousActionHandler{}
	responseEngine := runtime.NewResponseEngine()
	responseEngine.SetActionHandler(handler)

	application := &App{
		Config:         &Config{ExecutionStoreFile: filepath.Join(dir, "executions.db")},
		ExecutionStore: store,
		SecurityGraph:  autonomousCredentialWorkflowGraph(),
		RuntimeRespond: responseEngine,
	}

	startTool := findCerebroTool(application.cerebroTools(), "cerebro.autonomous_credential_response")
	if startTool == nil {
		t.Fatal("expected autonomous credential response tool")
	}
	startResult, err := startTool.Handler(context.Background(), json.RawMessage(`{
		"secret_node_id":"secret:public-repo:1",
		"require_approval":true
	}`))
	if err != nil {
		t.Fatalf("start tool returned error: %v", err)
	}
	var startBody map[string]any
	if err := json.Unmarshal([]byte(startResult), &startBody); err != nil {
		t.Fatalf("decode start payload: %v", err)
	}
	runID, ok := startBody["run_id"].(string)
	if !ok || strings.TrimSpace(runID) == "" {
		t.Fatalf("expected run_id, got %#v", startBody["run_id"])
	}

	approveTool := findCerebroTool(application.cerebroTools(), "cerebro.autonomous_workflow_approve")
	if approveTool == nil {
		t.Fatal("expected autonomous workflow approve tool")
	}
	approveResult, err := approveTool.Handler(context.Background(), json.RawMessage(fmt.Sprintf(`{
		"run_id":%q,
		"approve":true,
		"approved_by":"manager@example.com"
	}`, runID)))
	if err != nil {
		t.Fatalf("approve tool returned error: %v", err)
	}

	var approveBody map[string]any
	if err := json.Unmarshal([]byte(approveResult), &approveBody); err != nil {
		t.Fatalf("decode approve payload: %v", err)
	}
	if approveBody["status"] != string(autonomous.RunStatusCompleted) {
		t.Fatalf("expected completed run status, got %#v", approveBody["status"])
	}
	if approveBody["stage"] != string(autonomous.RunStageClosed) {
		t.Fatalf("expected closed stage, got %#v", approveBody["stage"])
	}
	if handler.calls != 1 {
		t.Fatalf("expected one revoke call, got %d", handler.calls)
	}
	if handler.principalID != "service_account:payments-prod" {
		t.Fatalf("expected principal service_account:payments-prod, got %q", handler.principalID)
	}
	if handler.provider != "aws" {
		t.Fatalf("expected provider aws, got %q", handler.provider)
	}

	runStore := autonomous.NewSQLiteRunStoreWithExecutionStore(store)
	run, err := runStore.LoadRun(context.Background(), runID)
	if err != nil {
		t.Fatalf("LoadRun: %v", err)
	}
	if run == nil {
		t.Fatal("expected persisted autonomous run")
	}
	if run.Status != autonomous.RunStatusCompleted || run.RemediationClaimID == "" || run.OutcomeID == "" {
		t.Fatalf("expected completed workflow with remediation artifacts, got %#v", run)
	}

	actionStore := actionengine.NewSQLiteStoreWithExecutionStore(store, actionengine.DefaultNamespace)
	execution, err := actionStore.LoadExecution(context.Background(), run.ActionExecutionID)
	if err != nil {
		t.Fatalf("LoadExecution: %v", err)
	}
	if execution == nil {
		t.Fatal("expected persisted action execution")
	}
	if execution.Status != actionengine.StatusCompleted {
		t.Fatalf("expected completed action execution, got %q", execution.Status)
	}
	if execution.ApprovedBy != "ensemble" {
		t.Fatalf("expected approved_by ensemble, got %q", execution.ApprovedBy)
	}

	statusTool := findCerebroTool(application.cerebroTools(), "cerebro.autonomous_workflow_status")
	if statusTool == nil {
		t.Fatal("expected autonomous workflow status tool")
	}
	statusResult, err := statusTool.Handler(context.Background(), json.RawMessage(fmt.Sprintf(`{"run_id":%q}`, runID)))
	if err != nil {
		t.Fatalf("status tool returned error: %v", err)
	}
	var statusBody map[string]any
	if err := json.Unmarshal([]byte(statusResult), &statusBody); err != nil {
		t.Fatalf("decode status payload: %v", err)
	}
	if _, ok := statusBody["events"].([]any); !ok {
		t.Fatalf("expected workflow events, got %#v", statusBody["events"])
	}
	if _, ok := statusBody["action_events"].([]any); !ok {
		t.Fatalf("expected action events, got %#v", statusBody["action_events"])
	}

	current := application.CurrentSecurityGraph()
	if _, ok := current.GetNode(run.RemediationClaimID); !ok {
		t.Fatalf("expected remediation claim node %q", run.RemediationClaimID)
	}
	if _, ok := current.GetNode(run.OutcomeID); !ok {
		t.Fatalf("expected outcome node %q", run.OutcomeID)
	}

	_, err = approveTool.Handler(context.Background(), json.RawMessage(fmt.Sprintf(`{
		"run_id":%q,
		"approve":true,
		"approved_by":"manager@example.com"
	}`, runID)))
	if err == nil {
		t.Fatal("expected second approval attempt to fail")
	}
	if !strings.Contains(err.Error(), "not awaiting approval") {
		t.Fatalf("expected awaiting approval error, got %v", err)
	}
	if handler.calls != 1 {
		t.Fatalf("expected one revoke call after replay attempt, got %d", handler.calls)
	}
}

func TestCerebroAutonomousWorkflowApproveTool_ConcurrentApprovalClaimsOnce(t *testing.T) {
	dir := t.TempDir()
	store, err := executionstore.NewSQLiteStore(filepath.Join(dir, "executions.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	handler := &blockingAutonomousActionHandler{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	responseEngine := runtime.NewResponseEngine()
	responseEngine.SetActionHandler(handler)

	application := &App{
		Config:         &Config{ExecutionStoreFile: filepath.Join(dir, "executions.db")},
		ExecutionStore: store,
		SecurityGraph:  autonomousCredentialWorkflowGraph(),
		RuntimeRespond: responseEngine,
	}

	startTool := findCerebroTool(application.cerebroTools(), "cerebro.autonomous_credential_response")
	if startTool == nil {
		t.Fatal("expected autonomous credential response tool")
	}
	startResult, err := startTool.Handler(context.Background(), json.RawMessage(`{
		"secret_node_id":"secret:public-repo:1",
		"require_approval":true
	}`))
	if err != nil {
		t.Fatalf("start tool returned error: %v", err)
	}
	var startBody map[string]any
	if err := json.Unmarshal([]byte(startResult), &startBody); err != nil {
		t.Fatalf("decode start payload: %v", err)
	}
	runID, ok := startBody["run_id"].(string)
	if !ok || strings.TrimSpace(runID) == "" {
		t.Fatalf("expected run_id, got %#v", startBody["run_id"])
	}

	approveTool := findCerebroTool(application.cerebroTools(), "cerebro.autonomous_workflow_approve")
	if approveTool == nil {
		t.Fatal("expected autonomous workflow approve tool")
	}

	type approveResult struct {
		body string
		err  error
	}
	results := make(chan approveResult, 2)
	approveCall := func() {
		body, err := approveTool.Handler(context.Background(), json.RawMessage(fmt.Sprintf(`{
			"run_id":%q,
			"approve":true,
			"approved_by":"manager@example.com"
		}`, runID)))
		results <- approveResult{body: body, err: err}
	}

	go approveCall()
	<-handler.started
	go approveCall()

	firstResult := <-results
	if firstResult.err == nil {
		t.Fatal("expected one concurrent approval to fail before release")
	}
	if !strings.Contains(firstResult.err.Error(), "not awaiting approval") {
		t.Fatalf("expected awaiting approval error, got %v", firstResult.err)
	}

	close(handler.release)

	secondResult := <-results
	if secondResult.err != nil {
		t.Fatalf("expected claimed approval to complete, got %v", secondResult.err)
	}

	if got := handler.calls.Load(); got != 1 {
		t.Fatalf("expected exactly one revoke call, got %d", got)
	}

	var body map[string]any
	if err := json.Unmarshal([]byte(secondResult.body), &body); err != nil {
		t.Fatalf("decode approve payload: %v", err)
	}
	if body["status"] != string(autonomous.RunStatusCompleted) {
		t.Fatalf("expected completed status, got %#v", body["status"])
	}
}

func TestCerebroScenarioSimulateTool(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "user:alice", Kind: graph.NodeKindUser, Name: "Alice"})
	g.AddNode(&graph.Node{ID: "svc:payments", Kind: graph.NodeKindApplication, Name: "Payments"})
	g.AddNode(&graph.Node{ID: "customer:acme", Kind: graph.NodeKindCustomer, Name: "Acme", Properties: map[string]any{"arr": 500000.0}})
	g.AddEdge(&graph.Edge{ID: "alice-svc", Source: "user:alice", Target: "svc:payments", Kind: graph.EdgeKindCanAdmin, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "svc-customer", Source: "svc:payments", Target: "customer:acme", Kind: graph.EdgeKindOwns, Effect: graph.EdgeEffectAllow})
	g.BuildIndex()

	application := &App{SecurityGraph: g}
	tool := findCerebroTool(application.cerebroTools(), "simulate")
	if tool == nil {
		t.Fatal("expected scenario simulate tool")
	}

	result, err := tool.Handler(context.Background(), json.RawMessage(`{
		"scenario":"customer_churn",
		"target":"customer:acme",
		"parameters":{"include_cascade":true,"depth":3},
		"requester":"user@company.com",
		"context":"slack_channel:C04ABC123"
	}`))
	if err != nil {
		t.Fatalf("tool returned error: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(result), &payload); err != nil {
		t.Fatalf("decode tool payload: %v", err)
	}
	if payload["scenario"] != "customer_churn" {
		t.Fatalf("expected scenario customer_churn, got %#v", payload["scenario"])
	}
	if payload["target"] != "customer:acme" {
		t.Fatalf("expected target customer:acme, got %#v", payload["target"])
	}
	if strings.TrimSpace(stringValue(payload["recommendation"])) == "" {
		t.Fatalf("expected recommendation, got %#v", payload["recommendation"])
	}

	before, ok := payload["before"].(map[string]any)
	if !ok {
		t.Fatalf("expected before map, got %#v", payload["before"])
	}
	if _, ok := before["risk_score"]; !ok {
		t.Fatalf("expected before.risk_score, got %#v", before)
	}
	if _, ok := before["affected_entities"]; !ok {
		t.Fatalf("expected before.affected_entities, got %#v", before)
	}
}

func TestCerebroScenarioSimulateTool_UnsupportedScenario(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "customer:acme", Kind: graph.NodeKindCustomer, Name: "Acme"})

	application := &App{SecurityGraph: g}
	tool := findCerebroTool(application.cerebroTools(), "simulate")
	if tool == nil {
		t.Fatal("expected scenario simulate tool")
	}

	_, err := tool.Handler(context.Background(), json.RawMessage(`{"scenario":"unknown","target":"customer:acme"}`))
	if err == nil {
		t.Fatal("expected unsupported scenario error")
	}
}

func TestCerebroInsightCardTool(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "customer:acme", Kind: graph.NodeKindCustomer, Name: "Acme", Properties: map[string]any{
		"arr":             250000.0,
		"usage_declining": true,
		"nps_score":       22,
	}})
	g.AddNode(&graph.Node{ID: "person:alice@example.com", Kind: graph.NodeKindPerson, Name: "Alice"})
	g.AddNode(&graph.Node{ID: "app:billing", Kind: graph.NodeKindApplication, Name: "Billing"})
	g.AddEdge(&graph.Edge{ID: "alice-customer", Source: "person:alice@example.com", Target: "customer:acme", Kind: graph.EdgeKindInteractedWith, Effect: graph.EdgeEffectAllow, Properties: map[string]any{
		"last_seen": time.Now().UTC().Format(time.RFC3339),
	}})
	g.AddEdge(&graph.Edge{ID: "app-customer", Source: "app:billing", Target: "customer:acme", Kind: graph.EdgeKindOwns, Effect: graph.EdgeEffectAllow})
	g.BuildIndex()

	application := &App{SecurityGraph: g}
	tool := findCerebroTool(application.cerebroTools(), "insight_card")
	if tool == nil {
		t.Fatal("expected insight_card tool")
	}

	result, err := tool.Handler(context.Background(), json.RawMessage(`{"entity":"customer:acme"}`))
	if err != nil {
		t.Fatalf("tool returned error: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(result), &payload); err != nil {
		t.Fatalf("decode tool payload: %v", err)
	}
	if payload["entity_id"] != "customer:acme" {
		t.Fatalf("expected entity_id customer:acme, got %#v", payload["entity_id"])
	}
	if payload["card_type"] != "customer" {
		t.Fatalf("expected card_type customer, got %#v", payload["card_type"])
	}
	if _, ok := payload["risk_score"]; !ok {
		t.Fatalf("expected risk_score, got %#v", payload)
	}
	if _, ok := payload["blast_radius"]; !ok {
		t.Fatalf("expected blast_radius, got %#v", payload)
	}
	if _, ok := payload["key_relationships"]; !ok {
		t.Fatalf("expected key_relationships, got %#v", payload)
	}
	if _, ok := payload["activity"]; !ok {
		t.Fatalf("expected activity, got %#v", payload)
	}
	if _, ok := payload["recommendations"]; !ok {
		t.Fatalf("expected recommendations, got %#v", payload)
	}
}

func TestCerebroInsightCardTool_FilterSections(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "person:alice@example.com", Kind: graph.NodeKindPerson, Name: "Alice", Properties: map[string]any{
		"risk_score": 0.81,
	}})
	g.AddNode(&graph.Node{ID: "person:bob@example.com", Kind: graph.NodeKindPerson, Name: "Bob"})
	g.AddEdge(&graph.Edge{ID: "alice-bob", Source: "person:alice@example.com", Target: "person:bob@example.com", Kind: graph.EdgeKindInteractedWith, Effect: graph.EdgeEffectAllow, Properties: map[string]any{
		"last_seen": time.Now().UTC().Format(time.RFC3339),
	}})
	g.BuildIndex()

	application := &App{SecurityGraph: g}
	tool := findCerebroTool(application.cerebroTools(), "insight_card")
	if tool == nil {
		t.Fatal("expected insight_card tool")
	}

	result, err := tool.Handler(context.Background(), json.RawMessage(`{"entity":"person:alice@example.com","sections":["risk","activity"]}`))
	if err != nil {
		t.Fatalf("tool returned error: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(result), &payload); err != nil {
		t.Fatalf("decode tool payload: %v", err)
	}
	if _, ok := payload["risk_score"]; !ok {
		t.Fatalf("expected risk_score for selected section, got %#v", payload)
	}
	if _, ok := payload["activity"]; !ok {
		t.Fatalf("expected activity for selected section, got %#v", payload)
	}
	if _, ok := payload["key_relationships"]; ok {
		t.Fatalf("did not expect key_relationships when relationships section is omitted: %#v", payload)
	}
	if _, ok := payload["recommendations"]; ok {
		t.Fatalf("did not expect recommendations when recommendations section is omitted: %#v", payload)
	}
}

func TestCerebroInsightCardTool_EntityNotFound(t *testing.T) {
	application := &App{SecurityGraph: graph.New()}
	tool := findCerebroTool(application.cerebroTools(), "insight_card")
	if tool == nil {
		t.Fatal("expected insight_card tool")
	}

	_, err := tool.Handler(context.Background(), json.RawMessage(`{"entity":"customer:missing"}`))
	if err == nil {
		t.Fatal("expected not found error")
	}
}

func mustPersistToolGraph(t *testing.T, g *graph.Graph) *graph.GraphPersistenceStore {
	t.Helper()
	store, err := graph.NewGraphPersistenceStore(graph.GraphPersistenceOptions{
		LocalPath:    filepath.Join(t.TempDir(), "graph-snapshots"),
		MaxSnapshots: 4,
	})
	if err != nil {
		t.Fatalf("NewGraphPersistenceStore() error = %v", err)
	}
	if _, err := store.SaveGraph(g); err != nil {
		t.Fatalf("SaveGraph() error = %v", err)
	}
	return store
}

func findCerebroTool(tools []agents.Tool, name string) *agents.Tool {
	for i := range tools {
		if tools[i].Name == name {
			return &tools[i]
		}
	}
	return nil
}

func policyBackedFindingStore(t *testing.T) *findings.Store {
	t.Helper()
	store := findings.NewStore()
	store.Upsert(context.Background(), policy.Finding{
		ID:           "finding-1",
		PolicyID:     "policy.public.bucket",
		PolicyName:   "Public bucket policy",
		Title:        "Public bucket",
		Description:  "S3 bucket is publicly accessible",
		Severity:     "high",
		ResourceID:   "bucket:prod",
		ResourceType: "bucket",
		Resource:     map[string]any{"id": "bucket:prod"},
	})
	return store
}
