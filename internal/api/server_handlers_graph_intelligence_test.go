package api

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/events"
	"github.com/writer/cerebro/internal/graph"
	reports "github.com/writer/cerebro/internal/graph/reports"
	"github.com/writer/cerebro/internal/graphingest"
	"github.com/writer/cerebro/internal/policy"
	"github.com/writer/cerebro/internal/webhooks"
)

type stubGraphIntelligenceService struct {
	graph             *graph.Graph
	mapperInitialized bool
	mapperValidation  string
	deadLetterPath    string
	mapperStats       graphingest.MapperStats
	contractCatalog   graphingest.ContractCatalog
	hasCatalog        bool
}

func (s stubGraphIntelligenceService) CurrentGraph(context.Context) (*graph.Graph, error) {
	return s.graph, nil
}

func (s stubGraphIntelligenceService) MapperInitialized() bool {
	return s.mapperInitialized
}

func (s stubGraphIntelligenceService) MapperValidationMode() string {
	return s.mapperValidation
}

func (s stubGraphIntelligenceService) MapperDeadLetterPath() string {
	return s.deadLetterPath
}

func (s stubGraphIntelligenceService) MapperStats() graphingest.MapperStats {
	return s.mapperStats
}

func (s stubGraphIntelligenceService) MapperContractCatalog(_ time.Time) (graphingest.ContractCatalog, bool) {
	return s.contractCatalog, s.hasCatalog
}

func TestGraphIntelligenceInsightsEndpoint(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph

	g.AddNode(&graph.Node{ID: "user:alice", Kind: graph.NodeKindUser, Name: "Alice"})
	g.AddNode(&graph.Node{ID: "role:ops", Kind: graph.NodeKindRole, Name: "Ops Role"})
	g.AddNode(&graph.Node{ID: "db:prod", Kind: graph.NodeKindDatabase, Name: "Prod DB", Risk: graph.RiskCritical})
	g.AddNode(&graph.Node{ID: "node:unknown", Kind: graph.NodeKind("api_intel_unknown_kind_v1"), Name: "Unknown"})
	g.AddEdge(&graph.Edge{ID: "alice-role", Source: "user:alice", Target: "role:ops", Kind: graph.EdgeKindCanAssume, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "role-db", Source: "role:ops", Target: "db:prod", Kind: graph.EdgeKindCanRead, Effect: graph.EdgeEffectAllow})

	w := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/insights?window_days=30&include_counterfactual=false&max_insights=1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	if _, ok := body["risk_score"].(float64); !ok {
		t.Fatalf("expected risk_score, got %#v", body["risk_score"])
	}
	if _, ok := body["coverage"].(float64); !ok {
		t.Fatalf("expected coverage, got %#v", body["coverage"])
	}
	insights, ok := body["insights"].([]any)
	if !ok || len(insights) == 0 {
		t.Fatalf("expected insights, got %#v", body["insights"])
	}
	if len(insights) != 1 {
		t.Fatalf("expected max_insights=1 to limit result to one insight, got %d", len(insights))
	}
	first, ok := insights[0].(map[string]any)
	if !ok {
		t.Fatalf("expected first insight object, got %T", insights[0])
	}
	if _, ok := first["confidence"].(float64); !ok {
		t.Fatalf("expected insight confidence, got %#v", first["confidence"])
	}
	if _, ok := first["coverage"].(float64); !ok {
		t.Fatalf("expected insight coverage, got %#v", first["coverage"])
	}
	if _, ok := first["evidence"].([]any); !ok {
		t.Fatalf("expected insight evidence array, got %#v", first["evidence"])
	}
}

func TestGraphIntelligenceEventCorrelationEndpoints(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph
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

	patterns := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/event-patterns", nil)
	if patterns.Code != http.StatusOK {
		t.Fatalf("expected 200 for event-patterns, got %d: %s", patterns.Code, patterns.Body.String())
	}
	patternBody := decodeJSON(t, patterns)
	if items, ok := patternBody["patterns"].([]any); !ok || len(items) < 2 {
		t.Fatalf("expected built-in event correlation patterns, got %#v", patternBody["patterns"])
	}

	correlations := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/event-correlations?event_id=incident:inc-1&limit=10", nil)
	if correlations.Code != http.StatusOK {
		t.Fatalf("expected 200 for event-correlations, got %d: %s", correlations.Code, correlations.Body.String())
	}
	correlationBody := decodeJSON(t, correlations)
	summary, ok := correlationBody["summary"].(map[string]any)
	if !ok || int(summary["correlation_count"].(float64)) != 2 {
		t.Fatalf("expected two correlations, got %#v", correlationBody)
	}

	chains := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/event-chains?event_id=incident:inc-1&direction=upstream&max_depth=4&limit=10", nil)
	if chains.Code != http.StatusOK {
		t.Fatalf("expected 200 for event-chains, got %d: %s", chains.Code, chains.Body.String())
	}
	chainBody := decodeJSON(t, chains)
	chainSummary, ok := chainBody["summary"].(map[string]any)
	if !ok || int(chainSummary["chain_count"].(float64)) != 1 || int(chainSummary["max_depth"].(float64)) != 2 {
		t.Fatalf("expected one upstream chain with depth two, got %#v", chainBody)
	}

	anomalies := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/event-anomalies?entity_id=service:payments&limit=10", nil)
	if anomalies.Code != http.StatusOK {
		t.Fatalf("expected 200 for event-anomalies, got %d: %s", anomalies.Code, anomalies.Body.String())
	}
	if _, ok := decodeJSON(t, anomalies)["anomalies"].([]any); !ok {
		t.Fatalf("expected anomalies array, got %s", anomalies.Body.String())
	}

	unscopedCorrelations := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/event-correlations?limit=10", nil)
	if unscopedCorrelations.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unscoped event-correlations, got %d: %s", unscopedCorrelations.Code, unscopedCorrelations.Body.String())
	}

	unscopedChains := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/event-chains?limit=10", nil)
	if unscopedChains.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unscoped event-chains, got %d: %s", unscopedChains.Code, unscopedChains.Body.String())
	}

	unscopedAnomalies := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/event-anomalies?limit=10", nil)
	if unscopedAnomalies.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unscoped event-anomalies, got %d: %s", unscopedAnomalies.Code, unscopedAnomalies.Body.String())
	}
}

func TestGraphIntelligenceHandlersUseServiceInterface(t *testing.T) {
	s := newTestServer(t)
	base := time.Date(2026, 3, 12, 10, 0, 0, 0, time.UTC)

	serviceGraph := graph.New()
	serviceGraph.AddNode(&graph.Node{ID: "service:payments", Kind: graph.NodeKindService, Name: "Payments"})
	serviceGraph.AddNode(&graph.Node{
		ID:   "pull_request:payments:42",
		Kind: graph.NodeKindPullRequest,
		Properties: map[string]any{
			"repository":  "payments",
			"number":      "42",
			"state":       "merged",
			"observed_at": base.Format(time.RFC3339),
			"valid_from":  base.Format(time.RFC3339),
		},
	})
	serviceGraph.AddNode(&graph.Node{
		ID:   "deployment:payments:deploy-1",
		Kind: graph.NodeKindDeploymentRun,
		Properties: map[string]any{
			"deploy_id":   "deploy-1",
			"service_id":  "payments",
			"environment": "prod",
			"status":      "succeeded",
			"observed_at": base.Add(5 * time.Minute).Format(time.RFC3339),
			"valid_from":  base.Add(5 * time.Minute).Format(time.RFC3339),
		},
	})
	serviceGraph.AddEdge(&graph.Edge{ID: "pr->service", Source: "pull_request:payments:42", Target: "service:payments", Kind: graph.EdgeKindTargets, Effect: graph.EdgeEffectAllow})
	serviceGraph.AddEdge(&graph.Edge{ID: "deploy->service", Source: "deployment:payments:deploy-1", Target: "service:payments", Kind: graph.EdgeKindTargets, Effect: graph.EdgeEffectAllow})
	graph.MaterializeEventCorrelations(serviceGraph, base.Add(10*time.Minute))

	s.graphIntelligence = stubGraphIntelligenceService{
		graph:             serviceGraph,
		mapperInitialized: true,
		mapperValidation:  "warn",
		deadLetterPath:    "/tmp/cerebro-dead-letter.jsonl",
		mapperStats: graphingest.MapperStats{
			EventsProcessed: 17,
		},
		contractCatalog: graphingest.ContractCatalog{
			APIVersion:  "cerebro.graph.contracts/v1alpha1",
			Kind:        "CloudEventMappingContractCatalog",
			GeneratedAt: base,
		},
		hasCatalog: true,
	}
	s.app.SecurityGraph = nil
	s.app.TapEventMapper = nil
	s.app.Config.GraphEventMapperValidationMode = ""
	s.app.Config.GraphEventMapperDeadLetterPath = ""

	correlations := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/event-correlations?entity_id=service:payments&limit=10", nil)
	if correlations.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed event-correlations, got %d: %s", correlations.Code, correlations.Body.String())
	}
	body := decodeJSON(t, correlations)
	summary, ok := body["summary"].(map[string]any)
	if !ok || int(summary["correlation_count"].(float64)) == 0 {
		t.Fatalf("expected scoped correlations from service-backed graph, got %#v", body)
	}

	healthResp := do(t, s, http.MethodGet, "/api/v1/graph/ingest/health?tail_limit=10", nil)
	if healthResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed ingest health, got %d: %s", healthResp.Code, healthResp.Body.String())
	}
	healthBody := decodeJSON(t, healthResp)
	mapper, ok := healthBody["mapper"].(map[string]any)
	if !ok {
		t.Fatalf("expected mapper payload, got %#v", healthBody["mapper"])
	}
	if mapper["validation_mode"] != "warn" {
		t.Fatalf("expected stub validation mode, got %#v", mapper["validation_mode"])
	}
	if mapper["dead_letter_path"] != "/tmp/cerebro-dead-letter.jsonl" {
		t.Fatalf("expected stub dead-letter path, got %#v", mapper["dead_letter_path"])
	}

	contracts := do(t, s, http.MethodGet, "/api/v1/graph/ingest/contracts", nil)
	if contracts.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed ingest contracts, got %d: %s", contracts.Code, contracts.Body.String())
	}
	contractsBody := decodeJSON(t, contracts)
	if contractsBody["source"] != "runtime_mapper" {
		t.Fatalf("expected runtime mapper contract source, got %#v", contractsBody["source"])
	}
}

func TestGraphIntelligenceInsightsEndpoint_InvalidParams(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/insights?window_days=0", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for window_days=0, got %d", w.Code)
	}

	w = do(t, s, http.MethodGet, "/api/v1/platform/intelligence/insights?from=2026-03-01T00:00:00Z", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when from is missing to, got %d", w.Code)
	}

	w = do(t, s, http.MethodGet, "/api/v1/platform/intelligence/insights?include_counterfactual=maybe", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid include_counterfactual, got %d", w.Code)
	}

	w = do(t, s, http.MethodGet, "/api/v1/platform/intelligence/insights?max_insights=0", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for max_insights=0, got %d", w.Code)
	}
}

func TestGraphIntelligenceQualityEndpoint(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph
	now := time.Date(2026, 3, 9, 16, 0, 0, 0, time.UTC)

	g.AddNode(&graph.Node{
		ID:   "person:alice@example.com",
		Kind: graph.NodeKindPerson,
		Name: "Alice",
		Properties: map[string]any{
			"email":       "alice@example.com",
			"observed_at": now.Add(-2 * time.Hour).Format(time.RFC3339),
			"valid_from":  now.Add(-2 * time.Hour).Format(time.RFC3339),
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
	g.AddNode(&graph.Node{
		ID:   "decision:rollback",
		Kind: graph.NodeKindDecision,
		Name: "Rollback",
		Properties: map[string]any{
			"decision_type": "rollback",
			"status":        "approved",
			"observed_at":   now.Add(-2 * time.Hour).Format(time.RFC3339),
			"valid_from":    now.Add(-2 * time.Hour).Format(time.RFC3339),
		},
	})
	g.AddNode(&graph.Node{
		ID:   "outcome:rollback",
		Kind: graph.NodeKindOutcome,
		Name: "Rollback outcome",
		Properties: map[string]any{
			"outcome_type": "deployment_result",
			"verdict":      "positive",
			"observed_at":  now.Add(-1 * time.Hour).Format(time.RFC3339),
			"valid_from":   now.Add(-1 * time.Hour).Format(time.RFC3339),
		},
	})
	g.AddNode(&graph.Node{ID: "node:unknown", Kind: graph.NodeKind("api_graph_quality_unknown_kind_v1"), Name: "Unknown"})

	g.AddEdge(&graph.Edge{ID: "alias-link", Source: "identity_alias:github:alice", Target: "person:alice@example.com", Kind: graph.EdgeKindAliasOf, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "outcome-evaluates", Source: "outcome:rollback", Target: "decision:rollback", Kind: graph.EdgeKindEvaluates, Effect: graph.EdgeEffectAllow})

	w := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/quality?history_limit=10&stale_after_hours=24", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	summary, ok := body["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary object, got %#v", body["summary"])
	}
	if _, ok := summary["maturity_score"].(float64); !ok {
		t.Fatalf("expected summary.maturity_score, got %#v", summary["maturity_score"])
	}
	if nodes, ok := summary["nodes"].(float64); !ok || nodes < 1 {
		t.Fatalf("expected summary.nodes >= 1, got %#v", summary["nodes"])
	}

	temporal, ok := body["temporal"].(map[string]any)
	if !ok {
		t.Fatalf("expected temporal object, got %#v", body["temporal"])
	}
	if hours, ok := temporal["stale_after_hours"].(float64); !ok || int(hours) != 24 {
		t.Fatalf("expected stale_after_hours=24, got %#v", temporal["stale_after_hours"])
	}

	recommendations, ok := body["recommendations"].([]any)
	if !ok || len(recommendations) == 0 {
		t.Fatalf("expected recommendations, got %#v", body["recommendations"])
	}
}

func TestGraphIntelligenceQualityEndpoint_InvalidParams(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/quality?history_limit=0", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for history_limit=0, got %d", w.Code)
	}

	w = do(t, s, http.MethodGet, "/api/v1/platform/intelligence/quality?since_version=0", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for since_version=0, got %d", w.Code)
	}

	w = do(t, s, http.MethodGet, "/api/v1/platform/intelligence/quality?stale_after_hours=0", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for stale_after_hours=0, got %d", w.Code)
	}
}

func TestGraphIntelligenceAgentActionEffectivenessEndpoint(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph
	now := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)

	g.AddNode(&graph.Node{
		ID:   "thread:evaluation:run-1:conv-1",
		Kind: graph.NodeKind("communication_thread"),
		Name: "conv-1",
		Properties: map[string]any{
			"thread_id":         "conv-1",
			"channel_id":        "run-1",
			"channel_name":      "evaluation",
			"conversation_id":   "conv-1",
			"evaluation_run_id": "run-1",
			"agent_email":       "agent-a@example.com",
			"observed_at":       now.Add(-2 * time.Hour).Format(time.RFC3339),
			"valid_from":        now.Add(-2 * time.Hour).Format(time.RFC3339),
			"source_system":     "platform_eval",
		},
	})
	g.AddNode(&graph.Node{
		ID:   "action:evaluation:run-1:conv-1:call-1",
		Kind: graph.NodeKindAction,
		Name: "call-1",
		Properties: map[string]any{
			"action_type":       "tool_call",
			"status":            "succeeded",
			"performed_at":      now.Add(-2 * time.Hour).Format(time.RFC3339),
			"actor_id":          "agent-a@example.com",
			"agent_email":       "agent-a@example.com",
			"conversation_id":   "conv-1",
			"evaluation_run_id": "run-1",
			"turn_id":           "turn-1",
			"tool_call_id":      "call-1",
			"observed_at":       now.Add(-2 * time.Hour).Format(time.RFC3339),
			"valid_from":        now.Add(-2 * time.Hour).Format(time.RFC3339),
			"source_system":     "platform_eval",
		},
	})
	g.AddNode(&graph.Node{
		ID:   "observation:evaluation_cost:run-1:conv-1:cost-1",
		Kind: graph.NodeKindObservation,
		Name: "cost-1",
		Properties: map[string]any{
			"observation_type":  "evaluation_cost",
			"subject_id":        "thread:evaluation:run-1:conv-1",
			"conversation_id":   "conv-1",
			"evaluation_run_id": "run-1",
			"tool_call_id":      "call-1",
			"amount_usd":        0.25,
			"currency":          "USD",
			"observed_at":       now.Add(-2 * time.Hour).Format(time.RFC3339),
			"valid_from":        now.Add(-2 * time.Hour).Format(time.RFC3339),
			"recorded_at":       now.Add(-2 * time.Hour).Format(time.RFC3339),
			"transaction_from":  now.Add(-2 * time.Hour).Format(time.RFC3339),
			"source_system":     "platform_eval",
		},
	})
	g.AddNode(&graph.Node{
		ID:   "outcome:evaluation:run-1:conv-1",
		Kind: graph.NodeKindOutcome,
		Name: "positive",
		Properties: map[string]any{
			"outcome_type":      "evaluation_conversation",
			"verdict":           "positive",
			"quality_score":     0.94,
			"conversation_id":   "conv-1",
			"evaluation_run_id": "run-1",
			"observed_at":       now.Add(-2 * time.Hour).Format(time.RFC3339),
			"valid_from":        now.Add(-2 * time.Hour).Format(time.RFC3339),
			"source_system":     "platform_eval",
		},
	})
	g.AddEdge(&graph.Edge{ID: "outcome-target:conv-1", Source: "outcome:evaluation:run-1:conv-1", Target: "thread:evaluation:run-1:conv-1", Kind: graph.EdgeKindTargets, Effect: graph.EdgeEffectAllow})

	w := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/agent-action-effectiveness?window_days=30&trend_days=7&max_agents=10", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	summary, ok := body["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary object, got %#v", body["summary"])
	}
	if conversations, ok := summary["conversations"].(float64); !ok || int(conversations) != 1 {
		t.Fatalf("expected summary.conversations=1, got %#v", summary["conversations"])
	}
	if correctness, ok := summary["correctness_percent"].(float64); !ok || correctness <= 0 {
		t.Fatalf("expected correctness_percent > 0, got %#v", summary["correctness_percent"])
	}
	agents, ok := body["agents"].([]any)
	if !ok || len(agents) != 1 {
		t.Fatalf("expected one agent rollup, got %#v", body["agents"])
	}
	trends, ok := body["trends"].([]any)
	if !ok || len(trends) != 1 {
		t.Fatalf("expected one trend bucket, got %#v", body["trends"])
	}
}

func TestGraphIntelligenceAgentActionEffectivenessEndpointInvalidParams(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/agent-action-effectiveness?window_days=0", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for window_days=0, got %d", w.Code)
	}
	w = do(t, s, http.MethodGet, "/api/v1/platform/intelligence/agent-action-effectiveness?trend_days=0", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for trend_days=0, got %d", w.Code)
	}
	w = do(t, s, http.MethodGet, "/api/v1/platform/intelligence/agent-action-effectiveness?max_agents=0", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for max_agents=0, got %d", w.Code)
	}
}

func TestPlatformIntelligenceQualityEndpoint(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph
	now := time.Date(2026, 3, 9, 16, 0, 0, 0, time.UTC)

	g.AddNode(&graph.Node{
		ID:   "person:alice@example.com",
		Kind: graph.NodeKindPerson,
		Name: "Alice",
		Properties: map[string]any{
			"email":       "alice@example.com",
			"observed_at": now.Format(time.RFC3339),
			"valid_from":  now.Format(time.RFC3339),
		},
	})

	platformResp := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/quality?stale_after_hours=24", nil)
	if platformResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for platform intelligence quality, got %d: %s", platformResp.Code, platformResp.Body.String())
	}
	if got := platformResp.Header().Get("Deprecation"); got != "" {
		t.Fatalf("did not expect deprecation header on platform endpoint, got %q", got)
	}
}

func TestPlatformIntelligenceReportsCatalog(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/reports", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)

	if count, ok := body["count"].(float64); !ok || int(count) < 7 {
		t.Fatalf("expected at least 7 built-in reports, got %#v", body["count"])
	}
	reports, ok := body["reports"].([]any)
	if !ok || len(reports) == 0 {
		t.Fatalf("expected report definitions, got %#v", body["reports"])
	}
	first, ok := reports[0].(map[string]any)
	if !ok {
		t.Fatalf("expected first report definition object, got %#v", reports[0])
	}
	if _, ok := first["endpoint"].(map[string]any); !ok {
		t.Fatalf("expected endpoint metadata on first report, got %#v", first["endpoint"])
	}
}

func TestPlatformIntelligenceAgentActionEffectivenessReportDefinition(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/reports/agent-action-effectiveness", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)
	if got := body["id"]; got != "agent-action-effectiveness" {
		t.Fatalf("expected agent-action-effectiveness definition, got %#v", got)
	}
	endpoint, ok := body["endpoint"].(map[string]any)
	if !ok {
		t.Fatalf("expected endpoint object, got %#v", body["endpoint"])
	}
	if path, _ := endpoint["path"].(string); path != "/api/v1/platform/intelligence/agent-action-effectiveness" {
		t.Fatalf("unexpected endpoint path: %#v", endpoint["path"])
	}
}

func TestPlatformIntelligenceReportDefinition(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/reports/leverage", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)

	if got := body["id"]; got != "leverage" {
		t.Fatalf("expected leverage definition, got %#v", got)
	}
	measures, ok := body["measures"].([]any)
	if !ok || len(measures) == 0 {
		t.Fatalf("expected measures, got %#v", body["measures"])
	}
	endpoint, ok := body["endpoint"].(map[string]any)
	if !ok {
		t.Fatalf("expected endpoint object, got %#v", body["endpoint"])
	}
	if jobCapable, _ := endpoint["job_capable"].(bool); !jobCapable {
		t.Fatalf("expected leverage report to advertise job_capable, got %#v", endpoint["job_capable"])
	}
	if runPath, _ := endpoint["run_path_template"].(string); runPath == "" {
		t.Fatalf("expected run_path_template, got %#v", endpoint["run_path_template"])
	}
}

func TestGraphIntelligenceEvaluationTemporalAnalysisEndpoint(t *testing.T) {
	s := newTestServer(t)
	addEvaluationTemporalAnalysisEndpointFixture(t, s.app.SecurityGraph, evaluationTemporalAnalysisEndpointFixture{
		RunID:        "run-1",
		Conversation: "conv-1",
		ServiceID:    "service:payments:conv-1",
		BaseAt:       time.Date(2026, 3, 22, 18, 0, 0, 0, time.UTC),
	})

	w := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/evaluation-temporal-analysis?evaluation_run_id=run-1&conversation_id=conv-1&timeline_limit=10", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	if got := body["evaluation_run_id"]; got != "run-1" {
		t.Fatalf("expected evaluation_run_id=run-1, got %#v", got)
	}
	summary, ok := body["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary object, got %#v", body["summary"])
	}
	if got := summary["claims"]; got != float64(4) {
		t.Fatalf("expected 4 claims, got %#v", got)
	}
	if got := summary["contradicted_claims"]; got != float64(2) {
		t.Fatalf("expected 2 contradicted claims, got %#v", got)
	}
	diff, ok := body["diff"].(map[string]any)
	if !ok {
		t.Fatalf("expected diff object, got %#v", body["diff"])
	}
	diffSummary, ok := diff["summary"].(map[string]any)
	if !ok || diffSummary["added_claims"] != float64(2) {
		t.Fatalf("expected diff summary with added_claims=2, got %#v", diff["summary"])
	}
	conflicts, ok := body["conflicts"].(map[string]any)
	if !ok {
		t.Fatalf("expected conflicts object, got %#v", body["conflicts"])
	}
	conflictSummary, ok := conflicts["summary"].(map[string]any)
	if !ok || conflictSummary["conflict_groups"] != float64(1) {
		t.Fatalf("expected conflict group summary, got %#v", conflicts["summary"])
	}
}

func TestGraphIntelligenceEvaluationTemporalAnalysisEndpointStageFilter(t *testing.T) {
	s := newTestServer(t)
	addEvaluationTemporalAnalysisEndpointFixture(t, s.app.SecurityGraph, evaluationTemporalAnalysisEndpointFixture{
		RunID:        "run-1",
		Conversation: "conv-1",
		ServiceID:    "service:payments:conv-1",
		BaseAt:       time.Date(2026, 3, 22, 18, 0, 0, 0, time.UTC),
	})
	tagEvaluationTemporalAnalysisEndpointStageFixture(t, s.app.SecurityGraph, "run-1", "conv-1")

	w := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/evaluation-temporal-analysis?evaluation_run_id=run-1&conversation_id=conv-1&stage_id=stage-2&timeline_limit=10", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	if got := body["stage_id"]; got != "stage-2" {
		t.Fatalf("expected stage_id=stage-2, got %#v", got)
	}
	summary, ok := body["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary object, got %#v", body["summary"])
	}
	if got := summary["actions"]; got != float64(1) {
		t.Fatalf("expected 1 action, got %#v", got)
	}
	if got := summary["claims"]; got != float64(2) {
		t.Fatalf("expected 2 claims, got %#v", got)
	}
	if got := summary["contradicted_claims"]; got != float64(1) {
		t.Fatalf("expected 1 contradicted claim, got %#v", got)
	}
}

func TestGraphIntelligenceEvaluationTemporalAnalysisEndpointInvalidParams(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/evaluation-temporal-analysis", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing evaluation_run_id, got %d: %s", w.Code, w.Body.String())
	}

	w = do(t, s, http.MethodGet, "/api/v1/platform/intelligence/evaluation-temporal-analysis?evaluation_run_id=run-1&timeline_limit=0", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid timeline_limit, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPlatformIntelligenceEvaluationTemporalAnalysisReportDefinition(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/reports/evaluation-temporal-analysis", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)
	if got := body["id"]; got != "evaluation-temporal-analysis" {
		t.Fatalf("expected evaluation-temporal-analysis definition, got %#v", got)
	}
	endpoint, ok := body["endpoint"].(map[string]any)
	if !ok || endpoint["path"] != "/api/v1/platform/intelligence/evaluation-temporal-analysis" {
		t.Fatalf("unexpected endpoint metadata: %#v", body["endpoint"])
	}
	parameters, ok := body["parameters"].([]any)
	if !ok {
		t.Fatalf("expected parameters array, got %#v", body["parameters"])
	}
	var stageIDFound bool
	for _, raw := range parameters {
		param, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if param["name"] == "stage_id" {
			stageIDFound = true
			break
		}
	}
	if !stageIDFound {
		t.Fatalf("expected stage_id parameter in definition, got %#v", parameters)
	}
}

func TestGraphIntelligencePlaybookEffectivenessEndpoint(t *testing.T) {
	s := newTestServer(t)
	startedAt := time.Now().UTC().Add(-90 * time.Minute).Truncate(time.Second)
	addPlaybookEffectivenessEndpointFixture(t, s.app.SecurityGraph, playbookEffectivenessEndpointFixture{
		RunID:        "run-a1",
		PlaybookID:   "pb-remediate",
		PlaybookName: "Remediate Public Exposure",
		TenantID:     "tenant-acme",
		TargetID:     "service:payments",
		TargetKind:   graph.NodeKindService,
		StartedAt:    startedAt,
		Stages: []playbookEffectivenessEndpointStage{
			{ID: "approve", Name: "Approve Fix", Order: 1, Status: "completed", ApprovalRequired: true, ApprovalStatus: "approved", ObservedAt: startedAt.Add(10 * time.Minute)},
		},
		Outcome: &playbookEffectivenessEndpointOutcome{
			Verdict:       "positive",
			Status:        "completed",
			RollbackState: "stable",
			ObservedAt:    startedAt.Add(40 * time.Minute),
		},
	})

	w := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/playbook-effectiveness?window_days=30&playbook_id=pb-remediate&tenant_id=tenant-acme&target_kind=service&max_playbooks=10", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	summary, ok := body["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary object, got %#v", body["summary"])
	}
	if got := summary["runs"]; got != float64(1) {
		t.Fatalf("expected one run, got %#v", got)
	}
	if got := summary["successful_runs"]; got != float64(1) {
		t.Fatalf("expected one successful run, got %#v", got)
	}
	playbooks, ok := body["playbooks"].([]any)
	if !ok || len(playbooks) != 1 {
		t.Fatalf("expected one playbook rollup, got %#v", body["playbooks"])
	}
}

func TestGraphIntelligencePlaybookEffectivenessEndpointInvalidParams(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/playbook-effectiveness?window_days=0", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for window_days=0, got %d", w.Code)
	}
	w = do(t, s, http.MethodGet, "/api/v1/platform/intelligence/playbook-effectiveness?max_playbooks=0", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for max_playbooks=0, got %d", w.Code)
	}
}

func TestPlatformIntelligencePlaybookEffectivenessReportDefinition(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/reports/playbook-effectiveness", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)
	if got := body["id"]; got != "playbook-effectiveness" {
		t.Fatalf("expected playbook-effectiveness definition, got %#v", got)
	}
	endpoint, ok := body["endpoint"].(map[string]any)
	if !ok || endpoint["path"] != "/api/v1/platform/intelligence/playbook-effectiveness" {
		t.Fatalf("unexpected endpoint metadata: %#v", body["endpoint"])
	}
}

func TestGraphIntelligenceUnifiedExecutionTimelineEndpoint(t *testing.T) {
	s := newTestServer(t)
	baseAt := time.Now().UTC().Add(-24 * time.Hour).Truncate(time.Second)
	addEvaluationTemporalAnalysisEndpointFixture(t, s.app.SecurityGraph, evaluationTemporalAnalysisEndpointFixture{
		RunID:        "run-1",
		Conversation: "conv-1",
		ServiceID:    "service:payments:conv-1",
		BaseAt:       baseAt,
	})
	tagEvaluationTemporalAnalysisEndpointTenant(t, s.app.SecurityGraph, "run-1", "conv-1", "tenant-acme")

	addPlaybookEffectivenessEndpointFixture(t, s.app.SecurityGraph, playbookEffectivenessEndpointFixture{
		RunID:        "run-pb-1",
		PlaybookID:   "pb-remediate",
		PlaybookName: "Repair Database",
		TenantID:     "tenant-acme",
		TargetID:     "database:orders",
		TargetKind:   graph.NodeKind("database"),
		StartedAt:    baseAt.Add(time.Hour),
		Stages: []playbookEffectivenessEndpointStage{
			{ID: "repair", Name: "Repair", Order: 1, Status: "completed", ObservedAt: baseAt.Add(70 * time.Minute)},
		},
		Outcome: &playbookEffectivenessEndpointOutcome{
			Verdict:       "positive",
			Status:        "completed",
			RollbackState: "stable",
			ObservedAt:    baseAt.Add(90 * time.Minute),
		},
	})
	s.app.SecurityGraph.AddNode(&graph.Node{
		ID:   "action:playbook:run-pb-1:patch",
		Kind: graph.NodeKindAction,
		Name: "Patch DB",
		Properties: map[string]any{
			"action_type":     "repair_database",
			"playbook_id":     "pb-remediate",
			"playbook_name":   "Repair Database",
			"playbook_run_id": "run-pb-1",
			"stage_id":        "repair",
			"action_id":       "patch",
			"status":          "succeeded",
			"title":           "Patch DB",
			"tenant_id":       "tenant-acme",
			"target_ids":      []string{"database:orders"},
			"source_system":   "platform_playbook",
			"observed_at":     baseAt.Add(80 * time.Minute).Format(time.RFC3339),
			"valid_from":      baseAt.Add(80 * time.Minute).Format(time.RFC3339),
		},
	})

	w := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/unified-execution-timeline?window_days=7&tenant_id=tenant-acme&max_events=50", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	summary, ok := body["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary object, got %#v", body["summary"])
	}
	if got := summary["evaluation_runs"]; got != float64(1) {
		t.Fatalf("expected one evaluation run, got %#v", got)
	}
	if got := summary["playbook_runs"]; got != float64(1) {
		t.Fatalf("expected one playbook run, got %#v", got)
	}
	if got := summary["claims"]; got != float64(4) {
		t.Fatalf("expected four claim events, got %#v", got)
	}
	events, ok := body["events"].([]any)
	if !ok || len(events) == 0 {
		t.Fatalf("expected timeline events, got %#v", body["events"])
	}
	var sawEvaluation, sawPlaybook bool
	for _, raw := range events {
		event, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		switch event["workflow"] {
		case "evaluation":
			sawEvaluation = true
		case "playbook":
			sawPlaybook = true
		}
	}
	if !sawEvaluation || !sawPlaybook {
		t.Fatalf("expected mixed workflow timeline, sawEvaluation=%v sawPlaybook=%v", sawEvaluation, sawPlaybook)
	}
}

func TestGraphIntelligenceUnifiedExecutionTimelineEndpointInvalidParams(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/unified-execution-timeline?window_days=0", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid window_days, got %d", w.Code)
	}

	w = do(t, s, http.MethodGet, "/api/v1/platform/intelligence/unified-execution-timeline?max_events=0", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid max_events, got %d", w.Code)
	}
}

func TestPlatformIntelligenceUnifiedExecutionTimelineReportDefinition(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/reports/unified-execution-timeline", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)
	if got := body["id"]; got != "unified-execution-timeline" {
		t.Fatalf("expected unified-execution-timeline definition, got %#v", got)
	}
	endpoint, ok := body["endpoint"].(map[string]any)
	if !ok || endpoint["path"] != "/api/v1/platform/intelligence/unified-execution-timeline" {
		t.Fatalf("unexpected endpoint metadata: %#v", body["endpoint"])
	}
	parameters, ok := body["parameters"].([]any)
	if !ok {
		t.Fatalf("expected parameters array, got %#v", body["parameters"])
	}
	var foundEvalRun, foundPlaybook, foundTargetKind bool
	for _, raw := range parameters {
		param, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		switch param["name"] {
		case "evaluation_run_id":
			foundEvalRun = true
		case "playbook_id":
			foundPlaybook = true
		case "target_kind":
			foundTargetKind = true
		}
	}
	if !foundEvalRun || !foundPlaybook || !foundTargetKind {
		t.Fatalf("expected evaluation_run_id, playbook_id, and target_kind parameters, got %#v", parameters)
	}
}

func TestPlatformIntelligenceMeasureCatalog(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/measures", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)
	if count, ok := body["count"].(float64); !ok || int(count) < 10 {
		t.Fatalf("expected at least 10 reusable measures, got %#v", body["count"])
	}
	measures, ok := body["measures"].([]any)
	if !ok || len(measures) == 0 {
		t.Fatalf("expected measures array, got %#v", body["measures"])
	}
	first, ok := measures[0].(map[string]any)
	if !ok {
		t.Fatalf("expected first measure object, got %#v", measures[0])
	}
	if _, ok := first["id"].(string); !ok {
		t.Fatalf("expected measure id, got %#v", first["id"])
	}
}

func TestPlatformIntelligenceCheckCatalog(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/checks", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)
	if count, ok := body["count"].(float64); !ok || int(count) < 6 {
		t.Fatalf("expected at least 6 reusable checks, got %#v", body["count"])
	}
	checks, ok := body["checks"].([]any)
	if !ok || len(checks) == 0 {
		t.Fatalf("expected checks array, got %#v", body["checks"])
	}
}

func TestPlatformIntelligenceSectionEnvelopeCatalog(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/section-envelopes", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)
	if count, ok := body["count"].(float64); !ok || int(count) < 8 {
		t.Fatalf("expected at least 8 section envelopes, got %#v", body["count"])
	}
	envelopes, ok := body["envelopes"].([]any)
	if !ok || len(envelopes) == 0 {
		t.Fatalf("expected envelopes array, got %#v", body["envelopes"])
	}

	getResp := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/section-envelopes/summary", nil)
	if getResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for summary envelope, got %d: %s", getResp.Code, getResp.Body.String())
	}
	getBody := decodeJSON(t, getResp)
	if got := getBody["schema_name"]; got != "PlatformSummaryEnvelope" {
		t.Fatalf("expected PlatformSummaryEnvelope schema, got %#v", got)
	}
}

func TestPlatformIntelligenceSectionFragmentCatalog(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/section-fragments", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)
	if count, ok := body["count"].(float64); !ok || int(count) < 3 {
		t.Fatalf("expected at least 3 section fragments, got %#v", body["count"])
	}
	fragments, ok := body["fragments"].([]any)
	if !ok || len(fragments) == 0 {
		t.Fatalf("expected fragments array, got %#v", body["fragments"])
	}

	getResp := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/section-fragments/telemetry", nil)
	if getResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for telemetry fragment, got %d: %s", getResp.Code, getResp.Body.String())
	}
	getBody := decodeJSON(t, getResp)
	if got := getBody["schema_name"]; got != "PlatformReportSectionTelemetry" {
		t.Fatalf("expected PlatformReportSectionTelemetry schema, got %#v", got)
	}
}

func TestPlatformIntelligenceBenchmarkPackCatalog(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/benchmark-packs", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)
	if count, ok := body["count"].(float64); !ok || int(count) < 6 {
		t.Fatalf("expected at least 6 benchmark packs, got %#v", body["count"])
	}
	packs, ok := body["packs"].([]any)
	if !ok || len(packs) == 0 {
		t.Fatalf("expected packs array, got %#v", body["packs"])
	}

	getResp := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/benchmark-packs/graph-quality.default", nil)
	if getResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for graph-quality benchmark pack, got %d: %s", getResp.Code, getResp.Body.String())
	}
	getBody := decodeJSON(t, getResp)
	if got := getBody["schema_name"]; got != "PlatformGraphQualityBenchmarkPack" {
		t.Fatalf("expected PlatformGraphQualityBenchmarkPack schema, got %#v", got)
	}
}

func TestPlatformGraphSnapshotCatalog(t *testing.T) {
	s := newTestServer(t)
	now := time.Date(2026, 3, 10, 12, 0, 0, 0, time.UTC)
	s.app.SecurityGraph.SetMetadata(graph.Metadata{
		BuiltAt:       now,
		NodeCount:     3,
		EdgeCount:     2,
		Providers:     []string{"github"},
		Accounts:      []string{"acct-a"},
		BuildDuration: 2 * time.Second,
	})

	run := &reports.ReportRun{
		ID:          "report_run:graph-snapshot",
		ReportID:    "quality",
		Status:      reports.ReportRunStatusSucceeded,
		SubmittedAt: now.Add(5 * time.Minute),
		Lineage:     reports.BuildReportLineage(s.app.SecurityGraph, reports.ReportDefinition{ID: "quality"}),
	}
	if err := s.storePlatformReportRun(run); err != nil {
		t.Fatalf("storePlatformReportRun() failed: %v", err)
	}

	list := do(t, s, http.MethodGet, "/api/v1/platform/graph/snapshots", nil)
	if list.Code != http.StatusOK {
		t.Fatalf("expected 200 for snapshot catalog, got %d: %s", list.Code, list.Body.String())
	}
	listBody := decodeJSON(t, list)
	if got := listBody["count"]; got != float64(1) {
		t.Fatalf("expected snapshot count 1, got %#v", got)
	}
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
	if got := snapshot["current"]; got != true {
		t.Fatalf("expected current snapshot flag, got %#v", got)
	}
	current := do(t, s, http.MethodGet, "/api/v1/platform/graph/snapshots/current", nil)
	if current.Code != http.StatusOK {
		t.Fatalf("expected 200 for current snapshot, got %d: %s", current.Code, current.Body.String())
	}
	get := do(t, s, http.MethodGet, "/api/v1/platform/graph/snapshots/"+snapshotID, nil)
	if get.Code != http.StatusOK {
		t.Fatalf("expected 200 for snapshot get, got %d: %s", get.Code, get.Body.String())
	}
}

func TestPlatformIntelligenceReportRunSync(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph
	now := time.Date(2026, 3, 9, 16, 0, 0, 0, time.UTC)

	g.AddNode(&graph.Node{
		ID:   "person:alice@example.com",
		Kind: graph.NodeKindPerson,
		Name: "Alice",
		Properties: map[string]any{
			"email":       "alice@example.com",
			"observed_at": now.Format(time.RFC3339),
			"valid_from":  now.Format(time.RFC3339),
		},
	})
	g.SetMetadata(graph.Metadata{
		BuiltAt:   now.Add(30 * time.Minute),
		NodeCount: 1,
		Providers: []string{"test"},
	})

	w := do(t, s, http.MethodPost, "/api/v1/platform/intelligence/reports/quality/runs", map[string]any{
		"execution_mode": "sync",
		"parameters": []map[string]any{
			{"name": "stale_after_hours", "integer_value": 24},
		},
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)
	if got := body["status"]; got != reports.ReportRunStatusSucceeded {
		t.Fatalf("expected succeeded report run, got %#v", got)
	}
	if got := body["report_id"]; got != "quality" {
		t.Fatalf("expected quality report_id, got %#v", got)
	}
	if _, ok := body["snapshot"].(map[string]any); !ok {
		t.Fatalf("expected snapshot metadata, got %#v", body["snapshot"])
	}
	lineage, ok := body["lineage"].(map[string]any)
	if !ok {
		t.Fatalf("expected lineage metadata, got %#v", body["lineage"])
	}
	if got := lineage["report_definition_version"]; got != reports.DefaultReportDefinitionVersion {
		t.Fatalf("expected default report definition version, got %#v", got)
	}
	if got := lineage["graph_snapshot_id"]; got == "" {
		t.Fatalf("expected graph snapshot id, got %#v", got)
	}
	storage, ok := body["storage"].(map[string]any)
	if !ok {
		t.Fatalf("expected storage metadata, got %#v", body["storage"])
	}
	if got := storage["storage_class"]; got != "local_durable" {
		t.Fatalf("expected local_durable storage class, got %#v", got)
	}
	if got := storage["materialized_result_available"]; got != true {
		t.Fatalf("expected materialized result availability, got %#v", got)
	}
	if got := body["latest_attempt_id"]; got == "" {
		t.Fatalf("expected latest_attempt_id, got %#v", got)
	}
	if got := body["attempt_count"]; got != float64(1) {
		t.Fatalf("expected attempt_count=1, got %#v", got)
	}
	statusURL, _ := body["status_url"].(string)
	if statusURL == "" {
		t.Fatalf("expected status_url, got %#v", body["status_url"])
	}
	sections, ok := body["sections"].([]any)
	if !ok || len(sections) == 0 {
		t.Fatalf("expected section summaries, got %#v", body["sections"])
	}
	firstSection, ok := sections[0].(map[string]any)
	if !ok {
		t.Fatalf("expected first section object, got %#v", sections[0])
	}
	if got := firstSection["envelope_kind"]; got != "summary" {
		t.Fatalf("expected summary envelope kind, got %#v", got)
	}
	if fieldKeys, ok := firstSection["field_keys"].([]any); !ok || len(fieldKeys) == 0 {
		t.Fatalf("expected field key capture, got %#v", firstSection["field_keys"])
	}
	expectedEventCount := 4 + len(sections)
	if got := body["event_count"]; got != float64(expectedEventCount) {
		t.Fatalf("expected event_count=%d, got %#v", expectedEventCount, got)
	}

	runResp := do(t, s, http.MethodGet, statusURL, nil)
	if runResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for report run lookup, got %d: %s", runResp.Code, runResp.Body.String())
	}
	runBody := decodeJSON(t, runResp)
	if _, ok := runBody["result"].(map[string]any); !ok {
		t.Fatalf("expected materialized result object, got %#v", runBody["result"])
	}
	snapshot, ok := runBody["snapshot"].(map[string]any)
	if !ok {
		t.Fatalf("expected snapshot object, got %#v", runBody["snapshot"])
	}
	if snapshotLineage, ok := snapshot["lineage"].(map[string]any); !ok || snapshotLineage["graph_snapshot_id"] == "" {
		t.Fatalf("expected snapshot lineage, got %#v", snapshot["lineage"])
	}
	if snapshotStorage, ok := snapshot["storage"].(map[string]any); !ok || snapshotStorage["storage_class"] != "local_durable" {
		t.Fatalf("expected snapshot storage metadata, got %#v", snapshot["storage"])
	}

	attemptsResp := do(t, s, http.MethodGet, statusURL+"/attempts", nil)
	if attemptsResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for attempts lookup, got %d: %s", attemptsResp.Code, attemptsResp.Body.String())
	}
	attemptsBody := decodeJSON(t, attemptsResp)
	if got := attemptsBody["count"]; got != float64(1) {
		t.Fatalf("expected one attempt, got %#v", got)
	}
	attempts, ok := attemptsBody["attempts"].([]any)
	if !ok || len(attempts) != 1 {
		t.Fatalf("expected one attempt entry, got %#v", attemptsBody["attempts"])
	}
	attempt, ok := attempts[0].(map[string]any)
	if !ok {
		t.Fatalf("expected attempt object, got %#v", attempts[0])
	}
	if got := attempt["status"]; got != reports.ReportRunStatusSucceeded {
		t.Fatalf("expected attempt succeeded, got %#v", got)
	}
	if got := attempt["execution_surface"]; got != "platform.inline" {
		t.Fatalf("expected inline execution surface, got %#v", got)
	}

	eventsResp := do(t, s, http.MethodGet, statusURL+"/events", nil)
	if eventsResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for events lookup, got %d: %s", eventsResp.Code, eventsResp.Body.String())
	}
	eventsBody := decodeJSON(t, eventsResp)
	if got := eventsBody["count"]; got != float64(expectedEventCount) {
		t.Fatalf("expected %d report events, got %#v", expectedEventCount, got)
	}
	events, ok := eventsBody["events"].([]any)
	if !ok || len(events) != expectedEventCount {
		t.Fatalf("expected %d event entries, got %#v", expectedEventCount, eventsBody["events"])
	}
	firstEvent, ok := events[0].(map[string]any)
	if !ok {
		t.Fatalf("expected first event object, got %#v", events[0])
	}
	if got := firstEvent["type"]; got != string(webhooks.EventPlatformReportRunQueued) {
		t.Fatalf("expected queued event first, got %#v", got)
	}
	lastEvent, ok := events[len(events)-1].(map[string]any)
	if !ok {
		t.Fatalf("expected last event object, got %#v", events[len(events)-1])
	}
	if got := lastEvent["type"]; got != string(webhooks.EventPlatformReportRunCompleted) {
		t.Fatalf("expected completed event last, got %#v", got)
	}
	sectionEvents := 0
	for _, raw := range events {
		event, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if event["type"] == string(webhooks.EventPlatformReportSectionEmitted) {
			sectionEvents++
		}
	}
	if sectionEvents != len(sections) {
		t.Fatalf("expected %d section_emitted events, got %d", len(sections), sectionEvents)
	}

	listResp := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/reports/quality/runs", nil)
	if listResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for run list, got %d: %s", listResp.Code, listResp.Body.String())
	}
	listBody := decodeJSON(t, listResp)
	if count, ok := listBody["count"].(float64); !ok || count < 1 {
		t.Fatalf("expected at least one report run, got %#v", listBody["count"])
	}
}

func TestPlatformIntelligenceReportRunCacheReuseExposesSectionTelemetry(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph
	now := time.Date(2026, 3, 9, 16, 45, 0, 0, time.UTC)

	g.AddNode(&graph.Node{
		ID:   "person:alice@example.com",
		Kind: graph.NodeKindPerson,
		Name: "Alice",
		Properties: map[string]any{
			"email":       "alice@example.com",
			"observed_at": now.Format(time.RFC3339),
			"valid_from":  now.Format(time.RFC3339),
		},
	})
	g.SetMetadata(graph.Metadata{
		BuiltAt:   now.Add(10 * time.Minute),
		NodeCount: 1,
		Providers: []string{"test"},
	})

	first := do(t, s, http.MethodPost, "/api/v1/platform/intelligence/reports/quality/runs", map[string]any{
		"execution_mode": "sync",
		"parameters": []map[string]any{
			{"name": "stale_after_hours", "integer_value": 24},
		},
	})
	if first.Code != http.StatusCreated {
		t.Fatalf("expected 201 for first run, got %d: %s", first.Code, first.Body.String())
	}
	firstBody := decodeJSON(t, first)
	firstRunID, _ := firstBody["id"].(string)
	if firstRunID == "" {
		t.Fatalf("expected first run id, got %#v", firstBody["id"])
	}
	if got := firstBody["cache_status"]; got != reports.ReportCacheStatusMiss {
		t.Fatalf("expected first run cache_status miss, got %#v", got)
	}

	second := do(t, s, http.MethodPost, "/api/v1/platform/intelligence/reports/quality/runs", map[string]any{
		"execution_mode": "sync",
		"parameters": []map[string]any{
			{"name": "stale_after_hours", "integer_value": 24},
		},
	})
	if second.Code != http.StatusCreated {
		t.Fatalf("expected 201 for second run, got %d: %s", second.Code, second.Body.String())
	}
	secondBody := decodeJSON(t, second)
	if got := secondBody["cache_status"]; got != reports.ReportCacheStatusHit {
		t.Fatalf("expected second run cache_status hit, got %#v", got)
	}
	if got := secondBody["cache_source_run_id"]; got != firstRunID {
		t.Fatalf("expected second run cache_source_run_id %q, got %#v", firstRunID, got)
	}
	sections, ok := secondBody["sections"].([]any)
	if !ok || len(sections) == 0 {
		t.Fatalf("expected cached sections, got %#v", secondBody["sections"])
	}
	firstSection, ok := sections[0].(map[string]any)
	if !ok {
		t.Fatalf("expected first section object, got %#v", sections[0])
	}
	telemetry, ok := firstSection["telemetry"].(map[string]any)
	if !ok {
		t.Fatalf("expected section telemetry, got %#v", firstSection["telemetry"])
	}
	if got := telemetry["cache_status"]; got != reports.ReportCacheStatusHit {
		t.Fatalf("expected section telemetry cache_status hit, got %#v", got)
	}
	if got := telemetry["cache_source_run_id"]; got != firstRunID {
		t.Fatalf("expected section telemetry cache_source_run_id %q, got %#v", firstRunID, got)
	}
	if _, ok := telemetry["materialization_duration_ms"].(float64); !ok {
		t.Fatalf("expected section telemetry materialization_duration_ms, got %#v", telemetry["materialization_duration_ms"])
	}
}

func TestPlatformIntelligenceReportRunControlAndRetryPolicyEndpoints(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph
	now := time.Date(2026, 3, 9, 16, 50, 0, 0, time.UTC)

	g.AddNode(&graph.Node{
		ID:   "person:alice@example.com",
		Kind: graph.NodeKindPerson,
		Name: "Alice",
		Properties: map[string]any{
			"email":       "alice@example.com",
			"observed_at": now.Format(time.RFC3339),
			"valid_from":  now.Format(time.RFC3339),
		},
	})
	g.SetMetadata(graph.Metadata{
		BuiltAt:   now.Add(10 * time.Minute),
		NodeCount: 1,
		Providers: []string{"test"},
	})

	create := do(t, s, http.MethodPost, "/api/v1/platform/intelligence/reports/quality/runs", map[string]any{
		"execution_mode": "sync",
		"parameters": []map[string]any{
			{"name": "stale_after_hours", "integer_value": 24},
		},
	})
	if create.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", create.Code, create.Body.String())
	}
	body := decodeJSON(t, create)
	statusURL, _ := body["status_url"].(string)
	if statusURL == "" {
		t.Fatalf("expected status_url, got %#v", body["status_url"])
	}

	control := do(t, s, http.MethodGet, statusURL+"/control", nil)
	if control.Code != http.StatusOK {
		t.Fatalf("expected 200 for control lookup, got %d: %s", control.Code, control.Body.String())
	}
	controlBody := decodeJSON(t, control)
	if got := controlBody["terminal"]; got != true {
		t.Fatalf("expected terminal control state, got %#v", got)
	}
	if got := controlBody["retryable"]; got != false {
		t.Fatalf("expected retryable=false for succeeded run, got %#v", got)
	}

	retryPolicy := do(t, s, http.MethodGet, statusURL+"/retry-policy", nil)
	if retryPolicy.Code != http.StatusOK {
		t.Fatalf("expected 200 for retry policy lookup, got %d: %s", retryPolicy.Code, retryPolicy.Body.String())
	}
	policyBody := decodeJSON(t, retryPolicy)
	if got := policyBody["remaining_attempts"]; got != float64(reports.DefaultReportRetryMaxAttempts-1) {
		t.Fatalf("expected remaining attempts to reflect one consumed attempt, got %#v", got)
	}

	update := do(t, s, http.MethodPut, statusURL+"/retry-policy", map[string]any{
		"max_attempts":    5,
		"base_backoff_ms": 100,
		"max_backoff_ms":  1000,
	})
	if update.Code != http.StatusOK {
		t.Fatalf("expected 200 for retry policy update, got %d: %s", update.Code, update.Body.String())
	}
	updateBody := decodeJSON(t, update)
	policy, ok := updateBody["retry_policy"].(map[string]any)
	if !ok {
		t.Fatalf("expected retry_policy object, got %#v", updateBody["retry_policy"])
	}
	if got := policy["max_attempts"]; got != float64(5) {
		t.Fatalf("expected max_attempts=5, got %#v", got)
	}
}

func TestPlatformIntelligenceReportRunAsync(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph
	now := time.Date(2026, 3, 9, 17, 0, 0, 0, time.UTC)

	g.AddNode(&graph.Node{
		ID:   "service:payments",
		Kind: graph.NodeKindService,
		Name: "Payments",
		Properties: map[string]any{
			"service_id":    "payments",
			"source_system": "github",
			"observed_at":   now.Format(time.RFC3339),
			"valid_from":    now.Format(time.RFC3339),
		},
	})
	g.SetMetadata(graph.Metadata{
		BuiltAt:   now.Add(20 * time.Minute),
		NodeCount: 1,
		Providers: []string{"test"},
	})

	w := do(t, s, http.MethodPost, "/api/v1/platform/intelligence/reports/metadata-quality/runs", map[string]any{
		"execution_mode": "async",
		"parameters": []map[string]any{
			{"name": "top_kinds", "integer_value": 10},
		},
	})
	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)
	jobURL, _ := body["job_status_url"].(string)
	statusURL, _ := body["status_url"].(string)
	if jobURL == "" || statusURL == "" {
		t.Fatalf("expected async run job/status URLs, got job=%#v status=%#v", body["job_status_url"], body["status_url"])
	}

	var runBody map[string]any
	for i := 0; i < 600; i++ {
		runResp := do(t, s, http.MethodGet, statusURL, nil)
		if runResp.Code != http.StatusOK {
			t.Fatalf("expected 200 for async run lookup, got %d: %s", runResp.Code, runResp.Body.String())
		}
		runBody = decodeJSON(t, runResp)
		if runBody["status"] == reports.ReportRunStatusSucceeded {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := runBody["status"]; got != reports.ReportRunStatusSucceeded {
		t.Fatalf("expected async report run to succeed, got %#v", got)
	}
	if _, ok := runBody["result"].(map[string]any); !ok {
		t.Fatalf("expected async result payload, got %#v", runBody["result"])
	}
	if got := runBody["attempt_count"]; got != float64(1) {
		t.Fatalf("expected one attempt, got %#v", got)
	}
	sections, ok := runBody["sections"].([]any)
	if !ok || len(sections) == 0 {
		t.Fatalf("expected async section summaries, got %#v", runBody["sections"])
	}
	expectedEventCount := 4 + len(sections)
	if got := runBody["event_count"]; got != float64(expectedEventCount) {
		t.Fatalf("expected %d report events, got %#v", expectedEventCount, got)
	}

	attemptsResp := do(t, s, http.MethodGet, statusURL+"/attempts", nil)
	if attemptsResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for async attempts lookup, got %d: %s", attemptsResp.Code, attemptsResp.Body.String())
	}
	attemptsBody := decodeJSON(t, attemptsResp)
	attempts, ok := attemptsBody["attempts"].([]any)
	if !ok || len(attempts) != 1 {
		t.Fatalf("expected one async attempt, got %#v", attemptsBody["attempts"])
	}
	attempt, ok := attempts[0].(map[string]any)
	if !ok {
		t.Fatalf("expected attempt object, got %#v", attempts[0])
	}
	if got := attempt["execution_surface"]; got != "platform.job" {
		t.Fatalf("expected job execution surface, got %#v", got)
	}
	if got := attempt["job_id"]; got == "" {
		t.Fatalf("expected job_id on async attempt, got %#v", got)
	}

	jobBody := waitForPlatformJobTerminalStatus(t, s, jobURL, "succeeded")
	if got := jobBody["status"]; got != "succeeded" {
		t.Fatalf("expected job succeeded, got %#v", got)
	}
}

func TestPlatformIntelligenceReportRunStreamEmitsSections(t *testing.T) {
	s := newTestServer(t)
	server := httptest.NewServer(s)
	defer server.Close()

	createResp := doAuthenticatedHTTP(t, server.URL, http.MethodPost, "/api/v1/platform/intelligence/reports/quality/runs", map[string]any{
		"execution_mode": "sync",
	}, nil)
	if createResp.Code != http.StatusCreated {
		t.Fatalf("expected 201 for sync run create, got %d: %s", createResp.Code, createResp.Body.String())
	}
	createBody := decodeJSON(t, createResp)
	statusURL, _ := createBody["status_url"].(string)
	if statusURL == "" {
		t.Fatalf("expected status_url, got %#v", createBody["status_url"])
	}

	streamCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(streamCtx, http.MethodGet, server.URL+statusURL+"/stream", nil)
	if err != nil {
		t.Fatalf("build report stream request: %v", err)
	}
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("open report stream: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	sectionCh := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(resp.Body)
		var eventName string
		var payload strings.Builder
		for scanner.Scan() {
			line := scanner.Text()
			switch {
			case strings.HasPrefix(line, "event: "):
				eventName = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				payload.WriteString(strings.TrimPrefix(line, "data: "))
			case line == "":
				if eventName == "section" {
					sectionCh <- payload.String()
					return
				}
				eventName = ""
				payload.Reset()
			}
		}
	}()

	select {
	case payload := <-sectionCh:
		if !strings.Contains(payload, "\"type\":\"section\"") {
			t.Fatalf("expected section stream payload, got %s", payload)
		}
		if !strings.Contains(payload, "\"section\"") {
			t.Fatalf("expected section envelope in payload, got %s", payload)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for report section stream event")
	}
}

func TestPlatformIntelligenceReportRunRetrySync(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph
	now := time.Date(2026, 3, 10, 1, 0, 0, 0, time.UTC)

	g.AddNode(&graph.Node{
		ID:   "person:alice@example.com",
		Kind: graph.NodeKindPerson,
		Name: "Alice",
		Properties: map[string]any{
			"email":       "alice@example.com",
			"observed_at": now.Format(time.RFC3339),
			"valid_from":  now.Format(time.RFC3339),
		},
	})
	g.SetMetadata(graph.Metadata{
		BuiltAt:   now.Add(5 * time.Minute),
		NodeCount: 1,
		Providers: []string{"test"},
	})

	original := s.platformReportHandlers["quality"]
	var calls atomic.Int64
	s.platformReportHandlers["quality"] = func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			s.error(w, http.StatusServiceUnavailable, "temporary upstream failure")
			return
		}
		original(w, r)
	}

	create := do(t, s, http.MethodPost, "/api/v1/platform/intelligence/reports/quality/runs", map[string]any{
		"execution_mode": "sync",
		"parameters": []map[string]any{
			{"name": "stale_after_hours", "integer_value": 24},
		},
	})
	if create.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for failed first run, got %d: %s", create.Code, create.Body.String())
	}
	created := decodeJSON(t, create)
	if got := created["status"]; got != reports.ReportRunStatusFailed {
		t.Fatalf("expected failed first run, got %#v", got)
	}
	statusURL, _ := created["status_url"].(string)
	if statusURL == "" {
		t.Fatalf("expected status_url, got %#v", created["status_url"])
	}

	retry := do(t, s, http.MethodPost, statusURL+":retry", map[string]any{
		"reason": "retry after transient failure",
	})
	if retry.Code != http.StatusOK {
		t.Fatalf("expected 200 for sync retry, got %d: %s", retry.Code, retry.Body.String())
	}
	retried := decodeJSON(t, retry)
	if got := retried["status"]; got != reports.ReportRunStatusSucceeded {
		t.Fatalf("expected retry to succeed, got %#v", got)
	}
	if got := retried["attempt_count"]; got != float64(2) {
		t.Fatalf("expected attempt_count=2, got %#v", got)
	}
	retryPolicy, ok := retried["retry_policy"].(map[string]any)
	if !ok {
		t.Fatalf("expected retry_policy metadata, got %#v", retried["retry_policy"])
	}
	if got := retryPolicy["max_attempts"]; got != float64(reports.DefaultReportRetryMaxAttempts) {
		t.Fatalf("expected default max attempts, got %#v", got)
	}

	attemptsResp := do(t, s, http.MethodGet, statusURL+"/attempts", nil)
	if attemptsResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for attempts lookup, got %d: %s", attemptsResp.Code, attemptsResp.Body.String())
	}
	attemptsBody := decodeJSON(t, attemptsResp)
	attempts, ok := attemptsBody["attempts"].([]any)
	if !ok || len(attempts) != 2 {
		t.Fatalf("expected two attempts, got %#v", attemptsBody["attempts"])
	}
	firstAttempt, ok := attempts[0].(map[string]any)
	if !ok {
		t.Fatalf("expected first attempt object, got %#v", attempts[0])
	}
	if got := firstAttempt["classification"]; got != reports.ReportAttemptClassTransient {
		t.Fatalf("expected transient first attempt classification, got %#v", got)
	}
	secondAttempt, ok := attempts[1].(map[string]any)
	if !ok {
		t.Fatalf("expected second attempt object, got %#v", attempts[1])
	}
	if got := secondAttempt["retry_of_attempt_id"]; got == "" {
		t.Fatalf("expected retry_of_attempt_id on second attempt, got %#v", got)
	}
	if got := secondAttempt["retry_reason"]; got != "retry after transient failure" {
		t.Fatalf("expected retry reason to persist, got %#v", got)
	}
}

func waitForPlatformJobTerminalStatus(t *testing.T, s *Server, jobURL, wantStatus string) map[string]any {
	t.Helper()
	if strings.TrimSpace(jobURL) == "" {
		t.Fatal("expected non-empty jobURL")
	}
	var latest map[string]any
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		resp := do(t, s, http.MethodGet, jobURL, nil)
		if resp.Code != http.StatusOK {
			t.Fatalf("expected 200 for platform job lookup, got %d: %s", resp.Code, resp.Body.String())
		}
		latest = decodeJSON(t, resp)
		status, _ := latest["status"].(string)
		if status == wantStatus {
			return latest
		}
		if status == "failed" || status == "canceled" {
			t.Fatalf("expected platform job status %q, got terminal status %q: %#v", wantStatus, status, latest)
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for platform job status %q, last payload: %#v", wantStatus, latest)
	return nil
}

func waitForPlatformReportRunStatus(t *testing.T, s *Server, statusURL, wantStatus string) map[string]any {
	t.Helper()
	if strings.TrimSpace(statusURL) == "" {
		t.Fatal("expected non-empty statusURL")
	}
	var latest map[string]any
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		resp := do(t, s, http.MethodGet, statusURL, nil)
		if resp.Code != http.StatusOK {
			t.Fatalf("expected 200 for report run lookup, got %d: %s", resp.Code, resp.Body.String())
		}
		latest = decodeJSON(t, resp)
		status, _ := latest["status"].(string)
		if status == wantStatus {
			return latest
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for report run status %q, last payload: %#v", wantStatus, latest)
	return nil
}

func TestPlatformIntelligenceReportRunRetryAsyncIncludesBackoffMetadata(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph
	now := time.Date(2026, 3, 10, 1, 30, 0, 0, time.UTC)

	g.AddNode(&graph.Node{
		ID:   "person:alice@example.com",
		Kind: graph.NodeKindPerson,
		Name: "Alice",
		Properties: map[string]any{
			"email":       "alice@example.com",
			"observed_at": now.Format(time.RFC3339),
			"valid_from":  now.Format(time.RFC3339),
		},
	})
	g.SetMetadata(graph.Metadata{
		BuiltAt:   now.Add(5 * time.Minute),
		NodeCount: 1,
		Providers: []string{"test"},
	})

	original := s.platformReportHandlers["quality"]
	var calls atomic.Int64
	s.platformReportHandlers["quality"] = func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			s.error(w, http.StatusServiceUnavailable, "temporary upstream failure")
			return
		}
		original(w, r)
	}

	create := do(t, s, http.MethodPost, "/api/v1/platform/intelligence/reports/quality/runs", map[string]any{
		"execution_mode": "async",
		"parameters": []map[string]any{
			{"name": "stale_after_hours", "integer_value": 24},
		},
	})
	if create.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for initial async run, got %d: %s", create.Code, create.Body.String())
	}
	created := decodeJSON(t, create)
	jobURL, _ := created["job_status_url"].(string)
	statusURL, _ := created["status_url"].(string)
	if statusURL == "" || jobURL == "" {
		t.Fatalf("expected async run URLs, got status=%#v job=%#v", created["status_url"], created["job_status_url"])
	}
	waitForPlatformJobTerminalStatus(t, s, jobURL, "failed")
	waitForPlatformReportRunStatus(t, s, statusURL, reports.ReportRunStatusFailed)

	retry := do(t, s, http.MethodPost, statusURL+":retry", map[string]any{
		"execution_mode": "async",
		"retry_policy": map[string]any{
			"max_attempts":    3,
			"base_backoff_ms": 20,
			"max_backoff_ms":  20,
		},
		"reason": "retry async with backoff",
	})
	if retry.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for async retry, got %d: %s", retry.Code, retry.Body.String())
	}
	retried := decodeJSON(t, retry)
	retryJobURL, _ := retried["job_status_url"].(string)
	if got := retried["status"]; got != reports.ReportRunStatusQueued {
		t.Fatalf("expected queued retry response, got %#v", got)
	}
	if got := retried["attempt_count"]; got != float64(2) {
		t.Fatalf("expected attempt_count=2 after retry queue, got %#v", got)
	}
	if retryJobURL == "" {
		t.Fatalf("expected retry job_status_url, got %#v", retried["job_status_url"])
	}

	attemptsResp := do(t, s, http.MethodGet, statusURL+"/attempts", nil)
	if attemptsResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for attempts lookup, got %d: %s", attemptsResp.Code, attemptsResp.Body.String())
	}
	attemptsBody := decodeJSON(t, attemptsResp)
	attempts, ok := attemptsBody["attempts"].([]any)
	if !ok || len(attempts) != 2 {
		t.Fatalf("expected two attempts, got %#v", attemptsBody["attempts"])
	}
	secondAttempt, ok := attempts[1].(map[string]any)
	if !ok {
		t.Fatalf("expected second attempt object, got %#v", attempts[1])
	}
	if got := secondAttempt["retry_backoff_ms"]; got != float64(20) {
		t.Fatalf("expected retry_backoff_ms=20, got %#v", got)
	}
	if got := secondAttempt["scheduled_for"]; got == "" {
		t.Fatalf("expected scheduled_for metadata, got %#v", got)
	}
	if got := secondAttempt["status"]; got != reports.ReportAttemptStatusScheduled &&
		got != reports.ReportAttemptStatusRunning &&
		got != reports.ReportAttemptStatusSucceeded {
		t.Fatalf("expected scheduled/running/succeeded second attempt status, got %#v", got)
	}

	waitForPlatformJobTerminalStatus(t, s, retryJobURL, "succeeded")
	latest := waitForPlatformReportRunStatus(t, s, statusURL, reports.ReportRunStatusSucceeded)
	sections, ok := latest["sections"].([]any)
	if !ok || len(sections) == 0 {
		t.Fatalf("expected sections on retried run, got %#v", latest["sections"])
	}
	firstSection, ok := sections[0].(map[string]any)
	if !ok {
		t.Fatalf("expected first section object, got %#v", sections[0])
	}
	telemetry, ok := firstSection["telemetry"].(map[string]any)
	if !ok {
		t.Fatalf("expected section telemetry on retried run, got %#v", firstSection["telemetry"])
	}
	if got := telemetry["retry_backoff_ms"]; got != float64(20) {
		t.Fatalf("expected section retry_backoff_ms=20, got %#v", got)
	}
}

func TestPlatformIntelligenceReportRunRetryRechecksMaxAttemptsInsideUpdate(t *testing.T) {
	s := newTestServer(t)
	now := time.Date(2026, 3, 10, 2, 15, 0, 0, time.UTC)
	run := &reports.ReportRun{
		ID:            "report_run:retry-race",
		ReportID:      "quality",
		Status:        reports.ReportRunStatusFailed,
		ExecutionMode: reports.ReportExecutionModeSync,
		SubmittedAt:   now.Add(-2 * time.Minute),
		CompletedAt:   ptrTime(now.Add(-time.Minute)),
		RequestedBy:   "alice@example.com",
		StatusURL:     "/api/v1/platform/intelligence/reports/quality/runs/report_run:retry-race",
		RetryPolicy: reports.ReportRetryPolicy{
			MaxAttempts:   2,
			BaseBackoffMS: 10,
			MaxBackoffMS:  20,
		},
		Error: "temporary upstream failure",
	}
	firstAttempt := reports.NewReportRunAttempt(run.ID, 1, reports.ReportRunStatusFailed, "api.request", "platform.inline", "test-host", run.RequestedBy, "", now.Add(-2*time.Minute))
	run.Attempts = []reports.ReportRunAttempt{firstAttempt}
	run.LatestAttemptID = firstAttempt.ID
	reports.CompleteLatestReportRunAttempt(run, reports.ReportRunStatusFailed, now.Add(-time.Minute), run.Error, reports.ReportAttemptClassTransient)
	run.AttemptCount = 1
	run.EventCount = 1
	if err := s.storePlatformReportRun(run); err != nil {
		t.Fatalf("storePlatformReportRun() failed: %v", err)
	}

	s.platformReportSaveMu.Lock()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- do(t, s, http.MethodPost, run.StatusURL+":retry", map[string]any{
			"retry_policy": map[string]any{
				"max_attempts":    2,
				"base_backoff_ms": 10,
				"max_backoff_ms":  20,
			},
			"reason": "stale retry window",
		})
	}()
	time.Sleep(50 * time.Millisecond)

	s.platformReportRunMu.Lock()
	stored := reports.CloneReportRun(s.platformReportRuns[run.ID])
	secondAttempt := reports.NewReportRunAttempt(run.ID, 2, reports.ReportRunStatusFailed, "api.retry", "platform.inline", "test-host", run.RequestedBy, "", now.Add(-30*time.Second))
	secondAttempt.RetryOfAttemptID = firstAttempt.ID
	secondAttempt.RetryReason = "other operator retry"
	stored.Attempts = append(stored.Attempts, secondAttempt)
	stored.LatestAttemptID = secondAttempt.ID
	stored.AttemptCount = len(stored.Attempts)
	s.platformReportRuns[run.ID] = stored
	s.platformReportRunMu.Unlock()
	if s.platformReportStore != nil {
		if err := s.platformReportStore.SaveRun(stored); err != nil {
			s.platformReportSaveMu.Unlock()
			t.Fatalf("SaveRun() failed: %v", err)
		}
	}
	s.platformReportSaveMu.Unlock()

	resp := <-done
	if resp.Code != http.StatusConflict {
		t.Fatalf("expected 409 once attempts are exhausted in the update window, got %d: %s", resp.Code, resp.Body.String())
	}

	status := do(t, s, http.MethodGet, run.StatusURL, nil)
	if status.Code != http.StatusOK {
		t.Fatalf("expected 200 for run lookup, got %d: %s", status.Code, status.Body.String())
	}
	body := decodeJSON(t, status)
	if got := body["attempt_count"]; got != float64(2) {
		t.Fatalf("expected attempt_count to remain at 2, got %#v", got)
	}
}

func TestPlatformIntelligenceReportRunCancelAsync(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph
	now := time.Date(2026, 3, 10, 1, 45, 0, 0, time.UTC)

	g.AddNode(&graph.Node{
		ID:   "person:alice@example.com",
		Kind: graph.NodeKindPerson,
		Name: "Alice",
		Properties: map[string]any{
			"email":       "alice@example.com",
			"observed_at": now.Format(time.RFC3339),
			"valid_from":  now.Format(time.RFC3339),
		},
	})
	g.SetMetadata(graph.Metadata{
		BuiltAt:   now.Add(5 * time.Minute),
		NodeCount: 1,
		Providers: []string{"test"},
	})

	startedCh := make(chan struct{}, 1)
	canceledEvents := make(chan webhooks.Event, 1)
	s.app.Webhooks.Subscribe(func(_ context.Context, event webhooks.Event) error {
		if event.Type == webhooks.EventPlatformReportRunCanceled {
			select {
			case canceledEvents <- event:
			default:
			}
		}
		return nil
	})
	s.platformReportHandlers["quality"] = func(w http.ResponseWriter, r *http.Request) {
		select {
		case startedCh <- struct{}{}:
		default:
		}
		<-r.Context().Done()
	}

	create := do(t, s, http.MethodPost, "/api/v1/platform/intelligence/reports/quality/runs", map[string]any{
		"execution_mode": "async",
		"parameters": []map[string]any{
			{"name": "stale_after_hours", "integer_value": 24},
		},
	})
	if create.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for async run, got %d: %s", create.Code, create.Body.String())
	}
	created := decodeJSON(t, create)
	statusURL, _ := created["status_url"].(string)
	jobURL, _ := created["job_status_url"].(string)
	if statusURL == "" || jobURL == "" {
		t.Fatalf("expected async run URLs, got status=%#v job=%#v", created["status_url"], created["job_status_url"])
	}

	select {
	case <-startedCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for report handler to start")
	}

	cancel := do(t, s, http.MethodPost, statusURL+":cancel", map[string]any{
		"reason": "operator requested cancellation",
	})
	if cancel.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for running cancel request, got %d: %s", cancel.Code, cancel.Body.String())
	}
	canceled := decodeJSON(t, cancel)
	if got := canceled["status"]; got != reports.ReportRunStatusCanceled {
		t.Fatalf("expected durable run to transition to canceled immediately, got %#v", got)
	}
	if got := canceled["cancel_reason"]; got != "operator requested cancellation" {
		t.Fatalf("expected cancel reason to persist on run control metadata, got %#v", got)
	}
	if got := canceled["cancel_requested_by"]; got == "" {
		t.Fatalf("expected cancel_requested_by, got %#v", got)
	}
	if got := canceled["cancel_requested_at"]; got == "" {
		t.Fatalf("expected cancel_requested_at, got %#v", got)
	}

	var runBody map[string]any
	for i := 0; i < 100; i++ {
		runResp := do(t, s, http.MethodGet, statusURL, nil)
		if runResp.Code != http.StatusOK {
			t.Fatalf("expected 200 for canceled run lookup, got %d: %s", runResp.Code, runResp.Body.String())
		}
		runBody = decodeJSON(t, runResp)
		if runBody["status"] == reports.ReportRunStatusCanceled {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := runBody["status"]; got != reports.ReportRunStatusCanceled {
		t.Fatalf("expected canceled run status, got %#v", got)
	}
	if got := runBody["error"]; got != "operator requested cancellation" {
		t.Fatalf("expected final canceled run to keep operator reason, got %#v", got)
	}

	controlResp := do(t, s, http.MethodGet, statusURL+"/control", nil)
	if controlResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for control lookup, got %d: %s", controlResp.Code, controlResp.Body.String())
	}
	controlBody := decodeJSON(t, controlResp)
	if got := controlBody["terminal"]; got != true {
		t.Fatalf("expected terminal control state after cancellation, got %#v", got)
	}
	if got := controlBody["cancel_reason"]; got != "operator requested cancellation" {
		t.Fatalf("expected control cancel reason, got %#v", got)
	}

	var jobBody map[string]any
	for i := 0; i < 100; i++ {
		jobResp := do(t, s, http.MethodGet, jobURL, nil)
		if jobResp.Code != http.StatusOK {
			t.Fatalf("expected 200 for job lookup, got %d: %s", jobResp.Code, jobResp.Body.String())
		}
		jobBody = decodeJSON(t, jobResp)
		if jobBody["status"] == "canceled" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := jobBody["status"]; got != "canceled" {
		t.Fatalf("expected canceled job, got %#v", got)
	}
	if got := jobBody["cancel_reason"]; got != "operator requested cancellation" {
		t.Fatalf("expected job cancel reason, got %#v", got)
	}
	select {
	case event := <-canceledEvents:
		if got := event.Data["run_id"]; got != canceled["id"] {
			t.Fatalf("expected canceled webhook run_id %v, got %#v", canceled["id"], got)
		}
		if got := event.Data["cancel_reason"]; got != "operator requested cancellation" {
			t.Fatalf("expected canceled webhook cancel_reason, got %#v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for canceled webhook event")
	}

	attemptsResp := do(t, s, http.MethodGet, statusURL+"/attempts", nil)
	if attemptsResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for attempts lookup, got %d: %s", attemptsResp.Code, attemptsResp.Body.String())
	}
	attemptsBody := decodeJSON(t, attemptsResp)
	attempts, ok := attemptsBody["attempts"].([]any)
	if !ok || len(attempts) != 1 {
		t.Fatalf("expected one canceled attempt, got %#v", attemptsBody["attempts"])
	}
	attempt, ok := attempts[0].(map[string]any)
	if !ok {
		t.Fatalf("expected attempt object, got %#v", attempts[0])
	}
	if got := attempt["classification"]; got != reports.ReportAttemptClassCancelled {
		t.Fatalf("expected cancelled attempt classification, got %#v", got)
	}
	if got := attempt["status"]; got != reports.ReportAttemptStatusCanceled {
		t.Fatalf("expected canceled attempt status, got %#v", got)
	}

	eventsResp := do(t, s, http.MethodGet, statusURL+"/events", nil)
	if eventsResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for events lookup, got %d: %s", eventsResp.Code, eventsResp.Body.String())
	}
	eventsBody := decodeJSON(t, eventsResp)
	events, ok := eventsBody["events"].([]any)
	if !ok || len(events) == 0 {
		t.Fatalf("expected event history, got %#v", eventsBody["events"])
	}
	if got := events[len(events)-1].(map[string]any)["type"]; got != string(webhooks.EventPlatformReportRunCanceled) {
		t.Fatalf("expected canceled event last, got %#v", got)
	}
}

func TestPlatformIntelligenceReportRunCancelDoesNotOverwriteSucceededRun(t *testing.T) {
	s := newTestServer(t)
	now := time.Date(2026, 3, 10, 2, 45, 0, 0, time.UTC)
	run := &reports.ReportRun{
		ID:            "report_run:cancel-race",
		ReportID:      "quality",
		Status:        reports.ReportRunStatusRunning,
		ExecutionMode: reports.ReportExecutionModeAsync,
		SubmittedAt:   now.Add(-2 * time.Minute),
		StartedAt:     ptrTime(now.Add(-time.Minute)),
		RequestedBy:   "alice@example.com",
		StatusURL:     "/api/v1/platform/intelligence/reports/quality/runs/report_run:cancel-race",
	}
	run.Attempts = []reports.ReportRunAttempt{
		reports.NewReportRunAttempt(run.ID, 1, reports.ReportRunStatusRunning, "api.request", "platform.job", "test-host", run.RequestedBy, "", now.Add(-2*time.Minute)),
	}
	run.LatestAttemptID = run.Attempts[0].ID
	reports.StartLatestReportRunAttempt(run, now.Add(-time.Minute))
	run.AttemptCount = len(run.Attempts)
	if err := s.storePlatformReportRun(run); err != nil {
		t.Fatalf("storePlatformReportRun() failed: %v", err)
	}

	s.platformReportSaveMu.Lock()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- do(t, s, http.MethodPost, run.StatusURL+":cancel", map[string]any{
			"reason": "late cancel",
		})
	}()
	time.Sleep(50 * time.Millisecond)

	s.platformReportRunMu.Lock()
	stored := reports.CloneReportRun(s.platformReportRuns[run.ID])
	completedAt := now
	stored.Status = reports.ReportRunStatusSucceeded
	stored.CompletedAt = &completedAt
	stored.Error = ""
	reports.CompleteLatestReportRunAttempt(stored, stored.Status, completedAt, "", "")
	stored.AttemptCount = len(stored.Attempts)
	s.platformReportRuns[run.ID] = stored
	s.platformReportRunMu.Unlock()
	if s.platformReportStore != nil {
		if err := s.platformReportStore.SaveRun(stored); err != nil {
			s.platformReportSaveMu.Unlock()
			t.Fatalf("SaveRun() failed: %v", err)
		}
	}
	s.platformReportSaveMu.Unlock()

	resp := <-done
	if resp.Code != http.StatusConflict {
		t.Fatalf("expected 409 when the run becomes terminal before cancel commit, got %d: %s", resp.Code, resp.Body.String())
	}

	status := do(t, s, http.MethodGet, run.StatusURL, nil)
	if status.Code != http.StatusOK {
		t.Fatalf("expected 200 for run lookup, got %d: %s", status.Code, status.Body.String())
	}
	body := decodeJSON(t, status)
	if got := body["status"]; got != reports.ReportRunStatusSucceeded {
		t.Fatalf("expected succeeded run to remain succeeded, got %#v", got)
	}
	if got := body["cancel_reason"]; got != nil {
		t.Fatalf("expected no cancel_reason on succeeded run, got %#v", got)
	}
}

func ptrTime(value time.Time) *time.Time {
	return &value
}

func TestAttachPlatformReportRunJobCancelsLateAttachedJobForCanceledRun(t *testing.T) {
	s := newTestServer(t)
	now := time.Date(2026, 3, 10, 1, 50, 0, 0, time.UTC)
	run := &reports.ReportRun{
		ID:            "report_run:late-cancel-job",
		ReportID:      "quality",
		Status:        reports.ReportRunStatusCanceled,
		ExecutionMode: reports.ReportExecutionModeAsync,
		SubmittedAt:   now.Add(-time.Minute),
		CompletedAt:   &now,
		RequestedBy:   "alice@example.com",
		StatusURL:     "/api/v1/platform/intelligence/reports/quality/runs/report_run:late-cancel-job",
		Error:         "operator requested cancellation",
	}
	run.Attempts = []reports.ReportRunAttempt{
		reports.NewReportRunAttempt(run.ID, 1, run.Status, "api.retry", "platform.async", "test-host", run.RequestedBy, "", now.Add(-time.Minute)),
	}
	run.LatestAttemptID = run.Attempts[0].ID
	run.AttemptCount = len(run.Attempts)
	if err := s.storePlatformReportRun(run); err != nil {
		t.Fatalf("storePlatformReportRun() failed: %v", err)
	}

	job := s.newPlatformJob(context.Background(), "platform.report_run", map[string]any{
		"report_id": run.ReportID,
		"run_id":    run.ID,
	}, run.RequestedBy)
	stored, cancelJob, cancelReason, err := s.attachPlatformReportRunJob(run.ID, job)
	if err != nil {
		t.Fatalf("attachPlatformReportRunJob() failed: %v", err)
	}
	if stored == nil {
		t.Fatal("expected updated run snapshot after attaching job")
		return
	}
	if !cancelJob {
		t.Fatal("expected canceled run to request immediate job cancellation")
	}
	if cancelReason != run.Error {
		t.Fatalf("expected cancel reason %q, got %q", run.Error, cancelReason)
	}
	if stored.JobID != job.ID {
		t.Fatalf("expected stored job id %q, got %q", job.ID, stored.JobID)
	}
	if !s.cancelPlatformJob(job.ID, cancelReason) {
		t.Fatal("expected cancelPlatformJob() to cancel the newly attached job")
	}

	jobSnapshot, ok := s.platformJobSnapshot(job.ID)
	if !ok {
		t.Fatalf("expected platform job %q to exist", job.ID)
	}
	if got := jobSnapshot.Status; got != "canceled" {
		t.Fatalf("expected canceled platform job, got %q", got)
	}
	if got := jobSnapshot.CancelReason; got != run.Error {
		t.Fatalf("expected job cancel reason %q, got %q", run.Error, got)
	}

	runSnapshot, ok := s.platformReportRunSnapshot(run.ReportID, run.ID)
	if !ok {
		t.Fatalf("expected persisted report run %q", run.ID)
	}
	if got := runSnapshot.Status; got != reports.ReportRunStatusCanceled {
		t.Fatalf("expected run to remain canceled, got %q", got)
	}
	if got := runSnapshot.JobID; got != job.ID {
		t.Fatalf("expected persisted run job id %q, got %q", job.ID, got)
	}
	if len(runSnapshot.Attempts) != 1 {
		t.Fatalf("expected one attempt on persisted run, got %d", len(runSnapshot.Attempts))
	}
	if got := runSnapshot.Attempts[0].JobID; got != job.ID {
		t.Fatalf("expected persisted attempt job id %q, got %q", job.ID, got)
	}
}

func TestPlatformIntelligenceReportRunPersistsAcrossServerRestart(t *testing.T) {
	application := newTestApp(t)
	s1 := NewServer(application)
	g := application.SecurityGraph
	now := time.Date(2026, 3, 10, 2, 0, 0, 0, time.UTC)

	g.AddNode(&graph.Node{
		ID:   "person:alice@example.com",
		Kind: graph.NodeKindPerson,
		Name: "Alice",
		Properties: map[string]any{
			"email":       "alice@example.com",
			"observed_at": now.Format(time.RFC3339),
			"valid_from":  now.Format(time.RFC3339),
		},
	})
	g.SetMetadata(graph.Metadata{
		BuiltAt:   now.Add(15 * time.Minute),
		NodeCount: 1,
		Providers: []string{"test"},
	})

	createResp := do(t, s1, http.MethodPost, "/api/v1/platform/intelligence/reports/quality/runs", map[string]any{
		"execution_mode": "sync",
		"parameters": []map[string]any{
			{"name": "stale_after_hours", "integer_value": 24},
		},
	})
	if createResp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", createResp.Code, createResp.Body.String())
	}
	createBody := decodeJSON(t, createResp)
	statusURL, _ := createBody["status_url"].(string)
	if statusURL == "" {
		t.Fatalf("expected status_url, got %#v", createBody["status_url"])
	}

	s2 := NewServer(application)
	runResp := do(t, s2, http.MethodGet, statusURL, nil)
	if runResp.Code != http.StatusOK {
		t.Fatalf("expected 200 after restart, got %d: %s", runResp.Code, runResp.Body.String())
	}
	runBody := decodeJSON(t, runResp)
	if got := runBody["status"]; got != reports.ReportRunStatusSucceeded {
		t.Fatalf("expected persisted run status succeeded, got %#v", got)
	}
	if _, ok := runBody["result"].(map[string]any); !ok {
		t.Fatalf("expected restored result payload, got %#v", runBody["result"])
	}
	attemptsResp := do(t, s2, http.MethodGet, statusURL+"/attempts", nil)
	if attemptsResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for restored attempts, got %d: %s", attemptsResp.Code, attemptsResp.Body.String())
	}
	attemptsBody := decodeJSON(t, attemptsResp)
	if got := attemptsBody["count"]; got != float64(1) {
		t.Fatalf("expected persisted attempt count=1, got %#v", got)
	}
	eventsResp := do(t, s2, http.MethodGet, statusURL+"/events", nil)
	if eventsResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for restored events, got %d: %s", eventsResp.Code, eventsResp.Body.String())
	}
	eventsBody := decodeJSON(t, eventsResp)
	sectionCount := 0
	if sections, ok := runBody["sections"].([]any); ok {
		sectionCount = len(sections)
	}
	expectedEventCount := float64(4 + sectionCount)
	if got := eventsBody["count"]; got != expectedEventCount {
		t.Fatalf("expected persisted event count=%v, got %#v", expectedEventCount, got)
	}
}

func TestPlatformIntelligenceReportRunLifecycleEvents(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph
	now := time.Date(2026, 3, 10, 3, 0, 0, 0, time.UTC)

	g.AddNode(&graph.Node{
		ID:   "person:alice@example.com",
		Kind: graph.NodeKindPerson,
		Name: "Alice",
		Properties: map[string]any{
			"email":       "alice@example.com",
			"observed_at": now.Format(time.RFC3339),
			"valid_from":  now.Format(time.RFC3339),
		},
	})

	eventsCh := make(chan webhooks.Event, 8)
	s.app.Webhooks.Subscribe(func(_ context.Context, event webhooks.Event) error {
		switch event.Type {
		case webhooks.EventPlatformReportRunQueued,
			webhooks.EventPlatformReportRunStarted,
			webhooks.EventPlatformReportRunCompleted,
			webhooks.EventPlatformReportSnapshotMaterialized:
			eventsCh <- event
		}
		return nil
	})

	w := do(t, s, http.MethodPost, "/api/v1/platform/intelligence/reports/quality/runs", map[string]any{
		"execution_mode": "sync",
		"parameters": []map[string]any{
			{"name": "stale_after_hours", "integer_value": 24},
		},
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)

	queued := <-eventsCh
	if queued.Type != webhooks.EventPlatformReportRunQueued {
		t.Fatalf("expected queued event first, got %q", queued.Type)
	}
	if queued.Data["report_id"] != "quality" {
		t.Fatalf("expected queued report_id quality, got %#v", queued.Data["report_id"])
	}
	if queued.Data["attempt_count"] != 1 {
		t.Fatalf("expected queued attempt_count=1, got %#v", queued.Data["attempt_count"])
	}
	if queued.Data["storage_class"] != "local_durable" {
		t.Fatalf("expected queued storage_class local_durable, got %#v", queued.Data["storage_class"])
	}

	started := <-eventsCh
	if started.Type != webhooks.EventPlatformReportRunStarted {
		t.Fatalf("expected started event second, got %q", started.Type)
	}
	if started.Data["status"] != reports.ReportRunStatusRunning {
		t.Fatalf("expected started status running, got %#v", started.Data["status"])
	}
	if started.Data["execution_surface"] != "platform.inline" {
		t.Fatalf("expected started execution_surface platform.inline, got %#v", started.Data["execution_surface"])
	}

	snapshot := <-eventsCh
	completed := <-eventsCh
	if snapshot.Type != webhooks.EventPlatformReportSnapshotMaterialized {
		snapshot, completed = completed, snapshot
	}
	if snapshot.Type != webhooks.EventPlatformReportSnapshotMaterialized {
		t.Fatalf("expected one snapshot event, got %q then %q", snapshot.Type, completed.Type)
	}
	if completed.Type != webhooks.EventPlatformReportRunCompleted {
		t.Fatalf("expected completed event, got %q", completed.Type)
	}
	if snapshot.Data["run_id"] != body["id"] {
		t.Fatalf("expected snapshot run_id %v, got %#v", body["id"], snapshot.Data["run_id"])
	}
	if completed.Data["snapshot_id"] == "" {
		t.Fatalf("expected completed event snapshot_id, got %#v", completed.Data["snapshot_id"])
	}
	if completed.Data["materialized_result"] != true {
		t.Fatalf("expected completed event to mark materialized_result=true, got %#v", completed.Data["materialized_result"])
	}
	if completed.Data["report_definition_version"] != reports.DefaultReportDefinitionVersion {
		t.Fatalf("expected completed event report definition version, got %#v", completed.Data["report_definition_version"])
	}
}

func TestPlatformReportRunUpdateRollsBackOnPersistenceFailure(t *testing.T) {
	application := newTestApp(t)
	s := NewServer(application)
	if s.platformReportStore == nil {
		t.Fatal("expected platformReportStore to be configured")
	}
	run := &reports.ReportRun{
		ID:            "report_run:test-rollback",
		ReportID:      "quality",
		Status:        reports.ReportRunStatusQueued,
		ExecutionMode: reports.ReportExecutionModeSync,
		SubmittedAt:   time.Date(2026, 3, 10, 4, 0, 0, 0, time.UTC),
		StatusURL:     "/api/v1/platform/intelligence/reports/quality/runs/report_run:test-rollback",
	}
	if err := s.storePlatformReportRun(run); err != nil {
		t.Fatalf("storePlatformReportRun() failed: %v", err)
	}

	// Force a deterministic persistence failure by making the underlying shared
	// execution store unavailable, while leaving the in-memory cache intact so we
	// can verify the update path does not partially mutate durable state.
	if application.ExecutionStore == nil {
		t.Fatal("expected shared execution store to be configured")
	}
	if err := application.ExecutionStore.Close(); err != nil {
		t.Fatalf("ExecutionStore.Close(): %v", err)
	}

	err := s.updatePlatformReportRun(run.ID, func(run *reports.ReportRun) {
		run.Status = reports.ReportRunStatusRunning
	})
	if err == nil {
		t.Fatal("expected persistence failure from updatePlatformReportRun")
	}
	stored, ok := s.platformReportRunSnapshot(run.ReportID, run.ID)
	if !ok {
		t.Fatalf("expected stored report run %q", run.ID)
	}
	if stored.Status != reports.ReportRunStatusQueued {
		t.Fatalf("expected status rollback to queued, got %q", stored.Status)
	}
}

func TestGraphIntelligenceMetadataQualityEndpoint(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph
	now := time.Date(2026, 3, 9, 17, 0, 0, 0, time.UTC)

	g.AddNode(&graph.Node{
		ID:   "service:payments",
		Kind: graph.NodeKindService,
		Name: "Payments",
		Properties: map[string]any{
			"service_id":    "payments",
			"source_system": "github",
			"observed_at":   now.Format(time.RFC3339),
			"valid_from":    now.Format(time.RFC3339),
		},
	})
	g.AddNode(&graph.Node{
		ID:   "deployment:1",
		Kind: graph.NodeKindDeploymentRun,
		Name: "Deploy #1",
		Properties: map[string]any{
			"deploy_id":       "dep-1",
			"service_id":      "payments",
			"environment":     "production",
			"status":          "mystery_status", // invalid enum for deployment status profile
			"source_system":   "github",
			"source_event_id": "evt-deploy-1",
			"observed_at":     "not-a-time", // invalid timestamp for metadata profile
			"valid_from":      now.Format(time.RFC3339),
		},
	})

	w := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/metadata-quality?top_kinds=10", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)

	summary, ok := body["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary object, got %#v", body["summary"])
	}
	if _, ok := summary["profiled_kinds"].(float64); !ok {
		t.Fatalf("expected summary.profiled_kinds, got %#v", summary["profiled_kinds"])
	}
	if _, ok := summary["required_key_coverage_percent"].(float64); !ok {
		t.Fatalf("expected summary.required_key_coverage_percent, got %#v", summary["required_key_coverage_percent"])
	}
	if _, ok := summary["timestamp_validity_percent"].(float64); !ok {
		t.Fatalf("expected summary.timestamp_validity_percent, got %#v", summary["timestamp_validity_percent"])
	}
	if _, ok := summary["enum_validity_percent"].(float64); !ok {
		t.Fatalf("expected summary.enum_validity_percent, got %#v", summary["enum_validity_percent"])
	}

	kinds, ok := body["kinds"].([]any)
	if !ok || len(kinds) == 0 {
		t.Fatalf("expected kinds array, got %#v", body["kinds"])
	}
	recommendations, ok := body["recommendations"].([]any)
	if !ok || len(recommendations) == 0 {
		t.Fatalf("expected recommendations, got %#v", body["recommendations"])
	}
}

func TestGraphIntelligenceMetadataQualityEndpoint_InvalidParams(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/metadata-quality?top_kinds=0", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for top_kinds=0, got %d", w.Code)
	}
}

func TestGraphIntelligenceAIWorkloadsEndpoint(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph

	g.AddNode(&graph.Node{ID: "internet", Kind: graph.NodeKindInternet, Name: "Internet"})
	g.AddNode(&graph.Node{
		ID:       "service:customer-llm-endpoint",
		Kind:     graph.NodeKindService,
		Name:     "SageMaker Endpoint",
		Provider: "aws",
	})
	g.AddNode(&graph.Node{
		ID:   "database:customer-pgvector",
		Kind: graph.NodeKindDatabase,
		Name: "Customer pgvector",
		Properties: map[string]any{
			"engine":              "pgvector",
			"data_classification": "confidential",
		},
	})
	g.AddNode(&graph.Node{
		ID:   "workload:research-agent",
		Kind: graph.NodeKindWorkload,
		Name: "Research Agent",
		Properties: map[string]any{
			"openai_api_key": "sk-test",
		},
	})
	g.AddNode(&graph.Node{
		ID:   "technology:ollama",
		Kind: graph.NodeKindTechnology,
		Name: "Ollama",
	})
	g.AddEdge(&graph.Edge{ID: "internet-llm", Source: "internet", Target: "service:customer-llm-endpoint", Kind: graph.EdgeKindExposedTo, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "llm-db", Source: "service:customer-llm-endpoint", Target: "database:customer-pgvector", Kind: graph.EdgeKindCanRead, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "agent-ollama", Source: "workload:research-agent", Target: "technology:ollama", Kind: graph.EdgeKindContains, Effect: graph.EdgeEffectAllow})

	w := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/ai-workloads?max_workloads=10&min_risk_score=0&include_shadow=true", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)

	summary, ok := body["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary object, got %#v", body["summary"])
	}
	if count, ok := summary["workload_count"].(float64); !ok || int(count) != 3 {
		t.Fatalf("expected workload_count=2, got %#v", summary["workload_count"])
	}
	if shadow, ok := summary["shadow_ai_workload_count"].(float64); !ok || int(shadow) != 2 {
		t.Fatalf("expected shadow_ai_workload_count=1, got %#v", summary["shadow_ai_workload_count"])
	}

	workloads, ok := body["workloads"].([]any)
	if !ok || len(workloads) != 3 {
		t.Fatalf("expected 2 workloads, got %#v", body["workloads"])
	}
	first, ok := workloads[0].(map[string]any)
	if !ok {
		t.Fatalf("expected workload object, got %#v", workloads[0])
	}
	if first["node_id"] != "service:customer-llm-endpoint" {
		t.Fatalf("expected internet-exposed endpoint first, got %#v", first["node_id"])
	}
	if exposures, ok := body["data_exposures"].([]any); !ok || len(exposures) == 0 {
		t.Fatalf("expected data exposures, got %#v", body["data_exposures"])
	}
}

func TestGraphIntelligenceAIWorkloadsEndpointInvalidParams(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/ai-workloads?max_workloads=0", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for max_workloads=0, got %d", w.Code)
	}

	w = do(t, s, http.MethodGet, "/api/v1/platform/intelligence/ai-workloads?min_risk_score=101", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for min_risk_score=101, got %d", w.Code)
	}

	w = do(t, s, http.MethodGet, "/api/v1/platform/intelligence/ai-workloads?include_shadow=maybe", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid include_shadow, got %d", w.Code)
	}
}

func TestGraphIntelligenceClaimConflictsEndpoint(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph

	g.AddNode(&graph.Node{
		ID:   "service:payments",
		Kind: graph.NodeKindService,
		Name: "Payments",
		Properties: map[string]any{
			"service_id":    "payments",
			"source_system": "cmdb",
			"observed_at":   "2026-03-09T00:00:00Z",
			"valid_from":    "2026-03-09T00:00:00Z",
		},
	})
	g.AddNode(&graph.Node{
		ID:   "evidence:doc:1",
		Kind: graph.NodeKindEvidence,
		Name: "Doc 1",
		Properties: map[string]any{
			"evidence_type": "document",
			"source_system": "docs",
			"observed_at":   "2026-03-09T00:00:00Z",
			"valid_from":    "2026-03-09T00:00:00Z",
		},
	})
	g.AddNode(&graph.Node{
		ID:   "evidence:doc:2",
		Kind: graph.NodeKindEvidence,
		Name: "Doc 2",
		Properties: map[string]any{
			"evidence_type": "document",
			"source_system": "docs",
			"observed_at":   "2026-03-09T00:00:00Z",
			"valid_from":    "2026-03-09T00:00:00Z",
		},
	})

	if _, err := graph.WriteClaim(g, graph.ClaimWriteRequest{
		ID:           "claim:tier:1",
		SubjectID:    "service:payments",
		Predicate:    "service_tier",
		ObjectValue:  "tier1",
		EvidenceIDs:  []string{"evidence:doc:1"},
		SourceID:     "source:cmdb:1",
		SourceName:   "CMDB",
		SourceType:   "system",
		SourceSystem: "api",
	}); err != nil {
		t.Fatalf("write claim 1: %v", err)
	}
	if _, err := graph.WriteClaim(g, graph.ClaimWriteRequest{
		ID:           "claim:tier:2",
		SubjectID:    "service:payments",
		Predicate:    "service_tier",
		ObjectValue:  "tier0",
		EvidenceIDs:  []string{"evidence:doc:2"},
		SourceID:     "source:sheet:1",
		SourceName:   "Ops Sheet",
		SourceType:   "document",
		SourceSystem: "api",
	}); err != nil {
		t.Fatalf("write claim 2: %v", err)
	}

	w := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/claim-conflicts?max_conflicts=10&stale_after_hours=24", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)
	summary, ok := body["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary object, got %#v", body["summary"])
	}
	if groups, ok := summary["conflict_groups"].(float64); !ok || int(groups) != 1 {
		t.Fatalf("expected one conflict group, got %#v", summary["conflict_groups"])
	}
	conflicts, ok := body["conflicts"].([]any)
	if !ok || len(conflicts) != 1 {
		t.Fatalf("expected one conflict, got %#v", body["conflicts"])
	}
}

func TestGraphIntelligenceClaimConflictsEndpoint_InvalidParams(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/claim-conflicts?max_conflicts=0", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for max_conflicts=0, got %d", w.Code)
	}

	w = do(t, s, http.MethodGet, "/api/v1/platform/intelligence/claim-conflicts?include_resolved=maybe", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid include_resolved, got %d", w.Code)
	}

	w = do(t, s, http.MethodGet, "/api/v1/platform/intelligence/claim-conflicts?valid_at=nope", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid valid_at, got %d", w.Code)
	}
}

func TestPlatformReportRunClaimConflictSectionsIncludeLineageAndTruncationMetadata(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph

	g.AddNode(&graph.Node{
		ID:   "service:payments",
		Kind: graph.NodeKindService,
		Name: "Payments",
		Properties: map[string]any{
			"service_id":    "payments",
			"source_system": "cmdb",
			"observed_at":   "2026-03-09T00:00:00Z",
			"valid_from":    "2026-03-09T00:00:00Z",
		},
	})
	g.AddNode(&graph.Node{
		ID:   "service:billing",
		Kind: graph.NodeKindService,
		Name: "Billing",
		Properties: map[string]any{
			"service_id":    "billing",
			"source_system": "cmdb",
			"observed_at":   "2026-03-09T00:00:00Z",
			"valid_from":    "2026-03-09T00:00:00Z",
		},
	})
	subjectIDs := []string{"service:payments", "service:payments", "service:billing", "service:billing"}
	for i, subjectID := range subjectIDs {
		index := i + 1
		evidenceID := fmt.Sprintf("evidence:doc:%d", i)
		g.AddNode(&graph.Node{
			ID:   evidenceID,
			Kind: graph.NodeKindEvidence,
			Name: fmt.Sprintf("Doc %d", i),
			Properties: map[string]any{
				"evidence_type": "document",
				"source_system": "docs",
				"observed_at":   "2026-03-09T00:00:00Z",
				"valid_from":    "2026-03-09T00:00:00Z",
			},
		})
		if _, err := graph.WriteClaim(g, graph.ClaimWriteRequest{
			ID:           fmt.Sprintf("claim:tier:%d", index),
			SubjectID:    subjectID,
			Predicate:    "service_tier",
			ObjectValue:  fmt.Sprintf("tier%d", index),
			EvidenceIDs:  []string{evidenceID},
			SourceID:     fmt.Sprintf("source:sheet:%d", index),
			SourceName:   fmt.Sprintf("Sheet %d", index),
			SourceType:   "document",
			SourceSystem: "api",
		}); err != nil {
			t.Fatalf("write claim %d: %v", index, err)
		}
	}

	run := do(t, s, http.MethodPost, "/api/v1/platform/intelligence/reports/claim-conflicts/runs", map[string]any{
		"execution_mode": "sync",
		"parameters": []map[string]any{
			{"name": "max_conflicts", "integer_value": 1},
			{"name": "stale_after_hours", "integer_value": 24},
		},
	})
	if run.Code != http.StatusCreated {
		t.Fatalf("expected 201 for claim-conflicts run, got %d: %s", run.Code, run.Body.String())
	}
	body := decodeJSON(t, run)
	sections, ok := body["sections"].([]any)
	if !ok || len(sections) == 0 {
		t.Fatalf("expected sections on report run, got %#v", body["sections"])
	}

	var summarySection map[string]any
	var conflictsSection map[string]any
	for _, raw := range sections {
		section, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		switch section["key"] {
		case "summary":
			summarySection = section
		case "conflicts":
			conflictsSection = section
		}
	}
	if summarySection == nil || conflictsSection == nil {
		t.Fatalf("expected summary and conflicts sections, got %#v", sections)
	}
	materialization, ok := summarySection["materialization"].(map[string]any)
	if !ok || materialization["truncated"] != true {
		t.Fatalf("expected summary truncation metadata, got %#v", summarySection["materialization"])
	}
	lineage, ok := conflictsSection["lineage"].(map[string]any)
	if !ok {
		t.Fatalf("expected conflicts lineage metadata, got %#v", conflictsSection["lineage"])
	}
	if got := lineage["claim_count"]; got != float64(2) {
		t.Fatalf("expected claim_count=2 for returned conflict group, got %#v", got)
	}
	if got := lineage["evidence_count"]; got != float64(2) {
		t.Fatalf("expected evidence_count=2 for returned conflict group, got %#v", got)
	}
	if got := lineage["source_count"]; got != float64(2) {
		t.Fatalf("expected source_count=2 for returned conflict group, got %#v", got)
	}

	statusURL, _ := body["status_url"].(string)
	if statusURL == "" {
		t.Fatalf("expected status_url, got %#v", body["status_url"])
	}
	eventsResp := do(t, s, http.MethodGet, statusURL+"/events", nil)
	if eventsResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for event history, got %d: %s", eventsResp.Code, eventsResp.Body.String())
	}
	eventsBody := decodeJSON(t, eventsResp)
	events, ok := eventsBody["events"].([]any)
	if !ok {
		t.Fatalf("expected event array, got %#v", eventsBody["events"])
	}
	foundSectionLineage := false
	foundSectionTruncation := false
	for _, raw := range events {
		event, ok := raw.(map[string]any)
		if !ok || event["type"] != string(webhooks.EventPlatformReportSectionEmitted) {
			continue
		}
		data, ok := event["data"].(map[string]any)
		if !ok {
			continue
		}
		if lineage, ok := data["lineage"].(map[string]any); ok && lineage["claim_count"] == float64(2) {
			foundSectionLineage = true
		}
		if materialization, ok := data["materialization"].(map[string]any); ok && materialization["truncated"] == true {
			foundSectionTruncation = true
		}
	}
	if !foundSectionLineage {
		t.Fatal("expected section_emitted event to include lineage metadata")
	}
	if !foundSectionTruncation {
		t.Fatal("expected section_emitted event to include truncation metadata")
	}
}

func TestGraphIntelligenceLeverageEndpoint(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph
	now := time.Date(2026, 3, 9, 19, 0, 0, 0, time.UTC)

	g.AddNode(&graph.Node{ID: "person:alice@example.com", Kind: graph.NodeKindPerson, Name: "Alice", Properties: map[string]any{
		"email":         "alice@example.com",
		"source_system": "github",
		"observed_at":   now.Add(-1 * time.Hour).Format(time.RFC3339),
		"valid_from":    now.Add(-1 * time.Hour).Format(time.RFC3339),
	}})
	g.AddNode(&graph.Node{ID: "identity_alias:github:alice", Kind: graph.NodeKindIdentityAlias, Name: "alice", Properties: map[string]any{
		"source_system": "github",
		"external_id":   "alice",
		"email":         "alice@example.com",
		"observed_at":   now.Add(-1 * time.Hour).Format(time.RFC3339),
		"valid_from":    now.Add(-1 * time.Hour).Format(time.RFC3339),
	}})
	g.AddNode(&graph.Node{ID: "service:payments", Kind: graph.NodeKindService, Name: "Payments", Properties: map[string]any{
		"service_id":    "payments",
		"source_system": "ci",
		"observed_at":   now.Add(-2 * time.Hour).Format(time.RFC3339),
		"valid_from":    now.Add(-2 * time.Hour).Format(time.RFC3339),
	}})
	g.AddNode(&graph.Node{ID: "decision:rollback", Kind: graph.NodeKindDecision, Name: "Rollback", Properties: map[string]any{
		"decision_type": "rollback",
		"status":        "approved",
		"observed_at":   now.Add(-2 * time.Hour).Format(time.RFC3339),
		"valid_from":    now.Add(-2 * time.Hour).Format(time.RFC3339),
	}})
	g.AddNode(&graph.Node{ID: "outcome:rollback", Kind: graph.NodeKindOutcome, Name: "Rollback outcome", Properties: map[string]any{
		"outcome_type": "deployment_result",
		"verdict":      "positive",
		"observed_at":  now.Add(-1 * time.Hour).Format(time.RFC3339),
		"valid_from":   now.Add(-1 * time.Hour).Format(time.RFC3339),
	}})
	g.AddEdge(&graph.Edge{ID: "alias-link", Source: "identity_alias:github:alice", Target: "person:alice@example.com", Kind: graph.EdgeKindAliasOf, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "outcome-evaluates", Source: "outcome:rollback", Target: "decision:rollback", Kind: graph.EdgeKindEvaluates, Effect: graph.EdgeEffectAllow})

	w := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/leverage?identity_queue_limit=10&recent_window_hours=24", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	summary, ok := body["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary object, got %#v", body["summary"])
	}
	if _, ok := summary["leverage_score"].(float64); !ok {
		t.Fatalf("expected leverage_score, got %#v", summary["leverage_score"])
	}
	query, ok := body["query"].(map[string]any)
	if !ok {
		t.Fatalf("expected query object, got %#v", body["query"])
	}
	if count, ok := query["template_count"].(float64); !ok || count < 1 {
		t.Fatalf("expected query template count >0, got %#v", query["template_count"])
	}
}

func TestPlatformGraphQueryTemplatesEndpoint(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodGet, "/api/v1/platform/graph/templates", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)
	if count, ok := body["count"].(float64); !ok || count < 1 {
		t.Fatalf("expected template count >0, got %#v", body["count"])
	}
	templates, ok := body["templates"].([]any)
	if !ok || len(templates) == 0 {
		t.Fatalf("expected templates array, got %#v", body["templates"])
	}
}

func TestGraphIntelligenceLeverageEndpoint_InvalidParams(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/leverage?identity_suggest_threshold=2", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid identity_suggest_threshold, got %d", w.Code)
	}
}

func TestGraphIngestHealthEndpoint(t *testing.T) {
	s := newTestServer(t)
	dlqPath := filepath.Join(t.TempDir(), "graph-mapper.dlq.jsonl")
	s.app.Config.GraphEventMapperValidationMode = "enforce"
	s.app.Config.GraphEventMapperDeadLetterPath = dlqPath

	mapper, err := graphingest.NewMapperWithOptions(graphingest.MappingConfig{
		Mappings: []graphingest.EventMapping{
			{
				Name:   "invalid_kind",
				Source: "ensemble.tap.test.invalid",
				Nodes: []graphingest.NodeMapping{
					{
						ID:       "test:entity:1",
						Kind:     "nonexistent_kind",
						Name:     "Invalid",
						Provider: "test",
					},
				},
			},
		},
	}, nil, graphingest.MapperOptions{
		ValidationMode: graphingest.MapperValidationEnforce,
		DeadLetterPath: dlqPath,
	})
	if err != nil {
		t.Fatalf("new mapper with options failed: %v", err)
	}
	s.app.TapEventMapper = mapper

	if _, err := mapper.Apply(s.app.SecurityGraph, events.CloudEvent{
		ID:     "evt-invalid-1",
		Type:   "ensemble.tap.test.invalid",
		Time:   time.Date(2026, 3, 9, 22, 30, 0, 0, time.UTC),
		Source: "urn:ensemble:tap",
		Data:   map[string]any{"id": "1"},
	}); err != nil {
		t.Fatalf("mapper apply failed: %v", err)
	}

	w := do(t, s, http.MethodGet, "/api/v1/graph/ingest/health?tail_limit=5", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)

	mapperBody, ok := body["mapper"].(map[string]any)
	if !ok {
		t.Fatalf("expected mapper object, got %#v", body["mapper"])
	}
	if initialized, _ := mapperBody["initialized"].(bool); !initialized {
		t.Fatalf("expected mapper initialized=true, got %#v", mapperBody["initialized"])
	}
	if mode, _ := mapperBody["validation_mode"].(string); mode != "enforce" {
		t.Fatalf("expected enforce validation mode, got %#v", mapperBody["validation_mode"])
	}

	stats, ok := mapperBody["stats"].(map[string]any)
	if !ok {
		t.Fatalf("expected mapper stats object, got %#v", mapperBody["stats"])
	}
	if deadLettered, ok := stats["dead_lettered"].(float64); !ok || deadLettered < 1 {
		t.Fatalf("expected dead_lettered >= 1, got %#v", stats["dead_lettered"])
	}
	sourceSLO, ok := mapperBody["source_slo"].([]any)
	if !ok || len(sourceSLO) == 0 {
		t.Fatalf("expected mapper source_slo entries, got %#v", mapperBody["source_slo"])
	}
	firstSource, ok := sourceSLO[0].(map[string]any)
	if !ok {
		t.Fatalf("expected first source_slo object, got %#v", sourceSLO[0])
	}
	if _, ok := firstSource["match_rate_percent"].(float64); !ok {
		t.Fatalf("expected source_slo.match_rate_percent, got %#v", firstSource["match_rate_percent"])
	}

	deadLetter, ok := body["dead_letter"].(map[string]any)
	if !ok {
		t.Fatalf("expected dead_letter object, got %#v", body["dead_letter"])
	}
	if exists, ok := deadLetter["exists"].(bool); !ok || !exists {
		t.Fatalf("expected dead_letter.exists=true, got %#v", deadLetter["exists"])
	}
	if parsed, ok := deadLetter["records_parsed"].(float64); !ok || parsed < 1 {
		t.Fatalf("expected dead_letter.records_parsed >= 1, got %#v", deadLetter["records_parsed"])
	}
	issueCounts, ok := deadLetter["issue_code_counts"].(map[string]any)
	if !ok {
		t.Fatalf("expected dead_letter.issue_code_counts object, got %#v", deadLetter["issue_code_counts"])
	}
	if _, ok := issueCounts[string(graph.SchemaIssueUnknownNodeKind)]; !ok {
		t.Fatalf("expected unknown_node_kind issue count, got %#v", issueCounts)
	}
}

func TestGraphIngestDeadLetterEndpoint(t *testing.T) {
	s := newTestServer(t)
	dlqPath := filepath.Join(t.TempDir(), "graph-mapper.dlq.db")
	s.app.Config.GraphEventMapperValidationMode = "enforce"
	s.app.Config.GraphEventMapperDeadLetterPath = dlqPath

	mapper, err := graphingest.NewMapperWithOptions(graphingest.MappingConfig{
		Mappings: []graphingest.EventMapping{
			{
				Name:   "invalid_kind",
				Source: "ensemble.tap.test.invalid",
				Nodes: []graphingest.NodeMapping{
					{
						ID:       "test:entity:1",
						Kind:     "nonexistent_kind",
						Name:     "Invalid",
						Provider: "test",
					},
				},
			},
		},
	}, nil, graphingest.MapperOptions{
		ValidationMode: graphingest.MapperValidationEnforce,
		DeadLetterPath: dlqPath,
	})
	if err != nil {
		t.Fatalf("new mapper with options failed: %v", err)
	}
	s.app.TapEventMapper = mapper

	if _, err := mapper.Apply(s.app.SecurityGraph, events.CloudEvent{
		ID:     "evt-invalid-query-1",
		Type:   "ensemble.tap.test.invalid",
		Time:   time.Date(2026, 3, 9, 22, 30, 0, 0, time.UTC),
		Source: "urn:ensemble:tap",
		Data:   map[string]any{"id": "1"},
	}); err != nil {
		t.Fatalf("mapper apply failed: %v", err)
	}

	w := do(t, s, http.MethodGet, "/api/v1/graph/ingest/dead-letter?limit=10&issue_code=unknown_node_kind", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)
	result, ok := body["result"].(map[string]any)
	if !ok {
		t.Fatalf("expected result object, got %#v", body["result"])
	}
	if total, ok := result["total"].(float64); !ok || total < 1 {
		t.Fatalf("expected dead-letter query total >= 1, got %#v", result["total"])
	}
	records, ok := result["records"].([]any)
	if !ok || len(records) == 0 {
		t.Fatalf("expected at least one dead-letter record, got %#v", result["records"])
	}
}

func TestGraphIngestContractsEndpoint(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodGet, "/api/v1/graph/ingest/contracts", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)

	catalogWrapper, ok := body["catalog"].(map[string]any)
	if !ok {
		t.Fatalf("expected catalog object, got %#v", body["catalog"])
	}
	if apiVersion, _ := catalogWrapper["apiVersion"].(string); apiVersion == "" {
		t.Fatalf("expected catalog.apiVersion, got %#v", catalogWrapper["apiVersion"])
	}
	mappings, ok := catalogWrapper["mappings"].([]any)
	if !ok || len(mappings) == 0 {
		t.Fatalf("expected non-empty contract mappings, got %#v", catalogWrapper["mappings"])
	}
	first, ok := mappings[0].(map[string]any)
	if !ok {
		t.Fatalf("expected first mapping object, got %#v", mappings[0])
	}
	if _, ok := first["data_schema"].(map[string]any); !ok {
		t.Fatalf("expected first mapping data_schema object, got %#v", first["data_schema"])
	}
}

func TestGraphIngestHealthEndpointInvalidTailLimit(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, http.MethodGet, "/api/v1/graph/ingest/health?tail_limit=0", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for tail_limit=0, got %d", w.Code)
	}
}

func TestGraphIntelligenceWeeklyCalibrationEndpoint(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph
	now := time.Date(2026, 3, 9, 18, 0, 0, 0, time.UTC)

	g.AddNode(&graph.Node{
		ID:   "identity_alias:github:alice",
		Kind: graph.NodeKindIdentityAlias,
		Name: "alice",
		Properties: map[string]any{
			"source_system": "github",
			"external_id":   "alice",
			"observed_at":   now.Format(time.RFC3339),
			"valid_from":    now.Format(time.RFC3339),
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

	w := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/calibration/weekly?window_days=7&trend_days=14", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)
	if _, ok := body["risk_feedback"].(map[string]any); !ok {
		t.Fatalf("expected risk_feedback object, got %#v", body["risk_feedback"])
	}
	riskFeedback := body["risk_feedback"].(map[string]any)
	if _, ok := riskFeedback["generated_at"].(string); !ok {
		t.Fatalf("expected typed risk_feedback.generated_at, got %#v", riskFeedback["generated_at"])
	}
	if _, ok := body["identity"].(map[string]any); !ok {
		t.Fatalf("expected identity object, got %#v", body["identity"])
	}
	if _, ok := body["ontology"].(map[string]any); !ok {
		t.Fatalf("expected ontology object, got %#v", body["ontology"])
	}
	temporal, ok := body["temporal"].(map[string]any)
	if !ok {
		t.Fatalf("expected temporal object, got %#v", body["temporal"])
	}
	if _, ok := temporal["count"].(float64); !ok {
		t.Fatalf("expected temporal.count, got %#v", temporal["count"])
	}
}

func TestGraphIntelligenceNaturalLanguageQueryEndpoint(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph

	g.AddNode(&graph.Node{
		ID:       "instance:web-1",
		Kind:     graph.NodeKindInstance,
		Name:     "web-1",
		Provider: "aws",
		Properties: map[string]any{
			"internet_exposed": true,
		},
	})
	s.app.Findings.Upsert(context.Background(), policy.Finding{
		ID:           "finding:web-1:cve",
		PolicyID:     "vuln-critical",
		PolicyName:   "Critical Vulnerability",
		Severity:     "critical",
		Description:  "Critical unpatched CVE",
		ResourceID:   "instance:web-1",
		ResourceName: "web-1",
		ResourceType: "instance",
		Resource:     map[string]any{"id": "instance:web-1"},
	})

	w := do(t, s, http.MethodPost, "/api/v1/platform/intelligence/nl-queries", map[string]any{
		"question": "Which internet-facing instances have critical unpatched CVEs?",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)
	plan, ok := body["plan"].(map[string]any)
	if !ok {
		t.Fatalf("expected plan object, got %#v", body["plan"])
	}
	if plan["kind"] != string("entity_findings_query") {
		t.Fatalf("plan kind = %#v, want entity_findings_query", plan["kind"])
	}
	if _, ok := body["summary"].(string); !ok {
		t.Fatalf("expected summary string, got %#v", body["summary"])
	}
	result, ok := body["result"].(map[string]any)
	if !ok {
		t.Fatalf("expected structured result, got %#v", body["result"])
	}
	if got, ok := result["matching_entities"].(float64); !ok || int(got) != 1 {
		t.Fatalf("matching_entities = %#v, want 1", result["matching_entities"])
	}
}

func TestGraphIntelligenceNaturalLanguageQueryEndpointRejectsMutationRequests(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodPost, "/api/v1/platform/intelligence/nl-queries", map[string]any{
		"question": "Delete all public buckets",
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for mutation request, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGraphIntelligenceKeyPersonRiskEndpoint(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph
	now := time.Now().UTC()

	g.AddNode(&graph.Node{ID: "person:alice@example.com", Kind: graph.NodeKindPerson, Name: "Alice", Properties: map[string]any{"department": "engineering"}})
	g.AddNode(&graph.Node{ID: "person:bob@example.com", Kind: graph.NodeKindPerson, Name: "Bob", Properties: map[string]any{"department": "engineering"}})
	g.AddNode(&graph.Node{ID: "department:engineering", Kind: graph.NodeKindDepartment, Name: "Engineering"})
	g.AddNode(&graph.Node{ID: "svc:core", Kind: graph.NodeKindApplication, Name: "Core"})
	g.AddNode(&graph.Node{ID: "customer:acme", Kind: graph.NodeKindCustomer, Name: "Acme", Properties: map[string]any{"arr": 100000.0}})
	g.AddEdge(&graph.Edge{ID: "alice-eng", Source: "person:alice@example.com", Target: "department:engineering", Kind: graph.EdgeKindMemberOf})
	g.AddEdge(&graph.Edge{ID: "bob-eng", Source: "person:bob@example.com", Target: "department:engineering", Kind: graph.EdgeKindMemberOf})
	g.AddEdge(&graph.Edge{ID: "alice-core", Source: "person:alice@example.com", Target: "svc:core", Kind: graph.EdgeKindCanAdmin, Properties: map[string]any{"last_seen": now.Add(-time.Hour)}})
	g.AddEdge(&graph.Edge{ID: "alice-acme", Source: "person:alice@example.com", Target: "customer:acme", Kind: graph.EdgeKindManagedBy, Properties: map[string]any{"last_seen": now.Add(-time.Hour)}})

	w := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/key-person-risk?limit=5", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)
	items, ok := body["items"].([]any)
	if !ok || len(items) == 0 {
		t.Fatalf("expected ranked key person items, got %#v", body["items"])
	}
	first := items[0].(map[string]any)
	if first["person_id"] != "person:alice@example.com" {
		t.Fatalf("expected alice as top key-person risk, got %#v", first)
	}

	focused := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/key-person-risk?person_id=person:alice@example.com", nil)
	if focused.Code != http.StatusOK {
		t.Fatalf("expected 200 for focused key-person risk, got %d: %s", focused.Code, focused.Body.String())
	}
	focusedBody := decodeJSON(t, focused)
	if got := focusedBody["person_id"]; got != "person:alice@example.com" {
		t.Fatalf("expected focused person_id alice, got %#v", got)
	}

	missing := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/key-person-risk?person_id=person:missing@example.com", nil)
	if missing.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for missing person, got %d: %s", missing.Code, missing.Body.String())
	}
}

func TestPlatformGraphQueryEndpoint_NeighborsAndPaths(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph

	g.AddNode(&graph.Node{ID: "user:alice", Kind: graph.NodeKindUser, Name: "Alice"})
	g.AddNode(&graph.Node{ID: "role:admin", Kind: graph.NodeKindRole, Name: "Admin"})
	g.AddNode(&graph.Node{ID: "db:prod", Kind: graph.NodeKindDatabase, Name: "Prod", Risk: graph.RiskCritical})
	g.AddEdge(&graph.Edge{ID: "alice-admin", Source: "user:alice", Target: "role:admin", Kind: graph.EdgeKindCanAssume, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "admin-db", Source: "role:admin", Target: "db:prod", Kind: graph.EdgeKindCanRead, Effect: graph.EdgeEffectAllow})

	neighbors := do(t, s, http.MethodGet, "/api/v1/platform/graph/queries?mode=neighbors&node_id=user:alice&direction=out&limit=10", nil)
	if neighbors.Code != http.StatusOK {
		t.Fatalf("expected 200 neighbors, got %d: %s", neighbors.Code, neighbors.Body.String())
	}
	neighborsBody := decodeJSON(t, neighbors)
	if neighborsBody["mode"] != "neighbors" {
		t.Fatalf("expected neighbors mode, got %#v", neighborsBody["mode"])
	}
	if count, ok := neighborsBody["count"].(float64); !ok || count < 1 {
		t.Fatalf("expected at least one neighbor, got %#v", neighborsBody["count"])
	}

	paths := do(t, s, http.MethodGet, "/api/v1/platform/graph/queries?mode=paths&node_id=user:alice&target_id=db:prod&k=2&max_depth=6", nil)
	if paths.Code != http.StatusOK {
		t.Fatalf("expected 200 paths, got %d: %s", paths.Code, paths.Body.String())
	}
	pathsBody := decodeJSON(t, paths)
	if pathsBody["mode"] != "paths" {
		t.Fatalf("expected paths mode, got %#v", pathsBody["mode"])
	}
	if count, ok := pathsBody["count"].(float64); !ok || count < 1 {
		t.Fatalf("expected at least one path, got %#v", pathsBody["count"])
	}

	if got := neighbors.Header().Get("Deprecation"); got != "" {
		t.Fatalf("did not expect deprecation header on platform graph query endpoint, got %q", got)
	}
}

func TestPlatformGraphQueryEndpoint_PostAlias(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph

	g.AddNode(&graph.Node{ID: "user:alice", Kind: graph.NodeKindUser, Name: "Alice"})
	g.AddNode(&graph.Node{ID: "role:admin", Kind: graph.NodeKindRole, Name: "Admin"})
	g.AddNode(&graph.Node{ID: "db:prod", Kind: graph.NodeKindDatabase, Name: "Prod", Risk: graph.RiskCritical})
	g.AddEdge(&graph.Edge{ID: "alice-admin", Source: "user:alice", Target: "role:admin", Kind: graph.EdgeKindCanAssume, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "admin-db", Source: "role:admin", Target: "db:prod", Kind: graph.EdgeKindCanRead, Effect: graph.EdgeEffectAllow})

	w := do(t, s, http.MethodPost, "/api/v1/platform/graph/queries", map[string]any{
		"mode":      "paths",
		"node_id":   "user:alice",
		"target_id": "db:prod",
		"k":         2,
		"max_depth": 6,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for platform graph query alias, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)
	if body["mode"] != "paths" {
		t.Fatalf("expected paths mode, got %#v", body["mode"])
	}
	if count, ok := body["count"].(float64); !ok || count < 1 {
		t.Fatalf("expected at least one path, got %#v", body["count"])
	}
}

func TestPlatformGraphQueryEndpoint_TemporalScope(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph

	g.AddNode(&graph.Node{
		ID:   "user:alice",
		Kind: graph.NodeKindUser,
		Name: "Alice",
		Properties: map[string]any{
			"observed_at": "2026-03-01T00:00:00Z",
			"valid_from":  "2026-03-01T00:00:00Z",
		},
	})
	g.AddNode(&graph.Node{
		ID:   "role:admin",
		Kind: graph.NodeKindRole,
		Name: "Admin",
		Properties: map[string]any{
			"observed_at": "2026-03-01T00:00:00Z",
			"valid_from":  "2026-03-01T00:00:00Z",
			"valid_to":    "2026-03-05T00:00:00Z",
		},
	})
	g.AddNode(&graph.Node{
		ID:   "db:prod",
		Kind: graph.NodeKindDatabase,
		Name: "Prod",
		Properties: map[string]any{
			"observed_at": "2026-03-01T00:00:00Z",
			"valid_from":  "2026-03-01T00:00:00Z",
		},
		Risk: graph.RiskCritical,
	})
	g.AddEdge(&graph.Edge{
		ID:     "alice-admin",
		Source: "user:alice",
		Target: "role:admin",
		Kind:   graph.EdgeKindCanAssume,
		Effect: graph.EdgeEffectAllow,
		Properties: map[string]any{
			"observed_at": "2026-03-01T00:00:00Z",
			"valid_from":  "2026-03-01T00:00:00Z",
			"valid_to":    "2026-03-05T00:00:00Z",
		},
	})
	g.AddEdge(&graph.Edge{
		ID:     "admin-db",
		Source: "role:admin",
		Target: "db:prod",
		Kind:   graph.EdgeKindCanRead,
		Effect: graph.EdgeEffectAllow,
		Properties: map[string]any{
			"observed_at": "2026-03-01T00:00:00Z",
			"valid_from":  "2026-03-01T00:00:00Z",
			"valid_to":    "2026-03-05T00:00:00Z",
		},
	})

	asOfActive := do(t, s, http.MethodGet, "/api/v1/platform/graph/queries?mode=neighbors&node_id=user:alice&direction=out&as_of=2026-03-04T00:00:00Z", nil)
	if asOfActive.Code != http.StatusOK {
		t.Fatalf("expected 200 for as_of active query, got %d: %s", asOfActive.Code, asOfActive.Body.String())
	}
	activeBody := decodeJSON(t, asOfActive)
	if count, ok := activeBody["count"].(float64); !ok || count < 1 {
		t.Fatalf("expected active neighbors count >=1, got %#v", activeBody["count"])
	}

	asOfExpired := do(t, s, http.MethodGet, "/api/v1/platform/graph/queries?mode=neighbors&node_id=user:alice&direction=out&as_of=2026-03-08T00:00:00Z", nil)
	if asOfExpired.Code != http.StatusOK {
		t.Fatalf("expected 200 for expired as_of query, got %d: %s", asOfExpired.Code, asOfExpired.Body.String())
	}
	expiredBody := decodeJSON(t, asOfExpired)
	if count, ok := expiredBody["count"].(float64); !ok || count != 0 {
		t.Fatalf("expected expired neighbors count 0, got %#v", expiredBody["count"])
	}

	windowed := do(t, s, http.MethodGet, "/api/v1/platform/graph/queries?mode=paths&node_id=user:alice&target_id=db:prod&from=2026-03-01T00:00:00Z&to=2026-03-06T00:00:00Z", nil)
	if windowed.Code != http.StatusOK {
		t.Fatalf("expected 200 for windowed query, got %d: %s", windowed.Code, windowed.Body.String())
	}
	windowedBody := decodeJSON(t, windowed)
	if count, ok := windowedBody["count"].(float64); !ok || count < 1 {
		t.Fatalf("expected at least one path in window, got %#v", windowedBody["count"])
	}
}

func TestPlatformGraphQueryEndpoint_InvalidParams(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph
	g.AddNode(&graph.Node{ID: "user:alice", Kind: graph.NodeKindUser, Name: "Alice"})

	w := do(t, s, http.MethodGet, "/api/v1/platform/graph/queries", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing node_id, got %d", w.Code)
	}

	w = do(t, s, http.MethodGet, "/api/v1/platform/graph/queries?mode=unsupported&node_id=user:alice", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unsupported mode, got %d", w.Code)
	}

	w = do(t, s, http.MethodGet, "/api/v1/platform/graph/queries?mode=paths&node_id=user:alice", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing target_id in paths mode, got %d", w.Code)
	}

	w = do(t, s, http.MethodGet, "/api/v1/platform/graph/queries?mode=neighbors&node_id=user:missing", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for missing node, got %d", w.Code)
	}

	w = do(t, s, http.MethodGet, "/api/v1/platform/graph/queries?mode=neighbors&node_id=user:alice&as_of=not-a-time", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid as_of, got %d", w.Code)
	}

	w = do(t, s, http.MethodGet, "/api/v1/platform/graph/queries?mode=neighbors&node_id=user:alice&from=2026-03-01T00:00:00Z", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when from is missing to, got %d", w.Code)
	}
}

type evaluationTemporalAnalysisEndpointFixture struct {
	RunID        string
	Conversation string
	ServiceID    string
	BaseAt       time.Time
}

func addEvaluationTemporalAnalysisEndpointFixture(t *testing.T, g *graph.Graph, fixture evaluationTemporalAnalysisEndpointFixture) {
	t.Helper()
	if g == nil {
		t.Fatal("graph is required")
	}

	baseAt := fixture.BaseAt.UTC()
	threadID := "thread:evaluation:" + fixture.RunID + ":" + fixture.Conversation
	decisionID := "decision:evaluation:" + fixture.RunID + ":" + fixture.Conversation + ":turn-1"
	actionSuccessID := "action:evaluation:" + fixture.RunID + ":" + fixture.Conversation + ":call-1"
	actionReversedID := "action:evaluation:" + fixture.RunID + ":" + fixture.Conversation + ":call-2"
	outcomeID := "outcome:evaluation:" + fixture.RunID + ":" + fixture.Conversation

	g.AddNode(&graph.Node{
		ID:   fixture.ServiceID,
		Kind: graph.NodeKindService,
		Name: fixture.ServiceID,
		Properties: map[string]any{
			"service_id":       fixture.ServiceID,
			"observed_at":      baseAt.Add(-30 * time.Minute).Format(time.RFC3339),
			"valid_from":       baseAt.Add(-30 * time.Minute).Format(time.RFC3339),
			"recorded_at":      baseAt.Add(-30 * time.Minute).Format(time.RFC3339),
			"transaction_from": baseAt.Add(-30 * time.Minute).Format(time.RFC3339),
			"source_system":    "platform_eval",
		},
	})
	for _, evidenceID := range []string{
		"evidence:" + fixture.RunID + ":" + fixture.Conversation + ":exposure-before",
		"evidence:" + fixture.RunID + ":" + fixture.Conversation + ":exposure-after",
		"evidence:" + fixture.RunID + ":" + fixture.Conversation + ":tier-before",
		"evidence:" + fixture.RunID + ":" + fixture.Conversation + ":tier-after",
	} {
		g.AddNode(&graph.Node{
			ID:   evidenceID,
			Kind: graph.NodeKindEvidence,
			Name: evidenceID,
			Properties: map[string]any{
				"evidence_type":    "document",
				"observed_at":      baseAt.Add(-20 * time.Minute).Format(time.RFC3339),
				"valid_from":       baseAt.Add(-20 * time.Minute).Format(time.RFC3339),
				"recorded_at":      baseAt.Add(-20 * time.Minute).Format(time.RFC3339),
				"transaction_from": baseAt.Add(-20 * time.Minute).Format(time.RFC3339),
				"source_system":    "platform_eval",
			},
		})
	}

	g.AddNode(&graph.Node{
		ID:   threadID,
		Kind: graph.NodeKind("communication_thread"),
		Name: fixture.Conversation,
		Properties: map[string]any{
			"thread_id":         fixture.Conversation,
			"channel_id":        fixture.RunID,
			"conversation_id":   fixture.Conversation,
			"evaluation_run_id": fixture.RunID,
			"agent_email":       "agent@example.com",
			"observed_at":       baseAt.Format(time.RFC3339),
			"valid_from":        baseAt.Format(time.RFC3339),
			"source_system":     "platform_eval",
		},
	})
	g.AddNode(&graph.Node{
		ID:   decisionID,
		Kind: graph.NodeKindDecision,
		Name: "turn-1",
		Properties: map[string]any{
			"decision_type":     "tool_selection",
			"status":            "completed",
			"conversation_id":   fixture.Conversation,
			"evaluation_run_id": fixture.RunID,
			"turn_id":           "turn-1",
			"agent_email":       "agent@example.com",
			"made_at":           baseAt.Add(5 * time.Minute).Format(time.RFC3339),
			"observed_at":       baseAt.Add(5 * time.Minute).Format(time.RFC3339),
			"valid_from":        baseAt.Add(5 * time.Minute).Format(time.RFC3339),
			"source_system":     "platform_eval",
		},
	})
	g.AddNode(&graph.Node{
		ID:   actionSuccessID,
		Kind: graph.NodeKindAction,
		Name: "call-1",
		Properties: map[string]any{
			"action_type":       "tool_call",
			"status":            "succeeded",
			"conversation_id":   fixture.Conversation,
			"evaluation_run_id": fixture.RunID,
			"turn_id":           "turn-1",
			"tool_call_id":      "call-1",
			"agent_email":       "agent@example.com",
			"observed_at":       baseAt.Add(10 * time.Minute).Format(time.RFC3339),
			"valid_from":        baseAt.Add(10 * time.Minute).Format(time.RFC3339),
			"source_system":     "platform_eval",
		},
	})
	g.AddNode(&graph.Node{
		ID:   actionReversedID,
		Kind: graph.NodeKindAction,
		Name: "call-2",
		Properties: map[string]any{
			"action_type":       "tool_call",
			"status":            "reversed",
			"conversation_id":   fixture.Conversation,
			"evaluation_run_id": fixture.RunID,
			"turn_id":           "turn-1",
			"tool_call_id":      "call-2",
			"agent_email":       "agent@example.com",
			"observed_at":       baseAt.Add(12 * time.Minute).Format(time.RFC3339),
			"valid_from":        baseAt.Add(12 * time.Minute).Format(time.RFC3339),
			"source_system":     "platform_eval",
		},
	})
	g.AddNode(&graph.Node{
		ID:   outcomeID,
		Kind: graph.NodeKindOutcome,
		Name: "negative",
		Properties: map[string]any{
			"outcome_type":      "evaluation_conversation",
			"verdict":           "negative",
			"quality_score":     0.15,
			"conversation_id":   fixture.Conversation,
			"evaluation_run_id": fixture.RunID,
			"observed_at":       baseAt.Add(20 * time.Minute).Format(time.RFC3339),
			"valid_from":        baseAt.Add(20 * time.Minute).Format(time.RFC3339),
			"source_system":     "platform_eval",
		},
	})
	g.AddEdge(&graph.Edge{ID: "decision-target:" + fixture.Conversation, Source: decisionID, Target: threadID, Kind: graph.EdgeKindTargets, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "action1-based-on:" + fixture.Conversation, Source: actionSuccessID, Target: decisionID, Kind: graph.EdgeKindBasedOn, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "action2-based-on:" + fixture.Conversation, Source: actionReversedID, Target: decisionID, Kind: graph.EdgeKindBasedOn, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "outcome-target:" + fixture.Conversation, Source: outcomeID, Target: threadID, Kind: graph.EdgeKindTargets, Effect: graph.EdgeEffectAllow})

	writeClaim := func(req graph.ClaimWriteRequest) {
		if _, err := graph.WriteClaim(g, req); err != nil {
			t.Fatalf("write claim %q: %v", req.ID, err)
		}
	}

	writeClaim(graph.ClaimWriteRequest{
		ID:              "claim:evaluation:" + fixture.RunID + ":" + fixture.Conversation + ":exposure-before",
		SubjectID:       fixture.ServiceID,
		Predicate:       "exposure",
		ObjectValue:     "private",
		EvidenceIDs:     []string{"evidence:" + fixture.RunID + ":" + fixture.Conversation + ":exposure-before"},
		SourceName:      "eval",
		SourceType:      "system",
		SourceSystem:    "platform_eval",
		ObservedAt:      baseAt.Add(-10 * time.Minute),
		RecordedAt:      baseAt.Add(-10 * time.Minute),
		TransactionFrom: baseAt.Add(-10 * time.Minute),
		Metadata: map[string]any{
			"evaluation_run_id": fixture.RunID,
			"conversation_id":   fixture.Conversation,
		},
	})
	writeClaim(graph.ClaimWriteRequest{
		ID:              "claim:evaluation:" + fixture.RunID + ":" + fixture.Conversation + ":exposure-after",
		SubjectID:       fixture.ServiceID,
		Predicate:       "exposure",
		ObjectValue:     "public",
		EvidenceIDs:     []string{"evidence:" + fixture.RunID + ":" + fixture.Conversation + ":exposure-after"},
		SourceName:      "eval",
		SourceType:      "system",
		SourceSystem:    "platform_eval",
		ObservedAt:      baseAt.Add(18 * time.Minute),
		RecordedAt:      baseAt.Add(18 * time.Minute),
		TransactionFrom: baseAt.Add(18 * time.Minute),
		Metadata: map[string]any{
			"evaluation_run_id": fixture.RunID,
			"conversation_id":   fixture.Conversation,
		},
	})
	writeClaim(graph.ClaimWriteRequest{
		ID:              "claim:evaluation:" + fixture.RunID + ":" + fixture.Conversation + ":tier-before",
		SubjectID:       fixture.ServiceID,
		Predicate:       "service_tier",
		ObjectValue:     "tier1",
		EvidenceIDs:     []string{"evidence:" + fixture.RunID + ":" + fixture.Conversation + ":tier-before"},
		SourceName:      "eval",
		SourceType:      "system",
		SourceSystem:    "platform_eval",
		ObservedAt:      baseAt.Add(-5 * time.Minute),
		RecordedAt:      baseAt.Add(-5 * time.Minute),
		TransactionFrom: baseAt.Add(-5 * time.Minute),
		Metadata: map[string]any{
			"evaluation_run_id": fixture.RunID,
			"conversation_id":   fixture.Conversation,
		},
	})
	writeClaim(graph.ClaimWriteRequest{
		ID:                "claim:evaluation:" + fixture.RunID + ":" + fixture.Conversation + ":tier-after",
		SubjectID:         fixture.ServiceID,
		Predicate:         "service_tier",
		ObjectValue:       "tier0",
		EvidenceIDs:       []string{"evidence:" + fixture.RunID + ":" + fixture.Conversation + ":tier-after"},
		SupersedesClaimID: "claim:evaluation:" + fixture.RunID + ":" + fixture.Conversation + ":tier-before",
		SourceName:        "eval",
		SourceType:        "system",
		SourceSystem:      "platform_eval",
		ObservedAt:        baseAt.Add(19 * time.Minute),
		RecordedAt:        baseAt.Add(19 * time.Minute),
		TransactionFrom:   baseAt.Add(19 * time.Minute),
		Metadata: map[string]any{
			"evaluation_run_id": fixture.RunID,
			"conversation_id":   fixture.Conversation,
		},
	})
}

func tagEvaluationTemporalAnalysisEndpointTenant(t *testing.T, g *graph.Graph, runID, conversationID, tenantID string) {
	t.Helper()
	nodeIDs := []string{
		"thread:evaluation:" + runID + ":" + conversationID,
		"decision:evaluation:" + runID + ":" + conversationID + ":turn-1",
		"action:evaluation:" + runID + ":" + conversationID + ":call-1",
		"action:evaluation:" + runID + ":" + conversationID + ":call-2",
		"outcome:evaluation:" + runID + ":" + conversationID,
		"claim:evaluation:" + runID + ":" + conversationID + ":exposure-before",
		"claim:evaluation:" + runID + ":" + conversationID + ":exposure-after",
		"claim:evaluation:" + runID + ":" + conversationID + ":tier-before",
		"claim:evaluation:" + runID + ":" + conversationID + ":tier-after",
	}
	for _, nodeID := range nodeIDs {
		node, ok := g.GetNode(nodeID)
		if !ok || node == nil {
			continue
		}
		if node.Properties == nil {
			node.Properties = make(map[string]any)
		}
		node.Properties["tenant_id"] = tenantID
	}
}

type playbookEffectivenessEndpointFixture struct {
	RunID        string
	PlaybookID   string
	PlaybookName string
	TenantID     string
	TargetID     string
	TargetKind   graph.NodeKind
	StartedAt    time.Time
	Stages       []playbookEffectivenessEndpointStage
	Outcome      *playbookEffectivenessEndpointOutcome
}

type playbookEffectivenessEndpointStage struct {
	ID               string
	Name             string
	Order            int
	Status           string
	ApprovalRequired bool
	ApprovalStatus   string
	ObservedAt       time.Time
}

type playbookEffectivenessEndpointOutcome struct {
	Verdict       string
	Status        string
	RollbackState string
	ObservedAt    time.Time
}

func addPlaybookEffectivenessEndpointFixture(t *testing.T, g *graph.Graph, fixture playbookEffectivenessEndpointFixture) {
	t.Helper()
	if g == nil {
		t.Fatal("graph is nil")
	}

	if fixture.TargetID != "" {
		g.AddNode(&graph.Node{
			ID:   fixture.TargetID,
			Kind: fixture.TargetKind,
			Name: fixture.TargetID,
			Properties: map[string]any{
				"observed_at": fixture.StartedAt.Format(time.RFC3339),
				"valid_from":  fixture.StartedAt.Format(time.RFC3339),
			},
		})
	}

	targetIDs := []string{}
	if fixture.TargetID != "" {
		targetIDs = append(targetIDs, fixture.TargetID)
	}

	threadID := "thread:playbook:" + fixture.RunID
	g.AddNode(&graph.Node{
		ID:   threadID,
		Kind: graph.NodeKind("communication_thread"),
		Name: fixture.PlaybookName,
		Properties: map[string]any{
			"thread_id":       fixture.RunID,
			"channel_id":      fixture.PlaybookID,
			"channel_name":    "playbook",
			"playbook_id":     fixture.PlaybookID,
			"playbook_name":   fixture.PlaybookName,
			"playbook_run_id": fixture.RunID,
			"status":          "started",
			"tenant_id":       fixture.TenantID,
			"target_ids":      targetIDs,
			"source_system":   "platform_playbook",
			"observed_at":     fixture.StartedAt.Format(time.RFC3339),
			"valid_from":      fixture.StartedAt.Format(time.RFC3339),
		},
	})

	lastStageID := ""
	for _, stage := range fixture.Stages {
		decisionID := "decision:playbook:" + fixture.RunID + ":" + stage.ID
		g.AddNode(&graph.Node{
			ID:   decisionID,
			Kind: graph.NodeKindDecision,
			Name: stage.Name,
			Properties: map[string]any{
				"decision_type":     "playbook_stage",
				"playbook_id":       fixture.PlaybookID,
				"playbook_name":     fixture.PlaybookName,
				"playbook_run_id":   fixture.RunID,
				"stage_id":          stage.ID,
				"stage_name":        stage.Name,
				"stage_order":       stage.Order,
				"status":            stage.Status,
				"approval_required": stage.ApprovalRequired,
				"approval_status":   stage.ApprovalStatus,
				"tenant_id":         fixture.TenantID,
				"target_ids":        targetIDs,
				"source_system":     "platform_playbook",
				"made_at":           stage.ObservedAt.Format(time.RFC3339),
				"observed_at":       stage.ObservedAt.Format(time.RFC3339),
				"valid_from":        stage.ObservedAt.Format(time.RFC3339),
			},
		})
		g.AddEdge(&graph.Edge{ID: "decision-thread:" + fixture.RunID + ":" + stage.ID, Source: decisionID, Target: threadID, Kind: graph.EdgeKindTargets, Effect: graph.EdgeEffectAllow})
		lastStageID = stage.ID
	}

	if fixture.Outcome != nil {
		outcomeID := "outcome:playbook:" + fixture.RunID
		g.AddNode(&graph.Node{
			ID:   outcomeID,
			Kind: graph.NodeKindOutcome,
			Name: fixture.PlaybookName + " " + fixture.Outcome.Verdict,
			Properties: map[string]any{
				"outcome_type":    "playbook_run",
				"playbook_id":     fixture.PlaybookID,
				"playbook_name":   fixture.PlaybookName,
				"playbook_run_id": fixture.RunID,
				"verdict":         fixture.Outcome.Verdict,
				"status":          fixture.Outcome.Status,
				"rollback_state":  fixture.Outcome.RollbackState,
				"tenant_id":       fixture.TenantID,
				"target_ids":      targetIDs,
				"source_system":   "platform_playbook",
				"observed_at":     fixture.Outcome.ObservedAt.Format(time.RFC3339),
				"valid_from":      fixture.Outcome.ObservedAt.Format(time.RFC3339),
			},
		})
		g.AddEdge(&graph.Edge{ID: "outcome-thread:" + fixture.RunID, Source: outcomeID, Target: threadID, Kind: graph.EdgeKindTargets, Effect: graph.EdgeEffectAllow})
		if lastStageID != "" {
			g.AddEdge(&graph.Edge{ID: "outcome-evaluates:" + fixture.RunID, Source: outcomeID, Target: "decision:playbook:" + fixture.RunID + ":" + lastStageID, Kind: graph.EdgeKindEvaluates, Effect: graph.EdgeEffectAllow})
		}
	}
}

func tagEvaluationTemporalAnalysisEndpointStageFixture(t *testing.T, g *graph.Graph, runID, conversationID string) {
	t.Helper()
	stageProperties := map[string]map[string]any{
		"decision:evaluation:" + runID + ":" + conversationID + ":turn-1": {
			"stage_id": "stage-2",
		},
		"action:evaluation:" + runID + ":" + conversationID + ":call-1": {
			"stage_id": "stage-1",
		},
		"action:evaluation:" + runID + ":" + conversationID + ":call-2": {
			"stage_id": "stage-2",
		},
		"outcome:evaluation:" + runID + ":" + conversationID: {
			"final_stage_id": "stage-2",
		},
		"claim:evaluation:" + runID + ":" + conversationID + ":exposure-before": {
			"stage_id": "stage-1",
		},
		"claim:evaluation:" + runID + ":" + conversationID + ":exposure-after": {
			"stage_id": "stage-2",
		},
		"claim:evaluation:" + runID + ":" + conversationID + ":tier-before": {
			"stage_id": "stage-1",
		},
		"claim:evaluation:" + runID + ":" + conversationID + ":tier-after": {
			"stage_id":             "stage-2",
			"previous_stage_id":    "stage-1",
			"supersedes_stage_id":  "stage-1",
			"contradicts_stage_id": "stage-1",
		},
	}
	for nodeID, props := range stageProperties {
		node, ok := g.GetNode(nodeID)
		if !ok {
			t.Fatalf("expected node %q to exist", nodeID)
		}
		if node.Properties == nil {
			node.Properties = make(map[string]any)
		}
		for key, value := range props {
			node.Properties[key] = value
		}
	}
}
