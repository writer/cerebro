package app

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/agents"
	"github.com/evalops/cerebro/internal/findings"
	"github.com/evalops/cerebro/internal/graph"
	"github.com/evalops/cerebro/internal/policy"
)

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

	result, err := tool.Handler(context.Background(), json.RawMessage(`{"identity_id":"user:alice","created_by":"ensemble-test"}`))
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
	if payload["created_by"] != "ensemble-test" {
		t.Fatalf("expected created_by ensemble-test, got %#v", payload["created_by"])
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
