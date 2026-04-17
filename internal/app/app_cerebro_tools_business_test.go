package app

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/graph"
)

func TestCerebroKeyPersonRiskTool(t *testing.T) {
	now := time.Now().UTC()
	g := graph.New()
	g.AddNode(&graph.Node{ID: "person:alice@example.com", Kind: graph.NodeKindPerson, Name: "Alice", Properties: map[string]any{"department": "engineering"}})
	g.AddNode(&graph.Node{ID: "person:bob@example.com", Kind: graph.NodeKindPerson, Name: "Bob", Properties: map[string]any{"department": "engineering"}})
	g.AddNode(&graph.Node{ID: "svc:core", Kind: graph.NodeKindApplication, Name: "Core"})
	g.AddNode(&graph.Node{ID: "customer:acme", Kind: graph.NodeKindCustomer, Name: "Acme", Properties: map[string]any{"arr": 100000.0}})
	g.AddEdge(&graph.Edge{ID: "alice-core", Source: "person:alice@example.com", Target: "svc:core", Kind: graph.EdgeKindCanAdmin, Properties: map[string]any{"last_seen": now.Add(-time.Hour)}})
	g.AddEdge(&graph.Edge{ID: "alice-acme", Source: "person:alice@example.com", Target: "customer:acme", Kind: graph.EdgeKindManagedBy, Properties: map[string]any{"last_seen": now.Add(-time.Hour)}})
	g.AddEdge(&graph.Edge{ID: "alice-bob", Source: "person:alice@example.com", Target: "person:bob@example.com", Kind: graph.EdgeKindInteractedWith, Properties: map[string]any{"last_seen": now.Add(-time.Hour)}})

	application := &App{SecurityGraph: g, Config: &Config{}}
	tool := findCerebroTool(application.AgentSDKTools(), "cerebro.key_person_risk")
	if tool == nil {
		t.Fatal("expected cerebro.key_person_risk tool")
		return
	}

	result, err := tool.Handler(context.Background(), json.RawMessage(`{"limit":5}`))
	if err != nil {
		t.Fatalf("key_person_risk returned error: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(result), &payload); err != nil {
		t.Fatalf("decode key_person_risk payload: %v", err)
	}
	items, ok := payload["items"].([]any)
	if !ok || len(items) == 0 {
		t.Fatalf("expected ranked items, got %#v", payload["items"])
	}
	first := items[0].(map[string]any)
	if first["person_id"] != "person:alice@example.com" {
		t.Fatalf("expected alice as top risk, got %#v", first)
	}

	focused, err := tool.Handler(context.Background(), json.RawMessage(`{"person_id":"person:alice@example.com"}`))
	if err != nil {
		t.Fatalf("focused key_person_risk returned error: %v", err)
	}
	var focusedPayload map[string]any
	if err := json.Unmarshal([]byte(focused), &focusedPayload); err != nil {
		t.Fatalf("decode focused payload: %v", err)
	}
	if got := focusedPayload["person_id"]; got != "person:alice@example.com" {
		t.Fatalf("expected focused person_id alice, got %#v", got)
	}
}
