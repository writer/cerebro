package api

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/graph"
)

func buildGraphStorePlatformEntitiesTestGraph(t *testing.T) *graph.Graph {
	t.Helper()

	base := time.Date(2026, 3, 10, 9, 0, 0, 0, time.UTC)
	baseProps := map[string]any{
		"observed_at":      base.UTC().Format(time.RFC3339),
		"valid_from":       base.UTC().Format(time.RFC3339),
		"recorded_at":      base.UTC().Format(time.RFC3339),
		"transaction_from": base.UTC().Format(time.RFC3339),
	}

	g := graph.New()
	g.AddNode(&graph.Node{
		ID:       "service:payments",
		Kind:     graph.NodeKindService,
		Name:     "Payments",
		Provider: "aws",
		Account:  "123456789012",
		Region:   "us-east-1",
		Risk:     graph.RiskHigh,
		Findings: []string{"finding:public-endpoint"},
		Tags:     map[string]string{"env": "prod"},
		Properties: map[string]any{
			"status":           "degraded",
			"owner":            "team-payments",
			"observed_at":      base.Add(2 * time.Hour).UTC().Format(time.RFC3339),
			"valid_from":       base.UTC().Format(time.RFC3339),
			"recorded_at":      base.UTC().Format(time.RFC3339),
			"transaction_from": base.UTC().Format(time.RFC3339),
		},
	})
	g.AddNode(&graph.Node{
		ID:       "arn:aws:s3:::audit-logs",
		Kind:     graph.NodeKindBucket,
		Name:     "Audit Logs",
		Provider: "aws",
		Account:  "123456789012",
		Region:   "us-east-1",
		Risk:     graph.RiskLow,
		Tags:     map[string]string{"env": "prod"},
		Properties: map[string]any{
			"bucket_name":       "audit-logs",
			"encrypted":         true,
			"block_public_acls": true,
			"observed_at":       base.UTC().Format(time.RFC3339),
			"valid_from":        base.UTC().Format(time.RFC3339),
			"recorded_at":       base.UTC().Format(time.RFC3339),
			"transaction_from":  base.UTC().Format(time.RFC3339),
		},
	})
	g.AddNode(&graph.Node{
		ID:         "person:alice@example.com",
		Kind:       graph.NodeKindPerson,
		Name:       "Alice Example",
		Provider:   "workspace",
		Properties: cloneJSONMap(baseProps),
	})
	g.AddNode(&graph.Node{
		ID:         "database:payments",
		Kind:       graph.NodeKindDatabase,
		Name:       "Payments DB",
		Provider:   "aws",
		Account:    "123456789012",
		Region:     "us-east-1",
		Risk:       graph.RiskMedium,
		Tags:       map[string]string{"env": "prod"},
		Properties: cloneJSONMap(baseProps),
	})
	g.AddEdge(&graph.Edge{
		ID:         "service:payments->database:payments:depends_on",
		Source:     "service:payments",
		Target:     "database:payments",
		Kind:       graph.EdgeKindDependsOn,
		Effect:     graph.EdgeEffectAllow,
		Properties: cloneJSONMap(baseProps),
	})
	g.BuildIndex()

	node, ok := g.GetNode("service:payments")
	if !ok || node == nil {
		t.Fatal("expected seeded service node")
	}
	node.PropertyHistory = map[string][]graph.PropertySnapshot{
		"status": {
			{Timestamp: base, Value: "healthy"},
			{Timestamp: base.Add(2 * time.Hour), Value: "degraded"},
		},
		"owner": {
			{Timestamp: base.Add(2 * time.Hour), Value: "team-payments"},
		},
	}

	return g
}

func TestPlatformEntityHandlersUseGraphStoreWhenRawGraphUnavailable(t *testing.T) {
	s := newStoreBackedGraphServer(t, buildGraphStorePlatformEntitiesTestGraph(t))

	list := do(t, s, http.MethodGet, "/api/v1/platform/entities?category=resource&provider=aws&tag_key=env&tag_value=prod&limit=10", nil)
	if list.Code != http.StatusOK {
		t.Fatalf("expected entity list 200, got %d: %s", list.Code, list.Body.String())
	}
	listBody := decodeJSON(t, list)
	if got := int(listBody["count"].(float64)); got < 2 {
		t.Fatalf("expected store-backed entity list results, got %#v", listBody)
	}

	search := do(t, s, http.MethodGet, "/api/v1/platform/entities/search?q=audit+logs&limit=5", nil)
	if search.Code != http.StatusOK {
		t.Fatalf("expected entity search 200, got %d: %s", search.Code, search.Body.String())
	}
	searchBody := decodeJSON(t, search)
	if got := int(searchBody["count"].(float64)); got < 1 {
		t.Fatalf("expected store-backed search results, got %#v", searchBody)
	}

	suggest := do(t, s, http.MethodGet, "/api/v1/platform/entities/suggest?prefix=ali&limit=5", nil)
	if suggest.Code != http.StatusOK {
		t.Fatalf("expected entity suggest 200, got %d: %s", suggest.Code, suggest.Body.String())
	}
	suggestBody := decodeJSON(t, suggest)
	if got := int(suggestBody["count"].(float64)); got < 1 {
		t.Fatalf("expected store-backed suggestions, got %#v", suggestBody)
	}

	detail := do(t, s, http.MethodGet, "/api/v1/platform/entities/service:payments", nil)
	if detail.Code != http.StatusOK {
		t.Fatalf("expected entity detail 200, got %d: %s", detail.Code, detail.Body.String())
	}
	detailBody := decodeJSON(t, detail)
	if got := detailBody["id"]; got != "service:payments" {
		t.Fatalf("expected store-backed entity detail, got %#v", detailBody)
	}

	g, err := s.currentTenantSecurityGraphView(context.Background())
	if err != nil {
		t.Fatalf("currentTenantSecurityGraphView() error = %v", err)
	}
	node, ok := g.GetNode("service:payments")
	if !ok || node == nil {
		t.Fatal("expected store-backed graph view node")
	}
	t.Logf("store-backed property history: %#v", node.PropertyHistory)

	at := do(t, s, http.MethodGet, "/api/v1/platform/entities/service:payments/at?timestamp=2026-03-10T09:30:00Z", nil)
	if at.Code != http.StatusOK {
		t.Fatalf("expected entity at-time 200, got %d: %s", at.Code, at.Body.String())
	}
	atBody := decodeJSON(t, at)
	entity, ok := atBody["entity"].(map[string]any)
	if !ok {
		t.Fatalf("expected entity block from store-backed at-time handler, got %#v", atBody)
	}
	properties, ok := entity["properties"].(map[string]any)
	if !ok {
		t.Fatalf("expected entity properties from store-backed at-time handler, got %#v", atBody)
	}
	if got := properties["status"]; got != "healthy" {
		t.Fatalf("expected historical status from store-backed handler, got %#v", got)
	}

	diff := do(t, s, http.MethodGet, "/api/v1/platform/entities/service:payments/diff?from=2026-03-10T09:00:00Z&to=2026-03-10T12:00:00Z", nil)
	if diff.Code != http.StatusOK {
		t.Fatalf("expected entity diff 200, got %d: %s", diff.Code, diff.Body.String())
	}
	diffBody := decodeJSON(t, diff)
	if got := len(diffBody["changed_keys"].([]any)); got < 2 {
		t.Fatalf("expected store-backed entity diff changes, got %#v", diffBody)
	}
}
