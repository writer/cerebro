package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/graph"
)

func TestGraphOutcomeAndFeedbackEndpoints(t *testing.T) {
	s := newTestServer(t)
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
		"metadata": map[string]any{
			"source": "crm",
		},
	})
	if record.Code != http.StatusOK {
		t.Fatalf("expected 200 from outcomes POST, got %d: %s", record.Code, record.Body.String())
	}
	recordBody := decodeJSON(t, record)
	if _, ok := recordBody["recorded"]; !ok {
		t.Fatalf("expected recorded payload, got %+v", recordBody)
	}

	list := do(t, s, http.MethodGet, "/api/v1/graph/outcomes?entity_id=customer:acme", nil)
	if list.Code != http.StatusOK {
		t.Fatalf("expected 200 from outcomes list, got %d: %s", list.Code, list.Body.String())
	}
	listBody := decodeJSON(t, list)
	if count, ok := listBody["count"].(float64); !ok || count < 1 {
		t.Fatalf("expected at least one outcome, got %+v", listBody)
	}

	feedback := do(t, s, http.MethodGet, "/api/v1/graph/risk-feedback?window_days=365&profile=revenue-heavy", nil)
	if feedback.Code != http.StatusOK {
		t.Fatalf("expected 200 from risk feedback, got %d: %s", feedback.Code, feedback.Body.String())
	}
	feedbackBody := decodeJSON(t, feedback)
	if count, ok := feedbackBody["outcome_count"].(float64); !ok || count < 1 {
		t.Fatalf("expected outcome_count >= 1, got %+v", feedbackBody["outcome_count"])
	}
	if profile, _ := feedbackBody["profile"].(string); profile != "revenue-heavy" {
		t.Fatalf("expected profile revenue-heavy, got %q", profile)
	}
	if metrics, ok := feedbackBody["rule_effectiveness"].([]any); !ok || len(metrics) == 0 {
		t.Fatalf("expected rule_effectiveness metrics, got %+v", feedbackBody["rule_effectiveness"])
	}
}

func TestGraphOutcomeEndpoint_RejectsInvalidPayload(t *testing.T) {
	s := newTestServer(t)
	seedGraphRiskFeedbackGraph(s.app.SecurityGraph)

	w := do(t, s, http.MethodPost, "/api/v1/graph/outcomes", map[string]any{
		"entity_id": "customer:missing",
		"outcome":   "churn",
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown entity, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGraphRiskFeedbackEndpoint_RejectsInvalidWindow(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodGet, "/api/v1/graph/risk-feedback?window_days=abc", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid window_days, got %d: %s", w.Code, w.Body.String())
	}
}

func seedGraphRiskFeedbackGraph(g *graph.Graph) {
	g.AddNode(&graph.Node{
		ID:   "customer:acme",
		Kind: graph.NodeKindCustomer,
		Name: "Acme",
		Properties: map[string]any{
			"failed_payment_count":     3,
			"open_p1_tickets":          2,
			"days_since_last_activity": 42,
		},
	})
	g.AddNode(&graph.Node{
		ID:   "deal:acme-renewal",
		Kind: graph.NodeKindDeal,
		Name: "Acme Renewal",
		Properties: map[string]any{
			"amount":                   180000,
			"days_since_last_activity": 35,
		},
	})
	g.AddEdge(&graph.Edge{
		ID:     "customer-acme-deal",
		Source: "customer:acme",
		Target: "deal:acme-renewal",
		Kind:   graph.EdgeKindOwns,
		Effect: graph.EdgeEffectAllow,
	})
}
