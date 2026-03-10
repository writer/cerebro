package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/graph"
)

func TestPlatformEntitiesListAndDetail(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph
	baseAt := time.Date(2026, 3, 10, 9, 0, 0, 0, time.UTC)
	baseProps := map[string]any{
		"observed_at":      baseAt.UTC().Format(time.RFC3339),
		"valid_from":       baseAt.UTC().Format(time.RFC3339),
		"recorded_at":      baseAt.UTC().Format(time.RFC3339),
		"transaction_from": baseAt.UTC().Format(time.RFC3339),
	}

	g.AddNode(&graph.Node{
		ID:         "service:payments",
		Kind:       graph.NodeKindService,
		Name:       "Payments",
		Provider:   "aws",
		Account:    "123456789012",
		Region:     "us-east-1",
		Risk:       graph.RiskHigh,
		Findings:   []string{"finding:public-endpoint"},
		Tags:       map[string]string{"env": "prod"},
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
	g.AddNode(&graph.Node{
		ID:         "bucket:logs",
		Kind:       graph.NodeKindBucket,
		Name:       "Audit Logs",
		Provider:   "aws",
		Account:    "123456789012",
		Region:     "us-east-1",
		Risk:       graph.RiskLow,
		Tags:       map[string]string{"env": "prod"},
		Properties: cloneJSONMap(baseProps),
	})
	g.AddNode(&graph.Node{ID: "person:alice@example.com", Kind: graph.NodeKindPerson, Name: "Alice", Properties: cloneJSONMap(baseProps)})
	g.AddNode(&graph.Node{ID: "person:bob@example.com", Kind: graph.NodeKindPerson, Name: "Bob", Properties: cloneJSONMap(baseProps)})
	g.AddEdge(&graph.Edge{
		ID:         "service:payments->database:payments:depends_on",
		Source:     "service:payments",
		Target:     "database:payments",
		Kind:       graph.EdgeKindDependsOn,
		Effect:     graph.EdgeEffectAllow,
		Properties: cloneJSONMap(baseProps),
	})
	g.AddNode(&graph.Node{
		ID:         "evidence:runbook",
		Kind:       graph.NodeKindEvidence,
		Name:       "Runbook",
		Provider:   "cmdb",
		Properties: map[string]any{"evidence_type": "document", "observed_at": baseAt.UTC().Format(time.RFC3339), "valid_from": baseAt.UTC().Format(time.RFC3339), "recorded_at": baseAt.UTC().Format(time.RFC3339), "transaction_from": baseAt.UTC().Format(time.RFC3339)},
	})
	if _, err := graph.WriteObservation(g, graph.ObservationWriteRequest{
		ID:              "observation:payments:manual-review",
		SubjectID:       "service:payments",
		ObservationType: "manual_review_signal",
		Summary:         "Analyst confirmed service ownership context",
		SourceSystem:    "analyst",
		ObservedAt:      baseAt.Add(30 * time.Minute),
		ValidFrom:       baseAt.Add(30 * time.Minute),
		RecordedAt:      baseAt.Add(30 * time.Minute),
		TransactionFrom: baseAt.Add(30 * time.Minute),
	}); err != nil {
		t.Fatalf("write observation: %v", err)
	}
	if _, err := graph.WriteClaim(g, graph.ClaimWriteRequest{
		ID:              "claim:payments:owner:alice",
		SubjectID:       "service:payments",
		Predicate:       "owner",
		ObjectID:        "person:alice@example.com",
		EvidenceIDs:     []string{"evidence:runbook"},
		SourceName:      "CMDB",
		SourceType:      "system",
		SourceSystem:    "cmdb",
		ObservedAt:      baseAt.Add(45 * time.Minute),
		ValidFrom:       baseAt.Add(45 * time.Minute),
		RecordedAt:      baseAt.Add(45 * time.Minute),
		TransactionFrom: baseAt.Add(45 * time.Minute),
	}); err != nil {
		t.Fatalf("write alice claim: %v", err)
	}
	if _, err := graph.WriteClaim(g, graph.ClaimWriteRequest{
		ID:              "claim:payments:owner:bob",
		SubjectID:       "service:payments",
		Predicate:       "owner",
		ObjectID:        "person:bob@example.com",
		SourceSystem:    "slack",
		ObservedAt:      baseAt.Add(90 * time.Minute),
		ValidFrom:       baseAt.Add(90 * time.Minute),
		RecordedAt:      baseAt.Add(90 * time.Minute),
		TransactionFrom: baseAt.Add(90 * time.Minute),
	}); err != nil {
		t.Fatalf("write bob claim: %v", err)
	}

	list := do(t, s, http.MethodGet, "/api/v1/platform/entities?category=resource&provider=aws&tag_key=env&tag_value=prod&limit=2", nil)
	if list.Code != http.StatusOK {
		t.Fatalf("expected 200 for entity list, got %d: %s", list.Code, list.Body.String())
	}
	listBody := decodeJSON(t, list)
	if listBody["count"].(float64) != 2 {
		t.Fatalf("expected page size 2, got %#v", listBody["count"])
	}
	pagination := listBody["pagination"].(map[string]any)
	if pagination["total"].(float64) != 3 || pagination["has_more"] != true {
		t.Fatalf("unexpected pagination: %#v", pagination)
	}
	summary := listBody["summary"].(map[string]any)
	if summary["knowledge_backed_entities"].(float64) != 1 || summary["resource_entities"].(float64) != 3 {
		t.Fatalf("unexpected entity summary: %#v", summary)
	}
	entities := listBody["entities"].([]any)
	first := entities[0].(map[string]any)
	if first["id"] != "service:payments" {
		t.Fatalf("expected high-risk service first, got %#v", first["id"])
	}

	detail := do(t, s, http.MethodGet, "/api/v1/platform/entities/service:payments", nil)
	if detail.Code != http.StatusOK {
		t.Fatalf("expected 200 for entity detail, got %d: %s", detail.Code, detail.Body.String())
	}
	detailBody := decodeJSON(t, detail)
	knowledge := detailBody["knowledge"].(map[string]any)
	if knowledge["claim_count"].(float64) != 2 || knowledge["evidence_count"].(float64) != 1 || knowledge["observation_count"].(float64) != 1 {
		t.Fatalf("unexpected knowledge block: %#v", knowledge)
	}
	relationships := detailBody["relationships"].([]any)
	if len(relationships) == 0 {
		t.Fatalf("expected relationship summaries, got %#v", detailBody["relationships"])
	}
	relationship := relationships[0].(map[string]any)
	if relationship["edge_kind"] != string(graph.EdgeKindDependsOn) {
		t.Fatalf("expected depends_on relationship, got %#v", relationship)
	}
}

func TestPlatformEntitiesRejectInvalidParams(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodGet, "/api/v1/platform/entities?risk=unknown", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid risk, got %d: %s", w.Code, w.Body.String())
	}

	w = do(t, s, http.MethodGet, "/api/v1/platform/entities?has_findings=maybe", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid has_findings, got %d: %s", w.Code, w.Body.String())
	}

	w = do(t, s, http.MethodGet, "/api/v1/platform/entities/service:payments?valid_at=nope", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid valid_at, got %d: %s", w.Code, w.Body.String())
	}
}
