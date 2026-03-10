package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/graph"
)

func TestPlatformKnowledgeClaimsList(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph

	baseProperties := map[string]any{
		"observed_at":      "2026-03-09T00:00:00Z",
		"valid_from":       "2026-03-09T00:00:00Z",
		"recorded_at":      "2026-03-09T00:00:00Z",
		"transaction_from": "2026-03-09T00:00:00Z",
	}
	g.AddNode(&graph.Node{ID: "service:payments", Kind: graph.NodeKindService, Name: "Payments", Properties: cloneJSONMap(baseProperties)})
	g.AddNode(&graph.Node{ID: "person:alice@example.com", Kind: graph.NodeKindPerson, Name: "Alice", Properties: cloneJSONMap(baseProperties)})
	g.AddNode(&graph.Node{ID: "person:bob@example.com", Kind: graph.NodeKindPerson, Name: "Bob", Properties: cloneJSONMap(baseProperties)})
	evidenceProps := cloneJSONMap(baseProperties)
	evidenceProps["evidence_type"] = "document"
	g.AddNode(&graph.Node{ID: "evidence:runbook", Kind: graph.NodeKindEvidence, Name: "Runbook", Properties: evidenceProps})

	recordedA := time.Date(2026, 3, 9, 10, 0, 0, 0, time.UTC)
	recordedB := time.Date(2026, 3, 9, 11, 0, 0, 0, time.UTC)
	if _, err := graph.WriteClaim(g, graph.ClaimWriteRequest{
		ID:              "claim:payments:owner:alice",
		SubjectID:       "service:payments",
		Predicate:       "owner",
		ObjectID:        "person:alice@example.com",
		EvidenceIDs:     []string{"evidence:runbook"},
		SourceName:      "CMDB",
		SourceType:      "system",
		SourceSystem:    "cmdb",
		ObservedAt:      recordedA,
		ValidFrom:       recordedA,
		RecordedAt:      recordedA,
		TransactionFrom: recordedA,
	}); err != nil {
		t.Fatalf("write claim alice: %v", err)
	}
	if _, err := graph.WriteClaim(g, graph.ClaimWriteRequest{
		ID:              "claim:payments:owner:bob",
		SubjectID:       "service:payments",
		Predicate:       "owner",
		ObjectID:        "person:bob@example.com",
		SourceSystem:    "api",
		ObservedAt:      recordedB,
		ValidFrom:       recordedB,
		RecordedAt:      recordedB,
		TransactionFrom: recordedB,
	}); err != nil {
		t.Fatalf("write claim bob: %v", err)
	}

	w := do(t, s, http.MethodGet, "/api/v1/platform/knowledge/claims?subject_id=service:payments&conflicted=true&limit=1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for claim list, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	if body["count"] != float64(1) {
		t.Fatalf("expected count=1, got %#v", body["count"])
	}
	pagination, ok := body["pagination"].(map[string]any)
	if !ok {
		t.Fatalf("expected pagination object, got %#v", body["pagination"])
	}
	if pagination["total"] != float64(2) || pagination["has_more"] != true {
		t.Fatalf("unexpected pagination: %#v", pagination)
	}
	summary, ok := body["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary object, got %#v", body["summary"])
	}
	if summary["conflicted_claims"] != float64(2) {
		t.Fatalf("expected conflicted_claims=2, got %#v", summary)
	}

	claims, ok := body["claims"].([]any)
	if !ok || len(claims) != 1 {
		t.Fatalf("expected one claim record, got %#v", body["claims"])
	}
	first, ok := claims[0].(map[string]any)
	if !ok {
		t.Fatalf("expected claim object, got %#v", claims[0])
	}
	if first["id"] != "claim:payments:owner:bob" {
		t.Fatalf("expected newest claim first, got %#v", first["id"])
	}
	derived, ok := first["derived"].(map[string]any)
	if !ok || derived["conflicted"] != true || derived["supported"] != false {
		t.Fatalf("unexpected derived state: %#v", first["derived"])
	}
	links, ok := first["links"].(map[string]any)
	if !ok {
		t.Fatalf("expected links object, got %#v", first["links"])
	}
	peers, ok := links["conflicting_claim_ids"].([]any)
	if !ok || len(peers) != 1 || peers[0] != "claim:payments:owner:alice" {
		t.Fatalf("expected conflicting peer for bob claim, got %#v", links["conflicting_claim_ids"])
	}
}

func TestPlatformKnowledgeClaimDetailRespectsRecordedAt(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph

	baseProperties := map[string]any{
		"observed_at":      "2026-03-09T00:00:00Z",
		"valid_from":       "2026-03-09T00:00:00Z",
		"recorded_at":      "2026-03-09T00:00:00Z",
		"transaction_from": "2026-03-09T00:00:00Z",
	}
	g.AddNode(&graph.Node{ID: "service:payments", Kind: graph.NodeKindService, Name: "Payments", Properties: cloneJSONMap(baseProperties)})
	g.AddNode(&graph.Node{ID: "person:alice@example.com", Kind: graph.NodeKindPerson, Name: "Alice", Properties: cloneJSONMap(baseProperties)})

	recordedAt := time.Date(2026, 3, 9, 12, 0, 0, 0, time.UTC)
	if _, err := graph.WriteClaim(g, graph.ClaimWriteRequest{
		ID:              "claim:payments:owner:alice",
		SubjectID:       "service:payments",
		Predicate:       "owner",
		ObjectID:        "person:alice@example.com",
		SourceSystem:    "api",
		ObservedAt:      recordedAt,
		ValidFrom:       recordedAt,
		RecordedAt:      recordedAt,
		TransactionFrom: recordedAt,
	}); err != nil {
		t.Fatalf("write claim: %v", err)
	}

	hidden := do(t, s, http.MethodGet, "/api/v1/platform/knowledge/claims/claim:payments:owner:alice?recorded_at=2026-03-09T11:59:00Z", nil)
	if hidden.Code != http.StatusNotFound {
		t.Fatalf("expected 404 before transaction_from, got %d: %s", hidden.Code, hidden.Body.String())
	}

	visible := do(t, s, http.MethodGet, "/api/v1/platform/knowledge/claims/claim:payments:owner:alice?recorded_at=2026-03-09T12:00:00Z", nil)
	if visible.Code != http.StatusOK {
		t.Fatalf("expected 200 at transaction_from, got %d: %s", visible.Code, visible.Body.String())
	}
	body := decodeJSON(t, visible)
	if body["id"] != "claim:payments:owner:alice" {
		t.Fatalf("expected claim id, got %#v", body)
	}
	derived, ok := body["derived"].(map[string]any)
	if !ok || derived["resolved"] != false {
		t.Fatalf("expected derived block, got %#v", body["derived"])
	}
}

func TestPlatformKnowledgeClaimsRejectInvalidParams(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodGet, "/api/v1/platform/knowledge/claims?supported=maybe", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid supported param, got %d: %s", w.Code, w.Body.String())
	}

	w = do(t, s, http.MethodGet, "/api/v1/platform/knowledge/claims?status=nope", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid status param, got %d: %s", w.Code, w.Body.String())
	}

	w = do(t, s, http.MethodGet, "/api/v1/platform/knowledge/claims/claim:missing?recorded_at=nope", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid recorded_at, got %d: %s", w.Code, w.Body.String())
	}
}
