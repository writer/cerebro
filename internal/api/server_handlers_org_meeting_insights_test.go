package api

import (
	"net/http"
	"testing"

	"github.com/writer/cerebro/internal/graph"
)

func TestOrgMeetingInsightsEndpoint(t *testing.T) {
	s := newTestServer(t)
	seedOrgMeetingInsightsGraph(s.app.SecurityGraph)

	w := do(t, s, http.MethodGet, "/api/v1/org/meeting-insights", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	meetings, ok := body["meetings"].([]any)
	if !ok || len(meetings) != 3 {
		t.Fatalf("expected 3 meeting insights, got %T %#v", body["meetings"], body["meetings"])
	}
	redundant, ok := body["redundant_meetings"].([]any)
	if !ok || len(redundant) == 0 {
		t.Fatalf("expected redundant meeting pairs, got %T %#v", body["redundant_meetings"], body["redundant_meetings"])
	}
}

func TestOrgMeetingInsightsEndpoint_TeamFilter(t *testing.T) {
	s := newTestServer(t)
	seedOrgMeetingInsightsGraph(s.app.SecurityGraph)

	w := do(t, s, http.MethodGet, "/api/v1/org/meeting-insights?team=support", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	meetings, ok := body["meetings"].([]any)
	if !ok || len(meetings) != 2 {
		t.Fatalf("expected 2 support meetings, got %T %#v", body["meetings"], body["meetings"])
	}
}

func TestOrgMeetingAnalysisEndpoint(t *testing.T) {
	s := newTestServer(t)
	seedOrgMeetingInsightsGraph(s.app.SecurityGraph)

	w := do(t, s, http.MethodGet, "/api/v1/org/meetings/activity:meeting-1/analysis", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)
	meeting, ok := body["meeting"].(map[string]any)
	if !ok {
		t.Fatalf("expected meeting object, got %T", body["meeting"])
	}
	if meeting["meeting_id"] != "activity:meeting-1" {
		t.Fatalf("expected meeting_id activity:meeting-1, got %v", meeting["meeting_id"])
	}

	w = do(t, s, http.MethodGet, "/api/v1/org/meetings/activity:unknown/analysis", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown meeting, got %d", w.Code)
	}
}

func seedOrgMeetingInsightsGraph(g *graph.Graph) {
	g.AddNode(&graph.Node{ID: "department:support", Kind: graph.NodeKindDepartment, Name: "Support"})
	g.AddNode(&graph.Node{ID: "department:engineering", Kind: graph.NodeKindDepartment, Name: "Engineering"})
	g.AddNode(&graph.Node{ID: "department:product", Kind: graph.NodeKindDepartment, Name: "Product"})

	g.AddNode(&graph.Node{ID: "person:alice@example.com", Kind: graph.NodeKindPerson, Name: "Alice", Properties: map[string]any{"department": "support"}})
	g.AddNode(&graph.Node{ID: "person:bob@example.com", Kind: graph.NodeKindPerson, Name: "Bob", Properties: map[string]any{"department": "engineering"}})
	g.AddNode(&graph.Node{ID: "person:carol@example.com", Kind: graph.NodeKindPerson, Name: "Carol", Properties: map[string]any{"department": "engineering"}})
	g.AddNode(&graph.Node{ID: "person:dave@example.com", Kind: graph.NodeKindPerson, Name: "Dave", Properties: map[string]any{"department": "product"}})

	g.AddNode(&graph.Node{ID: "system:payments", Kind: graph.NodeKindApplication, Name: "payments"})
	g.AddNode(&graph.Node{ID: "system:billing", Kind: graph.NodeKindApplication, Name: "billing"})

	g.AddEdge(&graph.Edge{ID: "m-alice", Source: "person:alice@example.com", Target: "department:support", Kind: graph.EdgeKindMemberOf, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "m-bob", Source: "person:bob@example.com", Target: "department:engineering", Kind: graph.EdgeKindMemberOf, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "m-carol", Source: "person:carol@example.com", Target: "department:engineering", Kind: graph.EdgeKindMemberOf, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "m-dave", Source: "person:dave@example.com", Target: "department:product", Kind: graph.EdgeKindMemberOf, Effect: graph.EdgeEffectAllow})

	g.AddEdge(&graph.Edge{ID: "sys-a", Source: "person:alice@example.com", Target: "system:payments", Kind: graph.EdgeKindOwns, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "sys-b", Source: "person:bob@example.com", Target: "system:payments", Kind: graph.EdgeKindManagedBy, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "sys-c", Source: "person:carol@example.com", Target: "system:payments", Kind: graph.EdgeKindOwns, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "sys-d", Source: "person:dave@example.com", Target: "system:billing", Kind: graph.EdgeKindManagedBy, Effect: graph.EdgeEffectAllow})

	g.AddEdge(&graph.Edge{ID: "i-ab", Source: "person:alice@example.com", Target: "person:bob@example.com", Kind: graph.EdgeKindInteractedWith, Effect: graph.EdgeEffectAllow, Properties: map[string]any{"frequency": 10}})
	g.AddEdge(&graph.Edge{ID: "i-bd", Source: "person:bob@example.com", Target: "person:dave@example.com", Kind: graph.EdgeKindInteractedWith, Effect: graph.EdgeEffectAllow, Properties: map[string]any{"frequency": 6}})

	g.AddNode(&graph.Node{ID: "activity:meeting-1", Kind: graph.NodeKindActivity, Name: "Weekly Payments Sync", Properties: map[string]any{"activity_type": "meeting", "duration_minutes": 60, "attendees": []string{"person:alice@example.com", "person:bob@example.com", "person:dave@example.com"}}})
	g.AddNode(&graph.Node{ID: "activity:meeting-2", Kind: graph.NodeKindActivity, Name: "Payments Triage", Properties: map[string]any{"activity_type": "meeting", "duration_minutes": 45, "attendees": []string{"person:alice@example.com", "person:bob@example.com"}}})
	g.AddNode(&graph.Node{ID: "activity:meeting-3", Kind: graph.NodeKindActivity, Name: "Billing Product Review", Properties: map[string]any{"activity_type": "meeting", "duration_minutes": 30, "attendees": []string{"person:bob@example.com", "person:dave@example.com"}}})

	g.AddEdge(&graph.Edge{ID: "meet1-a", Source: "activity:meeting-1", Target: "person:alice@example.com", Kind: graph.EdgeKindAssignedTo, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "meet1-b", Source: "activity:meeting-1", Target: "person:bob@example.com", Kind: graph.EdgeKindAssignedTo, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "meet1-d", Source: "activity:meeting-1", Target: "person:dave@example.com", Kind: graph.EdgeKindAssignedTo, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "meet2-a", Source: "activity:meeting-2", Target: "person:alice@example.com", Kind: graph.EdgeKindAssignedTo, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "meet2-b", Source: "activity:meeting-2", Target: "person:bob@example.com", Kind: graph.EdgeKindAssignedTo, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "meet3-b", Source: "activity:meeting-3", Target: "person:bob@example.com", Kind: graph.EdgeKindAssignedTo, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "meet3-d", Source: "activity:meeting-3", Target: "person:dave@example.com", Kind: graph.EdgeKindAssignedTo, Effect: graph.EdgeEffectAllow})
}
