package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/app"
	"github.com/writer/cerebro/internal/graph"
)

func buildGraphStoreOrgPolicyReadTestGraph(t *testing.T) *graph.Graph {
	t.Helper()

	g := buildOrgPolicyTestGraph()
	if _, err := graph.WriteOrganizationalPolicy(g, graph.OrganizationalPolicyWriteRequest{
		Title:                 "Acceptable Use Policy",
		PolicyVersion:         "2026.03",
		OwnerID:               "person:owner",
		ReviewCycleDays:       365,
		RequiredDepartmentIDs: []string{"department:engineering"},
		ObservedAt:            time.Date(2026, 3, 20, 9, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("seed policy error = %v", err)
	}
	if _, err := graph.AcknowledgeOrganizationalPolicy(g, graph.OrganizationalPolicyAcknowledgmentRequest{
		PolicyID:       "policy:acceptable-use-policy",
		PersonID:       "person:alice",
		AcknowledgedAt: time.Date(2026, 3, 20, 10, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("seed policy acknowledgment error = %v", err)
	}
	return g
}

func newLiveGraphStoreOrgPolicyServer(t *testing.T, g *graph.Graph, store graph.GraphStore) *Server {
	t.Helper()
	s := NewServerWithDependencies(serverDependencies{
		Config:       &app.Config{},
		graphRuntime: stubGraphRuntime{graph: g, store: store},
	})
	t.Cleanup(func() { s.Close() })
	return s
}

func TestOrgPolicyReadEndpointsUseStoreSubgraphWhenSnapshotsUnavailable(t *testing.T) {
	s := newStoreBackedGraphServer(t, nilSnapshotGraphStore{GraphStore: buildGraphStoreOrgPolicyReadTestGraph(t)})

	status := do(t, s, http.MethodGet, "/api/v1/org/policies/policy:acceptable-use-policy/acknowledgment-status", nil)
	if status.Code != http.StatusOK {
		t.Fatalf("expected acknowledgment status 200, got %d: %s", status.Code, status.Body.String())
	}
	statusBody := decodeJSON(t, status)
	if got := int(statusBody["required_people"].(float64)); got != 2 {
		t.Fatalf("required_people = %d, want 2", got)
	}

	assignees := do(t, s, http.MethodGet, "/api/v1/org/policies/policy:acceptable-use-policy/assignees", nil)
	if assignees.Code != http.StatusOK {
		t.Fatalf("expected assignee roster 200, got %d: %s", assignees.Code, assignees.Body.String())
	}
	assigneesBody := decodeJSON(t, assignees)
	if got := int(assigneesBody["acknowledged_people"].(float64)); got != 1 {
		t.Fatalf("acknowledged_people = %d, want 1", got)
	}
	if got := int(assigneesBody["pending_people"].(float64)); got != 1 {
		t.Fatalf("pending_people = %d, want 1", got)
	}

	reminders := do(t, s, http.MethodGet, "/api/v1/org/policies/policy:acceptable-use-policy/reminders", nil)
	if reminders.Code != http.StatusOK {
		t.Fatalf("expected reminder report 200, got %d: %s", reminders.Code, reminders.Body.String())
	}
	remindersBody := decodeJSON(t, reminders)
	if got := int(remindersBody["pending_people"].(float64)); got != 1 {
		t.Fatalf("pending_people = %d, want 1", got)
	}

	history := do(t, s, http.MethodGet, "/api/v1/org/policies/policy:acceptable-use-policy/versions", nil)
	if history.Code != http.StatusOK {
		t.Fatalf("expected version history 200, got %d: %s", history.Code, history.Body.String())
	}
	historyBody := decodeJSON(t, history)
	if got := int(historyBody["count"].(float64)); got != 1 {
		t.Fatalf("history count = %d, want 1", got)
	}
}

func TestOrgPolicyReadEndpointsPreferLiveGraphWhenAvailable(t *testing.T) {
	g := buildGraphStoreOrgPolicyReadTestGraph(t)
	store := &countingSnapshotStore{GraphStore: g}
	s := newLiveGraphStoreOrgPolicyServer(t, g, store)

	paths := []string{
		"/api/v1/org/policies/policy:acceptable-use-policy/acknowledgment-status",
		"/api/v1/org/policies/policy:acceptable-use-policy/assignees",
		"/api/v1/org/policies/policy:acceptable-use-policy/reminders",
		"/api/v1/org/policies/policy:acceptable-use-policy/versions",
	}
	for _, path := range paths {
		resp := do(t, s, http.MethodGet, path, nil)
		if resp.Code != http.StatusOK {
			t.Fatalf("expected %s to return 200, got %d: %s", path, resp.Code, resp.Body.String())
		}
	}
	if got := store.count.Load(); got != 0 {
		t.Fatalf("expected live graph reads to avoid snapshot calls, got %d", got)
	}
}
