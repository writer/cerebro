package api

import (
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/app"
	"github.com/writer/cerebro/internal/graph"
)

func buildOrgPolicyTestGraph() *graph.Graph {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "person:owner", Kind: graph.NodeKindPerson, Name: "Owner"})
	g.AddNode(&graph.Node{ID: "person:alice", Kind: graph.NodeKindPerson, Name: "Alice"})
	g.AddNode(&graph.Node{ID: "person:bob", Kind: graph.NodeKindPerson, Name: "Bob"})
	g.AddNode(&graph.Node{ID: "department:engineering", Kind: graph.NodeKindDepartment, Name: "Engineering"})
	g.AddEdge(&graph.Edge{ID: "alice-member", Source: "person:alice", Target: "department:engineering", Kind: graph.EdgeKindMemberOf, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "bob-member", Source: "person:bob", Target: "department:engineering", Kind: graph.EdgeKindMemberOf, Effect: graph.EdgeEffectAllow})
	return g
}

func newOrgPolicyServer(t *testing.T, g *graph.Graph) *Server {
	t.Helper()
	s := NewServerWithDependencies(serverDependencies{
		Config:        &app.Config{},
		Logger:        slog.Default(),
		SecurityGraph: g,
		graphRuntime:  stubGraphRuntime{graph: g, store: g},
		graphMutator:  stubGraphMutator{graph: g},
	})
	t.Cleanup(func() { s.Close() })
	return s
}

func TestOrgPolicyRegistryEndpoints(t *testing.T) {
	g := buildOrgPolicyTestGraph()
	s := newOrgPolicyServer(t, g)

	templates := do(t, s, http.MethodGet, "/api/v1/org/policies/templates?framework=soc2", nil)
	if templates.Code != http.StatusOK {
		t.Fatalf("expected template list 200, got %d: %s", templates.Code, templates.Body.String())
	}
	templatesBody := decodeJSON(t, templates)
	if got := int(templatesBody["count"].(float64)); got == 0 {
		t.Fatalf("expected soc2 templates, got %#v", templatesBody)
	}

	write := do(t, s, http.MethodPost, "/api/v1/org/policies", map[string]any{
		"template_id":             "acceptable-use-policy",
		"policy_version":          "2026.03",
		"owner_id":                "person:owner",
		"required_department_ids": []string{"department:engineering"},
		"framework_mappings":      []string{"soc2:cc6.1"},
		"review_cycle_days":       365,
		"source_system":           "api",
		"source_event_id":         "evt-1",
	})
	if write.Code != http.StatusOK {
		t.Fatalf("expected policy write 200, got %d: %s", write.Code, write.Body.String())
	}
	writeBody := decodeJSON(t, write)
	if writeBody["policy_id"] != "policy:acceptable-use-policy" {
		t.Fatalf("policy_id = %#v, want policy:acceptable-use-policy", writeBody["policy_id"])
	}

	status := do(t, s, http.MethodGet, "/api/v1/org/policies/policy:acceptable-use-policy/acknowledgment-status", nil)
	if status.Code != http.StatusOK {
		t.Fatalf("expected acknowledgment status 200, got %d: %s", status.Code, status.Body.String())
	}
	statusBody := decodeJSON(t, status)
	if got := int(statusBody["required_people"].(float64)); got != 2 {
		t.Fatalf("required_people = %d, want 2", got)
	}
	departments, ok := statusBody["departments"].([]any)
	if !ok || len(departments) != 1 {
		t.Fatalf("expected one department rollup, got %#v", statusBody["departments"])
	}

	history := do(t, s, http.MethodGet, "/api/v1/org/policies/policy:acceptable-use-policy/versions", nil)
	if history.Code != http.StatusOK {
		t.Fatalf("expected version history 200, got %d: %s", history.Code, history.Body.String())
	}
	historyBody := decodeJSON(t, history)
	if got := int(historyBody["count"].(float64)); got != 1 {
		t.Fatalf("history count = %d, want 1", got)
	}

	program := do(t, s, http.MethodGet, "/api/v1/org/policies/program-status?framework=soc2", nil)
	if program.Code != http.StatusOK {
		t.Fatalf("expected program status 200, got %d: %s", program.Code, program.Body.String())
	}
	programBody := decodeJSON(t, program)
	if got := int(programBody["policy_count"].(float64)); got != 1 {
		t.Fatalf("policy_count = %d, want 1", got)
	}
	if got := int(programBody["total_required_acknowledgments"].(float64)); got != 2 {
		t.Fatalf("total_required_acknowledgments = %d, want 2", got)
	}
}

func TestOrgPolicyAcknowledgmentEndpoints(t *testing.T) {
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

	s := newOrgPolicyServer(t, g)

	ack := do(t, s, http.MethodPost, "/api/v1/org/policies/policy:acceptable-use-policy/acknowledge", map[string]any{
		"person_id":       "person:alice",
		"acknowledged_at": "2026-03-20T10:00:00Z",
	})
	if ack.Code != http.StatusOK {
		t.Fatalf("expected policy acknowledgement 200, got %d: %s", ack.Code, ack.Body.String())
	}
	ackBody := decodeJSON(t, ack)
	if ackBody["policy_version"] != "2026.03" {
		t.Fatalf("policy_version = %#v, want 2026.03", ackBody["policy_version"])
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
	candidates, ok := remindersBody["reminder_candidates"].([]any)
	if !ok || len(candidates) != 1 {
		t.Fatalf("expected one reminder candidate, got %#v", remindersBody["reminder_candidates"])
	}

	review := do(t, s, http.MethodGet, "/api/v1/org/policies/review-schedule?as_of=2026-03-20T10:00:00Z", nil)
	if review.Code != http.StatusOK {
		t.Fatalf("expected review schedule 200, got %d: %s", review.Code, review.Body.String())
	}
	reviewBody := decodeJSON(t, review)
	if got := int(reviewBody["policy_count"].(float64)); got != 1 {
		t.Fatalf("policy_count = %d, want 1", got)
	}
}
