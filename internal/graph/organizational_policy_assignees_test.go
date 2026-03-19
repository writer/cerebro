package graph

import (
	"slices"
	"testing"
	"time"
)

func TestOrganizationalPolicyAssigneeRosterIncludesStatusesAndAssignmentScope(t *testing.T) {
	g := New()
	now := time.Date(2026, 3, 18, 13, 0, 0, 0, time.UTC)

	g.AddNode(&Node{ID: "person:owner", Kind: NodeKindPerson, Name: "Owner"})
	g.AddNode(&Node{ID: "person:alice", Kind: NodeKindPerson, Name: "Alice"})
	g.AddNode(&Node{ID: "person:bob", Kind: NodeKindPerson, Name: "Bob"})
	g.AddNode(&Node{ID: "person:carol", Kind: NodeKindPerson, Name: "Carol"})
	g.AddNode(&Node{ID: "person:dana", Kind: NodeKindPerson, Name: "Dana"})
	g.AddNode(&Node{ID: "department:engineering", Kind: NodeKindDepartment, Name: "Engineering"})
	g.AddNode(&Node{ID: "department:support", Kind: NodeKindDepartment, Name: "Support"})
	g.AddEdge(&Edge{ID: "alice-eng", Source: "person:alice", Target: "department:engineering", Kind: EdgeKindMemberOf, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "bob-eng", Source: "person:bob", Target: "department:engineering", Kind: EdgeKindMemberOf, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "carol-support", Source: "person:carol", Target: "department:support", Kind: EdgeKindMemberOf, Effect: EdgeEffectAllow})

	policy, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:                 "Acceptable Use Policy",
		PolicyVersion:         "v2",
		OwnerID:               "person:owner",
		RequiredDepartmentIDs: []string{"department:engineering", "department:support"},
		RequiredPersonIDs:     []string{"person:dana"},
		ObservedAt:            now,
	})
	if err != nil {
		t.Fatalf("WriteOrganizationalPolicy returned error: %v", err)
	}

	if _, err := AcknowledgeOrganizationalPolicy(g, OrganizationalPolicyAcknowledgmentRequest{
		PersonID:       "person:alice",
		PolicyID:       policy.PolicyID,
		PolicyVersion:  "v1",
		AcknowledgedAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("AcknowledgeOrganizationalPolicy(alice stale) returned error: %v", err)
	}
	if _, err := AcknowledgeOrganizationalPolicy(g, OrganizationalPolicyAcknowledgmentRequest{
		PersonID:       "person:carol",
		PolicyID:       policy.PolicyID,
		PolicyVersion:  "v2",
		AcknowledgedAt: now.Add(2 * time.Hour),
	}); err != nil {
		t.Fatalf("AcknowledgeOrganizationalPolicy(carol current) returned error: %v", err)
	}

	report, err := OrganizationalPolicyAssigneeRoster(g, policy.PolicyID)
	if err != nil {
		t.Fatalf("OrganizationalPolicyAssigneeRoster returned error: %v", err)
	}
	if report.RequiredPeople != 4 || report.AcknowledgedPeople != 1 || report.PendingPeople != 2 || report.StalePeople != 1 {
		t.Fatalf("unexpected roster counts: %#v", report)
	}

	byID := make(map[string]OrganizationalPolicyAssignee, len(report.Assignees))
	for _, assignee := range report.Assignees {
		byID[assignee.PersonID] = assignee
	}

	if got := byID["person:alice"]; got.Status != OrganizationalPolicyAssigneeStatusStale || got.AcknowledgedVersion != "v1" || !slices.Equal(got.DepartmentIDs, []string{"department:engineering"}) {
		t.Fatalf("unexpected alice assignee: %#v", got)
	}
	if got := byID["person:bob"]; got.Status != OrganizationalPolicyAssigneeStatusPending || got.DirectAssignment || !slices.Equal(got.DepartmentIDs, []string{"department:engineering"}) {
		t.Fatalf("unexpected bob assignee: %#v", got)
	}
	if got := byID["person:carol"]; got.Status != OrganizationalPolicyAssigneeStatusAcknowledged || got.AcknowledgedVersion != "v2" || got.AcknowledgedAt == nil || !slices.Equal(got.DepartmentIDs, []string{"department:support"}) {
		t.Fatalf("unexpected carol assignee: %#v", got)
	}
	if got := byID["person:dana"]; got.Status != OrganizationalPolicyAssigneeStatusPending || !got.DirectAssignment || len(got.DepartmentIDs) != 0 {
		t.Fatalf("unexpected dana assignee: %#v", got)
	}
}

func TestOrganizationalPolicyAssigneeRosterMarksDirectAndDepartmentAssignments(t *testing.T) {
	g := New()
	now := time.Date(2026, 3, 18, 14, 0, 0, 0, time.UTC)

	g.AddNode(&Node{ID: "person:owner", Kind: NodeKindPerson, Name: "Owner"})
	g.AddNode(&Node{ID: "person:alice", Kind: NodeKindPerson, Name: "Alice"})
	g.AddNode(&Node{ID: "department:engineering", Kind: NodeKindDepartment, Name: "Engineering"})
	g.AddEdge(&Edge{ID: "alice-eng", Source: "person:alice", Target: "department:engineering", Kind: EdgeKindMemberOf, Effect: EdgeEffectAllow})

	policy, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:                 "Access Control Policy",
		PolicyVersion:         "v1",
		OwnerID:               "person:owner",
		RequiredDepartmentIDs: []string{"department:engineering"},
		RequiredPersonIDs:     []string{"person:alice"},
		ObservedAt:            now,
	})
	if err != nil {
		t.Fatalf("WriteOrganizationalPolicy returned error: %v", err)
	}

	report, err := OrganizationalPolicyAssigneeRoster(g, policy.PolicyID)
	if err != nil {
		t.Fatalf("OrganizationalPolicyAssigneeRoster returned error: %v", err)
	}
	if len(report.Assignees) != 1 {
		t.Fatalf("expected one assignee, got %#v", report.Assignees)
	}
	if got := report.Assignees[0]; !got.DirectAssignment || !slices.Equal(got.DepartmentIDs, []string{"department:engineering"}) {
		t.Fatalf("expected direct+department assignment markers, got %#v", got)
	}
}

func TestOrganizationalPolicyAssigneeRosterRequiresPolicy(t *testing.T) {
	g := New()

	if _, err := OrganizationalPolicyAssigneeRoster(g, ""); err == nil {
		t.Fatal("expected empty policy id to fail")
	}
	if _, err := OrganizationalPolicyAssigneeRoster(g, "policy:missing"); err == nil {
		t.Fatal("expected missing policy to fail")
	}
}
