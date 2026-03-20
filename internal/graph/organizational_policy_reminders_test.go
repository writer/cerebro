package graph

import (
	"slices"
	"testing"
	"time"
)

func TestOrganizationalPolicyAcknowledgmentRemindersIncludesPendingAndStalePeople(t *testing.T) {
	g := New()
	now := time.Date(2026, 3, 18, 20, 0, 0, 0, time.UTC)

	g.AddNode(&Node{ID: "person:owner", Kind: NodeKindPerson, Name: "Owner"})
	g.AddNode(&Node{ID: "person:alice", Kind: NodeKindPerson, Name: "Alice"})
	g.AddNode(&Node{ID: "person:bob", Kind: NodeKindPerson, Name: "Bob"})
	g.AddNode(&Node{ID: "person:carol", Kind: NodeKindPerson, Name: "Carol"})
	g.AddNode(&Node{ID: "department:engineering", Kind: NodeKindDepartment, Name: "Engineering"})
	g.AddNode(&Node{ID: "department:security", Kind: NodeKindDepartment, Name: "Security"})
	g.AddEdge(&Edge{ID: "alice-eng", Source: "person:alice", Target: "department:engineering", Kind: EdgeKindMemberOf, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "bob-eng", Source: "person:bob", Target: "department:engineering", Kind: EdgeKindMemberOf, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "carol-sec", Source: "person:carol", Target: "department:security", Kind: EdgeKindMemberOf, Effect: EdgeEffectAllow})

	policy, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:                 "Acceptable Use Policy",
		PolicyVersion:         "v2",
		OwnerID:               "person:owner",
		RequiredDepartmentIDs: []string{"department:engineering"},
		RequiredPersonIDs:     []string{"person:carol"},
		ObservedAt:            now,
	})
	if err != nil {
		t.Fatalf("WriteOrganizationalPolicy returned error: %v", err)
	}

	if _, err := AcknowledgeOrganizationalPolicy(g, OrganizationalPolicyAcknowledgmentRequest{
		PersonID:       "person:alice",
		PolicyID:       policy.PolicyID,
		PolicyVersion:  "v1",
		AcknowledgedAt: now.Add(time.Minute),
	}); err != nil {
		t.Fatalf("AcknowledgeOrganizationalPolicy(alice stale) returned error: %v", err)
	}
	if _, err := AcknowledgeOrganizationalPolicy(g, OrganizationalPolicyAcknowledgmentRequest{
		PersonID:       "person:carol",
		PolicyID:       policy.PolicyID,
		PolicyVersion:  "v2",
		AcknowledgedAt: now.Add(2 * time.Minute),
	}); err != nil {
		t.Fatalf("AcknowledgeOrganizationalPolicy(carol current) returned error: %v", err)
	}

	report, err := OrganizationalPolicyAcknowledgmentReminders(g, policy.PolicyID)
	if err != nil {
		t.Fatalf("OrganizationalPolicyAcknowledgmentReminders returned error: %v", err)
	}
	if report.PolicyVersion != "v2" {
		t.Fatalf("policy version = %q, want v2", report.PolicyVersion)
	}
	if report.PendingPeople != 1 {
		t.Fatalf("pending people = %d, want 1", report.PendingPeople)
	}
	if report.StalePeople != 1 {
		t.Fatalf("stale people = %d, want 1", report.StalePeople)
	}
	if len(report.ReminderCandidates) != 2 {
		t.Fatalf("reminder candidates = %d, want 2", len(report.ReminderCandidates))
	}

	byID := make(map[string]OrganizationalPolicyReminderCandidate, len(report.ReminderCandidates))
	for _, candidate := range report.ReminderCandidates {
		byID[candidate.PersonID] = candidate
	}

	if got := byID["person:alice"]; got.Status != OrganizationalPolicyReminderStatusStale || got.AcknowledgedVersion != "v1" || !slices.Equal(got.DepartmentIDs, []string{"department:engineering"}) {
		t.Fatalf("alice candidate = %+v, want stale engineering reminder", got)
	}
	if got := byID["person:bob"]; got.Status != OrganizationalPolicyReminderStatusPending || !slices.Equal(got.DepartmentIDs, []string{"department:engineering"}) {
		t.Fatalf("bob candidate = %+v, want pending engineering reminder", got)
	}
	if _, ok := byID["person:carol"]; ok {
		t.Fatal("did not expect current-version acknowledgment to generate a reminder")
	}
}

func TestOrganizationalPolicyAcknowledgmentRemindersMarksDirectAssignments(t *testing.T) {
	g := New()
	now := time.Date(2026, 3, 18, 21, 0, 0, 0, time.UTC)

	g.AddNode(&Node{ID: "person:owner", Kind: NodeKindPerson, Name: "Owner"})
	g.AddNode(&Node{ID: "person:alice", Kind: NodeKindPerson, Name: "Alice"})

	policy, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:             "Incident Response Policy",
		PolicyVersion:     "v1",
		OwnerID:           "person:owner",
		RequiredPersonIDs: []string{"person:alice"},
		ObservedAt:        now,
	})
	if err != nil {
		t.Fatalf("WriteOrganizationalPolicy returned error: %v", err)
	}

	report, err := OrganizationalPolicyAcknowledgmentReminders(g, policy.PolicyID)
	if err != nil {
		t.Fatalf("OrganizationalPolicyAcknowledgmentReminders returned error: %v", err)
	}
	if len(report.ReminderCandidates) != 1 {
		t.Fatalf("reminder candidates = %d, want 1", len(report.ReminderCandidates))
	}
	candidate := report.ReminderCandidates[0]
	if !candidate.DirectAssignment {
		t.Fatalf("candidate = %+v, want direct assignment", candidate)
	}
	if len(candidate.DepartmentIDs) != 0 {
		t.Fatalf("candidate department ids = %#v, want none", candidate.DepartmentIDs)
	}
}

func TestOrganizationalPolicyAcknowledgmentRemindersRequiresPolicy(t *testing.T) {
	g := New()
	if _, err := OrganizationalPolicyAcknowledgmentReminders(g, ""); err == nil {
		t.Fatal("expected missing policy_id error")
	}
	if _, err := OrganizationalPolicyAcknowledgmentReminders(g, "policy:missing"); err == nil {
		t.Fatal("expected missing policy error")
	}
}
