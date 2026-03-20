package graph

import (
	"testing"
	"time"
)

func TestOrganizationalPolicyProgramReminderQueueAggregatesAcrossPolicies(t *testing.T) {
	g := New()
	now := time.Date(2026, 3, 18, 22, 0, 0, 0, time.UTC)

	g.AddNode(&Node{ID: "person:owner", Kind: NodeKindPerson, Name: "Owner"})
	g.AddNode(&Node{ID: "person:alice", Kind: NodeKindPerson, Name: "Alice"})
	g.AddNode(&Node{ID: "person:bob", Kind: NodeKindPerson, Name: "Bob"})
	g.AddNode(&Node{ID: "person:carol", Kind: NodeKindPerson, Name: "Carol"})
	g.AddNode(&Node{ID: "department:engineering", Kind: NodeKindDepartment, Name: "Engineering"})
	g.AddNode(&Node{ID: "department:security", Kind: NodeKindDepartment, Name: "Security"})
	g.AddEdge(&Edge{ID: "alice-eng", Source: "person:alice", Target: "department:engineering", Kind: EdgeKindMemberOf, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "bob-eng", Source: "person:bob", Target: "department:engineering", Kind: EdgeKindMemberOf, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "carol-sec", Source: "person:carol", Target: "department:security", Kind: EdgeKindMemberOf, Effect: EdgeEffectAllow})

	acceptableUse, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:                 "Acceptable Use Policy",
		PolicyVersion:         "v2",
		OwnerID:               "person:owner",
		FrameworkMappings:     []string{"SOC 2:CC6.1"},
		RequiredDepartmentIDs: []string{"department:engineering"},
		ObservedAt:            now,
	})
	if err != nil {
		t.Fatalf("WriteOrganizationalPolicy(acceptable use) returned error: %v", err)
	}
	privacy, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:             "Privacy Policy",
		PolicyVersion:     "v1",
		OwnerID:           "person:owner",
		FrameworkMappings: []string{"HIPAA:164.308(a)(1)"},
		RequiredPersonIDs: []string{"person:carol"},
		ObservedAt:        now,
	})
	if err != nil {
		t.Fatalf("WriteOrganizationalPolicy(privacy) returned error: %v", err)
	}
	changeMgmt, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:                 "Change Management Policy",
		PolicyVersion:         "v1",
		OwnerID:               "person:owner",
		FrameworkMappings:     []string{"soc2:cc8.1"},
		RequiredDepartmentIDs: []string{"department:security"},
		ObservedAt:            now,
	})
	if err != nil {
		t.Fatalf("WriteOrganizationalPolicy(change management) returned error: %v", err)
	}

	if _, err := AcknowledgeOrganizationalPolicy(g, OrganizationalPolicyAcknowledgmentRequest{
		PersonID:       "person:alice",
		PolicyID:       acceptableUse.PolicyID,
		PolicyVersion:  "v1",
		AcknowledgedAt: now.Add(time.Minute),
	}); err != nil {
		t.Fatalf("AcknowledgeOrganizationalPolicy(alice stale) returned error: %v", err)
	}
	if _, err := AcknowledgeOrganizationalPolicy(g, OrganizationalPolicyAcknowledgmentRequest{
		PersonID:       "person:carol",
		PolicyID:       changeMgmt.PolicyID,
		PolicyVersion:  "v1",
		AcknowledgedAt: now.Add(2 * time.Minute),
	}); err != nil {
		t.Fatalf("AcknowledgeOrganizationalPolicy(carol current) returned error: %v", err)
	}

	report, err := OrganizationalPolicyProgramReminderQueue(g, OrganizationalPolicyReminderQueueOptions{})
	if err != nil {
		t.Fatalf("OrganizationalPolicyProgramReminderQueue returned error: %v", err)
	}
	if report.PolicyCount != 3 {
		t.Fatalf("policy count = %d, want 3", report.PolicyCount)
	}
	if report.PoliciesWithReminders != 2 {
		t.Fatalf("policies with reminders = %d, want 2", report.PoliciesWithReminders)
	}
	if report.ReminderCount != 3 {
		t.Fatalf("reminder count = %d, want 3", report.ReminderCount)
	}
	if report.PendingReminders != 2 {
		t.Fatalf("pending reminders = %d, want 2", report.PendingReminders)
	}
	if report.StaleReminders != 1 {
		t.Fatalf("stale reminders = %d, want 1", report.StaleReminders)
	}
	if len(report.Items) != 3 {
		t.Fatalf("items = %d, want 3", len(report.Items))
	}

	first := report.Items[0]
	if first.Status != OrganizationalPolicyReminderStatusStale || first.PolicyID != acceptableUse.PolicyID || first.PersonID != "person:alice" {
		t.Fatalf("first item = %+v, want stale acceptable-use reminder for alice", first)
	}
	second := report.Items[1]
	if second.Status != OrganizationalPolicyReminderStatusPending || second.PolicyID != acceptableUse.PolicyID || second.PersonID != "person:bob" {
		t.Fatalf("second item = %+v, want pending acceptable-use reminder for bob", second)
	}
	third := report.Items[2]
	if third.Status != OrganizationalPolicyReminderStatusPending || third.PolicyID != privacy.PolicyID || third.PersonID != "person:carol" {
		t.Fatalf("third item = %+v, want pending privacy reminder for carol", third)
	}

	soc2, err := OrganizationalPolicyProgramReminderQueue(g, OrganizationalPolicyReminderQueueOptions{Framework: "SOC 2"})
	if err != nil {
		t.Fatalf("OrganizationalPolicyProgramReminderQueue(soc2) returned error: %v", err)
	}
	if soc2.Framework != "soc2" {
		t.Fatalf("framework = %q, want soc2", soc2.Framework)
	}
	if soc2.PolicyCount != 2 {
		t.Fatalf("soc2 policy count = %d, want 2", soc2.PolicyCount)
	}
	if soc2.PoliciesWithReminders != 1 {
		t.Fatalf("soc2 policies with reminders = %d, want 1", soc2.PoliciesWithReminders)
	}
	if soc2.ReminderCount != 2 {
		t.Fatalf("soc2 reminder count = %d, want 2", soc2.ReminderCount)
	}
}

func TestOrganizationalPolicyProgramReminderQueuePreservesAssignmentContext(t *testing.T) {
	g := New()
	now := time.Date(2026, 3, 18, 22, 30, 0, 0, time.UTC)

	g.AddNode(&Node{ID: "person:owner", Kind: NodeKindPerson, Name: "Owner"})
	g.AddNode(&Node{ID: "person:alice", Kind: NodeKindPerson, Name: "Alice"})
	g.AddNode(&Node{ID: "person:bob", Kind: NodeKindPerson, Name: "Bob"})
	g.AddNode(&Node{ID: "department:engineering", Kind: NodeKindDepartment, Name: "Engineering"})
	g.AddEdge(&Edge{ID: "bob-eng", Source: "person:bob", Target: "department:engineering", Kind: EdgeKindMemberOf, Effect: EdgeEffectAllow})

	policy, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:                 "Incident Response Policy",
		PolicyVersion:         "v3",
		OwnerID:               "person:owner",
		RequiredDepartmentIDs: []string{"department:engineering"},
		RequiredPersonIDs:     []string{"person:alice"},
		ObservedAt:            now,
	})
	if err != nil {
		t.Fatalf("WriteOrganizationalPolicy returned error: %v", err)
	}

	report, err := OrganizationalPolicyProgramReminderQueue(g, OrganizationalPolicyReminderQueueOptions{})
	if err != nil {
		t.Fatalf("OrganizationalPolicyProgramReminderQueue returned error: %v", err)
	}
	if len(report.Items) != 2 {
		t.Fatalf("items = %d, want 2", len(report.Items))
	}

	byPerson := map[string]OrganizationalPolicyReminderQueueItem{}
	for _, item := range report.Items {
		if item.PolicyID != policy.PolicyID {
			t.Fatalf("unexpected policy id %q", item.PolicyID)
		}
		byPerson[item.PersonID] = item
	}

	if alice := byPerson["person:alice"]; !alice.DirectAssignment || len(alice.DepartmentIDs) != 0 {
		t.Fatalf("alice item = %+v, want direct-only assignment", alice)
	}
	if bob := byPerson["person:bob"]; bob.DirectAssignment || len(bob.DepartmentIDs) != 1 || bob.DepartmentIDs[0] != "department:engineering" {
		t.Fatalf("bob item = %+v, want engineering department assignment", bob)
	}
}

func TestOrganizationalPolicyProgramReminderQueueRequiresGraph(t *testing.T) {
	if _, err := OrganizationalPolicyProgramReminderQueue(nil, OrganizationalPolicyReminderQueueOptions{}); err == nil {
		t.Fatal("expected missing graph error")
	}
}
