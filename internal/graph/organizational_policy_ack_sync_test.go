package graph

import (
	"slices"
	"strings"
	"testing"
)

func TestAcknowledgeOrganizationalPolicyForAssignedPeopleAcknowledgesPendingAndStaleAssignees(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "department:engineering", Kind: NodeKindDepartment, Name: "Engineering", Risk: RiskNone})
	g.AddNode(&Node{ID: "person:alice", Kind: NodeKindPerson, Name: "Alice", Risk: RiskNone})
	g.AddNode(&Node{ID: "person:bob", Kind: NodeKindPerson, Name: "Bob", Risk: RiskNone})
	g.AddNode(&Node{ID: "person:carol", Kind: NodeKindPerson, Name: "Carol", Risk: RiskNone})
	g.AddEdge(&Edge{ID: "alice-eng", Source: "person:alice", Target: "department:engineering", Kind: EdgeKindMemberOf})
	g.AddEdge(&Edge{ID: "bob-eng", Source: "person:bob", Target: "department:engineering", Kind: EdgeKindMemberOf})

	policy, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:                 "Acceptable Use Policy",
		PolicyVersion:         "v1",
		RequiredDepartmentIDs: []string{"department:engineering"},
		RequiredPersonIDs:     []string{"person:carol"},
	})
	if err != nil {
		t.Fatalf("WriteOrganizationalPolicy(v1) returned error: %v", err)
	}

	if _, err := AcknowledgeOrganizationalPolicy(g, OrganizationalPolicyAcknowledgmentRequest{
		PersonID:      "person:alice",
		PolicyID:      policy.PolicyID,
		PolicyVersion: "v1",
	}); err != nil {
		t.Fatalf("AcknowledgeOrganizationalPolicy(alice v1) returned error: %v", err)
	}
	if _, err := AcknowledgeOrganizationalPolicy(g, OrganizationalPolicyAcknowledgmentRequest{
		PersonID:      "person:carol",
		PolicyID:      policy.PolicyID,
		PolicyVersion: "v1",
	}); err != nil {
		t.Fatalf("AcknowledgeOrganizationalPolicy(carol v1) returned error: %v", err)
	}

	if _, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		ID:                    policy.PolicyID,
		Title:                 "Acceptable Use Policy",
		PolicyVersion:         "v2",
		RequiredDepartmentIDs: []string{"department:engineering"},
		RequiredPersonIDs:     []string{"person:carol"},
	}); err != nil {
		t.Fatalf("WriteOrganizationalPolicy(v2) returned error: %v", err)
	}

	result, err := AcknowledgeOrganizationalPolicyForAssignedPeople(g, OrganizationalPolicyAcknowledgmentSyncRequest{
		PolicyID: policy.PolicyID,
	})
	if err != nil {
		t.Fatalf("AcknowledgeOrganizationalPolicyForAssignedPeople returned error: %v", err)
	}

	if !slices.Equal(result.AcknowledgedPersonIDs, []string{"person:alice", "person:bob", "person:carol"}) {
		t.Fatalf("acknowledged person ids = %#v", result.AcknowledgedPersonIDs)
	}
	if len(result.AlreadyAcknowledgedPersonIDs) != 0 {
		t.Fatalf("already acknowledged person ids = %#v, want none", result.AlreadyAcknowledgedPersonIDs)
	}
	if len(result.Acknowledgments) != 3 {
		t.Fatalf("acknowledgments = %#v, want 3 results", result.Acknowledgments)
	}

	roster, err := OrganizationalPolicyAssigneeRoster(g, policy.PolicyID)
	if err != nil {
		t.Fatalf("OrganizationalPolicyAssigneeRoster returned error: %v", err)
	}
	if roster.RequiredPeople != 3 || roster.AcknowledgedPeople != 3 || roster.PendingPeople != 0 || roster.StalePeople != 0 {
		t.Fatalf("unexpected roster counts after sync: %+v", roster)
	}
}

func TestAcknowledgeOrganizationalPolicyForAssignedPeopleSupportsSubsetAndSkipsCurrent(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "person:alice", Kind: NodeKindPerson, Name: "Alice", Risk: RiskNone})
	g.AddNode(&Node{ID: "person:bob", Kind: NodeKindPerson, Name: "Bob", Risk: RiskNone})

	policy, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:             "Change Management Policy",
		PolicyVersion:     "v1",
		RequiredPersonIDs: []string{"person:alice", "person:bob"},
	})
	if err != nil {
		t.Fatalf("WriteOrganizationalPolicy returned error: %v", err)
	}
	if _, err := AcknowledgeOrganizationalPolicy(g, OrganizationalPolicyAcknowledgmentRequest{
		PersonID:      "person:bob",
		PolicyID:      policy.PolicyID,
		PolicyVersion: "v1",
	}); err != nil {
		t.Fatalf("AcknowledgeOrganizationalPolicy(bob current) returned error: %v", err)
	}

	result, err := AcknowledgeOrganizationalPolicyForAssignedPeople(g, OrganizationalPolicyAcknowledgmentSyncRequest{
		PolicyID:  policy.PolicyID,
		PersonIDs: []string{"person:alice", "person:bob"},
	})
	if err != nil {
		t.Fatalf("AcknowledgeOrganizationalPolicyForAssignedPeople returned error: %v", err)
	}

	if !slices.Equal(result.AcknowledgedPersonIDs, []string{"person:alice"}) {
		t.Fatalf("acknowledged person ids = %#v, want alice", result.AcknowledgedPersonIDs)
	}
	if !slices.Equal(result.AlreadyAcknowledgedPersonIDs, []string{"person:bob"}) {
		t.Fatalf("already acknowledged person ids = %#v, want bob", result.AlreadyAcknowledgedPersonIDs)
	}
}

func TestAcknowledgeOrganizationalPolicyForAssignedPeopleUsesUniqueSourceEventIDsPerPerson(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "person:alice", Kind: NodeKindPerson, Name: "Alice", Risk: RiskNone})
	g.AddNode(&Node{ID: "person:bob", Kind: NodeKindPerson, Name: "Bob", Risk: RiskNone})

	policy, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:             "Incident Response Plan",
		PolicyVersion:     "v1",
		RequiredPersonIDs: []string{"person:alice", "person:bob"},
	})
	if err != nil {
		t.Fatalf("WriteOrganizationalPolicy returned error: %v", err)
	}

	result, err := AcknowledgeOrganizationalPolicyForAssignedPeople(g, OrganizationalPolicyAcknowledgmentSyncRequest{
		PolicyID:      policy.PolicyID,
		SourceEventID: "sync:batch",
	})
	if err != nil {
		t.Fatalf("AcknowledgeOrganizationalPolicyForAssignedPeople returned error: %v", err)
	}
	if len(result.Acknowledgments) != 2 {
		t.Fatalf("acknowledgments = %#v, want 2 results", result.Acknowledgments)
	}

	seen := map[string]string{}
	for _, ack := range result.Acknowledgments {
		if ack.SourceEventID == "sync:batch" {
			t.Fatalf("acknowledgment %s reused batch source event id", ack.PersonID)
		}
		if !strings.HasPrefix(ack.SourceEventID, "sync:batch:person:") {
			t.Fatalf("acknowledgment %s source event id = %q, want sync:batch:person:*", ack.PersonID, ack.SourceEventID)
		}
		if priorPersonID, ok := seen[ack.SourceEventID]; ok {
			t.Fatalf("duplicate source event id %q for people %s and %s", ack.SourceEventID, priorPersonID, ack.PersonID)
		}
		seen[ack.SourceEventID] = ack.PersonID
	}
	if len(seen) != 2 {
		t.Fatalf("unique source event ids = %d, want 2", len(seen))
	}
	if _, ok := seen["sync:batch:person:person:alice"]; !ok {
		t.Fatalf("missing source event id for alice: %#v", seen)
	}
	if _, ok := seen["sync:batch:person:person:bob"]; !ok {
		t.Fatalf("missing source event id for bob: %#v", seen)
	}
}

func TestAcknowledgeOrganizationalPolicyForAssignedPeopleRejectsInvalidInput(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "person:alice", Kind: NodeKindPerson, Name: "Alice", Risk: RiskNone})
	g.AddNode(&Node{ID: "person:bob", Kind: NodeKindPerson, Name: "Bob", Risk: RiskNone})

	policy, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:             "Incident Response Plan",
		PolicyVersion:     "v1",
		RequiredPersonIDs: []string{"person:alice"},
	})
	if err != nil {
		t.Fatalf("WriteOrganizationalPolicy returned error: %v", err)
	}

	if _, err := AcknowledgeOrganizationalPolicyForAssignedPeople(g, OrganizationalPolicyAcknowledgmentSyncRequest{}); err == nil {
		t.Fatal("expected empty policy id to fail")
	}
	if _, err := AcknowledgeOrganizationalPolicyForAssignedPeople(g, OrganizationalPolicyAcknowledgmentSyncRequest{PolicyID: "policy:missing"}); err == nil {
		t.Fatal("expected missing policy to fail")
	}
	if _, err := AcknowledgeOrganizationalPolicyForAssignedPeople(g, OrganizationalPolicyAcknowledgmentSyncRequest{
		PolicyID:  policy.PolicyID,
		PersonIDs: []string{"person:bob"},
	}); err == nil {
		t.Fatal("expected unassigned person to fail")
	}
}
