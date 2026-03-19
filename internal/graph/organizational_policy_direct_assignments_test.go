package graph

import (
	"slices"
	"testing"
)

func TestUpdateOrganizationalPolicyDirectPersonAssignmentsPreservesDepartmentAssignments(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "department:engineering", Kind: NodeKindDepartment, Name: "Engineering", Risk: RiskNone})
	g.AddNode(&Node{ID: "person:alice", Kind: NodeKindPerson, Name: "Alice", Risk: RiskNone})
	g.AddNode(&Node{ID: "person:bob", Kind: NodeKindPerson, Name: "Bob", Risk: RiskNone})
	g.AddNode(&Node{ID: "person:carol", Kind: NodeKindPerson, Name: "Carol", Risk: RiskNone})

	policy, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:                 "Acceptable Use Policy",
		PolicyVersion:         "v1",
		RequiredDepartmentIDs: []string{"department:engineering"},
		RequiredPersonIDs:     []string{"person:alice"},
	})
	if err != nil {
		t.Fatalf("WriteOrganizationalPolicy returned error: %v", err)
	}

	updated, err := UpdateOrganizationalPolicyDirectPersonAssignments(g, OrganizationalPolicyDirectPersonAssignmentRequest{
		PolicyID:        policy.PolicyID,
		AddPersonIDs:    []string{"person:bob", "person:carol"},
		RemovePersonIDs: []string{"person:alice"},
	})
	if err != nil {
		t.Fatalf("UpdateOrganizationalPolicyDirectPersonAssignments returned error: %v", err)
	}

	if !slices.Equal(updated.DirectPersonIDs, []string{"person:bob", "person:carol"}) {
		t.Fatalf("direct person ids = %#v, want bob+carol", updated.DirectPersonIDs)
	}
	if !slices.Equal(updated.AddedPersonIDs, []string{"person:bob", "person:carol"}) {
		t.Fatalf("added person ids = %#v, want bob+carol", updated.AddedPersonIDs)
	}
	if !slices.Equal(updated.RemovedPersonIDs, []string{"person:alice"}) {
		t.Fatalf("removed person ids = %#v, want alice", updated.RemovedPersonIDs)
	}
	if !slices.Equal(updated.ChangedFields, []string{"required_person_ids"}) {
		t.Fatalf("changed fields = %#v, want required_person_ids", updated.ChangedFields)
	}

	assignedTargets := make(map[string]struct{})
	for _, edge := range g.GetOutEdges(policy.PolicyID) {
		if edge == nil || edge.Kind != EdgeKindAssignedTo {
			continue
		}
		assignedTargets[edge.Target] = struct{}{}
	}
	if _, ok := assignedTargets["department:engineering"]; !ok {
		t.Fatalf("expected department assignment to be preserved, got %#v", assignedTargets)
	}
	if _, ok := assignedTargets["person:alice"]; ok {
		t.Fatalf("expected alice direct assignment to be removed, got %#v", assignedTargets)
	}
	if _, ok := assignedTargets["person:bob"]; !ok {
		t.Fatalf("expected bob direct assignment, got %#v", assignedTargets)
	}
	if _, ok := assignedTargets["person:carol"]; !ok {
		t.Fatalf("expected carol direct assignment, got %#v", assignedTargets)
	}

	history, err := OrganizationalPolicyVersionHistory(g, policy.PolicyID)
	if err != nil {
		t.Fatalf("OrganizationalPolicyVersionHistory returned error: %v", err)
	}
	if len(history) != 2 {
		t.Fatalf("history entries = %d, want 2", len(history))
	}
	if !slices.Equal(history[1].RequiredDepartmentIDs, []string{"department:engineering"}) {
		t.Fatalf("history required departments = %#v, want engineering", history[1].RequiredDepartmentIDs)
	}
	if !slices.Equal(history[1].RequiredPersonIDs, []string{"person:bob", "person:carol"}) {
		t.Fatalf("history required people = %#v, want bob+carol", history[1].RequiredPersonIDs)
	}
	if !slices.Equal(history[1].ChangedFields, []string{"required_person_ids"}) {
		t.Fatalf("history changed fields = %#v, want required_person_ids", history[1].ChangedFields)
	}
}

func TestUpdateOrganizationalPolicyDirectPersonAssignmentsNoopKeepsHistoryStable(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "person:alice", Kind: NodeKindPerson, Name: "Alice", Risk: RiskNone})

	policy, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:             "Access Control Policy",
		PolicyVersion:     "v1",
		RequiredPersonIDs: []string{"person:alice"},
	})
	if err != nil {
		t.Fatalf("WriteOrganizationalPolicy returned error: %v", err)
	}

	updated, err := UpdateOrganizationalPolicyDirectPersonAssignments(g, OrganizationalPolicyDirectPersonAssignmentRequest{
		PolicyID:     policy.PolicyID,
		AddPersonIDs: []string{"person:alice"},
	})
	if err != nil {
		t.Fatalf("UpdateOrganizationalPolicyDirectPersonAssignments returned error: %v", err)
	}

	if len(updated.AddedPersonIDs) != 0 || len(updated.RemovedPersonIDs) != 0 {
		t.Fatalf("unexpected assignment delta: %+v", updated)
	}
	if len(updated.ChangedFields) != 0 {
		t.Fatalf("changed fields = %#v, want none", updated.ChangedFields)
	}

	history, err := OrganizationalPolicyVersionHistory(g, policy.PolicyID)
	if err != nil {
		t.Fatalf("OrganizationalPolicyVersionHistory returned error: %v", err)
	}
	if len(history) != 1 {
		t.Fatalf("history entries = %d, want 1", len(history))
	}
}

func TestUpdateOrganizationalPolicyDirectPersonAssignmentsRejectsInvalidInput(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "department:engineering", Kind: NodeKindDepartment, Name: "Engineering", Risk: RiskNone})
	g.AddNode(&Node{ID: "person:alice", Kind: NodeKindPerson, Name: "Alice", Risk: RiskNone})

	policy, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:             "Data Classification Policy",
		PolicyVersion:     "v1",
		RequiredPersonIDs: []string{"person:alice"},
	})
	if err != nil {
		t.Fatalf("WriteOrganizationalPolicy returned error: %v", err)
	}

	if _, err := UpdateOrganizationalPolicyDirectPersonAssignments(g, OrganizationalPolicyDirectPersonAssignmentRequest{}); err == nil {
		t.Fatal("expected empty policy id to fail")
	}
	if _, err := UpdateOrganizationalPolicyDirectPersonAssignments(g, OrganizationalPolicyDirectPersonAssignmentRequest{PolicyID: "policy:missing"}); err == nil {
		t.Fatal("expected missing policy to fail")
	}
	if _, err := UpdateOrganizationalPolicyDirectPersonAssignments(g, OrganizationalPolicyDirectPersonAssignmentRequest{
		PolicyID:        policy.PolicyID,
		AddPersonIDs:    []string{"person:alice"},
		RemovePersonIDs: []string{"person:alice"},
	}); err == nil {
		t.Fatal("expected overlapping add/remove ids to fail")
	}
	if _, err := UpdateOrganizationalPolicyDirectPersonAssignments(g, OrganizationalPolicyDirectPersonAssignmentRequest{
		PolicyID:     policy.PolicyID,
		AddPersonIDs: []string{"department:engineering"},
	}); err == nil {
		t.Fatal("expected non-person target to fail")
	}
}
