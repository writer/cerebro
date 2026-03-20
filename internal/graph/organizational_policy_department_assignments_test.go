package graph

import (
	"slices"
	"testing"
)

func TestUpdateOrganizationalPolicyDepartmentAssignmentsPreservesDirectPeople(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "department:engineering", Kind: NodeKindDepartment, Name: "Engineering", Risk: RiskNone})
	g.AddNode(&Node{ID: "department:support", Kind: NodeKindDepartment, Name: "Support", Risk: RiskNone})
	g.AddNode(&Node{ID: "department:security", Kind: NodeKindDepartment, Name: "Security", Risk: RiskNone})
	g.AddNode(&Node{ID: "person:alice", Kind: NodeKindPerson, Name: "Alice", Risk: RiskNone})

	policy, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:                 "Incident Response Plan",
		PolicyVersion:         "v1",
		RequiredDepartmentIDs: []string{"department:engineering"},
		RequiredPersonIDs:     []string{"person:alice"},
	})
	if err != nil {
		t.Fatalf("WriteOrganizationalPolicy returned error: %v", err)
	}

	updated, err := UpdateOrganizationalPolicyDepartmentAssignments(g, OrganizationalPolicyDepartmentAssignmentRequest{
		PolicyID:            policy.PolicyID,
		AddDepartmentIDs:    []string{"department:security", "department:support"},
		RemoveDepartmentIDs: []string{"department:engineering"},
	})
	if err != nil {
		t.Fatalf("UpdateOrganizationalPolicyDepartmentAssignments returned error: %v", err)
	}

	if !slices.Equal(updated.DepartmentIDs, []string{"department:security", "department:support"}) {
		t.Fatalf("department ids = %#v, want security+support", updated.DepartmentIDs)
	}
	if !slices.Equal(updated.AddedDepartmentIDs, []string{"department:security", "department:support"}) {
		t.Fatalf("added department ids = %#v, want security+support", updated.AddedDepartmentIDs)
	}
	if !slices.Equal(updated.RemovedDepartmentIDs, []string{"department:engineering"}) {
		t.Fatalf("removed department ids = %#v, want engineering", updated.RemovedDepartmentIDs)
	}
	if !slices.Equal(updated.ChangedFields, []string{"required_department_ids"}) {
		t.Fatalf("changed fields = %#v, want required_department_ids", updated.ChangedFields)
	}

	assignedTargets := make(map[string]struct{})
	for _, edge := range g.GetOutEdges(policy.PolicyID) {
		if edge == nil || edge.Kind != EdgeKindAssignedTo {
			continue
		}
		assignedTargets[edge.Target] = struct{}{}
	}
	if _, ok := assignedTargets["person:alice"]; !ok {
		t.Fatalf("expected direct person assignment to be preserved, got %#v", assignedTargets)
	}
	if _, ok := assignedTargets["department:engineering"]; ok {
		t.Fatalf("expected engineering department assignment to be removed, got %#v", assignedTargets)
	}
	if _, ok := assignedTargets["department:security"]; !ok {
		t.Fatalf("expected security department assignment, got %#v", assignedTargets)
	}
	if _, ok := assignedTargets["department:support"]; !ok {
		t.Fatalf("expected support department assignment, got %#v", assignedTargets)
	}

	history, err := OrganizationalPolicyVersionHistory(g, policy.PolicyID)
	if err != nil {
		t.Fatalf("OrganizationalPolicyVersionHistory returned error: %v", err)
	}
	if len(history) != 2 {
		t.Fatalf("history entries = %d, want 2", len(history))
	}
	if !slices.Equal(history[1].RequiredDepartmentIDs, []string{"department:security", "department:support"}) {
		t.Fatalf("history required departments = %#v, want security+support", history[1].RequiredDepartmentIDs)
	}
	if !slices.Equal(history[1].RequiredPersonIDs, []string{"person:alice"}) {
		t.Fatalf("history required people = %#v, want alice", history[1].RequiredPersonIDs)
	}
	if !slices.Equal(history[1].ChangedFields, []string{"required_department_ids"}) {
		t.Fatalf("history changed fields = %#v, want required_department_ids", history[1].ChangedFields)
	}
}

func TestUpdateOrganizationalPolicyDepartmentAssignmentsNoopKeepsHistoryStable(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "department:engineering", Kind: NodeKindDepartment, Name: "Engineering", Risk: RiskNone})

	policy, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:                 "Access Control Policy",
		PolicyVersion:         "v1",
		RequiredDepartmentIDs: []string{"department:engineering"},
	})
	if err != nil {
		t.Fatalf("WriteOrganizationalPolicy returned error: %v", err)
	}

	updated, err := UpdateOrganizationalPolicyDepartmentAssignments(g, OrganizationalPolicyDepartmentAssignmentRequest{
		PolicyID:         policy.PolicyID,
		AddDepartmentIDs: []string{"department:engineering"},
	})
	if err != nil {
		t.Fatalf("UpdateOrganizationalPolicyDepartmentAssignments returned error: %v", err)
	}

	if len(updated.AddedDepartmentIDs) != 0 || len(updated.RemovedDepartmentIDs) != 0 {
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

func TestUpdateOrganizationalPolicyDepartmentAssignmentsRejectsInvalidInput(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "department:engineering", Kind: NodeKindDepartment, Name: "Engineering", Risk: RiskNone})
	g.AddNode(&Node{ID: "person:alice", Kind: NodeKindPerson, Name: "Alice", Risk: RiskNone})

	policy, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:                 "Change Management Policy",
		PolicyVersion:         "v1",
		RequiredDepartmentIDs: []string{"department:engineering"},
	})
	if err != nil {
		t.Fatalf("WriteOrganizationalPolicy returned error: %v", err)
	}

	if _, err := UpdateOrganizationalPolicyDepartmentAssignments(g, OrganizationalPolicyDepartmentAssignmentRequest{}); err == nil {
		t.Fatal("expected empty policy id to fail")
	}
	if _, err := UpdateOrganizationalPolicyDepartmentAssignments(g, OrganizationalPolicyDepartmentAssignmentRequest{PolicyID: "policy:missing"}); err == nil {
		t.Fatal("expected missing policy to fail")
	}
	if _, err := UpdateOrganizationalPolicyDepartmentAssignments(g, OrganizationalPolicyDepartmentAssignmentRequest{
		PolicyID:            policy.PolicyID,
		AddDepartmentIDs:    []string{"department:engineering"},
		RemoveDepartmentIDs: []string{"department:engineering"},
	}); err == nil {
		t.Fatal("expected overlapping add/remove ids to fail")
	}
	if _, err := UpdateOrganizationalPolicyDepartmentAssignments(g, OrganizationalPolicyDepartmentAssignmentRequest{
		PolicyID:         policy.PolicyID,
		AddDepartmentIDs: []string{"person:alice"},
	}); err == nil {
		t.Fatal("expected non-department target to fail")
	}
}
