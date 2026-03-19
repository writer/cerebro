package graph

import (
	"slices"
	"testing"
	"time"
)

func TestOrganizationalPolicyAcknowledgmentStatusForDepartmentIncludesApplicablePolicies(t *testing.T) {
	g := New()
	now := time.Date(2026, 3, 18, 22, 0, 0, 0, time.UTC)

	g.AddNode(&Node{ID: "person:owner", Kind: NodeKindPerson, Name: "Owner"})
	g.AddNode(&Node{ID: "person:alice", Kind: NodeKindPerson, Name: "Alice"})
	g.AddNode(&Node{ID: "person:bob", Kind: NodeKindPerson, Name: "Bob"})
	g.AddNode(&Node{ID: "person:carol", Kind: NodeKindPerson, Name: "Carol"})
	g.AddNode(&Node{ID: "department:engineering", Kind: NodeKindDepartment, Name: "Engineering"})
	g.AddNode(&Node{ID: "department:support", Kind: NodeKindDepartment, Name: "Support"})
	g.AddEdge(&Edge{ID: "alice-eng", Source: "person:alice", Target: "department:engineering", Kind: EdgeKindMemberOf, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "bob-eng", Source: "person:bob", Target: "department:engineering", Kind: EdgeKindMemberOf, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "carol-support", Source: "person:carol", Target: "department:support", Kind: EdgeKindMemberOf, Effect: EdgeEffectAllow})

	departmentPolicy, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:                 "Acceptable Use Policy",
		PolicyVersion:         "2026.03",
		OwnerID:               "person:owner",
		RequiredDepartmentIDs: []string{"department:engineering"},
		ObservedAt:            now,
	})
	if err != nil {
		t.Fatalf("WriteOrganizationalPolicy(department) returned error: %v", err)
	}
	directPolicy, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:             "Incident Response Plan",
		PolicyVersion:     "2026.03",
		OwnerID:           "person:owner",
		RequiredPersonIDs: []string{"person:alice"},
		ObservedAt:        now,
	})
	if err != nil {
		t.Fatalf("WriteOrganizationalPolicy(direct) returned error: %v", err)
	}
	otherDepartmentPolicy, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:                 "Access Control Policy",
		PolicyVersion:         "2026.03",
		OwnerID:               "person:owner",
		RequiredDepartmentIDs: []string{"department:support"},
		ObservedAt:            now,
	})
	if err != nil {
		t.Fatalf("WriteOrganizationalPolicy(other department) returned error: %v", err)
	}
	if _, err := AcknowledgeOrganizationalPolicy(g, OrganizationalPolicyAcknowledgmentRequest{PersonID: "person:bob", PolicyID: departmentPolicy.PolicyID, AcknowledgedAt: now.Add(time.Minute)}); err != nil {
		t.Fatalf("AcknowledgeOrganizationalPolicy(bob) returned error: %v", err)
	}
	if _, err := AcknowledgeOrganizationalPolicy(g, OrganizationalPolicyAcknowledgmentRequest{PersonID: "person:alice", PolicyID: directPolicy.PolicyID, AcknowledgedAt: now.Add(2 * time.Minute)}); err != nil {
		t.Fatalf("AcknowledgeOrganizationalPolicy(alice) returned error: %v", err)
	}

	report, err := OrganizationalPolicyAcknowledgmentStatusForDepartment(g, "department:engineering")
	if err != nil {
		t.Fatalf("OrganizationalPolicyAcknowledgmentStatusForDepartment returned error: %v", err)
	}
	if report.DepartmentID != "department:engineering" || report.DepartmentName != "Engineering" {
		t.Fatalf("department report = %+v, want engineering identity", report)
	}
	if report.PolicyCount != 2 || report.SatisfiedPolicyCount != 1 || report.AllPoliciesSatisfied {
		t.Fatalf("department report counts = %+v, want 2 policies, 1 satisfied, not all satisfied", report)
	}
	if got := []string{report.Policies[0].PolicyID, report.Policies[1].PolicyID}; !slices.Equal(got, []string{departmentPolicy.PolicyID, directPolicy.PolicyID}) {
		t.Fatalf("policy ids = %#v, want [%s %s]", got, departmentPolicy.PolicyID, directPolicy.PolicyID)
	}
	if got := report.Policies[0]; !got.DirectDepartmentAssignment || got.RequiredPeople != 2 || got.AcknowledgedPeople != 1 || !slices.Equal(got.PendingPersonIDs, []string{"person:alice"}) {
		t.Fatalf("department-assigned policy = %+v, want engineering coverage with alice pending", got)
	}
	if got := report.Policies[1]; got.DirectDepartmentAssignment || !got.Satisfied || got.RequiredPeople != 1 || got.AcknowledgedPeople != 1 {
		t.Fatalf("direct-member policy = %+v, want satisfied direct-person policy", got)
	}
	if _, ok := g.GetNode(otherDepartmentPolicy.PolicyID); !ok {
		t.Fatalf("expected support policy to exist")
	}
}

func TestOrganizationalPolicyAcknowledgmentStatusForDepartmentTreatsStaleAcknowledgmentAsPending(t *testing.T) {
	g := New()
	now := time.Date(2026, 3, 18, 23, 0, 0, 0, time.UTC)

	g.AddNode(&Node{ID: "person:owner", Kind: NodeKindPerson, Name: "Owner"})
	g.AddNode(&Node{ID: "person:alice", Kind: NodeKindPerson, Name: "Alice"})
	g.AddNode(&Node{ID: "department:engineering", Kind: NodeKindDepartment, Name: "Engineering"})
	g.AddEdge(&Edge{ID: "alice-eng", Source: "person:alice", Target: "department:engineering", Kind: EdgeKindMemberOf, Effect: EdgeEffectAllow})

	policy, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:                 "Data Classification Policy",
		PolicyVersion:         "v1",
		OwnerID:               "person:owner",
		RequiredDepartmentIDs: []string{"department:engineering"},
		ObservedAt:            now,
	})
	if err != nil {
		t.Fatalf("WriteOrganizationalPolicy(v1) returned error: %v", err)
	}
	if _, err := AcknowledgeOrganizationalPolicy(g, OrganizationalPolicyAcknowledgmentRequest{
		PersonID:       "person:alice",
		PolicyID:       policy.PolicyID,
		PolicyVersion:  "v1",
		AcknowledgedAt: now.Add(time.Minute),
	}); err != nil {
		t.Fatalf("AcknowledgeOrganizationalPolicy(v1) returned error: %v", err)
	}
	if _, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		ID:                    policy.PolicyID,
		Title:                 "Data Classification Policy",
		PolicyVersion:         "v2",
		OwnerID:               "person:owner",
		RequiredDepartmentIDs: []string{"department:engineering"},
		ObservedAt:            now.Add(2 * time.Minute),
	}); err != nil {
		t.Fatalf("WriteOrganizationalPolicy(v2) returned error: %v", err)
	}

	report, err := OrganizationalPolicyAcknowledgmentStatusForDepartment(g, "department:engineering")
	if err != nil {
		t.Fatalf("OrganizationalPolicyAcknowledgmentStatusForDepartment returned error: %v", err)
	}
	if report.PolicyCount != 1 {
		t.Fatalf("policy count = %d, want 1", report.PolicyCount)
	}
	got := report.Policies[0]
	if got.PolicyVersion != "v2" || got.AcknowledgedPeople != 0 || !slices.Equal(got.PendingPersonIDs, []string{"person:alice"}) || got.Satisfied {
		t.Fatalf("stale acknowledgment policy = %+v, want v2 with alice pending", got)
	}
}

func TestOrganizationalPolicyAcknowledgmentStatusForDepartmentValidatesInputs(t *testing.T) {
	if _, err := OrganizationalPolicyAcknowledgmentStatusForDepartment(nil, "department:engineering"); err == nil {
		t.Fatalf("expected error for nil graph")
	}

	g := New()
	if _, err := OrganizationalPolicyAcknowledgmentStatusForDepartment(g, ""); err == nil {
		t.Fatalf("expected error for empty department id")
	}

	g.AddNode(&Node{ID: "person:alice", Kind: NodeKindPerson, Name: "Alice"})
	if _, err := OrganizationalPolicyAcknowledgmentStatusForDepartment(g, "person:alice"); err == nil {
		t.Fatalf("expected error for non-department node")
	}
}
