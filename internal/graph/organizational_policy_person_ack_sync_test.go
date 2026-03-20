package graph

import (
	"slices"
	"strings"
	"testing"
)

func TestAcknowledgeAssignedOrganizationalPoliciesForPersonAcknowledgesPendingAndStalePolicies(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "department:engineering", Kind: NodeKindDepartment, Name: "Engineering", Risk: RiskNone})
	g.AddNode(&Node{ID: "person:alice", Kind: NodeKindPerson, Name: "Alice", Risk: RiskNone})
	g.AddEdge(&Edge{ID: "alice-eng", Source: "person:alice", Target: "department:engineering", Kind: EdgeKindMemberOf, Effect: EdgeEffectAllow})

	pendingPolicy, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:                 "Acceptable Use Policy",
		PolicyVersion:         "v1",
		RequiredDepartmentIDs: []string{"department:engineering"},
	})
	if err != nil {
		t.Fatalf("WriteOrganizationalPolicy(pending) returned error: %v", err)
	}
	stalePolicy, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:             "Access Control Policy",
		PolicyVersion:     "v1",
		RequiredPersonIDs: []string{"person:alice"},
	})
	if err != nil {
		t.Fatalf("WriteOrganizationalPolicy(stale v1) returned error: %v", err)
	}
	if _, err := AcknowledgeOrganizationalPolicy(g, OrganizationalPolicyAcknowledgmentRequest{
		PersonID:      "person:alice",
		PolicyID:      stalePolicy.PolicyID,
		PolicyVersion: "v1",
	}); err != nil {
		t.Fatalf("AcknowledgeOrganizationalPolicy(stale v1) returned error: %v", err)
	}
	if _, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		ID:                stalePolicy.PolicyID,
		Title:             "Access Control Policy",
		PolicyVersion:     "v2",
		RequiredPersonIDs: []string{"person:alice"},
	}); err != nil {
		t.Fatalf("WriteOrganizationalPolicy(stale v2) returned error: %v", err)
	}
	currentPolicy, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:             "Change Management Policy",
		PolicyVersion:     "v1",
		RequiredPersonIDs: []string{"person:alice"},
	})
	if err != nil {
		t.Fatalf("WriteOrganizationalPolicy(current) returned error: %v", err)
	}
	if _, err := AcknowledgeOrganizationalPolicy(g, OrganizationalPolicyAcknowledgmentRequest{
		PersonID:      "person:alice",
		PolicyID:      currentPolicy.PolicyID,
		PolicyVersion: "v1",
	}); err != nil {
		t.Fatalf("AcknowledgeOrganizationalPolicy(current) returned error: %v", err)
	}

	result, err := AcknowledgeAssignedOrganizationalPoliciesForPerson(g, OrganizationalPolicyPersonAcknowledgmentSyncRequest{
		PersonID: "person:alice",
	})
	if err != nil {
		t.Fatalf("AcknowledgeAssignedOrganizationalPoliciesForPerson returned error: %v", err)
	}

	if !slices.Equal(result.AcknowledgedPolicyIDs, []string{pendingPolicy.PolicyID, stalePolicy.PolicyID}) {
		t.Fatalf("acknowledged policy ids = %#v", result.AcknowledgedPolicyIDs)
	}
	if !slices.Equal(result.AlreadyAcknowledgedPolicyIDs, []string{currentPolicy.PolicyID}) {
		t.Fatalf("already acknowledged policy ids = %#v", result.AlreadyAcknowledgedPolicyIDs)
	}
	if len(result.Acknowledgments) != 2 {
		t.Fatalf("acknowledgments = %#v, want 2 results", result.Acknowledgments)
	}

	report, err := OrganizationalPolicyAcknowledgmentStatusForPerson(g, "person:alice")
	if err != nil {
		t.Fatalf("OrganizationalPolicyAcknowledgmentStatusForPerson returned error: %v", err)
	}
	if report.RequiredPolicies != 3 || report.AcknowledgedPolicies != 3 {
		t.Fatalf("report counts = %+v, want all three acknowledged", report)
	}
	if len(report.PendingPolicyIDs) != 0 || len(report.StalePolicyIDs) != 0 {
		t.Fatalf("report pending/stale = %+v, want none", report)
	}
}

func TestAcknowledgeAssignedOrganizationalPoliciesForPersonSupportsSubset(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "person:alice", Kind: NodeKindPerson, Name: "Alice", Risk: RiskNone})

	firstPolicy, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:             "Data Classification Policy",
		PolicyVersion:     "v1",
		RequiredPersonIDs: []string{"person:alice"},
	})
	if err != nil {
		t.Fatalf("WriteOrganizationalPolicy(first) returned error: %v", err)
	}
	secondPolicy, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:             "Information Security Policy",
		PolicyVersion:     "v1",
		RequiredPersonIDs: []string{"person:alice"},
	})
	if err != nil {
		t.Fatalf("WriteOrganizationalPolicy(second) returned error: %v", err)
	}

	result, err := AcknowledgeAssignedOrganizationalPoliciesForPerson(g, OrganizationalPolicyPersonAcknowledgmentSyncRequest{
		PersonID:  "person:alice",
		PolicyIDs: []string{secondPolicy.PolicyID},
	})
	if err != nil {
		t.Fatalf("AcknowledgeAssignedOrganizationalPoliciesForPerson returned error: %v", err)
	}

	if !slices.Equal(result.AcknowledgedPolicyIDs, []string{secondPolicy.PolicyID}) {
		t.Fatalf("acknowledged policy ids = %#v, want second policy only", result.AcknowledgedPolicyIDs)
	}
	if len(result.AlreadyAcknowledgedPolicyIDs) != 0 {
		t.Fatalf("already acknowledged policy ids = %#v, want none", result.AlreadyAcknowledgedPolicyIDs)
	}

	report, err := OrganizationalPolicyAcknowledgmentStatusForPerson(g, "person:alice")
	if err != nil {
		t.Fatalf("OrganizationalPolicyAcknowledgmentStatusForPerson returned error: %v", err)
	}
	if !slices.Equal(report.PendingPolicyIDs, []string{firstPolicy.PolicyID}) {
		t.Fatalf("pending policy ids = %#v, want first policy only", report.PendingPolicyIDs)
	}
}

func TestAcknowledgeAssignedOrganizationalPoliciesForPersonUsesUniqueSourceEventIDsPerPolicy(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "person:alice", Kind: NodeKindPerson, Name: "Alice", Risk: RiskNone})

	firstPolicy, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:             "Data Classification Policy",
		PolicyVersion:     "v1",
		RequiredPersonIDs: []string{"person:alice"},
	})
	if err != nil {
		t.Fatalf("WriteOrganizationalPolicy(first) returned error: %v", err)
	}
	secondPolicy, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:             "Information Security Policy",
		PolicyVersion:     "v1",
		RequiredPersonIDs: []string{"person:alice"},
	})
	if err != nil {
		t.Fatalf("WriteOrganizationalPolicy(second) returned error: %v", err)
	}

	result, err := AcknowledgeAssignedOrganizationalPoliciesForPerson(g, OrganizationalPolicyPersonAcknowledgmentSyncRequest{
		PersonID:      "person:alice",
		SourceEventID: "sync:batch",
	})
	if err != nil {
		t.Fatalf("AcknowledgeAssignedOrganizationalPoliciesForPerson returned error: %v", err)
	}
	if len(result.Acknowledgments) != 2 {
		t.Fatalf("acknowledgments = %#v, want 2 results", result.Acknowledgments)
	}

	seen := map[string]string{}
	for _, ack := range result.Acknowledgments {
		if ack.SourceEventID == "sync:batch" {
			t.Fatalf("acknowledgment %s reused batch source event id", ack.PolicyID)
		}
		if !strings.HasPrefix(ack.SourceEventID, "sync:batch:policy:") {
			t.Fatalf("acknowledgment %s source event id = %q, want sync:batch:policy:*", ack.PolicyID, ack.SourceEventID)
		}
		if priorPolicyID, ok := seen[ack.SourceEventID]; ok {
			t.Fatalf("duplicate source event id %q for policies %s and %s", ack.SourceEventID, priorPolicyID, ack.PolicyID)
		}
		seen[ack.SourceEventID] = ack.PolicyID
	}
	if len(seen) != 2 {
		t.Fatalf("unique source event ids = %d, want 2", len(seen))
	}
	if _, ok := seen["sync:batch:policy:"+firstPolicy.PolicyID]; !ok {
		t.Fatalf("missing source event id for first policy: %#v", seen)
	}
	if _, ok := seen["sync:batch:policy:"+secondPolicy.PolicyID]; !ok {
		t.Fatalf("missing source event id for second policy: %#v", seen)
	}
}

func TestAcknowledgeAssignedOrganizationalPoliciesForPersonRejectsInvalidInput(t *testing.T) {
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
	unassignedPolicy, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:             "Vendor Security Policy",
		PolicyVersion:     "v1",
		RequiredPersonIDs: []string{"person:bob"},
	})
	if err != nil {
		t.Fatalf("WriteOrganizationalPolicy(unassigned) returned error: %v", err)
	}

	if _, err := AcknowledgeAssignedOrganizationalPoliciesForPerson(g, OrganizationalPolicyPersonAcknowledgmentSyncRequest{}); err == nil {
		t.Fatal("expected empty person id to fail")
	}
	if _, err := AcknowledgeAssignedOrganizationalPoliciesForPerson(g, OrganizationalPolicyPersonAcknowledgmentSyncRequest{
		PersonID:  "person:alice",
		PolicyIDs: []string{unassignedPolicy.PolicyID},
	}); err == nil {
		t.Fatal("expected unassigned policy to fail")
	}

	result, err := AcknowledgeAssignedOrganizationalPoliciesForPerson(g, OrganizationalPolicyPersonAcknowledgmentSyncRequest{
		PersonID:  "person:alice",
		PolicyIDs: []string{policy.PolicyID},
	})
	if err != nil {
		t.Fatalf("AcknowledgeAssignedOrganizationalPoliciesForPerson(valid subset) returned error: %v", err)
	}
	if !slices.Equal(result.AcknowledgedPolicyIDs, []string{policy.PolicyID}) {
		t.Fatalf("acknowledged policy ids = %#v, want assigned policy only", result.AcknowledgedPolicyIDs)
	}
}
