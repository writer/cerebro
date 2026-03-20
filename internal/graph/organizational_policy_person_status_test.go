package graph

import (
	"slices"
	"testing"
	"time"
)

func TestOrganizationalPolicyAcknowledgmentStatusForPersonIncludesDirectAndDepartmentAssignments(t *testing.T) {
	g := New()
	now := time.Date(2026, 3, 18, 17, 0, 0, 0, time.UTC)

	g.AddNode(&Node{ID: "person:owner", Kind: NodeKindPerson, Name: "Owner"})
	g.AddNode(&Node{ID: "person:alice", Kind: NodeKindPerson, Name: "Alice"})
	g.AddNode(&Node{ID: "department:engineering", Kind: NodeKindDepartment, Name: "Engineering"})
	g.AddNode(&Node{ID: "department:support", Kind: NodeKindDepartment, Name: "Support"})
	g.AddEdge(&Edge{ID: "alice-eng", Source: "person:alice", Target: "department:engineering", Kind: EdgeKindMemberOf, Effect: EdgeEffectAllow})

	deptPolicy, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:                 "Engineering Security Policy",
		PolicyVersion:         "v1",
		OwnerID:               "person:owner",
		RequiredDepartmentIDs: []string{"department:engineering"},
		ObservedAt:            now,
	})
	if err != nil {
		t.Fatalf("WriteOrganizationalPolicy(dept) returned error: %v", err)
	}
	directPolicy, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:             "Acceptable Use Policy",
		PolicyVersion:     "v1",
		OwnerID:           "person:owner",
		RequiredPersonIDs: []string{"person:alice"},
		ObservedAt:        now.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("WriteOrganizationalPolicy(direct) returned error: %v", err)
	}
	if _, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:                 "Support Policy",
		PolicyVersion:         "v1",
		OwnerID:               "person:owner",
		RequiredDepartmentIDs: []string{"department:support"},
		ObservedAt:            now.Add(2 * time.Minute),
	}); err != nil {
		t.Fatalf("WriteOrganizationalPolicy(unrelated) returned error: %v", err)
	}

	report, err := OrganizationalPolicyAcknowledgmentStatusForPerson(g, "person:alice")
	if err != nil {
		t.Fatalf("OrganizationalPolicyAcknowledgmentStatusForPerson returned error: %v", err)
	}
	if report.RequiredPolicies != 2 {
		t.Fatalf("required policies = %d, want 2", report.RequiredPolicies)
	}
	if report.AcknowledgedPolicies != 0 {
		t.Fatalf("acknowledged policies = %d, want 0", report.AcknowledgedPolicies)
	}
	if !slices.Equal(report.PendingPolicyIDs, []string{directPolicy.PolicyID, deptPolicy.PolicyID}) {
		t.Fatalf("pending policy ids = %#v, want direct+dept policies", report.PendingPolicyIDs)
	}

	byID := make(map[string]OrganizationalPolicyPersonRequirement, len(report.Policies))
	for _, item := range report.Policies {
		byID[item.PolicyID] = item
	}

	if got := byID[directPolicy.PolicyID]; !got.DirectAssignment || len(got.DepartmentIDs) != 0 || got.Status != OrganizationalPolicyPersonStatusPending {
		t.Fatalf("direct requirement = %+v, want direct pending with no department ids", got)
	}
	if got := byID[deptPolicy.PolicyID]; got.DirectAssignment || !slices.Equal(got.DepartmentIDs, []string{"department:engineering"}) || got.Status != OrganizationalPolicyPersonStatusPending {
		t.Fatalf("department requirement = %+v, want engineering-scoped pending requirement", got)
	}
}

func TestOrganizationalPolicyAcknowledgmentStatusForPersonTracksAcknowledgedAndStalePolicies(t *testing.T) {
	g := New()
	now := time.Date(2026, 3, 18, 18, 0, 0, 0, time.UTC)

	g.AddNode(&Node{ID: "person:owner", Kind: NodeKindPerson, Name: "Owner"})
	g.AddNode(&Node{ID: "person:alice", Kind: NodeKindPerson, Name: "Alice"})
	g.AddNode(&Node{ID: "department:engineering", Kind: NodeKindDepartment, Name: "Engineering"})
	g.AddEdge(&Edge{ID: "alice-eng", Source: "person:alice", Target: "department:engineering", Kind: EdgeKindMemberOf, Effect: EdgeEffectAllow})

	acknowledgedPolicy, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:             "Acceptable Use Policy",
		PolicyVersion:     "v1",
		OwnerID:           "person:owner",
		RequiredPersonIDs: []string{"person:alice"},
		ObservedAt:        now,
	})
	if err != nil {
		t.Fatalf("WriteOrganizationalPolicy(acknowledged) returned error: %v", err)
	}
	stalePolicy, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:             "Access Control Policy",
		PolicyVersion:     "v1",
		OwnerID:           "person:owner",
		RequiredPersonIDs: []string{"person:alice"},
		ObservedAt:        now.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("WriteOrganizationalPolicy(stale) returned error: %v", err)
	}
	pendingPolicy, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:                 "Engineering Security Policy",
		PolicyVersion:         "v2",
		OwnerID:               "person:owner",
		RequiredDepartmentIDs: []string{"department:engineering"},
		ObservedAt:            now.Add(2 * time.Minute),
	})
	if err != nil {
		t.Fatalf("WriteOrganizationalPolicy(pending) returned error: %v", err)
	}

	if _, err := AcknowledgeOrganizationalPolicy(g, OrganizationalPolicyAcknowledgmentRequest{
		PersonID:       "person:alice",
		PolicyID:       acknowledgedPolicy.PolicyID,
		AcknowledgedAt: now.Add(3 * time.Minute),
	}); err != nil {
		t.Fatalf("AcknowledgeOrganizationalPolicy(acknowledged) returned error: %v", err)
	}
	if _, err := AcknowledgeOrganizationalPolicy(g, OrganizationalPolicyAcknowledgmentRequest{
		PersonID:       "person:alice",
		PolicyID:       stalePolicy.PolicyID,
		AcknowledgedAt: now.Add(4 * time.Minute),
	}); err != nil {
		t.Fatalf("AcknowledgeOrganizationalPolicy(stale v1) returned error: %v", err)
	}
	if _, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		ID:                stalePolicy.PolicyID,
		Title:             "Access Control Policy",
		PolicyVersion:     "v2",
		OwnerID:           "person:owner",
		RequiredPersonIDs: []string{"person:alice"},
		ObservedAt:        now.Add(5 * time.Minute),
	}); err != nil {
		t.Fatalf("WriteOrganizationalPolicy(stale v2) returned error: %v", err)
	}

	report, err := OrganizationalPolicyAcknowledgmentStatusForPerson(g, "person:alice")
	if err != nil {
		t.Fatalf("OrganizationalPolicyAcknowledgmentStatusForPerson returned error: %v", err)
	}
	if report.RequiredPolicies != 3 {
		t.Fatalf("required policies = %d, want 3", report.RequiredPolicies)
	}
	if report.AcknowledgedPolicies != 1 {
		t.Fatalf("acknowledged policies = %d, want 1", report.AcknowledgedPolicies)
	}
	if !slices.Equal(report.PendingPolicyIDs, []string{pendingPolicy.PolicyID}) {
		t.Fatalf("pending policy ids = %#v, want [%s]", report.PendingPolicyIDs, pendingPolicy.PolicyID)
	}
	if !slices.Equal(report.StalePolicyIDs, []string{stalePolicy.PolicyID}) {
		t.Fatalf("stale policy ids = %#v, want [%s]", report.StalePolicyIDs, stalePolicy.PolicyID)
	}

	byID := make(map[string]OrganizationalPolicyPersonRequirement, len(report.Policies))
	for _, item := range report.Policies {
		byID[item.PolicyID] = item
	}

	if got := byID[acknowledgedPolicy.PolicyID]; got.Status != OrganizationalPolicyPersonStatusAcknowledged || got.AcknowledgedAt == nil || got.AcknowledgedVersion != "v1" {
		t.Fatalf("acknowledged requirement = %+v, want acknowledged with timestamp and version", got)
	}
	if got := byID[stalePolicy.PolicyID]; got.Status != OrganizationalPolicyPersonStatusStale || got.AcknowledgedVersion != "v1" {
		t.Fatalf("stale requirement = %+v, want stale with old version", got)
	}
	if got := byID[pendingPolicy.PolicyID]; got.Status != OrganizationalPolicyPersonStatusPending {
		t.Fatalf("pending requirement = %+v, want pending", got)
	}
}

func TestOrganizationalPolicyAcknowledgmentStatusForPersonRequiresPerson(t *testing.T) {
	g := New()
	if _, err := OrganizationalPolicyAcknowledgmentStatusForPerson(g, ""); err == nil {
		t.Fatal("expected missing person_id error")
	}
	if _, err := OrganizationalPolicyAcknowledgmentStatusForPerson(g, "person:missing"); err == nil {
		t.Fatal("expected missing person error")
	}
}
