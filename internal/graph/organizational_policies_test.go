package graph

import (
	"testing"
	"time"
)

func TestWriteOrganizationalPolicyCreatesAssignments(t *testing.T) {
	g := New()
	now := time.Date(2026, 3, 17, 12, 0, 0, 0, time.UTC)

	g.AddNode(&Node{ID: "person:owner", Kind: NodeKindPerson, Name: "Owner"})
	g.AddNode(&Node{ID: "person:alice", Kind: NodeKindPerson, Name: "Alice"})
	g.AddNode(&Node{ID: "department:engineering", Kind: NodeKindDepartment, Name: "Engineering"})

	result, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:                 "Acceptable Use Policy",
		PolicyVersion:         "2026.03",
		OwnerID:               "person:owner",
		ReviewCycleDays:       365,
		FrameworkMappings:     []string{"soc2:cc6.1", "iso27001:a.5.1"},
		RequiredDepartmentIDs: []string{"department:engineering"},
		RequiredPersonIDs:     []string{"person:alice"},
		ObservedAt:            now,
	})
	if err != nil {
		t.Fatalf("WriteOrganizationalPolicy returned error: %v", err)
	}

	if result.PolicyID != "policy:acceptable-use-policy" {
		t.Fatalf("policy id = %q, want policy:acceptable-use-policy", result.PolicyID)
	}

	policy, ok := g.GetNode(result.PolicyID)
	if !ok || policy == nil {
		t.Fatalf("policy node not found")
	}
	if policy.Kind != NodeKindPolicy {
		t.Fatalf("policy kind = %q, want %q", policy.Kind, NodeKindPolicy)
	}
	if got := readString(policy.Properties, "policy_version"); got != "2026.03" {
		t.Fatalf("policy version = %q, want 2026.03", got)
	}
	if got := readString(policy.Properties, "owner_id"); got != "person:owner" {
		t.Fatalf("owner_id = %q, want person:owner", got)
	}
	if got := readInt(policy.Properties, "review_cycle_days"); got != 365 {
		t.Fatalf("review_cycle_days = %d, want 365", got)
	}

	engAssigned := false
	aliceAssigned := false
	for _, edge := range g.GetOutEdges(result.PolicyID) {
		if edge == nil || edge.Kind != EdgeKindAssignedTo {
			continue
		}
		switch edge.Target {
		case "department:engineering":
			engAssigned = true
		case "person:alice":
			aliceAssigned = true
		}
	}
	if !engAssigned || !aliceAssigned {
		t.Fatalf("expected policy assignments to department and person, got %#v", g.GetOutEdges(result.PolicyID))
	}

	_, err = WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		ID:                    result.PolicyID,
		Title:                 "Acceptable Use Policy",
		PolicyVersion:         "2026.04",
		OwnerID:               "person:owner",
		RequiredDepartmentIDs: []string{"department:engineering"},
		ObservedAt:            now.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("second WriteOrganizationalPolicy returned error: %v", err)
	}

	for _, edge := range g.GetOutEdges(result.PolicyID) {
		if edge != nil && edge.Kind == EdgeKindAssignedTo && edge.Target == "person:alice" {
			t.Fatalf("expected stale direct assignment to be removed")
		}
	}
}

func TestAcknowledgeOrganizationalPolicyRecordsCurrentVersion(t *testing.T) {
	g := New()
	now := time.Date(2026, 3, 17, 13, 0, 0, 0, time.UTC)

	g.AddNode(&Node{ID: "person:owner", Kind: NodeKindPerson, Name: "Owner"})
	g.AddNode(&Node{ID: "person:alice", Kind: NodeKindPerson, Name: "Alice"})

	policy, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:             "Incident Response Policy",
		PolicyVersion:     "v3",
		OwnerID:           "person:owner",
		RequiredPersonIDs: []string{"person:alice"},
		ObservedAt:        now,
	})
	if err != nil {
		t.Fatalf("WriteOrganizationalPolicy returned error: %v", err)
	}

	ack, err := AcknowledgeOrganizationalPolicy(g, OrganizationalPolicyAcknowledgmentRequest{
		PersonID:       "person:alice",
		PolicyID:       policy.PolicyID,
		AcknowledgedAt: now.Add(30 * time.Minute),
	})
	if err != nil {
		t.Fatalf("AcknowledgeOrganizationalPolicy returned error: %v", err)
	}
	if ack.PolicyVersion != "v3" {
		t.Fatalf("ack policy version = %q, want v3", ack.PolicyVersion)
	}

	found := false
	for _, edge := range g.GetOutEdges("person:alice") {
		if edge == nil || edge.Kind != EdgeKindAcknowledged || edge.Target != policy.PolicyID {
			continue
		}
		found = true
		if got := readString(edge.Properties, "policy_version"); got != "v3" {
			t.Fatalf("ack edge policy_version = %q, want v3", got)
		}
		if got := readString(edge.Properties, "acknowledged_at"); got == "" {
			t.Fatal("ack edge missing acknowledged_at")
		}
	}
	if !found {
		t.Fatalf("acknowledged edge not found")
	}
}

func TestOrganizationalPolicyAcknowledgmentStatusRollsUpByDepartment(t *testing.T) {
	g := New()
	now := time.Date(2026, 3, 17, 14, 0, 0, 0, time.UTC)

	g.AddNode(&Node{ID: "person:owner", Kind: NodeKindPerson, Name: "Owner"})
	g.AddNode(&Node{ID: "person:alice", Kind: NodeKindPerson, Name: "Alice"})
	g.AddNode(&Node{ID: "person:bob", Kind: NodeKindPerson, Name: "Bob"})
	g.AddNode(&Node{ID: "person:carol", Kind: NodeKindPerson, Name: "Carol"})
	g.AddNode(&Node{ID: "department:engineering", Kind: NodeKindDepartment, Name: "Engineering"})
	g.AddNode(&Node{ID: "department:support", Kind: NodeKindDepartment, Name: "Support"})
	g.AddEdge(&Edge{ID: "alice-eng", Source: "person:alice", Target: "department:engineering", Kind: EdgeKindMemberOf, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "bob-eng", Source: "person:bob", Target: "department:engineering", Kind: EdgeKindMemberOf, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "carol-support", Source: "person:carol", Target: "department:support", Kind: EdgeKindMemberOf, Effect: EdgeEffectAllow})

	policy, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:                 "Security Awareness Policy",
		PolicyVersion:         "2026.01",
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
		AcknowledgedAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("AcknowledgeOrganizationalPolicy(alice) returned error: %v", err)
	}
	if _, err := AcknowledgeOrganizationalPolicy(g, OrganizationalPolicyAcknowledgmentRequest{
		PersonID:       "person:carol",
		PolicyID:       policy.PolicyID,
		AcknowledgedAt: now.Add(2 * time.Hour),
	}); err != nil {
		t.Fatalf("AcknowledgeOrganizationalPolicy(carol) returned error: %v", err)
	}

	report, err := OrganizationalPolicyAcknowledgmentStatus(g, policy.PolicyID)
	if err != nil {
		t.Fatalf("OrganizationalPolicyAcknowledgmentStatus returned error: %v", err)
	}

	if report.RequiredPeople != 3 {
		t.Fatalf("required people = %d, want 3", report.RequiredPeople)
	}
	if report.AcknowledgedPeople != 2 {
		t.Fatalf("acknowledged people = %d, want 2", report.AcknowledgedPeople)
	}
	if len(report.PendingPersonIDs) != 1 || report.PendingPersonIDs[0] != "person:bob" {
		t.Fatalf("pending people = %#v, want [person:bob]", report.PendingPersonIDs)
	}

	if len(report.Departments) != 2 {
		t.Fatalf("department rollups = %d, want 2", len(report.Departments))
	}

	byID := make(map[string]OrganizationalPolicyDepartmentRollup, len(report.Departments))
	for _, item := range report.Departments {
		byID[item.DepartmentID] = item
	}

	engineering := byID["department:engineering"]
	if engineering.RequiredPeople != 2 || engineering.AcknowledgedPeople != 1 {
		t.Fatalf("engineering rollup = %+v, want required=2 acknowledged=1", engineering)
	}
	if len(engineering.PendingPersonIDs) != 1 || engineering.PendingPersonIDs[0] != "person:bob" {
		t.Fatalf("engineering pending = %#v, want [person:bob]", engineering.PendingPersonIDs)
	}

	support := byID["department:support"]
	if support.RequiredPeople != 1 || support.AcknowledgedPeople != 1 {
		t.Fatalf("support rollup = %+v, want required=1 acknowledged=1", support)
	}
}

func TestOrganizationalPolicyAcknowledgmentStatusIgnoresStaleVersion(t *testing.T) {
	g := New()
	now := time.Date(2026, 3, 17, 15, 0, 0, 0, time.UTC)

	g.AddNode(&Node{ID: "person:owner", Kind: NodeKindPerson, Name: "Owner"})
	g.AddNode(&Node{ID: "person:alice", Kind: NodeKindPerson, Name: "Alice"})

	policy, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:             "Access Control Policy",
		PolicyVersion:     "v1",
		OwnerID:           "person:owner",
		RequiredPersonIDs: []string{"person:alice"},
		ObservedAt:        now,
	})
	if err != nil {
		t.Fatalf("WriteOrganizationalPolicy returned error: %v", err)
	}
	if _, err := AcknowledgeOrganizationalPolicy(g, OrganizationalPolicyAcknowledgmentRequest{
		PersonID:       "person:alice",
		PolicyID:       policy.PolicyID,
		AcknowledgedAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("AcknowledgeOrganizationalPolicy returned error: %v", err)
	}

	if _, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		ID:                policy.PolicyID,
		Title:             "Access Control Policy",
		PolicyVersion:     "v2",
		OwnerID:           "person:owner",
		RequiredPersonIDs: []string{"person:alice"},
		ObservedAt:        now.Add(2 * time.Hour),
	}); err != nil {
		t.Fatalf("WriteOrganizationalPolicy(update) returned error: %v", err)
	}

	report, err := OrganizationalPolicyAcknowledgmentStatus(g, policy.PolicyID)
	if err != nil {
		t.Fatalf("OrganizationalPolicyAcknowledgmentStatus returned error: %v", err)
	}
	if report.PolicyVersion != "v2" {
		t.Fatalf("report policy version = %q, want v2", report.PolicyVersion)
	}
	if report.AcknowledgedPeople != 0 {
		t.Fatalf("acknowledged people = %d, want 0 after version change", report.AcknowledgedPeople)
	}
	if len(report.PendingPersonIDs) != 1 || report.PendingPersonIDs[0] != "person:alice" {
		t.Fatalf("pending people = %#v, want [person:alice]", report.PendingPersonIDs)
	}
}
