package graph

import (
	"slices"
	"testing"
	"time"
)

func TestOrganizationalPolicyProgramStatusAggregatesCoverage(t *testing.T) {
	g := New()
	now := time.Date(2026, 3, 18, 13, 0, 0, 0, time.UTC)

	g.AddNode(&Node{ID: "person:owner", Kind: NodeKindPerson, Name: "Owner"})
	g.AddNode(&Node{ID: "person:alice", Kind: NodeKindPerson, Name: "Alice"})
	g.AddNode(&Node{ID: "person:bob", Kind: NodeKindPerson, Name: "Bob"})
	g.AddNode(&Node{ID: "person:carol", Kind: NodeKindPerson, Name: "Carol"})
	g.AddNode(&Node{ID: "department:engineering", Kind: NodeKindDepartment, Name: "Engineering"})

	g.AddEdge(&Edge{ID: "alice-member", Source: "person:alice", Target: "department:engineering", Kind: EdgeKindMemberOf})
	g.AddEdge(&Edge{ID: "bob-member", Source: "person:bob", Target: "department:engineering", Kind: EdgeKindMemberOf})

	acceptableUse, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:                 "Acceptable Use Policy",
		PolicyVersion:         "v1",
		OwnerID:               "person:owner",
		FrameworkMappings:     []string{"soc2:cc6.1"},
		RequiredDepartmentIDs: []string{"department:engineering"},
		ObservedAt:            now,
	})
	if err != nil {
		t.Fatalf("WriteOrganizationalPolicy(acceptable use) error = %v", err)
	}
	incidentResponse, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:             "Incident Response Plan",
		PolicyVersion:     "v3",
		OwnerID:           "person:owner",
		FrameworkMappings: []string{"iso27001:a.5.24"},
		RequiredPersonIDs: []string{"person:carol"},
		ObservedAt:        now.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("WriteOrganizationalPolicy(incident response) error = %v", err)
	}

	if _, err := AcknowledgeOrganizationalPolicy(g, OrganizationalPolicyAcknowledgmentRequest{
		PersonID:       "person:alice",
		PolicyID:       acceptableUse.PolicyID,
		AcknowledgedAt: now.Add(2 * time.Minute),
	}); err != nil {
		t.Fatalf("AcknowledgeOrganizationalPolicy(alice) error = %v", err)
	}
	if _, err := AcknowledgeOrganizationalPolicy(g, OrganizationalPolicyAcknowledgmentRequest{
		PersonID:       "person:carol",
		PolicyID:       incidentResponse.PolicyID,
		AcknowledgedAt: now.Add(3 * time.Minute),
	}); err != nil {
		t.Fatalf("AcknowledgeOrganizationalPolicy(carol) error = %v", err)
	}

	report, err := OrganizationalPolicyProgramStatus(g, OrganizationalPolicyProgramStatusOptions{})
	if err != nil {
		t.Fatalf("OrganizationalPolicyProgramStatus() error = %v", err)
	}

	if report.PolicyCount != 2 {
		t.Fatalf("PolicyCount = %d, want 2", report.PolicyCount)
	}
	if report.FullyAcknowledgedPolicies != 1 {
		t.Fatalf("FullyAcknowledgedPolicies = %d, want 1", report.FullyAcknowledgedPolicies)
	}
	if report.TotalRequiredAcknowledgments != 3 {
		t.Fatalf("TotalRequiredAcknowledgments = %d, want 3", report.TotalRequiredAcknowledgments)
	}
	if report.TotalAcknowledged != 2 {
		t.Fatalf("TotalAcknowledged = %d, want 2", report.TotalAcknowledged)
	}

	first := report.Policies[0]
	if first.PolicyID != acceptableUse.PolicyID {
		t.Fatalf("first policy id = %q, want %q", first.PolicyID, acceptableUse.PolicyID)
	}
	if first.RequiredPeople != 2 || first.AcknowledgedPeople != 1 || first.PendingPeople != 1 {
		t.Fatalf("unexpected first policy counts: %+v", first)
	}
	if !slices.Equal(first.DepartmentGapIDs, []string{"department:engineering"}) {
		t.Fatalf("DepartmentGapIDs = %#v, want [department:engineering]", first.DepartmentGapIDs)
	}
	if first.FullyAcknowledged {
		t.Fatalf("expected acceptable use policy to remain incomplete, got %+v", first)
	}

	second := report.Policies[1]
	if second.PolicyID != incidentResponse.PolicyID {
		t.Fatalf("second policy id = %q, want %q", second.PolicyID, incidentResponse.PolicyID)
	}
	if !second.FullyAcknowledged {
		t.Fatalf("expected incident response policy to be fully acknowledged, got %+v", second)
	}
}

func TestOrganizationalPolicyProgramStatusFiltersFramework(t *testing.T) {
	g := New()
	now := time.Date(2026, 3, 18, 14, 0, 0, 0, time.UTC)

	g.AddNode(&Node{ID: "person:owner", Kind: NodeKindPerson, Name: "Owner"})
	g.AddNode(&Node{ID: "person:alice", Kind: NodeKindPerson, Name: "Alice"})

	if _, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:             "Acceptable Use Policy",
		PolicyVersion:     "v1",
		OwnerID:           "person:owner",
		FrameworkMappings: []string{"soc2:cc6.1"},
		RequiredPersonIDs: []string{"person:alice"},
		ObservedAt:        now,
	}); err != nil {
		t.Fatalf("WriteOrganizationalPolicy(soc2) error = %v", err)
	}
	if _, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:             "Data Classification Policy",
		PolicyVersion:     "v2",
		OwnerID:           "person:owner",
		FrameworkMappings: []string{"hipaa:164.312"},
		RequiredPersonIDs: []string{"person:alice"},
		ObservedAt:        now.Add(time.Minute),
	}); err != nil {
		t.Fatalf("WriteOrganizationalPolicy(hipaa) error = %v", err)
	}

	report, err := OrganizationalPolicyProgramStatus(g, OrganizationalPolicyProgramStatusOptions{Framework: "SOC 2"})
	if err != nil {
		t.Fatalf("OrganizationalPolicyProgramStatus(soc2) error = %v", err)
	}

	if report.Framework != "soc2" {
		t.Fatalf("Framework = %q, want soc2", report.Framework)
	}
	if report.PolicyCount != 1 {
		t.Fatalf("PolicyCount = %d, want 1", report.PolicyCount)
	}
	if len(report.Policies) != 1 || report.Policies[0].PolicyName != "Acceptable Use Policy" {
		t.Fatalf("unexpected filtered policies: %#v", report.Policies)
	}
	if !slices.Equal(report.Policies[0].FrameworkMappings, []string{"soc2:cc6.1"}) {
		t.Fatalf("FrameworkMappings = %#v, want [soc2:cc6.1]", report.Policies[0].FrameworkMappings)
	}
}

func TestOrganizationalPolicyProgramStatusDoesNotMarkEmptyScopeAsFullyAcknowledged(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "person:owner", Kind: NodeKindPerson, Name: "Owner"})

	if _, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:             "Information Security Policy",
		PolicyVersion:     "v1",
		OwnerID:           "person:owner",
		FrameworkMappings: []string{"iso27001:a.5.1"},
	}); err != nil {
		t.Fatalf("WriteOrganizationalPolicy(empty scope) error = %v", err)
	}

	report, err := OrganizationalPolicyProgramStatus(g, OrganizationalPolicyProgramStatusOptions{})
	if err != nil {
		t.Fatalf("OrganizationalPolicyProgramStatus() error = %v", err)
	}

	if report.PolicyCount != 1 {
		t.Fatalf("PolicyCount = %d, want 1", report.PolicyCount)
	}
	if report.FullyAcknowledgedPolicies != 0 {
		t.Fatalf("FullyAcknowledgedPolicies = %d, want 0", report.FullyAcknowledgedPolicies)
	}
	if report.Policies[0].FullyAcknowledged {
		t.Fatalf("expected empty-scope policy to remain not fully acknowledged, got %+v", report.Policies[0])
	}
	if report.Policies[0].RequiredPeople != 0 || report.Policies[0].PendingPeople != 0 {
		t.Fatalf("unexpected empty-scope counts: %+v", report.Policies[0])
	}
}

func TestOrganizationalPolicyProgramStatusRequiresGraph(t *testing.T) {
	if _, err := OrganizationalPolicyProgramStatus(nil, OrganizationalPolicyProgramStatusOptions{}); err == nil {
		t.Fatal("expected graph required error")
	}
}
