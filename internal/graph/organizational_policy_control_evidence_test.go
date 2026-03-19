package graph

import (
	"slices"
	"testing"
	"time"
)

func TestOrganizationalPolicyControlEvidenceForControlReturnsMappedPolicyCoverage(t *testing.T) {
	g := New()
	now := time.Date(2026, 3, 18, 20, 0, 0, 0, time.UTC)

	g.AddNode(&Node{ID: "person:owner", Kind: NodeKindPerson, Name: "Owner"})
	g.AddNode(&Node{ID: "person:alice", Kind: NodeKindPerson, Name: "Alice"})
	g.AddNode(&Node{ID: "person:bob", Kind: NodeKindPerson, Name: "Bob"})
	g.AddNode(&Node{ID: "department:engineering", Kind: NodeKindDepartment, Name: "Engineering"})
	g.AddEdge(&Edge{ID: "alice-eng", Source: "person:alice", Target: "department:engineering", Kind: EdgeKindMemberOf, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "bob-eng", Source: "person:bob", Target: "department:engineering", Kind: EdgeKindMemberOf, Effect: EdgeEffectAllow})

	acceptableUse, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:             "Acceptable Use Policy",
		PolicyVersion:     "2026.03",
		OwnerID:           "person:owner",
		FrameworkMappings: []string{"SOC 2:CC6.1"},
		RequiredPersonIDs: []string{"person:alice"},
		ObservedAt:        now,
	})
	if err != nil {
		t.Fatalf("WriteOrganizationalPolicy(acceptable use) returned error: %v", err)
	}
	accessControl, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:                 "Access Control Policy",
		PolicyVersion:         "2026.03",
		OwnerID:               "person:owner",
		FrameworkMappings:     []string{"soc2:cc6.1", "iso27001:a.5.15"},
		RequiredDepartmentIDs: []string{"department:engineering"},
		ObservedAt:            now,
	})
	if err != nil {
		t.Fatalf("WriteOrganizationalPolicy(access control) returned error: %v", err)
	}
	if _, err := AcknowledgeOrganizationalPolicy(g, OrganizationalPolicyAcknowledgmentRequest{PersonID: "person:alice", PolicyID: acceptableUse.PolicyID, AcknowledgedAt: now.Add(time.Minute)}); err != nil {
		t.Fatalf("AcknowledgeOrganizationalPolicy(alice acceptable use) returned error: %v", err)
	}
	if _, err := AcknowledgeOrganizationalPolicy(g, OrganizationalPolicyAcknowledgmentRequest{PersonID: "person:bob", PolicyID: accessControl.PolicyID, AcknowledgedAt: now.Add(2 * time.Minute)}); err != nil {
		t.Fatalf("AcknowledgeOrganizationalPolicy(bob access control) returned error: %v", err)
	}

	report, err := OrganizationalPolicyControlEvidenceForControl(g, "soc 2", "CC6.1")
	if err != nil {
		t.Fatalf("OrganizationalPolicyControlEvidenceForControl returned error: %v", err)
	}
	if report.FrameworkID != "soc2" {
		t.Fatalf("framework id = %q, want soc2", report.FrameworkID)
	}
	if report.ControlID != "cc6-1" {
		t.Fatalf("control id = %q, want cc6-1", report.ControlID)
	}
	if report.PolicyCount != 2 {
		t.Fatalf("policy count = %d, want 2", report.PolicyCount)
	}
	if report.SatisfiedPolicyCount != 1 || report.AllPoliciesSatisfied {
		t.Fatalf("satisfaction = (%d,%v), want (1,false)", report.SatisfiedPolicyCount, report.AllPoliciesSatisfied)
	}
	if got := []string{report.Policies[0].PolicyID, report.Policies[1].PolicyID}; !slices.Equal(got, []string{acceptableUse.PolicyID, accessControl.PolicyID}) {
		t.Fatalf("policy ids = %#v, want [%s %s]", got, acceptableUse.PolicyID, accessControl.PolicyID)
	}
	if got := report.Policies[0]; !got.Satisfied || got.RequiredPeople != 1 || got.AcknowledgedPeople != 1 || len(got.PendingPersonIDs) != 0 {
		t.Fatalf("acceptable use evidence = %+v, want satisfied single-person coverage", got)
	}
	if got := report.Policies[1]; got.Satisfied || got.RequiredPeople != 2 || got.AcknowledgedPeople != 1 || !slices.Equal(got.PendingPersonIDs, []string{"person:alice"}) {
		t.Fatalf("access control evidence = %+v, want one pending engineering member", got)
	}
}

func TestOrganizationalPolicyControlEvidenceForControlIgnoresStaleAndUnmappedPolicies(t *testing.T) {
	g := New()
	now := time.Date(2026, 3, 18, 21, 0, 0, 0, time.UTC)

	g.AddNode(&Node{ID: "person:owner", Kind: NodeKindPerson, Name: "Owner"})
	g.AddNode(&Node{ID: "person:alice", Kind: NodeKindPerson, Name: "Alice"})

	policy, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:             "Acceptable Use Policy",
		PolicyVersion:     "v1",
		OwnerID:           "person:owner",
		FrameworkMappings: []string{"soc2:cc6.2"},
		RequiredPersonIDs: []string{"person:alice"},
		ObservedAt:        now,
	})
	if err != nil {
		t.Fatalf("WriteOrganizationalPolicy(v1) returned error: %v", err)
	}
	if _, err := AcknowledgeOrganizationalPolicy(g, OrganizationalPolicyAcknowledgmentRequest{PersonID: "person:alice", PolicyID: policy.PolicyID, PolicyVersion: "v1", AcknowledgedAt: now.Add(time.Minute)}); err != nil {
		t.Fatalf("AcknowledgeOrganizationalPolicy(v1) returned error: %v", err)
	}
	if _, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		ID:                policy.PolicyID,
		Title:             "Acceptable Use Policy",
		PolicyVersion:     "v2",
		OwnerID:           "person:owner",
		FrameworkMappings: []string{"soc2:cc6.2"},
		RequiredPersonIDs: []string{"person:alice"},
		ObservedAt:        now.Add(2 * time.Minute),
	}); err != nil {
		t.Fatalf("WriteOrganizationalPolicy(v2) returned error: %v", err)
	}
	if _, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:             "Incident Response Plan",
		PolicyVersion:     "v1",
		OwnerID:           "person:owner",
		FrameworkMappings: []string{"soc2:cc7.4"},
		RequiredPersonIDs: []string{"person:alice"},
		ObservedAt:        now,
	}); err != nil {
		t.Fatalf("WriteOrganizationalPolicy(unmapped) returned error: %v", err)
	}

	report, err := OrganizationalPolicyControlEvidenceForControl(g, "SOC2", "cc6.2")
	if err != nil {
		t.Fatalf("OrganizationalPolicyControlEvidenceForControl returned error: %v", err)
	}
	if report.PolicyCount != 1 {
		t.Fatalf("policy count = %d, want 1", report.PolicyCount)
	}
	if got := report.Policies[0]; got.PolicyVersion != "v2" || got.AcknowledgedPeople != 0 || !slices.Equal(got.PendingPersonIDs, []string{"person:alice"}) {
		t.Fatalf("stale acknowledgment evidence = %+v, want current version pending alice", got)
	}
}

func TestOrganizationalPolicyControlEvidenceForControlTreatsZeroScopePoliciesAsSatisfied(t *testing.T) {
	g := New()
	now := time.Date(2026, 3, 19, 0, 0, 0, 0, time.UTC)

	g.AddNode(&Node{ID: "person:owner", Kind: NodeKindPerson, Name: "Owner"})

	policy, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:             "Public Conduct Guidelines",
		PolicyVersion:     "v1",
		OwnerID:           "person:owner",
		FrameworkMappings: []string{"soc2:cc6.3"},
		ObservedAt:        now,
	})
	if err != nil {
		t.Fatalf("WriteOrganizationalPolicy returned error: %v", err)
	}

	report, err := OrganizationalPolicyControlEvidenceForControl(g, "soc2", "cc6.3")
	if err != nil {
		t.Fatalf("OrganizationalPolicyControlEvidenceForControl returned error: %v", err)
	}
	if report.PolicyCount != 1 || report.SatisfiedPolicyCount != 1 || !report.AllPoliciesSatisfied {
		t.Fatalf("report satisfaction = %+v, want single satisfied zero-scope policy", report)
	}
	if got := report.Policies[0]; got.PolicyID != policy.PolicyID || got.RequiredPeople != 0 || got.AcknowledgedPeople != 0 || !got.Satisfied || len(got.PendingPersonIDs) != 0 {
		t.Fatalf("zero-scope policy evidence = %+v, want satisfied zero-scope coverage", got)
	}
}

func TestOrganizationalPolicyControlEvidenceForControlValidatesInputs(t *testing.T) {
	if _, err := OrganizationalPolicyControlEvidenceForControl(nil, "soc2", "cc6.1"); err == nil {
		t.Fatalf("expected error for nil graph")
	}

	g := New()
	if _, err := OrganizationalPolicyControlEvidenceForControl(g, "", "cc6.1"); err == nil {
		t.Fatalf("expected error for empty framework")
	}
	if _, err := OrganizationalPolicyControlEvidenceForControl(g, "soc2", ""); err == nil {
		t.Fatalf("expected error for empty control")
	}

	report, err := OrganizationalPolicyControlEvidenceForControl(g, "soc2", "cc6.1")
	if err != nil {
		t.Fatalf("unexpected error for empty graph: %v", err)
	}
	if report.PolicyCount != 0 || report.AllPoliciesSatisfied || len(report.Policies) != 0 {
		t.Fatalf("empty graph report = %+v, want empty unsatisfied report", report)
	}
}
