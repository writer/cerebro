package graph

import (
	"slices"
	"strings"
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
	if result.VersionHistoryEntries != 1 {
		t.Fatalf("version history entries = %d, want 1", result.VersionHistoryEntries)
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

	history, err := OrganizationalPolicyVersionHistory(g, result.PolicyID)
	if err != nil {
		t.Fatalf("OrganizationalPolicyVersionHistory returned error: %v", err)
	}
	if len(history) != 1 {
		t.Fatalf("version history length = %d, want 1", len(history))
	}
	if history[0].PolicyVersion != "2026.03" {
		t.Fatalf("history[0] policy version = %q, want 2026.03", history[0].PolicyVersion)
	}
	if len(history[0].ChangedFields) != 0 {
		t.Fatalf("history[0] changed fields = %#v, want none", history[0].ChangedFields)
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

func TestWriteOrganizationalPolicyTracksVersionHistoryAndDiffs(t *testing.T) {
	g := New()
	now := time.Date(2026, 3, 18, 9, 0, 0, 0, time.UTC)

	g.AddNode(&Node{ID: "person:owner", Kind: NodeKindPerson, Name: "Owner"})
	g.AddNode(&Node{ID: "person:alice", Kind: NodeKindPerson, Name: "Alice"})
	g.AddNode(&Node{ID: "person:bob", Kind: NodeKindPerson, Name: "Bob"})
	g.AddNode(&Node{ID: "department:engineering", Kind: NodeKindDepartment, Name: "Engineering"})
	g.AddNode(&Node{ID: "department:security", Kind: NodeKindDepartment, Name: "Security"})

	created, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:                 "Data Classification Policy",
		Summary:               "Initial summary",
		PolicyVersion:         "v1",
		Content:               "employees must classify data before sharing",
		OwnerID:               "person:owner",
		ReviewCycleDays:       90,
		FrameworkMappings:     []string{"hipaa:164.312", "pci:3.2"},
		RequiredDepartmentIDs: []string{"department:engineering"},
		RequiredPersonIDs:     []string{"person:alice"},
		ObservedAt:            now,
	})
	if err != nil {
		t.Fatalf("WriteOrganizationalPolicy(create) returned error: %v", err)
	}
	if created.VersionHistoryEntries != 1 {
		t.Fatalf("create version history entries = %d, want 1", created.VersionHistoryEntries)
	}

	updated, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		ID:                    created.PolicyID,
		Title:                 "Data Classification Policy",
		Summary:               "Updated summary",
		PolicyVersion:         "v2",
		Content:               "employees must classify and label data before sharing",
		OwnerID:               "person:owner",
		ReviewCycleDays:       180,
		FrameworkMappings:     []string{"hipaa:164.312", "soc2:cc6.1"},
		RequiredDepartmentIDs: []string{"department:security"},
		RequiredPersonIDs:     []string{"person:bob"},
		ObservedAt:            now.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("WriteOrganizationalPolicy(update) returned error: %v", err)
	}

	wantChanged := []string{
		"content_digest",
		"framework_mappings",
		"policy_version",
		"required_department_ids",
		"required_person_ids",
		"review_cycle_days",
		"summary",
	}
	if !slices.Equal(updated.ChangedFields, wantChanged) {
		t.Fatalf("changed fields = %#v, want %#v", updated.ChangedFields, wantChanged)
	}
	if updated.VersionHistoryEntries != 2 {
		t.Fatalf("update version history entries = %d, want 2", updated.VersionHistoryEntries)
	}

	history, err := OrganizationalPolicyVersionHistory(g, created.PolicyID)
	if err != nil {
		t.Fatalf("OrganizationalPolicyVersionHistory returned error: %v", err)
	}
	if len(history) != 2 {
		t.Fatalf("version history length = %d, want 2", len(history))
	}
	if history[0].PolicyVersion != "v1" || history[1].PolicyVersion != "v2" {
		t.Fatalf("history versions = [%q %q], want [v1 v2]", history[0].PolicyVersion, history[1].PolicyVersion)
	}
	if !strings.HasPrefix(history[0].ContentDigest, "sha256:") || !strings.HasPrefix(history[1].ContentDigest, "sha256:") {
		t.Fatalf("history content digests = [%q %q], want sha256-prefixed digests", history[0].ContentDigest, history[1].ContentDigest)
	}
	if !slices.Equal(history[1].ChangedFields, wantChanged) {
		t.Fatalf("history[1] changed fields = %#v, want %#v", history[1].ChangedFields, wantChanged)
	}
	if !slices.Equal(history[0].RequiredDepartmentIDs, []string{"department:engineering"}) {
		t.Fatalf("history[0] required departments = %#v, want [department:engineering]", history[0].RequiredDepartmentIDs)
	}
	if !slices.Equal(history[1].RequiredPersonIDs, []string{"person:bob"}) {
		t.Fatalf("history[1] required people = %#v, want [person:bob]", history[1].RequiredPersonIDs)
	}
}

func TestWriteOrganizationalPolicyDoesNotAppendHistoryForNoopRewrite(t *testing.T) {
	g := New()
	now := time.Date(2026, 3, 18, 10, 0, 0, 0, time.UTC)

	g.AddNode(&Node{ID: "person:owner", Kind: NodeKindPerson, Name: "Owner"})
	g.AddNode(&Node{ID: "person:alice", Kind: NodeKindPerson, Name: "Alice"})

	created, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:             "Acceptable Use Policy",
		Summary:           "Baseline",
		PolicyVersion:     "v1",
		ContentDigest:     "sha256:baseline",
		OwnerID:           "person:owner",
		RequiredPersonIDs: []string{"person:alice"},
		ObservedAt:        now,
	})
	if err != nil {
		t.Fatalf("WriteOrganizationalPolicy(create) returned error: %v", err)
	}

	rewritten, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		ID:                created.PolicyID,
		Title:             "Acceptable Use Policy",
		Summary:           "Baseline",
		PolicyVersion:     "v1",
		ContentDigest:     "sha256:baseline",
		OwnerID:           "person:owner",
		RequiredPersonIDs: []string{"person:alice"},
		ObservedAt:        now.Add(2 * time.Hour),
	})
	if err != nil {
		t.Fatalf("WriteOrganizationalPolicy(rewrite) returned error: %v", err)
	}
	if len(rewritten.ChangedFields) != 0 {
		t.Fatalf("changed fields = %#v, want none", rewritten.ChangedFields)
	}
	if rewritten.VersionHistoryEntries != 1 {
		t.Fatalf("version history entries = %d, want 1", rewritten.VersionHistoryEntries)
	}

	history, err := OrganizationalPolicyVersionHistory(g, created.PolicyID)
	if err != nil {
		t.Fatalf("OrganizationalPolicyVersionHistory returned error: %v", err)
	}
	if len(history) != 1 {
		t.Fatalf("version history length = %d, want 1", len(history))
	}
}

func TestWriteOrganizationalPolicyBackfillsLegacyVersionHistory(t *testing.T) {
	g := New()
	now := time.Date(2026, 3, 18, 11, 0, 0, 0, time.UTC)

	g.AddNode(&Node{ID: "person:owner", Kind: NodeKindPerson, Name: "Owner"})
	g.AddNode(&Node{ID: "person:alice", Kind: NodeKindPerson, Name: "Alice"})
	g.AddNode(&Node{ID: "person:bob", Kind: NodeKindPerson, Name: "Bob"})

	created, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:             "Access Control Policy",
		Summary:           "Original",
		PolicyVersion:     "v1",
		ContentDigest:     "sha256:legacy-v1",
		OwnerID:           "person:owner",
		RequiredPersonIDs: []string{"person:alice"},
		ObservedAt:        now,
	})
	if err != nil {
		t.Fatalf("WriteOrganizationalPolicy(create) returned error: %v", err)
	}

	policy, ok := g.GetNode(created.PolicyID)
	if !ok || policy == nil {
		t.Fatalf("policy node not found")
	}
	delete(policy.Properties, "version_history")

	updated, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		ID:                created.PolicyID,
		Title:             "Access Control Policy",
		Summary:           "Original",
		PolicyVersion:     "v2",
		ContentDigest:     "sha256:legacy-v2",
		OwnerID:           "person:owner",
		RequiredPersonIDs: []string{"person:bob"},
		ObservedAt:        now.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("WriteOrganizationalPolicy(update) returned error: %v", err)
	}
	wantChanged := []string{"content_digest", "policy_version", "required_person_ids"}
	if !slices.Equal(updated.ChangedFields, wantChanged) {
		t.Fatalf("changed fields = %#v, want %#v", updated.ChangedFields, wantChanged)
	}

	history, err := OrganizationalPolicyVersionHistory(g, created.PolicyID)
	if err != nil {
		t.Fatalf("OrganizationalPolicyVersionHistory returned error: %v", err)
	}
	if len(history) != 2 {
		t.Fatalf("version history length = %d, want 2", len(history))
	}
	if history[0].PolicyVersion != "v1" || history[1].PolicyVersion != "v2" {
		t.Fatalf("history versions = [%q %q], want [v1 v2]", history[0].PolicyVersion, history[1].PolicyVersion)
	}
	if !slices.Equal(history[0].RequiredPersonIDs, []string{"person:alice"}) {
		t.Fatalf("legacy history required people = %#v, want [person:alice]", history[0].RequiredPersonIDs)
	}
	if !slices.Equal(history[1].ChangedFields, wantChanged) {
		t.Fatalf("history[1] changed fields = %#v, want %#v", history[1].ChangedFields, wantChanged)
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
