package graph

import (
	"testing"
	"time"
)

func TestOrganizationalPolicyReviewScheduleAtClassifiesCurrentDueAndOverduePolicies(t *testing.T) {
	g := New()
	asOf := time.Date(2026, 3, 18, 12, 0, 0, 0, time.UTC)

	g.AddNode(&Node{ID: "person:owner", Kind: NodeKindPerson, Name: "Owner"})

	if _, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:           "Current Review Policy",
		PolicyVersion:   "v1",
		OwnerID:         "person:owner",
		ReviewCycleDays: 30,
		ObservedAt:      asOf.AddDate(0, 0, -5),
	}); err != nil {
		t.Fatalf("WriteOrganizationalPolicy(current) returned error: %v", err)
	}
	if _, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:           "Due Today Policy",
		PolicyVersion:   "v1",
		OwnerID:         "person:owner",
		ReviewCycleDays: 30,
		ObservedAt:      asOf.AddDate(0, 0, -30).Add(-4 * time.Hour),
	}); err != nil {
		t.Fatalf("WriteOrganizationalPolicy(due) returned error: %v", err)
	}
	if _, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:           "Overdue Policy",
		PolicyVersion:   "v1",
		OwnerID:         "person:owner",
		ReviewCycleDays: 30,
		ObservedAt:      asOf.AddDate(0, 0, -45),
	}); err != nil {
		t.Fatalf("WriteOrganizationalPolicy(overdue) returned error: %v", err)
	}
	if _, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:         "No Cadence Policy",
		PolicyVersion: "v1",
		OwnerID:       "person:owner",
		ObservedAt:    asOf,
	}); err != nil {
		t.Fatalf("WriteOrganizationalPolicy(no cadence) returned error: %v", err)
	}

	report, err := OrganizationalPolicyReviewScheduleAt(g, asOf)
	if err != nil {
		t.Fatalf("OrganizationalPolicyReviewScheduleAt returned error: %v", err)
	}
	if report.PolicyCount != 3 {
		t.Fatalf("policy count = %d, want 3", report.PolicyCount)
	}
	if report.DuePolicies != 1 {
		t.Fatalf("due policies = %d, want 1", report.DuePolicies)
	}
	if report.OverduePolicies != 1 {
		t.Fatalf("overdue policies = %d, want 1", report.OverduePolicies)
	}
	if len(report.Policies) != 3 {
		t.Fatalf("schedule items = %d, want 3", len(report.Policies))
	}

	if report.Policies[0].PolicyName != "Overdue Policy" || report.Policies[0].Status != OrganizationalPolicyReviewStatusOverdue || report.Policies[0].DaysUntilReview != -15 {
		t.Fatalf("first review item = %+v, want overdue policy due 15 days ago", report.Policies[0])
	}
	if report.Policies[1].PolicyName != "Due Today Policy" || report.Policies[1].Status != OrganizationalPolicyReviewStatusDue || report.Policies[1].DaysUntilReview != 0 {
		t.Fatalf("second review item = %+v, want due-today policy", report.Policies[1])
	}
	if report.Policies[2].PolicyName != "Current Review Policy" || report.Policies[2].Status != OrganizationalPolicyReviewStatusCurrent || report.Policies[2].DaysUntilReview != 25 {
		t.Fatalf("third review item = %+v, want current policy due in 25 days", report.Policies[2])
	}
}

func TestOrganizationalPolicyReviewScheduleAtUsesLatestVersionHistoryTimestamp(t *testing.T) {
	g := New()
	asOf := time.Date(2026, 3, 18, 12, 0, 0, 0, time.UTC)

	g.AddNode(&Node{ID: "person:owner", Kind: NodeKindPerson, Name: "Owner"})

	policy, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:           "Review History Policy",
		PolicyVersion:   "v1",
		OwnerID:         "person:owner",
		ReviewCycleDays: 30,
		ObservedAt:      asOf.AddDate(0, 0, -90),
	})
	if err != nil {
		t.Fatalf("WriteOrganizationalPolicy(v1) returned error: %v", err)
	}
	if _, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		ID:              policy.PolicyID,
		Title:           "Review History Policy",
		PolicyVersion:   "v2",
		OwnerID:         "person:owner",
		ReviewCycleDays: 30,
		ObservedAt:      asOf.AddDate(0, 0, -10),
	}); err != nil {
		t.Fatalf("WriteOrganizationalPolicy(v2) returned error: %v", err)
	}

	report, err := OrganizationalPolicyReviewScheduleAt(g, asOf)
	if err != nil {
		t.Fatalf("OrganizationalPolicyReviewScheduleAt returned error: %v", err)
	}
	if len(report.Policies) != 1 {
		t.Fatalf("schedule items = %d, want 1", len(report.Policies))
	}
	item := report.Policies[0]
	if !item.LastReviewedAt.Equal(asOf.AddDate(0, 0, -10)) {
		t.Fatalf("last reviewed at = %s, want %s", item.LastReviewedAt, asOf.AddDate(0, 0, -10))
	}
	if !item.NextReviewAt.Equal(asOf.AddDate(0, 0, 20)) {
		t.Fatalf("next review at = %s, want %s", item.NextReviewAt, asOf.AddDate(0, 0, 20))
	}
	if item.Status != OrganizationalPolicyReviewStatusCurrent {
		t.Fatalf("status = %q, want current", item.Status)
	}
}

func TestWriteOrganizationalPolicyPreservesReviewCycleDaysWhenUpdateOmitsIt(t *testing.T) {
	g := New()
	asOf := time.Date(2026, 3, 18, 12, 0, 0, 0, time.UTC)

	g.AddNode(&Node{ID: "person:owner", Kind: NodeKindPerson, Name: "Owner"})

	policy, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		Title:           "Review Cadence Policy",
		PolicyVersion:   "v1",
		OwnerID:         "person:owner",
		ReviewCycleDays: 30,
		ObservedAt:      asOf.AddDate(0, 0, -35),
	})
	if err != nil {
		t.Fatalf("WriteOrganizationalPolicy(create) returned error: %v", err)
	}

	updatedObservedAt := asOf.AddDate(0, 0, -5)
	if _, err := WriteOrganizationalPolicy(g, OrganizationalPolicyWriteRequest{
		ID:            policy.PolicyID,
		Title:         "Review Cadence Policy",
		PolicyVersion: "v2",
		OwnerID:       "person:owner",
		ObservedAt:    updatedObservedAt,
	}); err != nil {
		t.Fatalf("WriteOrganizationalPolicy(update) returned error: %v", err)
	}

	policyNode, ok := g.GetNode(policy.PolicyID)
	if !ok || policyNode == nil {
		t.Fatalf("policy node %s not found after update", policy.PolicyID)
	}
	if got := readInt(policyNode.Properties, "review_cycle_days"); got != 30 {
		t.Fatalf("review_cycle_days = %d, want 30", got)
	}

	history, err := OrganizationalPolicyVersionHistory(g, policy.PolicyID)
	if err != nil {
		t.Fatalf("OrganizationalPolicyVersionHistory returned error: %v", err)
	}
	if len(history) != 2 {
		t.Fatalf("history entries = %d, want 2", len(history))
	}
	for _, field := range history[len(history)-1].ChangedFields {
		if field == "review_cycle_days" {
			t.Fatalf("latest changed fields unexpectedly include review_cycle_days: %v", history[len(history)-1].ChangedFields)
		}
	}

	report, err := OrganizationalPolicyReviewScheduleAt(g, asOf)
	if err != nil {
		t.Fatalf("OrganizationalPolicyReviewScheduleAt returned error: %v", err)
	}
	if len(report.Policies) != 1 {
		t.Fatalf("schedule items = %d, want 1", len(report.Policies))
	}
	item := report.Policies[0]
	if item.ReviewCycleDays != 30 {
		t.Fatalf("review cycle days = %d, want 30", item.ReviewCycleDays)
	}
	if !item.LastReviewedAt.Equal(updatedObservedAt) {
		t.Fatalf("last reviewed at = %s, want %s", item.LastReviewedAt, updatedObservedAt)
	}
	if item.Status != OrganizationalPolicyReviewStatusCurrent {
		t.Fatalf("status = %q, want current", item.Status)
	}
}

func TestOrganizationalPolicyReviewScheduleAtRequiresGraph(t *testing.T) {
	if _, err := OrganizationalPolicyReviewScheduleAt(nil, time.Time{}); err == nil {
		t.Fatal("expected nil graph error")
	}
}
