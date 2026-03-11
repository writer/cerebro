package graph

import (
	"testing"
	"time"
)

func TestReviewIdentityAlias_AcceptedAndRejected(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "person:alice@example.com", Kind: NodeKindPerson, Name: "Alice", Properties: map[string]any{"email": "alice@example.com"}})
	g.AddNode(&Node{ID: "person:bob@example.com", Kind: NodeKindPerson, Name: "Bob", Properties: map[string]any{"email": "bob@example.com"}})
	g.AddNode(&Node{ID: "alias:github:alice", Kind: NodeKindIdentityAlias, Name: "alice", Properties: map[string]any{
		"source_system": "github",
		"external_id":   "alice",
		"email":         "alice@example.com",
		"observed_at":   "2026-03-09T00:00:00Z",
		"valid_from":    "2026-03-09T00:00:00Z",
	}})

	accepted, err := ReviewIdentityAlias(g, IdentityReviewDecision{
		AliasNodeID:     "alias:github:alice",
		CanonicalNodeID: "person:alice@example.com",
		Verdict:         IdentityReviewVerdictAccepted,
		Reviewer:        "analyst@company.com",
		Reason:          "SSO email match",
	})
	if err != nil {
		t.Fatalf("accepted review failed: %v", err)
	}
	if !accepted.Applied {
		t.Fatalf("expected accepted review to apply alias link, got %#v", accepted)
	}

	aliasEdges := g.GetOutEdges("alias:github:alice")
	foundAlice := false
	for _, edge := range aliasEdges {
		if edge != nil && edge.Kind == EdgeKindAliasOf && edge.Target == "person:alice@example.com" {
			foundAlice = true
		}
	}
	if !foundAlice {
		t.Fatalf("expected alias link to alice, got %#v", aliasEdges)
	}

	rejected, err := ReviewIdentityAlias(g, IdentityReviewDecision{
		AliasNodeID:     "alias:github:alice",
		CanonicalNodeID: "person:bob@example.com",
		Verdict:         IdentityReviewVerdictRejected,
		Reviewer:        "analyst@company.com",
		Reason:          "Not the same person",
	})
	if err != nil {
		t.Fatalf("rejected review failed: %v", err)
	}
	if rejected.Applied {
		t.Fatalf("expected rejected review with no bob link to be non-applied, got %#v", rejected)
	}

	aliasNode, _ := g.GetNode("alias:github:alice")
	if aliasNode == nil {
		t.Fatal("expected alias node")
	}
	history := identityReviewHistory(aliasNode.Properties["identity_reviews"])
	if len(history) != 2 {
		t.Fatalf("expected 2 review history entries, got %#v", aliasNode.Properties["identity_reviews"])
	}
}

func TestBuildIdentityCalibrationReportAndQueue(t *testing.T) {
	now := time.Date(2026, 3, 9, 16, 0, 0, 0, time.UTC)
	g := New()
	g.AddNode(&Node{ID: "person:alice@example.com", Kind: NodeKindPerson, Name: "Alice", Properties: map[string]any{"email": "alice@example.com"}})
	g.AddNode(&Node{ID: "person:alicia@example.com", Kind: NodeKindPerson, Name: "Alicia", Properties: map[string]any{"email": "alicia@example.com"}})
	g.AddNode(&Node{ID: "person:bob@example.com", Kind: NodeKindPerson, Name: "Bob", Properties: map[string]any{"email": "bob@example.com"}})

	g.AddNode(&Node{ID: "alias:github:alice", Kind: NodeKindIdentityAlias, Name: "alice", Properties: map[string]any{
		"source_system": "github",
		"external_id":   "alice",
		"email":         "alice@example.com",
		"name":          "Alice",
		"observed_at":   now.Add(-2 * time.Hour).Format(time.RFC3339),
		"valid_from":    now.Add(-2 * time.Hour).Format(time.RFC3339),
	}})
	g.AddNode(&Node{ID: "alias:slack:alice", Kind: NodeKindIdentityAlias, Name: "alice.s", Properties: map[string]any{
		"source_system": "slack",
		"external_id":   "U123",
		"name":          "Alice Smith",
		"observed_at":   now.Add(-2 * time.Hour).Format(time.RFC3339),
		"valid_from":    now.Add(-2 * time.Hour).Format(time.RFC3339),
	}})

	if _, err := ReviewIdentityAlias(g, IdentityReviewDecision{
		AliasNodeID:     "alias:github:alice",
		CanonicalNodeID: "person:alice@example.com",
		Verdict:         IdentityReviewVerdictAccepted,
		ObservedAt:      now,
		Reviewer:        "reviewer-1",
		Reason:          "email exact match",
	}); err != nil {
		t.Fatalf("accepted review: %v", err)
	}
	if _, err := ReviewIdentityAlias(g, IdentityReviewDecision{
		AliasNodeID:     "alias:github:alice",
		CanonicalNodeID: "person:bob@example.com",
		Verdict:         IdentityReviewVerdictRejected,
		ObservedAt:      now.Add(1 * time.Minute),
		Reviewer:        "reviewer-1",
		Reason:          "false candidate",
	}); err != nil {
		t.Fatalf("rejected review: %v", err)
	}

	report := BuildIdentityCalibrationReport(g, IdentityCalibrationOptions{
		Now:              now,
		IncludeQueue:     true,
		QueueLimit:       10,
		SuggestThreshold: 0.2,
	})

	if report.AliasNodes != 2 {
		t.Fatalf("expected alias nodes 2, got %#v", report)
	}
	if report.ReviewedAliases < 1 {
		t.Fatalf("expected reviewed aliases >=1, got %#v", report)
	}
	if report.DecisionsTotal != 2 || report.AcceptedDecisions != 1 || report.RejectedDecisions != 1 {
		t.Fatalf("unexpected decision counters: %#v", report)
	}
	if report.PrecisionPercent != 50 {
		t.Fatalf("expected precision 50, got %.1f", report.PrecisionPercent)
	}
	if len(report.SourceMetrics) == 0 {
		t.Fatalf("expected source metrics, got %#v", report)
	}

	queue := IdentityReviewQueue(g, IdentityReviewQueueOptions{SuggestThreshold: 0.2, Limit: 10})
	if len(queue) == 0 {
		t.Fatalf("expected at least one queue item for unresolved alias, got %#v", queue)
	}
	if queue[0].AliasNodeID == "" {
		t.Fatalf("expected queue alias id, got %#v", queue[0])
	}
}
