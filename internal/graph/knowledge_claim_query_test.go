package graph

import (
	"testing"
	"time"
)

func TestQueryClaimsBuildsDerivedStateAndFilters(t *testing.T) {
	g := New()
	baseProperties := map[string]any{
		"observed_at":      "2026-03-09T00:00:00Z",
		"valid_from":       "2026-03-09T00:00:00Z",
		"recorded_at":      "2026-03-09T00:00:00Z",
		"transaction_from": "2026-03-09T00:00:00Z",
	}
	g.AddNode(&Node{ID: "service:payments", Kind: NodeKindService, Name: "Payments", Properties: cloneAnyMap(baseProperties)})
	g.AddNode(&Node{ID: "person:alice@example.com", Kind: NodeKindPerson, Name: "Alice", Properties: cloneAnyMap(baseProperties)})
	g.AddNode(&Node{ID: "person:bob@example.com", Kind: NodeKindPerson, Name: "Bob", Properties: cloneAnyMap(baseProperties)})
	g.AddNode(&Node{ID: "person:carol@example.com", Kind: NodeKindPerson, Name: "Carol", Properties: cloneAnyMap(baseProperties)})
	evidenceProps := cloneAnyMap(baseProperties)
	evidenceProps["evidence_type"] = "document"
	g.AddNode(&Node{ID: "evidence:runbook", Kind: NodeKindEvidence, Name: "Runbook", Properties: evidenceProps})

	recordedA := time.Date(2026, 3, 9, 10, 0, 0, 0, time.UTC)
	recordedB := time.Date(2026, 3, 9, 11, 0, 0, 0, time.UTC)
	recordedC := time.Date(2026, 3, 9, 9, 0, 0, 0, time.UTC)

	if _, err := WriteClaim(g, ClaimWriteRequest{
		ID:              "claim:payments:owner:alice",
		SubjectID:       "service:payments",
		Predicate:       "owner",
		ObjectID:        "person:alice@example.com",
		Summary:         "Payments is owned by Alice",
		EvidenceIDs:     []string{"evidence:runbook"},
		SourceName:      "CMDB",
		SourceType:      "system",
		SourceSystem:    "cmdb",
		ObservedAt:      recordedA,
		ValidFrom:       recordedA,
		RecordedAt:      recordedA,
		TransactionFrom: recordedA,
		Metadata: map[string]any{
			"ticket_id": "OPS-123",
		},
	}); err != nil {
		t.Fatalf("write claim alice: %v", err)
	}
	if _, err := WriteClaim(g, ClaimWriteRequest{
		ID:              "claim:payments:owner:bob",
		SubjectID:       "service:payments",
		Predicate:       "owner",
		ObjectID:        "person:bob@example.com",
		Summary:         "Payments is owned by Bob",
		SourceSystem:    "api",
		ObservedAt:      recordedB,
		ValidFrom:       recordedB,
		RecordedAt:      recordedB,
		TransactionFrom: recordedB,
	}); err != nil {
		t.Fatalf("write claim bob: %v", err)
	}
	if _, err := WriteClaim(g, ClaimWriteRequest{
		ID:              "claim:payments:owner:carol",
		SubjectID:       "service:payments",
		Predicate:       "owner",
		ObjectID:        "person:carol@example.com",
		Status:          "corrected",
		Summary:         "Payments used to be owned by Carol",
		SourceName:      "Archive",
		SourceType:      "document",
		SourceSystem:    "docs",
		ObservedAt:      recordedC,
		ValidFrom:       recordedC,
		RecordedAt:      recordedC,
		TransactionFrom: recordedC,
	}); err != nil {
		t.Fatalf("write claim carol: %v", err)
	}

	result := QueryClaims(g, ClaimQueryOptions{
		SubjectID:  "service:payments",
		RecordedAt: time.Date(2026, 3, 9, 12, 0, 0, 0, time.UTC),
		ValidAt:    time.Date(2026, 3, 9, 12, 0, 0, 0, time.UTC),
	})

	if got := result.Summary.MatchedClaims; got != 2 {
		t.Fatalf("expected 2 matched claims, got %+v", result.Summary)
	}
	if got := result.Summary.ActiveClaims; got != 2 {
		t.Fatalf("expected 2 active claims, got %+v", result.Summary)
	}
	if got := result.Summary.SupportedClaims; got != 1 {
		t.Fatalf("expected 1 supported claim, got %+v", result.Summary)
	}
	if got := result.Summary.UnsupportedClaims; got != 1 {
		t.Fatalf("expected 1 unsupported claim, got %+v", result.Summary)
	}
	if got := result.Summary.SourceBackedClaims; got != 1 {
		t.Fatalf("expected 1 source-backed claim, got %+v", result.Summary)
	}
	if got := result.Summary.SourcelessClaims; got != 1 {
		t.Fatalf("expected 1 sourceless claim, got %+v", result.Summary)
	}
	if got := result.Summary.ConflictedClaims; got != 2 {
		t.Fatalf("expected 2 conflicted claims, got %+v", result.Summary)
	}
	if len(result.Claims) != 2 {
		t.Fatalf("expected 2 returned claims, got %d", len(result.Claims))
	}

	first := result.Claims[0]
	if first.ID != "claim:payments:owner:bob" {
		t.Fatalf("expected most recent claim first, got %+v", first)
	}
	if first.Derived.Supported {
		t.Fatalf("expected bob claim to be unsupported, got %+v", first.Derived)
	}
	if !first.Derived.Sourceless {
		t.Fatalf("expected bob claim to be sourceless, got %+v", first.Derived)
	}
	if !first.Derived.Conflicted {
		t.Fatalf("expected bob claim to be conflicted, got %+v", first.Derived)
	}
	if len(first.Links.ConflictingClaimIDs) != 1 || first.Links.ConflictingClaimIDs[0] != "claim:payments:owner:alice" {
		t.Fatalf("expected alice as conflicting peer, got %+v", first.Links)
	}

	second := result.Claims[1]
	if second.ID != "claim:payments:owner:alice" {
		t.Fatalf("expected alice claim second, got %+v", second)
	}
	if !second.Derived.Supported || !second.Derived.SourceBacked {
		t.Fatalf("expected alice claim to be supported and source-backed, got %+v", second.Derived)
	}
	if second.Metadata["ticket_id"] != "OPS-123" {
		t.Fatalf("expected ticket_id metadata to survive read model, got %#v", second.Metadata)
	}

	unsupported := false
	filtered := QueryClaims(g, ClaimQueryOptions{
		SubjectID:  "service:payments",
		Supported:  &unsupported,
		RecordedAt: time.Date(2026, 3, 9, 12, 0, 0, 0, time.UTC),
		ValidAt:    time.Date(2026, 3, 9, 12, 0, 0, 0, time.UTC),
	})
	if len(filtered.Claims) != 1 || filtered.Claims[0].ID != "claim:payments:owner:bob" {
		t.Fatalf("expected only bob in unsupported filter, got %+v", filtered.Claims)
	}

	resolved := QueryClaims(g, ClaimQueryOptions{
		SubjectID:  "service:payments",
		Status:     "corrected",
		RecordedAt: time.Date(2026, 3, 9, 12, 0, 0, 0, time.UTC),
		ValidAt:    time.Date(2026, 3, 9, 12, 0, 0, 0, time.UTC),
	})
	if len(resolved.Claims) != 1 || resolved.Claims[0].ID != "claim:payments:owner:carol" {
		t.Fatalf("expected corrected claim to be queryable by status, got %+v", resolved.Claims)
	}
}

func TestGetClaimRecordRespectsBitemporalVisibility(t *testing.T) {
	g := New()
	baseProperties := map[string]any{
		"observed_at":      "2026-03-09T00:00:00Z",
		"valid_from":       "2026-03-09T00:00:00Z",
		"recorded_at":      "2026-03-09T00:00:00Z",
		"transaction_from": "2026-03-09T00:00:00Z",
	}
	g.AddNode(&Node{ID: "service:payments", Kind: NodeKindService, Name: "Payments", Properties: cloneAnyMap(baseProperties)})
	g.AddNode(&Node{ID: "person:alice@example.com", Kind: NodeKindPerson, Name: "Alice", Properties: cloneAnyMap(baseProperties)})

	recordedAt := time.Date(2026, 3, 9, 12, 0, 0, 0, time.UTC)
	if _, err := WriteClaim(g, ClaimWriteRequest{
		ID:              "claim:payments:owner:alice",
		SubjectID:       "service:payments",
		Predicate:       "owner",
		ObjectID:        "person:alice@example.com",
		SourceSystem:    "api",
		ObservedAt:      recordedAt,
		ValidFrom:       recordedAt,
		RecordedAt:      recordedAt,
		TransactionFrom: recordedAt,
	}); err != nil {
		t.Fatalf("write claim: %v", err)
	}

	if _, ok := GetClaimRecord(g, "claim:payments:owner:alice", recordedAt, recordedAt.Add(-time.Minute)); ok {
		t.Fatal("expected claim to be hidden before transaction_from")
	}

	record, ok := GetClaimRecord(g, "claim:payments:owner:alice", recordedAt, recordedAt)
	if !ok {
		t.Fatal("expected claim to be visible at transaction_from")
	}
	if record.ID != "claim:payments:owner:alice" {
		t.Fatalf("unexpected claim record: %+v", record)
	}
	if record.TransactionFrom != recordedAt {
		t.Fatalf("expected transaction_from=%s, got %+v", recordedAt, record)
	}
}

func TestWriteClaimDoesNotCreateSyntheticSourceWithoutAttribution(t *testing.T) {
	g := New()
	baseProperties := map[string]any{
		"observed_at":      "2026-03-09T00:00:00Z",
		"valid_from":       "2026-03-09T00:00:00Z",
		"recorded_at":      "2026-03-09T00:00:00Z",
		"transaction_from": "2026-03-09T00:00:00Z",
	}
	g.AddNode(&Node{ID: "service:payments", Kind: NodeKindService, Name: "Payments", Properties: cloneAnyMap(baseProperties)})
	g.AddNode(&Node{ID: "person:alice@example.com", Kind: NodeKindPerson, Name: "Alice", Properties: cloneAnyMap(baseProperties)})

	result, err := WriteClaim(g, ClaimWriteRequest{
		ID:               "claim:payments:owner:alice",
		SubjectID:        "service:payments",
		Predicate:        "owner",
		ObjectID:         "person:alice@example.com",
		SourceSystem:     "api",
		SourceURL:        "https://docs.example.com/claims/payments-owner",
		TrustTier:        "authoritative",
		ReliabilityScore: 0.91,
		ObservedAt:       time.Date(2026, 3, 9, 12, 0, 0, 0, time.UTC),
		ValidFrom:        time.Date(2026, 3, 9, 12, 0, 0, 0, time.UTC),
		RecordedAt:       time.Date(2026, 3, 9, 12, 0, 0, 0, time.UTC),
		TransactionFrom:  time.Date(2026, 3, 9, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("write claim: %v", err)
	}
	if result.SourceID != "" {
		t.Fatalf("expected no synthetic source id, got %+v", result)
	}
	record, ok := GetClaimRecord(g, result.ClaimID, time.Date(2026, 3, 9, 12, 0, 0, 0, time.UTC), time.Date(2026, 3, 9, 12, 0, 0, 0, time.UTC))
	if !ok {
		t.Fatalf("expected claim record for %q", result.ClaimID)
	}
	if record.Derived.SourceBacked || !record.Derived.Sourceless {
		t.Fatalf("expected sourceless derived state without explicit attribution, got %+v", record.Derived)
	}
	if record.Metadata["source_url"] != "https://docs.example.com/claims/payments-owner" {
		t.Fatalf("expected source_url metadata to stay on claim, got %#v", record.Metadata)
	}
	if record.Metadata["source_trust_tier"] != "authoritative" {
		t.Fatalf("expected source_trust_tier metadata to stay on claim, got %#v", record.Metadata)
	}
	if record.Metadata["source_reliability_score"] != 0.91 {
		t.Fatalf("expected source_reliability_score metadata to stay on claim, got %#v", record.Metadata)
	}
}
