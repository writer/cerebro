package graph

import (
	"testing"
	"time"
)

func TestWriteClaimCreatesClaimSourceAndEvidenceLinks(t *testing.T) {
	g := New()
	g.AddNode(&Node{
		ID:   "service:payments",
		Kind: NodeKindService,
		Name: "Payments",
		Properties: map[string]any{
			"service_id":       "payments",
			"observed_at":      "2026-03-09T00:00:00Z",
			"valid_from":       "2026-03-09T00:00:00Z",
			"recorded_at":      "2026-03-09T08:00:00Z",
			"transaction_from": "2026-03-09T08:00:00Z",
		},
	})
	g.AddNode(&Node{
		ID:   "person:alice@example.com",
		Kind: NodeKindPerson,
		Name: "Alice",
		Properties: map[string]any{
			"observed_at":      "2026-03-09T00:00:00Z",
			"valid_from":       "2026-03-09T00:00:00Z",
			"recorded_at":      "2026-03-09T08:00:00Z",
			"transaction_from": "2026-03-09T08:00:00Z",
		},
	})
	g.AddNode(&Node{
		ID:   "evidence:ticket:123",
		Kind: NodeKindEvidence,
		Name: "Ticket 123",
		Properties: map[string]any{
			"evidence_type":    "ticket",
			"source_system":    "jira",
			"observed_at":      "2026-03-09T00:00:00Z",
			"valid_from":       "2026-03-09T00:00:00Z",
			"recorded_at":      "2026-03-09T08:00:00Z",
			"transaction_from": "2026-03-09T08:00:00Z",
		},
	})

	recordedAt := time.Date(2026, 3, 9, 12, 0, 0, 0, time.UTC)
	result, err := WriteClaim(g, ClaimWriteRequest{
		SubjectID:        "service:payments",
		Predicate:        "owner",
		ObjectID:         "person:alice@example.com",
		Summary:          "Payments is owned by Alice",
		EvidenceIDs:      []string{"evidence:ticket:123"},
		SourceName:       "CMDB",
		SourceType:       "system",
		TrustTier:        "authoritative",
		ReliabilityScore: 0.98,
		SourceSystem:     "api",
		RecordedAt:       recordedAt,
	})
	if err != nil {
		t.Fatalf("write claim: %v", err)
	}
	if result.ClaimID == "" {
		t.Fatal("expected claim id")
	}
	claimNode, ok := g.GetNode(result.ClaimID)
	if !ok || claimNode == nil {
		t.Fatalf("expected claim node %q to exist", result.ClaimID)
	}
	if claimNode.Kind != NodeKindClaim {
		t.Fatalf("expected claim kind, got %q", claimNode.Kind)
	}
	if got := readString(claimNode.Properties, "recorded_at"); got == "" {
		t.Fatalf("expected recorded_at on claim, got %#v", claimNode.Properties)
	}
	if got := readString(claimNode.Properties, "transaction_from"); got == "" {
		t.Fatalf("expected transaction_from on claim, got %#v", claimNode.Properties)
	}
	if result.SourceID == "" {
		t.Fatal("expected source id")
	}
	if sourceNode, ok := g.GetNode(result.SourceID); !ok || sourceNode == nil || sourceNode.Kind != NodeKindSource {
		t.Fatalf("expected source node %q, got %#v", result.SourceID, sourceNode)
	}

	assertedBy := false
	basedOn := false
	refers := false
	for _, edge := range g.GetOutEdges(result.ClaimID) {
		switch edge.Kind {
		case EdgeKindAssertedBy:
			assertedBy = true
		case EdgeKindBasedOn:
			basedOn = true
		case EdgeKindRefers:
			refers = true
		}
	}
	if !assertedBy || !basedOn || !refers {
		t.Fatalf("expected asserted_by, based_on, and refers edges from claim")
	}
}

func TestBuildClaimConflictReportFindsContradictions(t *testing.T) {
	g := New()
	g.AddNode(&Node{
		ID:   "service:payments",
		Kind: NodeKindService,
		Name: "Payments",
		Properties: map[string]any{
			"service_id":       "payments",
			"source_system":    "cmdb",
			"observed_at":      "2026-03-09T00:00:00Z",
			"valid_from":       "2026-03-09T00:00:00Z",
			"recorded_at":      "2026-03-09T08:00:00Z",
			"transaction_from": "2026-03-09T08:00:00Z",
		},
	})
	g.AddNode(&Node{
		ID:   "evidence:doc:1",
		Kind: NodeKindEvidence,
		Name: "Runbook",
		Properties: map[string]any{
			"evidence_type":    "document",
			"source_system":    "docs",
			"observed_at":      "2026-03-09T00:00:00Z",
			"valid_from":       "2026-03-09T00:00:00Z",
			"recorded_at":      "2026-03-09T08:00:00Z",
			"transaction_from": "2026-03-09T08:00:00Z",
		},
	})
	g.AddNode(&Node{
		ID:   "evidence:doc:2",
		Kind: NodeKindEvidence,
		Name: "Spreadsheet",
		Properties: map[string]any{
			"evidence_type":    "document",
			"source_system":    "sheets",
			"observed_at":      "2026-03-09T00:00:00Z",
			"valid_from":       "2026-03-09T00:00:00Z",
			"recorded_at":      "2026-03-09T08:00:00Z",
			"transaction_from": "2026-03-09T08:00:00Z",
		},
	})

	_, err := WriteClaim(g, ClaimWriteRequest{
		ID:              "claim:service:payments:tier:a",
		SubjectID:       "service:payments",
		Predicate:       "service_tier",
		ObjectValue:     "tier1",
		EvidenceIDs:     []string{"evidence:doc:1"},
		SourceID:        "source:cmdb:primary",
		SourceName:      "Primary CMDB",
		SourceType:      "system",
		TrustTier:       "authoritative",
		SourceSystem:    "api",
		ObservedAt:      time.Date(2026, 3, 9, 9, 0, 0, 0, time.UTC),
		RecordedAt:      time.Date(2026, 3, 9, 9, 5, 0, 0, time.UTC),
		TransactionFrom: time.Date(2026, 3, 9, 9, 5, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("write first claim: %v", err)
	}
	_, err = WriteClaim(g, ClaimWriteRequest{
		ID:              "claim:service:payments:tier:b",
		SubjectID:       "service:payments",
		Predicate:       "service_tier",
		ObjectValue:     "tier0",
		EvidenceIDs:     []string{"evidence:doc:2"},
		SourceID:        "source:sheets:ops",
		SourceName:      "Ops Sheet",
		SourceType:      "document",
		TrustTier:       "verified",
		SourceSystem:    "api",
		ObservedAt:      time.Date(2026, 3, 9, 10, 0, 0, 0, time.UTC),
		RecordedAt:      time.Date(2026, 3, 9, 10, 1, 0, 0, time.UTC),
		TransactionFrom: time.Date(2026, 3, 9, 10, 1, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("write second claim: %v", err)
	}

	report := BuildClaimConflictReport(g, ClaimConflictReportOptions{
		ValidAt:      time.Date(2026, 3, 9, 11, 0, 0, 0, time.UTC),
		RecordedAt:   time.Date(2026, 3, 9, 11, 0, 0, 0, time.UTC),
		MaxConflicts: 10,
	})
	if report.Summary.TotalClaims != 2 {
		t.Fatalf("expected total claims=2, got %+v", report.Summary)
	}
	if report.Summary.ConflictGroups != 1 {
		t.Fatalf("expected one conflict group, got %+v", report.Summary)
	}
	if report.Summary.TotalConflictGroups != 1 {
		t.Fatalf("expected total conflict groups=1, got %+v", report.Summary)
	}
	if report.Summary.ReturnedConflictGroups != 1 {
		t.Fatalf("expected returned conflict groups=1, got %+v", report.Summary)
	}
	if report.Summary.ConflictingClaims != 2 {
		t.Fatalf("expected two conflicting claims, got %+v", report.Summary)
	}
	if report.Summary.TotalConflictingClaims != 2 {
		t.Fatalf("expected total conflicting claims=2, got %+v", report.Summary)
	}
	if report.Summary.ReturnedConflictingClaims != 2 {
		t.Fatalf("expected returned conflicting claims=2, got %+v", report.Summary)
	}
	if len(report.Conflicts) != 1 {
		t.Fatalf("expected one conflict, got %#v", report.Conflicts)
	}
	if len(report.Conflicts[0].Values) != 2 {
		t.Fatalf("expected two conflicting values, got %#v", report.Conflicts[0])
	}
	if report.Summary.UnsupportedClaims != 0 {
		t.Fatalf("expected supported claims, got %+v", report.Summary)
	}
	if report.Summary.SourcelessClaims != 0 {
		t.Fatalf("expected source-backed claims, got %+v", report.Summary)
	}
}

func TestGetAllNodesBitemporalUsesTransactionTime(t *testing.T) {
	g := New()
	g.AddNode(&Node{
		ID:   "service:payments",
		Kind: NodeKindService,
		Name: "Payments",
		Properties: map[string]any{
			"service_id":       "payments",
			"observed_at":      "2026-03-01T00:00:00Z",
			"valid_from":       "2026-03-01T00:00:00Z",
			"recorded_at":      "2026-03-05T00:00:00Z",
			"transaction_from": "2026-03-05T00:00:00Z",
			"transaction_to":   "2026-03-07T00:00:00Z",
			"source_system":    "cmdb",
			"source_event_id":  "evt-1",
			"confidence":       0.9,
		},
	})

	validAt := time.Date(2026, 3, 6, 0, 0, 0, 0, time.UTC)
	beforeRecorded := time.Date(2026, 3, 4, 0, 0, 0, 0, time.UTC)
	if got := len(g.GetAllNodesBitemporal(validAt, beforeRecorded)); got != 0 {
		t.Fatalf("expected node to be hidden before transaction_from, got %d", got)
	}

	duringRecorded := time.Date(2026, 3, 6, 0, 0, 0, 0, time.UTC)
	if got := len(g.GetAllNodesBitemporal(validAt, duringRecorded)); got != 1 {
		t.Fatalf("expected node during transaction window, got %d", got)
	}

	afterRecorded := time.Date(2026, 3, 8, 0, 0, 0, 0, time.UTC)
	if got := len(g.GetAllNodesBitemporal(validAt, afterRecorded)); got != 0 {
		t.Fatalf("expected node hidden after transaction_to, got %d", got)
	}
}

func TestWriteClaimRejectsConflictingExistingSourceMetadata(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "service:payments", Kind: NodeKindService, Name: "Payments"})
	g.AddNode(&Node{ID: "person:alice@example.com", Kind: NodeKindPerson, Name: "Alice"})

	_, err := WriteClaim(g, ClaimWriteRequest{
		SubjectID:       "service:payments",
		Predicate:       "owner",
		ObjectID:        "person:alice@example.com",
		SourceID:        "source:cmdb:primary",
		SourceName:      "Primary CMDB",
		SourceType:      "system",
		TrustTier:       "authoritative",
		SourceSystem:    "api",
		ObservedAt:      time.Date(2026, 3, 9, 9, 0, 0, 0, time.UTC),
		RecordedAt:      time.Date(2026, 3, 9, 9, 1, 0, 0, time.UTC),
		TransactionFrom: time.Date(2026, 3, 9, 9, 1, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("write first claim: %v", err)
	}

	_, err = WriteClaim(g, ClaimWriteRequest{
		SubjectID:       "service:payments",
		Predicate:       "owner",
		ObjectID:        "person:alice@example.com",
		SourceID:        "source:cmdb:primary",
		SourceName:      "Secondary CMDB",
		SourceType:      "system",
		TrustTier:       "derived",
		SourceSystem:    "api",
		ObservedAt:      time.Date(2026, 3, 9, 10, 0, 0, 0, time.UTC),
		RecordedAt:      time.Date(2026, 3, 9, 10, 1, 0, 0, time.UTC),
		TransactionFrom: time.Date(2026, 3, 9, 10, 1, 0, 0, time.UTC),
	})
	if err == nil {
		t.Fatal("expected conflicting source metadata to fail")
	}
}

func TestWriteClaimAutoGeneratedIDsIncludeSubject(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "service:payments", Kind: NodeKindService, Name: "Payments"})
	g.AddNode(&Node{ID: "service:billing", Kind: NodeKindService, Name: "Billing"})

	recordedAt := time.Date(2026, 3, 9, 12, 0, 0, 123456789, time.UTC)
	first, err := WriteClaim(g, ClaimWriteRequest{
		SubjectID:       "service:payments",
		Predicate:       "service_tier",
		ObjectValue:     "tier1",
		SourceSystem:    "api",
		RecordedAt:      recordedAt,
		TransactionFrom: recordedAt,
	})
	if err != nil {
		t.Fatalf("write first claim: %v", err)
	}
	second, err := WriteClaim(g, ClaimWriteRequest{
		SubjectID:       "service:billing",
		Predicate:       "service_tier",
		ObjectValue:     "tier1",
		SourceSystem:    "api",
		RecordedAt:      recordedAt,
		TransactionFrom: recordedAt,
	})
	if err != nil {
		t.Fatalf("write second claim: %v", err)
	}
	if first.ClaimID == second.ClaimID {
		t.Fatalf("expected distinct auto-generated claim ids, got %q", first.ClaimID)
	}
}

func TestBuildClaimConflictReportExposesTotalAndReturnedCountsWhenTruncated(t *testing.T) {
	g := New()
	for _, id := range []string{"service:payments", "service:billing"} {
		g.AddNode(&Node{ID: id, Kind: NodeKindService, Name: id})
	}

	recordedAt := time.Date(2026, 3, 9, 12, 0, 0, 0, time.UTC)
	cases := []ClaimWriteRequest{
		{
			ID:              "claim:payments:tier:tier1",
			SubjectID:       "service:payments",
			Predicate:       "service_tier",
			ObjectValue:     "tier1",
			SourceID:        "source:cmdb:payments",
			SourceName:      "Payments CMDB",
			SourceType:      "system",
			TrustTier:       "authoritative",
			SourceSystem:    "api",
			ObservedAt:      recordedAt,
			ValidFrom:       recordedAt,
			RecordedAt:      recordedAt,
			TransactionFrom: recordedAt,
		},
		{
			ID:              "claim:payments:tier:tier0",
			SubjectID:       "service:payments",
			Predicate:       "service_tier",
			ObjectValue:     "tier0",
			SourceID:        "source:sheet:payments",
			SourceName:      "Payments Sheet",
			SourceType:      "document",
			TrustTier:       "verified",
			SourceSystem:    "api",
			ObservedAt:      recordedAt.Add(1 * time.Minute),
			ValidFrom:       recordedAt.Add(1 * time.Minute),
			RecordedAt:      recordedAt.Add(1 * time.Minute),
			TransactionFrom: recordedAt.Add(1 * time.Minute),
		},
		{
			ID:              "claim:billing:tier:tier2",
			SubjectID:       "service:billing",
			Predicate:       "service_tier",
			ObjectValue:     "tier2",
			SourceID:        "source:cmdb:billing",
			SourceName:      "Billing CMDB",
			SourceType:      "system",
			TrustTier:       "authoritative",
			SourceSystem:    "api",
			ObservedAt:      recordedAt.Add(2 * time.Minute),
			ValidFrom:       recordedAt.Add(2 * time.Minute),
			RecordedAt:      recordedAt.Add(2 * time.Minute),
			TransactionFrom: recordedAt.Add(2 * time.Minute),
		},
		{
			ID:              "claim:billing:tier:tier3",
			SubjectID:       "service:billing",
			Predicate:       "service_tier",
			ObjectValue:     "tier3",
			SourceID:        "source:sheet:billing",
			SourceName:      "Billing Sheet",
			SourceType:      "document",
			TrustTier:       "verified",
			SourceSystem:    "api",
			ObservedAt:      recordedAt.Add(3 * time.Minute),
			ValidFrom:       recordedAt.Add(3 * time.Minute),
			RecordedAt:      recordedAt.Add(3 * time.Minute),
			TransactionFrom: recordedAt.Add(3 * time.Minute),
		},
	}
	for _, req := range cases {
		if _, err := WriteClaim(g, req); err != nil {
			t.Fatalf("write claim %s: %v", req.ID, err)
		}
	}

	report := BuildClaimConflictReport(g, ClaimConflictReportOptions{
		ValidAt:      recordedAt.Add(4 * time.Minute),
		RecordedAt:   recordedAt.Add(4 * time.Minute),
		MaxConflicts: 1,
	})
	if len(report.Conflicts) != 1 {
		t.Fatalf("expected one returned conflict, got %#v", report.Conflicts)
	}
	if !report.Summary.ConflictsTruncated {
		t.Fatalf("expected conflicts_truncated=true, got %+v", report.Summary)
	}
	if report.Summary.ConflictGroups != 2 || report.Summary.TotalConflictGroups != 2 {
		t.Fatalf("expected total conflict groups=2, got %+v", report.Summary)
	}
	if report.Summary.ReturnedConflictGroups != 1 {
		t.Fatalf("expected returned conflict groups=1, got %+v", report.Summary)
	}
	if report.Summary.ConflictingClaims != 4 || report.Summary.TotalConflictingClaims != 4 {
		t.Fatalf("expected total conflicting claims=4, got %+v", report.Summary)
	}
	if report.Summary.ReturnedConflictingClaims != 2 {
		t.Fatalf("expected returned conflicting claims=2, got %+v", report.Summary)
	}
}

func TestBuildClaimConflictReportTreatsCorrectedClaimsAsResolved(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "service:payments", Kind: NodeKindService, Name: "Payments"})

	g.AddNode(&Node{
		ID:   "claim:corrected",
		Kind: NodeKindClaim,
		Name: "Corrected claim",
		Properties: map[string]any{
			"subject_id":       "service:payments",
			"predicate":        "service_tier",
			"object_value":     "tier1",
			"status":           "corrected",
			"observed_at":      "2026-03-09T00:00:00Z",
			"valid_from":       "2026-03-09T00:00:00Z",
			"recorded_at":      "2026-03-09T00:00:00Z",
			"transaction_from": "2026-03-09T00:00:00Z",
		},
	})
	g.AddNode(&Node{
		ID:   "claim:active",
		Kind: NodeKindClaim,
		Name: "Active claim",
		Properties: map[string]any{
			"subject_id":       "service:payments",
			"predicate":        "service_tier",
			"object_value":     "tier2",
			"status":           "asserted",
			"observed_at":      "2026-03-09T00:00:00Z",
			"valid_from":       "2026-03-09T00:00:00Z",
			"recorded_at":      "2026-03-09T00:00:00Z",
			"transaction_from": "2026-03-09T00:00:00Z",
		},
	})

	report := BuildClaimConflictReport(g, ClaimConflictReportOptions{
		ValidAt:    time.Date(2026, 3, 9, 1, 0, 0, 0, time.UTC),
		RecordedAt: time.Date(2026, 3, 9, 1, 0, 0, 0, time.UTC),
	})
	if report.Summary.ActiveClaims != 1 {
		t.Fatalf("expected only one active claim, got %+v", report.Summary)
	}
	if report.Summary.ConflictGroups != 0 {
		t.Fatalf("expected corrected claim to be excluded from conflicts, got %+v", report.Summary)
	}
}
