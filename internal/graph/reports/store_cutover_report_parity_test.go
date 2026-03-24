package reports

import (
	"context"
	"testing"
	"time"

	graphpkg "github.com/writer/cerebro/internal/graph"
)

func TestCompareGraphStoreReportsWithReportParityProbesHasNoDriftForEquivalentStores(t *testing.T) {
	now := time.Date(2026, 3, 23, 22, 0, 0, 0, time.UTC)
	primary := buildReportParityFixtureGraph(t, now)
	shadow := primary.Clone()

	report, err := graphpkg.CompareGraphStoreReports(context.Background(), primary, shadow, reportParityProbes(now))
	if err != nil {
		t.Fatalf("CompareGraphStoreReports() error = %v", err)
	}
	if report.HasDrift() {
		t.Fatalf("expected no report drift, got %#v", report)
	}
}

func TestCompareGraphStoreReportsWithReportParityProbesDetectsFamilyDrift(t *testing.T) {
	now := time.Date(2026, 3, 23, 22, 0, 0, 0, time.UTC)
	ctx := context.Background()

	cases := []struct {
		name         string
		probe        graphpkg.StoreReportProbe
		expectedID   string
		buildPrimary func(t *testing.T) *Graph
		mutateShadow func(t *testing.T, g *Graph)
	}{
		{
			name:       "claim-conflicts",
			probe:      ClaimConflictReportParityProbe("claim-conflicts", ClaimConflictReportOptions{ValidAt: now, RecordedAt: now, MaxConflicts: 10}),
			expectedID: "claim-conflicts",
			buildPrimary: func(t *testing.T) *Graph {
				t.Helper()
				return buildClaimConflictParityGraph(t, now)
			},
			mutateShadow: func(t *testing.T, g *Graph) {
				t.Helper()
				if err := g.DeleteNode(ctx, "claim:payments-owner:bob"); err != nil {
					t.Fatalf("DeleteNode(bob claim): %v", err)
				}
			},
		},
		{
			name:       "entity-summary",
			probe:      EntitySummaryReportParityProbe("entity-summary", EntitySummaryReportOptions{EntityID: "service:payments", ValidAt: now, RecordedAt: now, MaxPostureClaims: 5}),
			expectedID: "entity-summary",
			buildPrimary: func(t *testing.T) *Graph {
				t.Helper()
				return buildEntitySummaryParityGraph(now)
			},
			mutateShadow: func(t *testing.T, g *Graph) {
				t.Helper()
				g.AddNode(&Node{
					ID:   "service:payments",
					Kind: NodeKindService,
					Name: "Payments Shadow",
					Properties: map[string]any{
						"observed_at":      now.Add(-20 * time.Minute).Format(time.RFC3339),
						"valid_from":       now.Add(-20 * time.Minute).Format(time.RFC3339),
						"recorded_at":      now.Add(-20 * time.Minute).Format(time.RFC3339),
						"transaction_from": now.Add(-20 * time.Minute).Format(time.RFC3339),
						"service_id":       "payments",
						"source_system":    "cutover_test",
					},
				})
			},
		},
		{
			name:       "evaluation-temporal-analysis",
			probe:      EvaluationTemporalAnalysisReportParityProbe("evaluation-temporal-analysis", EvaluationTemporalAnalysisReportOptions{Now: now, EvaluationRunID: "run-eval", ConversationID: "conv-1", TimelineLimit: 10}),
			expectedID: "evaluation-temporal-analysis",
			buildPrimary: func(t *testing.T) *Graph {
				t.Helper()
				g := New()
				addEvaluationTemporalAnalysisFixture(t, g, evaluationTemporalAnalysisFixture{
					RunID:        "run-eval",
					Conversation: "conv-1",
					ServiceID:    "service:payments:eval",
					BaseAt:       now.Add(-3 * time.Hour),
				})
				return g
			},
			mutateShadow: func(t *testing.T, g *Graph) {
				t.Helper()
				if err := g.DeleteNode(ctx, "outcome:evaluation:run-eval:conv-1"); err != nil {
					t.Fatalf("DeleteNode(eval outcome): %v", err)
				}
			},
		},
		{
			name:       "playbook-effectiveness",
			probe:      PlaybookEffectivenessReportParityProbe("playbook-effectiveness", PlaybookEffectivenessReportOptions{Now: now, Window: 7 * 24 * time.Hour, MaxPlaybooks: 10}),
			expectedID: "playbook-effectiveness",
			buildPrimary: func(t *testing.T) *Graph {
				t.Helper()
				g := New()
				addPlaybookEffectivenessFixture(g, playbookRunFixture{
					RunID:        "run-pb-1",
					PlaybookID:   "pb-remediate",
					PlaybookName: "Remediate Public Exposure",
					TenantID:     "tenant-acme",
					TargetID:     "service:payments",
					TargetKind:   NodeKindService,
					StartedAt:    now.Add(-2 * time.Hour),
					Stages: []playbookStageFixture{
						{ID: "identify", Name: "Identify Scope", Order: 1, Status: "completed", ObservedAt: now.Add(-115 * time.Minute)},
						{ID: "approve", Name: "Approve Fix", Order: 2, Status: "completed", ApprovalRequired: true, ApprovalStatus: "approved", PreviousStageID: "identify", ObservedAt: now.Add(-105 * time.Minute)},
					},
					Actions: []playbookActionFixture{
						{ID: "patch", StageID: "approve", ActionType: "automation", Status: "succeeded", Title: "Apply patch", ObservedAt: now.Add(-100 * time.Minute)},
					},
					Outcome: &playbookOutcomeFixture{
						Verdict:       "positive",
						Status:        "completed",
						RollbackState: "stable",
						ObservedAt:    now.Add(-90 * time.Minute),
					},
				})
				return g
			},
			mutateShadow: func(t *testing.T, g *Graph) {
				t.Helper()
				if err := g.DeleteNode(ctx, "outcome:playbook:run-pb-1"); err != nil {
					t.Fatalf("DeleteNode(playbook outcome): %v", err)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			primary := tc.buildPrimary(t)
			shadow := primary.Clone()
			tc.mutateShadow(t, shadow)

			report, err := graphpkg.CompareGraphStoreReports(ctx, primary, shadow, []graphpkg.StoreReportProbe{tc.probe})
			if err != nil {
				t.Fatalf("CompareGraphStoreReports() error = %v", err)
			}
			if !report.HasDrift() {
				t.Fatalf("expected drift, got %#v", report)
			}

			mismatch := findReportMismatch(report.Mismatches, graphpkg.StoreParityMismatchReportDrift, tc.expectedID)
			if mismatch == nil {
				t.Fatalf("expected report drift mismatch for %q, got %#v", tc.expectedID, report.Mismatches)
			}
		})
	}
}

func buildReportParityFixtureGraph(t *testing.T, now time.Time) *Graph {
	t.Helper()

	g := buildClaimConflictParityGraph(t, now)
	addEvaluationTemporalAnalysisFixture(t, g, evaluationTemporalAnalysisFixture{
		RunID:        "run-eval",
		Conversation: "conv-1",
		ServiceID:    "service:payments:eval",
		BaseAt:       now.Add(-3 * time.Hour),
	})
	addPlaybookEffectivenessFixture(g, playbookRunFixture{
		RunID:        "run-pb-1",
		PlaybookID:   "pb-remediate",
		PlaybookName: "Remediate Public Exposure",
		TenantID:     "tenant-acme",
		TargetID:     "service:payments",
		TargetKind:   NodeKindService,
		StartedAt:    now.Add(-2 * time.Hour),
		Stages: []playbookStageFixture{
			{ID: "identify", Name: "Identify Scope", Order: 1, Status: "completed", ObservedAt: now.Add(-115 * time.Minute)},
			{ID: "approve", Name: "Approve Fix", Order: 2, Status: "completed", ApprovalRequired: true, ApprovalStatus: "approved", PreviousStageID: "identify", ObservedAt: now.Add(-105 * time.Minute)},
		},
		Actions: []playbookActionFixture{
			{ID: "patch", StageID: "approve", ActionType: "automation", Status: "succeeded", Title: "Apply patch", ObservedAt: now.Add(-100 * time.Minute)},
		},
		Outcome: &playbookOutcomeFixture{
			Verdict:       "positive",
			Status:        "completed",
			RollbackState: "stable",
			ObservedAt:    now.Add(-90 * time.Minute),
		},
	})

	return g
}

func buildClaimConflictParityGraph(t *testing.T, now time.Time) *Graph {
	t.Helper()

	g := New()
	g.AddNode(&Node{
		ID:   "service:payments",
		Kind: NodeKindService,
		Name: "Payments",
		Properties: map[string]any{
			"service_id":       "payments",
			"observed_at":      now.Add(-6 * time.Hour).Format(time.RFC3339),
			"valid_from":       now.Add(-6 * time.Hour).Format(time.RFC3339),
			"recorded_at":      now.Add(-6 * time.Hour).Format(time.RFC3339),
			"transaction_from": now.Add(-6 * time.Hour).Format(time.RFC3339),
			"source_system":    "cutover_test",
		},
	})

	recordedAt := now.Add(-5 * time.Hour)
	if _, err := graphpkg.WriteClaim(g, graphpkg.ClaimWriteRequest{
		ID:               "claim:payments-owner:alice",
		SubjectID:        "service:payments",
		Predicate:        "owner",
		ObjectValue:      "alice@example.com",
		SourceID:         "source:cmdb:payments",
		SourceName:       "CMDB",
		SourceType:       "system",
		TrustTier:        "authoritative",
		ReliabilityScore: 0.98,
		SourceSystem:     "cutover_test",
		ObservedAt:       recordedAt,
		ValidFrom:        recordedAt,
		RecordedAt:       recordedAt,
		TransactionFrom:  recordedAt,
	}); err != nil {
		t.Fatalf("WriteClaim(alice): %v", err)
	}
	if _, err := graphpkg.WriteClaim(g, graphpkg.ClaimWriteRequest{
		ID:               "claim:payments-owner:bob",
		SubjectID:        "service:payments",
		Predicate:        "owner",
		ObjectValue:      "bob@example.com",
		SourceID:         "source:sheet:payments",
		SourceName:       "Inventory Export",
		SourceType:       "system",
		TrustTier:        "monitoring",
		ReliabilityScore: 0.61,
		SourceSystem:     "cutover_test",
		ObservedAt:       recordedAt.Add(5 * time.Minute),
		ValidFrom:        recordedAt.Add(5 * time.Minute),
		RecordedAt:       recordedAt.Add(5 * time.Minute),
		TransactionFrom:  recordedAt.Add(5 * time.Minute),
	}); err != nil {
		t.Fatalf("WriteClaim(bob): %v", err)
	}
	return g
}

func buildEntitySummaryParityGraph(now time.Time) *Graph {
	g := New()
	g.AddNode(&Node{
		ID:   "service:payments",
		Kind: NodeKindService,
		Name: "Payments",
		Properties: map[string]any{
			"service_id":       "payments",
			"observed_at":      now.Add(-2 * time.Hour).Format(time.RFC3339),
			"valid_from":       now.Add(-2 * time.Hour).Format(time.RFC3339),
			"recorded_at":      now.Add(-2 * time.Hour).Format(time.RFC3339),
			"transaction_from": now.Add(-2 * time.Hour).Format(time.RFC3339),
			"source_system":    "cutover_test",
		},
	})
	return g
}

func reportParityProbes(now time.Time) []graphpkg.StoreReportProbe {
	return []graphpkg.StoreReportProbe{
		ClaimConflictReportParityProbe("claim-conflicts", ClaimConflictReportOptions{ValidAt: now, RecordedAt: now, MaxConflicts: 10}),
		EntitySummaryReportParityProbe("entity-summary", EntitySummaryReportOptions{EntityID: "service:payments", ValidAt: now, RecordedAt: now, MaxPostureClaims: 5}),
		EvaluationTemporalAnalysisReportParityProbe("evaluation-temporal-analysis", EvaluationTemporalAnalysisReportOptions{Now: now, EvaluationRunID: "run-eval", ConversationID: "conv-1", TimelineLimit: 10}),
		PlaybookEffectivenessReportParityProbe("playbook-effectiveness", PlaybookEffectivenessReportOptions{Now: now, Window: 7 * 24 * time.Hour, MaxPlaybooks: 10}),
	}
}

func findReportMismatch(mismatches []graphpkg.StoreParityMismatch, class graphpkg.StoreParityMismatchClass, identifier string) *graphpkg.StoreParityMismatch {
	for i := range mismatches {
		if mismatches[i].Class == class && mismatches[i].Identifier == identifier {
			return &mismatches[i]
		}
	}
	return nil
}
