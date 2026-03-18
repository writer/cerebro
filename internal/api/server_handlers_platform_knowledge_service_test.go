package api

import (
	"context"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/app"
	"github.com/evalops/cerebro/internal/graph/knowledge"
)

type stubPlatformKnowledgeService struct {
	queryClaimsFunc      func(context.Context, knowledge.ClaimQueryOptions) (knowledge.ClaimCollection, error)
	diffKnowledgeFunc    func(context.Context, knowledge.KnowledgeDiffQueryOptions) (knowledge.KnowledgeDiffCollection, error)
	adjudicateClaimsFunc func(context.Context, knowledge.ClaimAdjudicationWriteRequest) (knowledge.ClaimAdjudicationWriteResult, error)
}

func (s stubPlatformKnowledgeService) QueryClaims(ctx context.Context, opts knowledge.ClaimQueryOptions) (knowledge.ClaimCollection, error) {
	if s.queryClaimsFunc != nil {
		return s.queryClaimsFunc(ctx, opts)
	}
	return knowledge.ClaimCollection{}, nil
}

func (s stubPlatformKnowledgeService) QueryEvidence(context.Context, knowledge.KnowledgeArtifactQueryOptions) (knowledge.KnowledgeArtifactCollection, error) {
	return knowledge.KnowledgeArtifactCollection{}, nil
}

func (s stubPlatformKnowledgeService) QueryObservations(context.Context, knowledge.KnowledgeArtifactQueryOptions) (knowledge.KnowledgeArtifactCollection, error) {
	return knowledge.KnowledgeArtifactCollection{}, nil
}

func (s stubPlatformKnowledgeService) GetClaim(context.Context, string, time.Time, time.Time) (knowledge.ClaimRecord, bool, error) {
	return knowledge.ClaimRecord{}, false, nil
}

func (s stubPlatformKnowledgeService) GetEvidence(context.Context, string, time.Time, time.Time) (knowledge.KnowledgeArtifactRecord, bool, error) {
	return knowledge.KnowledgeArtifactRecord{}, false, nil
}

func (s stubPlatformKnowledgeService) GetObservation(context.Context, string, time.Time, time.Time) (knowledge.KnowledgeArtifactRecord, bool, error) {
	return knowledge.KnowledgeArtifactRecord{}, false, nil
}

func (s stubPlatformKnowledgeService) QueryClaimGroups(context.Context, knowledge.ClaimGroupQueryOptions) (knowledge.ClaimGroupCollection, error) {
	return knowledge.ClaimGroupCollection{}, nil
}

func (s stubPlatformKnowledgeService) GetClaimGroup(context.Context, string, time.Time, time.Time, bool) (knowledge.ClaimGroupRecord, bool, error) {
	return knowledge.ClaimGroupRecord{}, false, nil
}

func (s stubPlatformKnowledgeService) GetClaimTimeline(context.Context, string, knowledge.ClaimTimelineOptions) (knowledge.ClaimTimeline, bool, error) {
	return knowledge.ClaimTimeline{}, false, nil
}

func (s stubPlatformKnowledgeService) ExplainClaim(context.Context, string, time.Time, time.Time) (knowledge.ClaimExplanation, bool, error) {
	return knowledge.ClaimExplanation{}, false, nil
}

func (s stubPlatformKnowledgeService) BuildClaimProofs(context.Context, string, knowledge.ClaimProofOptions) (knowledge.ClaimProofCollection, bool, error) {
	return knowledge.ClaimProofCollection{}, false, nil
}

func (s stubPlatformKnowledgeService) DiffClaims(context.Context, knowledge.ClaimDiffQueryOptions) (knowledge.ClaimDiffCollection, error) {
	return knowledge.ClaimDiffCollection{}, nil
}

func (s stubPlatformKnowledgeService) DiffKnowledge(ctx context.Context, opts knowledge.KnowledgeDiffQueryOptions) (knowledge.KnowledgeDiffCollection, error) {
	if s.diffKnowledgeFunc != nil {
		return s.diffKnowledgeFunc(ctx, opts)
	}
	return knowledge.KnowledgeDiffCollection{}, nil
}

func (s stubPlatformKnowledgeService) AdjudicateClaimGroup(ctx context.Context, req knowledge.ClaimAdjudicationWriteRequest) (knowledge.ClaimAdjudicationWriteResult, error) {
	if s.adjudicateClaimsFunc != nil {
		return s.adjudicateClaimsFunc(ctx, req)
	}
	return knowledge.ClaimAdjudicationWriteResult{}, nil
}

func TestPlatformKnowledgeHandlersUseServiceInterface(t *testing.T) {
	var called bool
	s := NewServerWithDependencies(serverDependencies{
		Config: &app.Config{},
		Logger: slog.Default(),
		platformKnowledge: stubPlatformKnowledgeService{
			queryClaimsFunc: func(_ context.Context, opts knowledge.ClaimQueryOptions) (knowledge.ClaimCollection, error) {
				called = true
				if opts.SubjectID != "service:payments" {
					t.Fatalf("expected subject filter to reach service, got %#v", opts)
				}
				return knowledge.ClaimCollection{
					Count: 1,
					Claims: []knowledge.ClaimRecord{{
						ID:        "claim:payments:owner:alice",
						SubjectID: "service:payments",
						Predicate: "owner",
					}},
				}, nil
			},
		},
	})
	t.Cleanup(func() { s.Close() })

	w := do(t, s, http.MethodGet, "/api/v1/platform/knowledge/claims?subject_id=service:payments", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed claims list, got %d: %s", w.Code, w.Body.String())
	}
	if !called {
		t.Fatal("expected claims handler to use platform knowledge service")
	}

	body := decodeJSON(t, w)
	if body["count"] != float64(1) {
		t.Fatalf("expected count=1, got %#v", body["count"])
	}
	claims, ok := body["claims"].([]any)
	if !ok || len(claims) != 1 {
		t.Fatalf("expected one stubbed claim, got %#v", body["claims"])
	}
}

func TestPlatformKnowledgeDiffsUseServiceInterface(t *testing.T) {
	var called bool
	from := time.Date(2026, 3, 17, 8, 0, 0, 0, time.UTC)
	to := from.Add(2 * time.Hour)

	s := NewServerWithDependencies(serverDependencies{
		Config: &app.Config{},
		Logger: slog.Default(),
		platformKnowledge: stubPlatformKnowledgeService{
			diffKnowledgeFunc: func(_ context.Context, opts knowledge.KnowledgeDiffQueryOptions) (knowledge.KnowledgeDiffCollection, error) {
				called = true
				if opts.FromValidAt != from || opts.ToRecordedAt != to {
					t.Fatalf("expected parsed diff window to reach service, got %#v", opts)
				}
				return knowledge.KnowledgeDiffCollection{
					Summary: knowledge.KnowledgeDiffSummary{
						AddedClaims: 1,
					},
				}, nil
			},
		},
	})
	t.Cleanup(func() { s.Close() })

	path := "/api/v1/platform/knowledge/diffs?kinds=claim" +
		"&from_valid_at=" + from.Format(time.RFC3339) +
		"&from_recorded_at=" + from.Format(time.RFC3339) +
		"&to_valid_at=" + to.Format(time.RFC3339) +
		"&to_recorded_at=" + to.Format(time.RFC3339)
	w := do(t, s, http.MethodGet, path, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed knowledge diff, got %d: %s", w.Code, w.Body.String())
	}
	if !called {
		t.Fatal("expected knowledge diff handler to use platform knowledge service")
	}

	body := decodeJSON(t, w)
	summary := body["summary"].(map[string]any)
	if summary["added_claims"] != float64(1) {
		t.Fatalf("expected stub diff summary, got %#v", summary)
	}
}

func TestPlatformKnowledgeAdjudicationUsesServiceInterface(t *testing.T) {
	var captured knowledge.ClaimAdjudicationWriteRequest
	base := time.Date(2026, 3, 17, 12, 0, 0, 0, time.UTC)

	s := NewServerWithDependencies(serverDependencies{
		Config: &app.Config{},
		Logger: slog.Default(),
		platformKnowledge: stubPlatformKnowledgeService{
			adjudicateClaimsFunc: func(_ context.Context, req knowledge.ClaimAdjudicationWriteRequest) (knowledge.ClaimAdjudicationWriteResult, error) {
				captured = req
				return knowledge.ClaimAdjudicationWriteResult{
					GroupID:              req.GroupID,
					Action:               req.Action,
					CreatedClaimID:       "claim:payments:owner:alice:authoritative",
					AuthoritativeClaimID: req.AuthoritativeClaimID,
					AffectedClaimIDs:     []string{"claim:payments:owner:alice", "claim:payments:owner:bob"},
					SupersededClaimIDs:   []string{"claim:payments:owner:bob"},
					ObservedAt:           base,
					RecordedAt:           base,
				}, nil
			},
		},
	})
	t.Cleanup(func() { s.Close() })

	w := do(t, s, http.MethodPost, "/api/v1/platform/knowledge/claim-groups/group:payments-owner/adjudications", map[string]any{
		"action":                 "accept_existing",
		"authoritative_claim_id": "claim:payments:owner:alice",
		"actor":                  "reviewer:alice",
		"rationale":              "authoritative source",
		"source_system":          "api",
		"source_event_id":        "adj-001",
		"observed_at":            base.Format(time.RFC3339),
		"valid_from":             base.Format(time.RFC3339),
		"recorded_at":            base.Format(time.RFC3339),
		"transaction_from":       base.Format(time.RFC3339),
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 for service-backed adjudication, got %d: %s", w.Code, w.Body.String())
	}
	if captured.GroupID != "group:payments-owner" {
		t.Fatalf("expected handler to bind URL group id into request, got %#v", captured)
	}

	body := decodeJSON(t, w)
	if body["group_id"] != "group:payments-owner" {
		t.Fatalf("expected stub adjudication response, got %#v", body)
	}
}
