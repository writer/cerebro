package api

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/app"
	"github.com/evalops/cerebro/internal/graph"
	"github.com/evalops/cerebro/internal/graph/knowledge"
)

type stubGraphWritebackService struct {
	writeObservationFunc      func(context.Context, graphWriteObservationRequest) (*graphWriteObservationResponse, error)
	writeClaimFunc            func(context.Context, graphWriteClaimRequest) (*knowledge.ClaimWriteResult, error)
	annotateEntityFunc        func(context.Context, graphAnnotateEntityRequest) (*graphAnnotationWriteResponse, error)
	writeDecisionFunc         func(context.Context, graphWriteDecisionRequest) (*graphDecisionWriteResponse, error)
	writeOutcomeFunc          func(context.Context, graphWriteOutcomeRequest) (*graphOutcomeWriteResponse, error)
	resolveIdentityFunc       func(context.Context, graphResolveIdentityRequest) (*graph.IdentityResolutionResult, error)
	splitIdentityFunc         func(context.Context, graphSplitIdentityRequest) (*graphIdentitySplitResponse, error)
	reviewIdentityFunc        func(context.Context, graphIdentityReviewRequest) (*graph.IdentityReviewRecord, error)
	identityCalibrationFunc   func(context.Context, graph.IdentityCalibrationOptions) (*graph.IdentityCalibrationReport, error)
	actuateRecommendationFunc func(context.Context, graphActuateRecommendationRequest) (*graph.RecommendationActuationResult, error)
}

func (s stubGraphWritebackService) WriteObservation(ctx context.Context, req graphWriteObservationRequest) (*graphWriteObservationResponse, error) {
	if s.writeObservationFunc != nil {
		return s.writeObservationFunc(ctx, req)
	}
	return &graphWriteObservationResponse{}, nil
}

func (s stubGraphWritebackService) WriteClaim(ctx context.Context, req graphWriteClaimRequest) (*knowledge.ClaimWriteResult, error) {
	if s.writeClaimFunc != nil {
		return s.writeClaimFunc(ctx, req)
	}
	return &knowledge.ClaimWriteResult{}, nil
}

func (s stubGraphWritebackService) AnnotateEntity(ctx context.Context, req graphAnnotateEntityRequest) (*graphAnnotationWriteResponse, error) {
	if s.annotateEntityFunc != nil {
		return s.annotateEntityFunc(ctx, req)
	}
	return &graphAnnotationWriteResponse{}, nil
}

func (s stubGraphWritebackService) WriteDecision(ctx context.Context, req graphWriteDecisionRequest) (*graphDecisionWriteResponse, error) {
	if s.writeDecisionFunc != nil {
		return s.writeDecisionFunc(ctx, req)
	}
	return &graphDecisionWriteResponse{}, nil
}

func (s stubGraphWritebackService) WriteOutcome(ctx context.Context, req graphWriteOutcomeRequest) (*graphOutcomeWriteResponse, error) {
	if s.writeOutcomeFunc != nil {
		return s.writeOutcomeFunc(ctx, req)
	}
	return &graphOutcomeWriteResponse{}, nil
}

func (s stubGraphWritebackService) ResolveIdentity(ctx context.Context, req graphResolveIdentityRequest) (*graph.IdentityResolutionResult, error) {
	if s.resolveIdentityFunc != nil {
		return s.resolveIdentityFunc(ctx, req)
	}
	return &graph.IdentityResolutionResult{}, nil
}

func (s stubGraphWritebackService) SplitIdentity(ctx context.Context, req graphSplitIdentityRequest) (*graphIdentitySplitResponse, error) {
	if s.splitIdentityFunc != nil {
		return s.splitIdentityFunc(ctx, req)
	}
	return &graphIdentitySplitResponse{}, nil
}

func (s stubGraphWritebackService) ReviewIdentity(ctx context.Context, req graphIdentityReviewRequest) (*graph.IdentityReviewRecord, error) {
	if s.reviewIdentityFunc != nil {
		return s.reviewIdentityFunc(ctx, req)
	}
	return &graph.IdentityReviewRecord{}, nil
}

func (s stubGraphWritebackService) IdentityCalibration(ctx context.Context, opts graph.IdentityCalibrationOptions) (*graph.IdentityCalibrationReport, error) {
	if s.identityCalibrationFunc != nil {
		return s.identityCalibrationFunc(ctx, opts)
	}
	return &graph.IdentityCalibrationReport{}, nil
}

func (s stubGraphWritebackService) ActuateRecommendation(ctx context.Context, req graphActuateRecommendationRequest) (*graph.RecommendationActuationResult, error) {
	if s.actuateRecommendationFunc != nil {
		return s.actuateRecommendationFunc(ctx, req)
	}
	return &graph.RecommendationActuationResult{}, nil
}

func newGraphWritebackServiceTestServer(t *testing.T, service graphWritebackService) *Server {
	t.Helper()
	s := NewServerWithDependencies(serverDependencies{
		Config:         &app.Config{},
		graphWriteback: service,
	})
	s.app.SecurityGraph = nil
	s.app.graphMutator = nil
	s.app.Webhooks = nil
	t.Cleanup(func() {
		s.Close()
	})
	return s
}

func TestGraphWritebackKnowledgeHandlersUseServiceInterface(t *testing.T) {
	now := time.Date(2026, 3, 18, 4, 0, 0, 0, time.UTC)
	s := newGraphWritebackServiceTestServer(t, stubGraphWritebackService{
		writeObservationFunc: func(_ context.Context, req graphWriteObservationRequest) (*graphWriteObservationResponse, error) {
			if req.SubjectID != "service:payments" || req.ObservationType != "deploy_risk_increase" {
				t.Fatalf("unexpected observation normalization: %#v", req)
			}
			return &graphWriteObservationResponse{
				ObservationID: "obs-1",
				SubjectID:     req.SubjectID,
				EntityID:      req.SubjectID,
				ObservedAt:    now,
				RecordedAt:    now,
			}, nil
		},
		writeClaimFunc: func(_ context.Context, req graphWriteClaimRequest) (*knowledge.ClaimWriteResult, error) {
			if req.SubjectID != "service:payments" || req.Predicate != "owner" {
				t.Fatalf("unexpected claim request: %#v", req)
			}
			return &knowledge.ClaimWriteResult{ClaimID: "claim-1", SourceID: "source-1"}, nil
		},
		annotateEntityFunc: func(_ context.Context, req graphAnnotateEntityRequest) (*graphAnnotationWriteResponse, error) {
			if req.EntityID != "service:payments" || req.Annotation != "rollback candidate" {
				t.Fatalf("unexpected annotation request: %#v", req)
			}
			return &graphAnnotationWriteResponse{AnnotationID: "ann-1", EntityID: req.EntityID, Count: 1}, nil
		},
		writeDecisionFunc: func(_ context.Context, req graphWriteDecisionRequest) (*graphDecisionWriteResponse, error) {
			if len(req.TargetIDs) != 1 || req.TargetIDs[0] != "service:payments" {
				t.Fatalf("expected normalized target ids, got %#v", req.TargetIDs)
			}
			return &graphDecisionWriteResponse{DecisionID: "decision-1", TargetCount: 1}, nil
		},
		writeOutcomeFunc: func(_ context.Context, req graphWriteOutcomeRequest) (*graphOutcomeWriteResponse, error) {
			if req.DecisionID != "decision-1" || len(req.TargetIDs) != 1 || req.TargetIDs[0] != "service:payments" {
				t.Fatalf("unexpected outcome request: %#v", req)
			}
			return &graphOutcomeWriteResponse{OutcomeID: "outcome-1", DecisionID: req.DecisionID, TargetCount: 1}, nil
		},
	})

	w := do(t, s, http.MethodPost, "/api/v1/platform/knowledge/observations", map[string]any{
		"entity_id":     "service:payments",
		"observation":   "deploy_risk_increase",
		"source_system": "api",
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	if body := decodeJSON(t, w); body["observation_id"] != "obs-1" {
		t.Fatalf("expected service-backed observation response, got %#v", body)
	}

	w = do(t, s, http.MethodPost, "/api/v1/platform/knowledge/claims", map[string]any{
		"subject_id":    "service:payments",
		"predicate":     "owner",
		"object_id":     "person:alice@example.com",
		"source_system": "api",
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	if body := decodeJSON(t, w); body["claim_id"] != "claim-1" {
		t.Fatalf("expected service-backed claim response, got %#v", body)
	}

	w = do(t, s, http.MethodPost, "/api/v1/graph/write/annotation", map[string]any{
		"entity_id":     "service:payments",
		"annotation":    "rollback candidate",
		"source_system": "api",
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	if body := decodeJSON(t, w); body["annotation_id"] != "ann-1" {
		t.Fatalf("expected service-backed annotation response, got %#v", body)
	}

	w = do(t, s, http.MethodPost, "/api/v1/platform/knowledge/decisions", map[string]any{
		"decision_type": "rollback",
		"target_ids":    []string{" service:payments ", "service:payments"},
		"source_system": "api",
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	if body := decodeJSON(t, w); body["decision_id"] != "decision-1" {
		t.Fatalf("expected service-backed decision response, got %#v", body)
	}

	w = do(t, s, http.MethodPost, "/api/v1/graph/write/outcome", map[string]any{
		"decision_id":   "decision-1",
		"outcome_type":  "deployment_result",
		"verdict":       "positive",
		"target_ids":    []string{" service:payments ", "service:payments"},
		"source_system": "api",
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	if body := decodeJSON(t, w); body["outcome_id"] != "outcome-1" {
		t.Fatalf("expected service-backed outcome response, got %#v", body)
	}
}

func TestGraphWritebackLeaseUnavailableReturnsServiceUnavailable(t *testing.T) {
	s := newGraphWritebackServiceTestServer(t, stubGraphWritebackService{
		writeObservationFunc: func(_ context.Context, _ graphWriteObservationRequest) (*graphWriteObservationResponse, error) {
			return nil, errors.New("graph writer lease not held by this process")
		},
	})

	w := do(t, s, http.MethodPost, "/api/v1/platform/knowledge/observations", map[string]any{
		"entity_id":     "service:payments",
		"observation":   "deploy_risk_increase",
		"source_system": "api",
	})
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 for graph writer lease unavailability, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGraphWritebackIdentityHandlersUseServiceInterface(t *testing.T) {
	s := newGraphWritebackServiceTestServer(t, stubGraphWritebackService{
		resolveIdentityFunc: func(_ context.Context, req graphResolveIdentityRequest) (*graph.IdentityResolutionResult, error) {
			if req.ExternalID != "alice-handle" {
				t.Fatalf("unexpected identity resolve request: %#v", req)
			}
			return &graph.IdentityResolutionResult{AliasNodeID: "identity_alias:github:alice"}, nil
		},
		splitIdentityFunc: func(_ context.Context, req graphSplitIdentityRequest) (*graphIdentitySplitResponse, error) {
			if req.AliasNodeID != "identity_alias:github:alice" || req.CanonicalNodeID != "person:alice@example.com" {
				t.Fatalf("unexpected split request: %#v", req)
			}
			return &graphIdentitySplitResponse{Removed: true, AliasNodeID: req.AliasNodeID, CanonicalNodeID: req.CanonicalNodeID}, nil
		},
		reviewIdentityFunc: func(_ context.Context, req graphIdentityReviewRequest) (*graph.IdentityReviewRecord, error) {
			if req.Verdict != "accepted" {
				t.Fatalf("unexpected review request: %#v", req)
			}
			return &graph.IdentityReviewRecord{Verdict: req.Verdict, Reviewer: req.Reviewer}, nil
		},
		identityCalibrationFunc: func(_ context.Context, opts graph.IdentityCalibrationOptions) (*graph.IdentityCalibrationReport, error) {
			if !opts.IncludeQueue || opts.QueueLimit != 10 || opts.SuggestThreshold != 0.75 {
				t.Fatalf("unexpected calibration opts: %#v", opts)
			}
			return &graph.IdentityCalibrationReport{AliasNodes: 2, ReviewedAliases: 1}, nil
		},
	})

	w := do(t, s, http.MethodPost, "/api/v1/graph/identity/resolve", map[string]any{
		"source_system": "github",
		"external_id":   "alice-handle",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if body := decodeJSON(t, w); body["alias_node_id"] != "identity_alias:github:alice" {
		t.Fatalf("expected service-backed resolve response, got %#v", body)
	}

	w = do(t, s, http.MethodPost, "/api/v1/graph/identity/split", map[string]any{
		"alias_node_id":     "identity_alias:github:alice",
		"canonical_node_id": "person:alice@example.com",
		"reason":            "manual correction",
		"source_system":     "analyst",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if body := decodeJSON(t, w); body["removed"] != true {
		t.Fatalf("expected service-backed split response, got %#v", body)
	}

	w = do(t, s, http.MethodPost, "/api/v1/graph/identity/review", map[string]any{
		"alias_node_id":     "identity_alias:github:alice",
		"canonical_node_id": "person:alice@example.com",
		"verdict":           "accepted",
		"reviewer":          "analyst@company.com",
		"reason":            "exact email",
		"source_system":     "analyst",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if body := decodeJSON(t, w); body["verdict"] != "accepted" {
		t.Fatalf("expected service-backed review response, got %#v", body)
	}

	w = do(t, s, http.MethodGet, "/api/v1/graph/identity/calibration?include_queue=true&queue_limit=10&suggest_threshold=0.75", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if body := decodeJSON(t, w); body["alias_nodes"] != float64(2) {
		t.Fatalf("expected service-backed calibration response, got %#v", body)
	}
}

func TestGraphWritebackActionHandlersUseServiceInterface(t *testing.T) {
	s := newGraphWritebackServiceTestServer(t, stubGraphWritebackService{
		actuateRecommendationFunc: func(_ context.Context, req graphActuateRecommendationRequest) (*graph.RecommendationActuationResult, error) {
			if req.RecommendationID != "rec-1" || req.DecisionID != "decision-1" {
				t.Fatalf("unexpected actuation request: %#v", req)
			}
			return &graph.RecommendationActuationResult{
				ActionID:         "action-1",
				RecommendationID: req.RecommendationID,
				SourceSystem:     "conductor",
				SourceEventID:    "api:1",
			}, nil
		},
	})

	w := do(t, s, http.MethodPost, "/api/v1/graph/actuate/recommendation", map[string]any{
		"recommendation_id": "rec-1",
		"insight_type":      "graph_freshness",
		"title":             "Increase scanner cadence",
		"decision_id":       "decision-1",
		"target_ids":        []string{"service:payments"},
		"source_system":     "conductor",
		"auto_generated":    true,
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	if body := decodeJSON(t, w); body["action_id"] != "action-1" {
		t.Fatalf("expected service-backed actuation response, got %#v", body)
	}
}
