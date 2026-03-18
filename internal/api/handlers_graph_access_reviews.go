package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/evalops/cerebro/internal/graph"
	"github.com/evalops/cerebro/internal/identity"
	"github.com/go-chi/chi/v5"
)

// Graph-based Access Review endpoints.
//
// These now delegate to the shared identity access-review service so graph and
// identity surfaces observe the same durable campaign state.

func (s *Server) createGraphAccessReview(w http.ResponseWriter, r *http.Request) {
	ctx := graph.WithTenantScope(r.Context(), currentTenantScopeID(r.Context()))
	g, err := s.currentTenantSecurityGraphView(ctx)
	if err != nil {
		s.errorFromErr(w, err)
		return
	}
	if s == nil || s.app == nil || s.app.Identity == nil {
		s.error(w, http.StatusServiceUnavailable, "identity service not initialized")
		return
	}

	var req struct {
		Name        string     `json:"name"`
		Description string     `json:"description"`
		CreatedBy   string     `json:"created_by"`
		Reviewers   []string   `json:"reviewers"`
		DueDate     *time.Time `json:"due_date"`
		Scope       struct {
			Type       string   `json:"type"`
			AccountIDs []string `json:"account_ids,omitempty"`
			Principals []string `json:"principals,omitempty"`
			Resources  []string `json:"resources,omitempty"`
			RiskLevels []string `json:"risk_levels,omitempty"`
		} `json:"scope"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	review, err := s.app.Identity.CreateReview(identity.WithResolvedGraph(ctx, g), &identity.AccessReview{
		Name:        req.Name,
		Description: req.Description,
		Type:        identity.ReviewTypeUserAccess,
		CreatedBy:   requestReviewActor(ctx, req.CreatedBy),
		DueAt:       req.DueDate,
		Reviewers:   req.Reviewers,
		Scope: identity.ReviewScope{
			Mode:       identity.ReviewScopeMode(strings.TrimSpace(req.Scope.Type)),
			Accounts:   req.Scope.AccountIDs,
			Users:      req.Scope.Principals,
			Resources:  req.Scope.Resources,
			RiskLevels: req.Scope.RiskLevels,
		},
		GenerationSource: "graph",
	})
	if err != nil {
		s.errorFromErr(w, err)
		return
	}

	s.json(w, http.StatusCreated, review)
}

func (s *Server) listGraphAccessReviews(w http.ResponseWriter, r *http.Request) {
	if s == nil || s.app == nil || s.app.Identity == nil {
		s.error(w, http.StatusServiceUnavailable, "identity service not initialized")
		return
	}
	allReviews := s.app.Identity.ListReviews(r.Context(), "")
	reviews := make([]*identity.AccessReview, 0, len(allReviews))
	for _, review := range allReviews {
		if review != nil && review.GenerationSource == "graph" {
			reviews = append(reviews, review)
		}
	}
	s.json(w, http.StatusOK, map[string]interface{}{
		"reviews": reviews,
		"count":   len(reviews),
	})
}

func (s *Server) getGraphAccessReview(w http.ResponseWriter, r *http.Request) {
	if s == nil || s.app == nil || s.app.Identity == nil {
		s.error(w, http.StatusServiceUnavailable, "identity service not initialized")
		return
	}
	id := chi.URLParam(r, "id")
	review, ok := s.app.Identity.GetReview(r.Context(), id)
	if !ok || review.GenerationSource != "graph" {
		s.error(w, http.StatusNotFound, "access review not found")
		return
	}
	s.json(w, http.StatusOK, review)
}

func (s *Server) startGraphAccessReview(w http.ResponseWriter, r *http.Request) {
	if s == nil || s.app == nil || s.app.Identity == nil {
		s.error(w, http.StatusServiceUnavailable, "identity service not initialized")
		return
	}
	id := chi.URLParam(r, "id")
	review, ok := s.app.Identity.GetReview(r.Context(), id)
	if !ok || review.GenerationSource != "graph" {
		s.error(w, http.StatusNotFound, "access review not found")
		return
	}
	if err := s.app.Identity.StartReview(r.Context(), id); err != nil {
		s.errorFromErr(w, err)
		return
	}
	review, _ = s.app.Identity.GetReview(r.Context(), id)
	s.json(w, http.StatusOK, review)
}

func (s *Server) decideGraphAccessReviewItem(w http.ResponseWriter, r *http.Request) {
	if s == nil || s.app == nil || s.app.Identity == nil {
		s.error(w, http.StatusServiceUnavailable, "identity service not initialized")
		return
	}
	reviewID := chi.URLParam(r, "id")
	review, ok := s.app.Identity.GetReview(r.Context(), reviewID)
	if !ok || review.GenerationSource != "graph" {
		s.error(w, http.StatusNotFound, "access review not found")
		return
	}
	itemID := chi.URLParam(r, "itemId")

	var decision struct {
		Action    identity.DecisionAction `json:"action"`
		DecidedBy string                  `json:"decided_by"`
		DecidedAt time.Time               `json:"decided_at"`
		Reason    string                  `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&decision); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}
	if err := s.app.Identity.RecordDecision(r.Context(), reviewID, itemID, &identity.ReviewDecision{
		Action:    decision.Action,
		Reviewer:  requestReviewActor(r.Context(), decision.DecidedBy),
		Comment:   decision.Reason,
		DecidedAt: decision.DecidedAt,
	}); err != nil {
		s.errorFromErr(w, err)
		return
	}
	s.json(w, http.StatusOK, map[string]string{"status": "decision recorded"})
}
