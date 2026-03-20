package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/writer/cerebro/internal/identity"
)

// Identity/Access Review endpoints

func (s *Server) listReviews(w http.ResponseWriter, r *http.Request) {
	status := identity.ReviewStatus(r.URL.Query().Get("status"))
	allReviews := s.app.Identity.ListReviews(r.Context(), status)
	reviews := make([]*identity.AccessReview, 0, len(allReviews))
	for _, review := range allReviews {
		if review != nil && review.GenerationSource != "graph" {
			reviews = append(reviews, review)
		}
	}
	s.json(w, http.StatusOK, map[string]interface{}{"reviews": reviews, "count": len(reviews)})
}

func (s *Server) createReview(w http.ResponseWriter, r *http.Request) {
	var review identity.AccessReview
	if err := json.NewDecoder(r.Body).Decode(&review); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}
	if strings.TrimSpace(review.GenerationSource) == "graph" {
		s.error(w, http.StatusBadRequest, "graph-generated reviews must use graph access review routes")
		return
	}
	review.GenerationSource = "manual"
	review.CreatedBy = requestReviewActor(r.Context(), review.CreatedBy)

	created, err := s.app.Identity.CreateReview(r.Context(), &review)
	if err != nil {
		s.errorFromErr(w, err)
		return
	}
	s.json(w, http.StatusCreated, created)
}

func (s *Server) getReview(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	review, ok := s.identityRouteReview(r, id)
	if !ok {
		s.error(w, http.StatusNotFound, "review not found")
		return
	}
	s.json(w, http.StatusOK, review)
}

func (s *Server) startReview(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, ok := s.identityRouteReview(r, id); !ok {
		s.error(w, http.StatusNotFound, "review not found")
		return
	}
	if err := s.app.Identity.StartReview(r.Context(), id); err != nil {
		s.errorFromErr(w, err)
		return
	}
	s.json(w, http.StatusOK, map[string]string{"status": "started"})
}

func (s *Server) listReviewItems(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	review, ok := s.identityRouteReview(r, id)
	if !ok {
		s.error(w, http.StatusNotFound, "review not found")
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"items": review.Items, "count": len(review.Items)})
}

func (s *Server) addReviewItem(w http.ResponseWriter, r *http.Request) {
	reviewID := chi.URLParam(r, "id")
	if _, ok := s.identityRouteReview(r, reviewID); !ok {
		s.error(w, http.StatusNotFound, "review not found")
		return
	}
	var item identity.ReviewItem
	if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	if err := s.app.Identity.AddReviewItem(r.Context(), reviewID, &item); err != nil {
		s.errorFromErr(w, err)
		return
	}
	s.json(w, http.StatusCreated, item)
}

func (s *Server) recordDecision(w http.ResponseWriter, r *http.Request) {
	reviewID := chi.URLParam(r, "id")
	if _, ok := s.identityRouteReview(r, reviewID); !ok {
		s.error(w, http.StatusNotFound, "review not found")
		return
	}
	itemID := chi.URLParam(r, "itemId")
	var decision identity.ReviewDecision
	if err := json.NewDecoder(r.Body).Decode(&decision); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}
	decision.Reviewer = requestReviewActor(r.Context(), decision.Reviewer)

	if err := s.app.Identity.RecordDecision(r.Context(), reviewID, itemID, &decision); err != nil {
		s.errorFromErr(w, err)
		return
	}
	s.json(w, http.StatusOK, map[string]string{"status": "decision recorded"})
}

func (s *Server) identityRouteReview(r *http.Request, id string) (*identity.AccessReview, bool) {
	review, ok := s.app.Identity.GetReview(r.Context(), id)
	if !ok || review.GenerationSource == "graph" {
		return nil, false
	}
	return review, true
}

func requestReviewActor(ctx context.Context, asserted string) string {
	if userID := strings.TrimSpace(GetUserID(ctx)); userID != "" {
		return userID
	}
	return strings.TrimSpace(asserted)
}
