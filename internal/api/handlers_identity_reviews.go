package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/writer/cerebro/internal/identity"
)

// Identity/Access Review endpoints

func (s *Server) listReviews(w http.ResponseWriter, r *http.Request) {
	status := identity.ReviewStatus(r.URL.Query().Get("status"))
	reviews := s.app.Identity.ListReviews(r.Context(), status)
	s.json(w, http.StatusOK, map[string]interface{}{"reviews": reviews, "count": len(reviews)})
}

func (s *Server) createReview(w http.ResponseWriter, r *http.Request) {
	var review identity.AccessReview
	if err := json.NewDecoder(r.Body).Decode(&review); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	created, err := s.app.Identity.CreateReview(r.Context(), &review)
	if err != nil {
		s.errorFromErr(w, err)
		return
	}
	s.json(w, http.StatusCreated, created)
}

func (s *Server) getReview(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	review, ok := s.app.Identity.GetReview(r.Context(), id)
	if !ok {
		s.error(w, http.StatusNotFound, "review not found")
		return
	}
	s.json(w, http.StatusOK, review)
}

func (s *Server) startReview(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.app.Identity.StartReview(r.Context(), id); err != nil {
		s.errorFromErr(w, err)
		return
	}
	s.json(w, http.StatusOK, map[string]string{"status": "started"})
}

func (s *Server) listReviewItems(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	review, ok := s.app.Identity.GetReview(r.Context(), id)
	if !ok {
		s.error(w, http.StatusNotFound, "review not found")
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"items": review.Items, "count": len(review.Items)})
}

func (s *Server) addReviewItem(w http.ResponseWriter, r *http.Request) {
	reviewID := chi.URLParam(r, "id")
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
	itemID := chi.URLParam(r, "itemId")
	var decision identity.ReviewDecision
	if err := json.NewDecoder(r.Body).Decode(&decision); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	if err := s.app.Identity.RecordDecision(r.Context(), itemID, &decision); err != nil {
		s.errorFromErr(w, err)
		return
	}
	s.json(w, http.StatusOK, map[string]string{"status": "decision recorded"})
}
