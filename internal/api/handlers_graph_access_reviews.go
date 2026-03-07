package api

import (
	"encoding/json"
	"net/http"
	"sync"

	"github.com/evalops/cerebro/internal/graph"
	"github.com/go-chi/chi/v5"
)

// Graph-based Access Review endpoints

var graphAccessReviews = make(map[string]*graph.AccessReview)
var graphAccessReviewsMu sync.RWMutex

func (s *Server) createGraphAccessReview(w http.ResponseWriter, r *http.Request) {
	if s.app.SecurityGraph == nil {
		s.error(w, http.StatusServiceUnavailable, "security graph not initialized")
		return
	}

	var req struct {
		Name        string            `json:"name"`
		Description string            `json:"description"`
		Scope       graph.ReviewScope `json:"scope"`
		CreatedBy   string            `json:"created_by"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	review := graph.CreateAccessReview(s.app.SecurityGraph, req.Name, req.Scope, req.CreatedBy)
	review.Description = req.Description

	graphAccessReviewsMu.Lock()
	graphAccessReviews[review.ID] = review
	graphAccessReviewsMu.Unlock()

	s.json(w, http.StatusCreated, review)
}

func (s *Server) listGraphAccessReviews(w http.ResponseWriter, r *http.Request) {
	graphAccessReviewsMu.RLock()
	reviews := make([]*graph.AccessReview, 0, len(graphAccessReviews))
	for _, review := range graphAccessReviews {
		reviews = append(reviews, review)
	}
	graphAccessReviewsMu.RUnlock()

	s.json(w, http.StatusOK, map[string]interface{}{
		"reviews": reviews,
		"count":   len(reviews),
	})
}

func (s *Server) getGraphAccessReview(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	graphAccessReviewsMu.RLock()
	review, ok := graphAccessReviews[id]
	graphAccessReviewsMu.RUnlock()

	if !ok {
		s.error(w, http.StatusNotFound, "access review not found")
		return
	}

	s.json(w, http.StatusOK, review)
}

func (s *Server) startGraphAccessReview(w http.ResponseWriter, r *http.Request) {
	if s.app.SecurityGraph == nil {
		s.error(w, http.StatusServiceUnavailable, "security graph not initialized")
		return
	}

	id := chi.URLParam(r, "id")

	graphAccessReviewsMu.Lock()
	review, ok := graphAccessReviews[id]
	if !ok {
		graphAccessReviewsMu.Unlock()
		s.error(w, http.StatusNotFound, "access review not found")
		return
	}

	review.Start()
	graphAccessReviewsMu.Unlock()

	s.json(w, http.StatusOK, review)
}

func (s *Server) decideGraphAccessReviewItem(w http.ResponseWriter, r *http.Request) {
	reviewID := chi.URLParam(r, "id")
	itemID := chi.URLParam(r, "itemId")

	var decision graph.ReviewDecision
	if err := json.NewDecoder(r.Body).Decode(&decision); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	graphAccessReviewsMu.Lock()
	review, ok := graphAccessReviews[reviewID]
	if !ok {
		graphAccessReviewsMu.Unlock()
		s.error(w, http.StatusNotFound, "access review not found")
		return
	}

	if !review.RecordDecision(itemID, decision) {
		graphAccessReviewsMu.Unlock()
		s.error(w, http.StatusNotFound, "review item not found")
		return
	}
	graphAccessReviewsMu.Unlock()

	s.json(w, http.StatusOK, map[string]string{"status": "decision recorded"})
}
