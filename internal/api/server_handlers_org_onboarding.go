package api

import (
	"net/http"
	"strings"

	"github.com/evalops/cerebro/internal/graph"
	"github.com/go-chi/chi/v5"
)

func (s *Server) orgOnboardingPlan(w http.ResponseWriter, r *http.Request) {
	if s.app.SecurityGraph == nil {
		s.error(w, http.StatusServiceUnavailable, "security graph not initialized")
		return
	}

	personID := strings.TrimSpace(chi.URLParam(r, "id"))
	if personID == "" {
		s.error(w, http.StatusBadRequest, "person id is required")
		return
	}

	plan := graph.GenerateOnboardingPlan(s.app.SecurityGraph, personID)
	if plan == nil {
		s.error(w, http.StatusNotFound, "onboarding plan not found")
		return
	}

	s.json(w, http.StatusOK, plan)
}
