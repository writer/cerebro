package api

import (
	"net/http"
	"strings"

	"github.com/evalops/cerebro/internal/graph"
	"github.com/go-chi/chi/v5"
)

func (s *Server) orgOnboardingPlan(w http.ResponseWriter, r *http.Request) {
	g, err := s.currentTenantSecurityGraphView(r.Context())
	if err != nil {
		s.errorFromErr(w, err)
		return
	}
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	personID := strings.TrimSpace(chi.URLParam(r, "id"))
	if personID == "" {
		s.error(w, http.StatusBadRequest, "person id is required")
		return
	}

	plan := graph.GenerateOnboardingPlan(g, personID)
	if plan == nil {
		s.error(w, http.StatusNotFound, "onboarding plan not found")
		return
	}

	s.json(w, http.StatusOK, plan)
}
