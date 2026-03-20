package api

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

func (s *Server) orgOnboardingPlan(w http.ResponseWriter, r *http.Request) {
	personID := strings.TrimSpace(chi.URLParam(r, "id"))
	if personID == "" {
		s.error(w, http.StatusBadRequest, "person id is required")
		return
	}

	plan, err := s.orgAnalysis.OnboardingPlan(r.Context(), personID)
	if err != nil {
		s.errorFromErr(w, err)
		return
	}
	if plan == nil {
		s.error(w, http.StatusNotFound, "onboarding plan not found")
		return
	}

	s.json(w, http.StatusOK, plan)
}
