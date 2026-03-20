package api

import (
	"net/http"
	"strconv"
	"strings"
)

func (s *Server) orgInformationFlow(w http.ResponseWriter, r *http.Request) {
	from := strings.TrimSpace(r.URL.Query().Get("from"))
	to := strings.TrimSpace(r.URL.Query().Get("to"))
	if from == "" || to == "" {
		s.error(w, http.StatusBadRequest, "from and to query params are required")
		return
	}

	path, err := s.orgAnalysis.InformationPath(r.Context(), from, to)
	if err != nil {
		s.errorFromErr(w, err)
		return
	}
	if path == nil {
		s.error(w, http.StatusNotFound, "no information path found for provided endpoints")
		return
	}

	s.json(w, http.StatusOK, path)
}

func (s *Server) orgClockSpeed(w http.ResponseWriter, r *http.Request) {
	clock, err := s.orgAnalysis.ClockSpeed(r.Context())
	if err != nil {
		s.errorFromErr(w, err)
		return
	}
	s.json(w, http.StatusOK, clock)
}

func (s *Server) orgRecommendedConnections(w http.ResponseWriter, r *http.Request) {
	limit := 10
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			if parsed > 50 {
				parsed = 50
			}
			limit = parsed
		}
	}

	recommendations, err := s.orgAnalysis.RecommendConnections(r.Context(), limit)
	if err != nil {
		s.errorFromErr(w, err)
		return
	}
	s.json(w, http.StatusOK, map[string]any{
		"count":           len(recommendations),
		"recommendations": recommendations,
	})
}
