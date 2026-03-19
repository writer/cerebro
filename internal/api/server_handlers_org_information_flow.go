package api

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/writer/cerebro/internal/graph"
)

func (s *Server) orgInformationFlow(w http.ResponseWriter, r *http.Request) {
	g, err := s.currentTenantSecurityGraphView(r.Context())
	if err != nil {
		s.errorFromErr(w, err)
		return
	}
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	from := strings.TrimSpace(r.URL.Query().Get("from"))
	to := strings.TrimSpace(r.URL.Query().Get("to"))
	if from == "" || to == "" {
		s.error(w, http.StatusBadRequest, "from and to query params are required")
		return
	}

	path := graph.ShortestInformationPath(g, from, to)
	if path == nil {
		s.error(w, http.StatusNotFound, "no information path found for provided endpoints")
		return
	}

	s.json(w, http.StatusOK, path)
}

func (s *Server) orgClockSpeed(w http.ResponseWriter, r *http.Request) {
	g, err := s.currentTenantSecurityGraphView(r.Context())
	if err != nil {
		s.errorFromErr(w, err)
		return
	}
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	clock := graph.ComputeClockSpeed(g)
	s.json(w, http.StatusOK, clock)
}

func (s *Server) orgRecommendedConnections(w http.ResponseWriter, r *http.Request) {
	g, err := s.currentTenantSecurityGraphView(r.Context())
	if err != nil {
		s.errorFromErr(w, err)
		return
	}
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	limit := 10
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			if parsed > 50 {
				parsed = 50
			}
			limit = parsed
		}
	}

	recommendations := graph.RecommendEdges(g, limit)
	s.json(w, http.StatusOK, map[string]any{
		"count":           len(recommendations),
		"recommendations": recommendations,
	})
}
