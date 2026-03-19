package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/writer/cerebro/internal/graph"
)

func (s *Server) recommendTeam(w http.ResponseWriter, r *http.Request) {
	g, err := s.currentTenantSecurityGraphView(r.Context())
	if err != nil {
		if errors.Is(err, graph.ErrStoreUnavailable) {
			s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
			return
		}
		s.errorFromErr(w, err)
		return
	}
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	var req graph.TeamRecommendationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	hasTargetSystem := false
	for _, system := range req.TargetSystems {
		if strings.TrimSpace(system) != "" {
			hasTargetSystem = true
			break
		}
	}
	if !hasTargetSystem {
		s.error(w, http.StatusBadRequest, "target_systems is required")
		return
	}

	s.json(w, http.StatusOK, graph.RecommendTeam(g, req))
}
