package api

import (
	"encoding/json"
	"net/http"

	"github.com/writer/cerebro/internal/graph"
)

type graphSimulateReorgRequest struct {
	Changes []graph.ReorgChange `json:"changes"`
}

func (s *Server) simulateReorg(w http.ResponseWriter, r *http.Request) {
	g, err := s.currentTenantSecurityGraphView(r.Context())
	if err != nil {
		s.errorFromErr(w, err)
		return
	}
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	var req graphSimulateReorgRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Changes) == 0 {
		s.error(w, http.StatusBadRequest, "at least one reorg change is required")
		return
	}

	impact, err := graph.SimulateReorg(g, req.Changes)
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}

	s.json(w, http.StatusOK, impact)
}
