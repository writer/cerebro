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
	if s.app.SecurityGraph == nil {
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

	impact, err := graph.SimulateReorg(s.app.SecurityGraph, req.Changes)
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}

	s.json(w, http.StatusOK, impact)
}
