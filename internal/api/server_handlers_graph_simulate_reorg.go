package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/writer/cerebro/internal/graph"
)

type graphSimulateReorgRequest struct {
	Changes []graph.ReorgChange `json:"changes"`
}

func (s *Server) simulateReorg(w http.ResponseWriter, r *http.Request) {
	var req graphSimulateReorgRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Changes) == 0 {
		s.error(w, http.StatusBadRequest, "at least one reorg change is required")
		return
	}

	impact, err := s.graphSimulation.SimulateReorg(r.Context(), req.Changes)
	if err != nil {
		if errors.Is(err, graph.ErrStoreUnavailable) {
			s.errorFromErr(w, err)
			return
		}
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}

	s.json(w, http.StatusOK, impact)
}
