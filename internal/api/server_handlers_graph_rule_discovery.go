package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/metrics"
)

func (s *Server) runGraphRuleDiscovery(w http.ResponseWriter, r *http.Request) {
	var req graph.RuleDiscoveryRequest
	if r.Body != nil {
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			s.error(w, http.StatusBadRequest, "invalid request body")
			return
		}
	}

	candidates, err := s.graphRuleDiscovery.Discover(r.Context(), req)
	if err != nil {
		s.errorFromErr(w, err)
		return
	}
	for _, candidate := range candidates {
		metrics.RecordGraphRuleDiscoveryCandidate(candidate.Type, candidate.Status)
	}
	s.json(w, http.StatusOK, map[string]any{
		"count":      len(candidates),
		"candidates": candidates,
	})
}

func (s *Server) listGraphRuleDiscoveryCandidates(w http.ResponseWriter, r *http.Request) {
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	candidates, err := s.graphRuleDiscovery.List(r.Context(), status)
	if err != nil {
		s.errorFromErr(w, err)
		return
	}
	s.json(w, http.StatusOK, map[string]any{
		"count":      len(candidates),
		"candidates": candidates,
	})
}

func (s *Server) decideGraphRuleDiscoveryCandidate(w http.ResponseWriter, r *http.Request) {
	candidateID := strings.TrimSpace(chi.URLParam(r, "id"))
	if candidateID == "" {
		s.error(w, http.StatusBadRequest, "candidate id is required")
		return
	}

	var req graph.RuleDecisionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	updated, err := s.graphRuleDiscovery.Decide(r.Context(), candidateID, req)
	if err != nil {
		if errors.Is(err, errGraphRiskUnavailable) {
			s.errorFromErr(w, err)
			return
		}
		if strings.Contains(err.Error(), "not found") {
			s.error(w, http.StatusNotFound, err.Error())
			return
		}
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}
	metrics.RecordGraphRuleDecision(updated.Type, updated.Status)
	s.json(w, http.StatusOK, map[string]any{
		"candidate": updated,
	})
}
