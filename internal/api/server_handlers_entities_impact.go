package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/evalops/cerebro/internal/graph"
)

func (s *Server) getEntityCohort(w http.ResponseWriter, r *http.Request) {
	entityID := chi.URLParam(r, "id")
	if strings.TrimSpace(entityID) == "" {
		s.error(w, http.StatusBadRequest, "entity id required")
		return
	}

	cohort, ok, err := s.entitiesImpact.GetEntityCohort(r.Context(), entityID)
	if err != nil {
		s.errorFromErr(w, err)
		return
	}
	if !ok {
		s.error(w, http.StatusNotFound, "cohort not found")
		return
	}

	s.json(w, http.StatusOK, cohort)
}

func (s *Server) getEntityOutlierScore(w http.ResponseWriter, r *http.Request) {
	entityID := chi.URLParam(r, "id")
	if strings.TrimSpace(entityID) == "" {
		s.error(w, http.StatusBadRequest, "entity id required")
		return
	}

	outlier, ok, err := s.entitiesImpact.GetEntityOutlierScore(r.Context(), entityID)
	if err != nil {
		s.errorFromErr(w, err)
		return
	}
	if !ok {
		s.error(w, http.StatusNotFound, "outlier score not found")
		return
	}

	s.json(w, http.StatusOK, outlier)
}

func (s *Server) impactAnalysis(w http.ResponseWriter, r *http.Request) {
	var req struct {
		StartNode string `json:"start_node"`
		Scenario  string `json:"scenario"`
		MaxDepth  int    `json:"max_depth"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}
	if strings.TrimSpace(req.StartNode) == "" {
		s.error(w, http.StatusBadRequest, "start_node is required")
		return
	}
	if req.MaxDepth <= 0 {
		req.MaxDepth = 6
	}
	if maxDepthRaw := r.URL.Query().Get("max_depth"); maxDepthRaw != "" {
		if parsed, err := strconv.Atoi(maxDepthRaw); err == nil && parsed > 0 {
			req.MaxDepth = parsed
		}
	}

	scenario := graph.ImpactScenario(strings.TrimSpace(strings.ToLower(req.Scenario)))
	switch scenario {
	case graph.ImpactScenarioChurnCascade, graph.ImpactScenarioRevenueImpact, graph.ImpactScenarioIncidentBlast:
		// valid
	default:
		s.error(w, http.StatusBadRequest, "scenario must be one of churn_cascade, revenue_impact, incident_blast_radius")
		return
	}

	result, err := s.entitiesImpact.AnalyzeImpact(r.Context(), req.StartNode, scenario, req.MaxDepth)
	if err != nil {
		s.errorFromErr(w, err)
		return
	}
	s.json(w, http.StatusOK, result)
}
