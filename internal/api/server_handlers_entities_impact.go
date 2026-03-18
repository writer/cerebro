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
	g, err := s.currentTenantSecurityGraphView(r.Context())
	if err != nil {
		s.errorFromErr(w, err)
		return
	}
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	entityID := chi.URLParam(r, "id")
	if strings.TrimSpace(entityID) == "" {
		s.error(w, http.StatusBadRequest, "entity id required")
		return
	}

	cohort, ok := graph.GetEntityCohort(g, entityID)
	if !ok {
		s.error(w, http.StatusNotFound, "cohort not found")
		return
	}

	s.json(w, http.StatusOK, cohort)
}

func (s *Server) getEntityOutlierScore(w http.ResponseWriter, r *http.Request) {
	g, err := s.currentTenantSecurityGraphView(r.Context())
	if err != nil {
		s.errorFromErr(w, err)
		return
	}
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	entityID := chi.URLParam(r, "id")
	if strings.TrimSpace(entityID) == "" {
		s.error(w, http.StatusBadRequest, "entity id required")
		return
	}

	outlier, ok := graph.GetEntityOutlierScore(g, entityID)
	if !ok {
		s.error(w, http.StatusNotFound, "outlier score not found")
		return
	}

	s.json(w, http.StatusOK, outlier)
}

func (s *Server) impactAnalysis(w http.ResponseWriter, r *http.Request) {
	g, err := s.currentTenantSecurityGraphView(r.Context())
	if err != nil {
		s.errorFromErr(w, err)
		return
	}
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

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

	analyzer := graph.NewImpactPathAnalyzer(g)
	result := analyzer.Analyze(req.StartNode, scenario, req.MaxDepth)
	s.json(w, http.StatusOK, result)
}
