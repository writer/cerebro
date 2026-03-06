package api

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/evalops/cerebro/internal/graph"
)

// Visualization endpoints (Mermaid)

func (s *Server) visualizeAttackPath(w http.ResponseWriter, r *http.Request) {
	if s.app.SecurityGraph == nil {
		s.error(w, http.StatusServiceUnavailable, "security graph not initialized")
		return
	}

	pathIndex := chi.URLParam(r, "id")
	idx, err := strconv.Atoi(pathIndex)
	if err != nil || idx < 0 {
		s.error(w, http.StatusBadRequest, "valid path index required")
		return
	}

	simulator := graph.NewAttackPathSimulator(s.app.SecurityGraph)
	result := simulator.Simulate(6)

	if idx >= len(result.Paths) {
		s.error(w, http.StatusNotFound, "attack path not found")
		return
	}

	exporter := graph.NewMermaidExporter(s.app.SecurityGraph)
	mermaid := exporter.ExportAttackPath(result.Paths[idx])

	w.Header().Set("Content-Type", "text/markdown")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(mermaid)) // #nosec G705 -- payload is server-generated Mermaid graph text
}

func (s *Server) visualizeToxicCombination(w http.ResponseWriter, r *http.Request) {
	if s.app.SecurityGraph == nil {
		s.error(w, http.StatusServiceUnavailable, "security graph not initialized")
		return
	}

	tcID := chi.URLParam(r, "id")
	if tcID == "" {
		s.error(w, http.StatusBadRequest, "toxic combination ID required")
		return
	}

	engine := graph.NewToxicCombinationEngine()
	results := engine.Analyze(s.app.SecurityGraph)

	var targetTC *graph.ToxicCombination
	for _, tc := range results {
		if tc.ID == tcID {
			targetTC = tc
			break
		}
	}

	if targetTC == nil {
		s.error(w, http.StatusNotFound, "toxic combination not found")
		return
	}

	exporter := graph.NewMermaidExporter(s.app.SecurityGraph)
	mermaid := exporter.ExportToxicCombination(targetTC)

	w.Header().Set("Content-Type", "text/markdown")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(mermaid)) // #nosec G705 -- payload is server-generated Mermaid graph text
}

func (s *Server) visualizeBlastRadius(w http.ResponseWriter, r *http.Request) {
	if s.app.SecurityGraph == nil {
		s.error(w, http.StatusServiceUnavailable, "security graph not initialized")
		return
	}

	principalID := chi.URLParam(r, "principalId")
	if principalID == "" {
		s.error(w, http.StatusBadRequest, "principal ID required")
		return
	}

	maxDepth := 3
	if depthStr := r.URL.Query().Get("max_depth"); depthStr != "" {
		if d, err := strconv.Atoi(depthStr); err == nil && d > 0 && d <= 10 {
			maxDepth = d
		}
	}

	result := graph.BlastRadius(s.app.SecurityGraph, principalID, maxDepth)
	exporter := graph.NewMermaidExporter(s.app.SecurityGraph)
	mermaid := exporter.ExportBlastRadius(result)

	w.Header().Set("Content-Type", "text/markdown")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(mermaid)) // #nosec G705 -- payload is server-generated Mermaid graph text
}

func (s *Server) visualizeReport(w http.ResponseWriter, r *http.Request) {
	if s.app.SecurityGraph == nil {
		s.error(w, http.StatusServiceUnavailable, "security graph not initialized")
		return
	}

	engine := graph.NewRiskEngine(s.app.SecurityGraph)
	report := engine.Analyze()

	exporter := graph.NewMermaidExporter(s.app.SecurityGraph)
	mermaid := exporter.ExportSecurityReport(report)

	w.Header().Set("Content-Type", "text/markdown")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(mermaid)) // #nosec G705 -- payload is server-generated Mermaid graph text
}
