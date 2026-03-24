package api

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/writer/cerebro/internal/graph"
	risk "github.com/writer/cerebro/internal/graph/risk"
)

// Visualization endpoints (Mermaid)

func (s *Server) visualizeAttackPath(w http.ResponseWriter, r *http.Request) {
	pathIndex := chi.URLParam(r, "id")
	idx, err := strconv.Atoi(pathIndex)
	if err != nil || idx < 0 {
		s.error(w, http.StatusBadRequest, "valid path index required")
		return
	}

	var (
		g      *graph.Graph
		result *risk.SimulationResult
	)
	if live := s.currentTenantSecurityGraph(r.Context()); live != nil {
		g = live
		result = risk.NewAttackPathSimulator(live).Simulate(6)
	} else {
		store := s.currentTenantSecurityGraphStore(r.Context())
		if store == nil {
			s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
			return
		}
		queryStore, ok := graph.AsAttackPathQueryStore(store)
		if !ok {
			result, err = graph.SimulateAttackPathsFromStore(r.Context(), store, 6)
		} else {
			result, err = queryStore.AttackPaths(r.Context(), 6)
		}
		if err != nil {
			s.errorFromErr(w, err)
			return
		}
	}

	if idx >= len(result.Paths) {
		s.error(w, http.StatusNotFound, "attack path not found")
		return
	}
	if g == nil {
		store := s.currentTenantSecurityGraphStore(r.Context())
		g, err = graph.BuildAttackPathViewGraph(r.Context(), store, result.Paths[idx])
		if err != nil {
			s.errorFromErr(w, err)
			return
		}
	}

	exporter := graph.NewMermaidExporter(g)
	mermaid := exporter.ExportAttackPath(result.Paths[idx])

	w.Header().Set("Content-Type", "text/markdown")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(mermaid)) // #nosec G705 -- payload is server-generated Mermaid graph text
}

func (s *Server) visualizeToxicCombination(w http.ResponseWriter, r *http.Request) {
	g, err := s.currentTenantSecurityGraphSnapshotView(r.Context())
	if err != nil {
		s.errorFromErr(w, err)
		return
	}

	tcID := chi.URLParam(r, "id")
	if tcID == "" {
		s.error(w, http.StatusBadRequest, "toxic combination ID required")
		return
	}

	engine := risk.NewToxicCombinationEngine()
	results := engine.Analyze(g)

	var targetTC *risk.ToxicCombination
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

	exporter := graph.NewMermaidExporter(g)
	mermaid := exporter.ExportToxicCombination(targetTC)

	w.Header().Set("Content-Type", "text/markdown")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(mermaid)) // #nosec G705 -- payload is server-generated Mermaid graph text
}

func (s *Server) visualizeBlastRadius(w http.ResponseWriter, r *http.Request) {
	store := s.currentTenantSecurityGraphStore(r.Context())
	if store == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
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

	result, err := store.BlastRadius(r.Context(), principalID, maxDepth)
	if err != nil {
		s.errorFromErr(w, err)
		return
	}
	exporter := graph.NewMermaidExporter(nil)
	mermaid := exporter.ExportBlastRadius(result)

	w.Header().Set("Content-Type", "text/markdown")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(mermaid)) // #nosec G705 -- payload is server-generated Mermaid graph text
}

func (s *Server) visualizeReport(w http.ResponseWriter, r *http.Request) {
	g, err := s.currentTenantSecurityGraphSnapshotView(r.Context())
	if err != nil {
		s.errorFromErr(w, err)
		return
	}

	engine := risk.NewRiskEngine(g)
	report := engine.Analyze()

	exporter := graph.NewMermaidExporter(g)
	mermaid := exporter.ExportSecurityReport(report)

	w.Header().Set("Content-Type", "text/markdown")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(mermaid)) // #nosec G705 -- payload is server-generated Mermaid graph text
}
