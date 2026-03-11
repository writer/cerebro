package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
)

func (s *Server) getAssetLineage(w http.ResponseWriter, r *http.Request) {
	if s.app.Lineage == nil {
		s.error(w, http.StatusServiceUnavailable, "lineage not initialized")
		return
	}
	assetID := chi.URLParam(r, "assetId")
	lineage, found := s.app.Lineage.GetLineage(assetID)
	if !found {
		s.error(w, http.StatusNotFound, "lineage not found")
		return
	}
	s.json(w, http.StatusOK, lineage)
}

func (s *Server) getLineageByCommit(w http.ResponseWriter, r *http.Request) {
	if s.app.Lineage == nil {
		s.error(w, http.StatusServiceUnavailable, "lineage not initialized")
		return
	}
	sha := chi.URLParam(r, "sha")
	assets := s.app.Lineage.GetLineageByCommit(sha)
	s.json(w, http.StatusOK, assets)
}

func (s *Server) getLineageByImage(w http.ResponseWriter, r *http.Request) {
	if s.app.Lineage == nil {
		s.error(w, http.StatusServiceUnavailable, "lineage not initialized")
		return
	}
	digest := chi.URLParam(r, "digest")
	assets := s.app.Lineage.GetLineageByImage(digest)
	s.json(w, http.StatusOK, assets)
}

func (s *Server) detectDrift(w http.ResponseWriter, r *http.Request) {
	if s.app.Lineage == nil {
		s.error(w, http.StatusServiceUnavailable, "lineage not initialized")
		return
	}
	assetID := chi.URLParam(r, "assetId")

	var req struct {
		CurrentState map[string]interface{} `json:"current_state"`
		IaCState     map[string]interface{} `json:"iac_state"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	drifts := s.app.Lineage.DetectDrift(r.Context(), assetID, req.CurrentState, req.IaCState)
	s.json(w, http.StatusOK, map[string]interface{}{
		"asset_id":       assetID,
		"drift_detected": len(drifts) > 0,
		"drifts":         drifts,
	})
}
