package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
)

func (s *Server) getAssetLineage(w http.ResponseWriter, r *http.Request) {
	assetID := chi.URLParam(r, "assetId")
	lineage, found, err := s.lineage.GetLineage(assetID)
	if err != nil {
		if errors.Is(err, errLineageUnavailable) {
			s.error(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		s.errorFromErr(w, err)
		return
	}
	if !found {
		s.error(w, http.StatusNotFound, "lineage not found")
		return
	}
	s.json(w, http.StatusOK, lineage)
}

func (s *Server) getLineageByCommit(w http.ResponseWriter, r *http.Request) {
	sha := chi.URLParam(r, "sha")
	assets, err := s.lineage.GetLineageByCommit(sha)
	if err != nil {
		if errors.Is(err, errLineageUnavailable) {
			s.error(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		s.errorFromErr(w, err)
		return
	}
	s.json(w, http.StatusOK, assets)
}

func (s *Server) getLineageByImage(w http.ResponseWriter, r *http.Request) {
	digest := chi.URLParam(r, "digest")
	assets, err := s.lineage.GetLineageByImage(digest)
	if err != nil {
		if errors.Is(err, errLineageUnavailable) {
			s.error(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		s.errorFromErr(w, err)
		return
	}
	s.json(w, http.StatusOK, assets)
}

func (s *Server) detectDrift(w http.ResponseWriter, r *http.Request) {
	assetID := chi.URLParam(r, "assetId")
	if err := s.lineage.Available(); err != nil {
		if errors.Is(err, errLineageUnavailable) {
			s.error(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		s.errorFromErr(w, err)
		return
	}

	var req struct {
		CurrentState map[string]interface{} `json:"current_state"`
		IaCState     map[string]interface{} `json:"iac_state"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	drifts, err := s.lineage.DetectDrift(r.Context(), assetID, req.CurrentState, req.IaCState)
	if err != nil {
		if errors.Is(err, errLineageUnavailable) {
			s.error(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		s.errorFromErr(w, err)
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{
		"asset_id":       assetID,
		"drift_detected": len(drifts) > 0,
		"drifts":         drifts,
	})
}
