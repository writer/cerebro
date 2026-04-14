package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/writer/cerebro/internal/providers"
)

// Provider endpoints.
//
// Endpoint software/CVE workflows generally use this control plane first:
//   1. POST /api/v1/providers/{name}/sync to materialize provider rows
//   2. GET /api/v1/providers/{name}/schema to discover table names and columns
//   3. POST /api/v1/query (or GET /api/v1/assets/{table} for spot checks) to
//      join device/agent, application, and vulnerability tables
//
// Today the provider layer preserves provider-native software names and versions.
// That keeps ingest lossless, but cross-provider patch-target correlation usually
// needs an extra normalization step above these endpoints.

func (s *Server) listProviders(w http.ResponseWriter, r *http.Request) {
	providerList := s.app.Providers.List()
	includeIncomplete := includeIncompleteProviders(r)
	result := make([]map[string]interface{}, 0, len(providerList))
	for _, p := range providerList {
		metadata := providers.ProviderMetadataFor(p.Name())
		if providers.IsProviderIncomplete(p.Name()) && !includeIncomplete {
			continue
		}
		result = append(result, map[string]interface{}{
			"name":     p.Name(),
			"type":     p.Type(),
			"tables":   len(p.Schema()),
			"maturity": metadata.Maturity,
		})
	}
	s.json(w, http.StatusOK, map[string]interface{}{"providers": result, "count": len(result)})
}

func (s *Server) getProvider(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if providers.IsProviderIncomplete(name) && !includeIncompleteProviders(r) {
		s.error(w, http.StatusNotFound, "provider not found")
		return
	}

	p, ok := s.app.Providers.Get(name)
	if !ok {
		s.error(w, http.StatusNotFound, "provider not found")
		return
	}
	metadata := providers.ProviderMetadataFor(name)
	s.json(w, http.StatusOK, map[string]interface{}{
		"name":     p.Name(),
		"type":     p.Type(),
		"schema":   p.Schema(),
		"maturity": metadata.Maturity,
	})
}

func (s *Server) configureProvider(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if providers.IsProviderIncomplete(name) && !includeIncompleteProviders(r) {
		s.error(w, http.StatusNotFound, "provider not found")
		return
	}

	var config map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	if err := s.app.Providers.Configure(r.Context(), name, config); err != nil {
		if errors.Is(err, providers.ErrProviderNotFound) {
			s.error(w, http.StatusNotFound, "provider not found")
			return
		}
		s.errorFromErr(w, err)
		return
	}
	s.json(w, http.StatusOK, map[string]string{"status": "configured"})
}

func (s *Server) syncProvider(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if providers.IsProviderIncomplete(name) && !includeIncompleteProviders(r) {
		s.error(w, http.StatusNotFound, "provider not found")
		return
	}

	p, ok := s.app.Providers.Get(name)
	if !ok {
		s.error(w, http.StatusNotFound, "provider not found")
		return
	}

	opts := providers.SyncOptions{FullSync: true}
	var req struct {
		FullSync *bool    `json:"full_sync,omitempty"`
		Tables   []string `json:"tables,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if !errors.Is(err, io.EOF) {
			s.error(w, http.StatusBadRequest, "invalid request")
			return
		}
	}
	if req.FullSync != nil {
		opts.FullSync = *req.FullSync
	}
	if len(req.Tables) > 0 {
		opts.Tables = req.Tables
	}

	result, err := p.Sync(r.Context(), opts)
	if err != nil {
		s.errorFromErr(w, err)
		return
	}
	s.json(w, http.StatusOK, result)
}

func (s *Server) getProviderSchema(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if providers.IsProviderIncomplete(name) && !includeIncompleteProviders(r) {
		s.error(w, http.StatusNotFound, "provider not found")
		return
	}

	p, ok := s.app.Providers.Get(name)
	if !ok {
		s.error(w, http.StatusNotFound, "provider not found")
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"tables": p.Schema()})
}

func (s *Server) testProvider(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if providers.IsProviderIncomplete(name) && !includeIncompleteProviders(r) {
		s.error(w, http.StatusNotFound, "provider not found")
		return
	}

	p, ok := s.app.Providers.Get(name)
	if !ok {
		s.error(w, http.StatusNotFound, "provider not found")
		return
	}

	if err := p.Test(r.Context()); err != nil {
		s.json(w, http.StatusOK, map[string]interface{}{"status": "failed", "error": err.Error()})
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"status": "success"})
}

// Helpers

func includeIncompleteProviders(r *http.Request) bool {
	include := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("include_incomplete")))
	return include == "1" || include == "true" || include == "yes"
}
