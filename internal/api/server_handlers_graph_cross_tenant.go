package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/metrics"
)

type crossTenantBuildRequest struct {
	TenantID   string `json:"tenant_id"`
	WindowDays int    `json:"window_days,omitempty"`
}

type crossTenantIngestRequest struct {
	Samples []graph.AnonymizedPatternSample `json:"samples"`
}

func (s *Server) buildCrossTenantPatternSamples(w http.ResponseWriter, r *http.Request) {
	if s.app.SecurityGraph == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}
	engine := s.graphRiskEngine()
	if engine == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	var req crossTenantBuildRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.TenantID = strings.TrimSpace(req.TenantID)
	if req.TenantID == "" {
		s.error(w, http.StatusBadRequest, "tenant_id is required")
		return
	}
	if req.WindowDays <= 0 {
		req.WindowDays = 90
	}

	samples, err := engine.BuildAnonymizedPatternSamples(req.TenantID, time.Duration(req.WindowDays)*24*time.Hour)
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}
	s.json(w, http.StatusOK, map[string]any{
		"count":   len(samples),
		"samples": samples,
	})
}

func (s *Server) ingestCrossTenantPatternSamples(w http.ResponseWriter, r *http.Request) {
	if s.app.SecurityGraph == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}
	engine := s.graphRiskEngine()
	if engine == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		metrics.RecordGraphCrossTenantIngest("read_error", 0)
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := s.verifyCrossTenantIngestAuth(r, body); err != nil {
		metrics.RecordGraphCrossTenantIngest("auth_failed", 0)
		status := http.StatusUnauthorized
		message := err.Error()
		var authErr crossTenantAuthError
		if errors.As(err, &authErr) {
			status = authErr.status
			message = authErr.message
		}
		s.error(w, status, message)
		return
	}

	var req crossTenantIngestRequest
	if err := json.Unmarshal(body, &req); err != nil {
		metrics.RecordGraphCrossTenantIngest("decode_error", 0)
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Samples) == 0 {
		metrics.RecordGraphCrossTenantIngest("empty_samples", 0)
		s.error(w, http.StatusBadRequest, "samples is required")
		return
	}

	summary := engine.IngestAnonymizedPatternSamples(req.Samples)
	s.persistRiskEngineState(r.Context(), engine)
	metrics.RecordGraphCrossTenantIngest("accepted", summary.Received)
	s.json(w, http.StatusOK, summary)
}

func (s *Server) listCrossTenantPatterns(w http.ResponseWriter, r *http.Request) {
	if s.app.SecurityGraph == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}
	engine := s.graphRiskEngine()
	if engine == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	minTenants := 1
	if raw := strings.TrimSpace(r.URL.Query().Get("min_tenants")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			s.error(w, http.StatusBadRequest, fmt.Sprintf("invalid min_tenants: %q", raw))
			return
		}
		minTenants = parsed
	}

	patterns := engine.CrossTenantPatterns(minTenants)
	metrics.RecordGraphCrossTenantPatterns(len(patterns))
	s.json(w, http.StatusOK, map[string]any{
		"count":    len(patterns),
		"patterns": patterns,
	})
}

func (s *Server) matchCrossTenantPatterns(w http.ResponseWriter, r *http.Request) {
	if s.app.SecurityGraph == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}
	engine := s.graphRiskEngine()
	if engine == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	minProbability := 0.60
	if raw := strings.TrimSpace(r.URL.Query().Get("min_probability")); raw != "" {
		parsed, err := strconv.ParseFloat(raw, 64)
		if err != nil || parsed <= 0 || parsed > 1 {
			s.error(w, http.StatusBadRequest, fmt.Sprintf("invalid min_probability: %q", raw))
			return
		}
		minProbability = parsed
	}
	limit := 25
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			s.error(w, http.StatusBadRequest, fmt.Sprintf("invalid limit: %q", raw))
			return
		}
		limit = parsed
	}

	matches := engine.MatchCrossTenantPatterns(minProbability, limit)
	metrics.RecordGraphCrossTenantMatches(len(matches))
	s.json(w, http.StatusOK, map[string]any{
		"count":   len(matches),
		"matches": matches,
	})
}
