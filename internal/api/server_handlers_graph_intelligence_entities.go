package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/graph/knowledge"
	reports "github.com/writer/cerebro/internal/graph/reports"
)

func (s *Server) graphIntelligenceClaimConflicts(w http.ResponseWriter, r *http.Request) {
	g := s.currentGraphIntelligenceGraph(r.Context())
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	maxConflicts := 25
	if raw := strings.TrimSpace(r.URL.Query().Get("max_conflicts")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 200 {
			s.error(w, http.StatusBadRequest, "max_conflicts must be between 1 and 200")
			return
		}
		maxConflicts = parsed
	}

	includeResolved := false
	if raw := strings.TrimSpace(r.URL.Query().Get("include_resolved")); raw != "" {
		parsed, err := strconv.ParseBool(raw)
		if err != nil {
			s.error(w, http.StatusBadRequest, "include_resolved must be a boolean")
			return
		}
		includeResolved = parsed
	}

	var staleAfter time.Duration
	if raw := strings.TrimSpace(r.URL.Query().Get("stale_after_hours")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 8760 {
			s.error(w, http.StatusBadRequest, "stale_after_hours must be between 1 and 8760")
			return
		}
		staleAfter = time.Duration(parsed) * time.Hour
	}

	var validAt time.Time
	if raw := strings.TrimSpace(r.URL.Query().Get("valid_at")); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			s.error(w, http.StatusBadRequest, "valid_at must be RFC3339")
			return
		}
		validAt = parsed
	}

	var recordedAt time.Time
	if raw := strings.TrimSpace(r.URL.Query().Get("recorded_at")); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			s.error(w, http.StatusBadRequest, "recorded_at must be RFC3339")
			return
		}
		recordedAt = parsed
	}

	report := knowledge.BuildClaimConflictReport(g, knowledge.ClaimConflictReportOptions{
		ValidAt:         validAt,
		RecordedAt:      recordedAt,
		MaxConflicts:    maxConflicts,
		IncludeResolved: includeResolved,
		StaleAfter:      staleAfter,
	})
	s.json(w, http.StatusOK, report)
}

func (s *Server) graphIntelligenceEntitySummary(w http.ResponseWriter, r *http.Request) {
	entityID := strings.TrimSpace(r.URL.Query().Get("entity_id"))
	if entityID == "" {
		s.error(w, http.StatusBadRequest, "entity_id is required")
		return
	}

	validAt, err := parseOptionalRFC3339Query(r, "valid_at")
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}
	recordedAt, err := parseOptionalRFC3339Query(r, "recorded_at")
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}

	maxPostureClaims := 10
	if raw := strings.TrimSpace(r.URL.Query().Get("max_posture_claims")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 100 {
			s.error(w, http.StatusBadRequest, "max_posture_claims must be between 1 and 100")
			return
		}
		maxPostureClaims = parsed
	}

	g, err := s.graphIntelligenceEntityGraph(r.Context(), entityID, validAt, recordedAt)
	if err != nil {
		s.errorFromErr(w, err)
		return
	}
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	report, ok := reports.BuildEntitySummaryReport(g, reports.EntitySummaryReportOptions{
		EntityID:         entityID,
		ValidAt:          validAt,
		RecordedAt:       recordedAt,
		MaxPostureClaims: maxPostureClaims,
	})
	if !ok {
		s.error(w, http.StatusNotFound, "entity not found")
		return
	}
	s.json(w, http.StatusOK, report)
}

func (s *Server) graphIntelligenceKeyPersonRisk(w http.ResponseWriter, r *http.Request) {
	g := s.currentGraphIntelligenceGraph(r.Context())
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	limit := 10
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 100 {
			s.error(w, http.StatusBadRequest, "limit must be between 1 and 100")
			return
		}
		limit = parsed
	}

	personID := strings.TrimSpace(r.URL.Query().Get("person_id"))
	report := reports.BuildKeyPersonRiskReport(g, time.Now().UTC(), personID, limit)
	if personID != "" && report.Count == 0 {
		s.error(w, http.StatusNotFound, "person not found")
		return
	}
	s.json(w, http.StatusOK, report)
}
