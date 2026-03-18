package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	risk "github.com/evalops/cerebro/internal/graph/risk"
	"github.com/evalops/cerebro/internal/metrics"
)

type recordOutcomeRequest struct {
	ID         string         `json:"id"`
	EntityID   string         `json:"entity_id"`
	Outcome    string         `json:"outcome"`
	OccurredAt time.Time      `json:"occurred_at"`
	Metadata   map[string]any `json:"metadata,omitempty"`
}

func (s *Server) listGraphOutcomes(w http.ResponseWriter, r *http.Request) {
	engine := s.graphRiskEngine()
	if engine == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	entityID := strings.TrimSpace(r.URL.Query().Get("entity_id"))
	outcome := strings.TrimSpace(r.URL.Query().Get("outcome"))
	outcomes := engine.OutcomeEvents(entityID, outcome)
	s.json(w, http.StatusOK, map[string]any{
		"count":    len(outcomes),
		"outcomes": outcomes,
	})
}

func (s *Server) recordGraphOutcome(w http.ResponseWriter, r *http.Request) {
	engine := s.graphRiskEngine()
	if engine == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	var req recordOutcomeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	recorded, err := engine.RecordOutcome(risk.OutcomeEvent{
		ID:         req.ID,
		EntityID:   req.EntityID,
		Outcome:    req.Outcome,
		OccurredAt: req.OccurredAt,
		Metadata:   req.Metadata,
	})
	if err != nil {
		metrics.RecordGraphOutcome("error")
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}
	metrics.RecordGraphOutcome("recorded")
	s.persistRiskEngineState(r.Context(), engine)

	s.json(w, http.StatusOK, map[string]any{
		"recorded": recorded,
	})
}

func (s *Server) graphRiskFeedback(w http.ResponseWriter, r *http.Request) {
	engine := s.graphRiskEngine()
	if engine == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	windowDays := 90
	if raw := strings.TrimSpace(r.URL.Query().Get("window_days")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			s.error(w, http.StatusBadRequest, fmt.Sprintf("invalid window_days: %q", raw))
			return
		}
		windowDays = parsed
	}

	profile := strings.TrimSpace(r.URL.Query().Get("profile"))
	report := engine.OutcomeFeedback(time.Duration(windowDays)*24*time.Hour, profile)
	s.json(w, http.StatusOK, report)
}
