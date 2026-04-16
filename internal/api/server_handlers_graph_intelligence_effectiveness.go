package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	reports "github.com/writer/cerebro/internal/graph/reports"
)

func (s *Server) graphIntelligenceAgentActionEffectiveness(w http.ResponseWriter, r *http.Request) {
	g := s.currentGraphIntelligenceGraph(r.Context())
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	windowDays := 30
	if raw := strings.TrimSpace(r.URL.Query().Get("window_days")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 365 {
			s.error(w, http.StatusBadRequest, "window_days must be between 1 and 365")
			return
		}
		windowDays = parsed
	}

	trendDays := 7
	if raw := strings.TrimSpace(r.URL.Query().Get("trend_days")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 90 {
			s.error(w, http.StatusBadRequest, "trend_days must be between 1 and 90")
			return
		}
		trendDays = parsed
	}

	maxAgents := 25
	if raw := strings.TrimSpace(r.URL.Query().Get("max_agents")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 200 {
			s.error(w, http.StatusBadRequest, "max_agents must be between 1 and 200")
			return
		}
		maxAgents = parsed
	}

	report := reports.BuildAgentActionEffectivenessReport(g, reports.AgentActionEffectivenessReportOptions{
		Window:    time.Duration(windowDays) * 24 * time.Hour,
		TrendDays: trendDays,
		MaxAgents: maxAgents,
	})
	s.json(w, http.StatusOK, report)
}

func (s *Server) graphIntelligencePlaybookEffectiveness(w http.ResponseWriter, r *http.Request) {
	g := s.currentGraphIntelligenceGraph(r.Context())
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	windowDays := 30
	if raw := strings.TrimSpace(r.URL.Query().Get("window_days")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 365 {
			s.error(w, http.StatusBadRequest, "window_days must be between 1 and 365")
			return
		}
		windowDays = parsed
	}

	maxPlaybooks := 25
	if raw := strings.TrimSpace(r.URL.Query().Get("max_playbooks")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 200 {
			s.error(w, http.StatusBadRequest, "max_playbooks must be between 1 and 200")
			return
		}
		maxPlaybooks = parsed
	}

	report := reports.BuildPlaybookEffectivenessReport(g, reports.PlaybookEffectivenessReportOptions{
		Window:       time.Duration(windowDays) * 24 * time.Hour,
		PlaybookID:   strings.TrimSpace(r.URL.Query().Get("playbook_id")),
		TenantID:     strings.TrimSpace(r.URL.Query().Get("tenant_id")),
		TargetKind:   strings.TrimSpace(r.URL.Query().Get("target_kind")),
		MaxPlaybooks: maxPlaybooks,
	})
	s.json(w, http.StatusOK, report)
}

func (s *Server) graphIntelligenceUnifiedExecutionTimeline(w http.ResponseWriter, r *http.Request) {
	g := s.currentGraphIntelligenceGraph(r.Context())
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	windowDays := 30
	if raw := strings.TrimSpace(r.URL.Query().Get("window_days")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 365 {
			s.error(w, http.StatusBadRequest, "window_days must be between 1 and 365")
			return
		}
		windowDays = parsed
	}

	maxEvents := 200
	if raw := strings.TrimSpace(r.URL.Query().Get("max_events")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 1000 {
			s.error(w, http.StatusBadRequest, "max_events must be between 1 and 1000")
			return
		}
		maxEvents = parsed
	}

	report := reports.BuildUnifiedExecutionTimelineReport(g, reports.UnifiedExecutionTimelineReportOptions{
		Window:          time.Duration(windowDays) * 24 * time.Hour,
		TenantID:        strings.TrimSpace(r.URL.Query().Get("tenant_id")),
		TargetKind:      strings.TrimSpace(r.URL.Query().Get("target_kind")),
		PlaybookID:      strings.TrimSpace(r.URL.Query().Get("playbook_id")),
		EvaluationRunID: strings.TrimSpace(r.URL.Query().Get("evaluation_run_id")),
		MaxEvents:       maxEvents,
	})
	s.json(w, http.StatusOK, report)
}

func (s *Server) graphIntelligenceEvaluationTemporalAnalysis(w http.ResponseWriter, r *http.Request) {
	g := s.currentGraphIntelligenceGraph(r.Context())
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	evaluationRunID := strings.TrimSpace(r.URL.Query().Get("evaluation_run_id"))
	if evaluationRunID == "" {
		s.error(w, http.StatusBadRequest, "evaluation_run_id is required")
		return
	}
	conversationID := strings.TrimSpace(r.URL.Query().Get("conversation_id"))
	stageID := strings.TrimSpace(r.URL.Query().Get("stage_id"))

	timelineLimit := 25
	if raw := strings.TrimSpace(r.URL.Query().Get("timeline_limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 100 {
			s.error(w, http.StatusBadRequest, "timeline_limit must be between 1 and 100")
			return
		}
		timelineLimit = parsed
	}

	report := reports.BuildEvaluationTemporalAnalysisReport(g, reports.EvaluationTemporalAnalysisReportOptions{
		EvaluationRunID: evaluationRunID,
		ConversationID:  conversationID,
		StageID:         stageID,
		TimelineLimit:   timelineLimit,
	})
	s.json(w, http.StatusOK, report)
}
