package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/graph"
	reports "github.com/writer/cerebro/internal/graph/reports"
)

func (s *Server) graphIntelligenceWeeklyCalibration(w http.ResponseWriter, r *http.Request) {
	g := s.currentGraphIntelligenceGraph(r.Context())
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}
	engine := s.currentTenantRiskEngine(r.Context())
	if engine == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	windowDays := 7
	if raw := strings.TrimSpace(r.URL.Query().Get("window_days")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 30 {
			s.error(w, http.StatusBadRequest, "window_days must be between 1 and 30")
			return
		}
		windowDays = parsed
	}

	trendDays := 14
	if raw := strings.TrimSpace(r.URL.Query().Get("trend_days")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 7 || parsed > 56 {
			s.error(w, http.StatusBadRequest, "trend_days must be between 7 and 56")
			return
		}
		trendDays = parsed
	}

	includeQueue := false
	if raw := strings.TrimSpace(r.URL.Query().Get("include_queue")); raw != "" {
		parsed, err := strconv.ParseBool(raw)
		if err != nil {
			s.error(w, http.StatusBadRequest, "include_queue must be a boolean")
			return
		}
		includeQueue = parsed
	}

	queueLimit := 25
	if raw := strings.TrimSpace(r.URL.Query().Get("queue_limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 200 {
			s.error(w, http.StatusBadRequest, "queue_limit must be between 1 and 200")
			return
		}
		queueLimit = parsed
	}

	profile := strings.TrimSpace(r.URL.Query().Get("profile"))
	report := reports.BuildWeeklyCalibrationReport(g, engine, reports.WeeklyCalibrationReportOptions{
		Now:              time.Now().UTC(),
		WindowDays:       windowDays,
		TrendDays:        trendDays,
		Profile:          profile,
		IncludeQueue:     includeQueue,
		QueueLimit:       queueLimit,
		SuggestThreshold: 0.55,
	})
	report.Temporal = reports.BuildWeeklyCalibrationTemporalSummary(
		report.GeneratedAt,
		windowDays,
		s.platformGraphChangelog(
			r.Context(),
			report.GeneratedAt,
			report.GeneratedAt.Add(-time.Duration(windowDays)*24*time.Hour),
			report.GeneratedAt,
			10,
			graph.GraphDiffFilter{},
		).Entries,
	)
	s.json(w, http.StatusOK, report)
}
