package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/graph"
	reports "github.com/writer/cerebro/internal/graph/reports"
)

func (s *Server) graphIntelligenceInsights(w http.ResponseWriter, r *http.Request) {
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

	historyLimit := 20
	if raw := strings.TrimSpace(r.URL.Query().Get("history_limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 200 {
			s.error(w, http.StatusBadRequest, "history_limit must be between 1 and 200")
			return
		}
		historyLimit = parsed
	}

	var sinceVersion int64
	if raw := strings.TrimSpace(r.URL.Query().Get("since_version")); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || parsed < 1 {
			s.error(w, http.StatusBadRequest, "since_version must be a positive integer")
			return
		}
		sinceVersion = parsed
	}

	windowDays := 90
	if raw := strings.TrimSpace(r.URL.Query().Get("window_days")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 3650 {
			s.error(w, http.StatusBadRequest, "window_days must be between 1 and 3650")
			return
		}
		windowDays = parsed
	}

	maxInsights := 8
	if raw := strings.TrimSpace(r.URL.Query().Get("max_insights")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 20 {
			s.error(w, http.StatusBadRequest, "max_insights must be between 1 and 20")
			return
		}
		maxInsights = parsed
	}

	includeCounterfactual := true
	if raw := strings.TrimSpace(r.URL.Query().Get("include_counterfactual")); raw != "" {
		parsed, err := strconv.ParseBool(raw)
		if err != nil {
			s.error(w, http.StatusBadRequest, "include_counterfactual must be a boolean")
			return
		}
		includeCounterfactual = parsed
	}

	var temporalDiff *graph.GraphDiff
	fromRaw := strings.TrimSpace(r.URL.Query().Get("from"))
	toRaw := strings.TrimSpace(r.URL.Query().Get("to"))
	if fromRaw != "" || toRaw != "" {
		if fromRaw == "" || toRaw == "" {
			s.error(w, http.StatusBadRequest, "both from and to query parameters are required (RFC3339)")
			return
		}

		from, err := time.Parse(time.RFC3339, fromRaw)
		if err != nil {
			s.error(w, http.StatusBadRequest, "invalid from timestamp, must be RFC3339")
			return
		}
		to, err := time.Parse(time.RFC3339, toRaw)
		if err != nil {
			s.error(w, http.StatusBadRequest, "invalid to timestamp, must be RFC3339")
			return
		}

		store := s.platformGraphSnapshotStore()
		if store == nil {
			s.error(w, http.StatusNotFound, "graph snapshot store not configured")
			return
		}
		diff, err := store.DiffByTime(from, to)
		if err != nil {
			status := http.StatusInternalServerError
			if strings.Contains(err.Error(), "no snapshots") {
				status = http.StatusNotFound
			}
			s.error(w, status, err.Error())
			return
		}
		temporalDiff = diff
	}

	report := reports.BuildIntelligenceReport(g, engine, reports.IntelligenceReportOptions{
		EntityID:              strings.TrimSpace(r.URL.Query().Get("entity_id")),
		OutcomeWindow:         time.Duration(windowDays) * 24 * time.Hour,
		SchemaHistoryLimit:    historyLimit,
		SchemaSinceVersion:    sinceVersion,
		MaxInsights:           maxInsights,
		IncludeCounterfactual: includeCounterfactual,
		TemporalDiff:          temporalDiff,
	})
	s.json(w, http.StatusOK, report)
}

func (s *Server) graphIntelligenceQuality(w http.ResponseWriter, r *http.Request) {
	g := s.currentGraphIntelligenceGraph(r.Context())
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	historyLimit := 20
	if raw := strings.TrimSpace(r.URL.Query().Get("history_limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 200 {
			s.error(w, http.StatusBadRequest, "history_limit must be between 1 and 200")
			return
		}
		historyLimit = parsed
	}

	var sinceVersion int64
	if raw := strings.TrimSpace(r.URL.Query().Get("since_version")); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || parsed < 1 {
			s.error(w, http.StatusBadRequest, "since_version must be a positive integer")
			return
		}
		sinceVersion = parsed
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

	report := reports.BuildGraphQualityReport(g, reports.GraphQualityReportOptions{
		FreshnessStaleAfter: staleAfter,
		SchemaHistoryLimit:  historyLimit,
		SchemaSinceVersion:  sinceVersion,
	})
	s.json(w, http.StatusOK, report)
}

func (s *Server) graphIntelligenceMetadataQuality(w http.ResponseWriter, r *http.Request) {
	g := s.currentGraphIntelligenceGraph(r.Context())
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	topKinds := 25
	if raw := strings.TrimSpace(r.URL.Query().Get("top_kinds")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 200 {
			s.error(w, http.StatusBadRequest, "top_kinds must be between 1 and 200")
			return
		}
		topKinds = parsed
	}

	report := reports.BuildGraphMetadataQualityReport(g, reports.GraphMetadataQualityReportOptions{
		TopKinds: topKinds,
	})
	s.json(w, http.StatusOK, report)
}

func (s *Server) graphIntelligenceAIWorkloads(w http.ResponseWriter, r *http.Request) {
	g := s.currentGraphIntelligenceGraph(r.Context())
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	maxWorkloads := 50
	if raw := strings.TrimSpace(r.URL.Query().Get("max_workloads")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 200 {
			s.error(w, http.StatusBadRequest, "max_workloads must be between 1 and 200")
			return
		}
		maxWorkloads = parsed
	}

	minRiskScore := 0
	if raw := strings.TrimSpace(r.URL.Query().Get("min_risk_score")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 || parsed > 100 {
			s.error(w, http.StatusBadRequest, "min_risk_score must be between 0 and 100")
			return
		}
		minRiskScore = parsed
	}

	includeShadow := true
	if raw := strings.TrimSpace(r.URL.Query().Get("include_shadow")); raw != "" {
		parsed, err := strconv.ParseBool(raw)
		if err != nil {
			s.error(w, http.StatusBadRequest, "include_shadow must be a boolean")
			return
		}
		includeShadow = parsed
	}

	report := reports.BuildAIWorkloadInventoryReport(g, reports.AIWorkloadInventoryReportOptions{
		MaxWorkloads:  maxWorkloads,
		MinRiskScore:  minRiskScore,
		IncludeShadow: includeShadow,
	})
	s.json(w, http.StatusOK, report)
}

func (s *Server) graphIntelligenceLeverage(w http.ResponseWriter, r *http.Request) {
	g := s.currentGraphIntelligenceGraph(r.Context())
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	historyLimit := 20
	if raw := strings.TrimSpace(r.URL.Query().Get("history_limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 200 {
			s.error(w, http.StatusBadRequest, "history_limit must be between 1 and 200")
			return
		}
		historyLimit = parsed
	}

	var sinceVersion int64
	if raw := strings.TrimSpace(r.URL.Query().Get("since_version")); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || parsed < 1 {
			s.error(w, http.StatusBadRequest, "since_version must be a positive integer")
			return
		}
		sinceVersion = parsed
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

	var recentWindow time.Duration
	if raw := strings.TrimSpace(r.URL.Query().Get("recent_window_hours")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 168 {
			s.error(w, http.StatusBadRequest, "recent_window_hours must be between 1 and 168")
			return
		}
		recentWindow = time.Duration(parsed) * time.Hour
	}

	var decisionSLA time.Duration
	if raw := strings.TrimSpace(r.URL.Query().Get("decision_sla_days")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 365 {
			s.error(w, http.StatusBadRequest, "decision_sla_days must be between 1 and 365")
			return
		}
		decisionSLA = time.Duration(parsed) * 24 * time.Hour
	}

	identitySuggestThreshold := 0.55
	if raw := strings.TrimSpace(r.URL.Query().Get("identity_suggest_threshold")); raw != "" {
		parsed, err := strconv.ParseFloat(raw, 64)
		if err != nil || parsed < 0 || parsed > 1 {
			s.error(w, http.StatusBadRequest, "identity_suggest_threshold must be between 0 and 1")
			return
		}
		identitySuggestThreshold = parsed
	}

	queueLimit := 25
	if raw := strings.TrimSpace(r.URL.Query().Get("identity_queue_limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 200 {
			s.error(w, http.StatusBadRequest, "identity_queue_limit must be between 1 and 200")
			return
		}
		queueLimit = parsed
	}

	report := reports.BuildGraphLeverageReport(g, reports.GraphLeverageReportOptions{
		FreshnessStaleAfter:      staleAfter,
		SchemaHistoryLimit:       historyLimit,
		SchemaSinceVersion:       sinceVersion,
		IdentitySuggestThreshold: identitySuggestThreshold,
		IdentityQueueLimit:       queueLimit,
		RecentWindow:             recentWindow,
		DecisionStaleAfter:       decisionSLA,
	})
	s.json(w, http.StatusOK, report)
}
