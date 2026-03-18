package api

import (
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/graph"
	reports "github.com/writer/cerebro/internal/graph/reports"
	"github.com/writer/cerebro/internal/graphingest"
)

func (s *Server) graphIntelligenceEventPatterns(w http.ResponseWriter, _ *http.Request) {
	s.json(w, http.StatusOK, graph.EventCorrelationPatternCatalogSnapshot(time.Now().UTC()))
}

func (s *Server) currentGraphIntelligenceGraph() *graph.Graph {
	if s == nil || s.graphIntelligence == nil {
		return nil
	}
	return s.graphIntelligence.CurrentGraph()
}

func (s *Server) graphIntelligenceEventCorrelations(w http.ResponseWriter, r *http.Request) {
	g := s.currentGraphIntelligenceGraph()
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	limit := 25
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 200 {
			s.error(w, http.StatusBadRequest, "limit must be between 1 and 200")
			return
		}
		limit = parsed
	}

	var since time.Time
	if raw := strings.TrimSpace(r.URL.Query().Get("since")); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			s.error(w, http.StatusBadRequest, "since must be RFC3339")
			return
		}
		since = parsed
	}

	var until time.Time
	if raw := strings.TrimSpace(r.URL.Query().Get("until")); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			s.error(w, http.StatusBadRequest, "until must be RFC3339")
			return
		}
		until = parsed
	}

	includeAnomalies := false
	if raw := strings.TrimSpace(r.URL.Query().Get("include_anomalies")); raw != "" {
		parsed, err := strconv.ParseBool(raw)
		if err != nil {
			s.error(w, http.StatusBadRequest, "include_anomalies must be a boolean")
			return
		}
		includeAnomalies = parsed
	}

	eventID := strings.TrimSpace(r.URL.Query().Get("event_id"))
	entityID := strings.TrimSpace(r.URL.Query().Get("entity_id"))
	patternID := strings.TrimSpace(r.URL.Query().Get("pattern_id"))
	if eventID == "" && entityID == "" {
		s.error(w, http.StatusBadRequest, "event_id or entity_id is required")
		return
	}

	result := graph.QueryEventCorrelations(g, time.Now().UTC(), graph.EventCorrelationQuery{
		EventID:          eventID,
		EntityID:         entityID,
		PatternID:        patternID,
		Limit:            limit,
		Since:            since,
		Until:            until,
		IncludeAnomalies: includeAnomalies,
	})
	s.json(w, http.StatusOK, result)
}

func (s *Server) graphIntelligenceEventAnomalies(w http.ResponseWriter, r *http.Request) {
	g := s.currentGraphIntelligenceGraph()
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	limit := 25
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 200 {
			s.error(w, http.StatusBadRequest, "limit must be between 1 and 200")
			return
		}
		limit = parsed
	}

	eventID := strings.TrimSpace(r.URL.Query().Get("event_id"))
	entityID := strings.TrimSpace(r.URL.Query().Get("entity_id"))
	patternID := strings.TrimSpace(r.URL.Query().Get("pattern_id"))
	if eventID == "" && entityID == "" {
		s.error(w, http.StatusBadRequest, "event_id or entity_id is required")
		return
	}

	result := graph.QueryEventCorrelations(g, time.Now().UTC(), graph.EventCorrelationQuery{
		EventID:          eventID,
		EntityID:         entityID,
		PatternID:        patternID,
		Limit:            limit,
		IncludeAnomalies: true,
	})
	s.json(w, http.StatusOK, map[string]any{
		"generated_at": result.GeneratedAt,
		"query":        result.Query,
		"summary": map[string]any{
			"anomaly_count": result.Summary.AnomalyCount,
		},
		"anomalies": result.Anomalies,
	})
}

func (s *Server) graphIntelligenceInsights(w http.ResponseWriter, r *http.Request) {
	g := s.currentGraphIntelligenceGraph()
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	engine := s.graphRiskEngine()
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

		snapshotPath := strings.TrimSpace(os.Getenv("GRAPH_SNAPSHOT_PATH"))
		if snapshotPath == "" {
			snapshotPath = filepath.Join(".cerebro", "graph-snapshots")
		}
		store := graph.NewSnapshotStore(snapshotPath, 10)
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
	g := s.currentGraphIntelligenceGraph()
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
	g := s.currentGraphIntelligenceGraph()
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

func (s *Server) graphIntelligenceClaimConflicts(w http.ResponseWriter, r *http.Request) {
	g := s.currentGraphIntelligenceGraph()
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

	report := graph.BuildClaimConflictReport(g, graph.ClaimConflictReportOptions{
		ValidAt:         validAt,
		RecordedAt:      recordedAt,
		MaxConflicts:    maxConflicts,
		IncludeResolved: includeResolved,
		StaleAfter:      staleAfter,
	})
	s.json(w, http.StatusOK, report)
}

func (s *Server) graphIntelligenceEntitySummary(w http.ResponseWriter, r *http.Request) {
	g := s.currentGraphIntelligenceGraph()
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

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

func (s *Server) graphIntelligenceLeverage(w http.ResponseWriter, r *http.Request) {
	g := s.currentGraphIntelligenceGraph()
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

func (s *Server) graphIngestHealth(w http.ResponseWriter, r *http.Request) {
	tailLimit := 25
	if raw := strings.TrimSpace(r.URL.Query().Get("tail_limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 500 {
			s.error(w, http.StatusBadRequest, "tail_limit must be between 1 and 500")
			return
		}
		tailLimit = parsed
	}

	validationMode := string(graphingest.MapperValidationEnforce)
	deadLetterPath := ""
	if s.graphIntelligence != nil {
		validationMode = s.graphIntelligence.MapperValidationMode()
		deadLetterPath = s.graphIntelligence.MapperDeadLetterPath()
	}

	stats := graphingest.MapperStats{}
	initialized := false
	if s.graphIntelligence != nil {
		initialized = s.graphIntelligence.MapperInitialized()
		stats = s.graphIntelligence.MapperStats()
	}

	deadLetter := graphingest.DeadLetterTailMetrics{
		Path:      deadLetterPath,
		TailLimit: tailLimit,
	}
	deadLetterError := ""
	if deadLetterPath != "" {
		inspected, err := graphingest.InspectDeadLetter(deadLetterPath, tailLimit)
		if err != nil {
			deadLetterError = err.Error()
		} else {
			deadLetter = inspected
		}
	}

	response := map[string]any{
		"checked_at": time.Now().UTC(),
		"mapper": map[string]any{
			"initialized":      initialized,
			"validation_mode":  validationMode,
			"dead_letter_path": deadLetterPath,
			"stats":            stats,
			"source_slo":       buildMapperSourceSLO(stats),
		},
		"dead_letter": deadLetter,
	}
	if deadLetterError != "" {
		response["dead_letter_error"] = deadLetterError
	}
	s.json(w, http.StatusOK, response)
}

func (s *Server) graphIngestDeadLetter(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 500 {
			s.error(w, http.StatusBadRequest, "limit must be between 1 and 500")
			return
		}
		limit = parsed
	}

	offset := 0
	if raw := strings.TrimSpace(r.URL.Query().Get("offset")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			s.error(w, http.StatusBadRequest, "offset must be >= 0")
			return
		}
		offset = parsed
	}

	deadLetterPath := ""
	if s.graphIntelligence != nil {
		deadLetterPath = s.graphIntelligence.MapperDeadLetterPath()
	}
	if deadLetterPath == "" {
		s.error(w, http.StatusServiceUnavailable, "graph event mapper dead-letter path is not configured")
		return
	}

	result, err := graphingest.QueryDeadLetter(deadLetterPath, graphingest.DeadLetterQueryOptions{
		Limit:       limit,
		Offset:      offset,
		EventType:   strings.TrimSpace(r.URL.Query().Get("event_type")),
		MappingName: strings.TrimSpace(r.URL.Query().Get("mapping_name")),
		IssueCode:   strings.TrimSpace(r.URL.Query().Get("issue_code")),
		EntityType:  strings.TrimSpace(r.URL.Query().Get("entity_type")),
		EntityKind:  strings.TrimSpace(r.URL.Query().Get("entity_kind")),
	})
	if err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.json(w, http.StatusOK, map[string]any{
		"checked_at": time.Now().UTC(),
		"path":       deadLetterPath,
		"filters": map[string]any{
			"limit":        limit,
			"offset":       offset,
			"event_type":   strings.TrimSpace(r.URL.Query().Get("event_type")),
			"mapping_name": strings.TrimSpace(r.URL.Query().Get("mapping_name")),
			"issue_code":   strings.TrimSpace(r.URL.Query().Get("issue_code")),
			"entity_type":  strings.TrimSpace(r.URL.Query().Get("entity_type")),
			"entity_kind":  strings.TrimSpace(r.URL.Query().Get("entity_kind")),
		},
		"result": result,
	})
}

func (s *Server) graphIngestContracts(w http.ResponseWriter, _ *http.Request) {
	now := time.Now().UTC()
	if s.graphIntelligence != nil {
		if catalog, ok := s.graphIntelligence.MapperContractCatalog(now); ok {
			s.json(w, http.StatusOK, map[string]any{
				"generated_at": now,
				"source":       "runtime_mapper",
				"catalog":      catalog,
			})
			return
		}
	}

	config, err := graphingest.LoadDefaultConfig()
	if err != nil {
		s.error(w, http.StatusInternalServerError, fmt.Sprintf("load default graph mapping config: %v", err))
		return
	}
	catalog := graphingest.BuildContractCatalog(config, now)
	s.json(w, http.StatusOK, map[string]any{
		"generated_at": now,
		"source":       "default_config",
		"catalog":      catalog,
	})
}

func (s *Server) graphIntelligenceWeeklyCalibration(w http.ResponseWriter, r *http.Request) {
	g := s.currentGraphIntelligenceGraph()
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}
	engine := s.graphRiskEngine()
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
	s.json(w, http.StatusOK, report)
}

type mapperSourceSLO struct {
	SourceSystem      string    `json:"source_system"`
	EventsProcessed   int64     `json:"events_processed"`
	MatchRatePercent  float64   `json:"match_rate_percent"`
	RejectRatePercent float64   `json:"reject_rate_percent"`
	DeadLetterPercent float64   `json:"dead_letter_percent"`
	LastEventAt       time.Time `json:"last_event_at,omitempty"`
	Status            string    `json:"status"`
}

func buildMapperSourceSLO(stats graphingest.MapperStats) []mapperSourceSLO {
	if len(stats.SourceStats) == 0 {
		return nil
	}
	out := make([]mapperSourceSLO, 0, len(stats.SourceStats))
	for source, sourceStats := range stats.SourceStats {
		processed := maxInt64(0, sourceStats.EventsProcessed)
		matched := maxInt64(0, sourceStats.EventsMatched)
		rejectedWrites := sourceStats.NodesRejected + sourceStats.EdgesRejected
		totalWrites := sourceStats.NodesUpserted + sourceStats.EdgesUpserted + rejectedWrites

		matchRate := percentInt64(matched, processed)
		rejectRate := percentInt64(rejectedWrites, totalWrites)
		deadLetterRate := percentInt64(sourceStats.DeadLettered, processed)
		status := "healthy"
		switch {
		case processed == 0:
			status = "unknown"
		case matchRate < 80 || rejectRate > 10 || deadLetterRate > 5:
			status = "unhealthy"
		case matchRate < 95 || rejectRate > 3 || deadLetterRate > 1:
			status = "degraded"
		}

		out = append(out, mapperSourceSLO{
			SourceSystem:      source,
			EventsProcessed:   processed,
			MatchRatePercent:  round1(matchRate),
			RejectRatePercent: round1(rejectRate),
			DeadLetterPercent: round1(deadLetterRate),
			LastEventAt:       sourceStats.LastEventAt.UTC(),
			Status:            status,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].EventsProcessed == out[j].EventsProcessed {
			return out[i].SourceSystem < out[j].SourceSystem
		}
		return out[i].EventsProcessed > out[j].EventsProcessed
	})
	return out
}

func percentInt64(numerator, denominator int64) float64 {
	if denominator <= 0 {
		return 0
	}
	return (float64(numerator) / float64(denominator)) * 100
}

func round1(value float64) float64 {
	return math.Round(value*10) / 10
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func (s *Server) graphQueryTemplates(w http.ResponseWriter, _ *http.Request) {
	templates := graph.DefaultGraphQueryTemplates()
	s.json(w, http.StatusOK, map[string]any{
		"templates": templates,
		"count":     len(templates),
	})
}

type graphQueryNeighborResult struct {
	Direction string      `json:"direction"`
	Edge      *graph.Edge `json:"edge"`
	Node      *graph.Node `json:"node,omitempty"`
}

func (s *Server) graphQuery(w http.ResponseWriter, r *http.Request) {
	g := s.currentGraphIntelligenceGraph()
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}
	queryGraph := g

	var asOf time.Time
	asOfRaw := strings.TrimSpace(r.URL.Query().Get("as_of"))
	if asOfRaw != "" {
		parsed, err := time.Parse(time.RFC3339, asOfRaw)
		if err != nil {
			s.error(w, http.StatusBadRequest, "as_of must be RFC3339")
			return
		}
		asOf = parsed.UTC()
		queryGraph = g.SubgraphAt(asOf)
	}

	var from time.Time
	var to time.Time
	fromRaw := strings.TrimSpace(r.URL.Query().Get("from"))
	toRaw := strings.TrimSpace(r.URL.Query().Get("to"))
	if fromRaw != "" || toRaw != "" {
		if fromRaw == "" || toRaw == "" {
			s.error(w, http.StatusBadRequest, "both from and to query parameters are required (RFC3339)")
			return
		}
		parsedFrom, err := time.Parse(time.RFC3339, fromRaw)
		if err != nil {
			s.error(w, http.StatusBadRequest, "from must be RFC3339")
			return
		}
		parsedTo, err := time.Parse(time.RFC3339, toRaw)
		if err != nil {
			s.error(w, http.StatusBadRequest, "to must be RFC3339")
			return
		}
		from = parsedFrom.UTC()
		to = parsedTo.UTC()
		queryGraph = g.SubgraphBetween(from, to)
	}

	mode := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("mode")))
	if mode == "" {
		mode = "neighbors"
	}

	nodeID := strings.TrimSpace(r.URL.Query().Get("node_id"))
	if nodeID == "" {
		s.error(w, http.StatusBadRequest, "node_id is required")
		return
	}
	if _, ok := queryGraph.GetNode(nodeID); !ok {
		s.error(w, http.StatusNotFound, fmt.Sprintf("node not found in selected scope: %s", nodeID))
		return
	}

	temporalScope := map[string]any{}
	if !asOf.IsZero() {
		temporalScope["as_of"] = asOf
	}
	if !from.IsZero() || !to.IsZero() {
		temporalScope["from"] = from
		temporalScope["to"] = to
	}

	switch mode {
	case "neighbors":
		s.graphQueryNeighbors(w, r, queryGraph, nodeID, temporalScope)
	case "paths", "path":
		s.graphQueryPaths(w, r, queryGraph, nodeID, temporalScope)
	default:
		s.error(w, http.StatusBadRequest, "mode must be one of neighbors, paths")
	}
}

func (s *Server) graphQueryNeighbors(w http.ResponseWriter, r *http.Request, g *graph.Graph, nodeID string, temporalScope map[string]any) {
	direction := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("direction")))
	if direction == "" {
		direction = "both"
	}
	if direction != "out" && direction != "in" && direction != "both" {
		s.error(w, http.StatusBadRequest, "direction must be one of out, in, both")
		return
	}

	limit := 25
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 200 {
			s.error(w, http.StatusBadRequest, "limit must be between 1 and 200")
			return
		}
		limit = parsed
	}

	results := make([]graphQueryNeighborResult, 0)
	edgesScanned := 0
	if direction == "out" || direction == "both" {
		for _, edge := range g.GetOutEdges(nodeID) {
			edgesScanned++
			targetNode, _ := g.GetNode(edge.Target)
			results = append(results, graphQueryNeighborResult{Direction: "out", Edge: edge, Node: targetNode})
		}
	}
	if direction == "in" || direction == "both" {
		for _, edge := range g.GetInEdges(nodeID) {
			edgesScanned++
			sourceNode, _ := g.GetNode(edge.Source)
			results = append(results, graphQueryNeighborResult{Direction: "in", Edge: edge, Node: sourceNode})
		}
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].Direction == results[j].Direction {
			if results[i].Edge.Source == results[j].Edge.Source {
				if results[i].Edge.Target == results[j].Edge.Target {
					return string(results[i].Edge.Kind) < string(results[j].Edge.Kind)
				}
				return results[i].Edge.Target < results[j].Edge.Target
			}
			return results[i].Edge.Source < results[j].Edge.Source
		}
		return results[i].Direction < results[j].Direction
	})

	total := len(results)
	if len(results) > limit {
		results = results[:limit]
	}

	s.json(w, http.StatusOK, map[string]any{
		"mode":      "neighbors",
		"node_id":   nodeID,
		"direction": direction,
		"temporal":  temporalScope,
		"total":     total,
		"count":     len(results),
		"limit":     limit,
		"truncated": total > len(results),
		"neighbors": results,
		"explain": map[string]any{
			"edge_scan_count": edgesScanned,
			"guardrails":      []string{"limit<=200", "mode=neighbors", "direction in|out|both", "as_of RFC3339", "from/to RFC3339"},
		},
	})
}

func (s *Server) graphQueryPaths(w http.ResponseWriter, r *http.Request, g *graph.Graph, nodeID string, temporalScope map[string]any) {
	targetID := strings.TrimSpace(r.URL.Query().Get("target_id"))
	if targetID == "" {
		s.error(w, http.StatusBadRequest, "target_id is required for paths mode")
		return
	}
	if _, ok := g.GetNode(targetID); !ok {
		s.error(w, http.StatusNotFound, fmt.Sprintf("target node not found: %s", targetID))
		return
	}

	k := 3
	if raw := strings.TrimSpace(r.URL.Query().Get("k")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 10 {
			s.error(w, http.StatusBadRequest, "k must be between 1 and 10")
			return
		}
		k = parsed
	}

	maxDepth := 6
	if raw := strings.TrimSpace(r.URL.Query().Get("max_depth")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 12 {
			s.error(w, http.StatusBadRequest, "max_depth must be between 1 and 12")
			return
		}
		maxDepth = parsed
	}

	simulator := graph.NewAttackPathSimulator(g)
	paths := simulator.KShortestPaths(nodeID, targetID, k, maxDepth)
	pathsExamined := 0
	for _, path := range paths {
		if path == nil {
			continue
		}
		pathsExamined += len(path.Steps)
	}

	s.json(w, http.StatusOK, map[string]any{
		"mode":      "paths",
		"source_id": nodeID,
		"target_id": targetID,
		"temporal":  temporalScope,
		"k":         k,
		"max_depth": maxDepth,
		"count":     len(paths),
		"paths":     paths,
		"explain": map[string]any{
			"path_step_count": pathsExamined,
			"guardrails":      []string{"k<=10", "max_depth<=12", "mode=paths", "as_of RFC3339", "from/to RFC3339"},
		},
	})
}
