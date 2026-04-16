package api

import (
	"fmt"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/graphingest"
)

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
