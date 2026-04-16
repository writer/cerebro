package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/graph"
)

func (s *Server) graphIntelligenceEventPatterns(w http.ResponseWriter, _ *http.Request) {
	s.json(w, http.StatusOK, graph.EventCorrelationPatternCatalogSnapshot(time.Now().UTC()))
}

func (s *Server) graphIntelligenceEventCorrelations(w http.ResponseWriter, r *http.Request) {
	g := s.currentGraphIntelligenceGraph(r.Context())
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
	if eventID != "" {
		if _, ok := g.GetNode(eventID); !ok {
			s.error(w, http.StatusNotFound, "event not found in selected scope")
			return
		}
	}
	if entityID != "" {
		if _, ok := g.GetNode(entityID); !ok {
			s.error(w, http.StatusNotFound, "entity not found in selected scope")
			return
		}
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

func (s *Server) graphIntelligenceEventChains(w http.ResponseWriter, r *http.Request) {
	g := s.currentGraphIntelligenceGraph(r.Context())
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

	maxDepth := 4
	if raw := strings.TrimSpace(r.URL.Query().Get("max_depth")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 6 {
			s.error(w, http.StatusBadRequest, "max_depth must be between 1 and 6")
			return
		}
		maxDepth = parsed
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

	direction := "both"
	if raw := strings.TrimSpace(r.URL.Query().Get("direction")); raw != "" {
		switch raw {
		case "upstream", "downstream", "both":
			direction = raw
		default:
			s.error(w, http.StatusBadRequest, "direction must be one of upstream, downstream, or both")
			return
		}
	}

	eventID := strings.TrimSpace(r.URL.Query().Get("event_id"))
	entityID := strings.TrimSpace(r.URL.Query().Get("entity_id"))
	patternID := strings.TrimSpace(r.URL.Query().Get("pattern_id"))
	if eventID == "" && entityID == "" {
		s.error(w, http.StatusBadRequest, "event_id or entity_id is required")
		return
	}
	if eventID != "" {
		if _, ok := g.GetNode(eventID); !ok {
			s.error(w, http.StatusNotFound, "event not found in selected scope")
			return
		}
	}
	if entityID != "" {
		if _, ok := g.GetNode(entityID); !ok {
			s.error(w, http.StatusNotFound, "entity not found in selected scope")
			return
		}
	}

	result := graph.QueryEventCorrelationChains(g, time.Now().UTC(), graph.EventCorrelationChainQuery{
		EventID:   eventID,
		EntityID:  entityID,
		PatternID: patternID,
		Direction: direction,
		Limit:     limit,
		MaxDepth:  maxDepth,
		Since:     since,
		Until:     until,
	})
	s.json(w, http.StatusOK, result)
}

func (s *Server) graphIntelligenceEventAnomalies(w http.ResponseWriter, r *http.Request) {
	g := s.currentGraphIntelligenceGraph(r.Context())
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
