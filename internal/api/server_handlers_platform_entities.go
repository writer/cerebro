package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"

	"github.com/evalops/cerebro/internal/graph"
)

const maxPlatformEntityQueryLength = 512

func platformEntityQueryLengthExceeds(value string) bool {
	return utf8.RuneCountInString(value) > maxPlatformEntityQueryLength
}

func (s *Server) listPlatformEntities(w http.ResponseWriter, r *http.Request) {
	g := s.app.CurrentSecurityGraph()
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	opts, err := parsePlatformEntityQueryOptions(r)
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}

	s.json(w, http.StatusOK, graph.QueryEntities(g, opts))
}

func (s *Server) searchPlatformEntities(w http.ResponseWriter, r *http.Request) {
	g := s.app.CurrentSecurityGraph()
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	opts, err := parsePlatformEntitySearchOptions(r)
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}
	s.json(w, http.StatusOK, graph.SearchEntities(g, opts))
}

func (s *Server) suggestPlatformEntities(w http.ResponseWriter, r *http.Request) {
	g := s.app.CurrentSecurityGraph()
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	opts, err := parsePlatformEntitySuggestOptions(r)
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}
	s.json(w, http.StatusOK, graph.SuggestEntities(g, opts))
}

func (s *Server) listPlatformEntityFacets(w http.ResponseWriter, r *http.Request) {
	s.json(w, http.StatusOK, graph.BuildEntityFacetContractCatalog(time.Now().UTC()))
}

func (s *Server) getPlatformEntityFacet(w http.ResponseWriter, r *http.Request) {
	facetID := strings.TrimSpace(chi.URLParam(r, "facet_id"))
	if facetID == "" {
		s.error(w, http.StatusBadRequest, "facet id required")
		return
	}
	facet, ok := graph.GetEntityFacetDefinition(facetID)
	if !ok {
		s.error(w, http.StatusNotFound, "facet not found")
		return
	}
	s.json(w, http.StatusOK, facet)
}

func (s *Server) getPlatformEntity(w http.ResponseWriter, r *http.Request) {
	g := s.app.CurrentSecurityGraph()
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	entityID := strings.TrimSpace(chi.URLParam(r, "entity_id"))
	if entityID == "" {
		s.error(w, http.StatusBadRequest, "entity id required")
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

	record, ok := graph.GetEntityRecord(g, entityID, validAt, recordedAt)
	if !ok {
		s.error(w, http.StatusNotFound, "entity not found")
		return
	}
	s.json(w, http.StatusOK, record)
}

func (s *Server) getPlatformEntityAtTime(w http.ResponseWriter, r *http.Request) {
	g := s.app.CurrentSecurityGraph()
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	entityID := strings.TrimSpace(chi.URLParam(r, "entity_id"))
	if entityID == "" {
		s.error(w, http.StatusBadRequest, "entity id required")
		return
	}
	timestamp, err := parseRequiredRFC3339Query(r, "timestamp")
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}
	recordedAt, err := parseOptionalRFC3339Query(r, "recorded_at")
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}

	record, ok := graph.GetEntityRecordAtTime(g, entityID, timestamp, recordedAt)
	if !ok {
		s.error(w, http.StatusNotFound, "entity not found")
		return
	}
	s.json(w, http.StatusOK, record)
}

func (s *Server) getPlatformEntityTimeDiff(w http.ResponseWriter, r *http.Request) {
	g := s.app.CurrentSecurityGraph()
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	entityID := strings.TrimSpace(chi.URLParam(r, "entity_id"))
	if entityID == "" {
		s.error(w, http.StatusBadRequest, "entity id required")
		return
	}
	from, err := parseRequiredRFC3339Query(r, "from")
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}
	to, err := parseRequiredRFC3339Query(r, "to")
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}
	recordedAt, err := parseOptionalRFC3339Query(r, "recorded_at")
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}

	record, ok := graph.GetEntityTimeDiff(g, entityID, from, to, recordedAt)
	if !ok {
		s.error(w, http.StatusNotFound, "entity not found")
		return
	}
	s.json(w, http.StatusOK, record)
}

func parsePlatformEntityQueryOptions(r *http.Request) (graph.EntityQueryOptions, error) {
	query := r.URL.Query()
	opts := graph.EntityQueryOptions{
		ID:           strings.TrimSpace(query.Get("id")),
		Kinds:        parseNodeKindsCSV(query.Get("kind")),
		Categories:   parseNodeCategoriesCSV(query.Get("category")),
		Capabilities: parseNodeCapabilitiesCSV(query.Get("capability")),
		Provider:     strings.TrimSpace(query.Get("provider")),
		Account:      strings.TrimSpace(query.Get("account")),
		Region:       strings.TrimSpace(query.Get("region")),
		Search:       strings.TrimSpace(query.Get("q")),
		TagKey:       strings.TrimSpace(query.Get("tag_key")),
		TagValue:     strings.TrimSpace(query.Get("tag_value")),
	}
	if platformEntityQueryLengthExceeds(opts.Search) {
		return graph.EntityQueryOptions{}, fmt.Errorf("q exceeds max length %d", maxPlatformEntityQueryLength)
	}
	if risk := strings.ToLower(strings.TrimSpace(query.Get("risk"))); risk != "" {
		switch graph.RiskLevel(risk) {
		case graph.RiskCritical, graph.RiskHigh, graph.RiskMedium, graph.RiskLow, graph.RiskNone:
			opts.Risk = graph.RiskLevel(risk)
		default:
			return graph.EntityQueryOptions{}, fmt.Errorf("invalid risk %q", risk)
		}
	}
	if hasFindings, ok, err := parseOptionalBoolQuery(r, "has_findings"); err != nil {
		return graph.EntityQueryOptions{}, err
	} else if ok {
		opts.HasFindings = &hasFindings
	}
	if validAt, err := parseOptionalRFC3339Query(r, "valid_at"); err != nil {
		return graph.EntityQueryOptions{}, err
	} else {
		opts.ValidAt = validAt
	}
	if recordedAt, err := parseOptionalRFC3339Query(r, "recorded_at"); err != nil {
		return graph.EntityQueryOptions{}, err
	} else {
		opts.RecordedAt = recordedAt
	}
	if raw := strings.TrimSpace(query.Get("limit")); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil {
			return graph.EntityQueryOptions{}, fmt.Errorf("invalid limit %q", raw)
		}
		opts.Limit = limit
	}
	if raw := strings.TrimSpace(query.Get("offset")); raw != "" {
		offset, err := strconv.Atoi(raw)
		if err != nil {
			return graph.EntityQueryOptions{}, fmt.Errorf("invalid offset %q", raw)
		}
		opts.Offset = offset
	}
	return opts, nil
}

func parsePlatformEntitySearchOptions(r *http.Request) (graph.EntitySearchOptions, error) {
	query := r.URL.Query()
	opts := graph.EntitySearchOptions{
		Query: strings.TrimSpace(query.Get("q")),
		Kinds: parseNodeKindsCSV(query.Get("kind")),
	}
	if opts.Query == "" {
		return graph.EntitySearchOptions{}, fmt.Errorf("q is required")
	}
	if platformEntityQueryLengthExceeds(opts.Query) {
		return graph.EntitySearchOptions{}, fmt.Errorf("q exceeds max length %d", maxPlatformEntityQueryLength)
	}
	if fuzzy, ok, err := parseOptionalBoolQuery(r, "fuzzy"); err != nil {
		return graph.EntitySearchOptions{}, err
	} else if ok {
		opts.Fuzzy = fuzzy
	}
	if raw := strings.TrimSpace(query.Get("limit")); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil {
			return graph.EntitySearchOptions{}, fmt.Errorf("invalid limit %q", raw)
		}
		opts.Limit = limit
	}
	return opts, nil
}

func parsePlatformEntitySuggestOptions(r *http.Request) (graph.EntitySuggestOptions, error) {
	query := r.URL.Query()
	opts := graph.EntitySuggestOptions{
		Prefix: strings.TrimSpace(query.Get("prefix")),
		Kinds:  parseNodeKindsCSV(query.Get("kind")),
	}
	if opts.Prefix == "" {
		return graph.EntitySuggestOptions{}, fmt.Errorf("prefix is required")
	}
	if platformEntityQueryLengthExceeds(opts.Prefix) {
		return graph.EntitySuggestOptions{}, fmt.Errorf("prefix exceeds max length %d", maxPlatformEntityQueryLength)
	}
	if raw := strings.TrimSpace(query.Get("limit")); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil {
			return graph.EntitySuggestOptions{}, fmt.Errorf("invalid limit %q", raw)
		}
		opts.Limit = limit
	}
	return opts, nil
}

func parseNodeKindsCSV(raw string) []graph.NodeKind {
	parts := splitCSV(raw)
	out := make([]graph.NodeKind, 0, len(parts))
	for _, part := range parts {
		out = append(out, graph.NodeKind(strings.ToLower(part)))
	}
	return out
}

func parseNodeCategoriesCSV(raw string) []graph.NodeKindCategory {
	parts := splitCSV(raw)
	out := make([]graph.NodeKindCategory, 0, len(parts))
	for _, part := range parts {
		out = append(out, graph.NodeKindCategory(strings.ToLower(part)))
	}
	return out
}

func parseNodeCapabilitiesCSV(raw string) []graph.NodeKindCapability {
	parts := splitCSV(raw)
	out := make([]graph.NodeKindCapability, 0, len(parts))
	for _, part := range parts {
		out = append(out, graph.NodeKindCapability(strings.ToLower(part)))
	}
	return out
}

func splitCSV(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return out
}

func parseRequiredRFC3339Query(r *http.Request, key string) (time.Time, error) {
	if strings.TrimSpace(r.URL.Query().Get(key)) == "" {
		return time.Time{}, errBadRequest(key + " is required")
	}
	parsed, err := parseOptionalRFC3339Query(r, key)
	if err != nil {
		return time.Time{}, err
	}
	if parsed.IsZero() {
		return time.Time{}, errBadRequest(key + " must be RFC3339")
	}
	return parsed, nil
}
