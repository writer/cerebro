package api

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/writer/cerebro/internal/graph"
)

func (s *Server) whoKnows(w http.ResponseWriter, r *http.Request) {
	if s.app.SecurityGraph == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	query := graph.KnowledgeQuery{
		Topic:         strings.TrimSpace(r.URL.Query().Get("topic")),
		Customer:      strings.TrimSpace(r.URL.Query().Get("customer")),
		System:        strings.TrimSpace(r.URL.Query().Get("system")),
		AvailableOnly: parseKnowledgeAvailableFlag(r.URL.Query().Get("available")),
		Limit:         5,
	}
	if query.Topic == "" && query.Customer == "" && query.System == "" {
		s.error(w, http.StatusBadRequest, "one of topic, customer, or system query params is required")
		return
	}

	if rawLimit := strings.TrimSpace(r.URL.Query().Get("limit")); rawLimit != "" {
		if parsed, err := strconv.Atoi(rawLimit); err == nil && parsed > 0 {
			query.Limit = parsed
		}
	}

	result := graph.WhoKnows(s.app.SecurityGraph, query)
	s.json(w, http.StatusOK, result)
}

func parseKnowledgeAvailableFlag(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
