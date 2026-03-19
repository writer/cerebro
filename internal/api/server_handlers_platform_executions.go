package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/evalops/cerebro/internal/executions"
)

type platformExecutionCollection struct {
	Count      int                  `json:"count"`
	Executions []executions.Summary `json:"executions"`
}

func (s *Server) listPlatformExecutions(w http.ResponseWriter, r *http.Request) {
	if s == nil || s.platformExecutions == nil {
		s.error(w, http.StatusInternalServerError, "platform execution store not configured")
		return
	}
	limit := 50
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 200 {
			s.error(w, http.StatusBadRequest, "limit must be between 1 and 200")
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
	orderBySubmittedAt := strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("order")), "submitted")
	opts := executions.ListOptions{
		Namespaces:         queryCSVValues(r, "namespace"),
		Statuses:           queryCSVValues(r, "status"),
		ExcludeStatuses:    queryCSVValues(r, "exclude_status"),
		ReportID:           strings.TrimSpace(r.URL.Query().Get("report_id")),
		Limit:              limit,
		Offset:             offset,
		OrderBySubmittedAt: orderBySubmittedAt,
	}
	summaries, err := s.platformExecutions.ListExecutions(r.Context(), opts)
	if err != nil {
		switch {
		case errors.Is(err, errPlatformExecutionStoreNotConfigured):
			s.error(w, http.StatusInternalServerError, "platform execution store not configured")
		case errors.Is(err, errPlatformExecutionStoreUnavailable):
			s.error(w, http.StatusInternalServerError, "platform execution store unavailable")
		default:
			s.error(w, http.StatusInternalServerError, "failed to list platform executions")
		}
		return
	}
	s.json(w, http.StatusOK, platformExecutionCollection{
		Count:      len(summaries),
		Executions: summaries,
	})
}

func queryCSVValues(r *http.Request, key string) []string {
	if r == nil {
		return nil
	}
	rawValues := r.URL.Query()[key]
	if len(rawValues) == 0 {
		return nil
	}
	values := make([]string, 0, len(rawValues))
	seen := make(map[string]struct{}, len(rawValues))
	for _, raw := range rawValues {
		for _, part := range strings.Split(raw, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if _, ok := seen[part]; ok {
				continue
			}
			seen[part] = struct{}{}
			values = append(values, part)
		}
	}
	if len(values) == 0 {
		return nil
	}
	return values
}
