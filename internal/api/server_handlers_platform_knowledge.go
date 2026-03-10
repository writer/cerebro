package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/evalops/cerebro/internal/graph"
)

func (s *Server) listPlatformKnowledgeClaims(w http.ResponseWriter, r *http.Request) {
	g := s.app.SecurityGraph
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	opts, err := parsePlatformClaimQueryOptions(r)
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}

	s.json(w, http.StatusOK, graph.QueryClaims(g, opts))
}

func (s *Server) getPlatformKnowledgeClaim(w http.ResponseWriter, r *http.Request) {
	g := s.app.SecurityGraph
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	claimID := strings.TrimSpace(chi.URLParam(r, "claim_id"))
	if claimID == "" {
		s.error(w, http.StatusBadRequest, "claim id required")
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

	record, ok := graph.GetClaimRecord(g, claimID, validAt, recordedAt)
	if !ok {
		s.error(w, http.StatusNotFound, "claim not found")
		return
	}
	s.json(w, http.StatusOK, record)
}

func parsePlatformClaimQueryOptions(r *http.Request) (graph.ClaimQueryOptions, error) {
	opts := graph.ClaimQueryOptions{
		SubjectID:   strings.TrimSpace(r.URL.Query().Get("subject_id")),
		Predicate:   strings.TrimSpace(r.URL.Query().Get("predicate")),
		ObjectID:    strings.TrimSpace(r.URL.Query().Get("object_id")),
		ObjectValue: strings.TrimSpace(r.URL.Query().Get("object_value")),
		ClaimType:   strings.TrimSpace(r.URL.Query().Get("claim_type")),
		SourceID:    strings.TrimSpace(r.URL.Query().Get("source_id")),
		EvidenceID:  strings.TrimSpace(r.URL.Query().Get("evidence_id")),
	}

	if rawStatus := strings.TrimSpace(r.URL.Query().Get("status")); rawStatus != "" {
		switch strings.ToLower(rawStatus) {
		case "asserted", "disputed", "corrected", "retracted", "superseded", "refuted":
			opts.Status = rawStatus
		default:
			return graph.ClaimQueryOptions{}, errBadRequest("status must be one of asserted, disputed, corrected, retracted, superseded, refuted")
		}
	}

	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 500 {
			return graph.ClaimQueryOptions{}, errBadRequest("limit must be between 1 and 500")
		}
		opts.Limit = parsed
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("offset")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			return graph.ClaimQueryOptions{}, errBadRequest("offset must be >= 0")
		}
		opts.Offset = parsed
	}

	validAt, err := parseOptionalRFC3339Query(r, "valid_at")
	if err != nil {
		return graph.ClaimQueryOptions{}, err
	}
	opts.ValidAt = validAt

	recordedAt, err := parseOptionalRFC3339Query(r, "recorded_at")
	if err != nil {
		return graph.ClaimQueryOptions{}, err
	}
	opts.RecordedAt = recordedAt

	if includeResolved, ok, err := parseOptionalBoolQuery(r, "include_resolved"); err != nil {
		return graph.ClaimQueryOptions{}, err
	} else if ok {
		opts.IncludeResolved = includeResolved
	}
	if supported, ok, err := parseOptionalBoolQuery(r, "supported"); err != nil {
		return graph.ClaimQueryOptions{}, err
	} else if ok {
		opts.Supported = &supported
	}
	if sourceless, ok, err := parseOptionalBoolQuery(r, "sourceless"); err != nil {
		return graph.ClaimQueryOptions{}, err
	} else if ok {
		opts.Sourceless = &sourceless
	}
	if conflicted, ok, err := parseOptionalBoolQuery(r, "conflicted"); err != nil {
		return graph.ClaimQueryOptions{}, err
	} else if ok {
		opts.Conflicted = &conflicted
	}
	return opts, nil
}

func parseOptionalBoolQuery(r *http.Request, key string) (bool, bool, error) {
	raw := strings.TrimSpace(r.URL.Query().Get(key))
	if raw == "" {
		return false, false, nil
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, false, errBadRequest(key + " must be true or false")
	}
	return value, true, nil
}

func parseOptionalRFC3339Query(r *http.Request, key string) (time.Time, error) {
	raw := strings.TrimSpace(r.URL.Query().Get(key))
	if raw == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, errBadRequest(key + " must be RFC3339")
	}
	return parsed.UTC(), nil
}

func errBadRequest(message string) error {
	return badRequestError(message)
}

type badRequestError string

func (e badRequestError) Error() string {
	return string(e)
}
