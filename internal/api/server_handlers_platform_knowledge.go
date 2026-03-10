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

func (s *Server) listPlatformKnowledgeEvidence(w http.ResponseWriter, r *http.Request) {
	g := s.app.SecurityGraph
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	opts, err := parsePlatformKnowledgeArtifactQueryOptions(r)
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}

	s.json(w, http.StatusOK, graph.QueryEvidence(g, opts))
}

func (s *Server) getPlatformKnowledgeEvidence(w http.ResponseWriter, r *http.Request) {
	s.getPlatformKnowledgeArtifact(w, r, graph.NodeKindEvidence)
}

func (s *Server) listPlatformKnowledgeObservations(w http.ResponseWriter, r *http.Request) {
	g := s.app.SecurityGraph
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	opts, err := parsePlatformKnowledgeArtifactQueryOptions(r)
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}

	s.json(w, http.StatusOK, graph.QueryObservations(g, opts))
}

func (s *Server) getPlatformKnowledgeObservation(w http.ResponseWriter, r *http.Request) {
	s.getPlatformKnowledgeArtifact(w, r, graph.NodeKindObservation)
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

func (s *Server) listPlatformKnowledgeClaimGroups(w http.ResponseWriter, r *http.Request) {
	g := s.app.SecurityGraph
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	opts, err := parsePlatformClaimGroupQueryOptions(r)
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}

	s.json(w, http.StatusOK, graph.QueryClaimGroups(g, opts))
}

func (s *Server) getPlatformKnowledgeClaimGroup(w http.ResponseWriter, r *http.Request) {
	g := s.app.SecurityGraph
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	groupID := strings.TrimSpace(chi.URLParam(r, "group_id"))
	if groupID == "" {
		s.error(w, http.StatusBadRequest, "group id required")
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
	includeResolved, _, err := parseOptionalBoolQuery(r, "include_resolved")
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}

	record, ok := graph.GetClaimGroupRecord(g, groupID, validAt, recordedAt, includeResolved)
	if !ok {
		s.error(w, http.StatusNotFound, "claim group not found")
		return
	}
	s.json(w, http.StatusOK, record)
}

func (s *Server) getPlatformKnowledgeClaimTimeline(w http.ResponseWriter, r *http.Request) {
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

	opts, err := parsePlatformClaimTimelineOptions(r)
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}

	timeline, ok := graph.GetClaimTimeline(g, claimID, opts)
	if !ok {
		s.error(w, http.StatusNotFound, "claim not found")
		return
	}
	s.json(w, http.StatusOK, timeline)
}

func (s *Server) getPlatformKnowledgeClaimExplanation(w http.ResponseWriter, r *http.Request) {
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

	explanation, ok := graph.ExplainClaim(g, claimID, validAt, recordedAt)
	if !ok {
		s.error(w, http.StatusNotFound, "claim not found")
		return
	}
	s.json(w, http.StatusOK, explanation)
}

func (s *Server) listPlatformKnowledgeClaimDiffs(w http.ResponseWriter, r *http.Request) {
	g := s.app.SecurityGraph
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	opts, err := parsePlatformClaimDiffQueryOptions(r)
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}

	s.json(w, http.StatusOK, graph.DiffClaims(g, opts))
}

func (s *Server) platformWriteObservation(w http.ResponseWriter, r *http.Request) {
	s.graphWriteObservation(w, r)
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

func parsePlatformKnowledgeArtifactQueryOptions(r *http.Request) (graph.KnowledgeArtifactQueryOptions, error) {
	opts := graph.KnowledgeArtifactQueryOptions{
		ID:       strings.TrimSpace(firstNonEmpty(r.URL.Query().Get("id"), r.URL.Query().Get("artifact_id"))),
		TargetID: strings.TrimSpace(firstNonEmpty(r.URL.Query().Get("target_id"), r.URL.Query().Get("subject_id"), r.URL.Query().Get("entity_id"))),
		ClaimID:  strings.TrimSpace(r.URL.Query().Get("claim_id")),
		SourceID: strings.TrimSpace(r.URL.Query().Get("source_id")),
		Type:     strings.TrimSpace(firstNonEmpty(r.URL.Query().Get("type"), r.URL.Query().Get("observation_type"), r.URL.Query().Get("evidence_type"))),
	}

	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 500 {
			return graph.KnowledgeArtifactQueryOptions{}, errBadRequest("limit must be between 1 and 500")
		}
		opts.Limit = parsed
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("offset")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			return graph.KnowledgeArtifactQueryOptions{}, errBadRequest("offset must be >= 0")
		}
		opts.Offset = parsed
	}

	validAt, err := parseOptionalRFC3339Query(r, "valid_at")
	if err != nil {
		return graph.KnowledgeArtifactQueryOptions{}, err
	}
	opts.ValidAt = validAt

	recordedAt, err := parseOptionalRFC3339Query(r, "recorded_at")
	if err != nil {
		return graph.KnowledgeArtifactQueryOptions{}, err
	}
	opts.RecordedAt = recordedAt
	return opts, nil
}

func parsePlatformClaimGroupQueryOptions(r *http.Request) (graph.ClaimGroupQueryOptions, error) {
	opts := graph.ClaimGroupQueryOptions{
		GroupID:            strings.TrimSpace(r.URL.Query().Get("group_id")),
		SubjectID:          strings.TrimSpace(r.URL.Query().Get("subject_id")),
		Predicate:          strings.TrimSpace(r.URL.Query().Get("predicate")),
		IncludeSingleValue: false,
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 500 {
			return graph.ClaimGroupQueryOptions{}, errBadRequest("limit must be between 1 and 500")
		}
		opts.Limit = parsed
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("offset")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			return graph.ClaimGroupQueryOptions{}, errBadRequest("offset must be >= 0")
		}
		opts.Offset = parsed
	}

	validAt, err := parseOptionalRFC3339Query(r, "valid_at")
	if err != nil {
		return graph.ClaimGroupQueryOptions{}, err
	}
	opts.ValidAt = validAt
	recordedAt, err := parseOptionalRFC3339Query(r, "recorded_at")
	if err != nil {
		return graph.ClaimGroupQueryOptions{}, err
	}
	opts.RecordedAt = recordedAt
	if includeResolved, ok, err := parseOptionalBoolQuery(r, "include_resolved"); err != nil {
		return graph.ClaimGroupQueryOptions{}, err
	} else if ok {
		opts.IncludeResolved = includeResolved
	}
	if includeSingleValue, ok, err := parseOptionalBoolQuery(r, "include_single_value"); err != nil {
		return graph.ClaimGroupQueryOptions{}, err
	} else if ok {
		opts.IncludeSingleValue = includeSingleValue
	}
	if needsAdjudication, ok, err := parseOptionalBoolQuery(r, "needs_adjudication"); err != nil {
		return graph.ClaimGroupQueryOptions{}, err
	} else if ok {
		opts.NeedsAdjudication = &needsAdjudication
	}
	return opts, nil
}

func parsePlatformClaimTimelineOptions(r *http.Request) (graph.ClaimTimelineOptions, error) {
	opts := graph.ClaimTimelineOptions{}
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 1000 {
			return graph.ClaimTimelineOptions{}, errBadRequest("limit must be between 1 and 1000")
		}
		opts.Limit = parsed
	}
	validAt, err := parseOptionalRFC3339Query(r, "valid_at")
	if err != nil {
		return graph.ClaimTimelineOptions{}, err
	}
	opts.ValidAt = validAt
	recordedAt, err := parseOptionalRFC3339Query(r, "recorded_at")
	if err != nil {
		return graph.ClaimTimelineOptions{}, err
	}
	opts.RecordedAt = recordedAt
	return opts, nil
}

func parsePlatformClaimDiffQueryOptions(r *http.Request) (graph.ClaimDiffQueryOptions, error) {
	opts := graph.ClaimDiffQueryOptions{
		ClaimID:     strings.TrimSpace(r.URL.Query().Get("claim_id")),
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
			return graph.ClaimDiffQueryOptions{}, errBadRequest("status must be one of asserted, disputed, corrected, retracted, superseded, refuted")
		}
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 500 {
			return graph.ClaimDiffQueryOptions{}, errBadRequest("limit must be between 1 and 500")
		}
		opts.Limit = parsed
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("offset")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			return graph.ClaimDiffQueryOptions{}, errBadRequest("offset must be >= 0")
		}
		opts.Offset = parsed
	}
	if includeResolved, ok, err := parseOptionalBoolQuery(r, "include_resolved"); err != nil {
		return graph.ClaimDiffQueryOptions{}, err
	} else if ok {
		opts.IncludeResolved = includeResolved
	}
	fromValidAt, err := parseOptionalRFC3339Query(r, "from_valid_at")
	if err != nil {
		return graph.ClaimDiffQueryOptions{}, err
	}
	opts.FromValidAt = fromValidAt
	fromRecordedAt, err := parseOptionalRFC3339Query(r, "from_recorded_at")
	if err != nil {
		return graph.ClaimDiffQueryOptions{}, err
	}
	opts.FromRecordedAt = fromRecordedAt
	toValidAt, err := parseOptionalRFC3339Query(r, "to_valid_at")
	if err != nil {
		return graph.ClaimDiffQueryOptions{}, err
	}
	opts.ToValidAt = toValidAt
	toRecordedAt, err := parseOptionalRFC3339Query(r, "to_recorded_at")
	if err != nil {
		return graph.ClaimDiffQueryOptions{}, err
	}
	opts.ToRecordedAt = toRecordedAt
	return opts, nil
}

func (s *Server) getPlatformKnowledgeArtifact(w http.ResponseWriter, r *http.Request, kind graph.NodeKind) {
	g := s.app.SecurityGraph
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	key := "artifact_id"
	switch kind {
	case graph.NodeKindEvidence:
		key = "evidence_id"
	case graph.NodeKindObservation:
		key = "observation_id"
	}
	id := strings.TrimSpace(chi.URLParam(r, key))
	if id == "" {
		s.error(w, http.StatusBadRequest, key+" required")
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

	var record graph.KnowledgeArtifactRecord
	var ok bool
	switch kind {
	case graph.NodeKindObservation:
		record, ok = graph.GetObservationRecord(g, id, validAt, recordedAt)
	default:
		record, ok = graph.GetEvidenceRecord(g, id, validAt, recordedAt)
	}
	if !ok {
		s.error(w, http.StatusNotFound, "knowledge artifact not found")
		return
	}
	s.json(w, http.StatusOK, record)
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
