package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/graph/knowledge"
	"github.com/writer/cerebro/internal/webhooks"
)

func (s *Server) listPlatformKnowledgeClaims(w http.ResponseWriter, r *http.Request) {
	opts, err := parsePlatformClaimQueryOptions(r)
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}

	claims, err := s.platformKnowledge.QueryClaims(r.Context(), opts)
	if err != nil {
		s.error(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	s.json(w, http.StatusOK, claims)
}

func (s *Server) listPlatformKnowledgeEvidence(w http.ResponseWriter, r *http.Request) {
	opts, err := parsePlatformKnowledgeArtifactQueryOptions(r)
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}

	evidence, err := s.platformKnowledge.QueryEvidence(r.Context(), opts)
	if err != nil {
		s.error(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	s.json(w, http.StatusOK, evidence)
}

func (s *Server) getPlatformKnowledgeEvidence(w http.ResponseWriter, r *http.Request) {
	s.getPlatformKnowledgeArtifact(w, r, graph.NodeKindEvidence)
}

func (s *Server) listPlatformKnowledgeObservations(w http.ResponseWriter, r *http.Request) {
	opts, err := parsePlatformKnowledgeArtifactQueryOptions(r)
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}

	observations, err := s.platformKnowledge.QueryObservations(r.Context(), opts)
	if err != nil {
		s.error(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	s.json(w, http.StatusOK, observations)
}

func (s *Server) getPlatformKnowledgeObservation(w http.ResponseWriter, r *http.Request) {
	s.getPlatformKnowledgeArtifact(w, r, graph.NodeKindObservation)
}

func (s *Server) getPlatformKnowledgeClaim(w http.ResponseWriter, r *http.Request) {
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

	record, ok, err := s.platformKnowledge.GetClaim(r.Context(), claimID, validAt, recordedAt)
	if err != nil {
		s.error(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	if !ok {
		s.error(w, http.StatusNotFound, "claim not found")
		return
	}
	s.json(w, http.StatusOK, record)
}

func (s *Server) listPlatformKnowledgeClaimGroups(w http.ResponseWriter, r *http.Request) {
	opts, err := parsePlatformClaimGroupQueryOptions(r)
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}

	groups, err := s.platformKnowledge.QueryClaimGroups(r.Context(), opts)
	if err != nil {
		s.error(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	s.json(w, http.StatusOK, groups)
}

func (s *Server) getPlatformKnowledgeClaimGroup(w http.ResponseWriter, r *http.Request) {
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

	record, ok, err := s.platformKnowledge.GetClaimGroup(r.Context(), groupID, validAt, recordedAt, includeResolved)
	if err != nil {
		s.error(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	if !ok {
		s.error(w, http.StatusNotFound, "claim group not found")
		return
	}
	s.json(w, http.StatusOK, record)
}

func (s *Server) getPlatformKnowledgeClaimTimeline(w http.ResponseWriter, r *http.Request) {
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

	timeline, ok, err := s.platformKnowledge.GetClaimTimeline(r.Context(), claimID, opts)
	if err != nil {
		s.error(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	if !ok {
		s.error(w, http.StatusNotFound, "claim not found")
		return
	}
	s.json(w, http.StatusOK, timeline)
}

func (s *Server) getPlatformKnowledgeClaimExplanation(w http.ResponseWriter, r *http.Request) {
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

	explanation, ok, err := s.platformKnowledge.ExplainClaim(r.Context(), claimID, validAt, recordedAt)
	if err != nil {
		s.error(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	if !ok {
		s.error(w, http.StatusNotFound, "claim not found")
		return
	}
	s.json(w, http.StatusOK, explanation)
}

func (s *Server) getPlatformKnowledgeClaimProofs(w http.ResponseWriter, r *http.Request) {
	claimID := strings.TrimSpace(chi.URLParam(r, "claim_id"))
	if claimID == "" {
		s.error(w, http.StatusBadRequest, "claim id required")
		return
	}

	opts, err := parsePlatformClaimProofOptions(r)
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}

	proofs, ok, err := s.platformKnowledge.BuildClaimProofs(r.Context(), claimID, opts)
	if err != nil {
		s.error(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	if !ok {
		s.error(w, http.StatusNotFound, "claim not found")
		return
	}
	s.json(w, http.StatusOK, proofs)
}

func (s *Server) listPlatformKnowledgeClaimDiffs(w http.ResponseWriter, r *http.Request) {
	opts, err := parsePlatformClaimDiffQueryOptions(r)
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}

	diffs, err := s.platformKnowledge.DiffClaims(r.Context(), opts)
	if err != nil {
		s.error(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	s.json(w, http.StatusOK, diffs)
}

func (s *Server) listPlatformKnowledgeDiffs(w http.ResponseWriter, r *http.Request) {
	opts, err := parsePlatformKnowledgeDiffQueryOptions(r)
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}

	diffs, err := s.platformKnowledge.DiffKnowledge(r.Context(), opts)
	if err != nil {
		switch {
		case errors.Is(err, errPlatformKnowledgeUnavailable), errors.Is(err, errPlatformKnowledgeSnapshotsUnavailable):
			s.error(w, http.StatusServiceUnavailable, err.Error())
		case strings.Contains(err.Error(), "not found"):
			s.error(w, http.StatusNotFound, err.Error())
		default:
			s.error(w, http.StatusBadRequest, err.Error())
		}
		return
	}

	s.json(w, http.StatusOK, diffs)
}

func (s *Server) adjudicatePlatformKnowledgeClaimGroup(w http.ResponseWriter, r *http.Request) {
	groupID := strings.TrimSpace(chi.URLParam(r, "group_id"))
	if groupID == "" {
		s.error(w, http.StatusBadRequest, "group id required")
		return
	}

	var req knowledge.ClaimAdjudicationWriteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.GroupID = groupID

	result, err := s.platformKnowledge.AdjudicateClaimGroup(r.Context(), req)
	if err != nil {
		status := http.StatusBadRequest
		switch {
		case errors.Is(err, errPlatformKnowledgeUnavailable):
			status = http.StatusServiceUnavailable
		case strings.Contains(err.Error(), "not found"):
			status = http.StatusNotFound
		}
		s.error(w, status, err.Error())
		return
	}

	s.emitPlatformLifecycleEvent(r.Context(), webhooks.EventPlatformClaimAdjudicated, map[string]any{
		"group_id":               result.GroupID,
		"action":                 result.Action,
		"created_claim_id":       result.CreatedClaimID,
		"authoritative_claim_id": result.AuthoritativeClaimID,
		"affected_claim_ids":     append([]string(nil), result.AffectedClaimIDs...),
		"superseded_claim_ids":   append([]string(nil), result.SupersededClaimIDs...),
		"observed_at":            result.ObservedAt.Format(time.RFC3339),
		"recorded_at":            result.RecordedAt.Format(time.RFC3339),
	})
	s.json(w, http.StatusCreated, result)
}

func (s *Server) platformWriteObservation(w http.ResponseWriter, r *http.Request) {
	s.graphWriteObservation(w, r)
}

func parsePlatformClaimQueryOptions(r *http.Request) (knowledge.ClaimQueryOptions, error) {
	opts := knowledge.ClaimQueryOptions{
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
			return knowledge.ClaimQueryOptions{}, errBadRequest("status must be one of asserted, disputed, corrected, retracted, superseded, refuted")
		}
	}

	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 500 {
			return knowledge.ClaimQueryOptions{}, errBadRequest("limit must be between 1 and 500")
		}
		opts.Limit = parsed
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("offset")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			return knowledge.ClaimQueryOptions{}, errBadRequest("offset must be >= 0")
		}
		opts.Offset = parsed
	}

	validAt, err := parseOptionalRFC3339Query(r, "valid_at")
	if err != nil {
		return knowledge.ClaimQueryOptions{}, err
	}
	opts.ValidAt = validAt

	recordedAt, err := parseOptionalRFC3339Query(r, "recorded_at")
	if err != nil {
		return knowledge.ClaimQueryOptions{}, err
	}
	opts.RecordedAt = recordedAt

	if includeResolved, ok, err := parseOptionalBoolQuery(r, "include_resolved"); err != nil {
		return knowledge.ClaimQueryOptions{}, err
	} else if ok {
		opts.IncludeResolved = includeResolved
	}
	if supported, ok, err := parseOptionalBoolQuery(r, "supported"); err != nil {
		return knowledge.ClaimQueryOptions{}, err
	} else if ok {
		opts.Supported = &supported
	}
	if sourceless, ok, err := parseOptionalBoolQuery(r, "sourceless"); err != nil {
		return knowledge.ClaimQueryOptions{}, err
	} else if ok {
		opts.Sourceless = &sourceless
	}
	if conflicted, ok, err := parseOptionalBoolQuery(r, "conflicted"); err != nil {
		return knowledge.ClaimQueryOptions{}, err
	} else if ok {
		opts.Conflicted = &conflicted
	}
	return opts, nil
}

func parsePlatformKnowledgeArtifactQueryOptions(r *http.Request) (knowledge.KnowledgeArtifactQueryOptions, error) {
	opts := knowledge.KnowledgeArtifactQueryOptions{
		ID:       strings.TrimSpace(firstNonEmpty(r.URL.Query().Get("id"), r.URL.Query().Get("artifact_id"))),
		TargetID: strings.TrimSpace(firstNonEmpty(r.URL.Query().Get("target_id"), r.URL.Query().Get("subject_id"), r.URL.Query().Get("entity_id"))),
		ClaimID:  strings.TrimSpace(r.URL.Query().Get("claim_id")),
		SourceID: strings.TrimSpace(r.URL.Query().Get("source_id")),
		Type:     strings.TrimSpace(firstNonEmpty(r.URL.Query().Get("type"), r.URL.Query().Get("observation_type"), r.URL.Query().Get("evidence_type"))),
	}

	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 500 {
			return knowledge.KnowledgeArtifactQueryOptions{}, errBadRequest("limit must be between 1 and 500")
		}
		opts.Limit = parsed
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("offset")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			return knowledge.KnowledgeArtifactQueryOptions{}, errBadRequest("offset must be >= 0")
		}
		opts.Offset = parsed
	}

	validAt, err := parseOptionalRFC3339Query(r, "valid_at")
	if err != nil {
		return knowledge.KnowledgeArtifactQueryOptions{}, err
	}
	opts.ValidAt = validAt

	recordedAt, err := parseOptionalRFC3339Query(r, "recorded_at")
	if err != nil {
		return knowledge.KnowledgeArtifactQueryOptions{}, err
	}
	opts.RecordedAt = recordedAt
	return opts, nil
}

func parsePlatformClaimGroupQueryOptions(r *http.Request) (knowledge.ClaimGroupQueryOptions, error) {
	opts := knowledge.ClaimGroupQueryOptions{
		GroupID:            strings.TrimSpace(r.URL.Query().Get("group_id")),
		SubjectID:          strings.TrimSpace(r.URL.Query().Get("subject_id")),
		Predicate:          strings.TrimSpace(r.URL.Query().Get("predicate")),
		IncludeSingleValue: false,
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 500 {
			return knowledge.ClaimGroupQueryOptions{}, errBadRequest("limit must be between 1 and 500")
		}
		opts.Limit = parsed
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("offset")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			return knowledge.ClaimGroupQueryOptions{}, errBadRequest("offset must be >= 0")
		}
		opts.Offset = parsed
	}

	validAt, err := parseOptionalRFC3339Query(r, "valid_at")
	if err != nil {
		return knowledge.ClaimGroupQueryOptions{}, err
	}
	opts.ValidAt = validAt
	recordedAt, err := parseOptionalRFC3339Query(r, "recorded_at")
	if err != nil {
		return knowledge.ClaimGroupQueryOptions{}, err
	}
	opts.RecordedAt = recordedAt
	if includeResolved, ok, err := parseOptionalBoolQuery(r, "include_resolved"); err != nil {
		return knowledge.ClaimGroupQueryOptions{}, err
	} else if ok {
		opts.IncludeResolved = includeResolved
	}
	if includeSingleValue, ok, err := parseOptionalBoolQuery(r, "include_single_value"); err != nil {
		return knowledge.ClaimGroupQueryOptions{}, err
	} else if ok {
		opts.IncludeSingleValue = includeSingleValue
	}
	if needsAdjudication, ok, err := parseOptionalBoolQuery(r, "needs_adjudication"); err != nil {
		return knowledge.ClaimGroupQueryOptions{}, err
	} else if ok {
		opts.NeedsAdjudication = &needsAdjudication
	}
	return opts, nil
}

func parsePlatformClaimTimelineOptions(r *http.Request) (knowledge.ClaimTimelineOptions, error) {
	opts := knowledge.ClaimTimelineOptions{}
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 1000 {
			return knowledge.ClaimTimelineOptions{}, errBadRequest("limit must be between 1 and 1000")
		}
		opts.Limit = parsed
	}
	validAt, err := parseOptionalRFC3339Query(r, "valid_at")
	if err != nil {
		return knowledge.ClaimTimelineOptions{}, err
	}
	opts.ValidAt = validAt
	recordedAt, err := parseOptionalRFC3339Query(r, "recorded_at")
	if err != nil {
		return knowledge.ClaimTimelineOptions{}, err
	}
	opts.RecordedAt = recordedAt
	return opts, nil
}

func parsePlatformClaimProofOptions(r *http.Request) (knowledge.ClaimProofOptions, error) {
	opts := knowledge.ClaimProofOptions{}
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 256 {
			return knowledge.ClaimProofOptions{}, errBadRequest("limit must be between 1 and 256")
		}
		opts.Limit = parsed
	}
	validAt, err := parseOptionalRFC3339Query(r, "valid_at")
	if err != nil {
		return knowledge.ClaimProofOptions{}, err
	}
	opts.ValidAt = validAt
	recordedAt, err := parseOptionalRFC3339Query(r, "recorded_at")
	if err != nil {
		return knowledge.ClaimProofOptions{}, err
	}
	opts.RecordedAt = recordedAt
	return opts, nil
}

func parsePlatformClaimDiffQueryOptions(r *http.Request) (knowledge.ClaimDiffQueryOptions, error) {
	opts := knowledge.ClaimDiffQueryOptions{
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
			return knowledge.ClaimDiffQueryOptions{}, errBadRequest("status must be one of asserted, disputed, corrected, retracted, superseded, refuted")
		}
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 500 {
			return knowledge.ClaimDiffQueryOptions{}, errBadRequest("limit must be between 1 and 500")
		}
		opts.Limit = parsed
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("offset")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			return knowledge.ClaimDiffQueryOptions{}, errBadRequest("offset must be >= 0")
		}
		opts.Offset = parsed
	}
	if includeResolved, ok, err := parseOptionalBoolQuery(r, "include_resolved"); err != nil {
		return knowledge.ClaimDiffQueryOptions{}, err
	} else if ok {
		opts.IncludeResolved = includeResolved
	}
	fromValidAt, err := parseOptionalRFC3339Query(r, "from_valid_at")
	if err != nil {
		return knowledge.ClaimDiffQueryOptions{}, err
	}
	opts.FromValidAt = fromValidAt
	fromRecordedAt, err := parseOptionalRFC3339Query(r, "from_recorded_at")
	if err != nil {
		return knowledge.ClaimDiffQueryOptions{}, err
	}
	opts.FromRecordedAt = fromRecordedAt
	toValidAt, err := parseOptionalRFC3339Query(r, "to_valid_at")
	if err != nil {
		return knowledge.ClaimDiffQueryOptions{}, err
	}
	opts.ToValidAt = toValidAt
	toRecordedAt, err := parseOptionalRFC3339Query(r, "to_recorded_at")
	if err != nil {
		return knowledge.ClaimDiffQueryOptions{}, err
	}
	opts.ToRecordedAt = toRecordedAt
	return opts, nil
}

func parsePlatformKnowledgeDiffQueryOptions(r *http.Request) (knowledge.KnowledgeDiffQueryOptions, error) {
	opts := knowledge.KnowledgeDiffQueryOptions{
		ClaimID:        strings.TrimSpace(r.URL.Query().Get("claim_id")),
		SubjectID:      strings.TrimSpace(r.URL.Query().Get("subject_id")),
		Predicate:      strings.TrimSpace(r.URL.Query().Get("predicate")),
		ObjectID:       strings.TrimSpace(r.URL.Query().Get("object_id")),
		ObjectValue:    strings.TrimSpace(r.URL.Query().Get("object_value")),
		ClaimType:      strings.TrimSpace(r.URL.Query().Get("claim_type")),
		TargetID:       strings.TrimSpace(firstNonEmpty(r.URL.Query().Get("target_id"), r.URL.Query().Get("entity_id"))),
		SourceID:       strings.TrimSpace(r.URL.Query().Get("source_id")),
		ArtifactType:   strings.TrimSpace(firstNonEmpty(r.URL.Query().Get("artifact_type"), r.URL.Query().Get("type"))),
		FromSnapshotID: strings.TrimSpace(r.URL.Query().Get("from_snapshot_id")),
		ToSnapshotID:   strings.TrimSpace(r.URL.Query().Get("to_snapshot_id")),
	}
	if rawKinds := strings.TrimSpace(r.URL.Query().Get("kinds")); rawKinds != "" {
		parts := strings.Split(rawKinds, ",")
		opts.Kinds = make([]graph.NodeKind, 0, len(parts))
		for _, part := range parts {
			opts.Kinds = append(opts.Kinds, graph.NodeKind(strings.TrimSpace(part)))
		}
	}
	if rawStatus := strings.TrimSpace(r.URL.Query().Get("status")); rawStatus != "" {
		switch strings.ToLower(rawStatus) {
		case "asserted", "disputed", "corrected", "retracted", "superseded", "refuted":
			opts.Status = rawStatus
		default:
			return knowledge.KnowledgeDiffQueryOptions{}, errBadRequest("status must be one of asserted, disputed, corrected, retracted, superseded, refuted")
		}
	}
	if includeResolved, ok, err := parseOptionalBoolQuery(r, "include_resolved"); err != nil {
		return knowledge.KnowledgeDiffQueryOptions{}, err
	} else if ok {
		opts.IncludeResolved = includeResolved
	}
	fromValidAt, err := parseOptionalRFC3339Query(r, "from_valid_at")
	if err != nil {
		return knowledge.KnowledgeDiffQueryOptions{}, err
	}
	opts.FromValidAt = fromValidAt
	fromRecordedAt, err := parseOptionalRFC3339Query(r, "from_recorded_at")
	if err != nil {
		return knowledge.KnowledgeDiffQueryOptions{}, err
	}
	opts.FromRecordedAt = fromRecordedAt
	toValidAt, err := parseOptionalRFC3339Query(r, "to_valid_at")
	if err != nil {
		return knowledge.KnowledgeDiffQueryOptions{}, err
	}
	opts.ToValidAt = toValidAt
	toRecordedAt, err := parseOptionalRFC3339Query(r, "to_recorded_at")
	if err != nil {
		return knowledge.KnowledgeDiffQueryOptions{}, err
	}
	opts.ToRecordedAt = toRecordedAt

	if (opts.FromSnapshotID == "") != (opts.ToSnapshotID == "") {
		return knowledge.KnowledgeDiffQueryOptions{}, errBadRequest("from_snapshot_id and to_snapshot_id must be supplied together")
	}
	if opts.FromSnapshotID == "" && opts.ToSnapshotID == "" && (opts.FromValidAt.IsZero() || opts.ToValidAt.IsZero()) {
		return knowledge.KnowledgeDiffQueryOptions{}, errBadRequest("either snapshot ids or both from_valid_at and to_valid_at are required")
	}
	return opts, nil
}

func (s *Server) getPlatformKnowledgeArtifact(w http.ResponseWriter, r *http.Request, kind graph.NodeKind) {
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

	var record knowledge.KnowledgeArtifactRecord
	var ok bool
	switch kind {
	case graph.NodeKindObservation:
		record, ok, err = s.platformKnowledge.GetObservation(r.Context(), id, validAt, recordedAt)
	default:
		record, ok, err = s.platformKnowledge.GetEvidence(r.Context(), id, validAt, recordedAt)
	}
	if err != nil {
		s.error(w, http.StatusServiceUnavailable, err.Error())
		return
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

func snapshotKnowledgeComparisonTime(snapshot *graph.Snapshot, record *graph.GraphSnapshotRecord) time.Time {
	if snapshot != nil && !snapshot.CreatedAt.IsZero() {
		return snapshot.CreatedAt.UTC()
	}
	if record != nil {
		if record.CapturedAt != nil && !record.CapturedAt.IsZero() {
			return record.CapturedAt.UTC()
		}
		if record.BuiltAt != nil && !record.BuiltAt.IsZero() {
			return record.BuiltAt.UTC()
		}
	}
	return time.Now().UTC()
}

type badRequestError string

func (e badRequestError) Error() string {
	return string(e)
}
