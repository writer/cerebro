package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/evalops/cerebro/internal/graph"
	"github.com/evalops/cerebro/internal/webhooks"
)

type graphWriteObservationRequest struct {
	ID              string         `json:"id"`
	EntityID        string         `json:"entity_id"`
	SubjectID       string         `json:"subject_id"`
	Observation     string         `json:"observation"`
	ObservationType string         `json:"observation_type"`
	Summary         string         `json:"summary"`
	SourceSystem    string         `json:"source_system"`
	SourceEventID   string         `json:"source_event_id"`
	ObservedAt      time.Time      `json:"observed_at"`
	ValidFrom       time.Time      `json:"valid_from"`
	ValidTo         *time.Time     `json:"valid_to,omitempty"`
	RecordedAt      time.Time      `json:"recorded_at,omitempty"`
	TransactionFrom time.Time      `json:"transaction_from,omitempty"`
	TransactionTo   *time.Time     `json:"transaction_to,omitempty"`
	Confidence      float64        `json:"confidence"`
	Metadata        map[string]any `json:"metadata,omitempty"`
}

type graphWriteClaimRequest struct {
	ID                 string         `json:"id"`
	ClaimType          string         `json:"claim_type,omitempty"`
	SubjectID          string         `json:"subject_id"`
	Predicate          string         `json:"predicate"`
	ObjectID           string         `json:"object_id,omitempty"`
	ObjectValue        string         `json:"object_value,omitempty"`
	Status             string         `json:"status,omitempty"`
	Summary            string         `json:"summary,omitempty"`
	EvidenceIDs        []string       `json:"evidence_ids,omitempty"`
	SupportingClaimIDs []string       `json:"supporting_claim_ids,omitempty"`
	RefutingClaimIDs   []string       `json:"refuting_claim_ids,omitempty"`
	SupersedesClaimID  string         `json:"supersedes_claim_id,omitempty"`
	SourceID           string         `json:"source_id,omitempty"`
	SourceName         string         `json:"source_name,omitempty"`
	SourceType         string         `json:"source_type,omitempty"`
	SourceURL          string         `json:"source_url,omitempty"`
	TrustTier          string         `json:"trust_tier,omitempty"`
	ReliabilityScore   float64        `json:"reliability_score,omitempty"`
	SourceSystem       string         `json:"source_system"`
	SourceEventID      string         `json:"source_event_id"`
	ObservedAt         time.Time      `json:"observed_at"`
	ValidFrom          time.Time      `json:"valid_from"`
	ValidTo            *time.Time     `json:"valid_to,omitempty"`
	RecordedAt         time.Time      `json:"recorded_at,omitempty"`
	TransactionFrom    time.Time      `json:"transaction_from,omitempty"`
	TransactionTo      *time.Time     `json:"transaction_to,omitempty"`
	Confidence         float64        `json:"confidence"`
	Metadata           map[string]any `json:"metadata,omitempty"`
}

type graphAnnotateEntityRequest struct {
	EntityID      string         `json:"entity_id"`
	Annotation    string         `json:"annotation"`
	Tags          []string       `json:"tags,omitempty"`
	SourceSystem  string         `json:"source_system"`
	SourceEventID string         `json:"source_event_id"`
	ObservedAt    time.Time      `json:"observed_at"`
	ValidFrom     time.Time      `json:"valid_from"`
	ValidTo       *time.Time     `json:"valid_to,omitempty"`
	Confidence    float64        `json:"confidence"`
	Metadata      map[string]any `json:"metadata,omitempty"`
}

type graphWriteDecisionRequest struct {
	ID            string         `json:"id"`
	DecisionType  string         `json:"decision_type"`
	Status        string         `json:"status"`
	MadeBy        string         `json:"made_by"`
	Rationale     string         `json:"rationale"`
	TargetIDs     []string       `json:"target_ids"`
	EvidenceIDs   []string       `json:"evidence_ids,omitempty"`
	ActionIDs     []string       `json:"action_ids,omitempty"`
	SourceSystem  string         `json:"source_system"`
	SourceEventID string         `json:"source_event_id"`
	ObservedAt    time.Time      `json:"observed_at"`
	ValidFrom     time.Time      `json:"valid_from"`
	ValidTo       *time.Time     `json:"valid_to,omitempty"`
	Confidence    float64        `json:"confidence"`
	Metadata      map[string]any `json:"metadata,omitempty"`
}

type graphWriteOutcomeRequest struct {
	ID            string         `json:"id"`
	DecisionID    string         `json:"decision_id"`
	OutcomeType   string         `json:"outcome_type"`
	Verdict       string         `json:"verdict"`
	ImpactScore   float64        `json:"impact_score"`
	TargetIDs     []string       `json:"target_ids,omitempty"`
	SourceSystem  string         `json:"source_system"`
	SourceEventID string         `json:"source_event_id"`
	ObservedAt    time.Time      `json:"observed_at"`
	ValidFrom     time.Time      `json:"valid_from"`
	ValidTo       *time.Time     `json:"valid_to,omitempty"`
	Confidence    float64        `json:"confidence"`
	Metadata      map[string]any `json:"metadata,omitempty"`
}

type graphResolveIdentityRequest struct {
	AliasID           string    `json:"alias_id,omitempty"`
	SourceSystem      string    `json:"source_system"`
	SourceEventID     string    `json:"source_event_id,omitempty"`
	ExternalID        string    `json:"external_id"`
	AliasType         string    `json:"alias_type,omitempty"`
	CanonicalHint     string    `json:"canonical_hint,omitempty"`
	Email             string    `json:"email,omitempty"`
	Name              string    `json:"name,omitempty"`
	ObservedAt        time.Time `json:"observed_at,omitempty"`
	Confidence        float64   `json:"confidence,omitempty"`
	AutoLinkThreshold float64   `json:"auto_link_threshold,omitempty"`
	SuggestThreshold  float64   `json:"suggest_threshold,omitempty"`
}

type graphSplitIdentityRequest struct {
	AliasNodeID     string    `json:"alias_node_id"`
	CanonicalNodeID string    `json:"canonical_node_id"`
	Reason          string    `json:"reason"`
	SourceSystem    string    `json:"source_system"`
	SourceEventID   string    `json:"source_event_id"`
	ObservedAt      time.Time `json:"observed_at"`
}

type graphIdentityReviewRequest struct {
	AliasNodeID     string    `json:"alias_node_id"`
	CanonicalNodeID string    `json:"canonical_node_id"`
	Verdict         string    `json:"verdict"`
	Reviewer        string    `json:"reviewer"`
	Reason          string    `json:"reason"`
	SourceSystem    string    `json:"source_system"`
	SourceEventID   string    `json:"source_event_id"`
	ObservedAt      time.Time `json:"observed_at"`
	Confidence      float64   `json:"confidence"`
}

type graphActuateRecommendationRequest struct {
	ID               string         `json:"id"`
	RecommendationID string         `json:"recommendation_id"`
	InsightType      string         `json:"insight_type"`
	Title            string         `json:"title"`
	Summary          string         `json:"summary"`
	DecisionID       string         `json:"decision_id"`
	TargetIDs        []string       `json:"target_ids"`
	SourceSystem     string         `json:"source_system"`
	SourceEventID    string         `json:"source_event_id"`
	ObservedAt       time.Time      `json:"observed_at"`
	ValidFrom        time.Time      `json:"valid_from"`
	ValidTo          *time.Time     `json:"valid_to,omitempty"`
	Confidence       float64        `json:"confidence"`
	AutoGenerated    bool           `json:"auto_generated"`
	Metadata         map[string]any `json:"metadata,omitempty"`
}

func (s *Server) graphWriteObservation(w http.ResponseWriter, r *http.Request) {
	var req graphWriteObservationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.EntityID = strings.TrimSpace(req.EntityID)
	req.SubjectID = strings.TrimSpace(req.SubjectID)
	req.Observation = strings.TrimSpace(req.Observation)
	req.ObservationType = strings.TrimSpace(req.ObservationType)
	req.Summary = strings.TrimSpace(req.Summary)

	subjectID := firstNonEmpty(req.SubjectID, req.EntityID)
	observationType := firstNonEmpty(req.ObservationType, req.Observation)
	if subjectID == "" {
		s.error(w, http.StatusBadRequest, "subject_id is required")
		return
	}
	if observationType == "" {
		s.error(w, http.StatusBadRequest, "observation_type is required")
		return
	}

	req.SubjectID = subjectID
	req.ObservationType = observationType
	result, err := s.graphWriteback.WriteObservation(r.Context(), req)
	if err != nil {
		s.graphWritebackError(w, err)
		return
	}
	s.json(w, http.StatusCreated, result)
}

func (s *Server) graphWriteClaim(w http.ResponseWriter, r *http.Request) {
	var req graphWriteClaimRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	result, err := s.graphWriteback.WriteClaim(r.Context(), req)
	if err != nil {
		s.graphWritebackError(w, err)
		return
	}
	s.json(w, http.StatusCreated, result)
}

func (s *Server) graphAnnotateEntity(w http.ResponseWriter, r *http.Request) {
	var req graphAnnotateEntityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.EntityID = strings.TrimSpace(req.EntityID)
	req.Annotation = strings.TrimSpace(req.Annotation)
	if req.EntityID == "" {
		s.error(w, http.StatusBadRequest, "entity_id is required")
		return
	}
	if req.Annotation == "" {
		s.error(w, http.StatusBadRequest, "annotation is required")
		return
	}

	result, err := s.graphWriteback.AnnotateEntity(r.Context(), req)
	if err != nil {
		s.graphWritebackError(w, err)
		return
	}
	s.json(w, http.StatusCreated, result)
}

func (s *Server) graphWriteDecision(w http.ResponseWriter, r *http.Request) {
	var req graphWriteDecisionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.DecisionType = strings.TrimSpace(req.DecisionType)
	req.Status = strings.TrimSpace(req.Status)
	req.MadeBy = strings.TrimSpace(req.MadeBy)
	req.Rationale = strings.TrimSpace(req.Rationale)
	if req.DecisionType == "" {
		s.error(w, http.StatusBadRequest, "decision_type is required")
		return
	}
	if len(req.TargetIDs) == 0 {
		s.error(w, http.StatusBadRequest, "target_ids requires at least one target")
		return
	}
	req.TargetIDs = uniqueNormalizedIDs(req.TargetIDs)
	result, err := s.graphWriteback.WriteDecision(r.Context(), req)
	if err != nil {
		s.graphWritebackError(w, err)
		return
	}
	s.json(w, http.StatusCreated, result)
}

func (s *Server) graphWriteOutcome(w http.ResponseWriter, r *http.Request) {
	var req graphWriteOutcomeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.DecisionID = strings.TrimSpace(req.DecisionID)
	req.OutcomeType = strings.TrimSpace(req.OutcomeType)
	req.Verdict = strings.TrimSpace(req.Verdict)
	if req.DecisionID == "" {
		s.error(w, http.StatusBadRequest, "decision_id is required")
		return
	}
	if req.OutcomeType == "" || req.Verdict == "" {
		s.error(w, http.StatusBadRequest, "outcome_type and verdict are required")
		return
	}
	req.TargetIDs = uniqueNormalizedIDs(req.TargetIDs)
	result, err := s.graphWriteback.WriteOutcome(r.Context(), req)
	if err != nil {
		s.graphWritebackError(w, err)
		return
	}
	s.json(w, http.StatusCreated, result)
}

func (s *Server) graphResolveIdentity(w http.ResponseWriter, r *http.Request) {
	var req graphResolveIdentityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	result, err := s.graphWriteback.ResolveIdentity(r.Context(), req)
	if err != nil {
		s.graphWritebackError(w, err)
		return
	}
	s.json(w, http.StatusOK, result)
}

func (s *Server) graphSplitIdentity(w http.ResponseWriter, r *http.Request) {
	var req graphSplitIdentityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	result, err := s.graphWriteback.SplitIdentity(r.Context(), req)
	if err != nil {
		s.graphWritebackError(w, err)
		return
	}
	s.json(w, http.StatusOK, result)
}

func (s *Server) graphReviewIdentity(w http.ResponseWriter, r *http.Request) {
	var req graphIdentityReviewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	result, err := s.graphWriteback.ReviewIdentity(r.Context(), req)
	if err != nil {
		s.graphWritebackError(w, err)
		return
	}
	s.json(w, http.StatusOK, result)
}

func (s *Server) graphIdentityCalibration(w http.ResponseWriter, r *http.Request) {
	includeQueue := true
	if raw := strings.TrimSpace(r.URL.Query().Get("include_queue")); raw != "" {
		parsed, err := strconv.ParseBool(raw)
		if err != nil {
			s.error(w, http.StatusBadRequest, "include_queue must be a boolean")
			return
		}
		includeQueue = parsed
	}

	suggestThreshold := 0.55
	if raw := strings.TrimSpace(r.URL.Query().Get("suggest_threshold")); raw != "" {
		parsed, err := strconv.ParseFloat(raw, 64)
		if err != nil || parsed < 0 || parsed > 1 {
			s.error(w, http.StatusBadRequest, "suggest_threshold must be between 0 and 1")
			return
		}
		suggestThreshold = parsed
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

	report, err := s.graphWriteback.IdentityCalibration(r.Context(), graph.IdentityCalibrationOptions{
		SuggestThreshold: suggestThreshold,
		QueueLimit:       queueLimit,
		IncludeQueue:     includeQueue,
	})
	if err != nil {
		s.graphWritebackError(w, err)
		return
	}
	s.json(w, http.StatusOK, report)
}

func (s *Server) graphActuateRecommendation(w http.ResponseWriter, r *http.Request) {
	var req graphActuateRecommendationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	result, err := s.graphWriteback.ActuateRecommendation(r.Context(), req)
	if err != nil {
		s.graphWritebackError(w, err)
		return
	}
	s.json(w, http.StatusCreated, result)
}

func cloneJSONMap(value map[string]any) map[string]any {
	if len(value) == 0 {
		return map[string]any{}
	}
	out := make(map[string]any, len(value))
	for key, item := range value {
		out[key] = item
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func uniqueNormalizedIDs(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		normalized := strings.TrimSpace(value)
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	return out
}

func normalizeStringSlice(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		normalized := strings.TrimSpace(value)
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	return out
}

func (s *Server) emitPlatformLifecycleEvent(ctx context.Context, eventType webhooks.EventType, data map[string]any) {
	if s == nil || s.app == nil || s.app.Webhooks == nil {
		return
	}
	payload := cloneJSONMap(data)
	if tenantID := strings.TrimSpace(GetTenantID(ctx)); tenantID != "" {
		payload["tenant_id"] = tenantID
	}
	if err := s.app.Webhooks.EmitWithErrors(ctx, eventType, payload); err != nil {
		s.app.Logger.Warn("failed to emit platform lifecycle event", "event_type", eventType, "error", err)
	}
}

func readStringProperty(node *graph.Node, key string, fallback ...string) string {
	if node != nil && node.Properties != nil {
		if value, ok := node.Properties[key]; ok {
			if rendered := strings.TrimSpace(fmt.Sprintf("%v", value)); rendered != "" && rendered != "<nil>" {
				return rendered
			}
		}
	}
	return firstNonEmpty(fallback...)
}

func (s *Server) graphWritebackError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errGraphWritebackUnavailable),
		strings.Contains(err.Error(), "not initialized"),
		strings.Contains(err.Error(), "graph writer lease not held"):
		s.error(w, http.StatusServiceUnavailable, errGraphWritebackUnavailable.Error())
	case strings.Contains(err.Error(), "not found"):
		s.error(w, http.StatusNotFound, err.Error())
	default:
		s.error(w, http.StatusBadRequest, err.Error())
	}
}

func normalizeRFC3339(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}

func nodeName(node *graph.Node) string {
	if node == nil {
		return ""
	}
	return strings.TrimSpace(node.Name)
}

func annotationsFromProperties(raw any) []map[string]any {
	switch typed := raw.(type) {
	case []map[string]any:
		return append([]map[string]any(nil), typed...)
	case []any:
		out := make([]map[string]any, 0, len(typed))
		for _, item := range typed {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			out = append(out, m)
		}
		return out
	default:
		return []map[string]any{}
	}
}
