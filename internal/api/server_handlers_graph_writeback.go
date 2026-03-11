package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/webhooks"
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
	g := s.app.SecurityGraph
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

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
	result, err := graph.WriteObservation(g, graph.ObservationWriteRequest{
		ID:              req.ID,
		SubjectID:       subjectID,
		ObservationType: observationType,
		Summary:         req.Summary,
		SourceSystem:    req.SourceSystem,
		SourceEventID:   req.SourceEventID,
		ObservedAt:      req.ObservedAt,
		ValidFrom:       req.ValidFrom,
		ValidTo:         req.ValidTo,
		RecordedAt:      req.RecordedAt,
		TransactionFrom: req.TransactionFrom,
		TransactionTo:   req.TransactionTo,
		Confidence:      req.Confidence,
		Metadata:        cloneJSONMap(req.Metadata),
	})
	if err != nil {
		switch {
		case strings.Contains(err.Error(), "required"):
			s.error(w, http.StatusBadRequest, err.Error())
		case strings.Contains(err.Error(), "not found"):
			s.error(w, http.StatusNotFound, err.Error())
		default:
			s.error(w, http.StatusBadRequest, err.Error())
		}
		return
	}

	s.json(w, http.StatusCreated, map[string]any{
		"observation_id": result.ObservationID,
		"subject_id":     result.SubjectID,
		"entity_id":      result.SubjectID,
		"observed_at":    result.ObservedAt,
		"recorded_at":    result.RecordedAt,
	})
}

func (s *Server) graphWriteClaim(w http.ResponseWriter, r *http.Request) {
	g := s.app.SecurityGraph
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	var req graphWriteClaimRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	result, err := graph.WriteClaim(g, graph.ClaimWriteRequest{
		ID:                 req.ID,
		ClaimType:          req.ClaimType,
		SubjectID:          req.SubjectID,
		Predicate:          req.Predicate,
		ObjectID:           req.ObjectID,
		ObjectValue:        req.ObjectValue,
		Status:             req.Status,
		Summary:            req.Summary,
		EvidenceIDs:        req.EvidenceIDs,
		SupportingClaimIDs: req.SupportingClaimIDs,
		RefutingClaimIDs:   req.RefutingClaimIDs,
		SupersedesClaimID:  req.SupersedesClaimID,
		SourceID:           req.SourceID,
		SourceName:         req.SourceName,
		SourceType:         req.SourceType,
		SourceURL:          req.SourceURL,
		TrustTier:          req.TrustTier,
		ReliabilityScore:   req.ReliabilityScore,
		SourceSystem:       req.SourceSystem,
		SourceEventID:      req.SourceEventID,
		ObservedAt:         req.ObservedAt,
		ValidFrom:          req.ValidFrom,
		ValidTo:            req.ValidTo,
		RecordedAt:         req.RecordedAt,
		TransactionFrom:    req.TransactionFrom,
		TransactionTo:      req.TransactionTo,
		Confidence:         req.Confidence,
		Metadata:           req.Metadata,
	})
	if err != nil {
		status := http.StatusBadRequest
		switch {
		case strings.Contains(err.Error(), "not found"):
			status = http.StatusNotFound
		}
		s.error(w, status, err.Error())
		return
	}

	var claimNode *graph.Node
	if node, ok := g.GetNode(result.ClaimID); ok && node != nil {
		claimNode = node
	}
	s.emitPlatformLifecycleEvent(r.Context(), webhooks.EventPlatformClaimWritten, map[string]any{
		"claim_id":             result.ClaimID,
		"subject_id":           strings.TrimSpace(req.SubjectID),
		"predicate":            strings.TrimSpace(req.Predicate),
		"claim_type":           readStringProperty(claimNode, "claim_type", req.ClaimType),
		"status":               readStringProperty(claimNode, "status", req.Status),
		"source_id":            result.SourceID,
		"object_id":            strings.TrimSpace(req.ObjectID),
		"object_value":         strings.TrimSpace(req.ObjectValue),
		"evidence_ids":         append([]string(nil), req.EvidenceIDs...),
		"supporting_claim_ids": append([]string(nil), req.SupportingClaimIDs...),
		"refuting_claim_ids":   append([]string(nil), req.RefutingClaimIDs...),
		"source_system":        readStringProperty(claimNode, "source_system", req.SourceSystem),
		"source_event_id":      readStringProperty(claimNode, "source_event_id", req.SourceEventID),
		"observed_at":          readStringProperty(claimNode, "observed_at", result.ObservedAt.Format(time.RFC3339)),
		"recorded_at":          readStringProperty(claimNode, "recorded_at", result.RecordedAt.Format(time.RFC3339)),
		"transaction_from":     readStringProperty(claimNode, "transaction_from"),
	})
	s.json(w, http.StatusCreated, result)
}

func (s *Server) graphAnnotateEntity(w http.ResponseWriter, r *http.Request) {
	g := s.app.SecurityGraph
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

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

	entity, ok := g.GetNode(req.EntityID)
	if !ok || entity == nil {
		s.error(w, http.StatusNotFound, fmt.Sprintf("entity not found: %s", req.EntityID))
		return
	}

	metadata := graph.NormalizeWriteMetadata(req.ObservedAt, req.ValidFrom, req.ValidTo, req.SourceSystem, req.SourceEventID, req.Confidence, graph.WriteMetadataDefaults{
		SourceSystem:      "api",
		SourceEventPrefix: "api",
		DefaultConfidence: 0.80,
	})

	annotationID := fmt.Sprintf("annotation:%s:%d", req.EntityID, metadata.ObservedAt.UnixNano())
	properties := cloneJSONMap(entity.Properties)
	if properties == nil {
		properties = make(map[string]any)
	}
	existing := annotationsFromProperties(properties["annotations"])
	entry := map[string]any{
		"id":              annotationID,
		"annotation":      req.Annotation,
		"tags":            normalizeStringSlice(req.Tags),
		"source_system":   metadata.SourceSystem,
		"source_event_id": metadata.SourceEventID,
		"observed_at":     metadata.ObservedAt.Format(time.RFC3339),
		"valid_from":      metadata.ValidFrom.Format(time.RFC3339),
		"confidence":      metadata.Confidence,
	}
	if metadata.ValidTo != nil {
		entry["valid_to"] = metadata.ValidTo.Format(time.RFC3339)
	}
	if len(req.Metadata) > 0 {
		entry["metadata"] = cloneJSONMap(req.Metadata)
	}
	existing = append(existing, entry)
	properties["annotations"] = existing
	metadata.ApplyTo(properties)

	entity.Properties = properties
	g.AddNode(entity)

	s.json(w, http.StatusCreated, map[string]any{
		"annotation_id": annotationID,
		"entity_id":     req.EntityID,
		"count":         len(existing),
	})
}

func (s *Server) graphWriteDecision(w http.ResponseWriter, r *http.Request) {
	g := s.app.SecurityGraph
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

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
	targetIDs := uniqueNormalizedIDs(req.TargetIDs)
	for _, targetID := range targetIDs {
		if _, ok := g.GetNode(targetID); !ok {
			s.error(w, http.StatusNotFound, fmt.Sprintf("target not found: %s", targetID))
			return
		}
	}

	metadata := graph.NormalizeWriteMetadata(req.ObservedAt, req.ValidFrom, req.ValidTo, req.SourceSystem, req.SourceEventID, req.Confidence, graph.WriteMetadataDefaults{
		SourceSystem:      "api",
		SourceEventPrefix: "api",
		DefaultConfidence: 0.80,
	})

	decisionID := strings.TrimSpace(req.ID)
	if decisionID == "" {
		decisionID = fmt.Sprintf("decision:%d", metadata.ObservedAt.UnixNano())
	}
	properties := cloneJSONMap(req.Metadata)
	properties["decision_type"] = req.DecisionType
	properties["status"] = firstNonEmpty(req.Status, "proposed")
	properties["made_at"] = metadata.ObservedAt.Format(time.RFC3339)
	properties["made_by"] = req.MadeBy
	properties["rationale"] = req.Rationale
	metadata.ApplyTo(properties)

	g.AddNode(&graph.Node{
		ID:         decisionID,
		Kind:       graph.NodeKindDecision,
		Name:       firstNonEmpty(req.DecisionType, decisionID),
		Provider:   metadata.SourceSystem,
		Properties: properties,
		Risk:       graph.RiskNone,
	})

	for _, targetID := range targetIDs {
		edgeProperties := metadata.PropertyMap()
		g.AddEdge(&graph.Edge{
			ID:         fmt.Sprintf("%s->%s:%s", decisionID, targetID, graph.EdgeKindTargets),
			Source:     decisionID,
			Target:     targetID,
			Kind:       graph.EdgeKindTargets,
			Effect:     graph.EdgeEffectAllow,
			Properties: edgeProperties,
		})
	}
	for _, evidenceID := range uniqueNormalizedIDs(req.EvidenceIDs) {
		if _, ok := g.GetNode(evidenceID); !ok {
			continue
		}
		edgeProperties := metadata.PropertyMap()
		g.AddEdge(&graph.Edge{
			ID:         fmt.Sprintf("%s->%s:%s", decisionID, evidenceID, graph.EdgeKindBasedOn),
			Source:     decisionID,
			Target:     evidenceID,
			Kind:       graph.EdgeKindBasedOn,
			Effect:     graph.EdgeEffectAllow,
			Properties: edgeProperties,
		})
	}
	for _, actionID := range uniqueNormalizedIDs(req.ActionIDs) {
		if _, ok := g.GetNode(actionID); !ok {
			continue
		}
		edgeProperties := metadata.PropertyMap()
		g.AddEdge(&graph.Edge{
			ID:         fmt.Sprintf("%s->%s:%s", decisionID, actionID, graph.EdgeKindExecutedBy),
			Source:     decisionID,
			Target:     actionID,
			Kind:       graph.EdgeKindExecutedBy,
			Effect:     graph.EdgeEffectAllow,
			Properties: edgeProperties,
		})
	}

	s.emitPlatformLifecycleEvent(r.Context(), webhooks.EventPlatformDecisionRecorded, map[string]any{
		"decision_id":     decisionID,
		"decision_type":   req.DecisionType,
		"status":          firstNonEmpty(req.Status, "proposed"),
		"made_by":         req.MadeBy,
		"rationale":       req.Rationale,
		"target_ids":      append([]string(nil), targetIDs...),
		"evidence_ids":    append([]string(nil), uniqueNormalizedIDs(req.EvidenceIDs)...),
		"action_ids":      append([]string(nil), uniqueNormalizedIDs(req.ActionIDs)...),
		"source_system":   metadata.SourceSystem,
		"source_event_id": metadata.SourceEventID,
		"observed_at":     metadata.ObservedAt.Format(time.RFC3339),
		"valid_from":      metadata.ValidFrom.Format(time.RFC3339),
	})
	s.json(w, http.StatusCreated, map[string]any{
		"decision_id":  decisionID,
		"target_count": len(targetIDs),
	})
}

func (s *Server) graphWriteOutcome(w http.ResponseWriter, r *http.Request) {
	g := s.app.SecurityGraph
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

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
	if _, ok := g.GetNode(req.DecisionID); !ok {
		s.error(w, http.StatusNotFound, fmt.Sprintf("decision not found: %s", req.DecisionID))
		return
	}

	metadata := graph.NormalizeWriteMetadata(req.ObservedAt, req.ValidFrom, req.ValidTo, req.SourceSystem, req.SourceEventID, req.Confidence, graph.WriteMetadataDefaults{
		SourceSystem:      "api",
		SourceEventPrefix: "api",
		DefaultConfidence: 0.80,
	})

	outcomeID := strings.TrimSpace(req.ID)
	if outcomeID == "" {
		outcomeID = fmt.Sprintf("outcome:%d", metadata.ObservedAt.UnixNano())
	}
	properties := cloneJSONMap(req.Metadata)
	properties["outcome_type"] = req.OutcomeType
	properties["verdict"] = req.Verdict
	properties["impact_score"] = req.ImpactScore
	metadata.ApplyTo(properties)

	g.AddNode(&graph.Node{
		ID:         outcomeID,
		Kind:       graph.NodeKindOutcome,
		Name:       firstNonEmpty(req.OutcomeType, outcomeID),
		Provider:   metadata.SourceSystem,
		Properties: properties,
		Risk:       graph.RiskNone,
	})
	evaluatesEdgeProperties := metadata.PropertyMap()
	g.AddEdge(&graph.Edge{
		ID:         fmt.Sprintf("%s->%s:%s", outcomeID, req.DecisionID, graph.EdgeKindEvaluates),
		Source:     outcomeID,
		Target:     req.DecisionID,
		Kind:       graph.EdgeKindEvaluates,
		Effect:     graph.EdgeEffectAllow,
		Properties: evaluatesEdgeProperties,
	})

	targetIDs := uniqueNormalizedIDs(req.TargetIDs)
	for _, targetID := range targetIDs {
		if _, ok := g.GetNode(targetID); !ok {
			continue
		}
		edgeProperties := metadata.PropertyMap()
		g.AddEdge(&graph.Edge{
			ID:         fmt.Sprintf("%s->%s:%s", outcomeID, targetID, graph.EdgeKindTargets),
			Source:     outcomeID,
			Target:     targetID,
			Kind:       graph.EdgeKindTargets,
			Effect:     graph.EdgeEffectAllow,
			Properties: edgeProperties,
		})
	}

	s.emitPlatformLifecycleEvent(r.Context(), webhooks.EventPlatformOutcomeRecorded, map[string]any{
		"outcome_id":      outcomeID,
		"decision_id":     req.DecisionID,
		"outcome_type":    req.OutcomeType,
		"verdict":         req.Verdict,
		"impact_score":    req.ImpactScore,
		"target_ids":      append([]string(nil), targetIDs...),
		"source_system":   metadata.SourceSystem,
		"source_event_id": metadata.SourceEventID,
		"observed_at":     metadata.ObservedAt.Format(time.RFC3339),
		"valid_from":      metadata.ValidFrom.Format(time.RFC3339),
	})
	s.json(w, http.StatusCreated, map[string]any{
		"outcome_id":   outcomeID,
		"decision_id":  req.DecisionID,
		"target_count": len(targetIDs),
	})
}

func (s *Server) graphResolveIdentity(w http.ResponseWriter, r *http.Request) {
	g := s.app.SecurityGraph
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	var req graphResolveIdentityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	result, err := graph.ResolveIdentityAlias(g, graph.IdentityAliasAssertion{
		AliasID:       req.AliasID,
		SourceSystem:  req.SourceSystem,
		SourceEventID: req.SourceEventID,
		ExternalID:    req.ExternalID,
		AliasType:     req.AliasType,
		CanonicalHint: req.CanonicalHint,
		Email:         req.Email,
		Name:          req.Name,
		ObservedAt:    req.ObservedAt,
		Confidence:    req.Confidence,
	}, graph.IdentityResolutionOptions{
		AutoLinkThreshold: req.AutoLinkThreshold,
		SuggestThreshold:  req.SuggestThreshold,
	})
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}
	s.json(w, http.StatusOK, result)
}

func (s *Server) graphSplitIdentity(w http.ResponseWriter, r *http.Request) {
	g := s.app.SecurityGraph
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	var req graphSplitIdentityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	removed, err := graph.SplitIdentityAlias(
		g,
		req.AliasNodeID,
		req.CanonicalNodeID,
		req.Reason,
		req.SourceSystem,
		req.SourceEventID,
		req.ObservedAt,
	)
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}
	s.json(w, http.StatusOK, map[string]any{
		"removed":           removed,
		"alias_node_id":     strings.TrimSpace(req.AliasNodeID),
		"canonical_node_id": strings.TrimSpace(req.CanonicalNodeID),
	})
}

func (s *Server) graphReviewIdentity(w http.ResponseWriter, r *http.Request) {
	g := s.app.SecurityGraph
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	var req graphIdentityReviewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	record, err := graph.ReviewIdentityAlias(g, graph.IdentityReviewDecision{
		AliasNodeID:     req.AliasNodeID,
		CanonicalNodeID: req.CanonicalNodeID,
		Verdict:         req.Verdict,
		Reviewer:        req.Reviewer,
		Reason:          req.Reason,
		SourceSystem:    req.SourceSystem,
		SourceEventID:   req.SourceEventID,
		ObservedAt:      req.ObservedAt,
		Confidence:      req.Confidence,
	})
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}
	s.json(w, http.StatusOK, record)
}

func (s *Server) graphIdentityCalibration(w http.ResponseWriter, r *http.Request) {
	g := s.app.SecurityGraph
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

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

	report := graph.BuildIdentityCalibrationReport(g, graph.IdentityCalibrationOptions{
		SuggestThreshold: suggestThreshold,
		QueueLimit:       queueLimit,
		IncludeQueue:     includeQueue,
	})
	s.json(w, http.StatusOK, report)
}

func (s *Server) graphActuateRecommendation(w http.ResponseWriter, r *http.Request) {
	g := s.app.SecurityGraph
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	var req graphActuateRecommendationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	result, err := graph.ActuateRecommendation(g, graph.RecommendationActuationRequest{
		ID:               req.ID,
		RecommendationID: req.RecommendationID,
		InsightType:      req.InsightType,
		Title:            req.Title,
		Summary:          req.Summary,
		DecisionID:       req.DecisionID,
		TargetIDs:        req.TargetIDs,
		SourceSystem:     req.SourceSystem,
		SourceEventID:    req.SourceEventID,
		ObservedAt:       req.ObservedAt,
		ValidFrom:        req.ValidFrom,
		ValidTo:          req.ValidTo,
		Confidence:       req.Confidence,
		AutoGenerated:    req.AutoGenerated,
		Metadata:         req.Metadata,
	})
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}
	var actionNode *graph.Node
	if node, ok := g.GetNode(result.ActionID); ok && node != nil {
		actionNode = node
	}
	s.emitPlatformLifecycleEvent(r.Context(), webhooks.EventPlatformActionRecorded, map[string]any{
		"action_id":         result.ActionID,
		"title":             firstNonEmpty(strings.TrimSpace(req.Title), nodeName(actionNode)),
		"decision_id":       strings.TrimSpace(req.DecisionID),
		"recommendation_id": strings.TrimSpace(req.RecommendationID),
		"insight_type":      strings.TrimSpace(req.InsightType),
		"summary":           strings.TrimSpace(req.Summary),
		"status":            readStringProperty(actionNode, "status", "planned"),
		"target_ids":        append([]string(nil), uniqueNormalizedIDs(req.TargetIDs)...),
		"source_system":     result.SourceSystem,
		"source_event_id":   result.SourceEventID,
		"observed_at":       readStringProperty(actionNode, "observed_at", normalizeRFC3339(req.ObservedAt)),
		"valid_from":        readStringProperty(actionNode, "valid_from", normalizeRFC3339(req.ValidFrom)),
		"auto_generated":    req.AutoGenerated,
	})
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
