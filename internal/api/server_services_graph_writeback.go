package api

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/graph/knowledge"
	"github.com/writer/cerebro/internal/webhooks"
)

var errGraphWritebackUnavailable = errors.New("graph platform not initialized")

type graphWritebackService interface {
	WriteObservation(ctx context.Context, req graphWriteObservationRequest) (*graphWriteObservationResponse, error)
	WriteClaim(ctx context.Context, req graphWriteClaimRequest) (*knowledge.ClaimWriteResult, error)
	AnnotateEntity(ctx context.Context, req graphAnnotateEntityRequest) (*graphAnnotationWriteResponse, error)
	WriteDecision(ctx context.Context, req graphWriteDecisionRequest) (*graphDecisionWriteResponse, error)
	WriteOutcome(ctx context.Context, req graphWriteOutcomeRequest) (*graphOutcomeWriteResponse, error)
	ResolveIdentity(ctx context.Context, req graphResolveIdentityRequest) (*graph.IdentityResolutionResult, error)
	SplitIdentity(ctx context.Context, req graphSplitIdentityRequest) (*graphIdentitySplitResponse, error)
	ReviewIdentity(ctx context.Context, req graphIdentityReviewRequest) (*graph.IdentityReviewRecord, error)
	IdentityCalibration(ctx context.Context, opts graph.IdentityCalibrationOptions) (*graph.IdentityCalibrationReport, error)
	ActuateRecommendation(ctx context.Context, req graphActuateRecommendationRequest) (*graph.RecommendationActuationResult, error)
}

type graphWriteObservationResponse struct {
	ObservationID string    `json:"observation_id"`
	SubjectID     string    `json:"subject_id"`
	EntityID      string    `json:"entity_id"`
	ObservedAt    time.Time `json:"observed_at"`
	RecordedAt    time.Time `json:"recorded_at"`
}

type graphAnnotationWriteResponse struct {
	AnnotationID string `json:"annotation_id"`
	EntityID     string `json:"entity_id"`
	Count        int    `json:"count"`
}

type graphDecisionWriteResponse struct {
	DecisionID  string `json:"decision_id"`
	TargetCount int    `json:"target_count"`
}

type graphOutcomeWriteResponse struct {
	OutcomeID   string `json:"outcome_id"`
	DecisionID  string `json:"decision_id"`
	TargetCount int    `json:"target_count"`
}

type graphIdentitySplitResponse struct {
	Removed         bool   `json:"removed"`
	AliasNodeID     string `json:"alias_node_id"`
	CanonicalNodeID string `json:"canonical_node_id"`
}

type serverGraphWritebackService struct {
	server *Server
	deps   *serverDependencies
}

func newGraphWritebackService(server *Server, deps *serverDependencies) graphWritebackService {
	return serverGraphWritebackService{server: server, deps: deps}
}

func (s serverGraphWritebackService) WriteObservation(ctx context.Context, req graphWriteObservationRequest) (*graphWriteObservationResponse, error) {
	var result knowledge.ObservationWriteResult
	_, err := s.mutate(ctx, func(g *graph.Graph) error {
		var writeErr error
		result, writeErr = knowledge.WriteObservation(g, knowledge.ObservationWriteRequest{
			ID:              req.ID,
			SubjectID:       req.SubjectID,
			ObservationType: req.ObservationType,
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
		return writeErr
	})
	if err != nil {
		return nil, err
	}
	return &graphWriteObservationResponse{
		ObservationID: result.ObservationID,
		SubjectID:     result.SubjectID,
		EntityID:      result.SubjectID,
		ObservedAt:    result.ObservedAt,
		RecordedAt:    result.RecordedAt,
	}, nil
}

func (s serverGraphWritebackService) WriteClaim(ctx context.Context, req graphWriteClaimRequest) (*knowledge.ClaimWriteResult, error) {
	var result knowledge.ClaimWriteResult
	mutatedGraph, err := s.mutate(ctx, func(g *graph.Graph) error {
		var writeErr error
		result, writeErr = knowledge.WriteClaim(g, knowledge.ClaimWriteRequest{
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
		return writeErr
	})
	if err != nil {
		return nil, err
	}

	var claimNode *graph.Node
	if mutatedGraph != nil {
		if node, ok := mutatedGraph.GetNode(result.ClaimID); ok && node != nil {
			claimNode = node
		}
	}
	s.emitPlatformLifecycleEvent(ctx, webhooks.EventPlatformClaimWritten, map[string]any{
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
	return &result, nil
}

func (s serverGraphWritebackService) AnnotateEntity(ctx context.Context, req graphAnnotateEntityRequest) (*graphAnnotationWriteResponse, error) {
	var (
		annotationID string
		count        int
	)
	_, err := s.mutate(ctx, func(g *graph.Graph) error {
		entity, ok := g.GetNode(req.EntityID)
		if !ok || entity == nil {
			return fmt.Errorf("entity not found: %s", req.EntityID)
		}

		metadata := graph.NormalizeWriteMetadata(req.ObservedAt, req.ValidFrom, req.ValidTo, req.SourceSystem, req.SourceEventID, req.Confidence, graph.WriteMetadataDefaults{
			SourceSystem:      "api",
			SourceEventPrefix: "api",
			DefaultConfidence: 0.80,
		})

		annotationID = fmt.Sprintf("annotation:%s:%d", req.EntityID, metadata.ObservedAt.UnixNano())
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
		count = len(existing)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &graphAnnotationWriteResponse{
		AnnotationID: annotationID,
		EntityID:     req.EntityID,
		Count:        count,
	}, nil
}

func (s serverGraphWritebackService) WriteDecision(ctx context.Context, req graphWriteDecisionRequest) (*graphDecisionWriteResponse, error) {
	var decisionID string
	metadata := graph.NormalizeWriteMetadata(req.ObservedAt, req.ValidFrom, req.ValidTo, req.SourceSystem, req.SourceEventID, req.Confidence, graph.WriteMetadataDefaults{
		SourceSystem:      "api",
		SourceEventPrefix: "api",
		DefaultConfidence: 0.80,
	})
	_, err := s.mutate(ctx, func(g *graph.Graph) error {
		for _, targetID := range req.TargetIDs {
			if _, ok := g.GetNode(targetID); !ok {
				return fmt.Errorf("target not found: %s", targetID)
			}
		}

		decisionID = strings.TrimSpace(req.ID)
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

		for _, targetID := range req.TargetIDs {
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
		return nil
	})
	if err != nil {
		return nil, err
	}

	s.emitPlatformLifecycleEvent(ctx, webhooks.EventPlatformDecisionRecorded, map[string]any{
		"decision_id":     decisionID,
		"decision_type":   req.DecisionType,
		"status":          firstNonEmpty(req.Status, "proposed"),
		"made_by":         req.MadeBy,
		"rationale":       req.Rationale,
		"target_ids":      append([]string(nil), req.TargetIDs...),
		"evidence_ids":    append([]string(nil), uniqueNormalizedIDs(req.EvidenceIDs)...),
		"action_ids":      append([]string(nil), uniqueNormalizedIDs(req.ActionIDs)...),
		"source_system":   metadata.SourceSystem,
		"source_event_id": metadata.SourceEventID,
		"observed_at":     metadata.ObservedAt.Format(time.RFC3339),
		"valid_from":      metadata.ValidFrom.Format(time.RFC3339),
	})
	return &graphDecisionWriteResponse{
		DecisionID:  decisionID,
		TargetCount: len(req.TargetIDs),
	}, nil
}

func (s serverGraphWritebackService) WriteOutcome(ctx context.Context, req graphWriteOutcomeRequest) (*graphOutcomeWriteResponse, error) {
	var outcomeID string
	metadata := graph.NormalizeWriteMetadata(req.ObservedAt, req.ValidFrom, req.ValidTo, req.SourceSystem, req.SourceEventID, req.Confidence, graph.WriteMetadataDefaults{
		SourceSystem:      "api",
		SourceEventPrefix: "api",
		DefaultConfidence: 0.80,
	})
	_, err := s.mutate(ctx, func(g *graph.Graph) error {
		if _, ok := g.GetNode(req.DecisionID); !ok {
			return fmt.Errorf("decision not found: %s", req.DecisionID)
		}

		outcomeID = strings.TrimSpace(req.ID)
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

		for _, targetID := range req.TargetIDs {
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
		return nil
	})
	if err != nil {
		return nil, err
	}

	s.emitPlatformLifecycleEvent(ctx, webhooks.EventPlatformOutcomeRecorded, map[string]any{
		"outcome_id":      outcomeID,
		"decision_id":     req.DecisionID,
		"outcome_type":    req.OutcomeType,
		"verdict":         req.Verdict,
		"impact_score":    req.ImpactScore,
		"target_ids":      append([]string(nil), req.TargetIDs...),
		"source_system":   metadata.SourceSystem,
		"source_event_id": metadata.SourceEventID,
		"observed_at":     metadata.ObservedAt.Format(time.RFC3339),
		"valid_from":      metadata.ValidFrom.Format(time.RFC3339),
	})
	return &graphOutcomeWriteResponse{
		OutcomeID:   outcomeID,
		DecisionID:  req.DecisionID,
		TargetCount: len(req.TargetIDs),
	}, nil
}

func (s serverGraphWritebackService) ResolveIdentity(ctx context.Context, req graphResolveIdentityRequest) (*graph.IdentityResolutionResult, error) {
	var result graph.IdentityResolutionResult
	_, err := s.mutate(ctx, func(g *graph.Graph) error {
		var resolveErr error
		result, resolveErr = graph.ResolveIdentityAlias(g, graph.IdentityAliasAssertion{
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
		return resolveErr
	})
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (s serverGraphWritebackService) SplitIdentity(ctx context.Context, req graphSplitIdentityRequest) (*graphIdentitySplitResponse, error) {
	var removed bool
	_, err := s.mutate(ctx, func(g *graph.Graph) error {
		var splitErr error
		removed, splitErr = graph.SplitIdentityAlias(
			g,
			req.AliasNodeID,
			req.CanonicalNodeID,
			req.Reason,
			req.SourceSystem,
			req.SourceEventID,
			req.ObservedAt,
		)
		return splitErr
	})
	if err != nil {
		return nil, err
	}
	return &graphIdentitySplitResponse{
		Removed:         removed,
		AliasNodeID:     strings.TrimSpace(req.AliasNodeID),
		CanonicalNodeID: strings.TrimSpace(req.CanonicalNodeID),
	}, nil
}

func (s serverGraphWritebackService) ReviewIdentity(ctx context.Context, req graphIdentityReviewRequest) (*graph.IdentityReviewRecord, error) {
	var record graph.IdentityReviewRecord
	_, err := s.mutate(ctx, func(g *graph.Graph) error {
		var reviewErr error
		record, reviewErr = graph.ReviewIdentityAlias(g, graph.IdentityReviewDecision{
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
		return reviewErr
	})
	if err != nil {
		return nil, err
	}
	return &record, nil
}

func (s serverGraphWritebackService) IdentityCalibration(ctx context.Context, opts graph.IdentityCalibrationOptions) (*graph.IdentityCalibrationReport, error) {
	g, err := currentOrStoredGraphView(ctx, s.currentGraph(), s.currentStore())
	if err != nil {
		return nil, errGraphWritebackUnavailable
	}
	report := graph.BuildIdentityCalibrationReport(g, opts)
	return &report, nil
}

func (s serverGraphWritebackService) ActuateRecommendation(ctx context.Context, req graphActuateRecommendationRequest) (*graph.RecommendationActuationResult, error) {
	var result graph.RecommendationActuationResult
	mutatedGraph, err := s.mutate(ctx, func(g *graph.Graph) error {
		var actuationErr error
		result, actuationErr = graph.ActuateRecommendation(g, graph.RecommendationActuationRequest{
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
		return actuationErr
	})
	if err != nil {
		return nil, err
	}

	var actionNode *graph.Node
	if mutatedGraph != nil {
		if node, ok := mutatedGraph.GetNode(result.ActionID); ok && node != nil {
			actionNode = node
		}
	}
	s.emitPlatformLifecycleEvent(ctx, webhooks.EventPlatformActionRecorded, map[string]any{
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
	return &result, nil
}

func (s serverGraphWritebackService) mutate(ctx context.Context, mutate func(*graph.Graph) error) (*graph.Graph, error) {
	if s.deps == nil || s.deps.graphMutator == nil {
		return nil, errGraphWritebackUnavailable
	}
	return s.deps.MutateSecurityGraph(ctx, mutate)
}

func (s serverGraphWritebackService) currentGraph() *graph.Graph {
	if s.deps == nil {
		return nil
	}
	return s.deps.CurrentSecurityGraph()
}

func (s serverGraphWritebackService) currentStore() graph.GraphStore {
	if s.deps == nil {
		return nil
	}
	return s.deps.CurrentSecurityGraphStore()
}

func (s serverGraphWritebackService) emitPlatformLifecycleEvent(ctx context.Context, eventType webhooks.EventType, data map[string]any) {
	if s.server != nil {
		s.server.emitPlatformLifecycleEvent(ctx, eventType, data)
		return
	}
	if s.deps == nil || s.deps.Webhooks == nil {
		return
	}
	payload := cloneJSONMap(data)
	if tenantID := strings.TrimSpace(GetTenantID(ctx)); tenantID != "" {
		payload["tenant_id"] = tenantID
	}
	if err := s.deps.Webhooks.EmitWithErrors(ctx, eventType, payload); err != nil && s.deps.Logger != nil {
		s.deps.Logger.Warn("failed to emit platform lifecycle event", "event_type", eventType, "error", err)
	}
}

var _ graphWritebackService = serverGraphWritebackService{}
